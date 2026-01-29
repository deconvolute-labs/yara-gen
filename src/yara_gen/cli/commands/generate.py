from __future__ import annotations

import argparse
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from yara_gen.adapters import ADAPTER_MAP, get_adapter
from yara_gen.constants import DEFAULT_RULE_FILENAME, EngineType
from yara_gen.engine.factory import get_engine
from yara_gen.errors import ConfigurationError, DataError
from yara_gen.generation.deduplication import parse_existing_rules
from yara_gen.generation.writer import YaraWriter
from yara_gen.models.config import AppConfig
from yara_gen.models.text import DatasetType, GeneratedRule, TextSample
from yara_gen.utils.config import apply_overrides, load_config
from yara_gen.utils.logger import (
    get_logger,
    log_config,
    log_named_value,
)

logger = get_logger()


def register_args(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    parents: list[argparse.ArgumentParser],
) -> None:
    available_adapters = ", ".join(sorted(ADAPTER_MAP.keys()))

    parser = subparsers.add_parser(
        "generate",
        help="Extract signatures from adversarial inputs and generate YARA rules.",
        parents=parents,
    )

    parser.add_argument(
        "input", type=Path, nargs="?", help="Path to the adversarial dataset"
    )

    parser.add_argument(
        "--config",
        "-c",
        type=Path,
        default="generation_config.yaml",
        help="Path to the configuration YAML file (default: generation_config.yaml)",
    )

    # Note: Defaults are set to None to allow generation_config.yaml to take precedence
    # unless the user explicitly provides the flag.
    parser.add_argument(
        "--adversarial-adapter",
        "-a",
        type=str,
        help=(
            f"Adapter for adversarial input. Options: [{available_adapters}] "
            "(overrides config)"
        ),
    )

    parser.add_argument(
        "--benign-dataset",
        "-b",
        type=Path,
        help="Path to the control dataset (overrides config)",
    )

    parser.add_argument(
        "--benign-adapter",
        "-ba",
        type=str,
        help=(
            f"Adapter for benign input. Options: [{available_adapters}] "
            "(overrides config)"
        ),
    )

    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Path to save the generated .yar file (overrides config)",
    )

    parser.add_argument(
        "--existing-rules",
        "-e",
        type=Path,
        help="Path to existing .yar rules for deduplication",
    )

    parser.add_argument(
        "--engine",
        choices=[e.value for e in EngineType],
        help=("The algorithm used to generate rules (overrides config)"),
    )

    parser.add_argument(
        "--rule-date",
        type=str,
        help=(
            "Fixed date string (e.g. 2026-01-27) for rule metadata to ensure "
            "deterministic builds."
        ),
    )

    parser.add_argument(
        "--tag",
        action="append",
        dest="tags",
        help="Custom tags to add to generated rules (can be used multiple times)",
    )


def _load_app_configuration(args: argparse.Namespace) -> AppConfig:
    """
    Loads configuration from file and applies CLI overrides.
    """
    # args.config comes from the parent parser in cli/args.py
    config_path = getattr(args, "config", Path("generation_config.yaml"))
    logger.info(f"Loading configuration from: {config_path}")

    # Load raw dict; empty if file missing (handled in load_config defaults/errors)
    raw_config = load_config(config_path)

    # Apply Dot-Notation overrides (--set)
    # e.g. --set engine.min_ngram=4
    raw_config = apply_overrides(raw_config, getattr(args, "set", None))

    # Apply explicit CLI argument overrides
    if args.output:
        raw_config["output_path"] = str(args.output)

    # Adversarial adapter overrides
    if "adversarial_adapter" not in raw_config:
        raw_config["adversarial_adapter"] = {}
    if args.adversarial_adapter:
        raw_config["adversarial_adapter"]["type"] = args.adversarial_adapter

    # Benign adapter overrides
    if "benign_adapter" not in raw_config:
        raw_config["benign_adapter"] = {}
    if args.benign_adapter:
        raw_config["benign_adapter"]["type"] = args.benign_adapter

    # Engine overrides
    if "engine" not in raw_config:
        raw_config["engine"] = {}
    if args.engine:
        raw_config["engine"]["type"] = args.engine
    if args.rule_date:
        raw_config["engine"]["rule_date"] = args.rule_date

    # Merge tags
    config_tags = raw_config.get("tags", [])
    if not isinstance(config_tags, list):
        config_tags = []

    if args.tags:
        for tag in args.tags:
            if tag not in config_tags:
                config_tags.append(tag)

    raw_config["tags"] = config_tags

    return AppConfig(**raw_config)


def _initialize_components(app_config: AppConfig) -> tuple[Any, Any, Any]:
    """
    Initializes engine and adapters based on configuration.
    """
    engine_type = app_config.engine.type
    adv_adapter_type = app_config.adversarial_adapter.type
    benign_adapter_type = app_config.benign_adapter.type

    logger.info(f"Starting generation with Engine: {engine_type}")

    try:
        engine = get_engine(app_config.engine)
        adv_adapter = get_adapter(adv_adapter_type, DatasetType.ADVERSARIAL)
        benign_adapter = get_adapter(benign_adapter_type, DatasetType.BENIGN)
        return engine, adv_adapter, benign_adapter
    except ValueError as e:
        logger.error(f"Component Initialization Error: {e}")
        sys.exit(1)


def _load_pipeline_data(
    args: argparse.Namespace,
    app_config: AppConfig,
    adv_adapter: Any,
    benign_adapter: Any,
) -> tuple[Iterator[TextSample], Iterator[TextSample]]:
    """
    Loads adversarial and benign data streams.
    """
    try:
        adv_path = args.input
        if not adv_path:
            raise ConfigurationError("No input path provided (via CLI argument).")

        logger.info(f"Loading adversarial data: {adv_path}")
        adv_stream = adv_adapter.load(
            adv_path, **app_config.adversarial_adapter.model_dump(exclude={"type"})
        )

        benign_path = args.benign_dataset
        if not benign_path:
            raise ConfigurationError(
                "No benign dataset path provided (--benign-dataset)."
            )

        logger.info(f"Loading benign data: {benign_path}")
        benign_stream = benign_adapter.load(
            benign_path, **app_config.benign_adapter.model_dump(exclude={"type"})
        )

        return adv_stream, benign_stream

    except (DataError, FileNotFoundError) as e:
        logger.error(f"Data Processing Error: {e}")
        sys.exit(1)


def _apply_deduplication(
    rules: list[GeneratedRule], existing_rules_path: Path | None
) -> list[GeneratedRule]:
    """
    Removes rules that match existing rules.
    """
    if existing_rules_path and existing_rules_path.exists():
        logger.info(f"Deduplicating against existing rules: {existing_rules_path}")
        existing_payloads = parse_existing_rules(existing_rules_path)
        initial_count = len(rules)

        # Determine unique payloads to check
        rules = [
            r for r in rules if not any(s.value in existing_payloads for s in r.strings)
        ]

        dropped_count = initial_count - len(rules)
        if dropped_count > 0:
            logger.info(
                f"Deduplication complete. Dropped {dropped_count} duplicate rules."
            )
    return rules


def _write_results(rules: list[GeneratedRule], output_path: str) -> None:
    """
    Writes generated rules to a file.
    """
    try:
        writer = YaraWriter()
        writer.write(rules, Path(output_path))
        if rules:
            logger.info(f"Generation complete. Created {len(rules)} rules.")
        else:
            logger.warning("Generation complete, but NO rules were created.")
    except OSError as e:
        logger.error(f"Failed to write output file '{output_path}': {e}")
        sys.exit(1)


def run(args: argparse.Namespace) -> None:
    """
    Executes the rule generation pipeline.
    """
    try:
        app_config = _load_app_configuration(args)

        log_named_value(logger, "Adversarial", args.input)
        log_named_value(logger, "Benign", args.benign_dataset)
        log_named_value(
            logger, "Output", app_config.output_path or DEFAULT_RULE_FILENAME
        )

        # Log the deep configuration
        log_config(logger, app_config.model_dump())

        engine, adv_adapter, benign_adapter = _initialize_components(app_config)

        adv_stream, benign_stream = _load_pipeline_data(
            args, app_config, adv_adapter, benign_adapter
        )

        # Execute Extraction
        rules = engine.extract(adversarial=adv_stream, benign=benign_stream)

        # Post-Processing: Apply Tags and Metadata
        if app_config.tags or app_config.metadata:
            logger.debug(
                f"Applying global tags/metadata to {len(rules)} rules. "
                f"Tags: {app_config.tags}, "
                f"Metadata Keys: {list(app_config.metadata.keys())}"
            )
            for rule in rules:
                rule.tags.extend(app_config.tags)
                rule.metadata.update(app_config.metadata)

        # Deduplication
        rules = _apply_deduplication(rules, args.existing_rules)

        # Output Generation
        output_file = app_config.output_path or DEFAULT_RULE_FILENAME
        _write_results(rules, output_file)

    except ConfigurationError as e:
        logger.error(f"Configuration Error: {e}")
        sys.exit(1)
    except Exception:
        logger.exception("An unexpected critical error occurred")
        sys.exit(1)
