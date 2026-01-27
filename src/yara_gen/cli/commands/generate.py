from __future__ import annotations

import argparse
import sys
from pathlib import Path

from yara_gen.adapters import ADAPTER_MAP, get_adapter
from yara_gen.constants import AdapterType, EngineType
from yara_gen.engine.factory import get_engine
from yara_gen.errors import ConfigurationError, DataError
from yara_gen.generation.writer import YaraWriter
from yara_gen.models.config import AppConfig
from yara_gen.models.text import DatasetType
from yara_gen.utils.config import apply_overrides, load_config
from yara_gen.utils.deduplication import parse_existing_rules
from yara_gen.utils.logger import get_logger, log_run_config

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

    # Note: Defaults are set to None to allow config.yaml to take precedence
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

    # Generic Rule Parameters (kept in CLI as requested)
    parser.add_argument(
        "--rule-date",
        type=str,
        help=(
            "Fixed date string (e.g. 2023-01-01) for rule metadata to ensure "
            "deterministic builds."
        ),
    )

    parser.add_argument(
        "--tag",
        action="append",
        dest="tags",
        help="Custom tags to add to generated rules (can be used multiple times)",
    )


def run(args: argparse.Namespace) -> None:
    try:
        # Load Base Config from YAML
        # args.config comes from the parent parser in cli/args.py
        config_path = getattr(args, "config", Path("config.yaml"))
        logger.info(f"Loading configuration from: {config_path}")

        # Load raw dict; empty if file missing (handled in load_config defaults/errors)
        raw_config = load_config(config_path)

        # Apply Dot-Notation Overrides (--set)
        # e.g. --set engine.min_ngram=4
        raw_config = apply_overrides(raw_config, getattr(args, "set", None))

        # Apply Explicit CLI Argument Overrides
        # We manually map top-level CLI args to the config structure
        if args.output:
            raw_config["output_path"] = str(args.output)

        # Adversarial Adapter Overrides
        if "adversarial_adapter" not in raw_config:
            raw_config["adversarial_adapter"] = {}
        if args.adversarial_adapter:
            raw_config["adversarial_adapter"]["type"] = args.adversarial_adapter

        # Benign Adapter Overrides
        if "benign_adapter" not in raw_config:
            raw_config["benign_adapter"] = {}
        if args.benign_adapter:
            raw_config["benign_adapter"]["type"] = args.benign_adapter

        # Engine Overrides
        if "engine" not in raw_config:
            raw_config["engine"] = {}
        if args.engine:
            raw_config["engine"]["type"] = args.engine
        if args.rule_date:
            raw_config["engine"]["rule_date"] = args.rule_date

        # Validate & Instantiate AppConfig
        # This converts the dict into strict Pydantic models
        app_config = AppConfig(**raw_config)

        # Extract types for factories (defaulting to constants if missing)
        # We access the raw dictionary or extra fields for 'type' since it might not
        # be explicit in BaseEngineConfig
        engine_type = raw_config.get("engine", {}).get("type") or EngineType.NGRAM.value
        adv_adapter_type = (
            raw_config.get("adversarial_adapter", {}).get("type")
            or AdapterType.JSONL.value
        )
        benign_adapter_type = (
            raw_config.get("benign_adapter", {}).get("type") or AdapterType.JSONL.value
        )

        # Log the final resolved configuration for debugging
        log_run_config(logger, args, app_config.model_dump())
        logger.debug(f"Using config: {app_config.model_dump_json()}")
        logger.debug(f"Using engine config: {app_config.engine}")
        logger.info(f"Starting generation with Engine: {engine_type}")

        # Initialize Components
        try:
            engine = get_engine(engine_type, app_config.engine)
            adv_adapter = get_adapter(adv_adapter_type, DatasetType.ADVERSARIAL)
            benign_adapter = get_adapter(benign_adapter_type, DatasetType.BENIGN)
        except ValueError as e:
            logger.error(f"Component Initialization Error: {e}")
            sys.exit(1)

        # Data Loading
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
                raise ConfigurationError("No benign dataset path provided (--benign).")

            logger.info(f"Loading benign data: {benign_path}")
            benign_stream = benign_adapter.load(
                benign_path, **app_config.benign_adapter.model_dump(exclude={"type"})
            )

            # Execute Extraction
            # This is where DataError is likely (e.g. empty inputs, network fail)
            rules = engine.extract(adversarial=adv_stream, benign=benign_stream)

        except (DataError, FileNotFoundError) as e:
            logger.error(f"Data Processing Error: {e}")
            sys.exit(1)

        # Post-Processing: Apply Tags
        if args.tags:
            logger.debug(f"Applying tags to {len(rules)} rules: {args.tags}")
            for rule in rules:
                rule.tags.extend(args.tags)

        # Deduplication
        if args.existing_rules and args.existing_rules.exists():
            logger.info(f"Deduplicating against existing rules: {args.existing_rules}")
            existing_payloads = parse_existing_rules(args.existing_rules)
            initial_count = len(rules)
            rules = [
                r
                for r in rules
                if not any(s.value in existing_payloads for s in r.strings)
            ]
            dropped_count = initial_count - len(rules)
            if dropped_count > 0:
                logger.info(
                    f"Deduplication complete. Dropped {dropped_count} duplicate rules."
                )

        # Output Generation
        output_file = app_config.output_path or "generated_rules.yar"
        try:
            writer = YaraWriter()
            writer.write(rules, Path(output_file))
            if rules:
                logger.info(f"Generation complete. Created {len(rules)} rules.")
            else:
                logger.warning("Generation complete, but NO rules were created.")
        except OSError as e:
            logger.error(f"Failed to write output file '{output_file}': {e}")
            sys.exit(1)

    except ConfigurationError as e:
        logger.error(f"Configuration Error: {e}")
        sys.exit(1)
    except Exception:
        logger.exception("An unexpected critical error occurred")
        sys.exit(1)
