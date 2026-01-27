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
) -> None:
    available_adapters = ", ".join(sorted(ADAPTER_MAP.keys()))

    parser = subparsers.add_parser(
        "generate",
        help="Extract signatures from adversarial inputs and generate YARA rules.",
    )

    parser.add_argument(
        "input_path", type=Path, nargs="?", help="Path to the adversarial dataset"
    )

    # Note: Defaults are set to None to allow config.yaml to take precedence
    # unless the user explicitly provides the flag.

    parser.add_argument(
        "--adapter",
        "-a",
        type=str,
        help=(
            f"Adapter for adversarial input. Options: [{available_adapters}] "
            "(overrides config)"
        ),
    )

    parser.add_argument(
        "--benign",
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
        "--existing-rules",
        "-e",
        type=Path,
        help="Path to existing .yar rules for deduplication",
    )

    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Path to save the generated .yar file (overrides config)",
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
        # 1. Load Base Config from YAML
        # args.config comes from the parent parser in cli/args.py
        config_path = args.config
        logger.info(f"Loading configuration from: {config_path}")

        # Load raw dict; empty if file missing (handled in load_config defaults/errors)
        raw_config = load_config(config_path)

        # 2. Apply Dot-Notation Overrides (--set)
        # e.g. --set engine.min_ngram=4
        raw_config = apply_overrides(raw_config, args.set)

        # 3. Apply Explicit CLI Argument Overrides
        # We manually map top-level CLI args to the config structure
        if args.output:
            raw_config["output_path"] = str(args.output)

        # Adversarial Adapter Overrides
        if "adversarial_adapter" not in raw_config:
            raw_config["adversarial_adapter"] = {}
        if args.adapter:
            raw_config["adversarial_adapter"]["type"] = args.adapter

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

        # 4. Validate & Instantiate AppConfig
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
        logger.info(f"Starting generation with Engine: {engine_type}")

        # 5. Initialize Components
        try:
            # Engine
            engine = get_engine(engine_type, app_config.engine)

            # Adversarial Data
            # Note: Input path can come from CLI or Config (though CLI arg input_path
            # is usually required for file adapters)
            adv_path = (
                args.input_path
            )  # CLI input path takes priority if we had a config field for it
            if not adv_path:
                raise ConfigurationError("No input path provided (via CLI argument).")

            logger.info(f"Loading adversarial data: {adv_path}")
            adv_adapter = get_adapter(adv_adapter_type, DatasetType.ADVERSARIAL)
            # We pass the whole adapter config as kwargs so 'config_name', 'split'
            # etc. are passed through
            adv_stream = adv_adapter.load(
                adv_path, **app_config.adversarial_adapter.model_dump(exclude={"type"})
            )

            # Benign Data
            benign_path = args.benign
            if not benign_path:
                raise ConfigurationError("No benign dataset path provided (--benign).")

            logger.info(f"Loading benign data: {benign_path}")
            benign_adapter = get_adapter(benign_adapter_type, DatasetType.BENIGN)
            benign_stream = benign_adapter.load(
                benign_path, **app_config.benign_adapter.model_dump(exclude={"type"})
            )

            # Execution
            rules = engine.extract(adversarial=adv_stream, benign=benign_stream)

            # Post-Processing: Apply Tags
            if args.tags:
                logger.debug(f"Applying tags to {len(rules)} rules: {args.tags}")
                for rule in rules:
                    # Assuming rule.tags is a list/set of strings
                    rule.tags.extend(args.tags)

            # Deduplication
            if args.existing_rules and args.existing_rules.exists():
                logger.info(
                    f"Deduplicating against existing rules: {args.existing_rules}"
                )
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
                        f"Deduplication complete. Dropped {dropped_count} "
                        "duplicate rules."
                    )

            # Output Generation
            output_file = app_config.output_path or "generated_rules.yar"
            writer = YaraWriter()
            writer.write(rules, Path(output_file))

            if rules:
                logger.info(f"Generation complete. Created {len(rules)} rules.")
            else:
                logger.warning("Generation complete, but NO rules were created.")

        except (ValueError, FileNotFoundError) as e:
            raise DataError(f"Data processing failed: {str(e)}") from e

    except (ConfigurationError, DataError) as e:
        logger.error(f"{e.__class__.__name__}: {str(e)}")
        sys.exit(1)
    except Exception:
        logger.exception("An unexpected error occurred.")
        sys.exit(1)
