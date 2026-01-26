from __future__ import annotations

import argparse
import sys
from pathlib import Path

from yara_gen.adapters import ADAPTER_MAP, get_adapter
from yara_gen.constants import AdapterType, EngineType, NGramSettings
from yara_gen.extraction.factory import get_extractor
from yara_gen.generation.writer import YaraWriter
from yara_gen.models.config import BaseExtractorConfig, NgramConfig
from yara_gen.models.text import DatasetType
from yara_gen.utils.args import parse_filter_arg
from yara_gen.utils.deduplication import parse_existing_rules
from yara_gen.utils.logger import get_logger, log_run_config
from yara_gen.utils.stream import filter_stream

logger = get_logger()


def register_args(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    available_adapters = ", ".join(sorted(ADAPTER_MAP.keys()))

    parser = subparsers.add_parser(
        "generate",
        help="Extract signatures from adversarial inputs and generate YARA rules.",
    )

    parser.add_argument("input_path", type=Path, help="Path to the adversarial dataset")

    parser.add_argument(
        "--adapter",
        "-a",
        type=str,
        default=AdapterType.JSONL.value,
        help=(
            f"Adapter for adversarial input. Options: [{available_adapters}] "
            f"(default: {AdapterType.JSONL.value})"
        ),
    )

    parser.add_argument(
        "--config-name",
        type=str,
        help="Configuration name for adversarial dataset (e.g. HuggingFace configs).",
    )

    parser.add_argument(
        "--benign", "-b", type=Path, required=True, help="Path to the control dataset"
    )

    parser.add_argument(
        "--benign-adapter",
        "-ba",
        type=str,
        default=AdapterType.JSONL.value,
        help=(
            f"Adapter for benign input. Options: [{available_adapters}] "
            f"(default: {AdapterType.JSONL.value})"
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
        required=True,
        help="Path to save the generated .yar file",
    )

    parser.add_argument(
        "--engine",
        choices=[e.value for e in EngineType],
        default=EngineType.NGRAM.value,
        help=(
            f"The algorithm used to generate rules (default: {EngineType.NGRAM.value})"
        ),
    )

    # Engine-specific args (N-Gram)
    parser.add_argument(
        "--min-ngram", type=int, default=3, help="[N-Gram Engine] Minimum token length"
    )

    parser.add_argument(
        "--max-ngram", type=int, default=10, help="[N-Gram Engine] Maximum token length"
    )

    parser.add_argument(
        "--mode",
        choices=["strict", "loose"],
        default="strict",
        help="Sensitivity threshold (default: strict)",
    )

    parser.add_argument(
        "--tag",
        action="append",
        dest="tags",
        help="Custom tags to add to generated rules (can be used multiple times)",
    )

    parser.add_argument(
        "--filter",
        type=str,
        help=(
            "Filter applied to adversarial data in 'column=value' format "
            "(e.g. 'label=1')."
        ),
    )

    parser.add_argument(
        "--rule-date",
        type=str,
        help=(
            "Fixed date string (e.g. 2023-01-01) for rule metadata to ensure "
            "deterministic builds."
        ),
    )

    parser.add_argument(
        "--threshold",
        type=float,
        help="Override the score threshold (0.0-1.0). Overrides --mode defaults.",
    )

    parser.add_argument(
        "--min-df",
        type=float,
        default=NGramSettings.MIN_DOCUMENT_FREQ,
        help="Minimum document frequency (percentage 0.0-1.0 or integer count).",
    )


def run(args: argparse.Namespace) -> None:
    try:
        filter_col, filter_val = parse_filter_arg(args.filter)
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)

    logger.info(f"Starting generation in {args.mode} mode...")

    # Build the specific Configuration based on Engine selection
    extractor_config: BaseExtractorConfig

    # Determine threshold
    if args.threshold is not None:
        chosen_threshold = args.threshold
    else:
        chosen_threshold = (
            NGramSettings.THRESHOLD_STRICT
            if args.mode == "strict"
            else NGramSettings.THRESHOLD_LOOSE
        )

    thresh_value = (
        chosen_threshold.value
        if isinstance(chosen_threshold, NGramSettings)
        else chosen_threshold
    )

    extra_config = {
        "calculated_threshold": thresh_value,
        "threshold_source": "Override" if args.threshold else "Default",
    }
    log_run_config(logger, args, extra_config)

    if args.engine == EngineType.NGRAM.value:
        logger.debug("Configuring N-Gram Engine parameters...")
        extractor_config = NgramConfig(
            score_threshold=chosen_threshold,
            min_ngram_length=args.min_ngram,
            max_ngram_length=args.max_ngram,
            rule_date=args.rule_date,
            min_document_frequency=args.min_df,
        )
    else:
        # Placeholder for other engines if implemented
        # For now, defaulting to base or erroring if strict checking wasn't done by
        # argparse
        # Stub engine might need config too.
        extractor_config = BaseExtractorConfig(rule_date=args.rule_date)
        if args.engine != EngineType.STUB.value:
            # Should be caught by argparse choices but good for safety
            pass

    try:
        # Adversarial Stream
        logger.info(f"Loading adversarial data from: {args.input_path}")
        adv_adapter = get_adapter(args.adapter, DatasetType.ADVERSARIAL)
        adv_stream = adv_adapter.load(args.input_path, config_name=args.config_name)

        # Apply Universal Filter
        if filter_col and filter_val:
            adv_stream = filter_stream(adv_stream, filter_col, filter_val)

        logger.info(f"Loading benign data from: {args.benign}")
        benign_adapter = get_adapter(args.benign_adapter, DatasetType.BENIGN)
        benign_stream = benign_adapter.load(args.benign)

        # Extraction
        logger.info(f"Initializing extraction engine: {args.engine}")
        extractor = get_extractor(args.engine, extractor_config)
        rules = extractor.extract(adversarial=adv_stream, benign=benign_stream)

        # Deduplication
        if args.existing_rules:
            if args.existing_rules.exists():
                logger.info(
                    f"Deduplicating against existing rules: {args.existing_rules}"
                )
                existing_payloads = parse_existing_rules(args.existing_rules)

                initial_count = len(rules)
                # Filter out rules where ANY of their strings exist in the known set
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
                else:
                    logger.debug("Deduplication complete. No duplicates found.")
            else:
                logger.warning(
                    f"Existing rules file not found: {args.existing_rules}. "
                    "Skipping deduplication."
                )

        # Output Generation
        writer = YaraWriter()
        writer.write(rules, args.output)

        if rules:
            logger.info(f"Generation complete. Created {len(rules)} rules.")
        else:
            logger.warning("Generation complete, but NO rules were created.")
    except Exception:
        logger.exception("Generation failed")
        sys.exit(1)
