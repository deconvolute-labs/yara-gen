from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from yara_gen.adapters import ADAPTER_MAP, get_adapter
from yara_gen.constants import AdapterType
from yara_gen.models.text import DatasetType
from yara_gen.utils.args import parse_filter_arg
from yara_gen.utils.logger import get_logger, log_run_config
from yara_gen.utils.stream import filter_stream

logger = get_logger()


def register_args(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    available_adapters = ", ".join(sorted(ADAPTER_MAP.keys()))

    parser = subparsers.add_parser(
        "prepare",
        help="Ingest a large dataset and normalize it into optimized JSONL format.",
    )

    parser.add_argument(
        "input_path",
        type=Path,
        help="Path to the raw source file (XML, CSV, TXT, etc.)",
    )

    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        required=True,
        help="Path to save the clean .jsonl file",
    )

    parser.add_argument(
        "--adapter",
        "-a",
        type=str,
        default=AdapterType.RAW_TEXT.value,
        help=(
            f"The parsing logic to use. Options: [{available_adapters}] "
            f"(default: {AdapterType.RAW_TEXT.value})"
        ),
    )

    parser.add_argument(
        "--config-name",
        type=str,
        help=(
            "Configuration name for datasets with multiple subsets "
            "(e.g. HuggingFace configs)."
        ),
    )

    parser.add_argument(
        "--limit",
        type=int,
        help="Limit the number of samples to process (useful for debugging).",
    )

    parser.add_argument(
        "--filter",
        type=str,
        help="Filter data in 'column=value' format (e.g. 'label=1').",
    )


def run(args: argparse.Namespace) -> None:
    """Executes the prepare command logic."""
    try:
        filter_col, filter_val = parse_filter_arg(args.filter)
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)

    log_run_config(logger, args)

    logger.info(
        f"Preparing data from {args.input_path} using adapter '{args.adapter}'..."
    )
    # Initialize Adapter (forcing RAW type)
    try:
        adapter = get_adapter(args.adapter, DatasetType.RAW)
        stream = adapter.load(args.input_path, config_name=args.config_name)

        # Apply Universal Filter
        if filter_col and filter_val:
            stream = filter_stream(stream, filter_col, filter_val)
    except Exception as e:
        logger.exception(f"Failed to initialize adapter: {e}")
        sys.exit(1)

    # Open Output & Stream
    count = 0
    try:
        # Ensure parent dir exists
        args.output.parent.mkdir(parents=True, exist_ok=True)

        with args.output.open("w", encoding="utf-8") as f:
            for sample in stream:
                line = json.dumps(sample.to_dict(), ensure_ascii=False)
                f.write(line + "\n")
                count += 1

                if count % 5000 == 0:
                    logger.debug(f"Processed {count} samples...")

                if args.limit and count >= args.limit:
                    logger.info(f"Reached limit of {args.limit} samples.")
                    break

        logger.info(f"Successfully wrote {count} samples to {args.output}")

    except Exception:
        # Using exception logger as requested to allow stack trace
        logger.exception("Failed during preparation")
        sys.exit(1)
