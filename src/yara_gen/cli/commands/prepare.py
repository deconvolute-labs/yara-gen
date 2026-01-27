from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from yara_gen.adapters import ADAPTER_MAP, get_adapter
from yara_gen.constants import AdapterType
from yara_gen.errors import ConfigurationError, DataError
from yara_gen.models.text import DatasetType
from yara_gen.utils.args import parse_filter_arg
from yara_gen.utils.config import apply_overrides
from yara_gen.utils.logger import get_logger, log_run_config
from yara_gen.utils.stream import filter_stream

logger = get_logger()


def register_args(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    parents: list[argparse.ArgumentParser],
) -> None:
    available_adapters = ", ".join(sorted(ADAPTER_MAP.keys()))

    parser = subparsers.add_parser(
        "prepare",
        help="Ingest a large dataset and normalize it into optimized JSONL format.",
        parents=parents,
    )

    parser.add_argument(
        "input",
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

    # Initialize empty config structure for the adapter
    config: dict[str, Any] = {"adapter": {}}

    # Apply Dot-Notation Overrides (--set adapter.config_name=foo)
    try:
        config = apply_overrides(config, getattr(args, "set", None))
    except ConfigurationError as e:
        logger.error(f"Configuration Error: {e}")
        sys.exit(1)

    # Extract the dictionary specifically for the adapter
    adapter_kwargs = config.get("adapter", {})

    log_run_config(logger, args, {"adapter_kwargs": adapter_kwargs})
    logger.debug(f"Using config: {config}")
    logger.debug(f"Using adapter args: {adapter_kwargs}")
    logger.info(f"Preparing data from {args.input} using adapter '{args.adapter}' ...")

    try:
        # Initialize Adapter
        # Catch ValueError if the adapter name is typo-ed
        try:
            adapter = get_adapter(args.adapter, DatasetType.RAW)
        except ValueError as e:
            logger.error(f"Adapter selection failed: {e}")
            sys.exit(1)

        # Load stream
        # Catch DataError if the file is missing or HF is down
        try:
            stream = adapter.load(args.input, **adapter_kwargs)
        except (DataError, FileNotFoundError) as e:
            logger.error(f"Data Loading Error: {e}")
            sys.exit(1)

        # Apply Universal Filter
        if filter_col and filter_val:
            stream = filter_stream(stream, filter_col, filter_val)

        # Open Output & Stream
        count = 0
        # Ensure parent dir exists
        args.output.parent.mkdir(parents=True, exist_ok=True)

        with args.output.open("w", encoding="utf-8") as f:
            for sample in stream:
                line = json.dumps(sample.to_dict(), ensure_ascii=False)
                f.write(line + "\n")
                count += 1

                if count % 1000 == 0:
                    logger.debug(f"Processed {count} samples ...")

                if args.limit and count >= args.limit:
                    logger.info(f"Reached limit of {args.limit} samples.")
                    break

        logger.info(f"Successfully wrote {count} samples to {args.output}")

    except OSError as e:
        logger.error(f"File I/O Error: {e}")
        sys.exit(1)
    except DataError as e:
        logger.error(f"Processing Error: {e}")
        sys.exit(1)
    except Exception:
        logger.exception("An unexpected critical error occurred")
        sys.exit(1)
