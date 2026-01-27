from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from yara_gen.adapters import ADAPTER_MAP, get_adapter
from yara_gen.constants import AdapterType
from yara_gen.errors import ConfigurationError, DataError
from yara_gen.models.config import AdapterConfig
from yara_gen.models.text import DatasetType
from yara_gen.utils.args import parse_filter_arg
from yara_gen.utils.config import apply_overrides
from yara_gen.utils.logger import (
    get_logger,
    log_config,
    log_named_value,
)
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

    # Initialize configuration structure
    # We start with the CLI arg for the type
    raw_config: dict[str, Any] = {"type": args.adapter}

    # Apply Dot-Notation Overrides (--set adapter.config_name=foo)
    try:
        raw_config = apply_overrides(raw_config, getattr(args, "set", None))
        if "adapter" in raw_config and isinstance(raw_config["adapter"], dict):
            raw_config.update(raw_config.pop("adapter"))
    except ConfigurationError as e:
        logger.error(f"Configuration Error: {e}")
        sys.exit(1)

    try:
        adapter_config = AdapterConfig(**raw_config)
    except Exception as e:
        logger.error(f"Adapter Configuration Error: {e}")
        sys.exit(1)

    log_named_value(logger, "Input", args.input)
    log_named_value(logger, "Output", args.output)

    if args.limit:
        log_named_value(logger, "Limit", args.limit)
    if filter_col:
        log_named_value(logger, "Filter", f"{filter_col} == {filter_val}")

    log_config(logger, adapter_config.model_dump())

    logger.info(
        f"Preparing data from {args.input} using adapter '{adapter_config.type}' ..."
    )

    try:
        try:
            adapter = get_adapter(args.adapter, DatasetType.RAW)
        except ValueError as e:
            logger.error(f"Adapter selection failed: {e}")
            sys.exit(1)

        try:
            # We exclude 'type' because load() usually expects kwargs for the internal
            # logic (like chunk_size, delimiter, etc), not the factory type string.
            load_kwargs = adapter_config.model_dump(exclude={"type"})
            stream = adapter.load(args.input, **load_kwargs)
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
