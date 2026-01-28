from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from yara_gen.adapters import ADAPTER_MAP, get_adapter
from yara_gen.adapters.utils import filter_stream
from yara_gen.cli.utils import parse_filter_arg
from yara_gen.constants import AdapterType
from yara_gen.errors import ConfigurationError, DataError
from yara_gen.models.adapter_config import AdapterConfig
from yara_gen.models.config import PrepareConfig
from yara_gen.models.text import DatasetType, TextSample
from yara_gen.utils.config import apply_overrides
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
        default=None,
        help=(f"The parsing logic to use. Options: [{available_adapters}]"),
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


def _get_adapter_type(args: argparse.Namespace) -> str:
    """
    Detects adapter type from arguments or file extension.
    """
    if args.adapter is not None:
        return str(args.adapter)

    if args.input.exists():
        # It's a local file; check extension for JSONL, otherwise fallback to raw
        if args.input.suffix.lower() == ".jsonl":
            adapter_type = AdapterType.JSONL.value
        else:
            adapter_type = AdapterType.RAW_TEXT.value
        logger.info(f"Auto-detected local adapter: {adapter_type}")
    else:
        # It's not a file, assume it's a Hugging Face repo ID
        adapter_type = AdapterType.HUGGINGFACE.value
        logger.info(
            f"Input '{args.input}' not found locally. "
            f"Defaulting to adapter: {adapter_type}"
        )
    return adapter_type


def _build_configuration(args: argparse.Namespace) -> PrepareConfig:
    """
    Builds and validates the configuration.
    """
    adapter_type = _get_adapter_type(args)

    # Initialize configuration structure
    raw_config: dict[str, Any] = {"adapter": {"type": adapter_type}}

    # Apply Dot-Notation Overrides (--set adapter.config_name=foo)
    try:
        raw_config = apply_overrides(raw_config, getattr(args, "set", None))
    except ConfigurationError as e:
        logger.error(f"Configuration Error: {e}")
        sys.exit(1)

    try:
        return PrepareConfig(**raw_config)
    except Exception as e:
        logger.error(f"Adapter Configuration Error: {e}")
        sys.exit(1)
        raise  # Should handle sys.exit in caller or here clearly


def _get_dataset_stream(
    input_path: Path, adapter_config: AdapterConfig
) -> Iterator[TextSample]:
    """
    Initializes adapter and loads the data stream.
    """
    try:
        adapter = get_adapter(adapter_config.type, DatasetType.RAW)
    except ValueError as e:
        logger.error(f"Adapter selection failed: {e}")
        sys.exit(1)

    try:
        # We exclude 'type' because load() usually expects kwargs for the internal
        # logic (like chunk_size, delimiter, etc), not the factory type string.
        load_kwargs = adapter_config.model_dump(exclude={"type"})
        return adapter.load(input_path, **load_kwargs)
    except (DataError, FileNotFoundError) as e:
        logger.error(f"Data Loading Error: {e}")
        sys.exit(1)


def _write_output(
    stream: Iterator[TextSample], output_path: Path, limit: int | None
) -> None:
    """
    Writes the stream to the output file.
    """
    try:
        count = 0
        # Ensure parent dir exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open("w", encoding="utf-8") as f:
            for sample in stream:
                line = json.dumps(sample.to_dict(), ensure_ascii=False)
                f.write(line + "\n")
                count += 1

                if count % 1000 == 0:
                    logger.debug(f"Processed {count} samples ...")

                if limit and count >= limit:
                    logger.info(f"Reached limit of {limit} samples.")
                    break

        logger.info(f"Successfully wrote {count} samples to {output_path}")

    except OSError as e:
        logger.error(f"File I/O Error: {e}")
        sys.exit(1)
    except DataError as e:
        logger.error(f"Processing Error: {e}")
        sys.exit(1)


def run(args: argparse.Namespace) -> None:
    """
    Executes the data preparation utility.

    Normalizes various input formats into a clean JSONL dataset.
    """
    try:
        filter_col, filter_val = parse_filter_arg(args.filter)
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)

    prepare_config = _build_configuration(args)
    adapter_config = prepare_config.adapter

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
        stream = _get_dataset_stream(args.input, adapter_config)

        # Apply Universal Filter
        if filter_col and filter_val:
            stream = filter_stream(stream, filter_col, filter_val)

        _write_output(stream, args.output, args.limit)

    except Exception:
        logger.exception("An unexpected critical error occurred")
        sys.exit(1)
