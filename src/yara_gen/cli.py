import argparse
from pathlib import Path

from yara_gen.adapters import ADAPTER_MAP


def parse_filter_arg(filter_str: str | None) -> tuple[str | None, str | None]:
    """Helper to parse 'col=val' string."""
    if not filter_str:
        return None, None
    if "=" not in filter_str:
        raise ValueError("Filter must be in 'column=value' format (e.g. 'label=1')")
    key, val = filter_str.split("=", 1)
    return key.strip(), val.strip()


def parse_args() -> argparse.Namespace:
    available_adapters = ", ".join(sorted(ADAPTER_MAP.keys()))

    parser = argparse.ArgumentParser(
        description=(
            "Automated YARA rule generator for indirect prompt injection defense."
        ),
        prog="yara-rule-gen",
    )

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose debug logging"
    )

    subparsers = parser.add_subparsers(
        dest="command", required=True, help="Available commands"
    )

    # Command: PREPARE
    parser_prepare = subparsers.add_parser(
        "prepare",
        help="Ingest a large dataset and normalize it into optimized JSONL format.",
    )

    parser_prepare.add_argument(
        "input_path",
        type=Path,
        help="Path to the raw source file (XML, CSV, TXT, etc.)",
    )

    parser_prepare.add_argument(
        "--output",
        "-o",
        type=Path,
        required=True,
        help="Path to save the clean .jsonl file",
    )

    parser_prepare.add_argument(
        "--adapter",
        "-a",
        type=str,
        default="raw-text",
        help=(
            f"The parsing logic to use. Options: [{available_adapters}] "
            "(default: raw-text)"
        ),
    )

    parser_prepare.add_argument(
        "--config-name",
        type=str,
        help=(
            "Configuration name for datasets with multiple subsets "
            "(e.g. HuggingFace configs)."
        ),
    )

    parser_prepare.add_argument(
        "--limit",
        type=int,
        help="Limit the number of samples to process (useful for debugging).",
    )

    parser_prepare.add_argument(
        "--filter",
        type=str,
        help="Filter data in 'column=value' format (e.g. 'label=1').",
    )

    # Command: GENERATE
    parser_generate = subparsers.add_parser(
        "generate",
        help="Extract signatures from adversarial inputs and generate YARA rules.",
    )

    parser_generate.add_argument(
        "input_path", type=Path, help="Path to the adversarial dataset"
    )

    parser_generate.add_argument(
        "--adapter",
        "-a",
        type=str,
        default="jsonl",
        help=(
            f"Adapter for adversarial input. Options: [{available_adapters}] "
            "(default: jsonl)"
        ),
    )

    parser_generate.add_argument(
        "--config-name",
        type=str,
        help="Configuration name for adversarial dataset (e.g. HuggingFace configs).",
    )

    parser_generate.add_argument(
        "--benign", "-b", type=Path, required=True, help="Path to the control dataset"
    )

    parser_generate.add_argument(
        "--benign-adapter",
        "-ba",
        type=str,
        default="jsonl",
        help=(
            f"Adapter for benign input. Options: [{available_adapters}] "
            "(default: jsonl)"
        ),
    )

    parser_generate.add_argument(
        "--existing-rules",
        "-e",
        type=Path,
        help="Path to existing .yar rules for deduplication",
    )

    parser_generate.add_argument(
        "--output",
        "-o",
        type=Path,
        required=True,
        help="Path to save the generated .yar file",
    )

    parser_generate.add_argument(
        "--engine",
        choices=["ngram", "stub"],  # 'stub' is our current placeholder
        default="ngram",
        help="The algorithm used to generate rules (default: ngram)",
    )

    # Engine-specific args (N-Gram)
    # We leave these global for now. In main.py we only use them if engine='ngram'.
    parser_generate.add_argument(
        "--min-ngram", type=int, default=3, help="[N-Gram Engine] Minimum token length"
    )

    parser_generate.add_argument(
        "--max-ngram", type=int, default=10, help="[N-Gram Engine] Maximum token length"
    )

    parser_generate.add_argument(
        "--mode",
        choices=["strict", "loose"],
        default="strict",
        help="Sensitivity threshold (default: strict)",
    )

    parser_generate.add_argument(
        "--tag",
        action="append",
        dest="tags",
        help="Custom tags to add to generated rules (can be used multiple times)",
    )

    parser_generate.add_argument(
        "--filter",
        type=str,
        help=(
            "Filter applied to adversarial data in 'column=value' format "
            "(e.g. 'label=1')."
        ),
    )

    return parser.parse_args()
