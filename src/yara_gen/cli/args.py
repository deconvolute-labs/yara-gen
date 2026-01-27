import argparse
from pathlib import Path

from yara_gen.cli.commands import generate, prepare


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Automated YARA rule generator for indirect prompt injection defense."
        ),
        prog="yara-rule-gen",
    )

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose debug logging"
    )

    # Global Configuration Arguments
    parser.add_argument(
        "--config",
        "-c",
        type=Path,
        default=Path("config.yaml"),
        help="Path to the configuration YAML file (default: config.yaml)",
    )

    parser.add_argument(
        "--set",
        "-s",
        action="append",
        help="Override config values using dot notation (e.g. 'engine.min_ngram=4')",
    )

    subparsers = parser.add_subparsers(
        dest="command", required=True, help="Available commands"
    )

    prepare.register_args(subparsers)
    generate.register_args(subparsers)

    return parser.parse_args()
