import argparse
from pathlib import Path

from yara_gen.cli.commands import generate, prepare


def parse_args() -> argparse.Namespace:
    """
    Parses command-line arguments for the global application.

    Defines shared arguments (verbose, config, set) and registers
    sub-commands (prepare, generate).

    Returns:
        argparse.Namespace: The populated argument namespace containing
        both global flags and command-specific parameters.
    """
    shared_parser = argparse.ArgumentParser(add_help=False)

    shared_parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Enable verbose debug logging",
    )

    shared_parser.add_argument(
        "--config",
        "-c",
        type=Path,
        default=argparse.SUPPRESS,
        help="Path to the configuration YAML file (default: generation_config.yaml)",
    )

    shared_parser.add_argument(
        "--set",
        "-s",
        action="append",
        default=argparse.SUPPRESS,
        help="Override config values using dot notation (e.g. 'engine.min_ngram=4')",
    )

    parser = argparse.ArgumentParser(
        description=(
            "Automated YARA rule generator for indirect prompt injection defense."
        ),
        prog="yara-rule-gen",
        parents=[shared_parser],
    )

    subparsers = parser.add_subparsers(
        dest="command", required=True, help="Available commands"
    )

    prepare.register_args(subparsers, parents=[shared_parser])
    generate.register_args(subparsers, parents=[shared_parser])

    return parser.parse_args()
