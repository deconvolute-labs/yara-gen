import argparse

from yara_gen.commands import generate, prepare


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

    subparsers = parser.add_subparsers(
        dest="command", required=True, help="Available commands"
    )

    prepare.register_args(subparsers)
    generate.register_args(subparsers)

    return parser.parse_args()
