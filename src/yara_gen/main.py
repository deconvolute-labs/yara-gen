from yara_gen.cli import parse_args
from yara_gen.commands import generate, prepare
from yara_gen.utils.logger import setup_logger


def main() -> None:
    """
    Main application orchestrator.
    """
    args = parse_args()

    log_level = "DEBUG" if args.verbose else "INFO"
    logger = setup_logger(level=log_level)
    logger.debug(f"Logger initialized in {log_level} mode")

    # Dispatch logic
    if args.command == "prepare":
        prepare.run(args)
    elif args.command == "generate":
        generate.run(args)


if __name__ == "__main__":
    main()
