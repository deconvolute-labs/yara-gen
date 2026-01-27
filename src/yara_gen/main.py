from datetime import datetime

from yara_gen.cli.args import parse_args
from yara_gen.cli.commands import generate, prepare
from yara_gen.utils.logger import setup_logger


def main() -> None:
    """
    Main application orchestrator.
    """
    args = parse_args()

    # Construct Log Filename
    # Schema: logs_<command>_<input_path name only>_<timestamp>.log
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    input_name = "unknown"
    if hasattr(args, "input_path") and args.input_path:
        input_name = args.input_path.name

    log_filename = f"logs_{args.command}_{input_name.split('.')[0]}_{timestamp}.log"
    log_path = f"logs/{log_filename}"

    log_level = "DEBUG" if getattr(args, "verbose", False) else "INFO"
    logger = setup_logger(level=log_level, log_file=log_path)
    logger.debug(f"Logger initialized in {log_level} mode")
    logger.info(f"Logging to file: {log_path}")

    # Dispatch logic
    if args.command == "prepare":
        prepare.run(args)
    elif args.command == "generate":
        generate.run(args)


if __name__ == "__main__":
    main()
