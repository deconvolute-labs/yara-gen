from datetime import datetime
from pathlib import Path

from yara_gen.cli.args import parse_args
from yara_gen.cli.commands import generate, prepare
from yara_gen.utils.config import load_config
from yara_gen.utils.logger import log_header, setup_logger


def main() -> None:
    """
    Main application entry point.

    Orchestrates argument parsing, logger initialization, and command dispatch.
    Determines log filenames dynamically based on the input source (CLI arg or Config).
    """
    args = parse_args()

    # Construct log filename
    # Schema: logs_<command>_<input_path name only>_<timestamp>.log
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    input_name = "unknown"

    # Try CLI input first
    if hasattr(args, "input") and args.input:
        input_name = args.input.name

    # Fallback: If generating, peek at the config file for a name
    elif args.command == "generate":
        # We default to generation_config.yaml if not specified
        cfg_path = getattr(args, "config", Path("generation_config.yaml"))
        if cfg_path.exists():
            try:
                # Lightweight load just to get a label
                raw_cfg = load_config(cfg_path)
                adv_cfg = raw_cfg.get("adversarial_adapter", {})

                # Prioritize a specific config name (common in HF), else adapter type
                input_name = adv_cfg.get(
                    "config_name", adv_cfg.get("type", "batch_run")
                )
            except Exception:
                # If config load fails here, we ignore it, generate.py will handle the
                # error properly
                input_name = "batch_run"

    # Sanitize name (remove extension if present, though unlikely for config keys)
    safe_name = input_name.split(".")[0]
    log_filename = f"logs_{args.command}_{safe_name}_{timestamp}.log"
    log_path = f"logs/{log_filename}"

    log_level = "DEBUG" if getattr(args, "verbose", False) else "INFO"
    logger = setup_logger(level=log_level, log_file=log_path)

    # Logs
    if args.command == "prepare":
        log_header(logger, title="YARA Gen - Data Preparation")
    elif args.command == "generate":
        log_header(logger, title="YARA Gen - Rule Generation")
    logger.debug(f"Logger initialized in {log_level} mode")
    logger.info(f"Logging to file: {log_path}")

    # Dispatch logic
    if args.command == "prepare":
        prepare.run(args)
    elif args.command == "generate":
        generate.run(args)


if __name__ == "__main__":
    main()
