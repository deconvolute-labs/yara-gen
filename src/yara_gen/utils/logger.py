import argparse
import logging
import sys
from typing import Any

from yara_gen.constants import LOGGER_NAME

LOG_FORMAT = "[%(levelname)s] %(asctime)s %(message)s"
DATE_FORMAT = "%H:%M:%S"


def setup_logger(
    name: str = LOGGER_NAME, level: str = "INFO", log_file: str | None = None
) -> logging.Logger:
    """
    Configures and returns a centralized logger.
    """
    logger = logging.getLogger(name)

    # If logger already has handlers, assume it's set up and return it
    # (Prevents duplicate logs if called multiple times)
    if logger.handlers:
        return logger

    # Set Level
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    # Create Console Handler (Standard Output)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)

    # Create Formatter
    formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)
    console_handler.setFormatter(formatter)

    # Add Console Handler
    logger.addHandler(console_handler)

    # Create File Handler if requested
    if log_file:
        from pathlib import Path

        file_path = Path(log_file)
        file_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(file_path, encoding="utf-8")
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str = LOGGER_NAME) -> logging.Logger:
    """
    Helper to get the logger in other modules without re-configuring.
    """
    return logging.getLogger(name)


def log_run_config(
    logger: logging.Logger,
    args: argparse.Namespace,
    extra_info: dict[str, Any] | None = None,
) -> None:
    """
    Logs the program banner and configuration parameters in a formatted box.
    """
    width = 60
    border = "+" + "-" * (width - 2) + "+"

    def log_line(content: str, center: bool = False) -> None:
        if center:
            logger.info(f"| {content.center(width - 4)} |")
        else:
            logger.info(f"| {content.ljust(width - 4)} |")

    logger.info(border)
    log_line("YARA Gen", center=True)
    logger.info("|" + "-" * (width - 2) + "|")  # Separator

    config_items = vars(args).copy()
    if extra_info:
        config_items.update(extra_info)

    filtered_items = {
        k: v for k, v in config_items.items() if k not in ["command", "func"]
    }

    if filtered_items:
        log_line("Configuration", center=True)
        logger.info("|" + "-" * (width - 2) + "|")  # Separator

        for key, value in sorted(filtered_items.items()):
            # Format Key
            key_str = key.replace("_", " ").title()

            # Format Value
            val_str = str(value)
            if len(val_str) > 33:  # Wrap/Truncate if too long (simple approach)
                val_str = val_str[:30] + "..."

            logger.info(f"| {key_str:<20}: {val_str:<33} |")

    logger.info(border)
