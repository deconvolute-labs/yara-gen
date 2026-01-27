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
    width = 80
    border = "+" + "-" * (width - 2) + "+"

    def log_line(content: str, center: bool = False) -> None:
        if center:
            logger.info(f"| {content.center(width - 4)} |")
        else:
            # Check if content fits directly
            if len(content) <= width - 4:
                logger.info(f"| {content.ljust(width - 4)} |")
            else:
                # Basic wrapping if a single line is too long (though recursive format handles most)
                logger.info(f"| {content[: width - 7]}... |")

    def format_value(key: str, value: Any, level: int = 0) -> list[str]:
        """
        Recursively formats values into a list of strings for display.
        """
        lines = []
        indent = "  " * level
        key_width = 20 - (len(indent))  # Adjust key width based on indent
        if key_width < 5:
            key_width = 5

        # Format Key (only for top level or dict keys)
        if key:
            key_str = key.replace("_", " ").title()
            prefix = f"{indent}{key_str:<{key_width}}: "
        else:
            prefix = f"{indent}- "

        if isinstance(value, dict):
            if key:
                lines.append(f"{indent}{key_str}")
            for k, v in value.items():
                lines.extend(format_value(k, v, level + 1))

        elif isinstance(value, (list, tuple, set)):
            # If it's a simple list of primitives, try to keep it compact?
            # User check: "list for example for the ADapter Keywords... show all variables"
            # Let's print them one per line if they are strings, effectively
            if key:
                lines.append(f"{indent}{key_str}:")
            for item in value:
                # Lists just get bullet points
                lines.extend(format_value("", item, level + 1))

        else:
            # Primitive values
            val_str = str(value)
            # If it's a list item (no key), just the value
            if not key:
                lines.append(f"{indent}{val_str}")
            else:
                lines.append(f"{prefix}{val_str}")

        return lines

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
            formatted_lines = format_value(key, value)
            for line in formatted_lines:
                # Ensure we don't exceed the box width logic in log_line
                # We construct the full content string here, log_line handles the border
                log_line(line)

    logger.info(border)
