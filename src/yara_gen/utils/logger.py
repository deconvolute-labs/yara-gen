import json
import logging
import sys
from typing import Any

from yara_gen.constants import LOGGER_NAME, META_AUTHOR

LOG_FORMAT = "[%(levelname)s] %(asctime)s %(message)s"
DATE_FORMAT = "%H:%M:%S"


def setup_logger(
    name: str = LOGGER_NAME, level: str = "INFO", log_file: str | None = None
) -> logging.Logger:
    """
    Configures the application-wide logger with console and optional file handlers.

    Sets the global logging level to DEBUG to capture all events, while allowing
    individual handlers to filter based on the provided `level`.

    Args:
        level (str): The logging level for the console handler (e.g. "INFO", "DEBUG").
            Defaults to "INFO".
        log_file (str | None): Optional path to a file where logs should be saved.
            File logs are always written at DEBUG level.

    Returns:
        logging.Logger: The configured logger instance.
    """
    logger = logging.getLogger(name)

    # If logger already has handlers, assume it's set up and return it
    # (Prevents duplicate logs if called multiple times)
    if logger.handlers:
        return logger

    # Set level
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    # Create console handler (standard output)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)

    # Create formatter
    formatter = logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT)
    console_handler.setFormatter(formatter)

    # Add console handler
    logger.addHandler(console_handler)

    # Create file handler if requested
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
    Retrieves the existing application-wide logger instance.

    Returns:
        logging.Logger: The logger instance associated with the constant LOGGER_NAME.
    """
    return logging.getLogger(name)


def log_header(logger: logging.Logger, title: str = "YARA Gen") -> None:
    """
    Logs a stylized ASCII header box to visually delineate run sections.

    Args:
        logger (logging.Logger): The logger instance to use.
        title (str): The title text to display centered within the header box.
            Defaults to "YARA Gen".
    """
    width = 60
    border = "+" + "=" * (width - 2) + "+"

    # Center the title
    padded_title = f"{title}".center(width - 4)
    padded_author = f"by {META_AUTHOR}".center(width - 4)

    logger.info(border)
    logger.info(f"| {padded_title} |")
    logger.info(f"| {padded_author} |")
    logger.info(border)


def log_named_value(logger: logging.Logger, key: str, value: Any) -> None:
    """
    Logs a key-value pair in a consistent, aligned format.

    Useful for printing startup parameters or summary statistics
    (e.g. "Input : data.txt").

    Args:
        logger (logging.Logger): The logger instance to use.
        key (str): The label for the value (will be padded for alignment).
        value (Any): The value to display.
    """
    # Just a simple consistent alignment
    logger.info(f"{key:<12}: {value}")


def log_config(logger: logging.Logger, config: dict[str, Any]) -> None:
    """
    Logs a configuration dictionary as a formatted, pretty-printed JSON string.

    Args:
        logger (logging.Logger): The logger instance to use.
        config (dict[str, Any]): The dictionary containing configuration data to log.
    """
    logger.info("Configuration:")
    logger.info(json.dumps(config, indent=2, default=str))
