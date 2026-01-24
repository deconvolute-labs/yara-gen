import logging
import sys

LOG_FORMAT = "[%(levelname)s] %(asctime)s %(message)s"
DATE_FORMAT = "%H:%M:%S"


def setup_logger(name: str = "yara-gen", level: str = "INFO") -> logging.Logger:
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

    # Add Handler
    logger.addHandler(console_handler)

    return logger


def get_logger(name: str = "yara-rule-gen") -> logging.Logger:
    """
    Helper to get the logger in other modules without re-configuring.
    """
    return logging.getLogger(name)
