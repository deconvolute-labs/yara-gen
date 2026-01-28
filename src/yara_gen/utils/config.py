import copy
from pathlib import Path
from typing import Any

import yaml

from yara_gen.errors import ConfigurationError


def load_config(path: Path) -> dict[str, Any]:
    """
    Load and parse a YAML configuration file.

    Args:
        path (Path): The filesystem path to the YAML configuration file.

    Returns:
        dict[str, Any]: A dictionary containing the configuration data.
            Returns an empty dictionary if the source file is empty.

    Raises:
        ConfigurationError: If the file does not exist or contains invalid YAML syntax.
    """
    if not path.exists():
        raise ConfigurationError(f"Configuration file not found: {path}")

    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
            return data if data else {}
    except yaml.YAMLError as e:
        raise ConfigurationError(f"Invalid YAML format in {path}: {e}") from e


def _parse_value(value: str) -> str | int | float | bool:
    """
    Attempt to parse a CLI string value into a native Python type.

    This helper function is used to convert command-line override strings
    into their appropriate types (Boolean, Integer, Float) before applying
    them to the configuration dictionary.

    Args:
        value (str): The string value received from the command line.

    Returns:
        str | int | float | bool: The value converted to the most specific
            matching type, or the original string if no conversion is possible.
    """
    # Boolean
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False

    # Integer
    if value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
        return int(value)

    # Float
    try:
        return float(value)
    except ValueError:
        pass

    # Default to String
    return value


def apply_overrides(
    config: dict[str, Any], overrides: list[str] | None
) -> dict[str, Any]:
    """
    Apply dot-notation overrides to a configuration dictionary.

    This function processes a list of override strings (e.g. 'engine.min_ngram=4')
    and updates the provided configuration dictionary. It supports creating
    deeply nested structures if they do not already exist.

    Args:
        config (dict[str, Any]): The base configuration dictionary (usually
            loaded from YAML).
        overrides (list[str] | None): A list of strings in 'key.subkey=value' format.
                If None or empty, the original config is returned.

    Returns:
        dict[str, Any]: A deep copy of the configuration dictionary with overrides
            applied.

    Raises:
        ConfigurationError: If an override string is malformed or if a path traversal
            conflict occurs (e.g. trying to set a child key on a value that is not a
            dictionary).
    """
    if not overrides:
        return config

    # Deep copy to ensure we don't mutate the original dictionary reference
    updated_config = copy.deepcopy(config)

    for override in overrides:
        if "=" not in override:
            raise ConfigurationError(
                f"Invalid override format: '{override}'. Expected 'key.subkey=value'."
            )

        key_path, value_str = override.split("=", 1)
        keys = key_path.split(".")
        value = _parse_value(value_str)

        # Traverse and create structure
        current_level = updated_config
        for _, key in enumerate(keys[:-1]):
            if key not in current_level:
                current_level[key] = {}

            if not isinstance(current_level[key], dict):
                # If we encounter a non-dict at an intermediate step, we can't
                # traverse deeper. Example: config['a'] = 1, override is 'a.b=2'
                raise ConfigurationError(
                    f"Cannot set '{key_path}': '{key}' is not a dictionary."
                )

            current_level = current_level[key]

        # Set the final value
        current_level[keys[-1]] = value

    return updated_config
