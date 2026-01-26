import re
from pathlib import Path


def parse_existing_rules(file_path: Path) -> set[str]:
    """
    Parses a YARA file and extracts the string payloads to a set.

    Args:
        file_path: Path to the existing .yar file.

    Returns:
        A set of string payloads found in the file.
    """
    if not file_path.exists():
        return set()

    content = file_path.read_text(encoding="utf-8")

    # Regex breakdown:
    # \$[a-zA-Z0-9_]+  -> Match variable name (e.g. $s0)
    # \s*=\s* -> Match assignment operator with whitespace
    # "                -> Match opening quote
    # (                -> Start Capture Group 1
    #   (?:            -> Non-capturing group for alternation
    #     [^"\\]       -> Match any character EXCEPT quote or backslash
    #     |            -> OR
    #     \\.          -> Match an escaped character (backslash + anything)
    #   )* -> Repeat zero or more times
    # )                -> End Capture Group 1
    # "                -> Match closing quote
    pattern = re.compile(r'\$[a-zA-Z0-9_]+\s*=\s*"((?:[^"\\]|\\.)*)"')

    matches = pattern.findall(content)

    cleaned_matches = set()
    for m in matches:
        # Unescape the YARA string back to raw python string
        # 1. Replace \" with "
        # 2. Replace \\ with \
        unescaped = m.replace('\\"', '"').replace("\\\\", "\\")
        cleaned_matches.add(unescaped)

    return cleaned_matches
