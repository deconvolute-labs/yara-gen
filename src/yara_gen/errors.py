class YaraGenError(Exception):
    """Base exception for all yara-gen custom errors."""

    pass


class ConfigurationError(YaraGenError):
    """Raised when provided arguments or configuration are invalid."""

    pass


class DataError(YaraGenError):
    """Raised when input datasets are empty, corrupt, or missing."""

    pass


class ExtractionError(YaraGenError):
    """Raised when the extraction engine fails (e.g. empty vocabulary)."""

    pass
