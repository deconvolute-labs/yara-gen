from enum import Enum

META_AUTHOR = "Deconvolute Labs"
META_DESC = "Auto-generated rule for Deconvolute SDK security suite."
LOGGER_NAME = "yara-gen"


class EngineType(str, Enum):
    NGRAM = "ngram"
    STUB = "stub"


class AdapterType(str, Enum):
    RAW_TEXT = "raw-text"
    JSONL = "jsonl"
    GENERIC_CSV = "generic-csv"
    HUGGINGFACE = "huggingface"


class EngineConstants(Enum):
    """
    Default configuration values and thresholds for extraction engines.
    Includes scoring thresholds, N-gram limits, and optimization bounds.
    """

    # Thresholds
    THRESHOLD_STRICT = 0.1
    THRESHOLD_LOOSE = 0.01
    MIN_DOCUMENT_FREQ = 0.01

    # Defaults
    DEFAULT_MIN_NGRAM = 3
    DEFAULT_MAX_NGRAM = 10

    # Limits
    MAX_RULES_PER_RUN = 50

    # Scoring
    DEFAULT_BENIGN_PENALTY = 1.0
