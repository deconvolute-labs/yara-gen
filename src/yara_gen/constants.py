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


class NGramSettings(float, Enum):
    THRESHOLD_STRICT = 0.1
    THRESHOLD_LOOSE = 0.01
    MIN_DOCUMENT_FREQ = 0.01
