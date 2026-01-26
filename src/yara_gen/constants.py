from enum import Enum

META_AUTHOR = "Deconvolute Labs"
META_DESC = "Auto-generated rule for Deconvolute SDK security suite."


class EngineType(str, Enum):
    NGRAM = "ngram"
    STUB = "stub"


class AdapterType(str, Enum):
    RAW_TEXT = "raw-text"
    JSONL = "jsonl"
    GENERIC_CSV = "generic-csv"
    HUGGINGFACE = "huggingface"
