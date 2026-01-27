from pydantic import BaseModel

from yara_gen.constants import EngineConstants


class BaseExtractorConfig(BaseModel):
    """
    Base configuration shared by all extraction engines.
    """

    score_threshold: float = EngineConstants.THRESHOLD_STRICT.value
    rule_date: str | None = None


class NgramConfig(BaseExtractorConfig):
    """
    Configuration specific to the Differential N-Gram Engine.
    """

    min_ngram_length: int = EngineConstants.DEFAULT_MIN_NGRAM.value
    max_ngram_length: int = EngineConstants.DEFAULT_MAX_NGRAM.value

    # The penalty lambda for benign matches
    benign_penalty_weight: float = EngineConstants.DEFAULT_BENIGN_PENALTY.value

    min_document_frequency: float = EngineConstants.MIN_DOCUMENT_FREQ.value
