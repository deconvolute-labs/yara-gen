from pydantic import BaseModel

from yara_gen.constants import NGramSettings


class BaseExtractorConfig(BaseModel):
    """
    Base configuration shared by all extraction engines.
    """

    score_threshold: float = 0.8
    rule_date: str | None = None


class NgramConfig(BaseExtractorConfig):
    """
    Configuration specific to the Differential N-Gram Engine.
    """

    min_ngram_length: int = 3
    max_ngram_length: int = 10
    # The penalty lambda for benign matches
    benign_penalty_weight: float = 1.0
    min_document_frequency: float = NGramSettings.MIN_DOCUMENT_FREQ
