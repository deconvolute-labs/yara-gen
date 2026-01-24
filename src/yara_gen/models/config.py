from pydantic import BaseModel


class BaseExtractorConfig(BaseModel):
    """
    Base configuration shared by all extraction engines.
    """

    score_threshold: float = 0.8


class NgramConfig(BaseExtractorConfig):
    """
    Configuration specific to the Differential N-Gram Engine.
    """

    min_ngram_length: int = 3
    max_ngram_length: int = 10
    # The penalty lambda for benign matches
    benign_penalty_weight: float = 1.0
