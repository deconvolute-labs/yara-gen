from typing import Annotated, Literal

from pydantic import BaseModel, Field

from yara_gen.constants import EngineConstants


class BaseEngineConfig(BaseModel):
    """
    Base configuration shared by all engines.
    """

    type: Literal["ngram", "stub"]

    score_threshold: float = EngineConstants.THRESHOLD_STRICT.value
    max_rules_per_run: int = EngineConstants.MAX_RULES_PER_RUN.value
    rule_date: str | None = None

    # Allow extra fields for engine-specific overrides (like min_ngram)
    # when loading generic configs.
    model_config = {"extra": "allow"}


class NgramEngineConfig(BaseEngineConfig):
    """
    Configuration specific to the Differential N-Gram Engine.
    """

    type: Literal["ngram"] = "ngram"

    min_ngram: int = EngineConstants.DEFAULT_MIN_NGRAM.value
    max_ngram: int = EngineConstants.DEFAULT_MAX_NGRAM.value

    # The penalty lambda for benign matches
    benign_penalty_weight: float = EngineConstants.DEFAULT_BENIGN_PENALTY.value

    min_document_frequency: float = EngineConstants.MIN_DOCUMENT_FREQ.value


class StubEngineConfig(BaseEngineConfig):
    """
    Configuration for the Stub engine (mostly for testing/dry-runs).
    """

    type: Literal["stub"] = "stub"


EngineConfig = Annotated[
    NgramEngineConfig | StubEngineConfig, Field(discriminator="type")
]
