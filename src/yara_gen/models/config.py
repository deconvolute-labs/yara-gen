from pydantic import BaseModel, Field

from yara_gen.constants import EngineConstants


class BaseEngineConfig(BaseModel):
    """
    Base configuration shared by all engines.
    """

    # The actual score threshold to use for this run.
    # Users can overwrite this directly to bypass "strict/loose" defaults.
    score_threshold: float = EngineConstants.THRESHOLD_STRICT.value

    # Limits the number of rules generated to prevent flooding.
    max_rules_per_run: int = EngineConstants.MAX_RULES_PER_RUN.value

    rule_date: str | None = None

    # Allow extra fields for engine-specific overrides (like min_ngram_length)
    # when loading generic configs.
    model_config = {"extra": "allow"}


class NgramEngineConfig(BaseEngineConfig):
    """
    Configuration specific to the Differential N-Gram Engine.
    """

    min_ngram_length: int = EngineConstants.DEFAULT_MIN_NGRAM.value
    max_ngram_length: int = EngineConstants.DEFAULT_MAX_NGRAM.value

    # The penalty lambda for benign matches
    benign_penalty_weight: float = EngineConstants.DEFAULT_BENIGN_PENALTY.value

    min_document_frequency: float = EngineConstants.MIN_DOCUMENT_FREQ.value


class AdapterConfig(BaseModel):
    """
    Generic configuration for adapters.
    """

    type: str = "jsonl"

    # Allows passing in adapter-specific args directly
    model_config = {"extra": "allow"}


class AppConfig(BaseModel):
    """
    Top-level application configuration.
    """

    # Global settings
    output_path: str | None = None

    # Domain specific configs
    adversarial_adapter: AdapterConfig = Field(default_factory=AdapterConfig)
    benign_adapter: AdapterConfig = Field(default_factory=AdapterConfig)

    # BaseEngineConfig here to allow loading the YAML structure
    engine: BaseEngineConfig = Field(default_factory=BaseEngineConfig)
