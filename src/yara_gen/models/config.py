from pydantic import BaseModel, Field

from yara_gen.models.adapter_config import AdapterConfig
from yara_gen.models.engine_config import (
    EngineConfig,
    NgramEngineConfig,
)


class PrepareConfig(BaseModel):
    """
    Configuration for the prepare command.
    Wraps the adapter config to ensure overrides are properly namespaced.
    """

    adapter: AdapterConfig


class AppConfig(BaseModel):
    """
    Top-level application configuration.
    """

    # Global settings
    output_path: str | None = None

    # Domain specific configs
    adversarial_adapter: AdapterConfig = Field(default_factory=AdapterConfig)
    benign_adapter: AdapterConfig = Field(default_factory=AdapterConfig)

    engine: EngineConfig = Field(default_factory=NgramEngineConfig)
