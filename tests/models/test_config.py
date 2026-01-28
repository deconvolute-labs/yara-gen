from typing import Any

from yara_gen.constants import EngineConstants
from yara_gen.models.adapter_config import AdapterConfig
from yara_gen.models.config import (
    AppConfig,
)
from yara_gen.models.engine_config import NgramEngineConfig, StubEngineConfig


def test_ngram_engine_config_defaults() -> None:
    """Test that NgramEngineConfig has correct defaults."""
    config = NgramEngineConfig()
    assert config.type == "ngram"
    assert config.score_threshold == EngineConstants.THRESHOLD_STRICT.value
    assert config.max_rules_per_run == EngineConstants.MAX_RULES_PER_RUN.value
    assert config.min_ngram == EngineConstants.DEFAULT_MIN_NGRAM.value
    assert config.max_ngram == EngineConstants.DEFAULT_MAX_NGRAM.value


def test_ngram_engine_config_overrides() -> None:
    """Test that extra fields are allowed in NgramEngineConfig."""
    config = NgramEngineConfig(extra_param="foo")  # type: ignore
    assert config.extra_param == "foo"  # type: ignore


def test_stub_engine_config() -> None:
    """Test StubEngineConfig initialization."""
    config = StubEngineConfig()
    assert config.type == "stub"


def test_adapter_config_defaults() -> None:
    """Test AdapterConfig defaults."""
    config = AdapterConfig()
    assert config.type == "jsonl"


def test_adapter_config_extra_fields() -> None:
    """Test that AdapterConfig accepts extra fields."""
    config = AdapterConfig(chunk_size=512, delimiter=",")  # type: ignore
    assert config.chunk_size == 512  # type: ignore
    assert config.delimiter == ","  # type: ignore


def test_app_config_initialization() -> None:
    """Test AppConfig initialization with defaults."""
    config = AppConfig()
    assert isinstance(config.engine, NgramEngineConfig)
    assert isinstance(config.adversarial_adapter, AdapterConfig)
    assert isinstance(config.benign_adapter, AdapterConfig)


def test_app_config_nested_overrides() -> None:
    """Test AppConfig with nested dictionary initialization."""
    data: dict[str, Any] = {
        "engine": {"type": "ngram", "min_ngram": 5},
        "adversarial_adapter": {"type": "csv", "delimiter": "|"},
    }
    config = AppConfig(**data)
    assert isinstance(config.engine, NgramEngineConfig)
    assert config.engine.min_ngram == 5
    assert config.adversarial_adapter.type == "csv"
    assert config.adversarial_adapter.delimiter == "|"  # type: ignore
