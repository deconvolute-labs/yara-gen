import pytest

from yara_gen.engine.factory import get_engine
from yara_gen.engine.ngram import NgramEngine
from yara_gen.engine.stub import StubEngine
from yara_gen.models.config import BaseEngineConfig, NgramEngineConfig


class TestEngineFactory:
    def test_get_stub_engine(self):
        """Test retrieving the Stub engine."""
        config = BaseEngineConfig()
        engine = get_engine("stub", config)

        assert isinstance(engine, StubEngine)
        # Ensure config was passed down
        assert engine.config == config

    def test_get_ngram_engine(self):
        """Test retrieving the N-Gram engine."""
        config = NgramEngineConfig(min_ngram_length=2)
        engine = get_engine("ngram", config)

        assert isinstance(engine, NgramEngine)
        assert engine.config.min_ngram_length == 2

    def test_unknown_engine_raises_error(self):
        """Test that invalid engine names explode gracefully."""
        config = BaseEngineConfig()

        with pytest.raises(ValueError, match="Unknown engine 'chaos_engine'"):
            get_engine("chaos_engine", config)
