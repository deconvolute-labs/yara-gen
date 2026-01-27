from yara_gen.engine.factory import get_engine
from yara_gen.engine.ngram import NgramEngine
from yara_gen.engine.stub import StubEngine
from yara_gen.models.config import BaseEngineConfig, NgramEngineConfig


class TestEngineFactory:
    def test_get_stub_engine(self):
        """Test retrieving the Stub engine."""
        config = BaseEngineConfig(type="stub")
        engine = get_engine(config)

        assert isinstance(engine, StubEngine)
        # Ensure config was passed down
        assert engine.config == config

    def test_get_ngram_engine(self):
        """Test retrieving the N-Gram engine."""
        config = NgramEngineConfig(min_ngram=2)
        engine = get_engine(config)

        assert isinstance(engine, NgramEngine)
        assert engine.config.min_ngram == 2
