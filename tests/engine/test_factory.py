import pytest

from yara_gen.engine.factory import get_extractor
from yara_gen.engine.ngram import NgramExtractor
from yara_gen.engine.stub import StubExtractor
from yara_gen.models.config import BaseExtractorConfig, NgramConfig


class TestExtractorFactory:
    def test_get_stub_extractor(self):
        """Test retrieving the Stub engine."""
        config = BaseExtractorConfig()
        extractor = get_extractor("stub", config)

        assert isinstance(extractor, StubExtractor)
        # Ensure config was passed down
        assert extractor.config == config

    def test_get_ngram_extractor(self):
        """Test retrieving the N-Gram engine."""
        config = NgramConfig(min_ngram_length=2)
        extractor = get_extractor("ngram", config)

        assert isinstance(extractor, NgramExtractor)
        assert extractor.config.min_ngram_length == 2

    def test_unknown_engine_raises_error(self):
        """Test that invalid engine names explode gracefully."""
        config = BaseExtractorConfig()

        with pytest.raises(ValueError, match="Unknown engine 'chaos_engine'"):
            get_extractor("chaos_engine", config)
