import pytest

from yara_gen.engine.stub import StubExtractor
from yara_gen.models.config import BaseExtractorConfig
from yara_gen.models.text import DatasetType, TextSample


class TestStubExtractor:
    @pytest.fixture
    def extractor(self):
        config = BaseExtractorConfig()
        return StubExtractor(config)

    def test_stub_returns_placeholder_rule(self, extractor):
        """The stub should always return one specific test rule."""
        # Create dummy input data
        adversarial = [
            TextSample(
                text="attack", source="test", dataset_type=DatasetType.ADVERSARIAL
            )
        ]
        benign: list[TextSample] = []

        rules = extractor.extract(adversarial, benign)

        assert len(rules) == 1
        assert rules[0].name == "stub_rule_001"
        assert rules[0].score == 1.0
        assert "stub" in rules[0].tags

    def test_stub_consumes_input(self, extractor, caplog):
        """Verify the stub actually iterates over the input generator."""
        # Generator that yields 3 items
        adversarial = (
            TextSample(
                text=f"attack {i}", source="test", dataset_type=DatasetType.ADVERSARIAL
            )
            for i in range(3)
        )

        with caplog.at_level("INFO"):
            extractor.extract(adversarial, [])

        # Check logs to prove it counted 3 items
        assert "Consumed 3 adversarial samples" in caplog.text
