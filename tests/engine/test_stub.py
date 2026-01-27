import pytest

from yara_gen.engine.stub import StubEngine
from yara_gen.models.config import BaseEngineConfig
from yara_gen.models.text import DatasetType, TextSample


class TestStubEngine:
    @pytest.fixture
    def engine(self):
        config = BaseEngineConfig(type="stub")
        return StubEngine(config)

    def test_stub_returns_placeholder_rule(self, engine):
        """The stub should always return one specific test rule."""
        # Create dummy input data
        adversarial = [
            TextSample(
                text="attack", source="test", dataset_type=DatasetType.ADVERSARIAL
            )
        ]
        benign: list[TextSample] = []

        rules = engine.extract(adversarial, benign)

        assert len(rules) == 1
        assert rules[0].name == "stub_rule_001"
        assert rules[0].score == 1.0
        assert "stub" in rules[0].tags

    def test_stub_consumes_input(self, engine, caplog):
        """Verify the stub actually iterates over the input generator."""
        # Generator that yields 3 items
        adversarial = (
            TextSample(
                text=f"attack {i}", source="test", dataset_type=DatasetType.ADVERSARIAL
            )
            for i in range(3)
        )

        with caplog.at_level("INFO"):
            engine.extract(adversarial, [])

        # Check logs to prove it counted 3 items
        assert "Consumed 3 adversarial samples" in caplog.text
