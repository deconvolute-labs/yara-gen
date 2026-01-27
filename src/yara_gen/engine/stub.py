from collections.abc import Iterable

from yara_gen.engine.base import BaseEngine
from yara_gen.models.config import BaseEngineConfig
from yara_gen.models.text import GeneratedRule, RuleString, TextSample
from yara_gen.utils.logger import get_logger

logger = get_logger()


class StubEngine(BaseEngine[BaseEngineConfig]):
    """
    A dummy engine for testing the pipeline wiring without running real math.
    """

    def extract(
        self, adversarial: Iterable[TextSample], benign: Iterable[TextSample]
    ) -> list[GeneratedRule]:
        logger.info("StubEngine: Started extraction (STUB MODE).")

        # Consume inputs to prove we can read them
        count = sum(1 for _ in adversarial)
        logger.info(f"StubEngine: Consumed {count} adversarial samples.")

        return [
            GeneratedRule(
                name="stub_rule_001",
                tags=["stub", "test"],
                score=1.0,
                strings=[
                    RuleString(
                        value="test_string_stub", score=1.0, modifiers=["nocase"]
                    )
                ],
                metadata={"type": "stub"},
            )
        ]
