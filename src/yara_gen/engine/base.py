from abc import ABC, abstractmethod
from collections.abc import Iterable

from yara_gen.models.engine_config import BaseEngineConfig
from yara_gen.models.text import GeneratedRule, TextSample


class BaseEngine[TConfig: BaseEngineConfig](ABC):
    """
    Abstract Base Class for all engine strategies.

    The Strategy Pattern allows us to swap algorithms
    without changing the CLI or Orchestrator code.
    """

    def __init__(self, config: TConfig):
        self.config = config

    @abstractmethod
    def extract(
        self, adversarial: Iterable[TextSample], benign: Iterable[TextSample]
    ) -> list[GeneratedRule]:
        """
        Core logic to derive rules from data.
        """
        pass
