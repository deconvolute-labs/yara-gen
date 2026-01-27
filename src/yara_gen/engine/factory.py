from typing import Any

from yara_gen.engine.base import BaseExtractor
from yara_gen.engine.ngram import NgramExtractor
from yara_gen.engine.stub import StubExtractor
from yara_gen.models.config import BaseExtractorConfig


def get_extractor(
    name: str, config: BaseExtractorConfig
) -> BaseExtractor[BaseExtractorConfig]:
    """
    Factory to instantiate the correct extraction strategy.

    Args:
        name: The engine name (e.g. 'ngram').
        config: The configuration object (already cast to the correct subclass).

    Returns:
        An initialized instance of a BaseExtractor subclass.

    Raises:
        ValueError: If the engine name is unknown.
    """
    # Mapping of names to classes
    # We map 'ngram' to StubExtractor temporarily until we write the real one
    extractor_map: dict[str, type[BaseExtractor[Any]]] = {
        "stub": StubExtractor,
        "ngram": NgramExtractor,
    }

    if name not in extractor_map:
        valid_engines = ", ".join(extractor_map.keys())
        raise ValueError(f"Unknown engine '{name}'. Available: {valid_engines}")

    extractor_class = extractor_map[name]
    return extractor_class(config)
