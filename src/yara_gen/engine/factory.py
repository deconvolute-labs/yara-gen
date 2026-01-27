from typing import Any

from yara_gen.engine.base import BaseEngine
from yara_gen.engine.ngram import NgramEngine
from yara_gen.engine.stub import StubEngine
from yara_gen.models.config import BaseEngineConfig


def get_engine(name: str, config: BaseEngineConfig) -> BaseEngine[BaseEngineConfig]:
    """
    Factory to instantiate the correct extraction strategy.

    Args:
        name: The engine name (e.g. 'ngram').
        config: The configuration object (already cast to the correct subclass).

    Returns:
        An initialized instance of a BaseEngine subclass.

    Raises:
        ValueError: If the engine name is unknown.
    """
    # Mapping of names to classes
    # We map 'ngram' to StubEngine temporarily until we write the real one
    engine_map: dict[str, type[BaseEngine[Any]]] = {
        "stub": StubEngine,
        "ngram": NgramEngine,
    }

    if name not in engine_map:
        valid_engines = ", ".join(engine_map.keys())
        raise ValueError(f"Unknown engine '{name}'. Available: {valid_engines}")

    engine_class = engine_map[name]
    return engine_class(config)
