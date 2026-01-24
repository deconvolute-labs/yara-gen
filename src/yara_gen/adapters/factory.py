from yara_gen.adapters.csv import GenericCSVAdapter
from yara_gen.adapters.huggingface import HuggingFaceAdapter
from yara_gen.models.text import DatasetType

from .base import BaseAdapter
from .jsonl import JSONLAdapter

ADAPTER_MAP: dict[str, type[BaseAdapter]] = {
    "jsonl": JSONLAdapter,
    "raw-text": JSONLAdapter,  # Fallback/Alias
    "generic-csv": GenericCSVAdapter,
    "huggingface": HuggingFaceAdapter,
}


def get_adapter(name: str, dataset_type: DatasetType) -> BaseAdapter:
    """
    Factory function to instantiate the correct adapter.

    Args:
        name: The string alias from the CLI (e.g. 'jsonl').
        dataset_type: Whether this is for ADVERSARIAL or BENIGN data.

    Returns:
        An instance of a BaseAdapter subclass.

    Raises:
        ValueError: If the adapter name is unknown.
    """
    if name not in ADAPTER_MAP:
        valid = ", ".join(ADAPTER_MAP.keys())
        raise ValueError(f"Unknown adapter '{name}'. Available: {valid}")

    adapter_class = ADAPTER_MAP[name]
    return adapter_class(dataset_type=dataset_type)
