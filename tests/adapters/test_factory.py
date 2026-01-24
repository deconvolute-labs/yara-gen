import pytest

from yara_gen.adapters.factory import ADAPTER_MAP, get_adapter
from yara_gen.adapters.huggingface import HuggingFaceAdapter
from yara_gen.adapters.jsonl import JSONLAdapter
from yara_gen.models.text import DatasetType


class TestAdapterFactory:
    def test_get_jsonl_adapter(self):
        adapter = get_adapter("jsonl", DatasetType.BENIGN)
        assert isinstance(adapter, JSONLAdapter)
        assert adapter.dataset_type == DatasetType.BENIGN

    def test_get_huggingface_adapter(self):
        adapter = get_adapter("huggingface", DatasetType.ADVERSARIAL)
        assert isinstance(adapter, HuggingFaceAdapter)
        assert adapter.dataset_type == DatasetType.ADVERSARIAL

    def test_unknown_adapter_raises_error(self):
        with pytest.raises(ValueError, match="Unknown adapter 'mysterious_format'"):
            get_adapter("mysterious_format", DatasetType.ADVERSARIAL)

    def test_adapter_map_integrity(self):
        """Ensure all registered keys map to valid classes."""
        assert "jsonl" in ADAPTER_MAP
        assert "generic-csv" in ADAPTER_MAP
        assert "huggingface" in ADAPTER_MAP
