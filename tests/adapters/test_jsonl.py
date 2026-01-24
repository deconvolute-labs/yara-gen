import json

import pytest

from yara_gen.adapters.jsonl import JSONLAdapter
from yara_gen.models.text import DatasetType


class TestJSONLAdapter:
    @pytest.fixture
    def adapter(self):
        return JSONLAdapter(dataset_type=DatasetType.BENIGN)

    def test_load_valid_jsonl(self, adapter, tmp_path):
        """Test loading a standard JSONL file."""
        f = tmp_path / "data.jsonl"
        data = [
            {"text": "safe input 1", "source": "synthetic"},
            {"text": "safe input 2", "source": "synthetic"},
        ]
        f.write_text("\n".join(json.dumps(d) for d in data), encoding="utf-8")

        samples = list(adapter.load(f))

        assert len(samples) == 2
        assert samples[0].text == "safe input 1"
        assert samples[0].source == "synthetic"

    def test_flexible_text_keys(self, adapter, tmp_path):
        """Test that the adapter finds text in 'prompt' or 'content' fields."""
        f = tmp_path / "flexible.jsonl"
        lines = [
            json.dumps({"prompt": "found via prompt"}),
            json.dumps({"content": "found via content"}),
            json.dumps({"body": "found via body"}),
        ]
        f.write_text("\n".join(lines), encoding="utf-8")

        samples = list(adapter.load(f))

        assert len(samples) == 3
        assert samples[0].text == "found via prompt"
        assert samples[1].text == "found via content"

    def test_skips_malformed_json(self, adapter, tmp_path):
        """Test that invalid JSON lines are skipped without crashing."""
        f = tmp_path / "broken.jsonl"
        content = """
        {"text": "valid line"}
        {BROKEN_JSON_HERE
        {"text": "valid line 2"}
        """
        f.write_text(content.strip(), encoding="utf-8")

        samples = list(adapter.load(f))

        # Should recover and get the 2 valid lines
        assert len(samples) == 2
        assert samples[0].text == "valid line"
        assert samples[1].text == "valid line 2"

    def test_skips_empty_lines(self, adapter, tmp_path):
        """Test that empty lines are ignored."""
        f = tmp_path / "empty_lines.jsonl"
        content = '{"text": "A"}\n\n{"text": "B"}'
        f.write_text(content, encoding="utf-8")

        samples = list(adapter.load(f))
        assert len(samples) == 2
