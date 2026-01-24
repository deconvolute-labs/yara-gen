import csv

import pytest

from yara_gen.adapters.csv import GenericCSVAdapter
from yara_gen.models.text import DatasetType


class TestGenericCSVAdapter:
    @pytest.fixture
    def adapter(self):
        return GenericCSVAdapter(dataset_type=DatasetType.ADVERSARIAL)

    def test_load_valid_csv_default_column(self, adapter, tmp_path):
        """Test loading a standard CSV with the default 'text' column."""
        f = tmp_path / "test.csv"
        with f.open("w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=["text", "category"])
            writer.writeheader()
            writer.writerow({"text": "malicious input", "category": "injection"})
            writer.writerow({"text": "another input", "category": "jailbreak"})

        samples = list(adapter.load(f))

        assert len(samples) == 2
        assert samples[0].text == "malicious input"
        assert samples[0].metadata["category"] == "injection"
        assert samples[0].dataset_type == DatasetType.ADVERSARIAL

    def test_load_custom_column(self, adapter, tmp_path):
        """Test specifying a custom column name for the text payload."""
        f = tmp_path / "custom.csv"
        with f.open("w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=["prompt_content", "id"])
            writer.writeheader()
            writer.writerow({"prompt_content": "ignore instructions", "id": "1"})

        samples = list(adapter.load(f, column="prompt_content"))

        assert len(samples) == 1
        assert samples[0].text == "ignore instructions"

    def test_missing_column_raises_value_error(self, adapter, tmp_path):
        """Test that missing the required column raises a ValueError."""
        f = tmp_path / "bad.csv"
        with f.open("w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=["wrong_col", "id"])
            writer.writeheader()
            writer.writerow({"wrong_col": "data", "id": "1"})

        with pytest.raises(ValueError, match="Column 'text' not found"):
            list(adapter.load(f))

    def test_empty_csv_handled_gracefully(self, adapter, tmp_path):
        """Test that an empty CSV returns no samples."""
        f = tmp_path / "empty.csv"
        f.touch()  # Create empty file

        samples = list(adapter.load(f))
        assert len(samples) == 0

    def test_file_not_found(self, adapter, tmp_path):
        """Test validaton for non-existent file."""
        with pytest.raises(FileNotFoundError):
            list(adapter.load(tmp_path / "ghost.csv"))
