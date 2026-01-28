import pytest

from yara_gen.adapters.huggingface import HuggingFaceAdapter
from yara_gen.errors import DataError
from yara_gen.models.text import DatasetType


class TestHuggingFaceAdapter:
    @pytest.fixture
    def adapter(self):
        return HuggingFaceAdapter(dataset_type=DatasetType.ADVERSARIAL)

    def test_load_streams_data_correctly(self, adapter, mocker):
        """Test successful streaming from a mocked HF dataset."""
        # Mock the dataset iterator
        mock_data = [
            {"text": "attack one", "label": "unsafe"},
            {"text": "attack two", "label": "unsafe"},
        ]

        # We patch the function where it is imported/used
        mock_load_dataset = mocker.patch("yara_gen.adapters.huggingface.load_dataset")
        mock_load_dataset.return_value = mock_data

        # We pass a string ID
        samples = list(adapter.load("deepset/test-dataset"))

        assert len(samples) == 2
        assert samples[0].text == "attack one"
        assert samples[0].metadata["label"] == "unsafe"

        # Verify call args
        mock_load_dataset.assert_called_with(
            "deepset/test-dataset", name=None, split="train", streaming=True
        )

    def test_load_with_custom_column_and_split(self, adapter, mocker):
        """Test specifying a custom column and split."""
        mock_data = [{"content": "malicious payload", "id": 1}]
        mock_load_dataset = mocker.patch("yara_gen.adapters.huggingface.load_dataset")
        mock_load_dataset.return_value = mock_data

        samples = list(adapter.load("user/repo", column="content", split="validation"))

        assert len(samples) == 1
        assert samples[0].text == "malicious payload"
        mock_load_dataset.assert_called_with(
            "user/repo", name=None, split="validation", streaming=True
        )

    def test_fallback_to_prompt_column(self, adapter, mocker):
        """Test heuristic fallback: if 'text' is missing, try 'prompt'."""
        mock_data = [{"prompt": "ignore instructions", "category": "jailbreak"}]
        mock_load_dataset = mocker.patch("yara_gen.adapters.huggingface.load_dataset")
        mock_load_dataset.return_value = mock_data

        samples = list(adapter.load("rubend18/test"))

        assert len(samples) == 1
        assert samples[0].text == "ignore instructions"

    def test_hf_load_failure(self, adapter, mocker):
        """Test that connection errors raise a ValueError."""
        mock_load_dataset = mocker.patch("yara_gen.adapters.huggingface.load_dataset")
        mock_load_dataset.side_effect = Exception("Connection refused")

        with pytest.raises(DataError, match="Could not load Hugging Face dataset"):
            list(adapter.load("bad/repo"))

    def test_load_with_config_name(self, adapter, mocker):
        """Test loading with a specific config name."""
        mock_data = [{"text": "config sample"}]
        mock_load_dataset = mocker.patch("yara_gen.adapters.huggingface.load_dataset")
        mock_load_dataset.return_value = mock_data

        samples = list(adapter.load("user/multi-config-repo", config_name="subset_v2"))

        assert len(samples) == 1
        assert samples[0].text == "config sample"
        mock_load_dataset.assert_called_with(
            "user/multi-config-repo",
            name="subset_v2",
            split="train",
            streaming=True,
        )
