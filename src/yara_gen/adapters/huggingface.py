from collections.abc import Generator
from pathlib import Path
from typing import Any

from datasets import load_dataset

from yara_gen.adapters.base import BaseAdapter
from yara_gen.models.text import TextSample
from yara_gen.utils.logger import get_logger

logger = get_logger()


class HuggingFaceAdapter(BaseAdapter):
    """
    Generic adapter for streaming ANY dataset from the Hugging Face Hub.

    This adapter bypasses local files and streams data directly from the Hub.
    It requires the user to specify which column contains the analysis text.

    Usage:
        input_path should be the Repo ID (e.g. 'rubend18/ChatGPT-Jailbreak-Prompts')
    """

    def validate_file(self, source: Path) -> bool:
        """
        Overrides validation to allow non-existent local paths.

        We assume 'source' is a Repo ID string, not a file path.
        """
        return True

    def load(self, source: Path, **kwargs: Any) -> Generator[TextSample]:
        """
        Streams samples from Hugging Face.

        Args:
            source (Path): The Hugging Face Repo ID (e.g. 'user/dataset').
                (Converted to string internally).
            **kwargs:
                column (str): The name of the text column (default: 'text').
                split (str): The dataset split to use (default: 'train').

        Yields:
            TextSample: Normalized samples.
        """
        repo_id = str(source)
        target_column = kwargs.get("column", "text")
        split = kwargs.get("split", "train")
        config_name = kwargs.get("config_name")

        log_msg = f"Streaming {repo_id}"
        if config_name:
            log_msg += f" (config='{config_name}')"
        log_msg += f" (split='{split}', col='{target_column}')..."
        logger.info(log_msg)

        try:
            # streaming=True is critical for large datasets
            ds = load_dataset(repo_id, name=config_name, split=split, streaming=True)
        except Exception as e:
            logger.error(f"Failed to load HF dataset '{repo_id}': {e}")
            raise ValueError(f"Could not load Hugging Face dataset: {e}") from e

        count = 0
        for row in ds:
            text_content = row.get(target_column)

            # Heuristic: If default 'text' fails, try 'prompt' as a fallback
            if not text_content and target_column == "text":
                text_content = row.get("prompt") or row.get("Prompt")

            if not text_content:
                continue

            # Metadata is everything EXCEPT the text column
            metadata = {k: v for k, v in row.items() if k != target_column}

            yield TextSample(
                text=str(text_content),
                source=repo_id,
                dataset_type=self.dataset_type,
                metadata=metadata,
            )
            count += 1

            if count % 2000 == 0:
                logger.debug(f"Streamed {count} samples from Hub...")

        logger.info(f"Finished streaming {count} samples from {repo_id}.")
