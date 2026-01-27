from collections.abc import Generator
from pathlib import Path
from typing import Any

from datasets import load_dataset

from yara_gen.adapters.base import BaseAdapter
from yara_gen.errors import DataError
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
        No-op override for Hugging Face sources.

        Since 'source' is a Repository ID (string) and not a local file path,
        we always return True to bypass the BaseAdapter's file existence checks.
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
                config_name (str): The HF configuration/subset name.
                Any other kwargs are passed directly to load_dataset().

        Yields:
            TextSample: Normalized samples.

        Raises:
            DataError: If the dataset cannot be found, accessed, or streamed.
        """
        repo_id = str(source)

        # Pop specific args that we handle manually or want to rename
        target_column = kwargs.pop("column", "text")
        config_name = kwargs.pop("config_name", None)
        split = kwargs.pop("split", "train")

        log_msg = f"Streaming {repo_id}"
        if config_name:
            log_msg += f" (config='{config_name}')"
        log_msg += f" (split='{split}', col='{target_column}') ..."
        logger.info(log_msg)

        try:
            # streaming=True is critical for large datasets
            # We pass **kwargs to allow users to set 'token', 'revision',
            # 'trust_remote_code', etc. via config/CLI.
            ds = load_dataset(
                repo_id, name=config_name, split=split, streaming=True, **kwargs
            )
        except Exception as e:
            logger.error(f"Failed to load HF dataset '{repo_id}': {e}")
            raise DataError(
                f"Could not load Hugging Face dataset '{repo_id}': {str(e)}"
            ) from e

        count = 0
        try:
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

                if count % 1000 == 0:
                    logger.debug(f"Streamed {count} samples from Hub ...")
        except Exception as e:
            # Catch errors that occur mid-stream (e.g. network drop)
            raise DataError(f"Stream interrupted for '{repo_id}': {str(e)}") from e
        logger.info(f"Finished streaming {count} samples from {repo_id}.")
