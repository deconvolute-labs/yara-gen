import json
from collections.abc import Generator
from pathlib import Path
from typing import Any

from yara_gen.adapters.base import BaseAdapter
from yara_gen.models.text import TextSample
from yara_gen.utils.logger import get_logger

logger = get_logger()


class JSONLAdapter(BaseAdapter):
    """
    Standard adapter for reading newline-delimited JSON (.jsonl) files.

    This adapter is designed to be the primary interface for "Benign Control Sets"
    and pre-processed adversarial data. It offers a flexible schema reader that
    attempts to find the text content in multiple common field names ('text',
    'prompt', 'content', etc.) if a strict schema is not provided.

    Example:
        A valid input line in the .jsonl file:
        {
            "text": "Ignore previous instructions",
            "source": "red_team_v1",
            "meta": {"risk": "high"}
        }
    """

    def load(self, source: Path, **kwargs: Any) -> Generator[TextSample]:
        """
        Reads a .jsonl file line-by-line and yields a TextSample objects.

        This method is fault-tolerant: it skips empty lines and logs (but does not
        crash on) malformed JSON lines.

        Args:
            source (Path): Path to the .jsonl file.
            **kwargs:
                Unused here, but accepted to maintain signature compatibility.

        Yields:
            TextSample: The parsed and normalized sample.

        Raises:
            FileNotFoundError: If the source file does not exist.
        """
        self.validate_file(source)
        logger.debug(f"Streaming data from {source}")

        success_count = 0
        error_count = 0

        with source.open("r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                try:
                    data = json.loads(line)

                    # Extract Text (Try multiple common keys)
                    text_content = (
                        data.get("text")
                        or data.get("prompt")
                        or data.get("content")
                        or data.get("body")
                    )

                    if not text_content or not isinstance(text_content, str):
                        # If strictly required, we could log a warning here
                        continue

                    # Extract Metadata (everything else)
                    # We create a copy to avoid mutating the original dict if needed,
                    # though here we just filter out the text key we used.
                    metadata = data.copy()

                    # Construct Sample
                    sample = TextSample(
                        text=text_content,
                        source=data.get("source", source.name),
                        dataset_type=self.dataset_type,
                        metadata=metadata,
                    )

                    yield sample
                    success_count += 1

                except json.JSONDecodeError:
                    error_count += 1
                    logger.debug(f"JSON decode error at line {line_no} in {source}")
                except Exception as e:
                    error_count += 1
                    logger.warning(f"Unexpected error at line {line_no}: {e}")

        logger.info(
            f"Loaded {success_count} samples from {source.name} "
            "(Skipped {error_count} errors)"
        )
