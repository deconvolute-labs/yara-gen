import csv
from collections.abc import Generator
from pathlib import Path
from typing import Any

from yara_gen.adapters.base import BaseAdapter
from yara_gen.models.text import TextSample
from yara_gen.utils.logger import get_logger

logger = get_logger()


class GenericCSVAdapter(BaseAdapter):
    """
    Standard adapter for reading text samples from Comma-Separated Values (CSV) files.

    This adapter provides a flexible way to ingest tabular data. It requires the user
    to specify which column contains the text content via the 'column' argument.
    All other columns in the row are automatically preserved as metadata, allowing
    for rich context (e.g. attack categories, scores) to be carried through to the
    rule generation phase.

    Attributes:
        dataset_type (DatasetType): The classification of the data (adversarial or
            benign).
    """

    def load(self, source: Path, **kwargs: Any) -> Generator[TextSample]:
        """
        Reads a CSV file and streams TextSample objects.

        This method uses Python's `csv.DictReader` to handle headers automatically.
        It is memory-efficient and can handle large CSV files.

        Args:
            source (Path): Path to the CSV file.
            **kwargs:
                column (str, optional): The name of the column containing the
                    text payload. Defaults to 'text'.

        Returns:
            TextSample: The parsed sample with text from the specified column
            and metadata from all other columns.

        Raises:
            FileNotFoundError: If the source file does not exist.
            ValueError: If the specified column is missing from the CSV header.
        """
        self.validate_file(source)

        # Allow overriding the text column name (default to 'text')
        text_col = kwargs.get("column", "text")

        logger.debug(f"Reading CSV {source}, looking for column '{text_col}'")

        success_count = 0

        with source.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)

            if not reader.fieldnames:
                logger.warning(f"CSV {source} is empty or has no header.")
                return

            if text_col not in reader.fieldnames:
                # Fallback check for case-insensitivity
                available_cols = reader.fieldnames
                logger.error(
                    f"Column '{text_col}' not found in CSV. Available: {available_cols}"
                )
                raise ValueError(f"Column '{text_col}' not found in {source}")

            for row_no, row in enumerate(reader, 1):
                text_content = row.get(text_col)

                if not text_content:
                    continue

                # Store all other columns as metadata
                metadata = row.copy()
                del metadata[text_col]

                yield TextSample(
                    text=text_content,
                    source=f"{source.name}:line_{row_no}",
                    dataset_type=self.dataset_type,
                    metadata=metadata,
                )
                success_count += 1

        logger.info(f"Loaded {success_count} samples from {source.name}")
