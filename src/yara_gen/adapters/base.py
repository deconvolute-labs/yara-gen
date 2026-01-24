from abc import ABC, abstractmethod
from collections.abc import Generator
from pathlib import Path
from typing import Any

from yara_gen.models.text import DatasetType, TextSample


class BaseAdapter(ABC):
    """
    Abstract Base Class for all data ingestion adapters.

    Responsibilities:
    1. Accept a raw input source (file path, URL, etc.)
    2. Stream normalized TextSample objects to the pipeline
    3. Handle basic file validation
    """

    def __init__(self, dataset_type: DatasetType):
        self.dataset_type = dataset_type

    @abstractmethod
    def load(self, source: Path, **kwargs: Any) -> Generator[TextSample]:
        """
        Stream TextSamples from the source.

        Args:
            source: Path to the input file
            **kwargs: Adapter-specific arguments (e.g., column names for CSV)

        Yields:
            TextSample: A normalized data point
        """
        pass

    def validate_file(self, source: Path) -> bool:
        """
        Performs basic validation on the input file path.

        Args:
            source (Path): The file path to validate.

        Returns:
            bool: True if the file exists and is a valid file (not a directory).

        Raises:
            FileNotFoundError: If the path does not exist.
            ValueError: If the path points to a directory instead of a file.
        """
        if not source.exists():
            raise FileNotFoundError(f"Input file not found: {source}")
        if not source.is_file():
            raise ValueError(f"Input path is not a file: {source}")
        return True
