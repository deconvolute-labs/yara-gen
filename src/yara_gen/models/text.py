from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class DatasetType(str, Enum):
    ADVERSARIAL = "adversarial"
    BENIGN = "benign"
    RAW = "raw"


class TextSample(BaseModel):
    """
    The atomic unit of data for the pipeline.
    Normalized from any input source (CSV, JSON, etc.).
    """

    text: str
    source: str
    dataset_type: DatasetType
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """
        Serializes the sample to a JSON-compatible dictionary.
        Handles the Enum conversion explicitly.
        """
        return {
            "text": self.text,
            "source": self.source,
            # We store the string value ('raw', 'benign') not the Enum object
            "dataset_type": self.dataset_type.value,
            "metadata": self.metadata,
        }

    # Enable hashing so we can use set(samples) for fast deduplication
    def __hash__(self) -> int:
        return hash(self.text)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, TextSample):
            return self.text == other.text
        return False


class RuleString(BaseModel):
    """
    A specific string/n-gram to be included in a YARA rule.
    Tracks its own confidence score.
    """

    value: str
    score: float
    modifiers: list[str] = Field(default_factory=lambda: ["nocase", "wide", "ascii"])


class GeneratedRule(BaseModel):
    """
    Represents a full YARA rule candidate.
    """

    name: str
    tags: list[str] = Field(default_factory=list)
    # The overall rule score (usually the avg or max of its strings)
    score: float
    strings: list[RuleString]
    metadata: dict[str, str] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.now)
