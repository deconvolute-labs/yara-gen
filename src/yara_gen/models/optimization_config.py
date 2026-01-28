from typing import Annotated, Literal

from pydantic import BaseModel, Field


class NgramSearchSpace(BaseModel):
    """
    Defines the grid search parameters for the Ngram Engine.
    Lists/Arrays indicate values to iterate over.
    """

    type: Literal["ngram"] = "ngram"

    # Grid Search Parameters (Lists of values to try)
    min_ngram: list[int] = Field(default_factory=lambda: [3, 4])
    max_ngram: list[int] = Field(default_factory=lambda: [4, 5, 6])
    benign_penalty_weight: list[float] = Field(default_factory=lambda: [0.5, 1.0, 2.0])
    score_threshold: list[float] = Field(default_factory=lambda: [0.05, 0.1, 0.15])
    min_document_frequency: list[float] = Field(default_factory=lambda: [0.005, 0.01])


class SelectionConfig(BaseModel):
    """
    Criteria for selecting the 'best' run automatically.
    """

    target_metric: Literal["precision", "recall", "f1_score"] = "recall"

    # Hard constraints (Run is rejected if these aren't met)
    min_precision: float = 0.95
    max_false_positives: int = 0


class OptimizationConfig(BaseModel):
    """
    Root configuration for the optimization command.
    """

    search_space: Annotated[NgramSearchSpace, Field(discriminator="type")]
    selection: SelectionConfig = Field(default_factory=SelectionConfig)

    # Data Splitting
    dev_split_ratio: float = 0.2

    # Random seed for deterministic splitting
    seed: int = 42
