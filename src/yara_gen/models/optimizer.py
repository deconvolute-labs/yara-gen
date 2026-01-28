from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from yara_gen.models.evaluator import EvaluationMetrics


class OptimizationResult(BaseModel):
    """
    Represents the outcome of a single optimization iteration.
    """

    iteration: int
    parameters: dict[str, Any]
    metrics: EvaluationMetrics
    duration_seconds: float
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())


class OptimizationReport(BaseModel):
    """
    The full report persisted to disk, containing all run history.
    """

    meta: dict[str, Any]
    runs: list[OptimizationResult] = []
