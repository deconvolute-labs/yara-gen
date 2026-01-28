import itertools
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter

from yara_gen.adapters import get_adapter
from yara_gen.engine.factory import get_engine
from yara_gen.models.engine_config import EngineConfig
from yara_gen.models.evaluator import EvaluationMetrics
from yara_gen.models.optimization_config import OptimizationConfig
from yara_gen.models.optimizer import OptimizationReport, OptimizationResult
from yara_gen.models.text import DatasetType
from yara_gen.optimization.evaluator import Evaluator
from yara_gen.utils.logger import get_logger

logger = get_logger()


class Optimizer:
    """
    Orchestrates the hyperparameter optimization loop.

    This class is responsible for:
    1.  Generating the search space combinations.
    2.  Iterating through each combination (Training -> Extraction -> Evaluation).
    3.  Persisting results atomically after every iteration to prevent data loss.
    4.  Providing "Flight Recorder" style logging updates.
    """

    def __init__(
        self,
        config: OptimizationConfig,
        train_adv_path: Path,
        train_benign_path: Path,
        dev_path: Path,
        output_path: Path,
    ):
        """
        Initializes the Optimizer.

        Args:
            config (OptimizationConfig): The optimization configuration containing
                the search space and selection criteria.
            train_adv_path (Path): Path to the adversarial training dataset (JSONL).
            train_benign_path (Path): Path to the benign training dataset (JSONL).
            dev_path (Path): Path to the combined/labeled development dataset (JSONL).
            output_path (Path): Path where the JSON results report will be saved.
        """
        self.config = config
        self.train_adv_path = train_adv_path
        self.train_benign_path = train_benign_path
        self.dev_path = dev_path
        self.output_path = output_path

        # We use the existing adapters to stream data
        # Assuming JSONL for the temp files we created
        self.adapter = get_adapter("jsonl", DatasetType.ADVERSARIAL)

        self.evaluator = Evaluator()

    def run(self) -> OptimizationReport:
        """
        Executes the full optimization loop.

        Returns:
            OptimizationReport: The complete report containing metrics for all runs.
        """
        # Expand Search Space
        combinations = self._generate_parameter_combinations()
        total_iterations = len(combinations)

        logger.info("Optimization Loop Started")
        logger.info(f"Search Space Size: {total_iterations} combinations")
        logger.info(f"Results will be saved incrementally to: {self.output_path}\n")

        report = OptimizationReport(
            meta={
                "start_time": datetime.now().isoformat(),
                "config_dump": self.config.model_dump(),
                "dataset_paths": {
                    "train_adv": str(self.train_adv_path),
                    "dev": str(self.dev_path),
                },
            }
        )

        start_time_global = time.time()

        for i, params in enumerate(combinations, 1):
            iter_start_time = time.time()

            # Visual Separator
            self._log_iteration_start(i, total_iterations, params, start_time_global)

            try:
                # A. Train & Extract
                metrics = self._execute_run(params)

                duration = time.time() - iter_start_time

                # B. Record Result
                result = OptimizationResult(
                    iteration=i,
                    parameters=params,
                    metrics=metrics,
                    duration_seconds=round(duration, 2),
                )
                report.runs.append(result)

                # C. Log Outcome
                self._log_iteration_end(result)

                # D. Atomic Save
                self._save_report_atomically(report)

            except Exception as e:
                logger.error(f"Iteration {i} failed: {e}", exc_info=True)
                # We continue to the next iteration instead of crashing the whole loop
                continue

        return report

    def _generate_parameter_combinations(self) -> list[dict[str, Any]]:
        """
        Expands the search space into a flat list of parameter dictionaries.

        Returns:
            list[dict[str, Any]]: A list of dictionaries, where each dictionary
                represents a specific set of arguments for the engine (e.g.,
                {'min_ngram': 3, 'score_threshold': 0.1}).
        """
        # Extract the search arrays from the config
        # Exclude 'type' as it is a constant discriminator
        space_dict = self.config.search_space.model_dump(exclude={"type"})

        keys = list(space_dict.keys())
        values = list(space_dict.values())

        # Cartesian product
        combinations = []
        for combination_values in itertools.product(*values):
            # Re-zip keys with values
            combinations.append(dict(zip(keys, combination_values, strict=True)))

        return combinations

    def _execute_run(self, params: dict[str, Any]) -> EvaluationMetrics:
        """
        Instantiates the engine with specific parameters and evaluates it.

        Args:
            params (dict[str, Any]): The hyperparameters for this run.

        Returns:
            EvaluationMetrics: The TP/FP/etc. scores for this configuration.
        """
        # Configure Engine
        # We merge the base params (like engine type) with the loop params
        engine_config_dict = {"type": self.config.search_space.type, **params}

        # Since we are essentially bypassing the AppConfig validation for the
        # sub-config, we construct the EngineConfig directly.
        engine_config: EngineConfig = TypeAdapter(EngineConfig).validate_python(
            engine_config_dict
        )

        engine = get_engine(engine_config)

        # Load Streams
        # We create fresh iterators for every run because streams are consumed.
        # Since these are local files, this is fast.
        train_adv_stream = self.adapter.load(self.train_adv_path)
        train_benign_stream = self.adapter.load(self.train_benign_path)

        # Extract Rules
        logger.debug("  -> Training engine...")
        rules = engine.extract(adversarial=train_adv_stream, benign=train_benign_stream)

        # Evaluate
        logger.debug(f"  -> Evaluating {len(rules)} rules on dev set...")
        metrics = self.evaluator.evaluate(rules, self.dev_path)

        return metrics

    def _save_report_atomically(self, report: OptimizationReport) -> None:
        """
        Persists the current report to disk using an atomic write strategy.

        This prevents file corruption if the process is interrupted during writing.
        Strategy: Write to 'filename.json.tmp' -> OS Rename to 'filename.json'.

        Args:
            report (OptimizationReport): The full data object to save.
        """
        temp_path = self.output_path.with_suffix(".json.tmp")

        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                f.write(report.model_dump_json(indent=2))

            # Atomic replacement
            os.replace(temp_path, self.output_path)
        except OSError as e:
            logger.error(f"Failed to save optimization report: {e}")

    def _log_iteration_start(
        self, current_idx: int, total: int, params: dict[str, Any], start_time: float
    ) -> None:
        """
        Prints the 'Flight Recorder' header for the current iteration.
        """
        # Calculate ETA
        elapsed = time.time() - start_time
        if current_idx > 1:
            avg_time = elapsed / (current_idx - 1)
            remaining = avg_time * (total - current_idx + 1)
            eta_str = f"{remaining / 60:.1f}m"
        else:
            eta_str = "--:--"

        # Format params for display (truncate if too long)
        param_str = ", ".join(f"{k}={v}" for k, v in params.items())

        print(f"[ITER {current_idx}/{total}] ETA: {eta_str}")
        print(f"Params: {{{param_str}}}")

    def _log_iteration_end(self, result: OptimizationResult) -> None:
        """
        Prints the summary metrics for the completed iteration.
        """
        m = result.metrics
        print("")
        print(
            f"[RESULT] TP: {m.tp} | FP: {m.fp} | "
            f"Prec: {m.precision:.3f} | Rec: {m.recall:.3f} | "
            f"F1: {m.f1_score:.3f} ({result.duration_seconds}s)"
        )
        print("")
        print("-" * 80)
        print("")
