import argparse
import sys
from pathlib import Path

from yara_gen.adapters import get_adapter
from yara_gen.errors import ConfigurationError
from yara_gen.models.optimization_config import OptimizationConfig, SelectionConfig
from yara_gen.models.optimizer import OptimizationReport, OptimizationResult
from yara_gen.models.text import DatasetType
from yara_gen.optimization.optimizer import Optimizer
from yara_gen.optimization.splitter import DataSplitter
from yara_gen.utils.config import load_config
from yara_gen.utils.logger import get_logger, log_header, log_named_value

logger = get_logger()


def register_args(
    subparsers: argparse._SubParsersAction,  # type: ignore[type-arg]
    parents: list[argparse.ArgumentParser],
) -> None:
    """
    Registers the 'optimize' command and its arguments.
    """
    parser = subparsers.add_parser(
        "optimize",
        help="Run hyperparameter optimization loop for rule generation.",
        parents=parents,
    )

    parser.add_argument(
        "input", type=Path, nargs="?", help="Path to the adversarial dataset source"
    )

    parser.add_argument(
        "--benign-dataset",
        "-b",
        type=Path,
        help="Path to the benign dataset source in JSONL",
    )

    parser.add_argument(
        "--config",
        "-c",
        type=Path,
        default=Path("optimization_config.yaml"),
        help="Path to the optimization configuration file (defines search space)",
    )

    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help=(
            "Path to save the JSON optimization report "
            "(default: optimization_results_<timestamp>.json)"
        ),
    )


def _load_optimization_config(config_path: Path) -> OptimizationConfig:
    """
    Loads and validates the optimization configuration.
    """
    if not config_path.exists():
        raise ConfigurationError(
            f"Optimization config file not found: {config_path}. "
            "Please create it or specify a path with --config."
        )

    raw_config = load_config(config_path)
    try:
        return OptimizationConfig(**raw_config)
    except Exception as e:
        raise ConfigurationError(f"Invalid optimization config format: {e}") from e


def _select_best_run(
    report: OptimizationReport, selection_config: SelectionConfig
) -> OptimizationResult | None:
    """
    Selects the best run based on the criteria defined in the config.

    1. Filters runs that violate hard constraints (e.g. max_fp).
    2. Sorts remaining runs by the target metric (descending).

    Returns:
        The 'run' result object of the winner, or None if no run qualifies.
    """
    valid_runs: list[OptimizationResult] = []

    # Filter
    for run in report.runs:
        m = run.metrics

        # Check constraints
        if m.precision < selection_config.min_precision:
            continue
        if m.fp > selection_config.max_false_positives:
            continue

        valid_runs.append(run)

    if not valid_runs:
        return None

    # Sort
    # Get the value of the target metric (e.g. 'recall' -> run.metrics.recall)
    target = selection_config.target_metric

    # Sort descending (higher is better)
    valid_runs.sort(key=lambda x: getattr(x.metrics, target), reverse=True)

    return valid_runs[0]


def run(args: argparse.Namespace) -> None:
    """
    Executes the optimization command workflow.
    """
    try:
        if not args.input or not args.benign_dataset:
            raise ConfigurationError(
                "Both --input (adversarial) and --benign-dataset are required "
                "for optimization."
            )

        config = _load_optimization_config(args.config)

        # Determine output path
        timestamp = (
            logger.handlers[0].baseFilename.split("_")[-1].replace(".log", "")
            if logger.handlers and hasattr(logger.handlers[0], "baseFilename")
            else "unknown"
        )
        output_file = args.output or Path(f"optimization_results_{timestamp}.json")

        log_header(logger, "YARA Gen - Optimization Mode")
        log_named_value(logger, "Adversarial Source", args.input)
        log_named_value(logger, "Benign Source", args.benign_dataset)
        log_named_value(logger, "Config File", args.config)
        log_named_value(logger, "Report Output", output_file)

        # Data Preparation (Splitter)
        # Hidden directory for cache
        cache_dir = Path("data/.optimize")
        splitter = DataSplitter(output_dir=cache_dir, seed=config.seed)

        # Load Source Streams
        # We default to JSONL for now.
        adv_adapter = get_adapter("jsonl", DatasetType.ADVERSARIAL)
        benign_adapter = get_adapter("jsonl", DatasetType.BENIGN)

        adv_stream = adv_adapter.load(args.input)
        benign_stream = benign_adapter.load(args.benign_dataset)

        splitter.prepare_splits(adv_stream, benign_stream, config.dev_split_ratio)

        # Optimization Loop
        optimizer = Optimizer(
            config=config,
            train_adv_path=splitter.train_adv_path,
            train_benign_path=splitter.train_benign_path,
            dev_path=splitter.dev_path,
            output_path=output_file,
        )

        report = optimizer.run()

        # Post-Processing (Selection)
        best_run = _select_best_run(report, config.selection)

        # TODO: This should be logged better
        print("\n" + "=" * 60)
        if best_run:
            m = best_run.metrics
            print(f"BEST RUN: Iteration #{best_run.iteration}")
            print(
                f"   Score ({config.selection.target_metric}): "
                f"{getattr(m, config.selection.target_metric):.4f}"
            )
            print(
                f"   Metrics: TP={m.tp} FP={m.fp} "
                f"Prec={m.precision:.3f} Rec={m.recall:.3f}"
            )
            print(f"   Parameters: {best_run.parameters}")
            print("-" * 60)

            # Generate CLI snippet
            # engine.min_ngram=4
            set_str = " ".join(
                [f"engine.{k}={v}" for k, v in best_run.parameters.items()]
            )
            print("To generate rules with this configuration:")
            print(
                f"yara-gen generate --input {args.input} "
                f"--benign-dataset {args.benign_dataset} --set {set_str}"
            )
        else:
            logger.warning(
                "No runs met the selection criteria (Constraints too strict?)"
            )

        print("=" * 60 + "\n")

    except ConfigurationError as e:
        logger.error(f"Configuration Error: {e}")
        sys.exit(1)
    except Exception:
        logger.exception("An unexpected critical error occurred during optimization")
        sys.exit(1)
