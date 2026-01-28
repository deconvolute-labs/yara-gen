import pytest

from yara_gen.models.evaluator import EvaluationMetrics
from yara_gen.models.optimization_config import NgramSearchSpace, OptimizationConfig
from yara_gen.models.text import GeneratedRule
from yara_gen.optimization.optimizer import Optimizer


@pytest.fixture
def base_config():
    """Returns a config with a small, predictable search space."""
    return OptimizationConfig(
        search_space=NgramSearchSpace(
            type="ngram",
            min_ngram=[3, 4],
            max_ngram=[4],
            benign_penalty_weight=[1.0],
            score_threshold=[0.1, 0.2],
            min_document_frequency=[0.01],
        ),
        dev_split_ratio=0.2,
    )


@pytest.fixture
def optimizer(base_config, tmp_path):
    """Returns an Optimizer instance pointing to temp paths."""
    return Optimizer(
        config=base_config,
        train_adv_path=tmp_path / "train_adv.jsonl",
        train_benign_path=tmp_path / "train_benign.jsonl",
        dev_path=tmp_path / "dev.jsonl",
        output_path=tmp_path / "results.json",
    )


def test_generate_parameter_combinations(optimizer):
    """Verify Cartesian product logic."""
    combos = optimizer._generate_parameter_combinations()

    # We expect 2 * 2 * 1 * 1 * 1 = 4 combinations
    assert len(combos) == 4

    # Check structure
    first = combos[0]
    assert "min_ngram" in first
    assert "score_threshold" in first
    assert "type" not in first


def test_atomic_save_behavior(optimizer, tmp_path, mocker):
    """Verify os.replace is called to ensure data safety."""
    # Create a dummy report object
    from yara_gen.models.optimizer import OptimizationReport

    report = OptimizationReport(meta={"test": True}, runs=[])

    # Spy on os.replace
    replace_mock = mocker.patch("os.replace")

    optimizer._save_report_atomically(report)

    # Check that a temp file was written
    temp_file = tmp_path / "results.json.tmp"
    assert temp_file.exists()

    # Check that atomic replace was triggered
    replace_mock.assert_called_once_with(temp_file, optimizer.output_path)


def test_optimizer_run_loop(optimizer, mocker):
    """
    Test the full run loop by mocking the heavy Engine and Evaluator.
    This ensures the loop iterates correctly and aggregates results.
    """
    # Mock the Engine Factory
    mock_engine = mocker.Mock()
    # Engine returns a dummy list of rules
    mock_engine.extract.return_value = [
        GeneratedRule(name="test", score=1.0, strings=[], condition="")
    ]
    mocker.patch("yara_gen.optimization.optimizer.get_engine", return_value=mock_engine)

    # Mock the Adapter (file loading)
    mock_adapter = mocker.Mock()
    mocker.patch(
        "yara_gen.optimization.optimizer.get_adapter", return_value=mock_adapter
    )

    # Mock the Evaluator inside the optimizer instance
    optimizer.evaluator = mocker.Mock()
    # Return fixed metrics
    optimizer.evaluator.evaluate.return_value = EvaluationMetrics(
        tp=10, fp=2, precision=0.83
    )

    # Mock os.replace to avoid error on missing file
    # (since we mocked os.replace in test_atomic_save)
    mocker.patch("os.replace")

    report = optimizer.run()

    # Check Runs count (Should be 4 based on config)
    assert len(report.runs) == 4

    # Check Metrics aggregation
    assert report.runs[0].metrics.tp == 10

    # Check Engine calls
    # extract() should be called 4 times
    assert mock_engine.extract.call_count == 4

    # Check Evaluator calls
    assert optimizer.evaluator.evaluate.call_count == 4
