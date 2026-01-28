import json
from argparse import Namespace
from pathlib import Path

import pytest

from yara_gen.cli.commands import optimize


@pytest.fixture
def input_files(tmp_path):
    """Creates minimal valid input files for the CLI smoke test."""
    adv_path = tmp_path / "adv.jsonl"
    benign_path = tmp_path / "benign.jsonl"

    with open(adv_path, "w") as f:
        f.write(json.dumps({"text": "attack sample", "source": "src"}) + "\n")

    with open(benign_path, "w") as f:
        f.write(json.dumps({"text": "safe sample", "source": "src"}) + "\n")

    return adv_path, benign_path


def test_optimize_cli_end_to_end(input_files, tmp_path, mocker):
    """
    Smoke test: Runs the optimize command with real arguments but mocked Engine.
    We mock the Engine to avoid Ngram processing overhead, but let the Splitter
    and Optimizer logic run to verify wiring.
    """
    adv_path, benign_path = input_files
    output_path = tmp_path / "final_report.json"

    # Mock the Engine to return empty rules immediately
    # This prevents the test from hanging on actual processing
    mock_engine = mocker.Mock()
    mock_engine.extract.return_value = []
    mocker.patch("yara_gen.optimization.optimizer.get_engine", return_value=mock_engine)

    # Mock the Evaluator to return zeros
    mock_evaluator = mocker.Mock()
    from yara_gen.models.evaluator import EvaluationMetrics

    mock_evaluator.evaluate.return_value = EvaluationMetrics()
    # We need to patch the Evaluator class so that when Optimizer() instantiates it,
    # it gets our mock
    mocker.patch(
        "yara_gen.optimization.optimizer.Evaluator", return_value=mock_evaluator
    )

    # Mock the DataSplitter class to return paths in our tmp_path
    mock_splitter_instance = mocker.Mock()
    mock_splitter_instance.train_adv_path = tmp_path / "train_adv.jsonl"
    mock_splitter_instance.train_benign_path = tmp_path / "train_benign.jsonl"
    mock_splitter_instance.dev_path = tmp_path / "dev.jsonl"
    # Ensure these files exist so Optimizer doesn't crash loading them
    mock_splitter_instance.train_adv_path.touch()
    mock_splitter_instance.train_benign_path.touch()
    mock_splitter_instance.dev_path.touch()

    mocker.patch(
        "yara_gen.cli.commands.optimize.DataSplitter",
        return_value=mock_splitter_instance,
    )

    # Mock loading the config to avoid needing a real config file on disk
    mock_config = mocker.Mock()
    mock_config.seed = 42
    mock_config.dev_split_ratio = 0.2
    mock_config.model_dump.return_value = {"mock": "config"}
    # Create a minimal valid search space
    from yara_gen.models.optimization_config import NgramSearchSpace, SelectionConfig

    mock_config.search_space = NgramSearchSpace(min_ngram=[3])
    mock_config.selection = SelectionConfig()

    mocker.patch(
        "yara_gen.cli.commands.optimize._load_optimization_config",
        return_value=mock_config,
    )

    # Construct Args
    args = Namespace(
        input=adv_path,
        benign_dataset=benign_path,
        config=Path("dummy_config.yaml"),
        output=output_path,
    )

    optimize.run(args)

    # Did it try to save the report?
    # Since we let the Optimizer run (mostly), it should have created the output file.
    # Note: `_save_report_atomically` writes to .tmp then renames.
    assert output_path.exists(), "Optimization report was not created"

    # Did we split data?
    mock_splitter_instance.prepare_splits.assert_called_once()
