import sys
from pathlib import Path
from unittest.mock import MagicMock

import yaml

from yara_gen.main import main


def test_generate_dot_notation_overrides(tmp_path: Path, mocker: MagicMock) -> None:
    """
    Test that --set arguments (dot notation) correctly override config.yaml values
    during the 'generate' command execution.
    """
    input_dir = tmp_path / "data"
    input_dir.mkdir()

    # Create config.yaml with specific defaults
    config_file = tmp_path / "config.yaml"
    config_data = {
        "engine": {
            "type": "ngram",
            "min_ngram": 3,
            "max_ngram": 5,
            "max_rules_per_run": 10,
        },
        "adversarial_adapter": {"type": "jsonl"},
        "benign_adapter": {"type": "jsonl"},
    }
    config_file.write_text(yaml.dump(config_data), encoding="utf-8")

    # Create dummy input files (content doesn't matter as we mock the engine)
    adv_file = input_dir / "adversarial.jsonl"
    adv_file.write_text('{"text": "foo"}', encoding="utf-8")

    benign_file = input_dir / "benign.jsonl"
    benign_file.write_text('{"text": "bar"}', encoding="utf-8")

    # Mock Internal Components
    mock_get_engine = mocker.patch("yara_gen.cli.commands.generate.get_engine")
    mock_engine_instance = MagicMock()
    mock_get_engine.return_value = mock_engine_instance
    mock_engine_instance.extract.return_value = []  # Return empty rules

    # Mock adapters so they don't actually try to load files
    mocker.patch("yara_gen.cli.commands.generate.get_adapter")

    # We pass --set engine.min_ngram=10 and engine.max_rules_per_run=25 to
    # override defaults
    test_args = [
        "yara-gen",
        "generate",
        "--config",
        str(config_file),
        "--set",
        "engine.min_ngram=10",
        "--set",
        "engine.max_rules_per_run=25",
        str(adv_file),
        "--benign-dataset",
        str(benign_file),
    ]

    mocker.patch.object(sys, "argv", test_args)

    # Run the application
    main()

    # Verify get_engine was called
    assert mock_get_engine.called, "get_engine was not called"

    # Retrieve the configuration object passed to get_engine
    # Retrieve the configuration object passed to get_engine
    # Signature: get_engine(config_model)
    args, _ = mock_get_engine.call_args
    engine_config_arg = args[0]

    # Check if overrides were applied
    # Note: validation ensures these are integers if Pydantic model is correct
    # We access via getattr or direct attribute. Extra fields are accessible directly
    # in Pydantic v2
    min_ngram = getattr(engine_config_arg, "min_ngram", None)
    assert min_ngram == 10, f"min_ngram was not overridden by --set. Got: {min_ngram}"

    assert engine_config_arg.max_rules_per_run == 25, (
        f"max_rules_per_run not overridden. Got: {engine_config_arg.max_rules_per_run}"
    )

    # Check that non-overridden values remain as per config.yaml
    max_ngram = getattr(engine_config_arg, "max_ngram", None)
    assert max_ngram == 5, f"max_ngram should match config.yaml. Got: {max_ngram}"


def test_generate_cli_args_override_config(tmp_path: Path, mocker: MagicMock) -> None:
    """
    Test that explicit CLI flags (like --engine, --output) take precedence over
    values defined in config.yaml.
    """
    input_dir = tmp_path / "data"
    input_dir.mkdir()

    # Config defines 'stub' engine and a default output
    config_file = tmp_path / "config.yaml"
    config_data = {
        "output_path": "from_config.yar",
        "engine": {"type": "stub"},
        "adversarial_adapter": {"type": "jsonl"},
        "benign_adapter": {"type": "jsonl"},
    }
    config_file.write_text(yaml.dump(config_data), encoding="utf-8")

    adv_file = input_dir / "adversarial.jsonl"
    adv_file.write_text("{}")
    benign_file = input_dir / "benign.jsonl"
    benign_file.write_text("{}")

    # Mock Internal Components
    mock_get_engine = mocker.patch("yara_gen.cli.commands.generate.get_engine")
    mock_engine_instance = MagicMock()
    mock_get_engine.return_value = mock_engine_instance
    mock_engine_instance.extract.return_value = []

    mocker.patch("yara_gen.cli.commands.generate.get_adapter")

    # Mock YaraWriter to inspect the output path
    mock_writer = mocker.patch("yara_gen.cli.commands.generate.YaraWriter")
    mock_writer_instance = MagicMock()
    mock_writer.return_value = mock_writer_instance

    # Simulate CLI Execution
    # Override engine to 'ngram' and output to 'from_cli.yar'
    custom_output = tmp_path / "from_cli.yar"

    test_args = [
        "yara-gen",
        "--config",
        str(config_file),
        "generate",
        str(adv_file),
        "--benign-dataset",
        str(benign_file),
        "--output",
        str(custom_output),
        "--engine",
        "ngram",
    ]

    mocker.patch.object(sys, "argv", test_args)

    main()

    assert mock_get_engine.called
    engine_config_arg = mock_get_engine.call_args[0][0]
    assert engine_config_arg.type == "ngram", (
        "CLI --engine argument did not override config file"
    )

    # Check Output Path Override
    assert mock_writer_instance.write.called
    write_path = mock_writer_instance.write.call_args[0][1]
    assert write_path == custom_output, (
        "CLI --output argument did not override config file"
    )


def test_generate_adapter_overrides(tmp_path: Path, mocker: MagicMock) -> None:
    """
    Test that --adversarial-adapter and --benign-adapter arguments correctly
    override the values in config.yaml.
    """
    input_dir = tmp_path / "data"
    input_dir.mkdir()

    # Config defines defaults
    config_file = tmp_path / "config.yaml"
    config_data = {
        "adversarial_adapter": {"type": "jsonl"},
        "benign_adapter": {"type": "jsonl"},
        "engine": {"type": "stub"},
    }
    config_file.write_text(yaml.dump(config_data), encoding="utf-8")

    adv_file = input_dir / "adversarial.txt"
    adv_file.write_text("content")
    benign_file = input_dir / "benign.csv"
    benign_file.write_text("content")

    # Mock Internal Components
    mock_get_engine = mocker.patch("yara_gen.cli.commands.generate.get_engine")
    mock_engine_instance = MagicMock()
    mock_get_engine.return_value = mock_engine_instance
    mock_engine_instance.extract.return_value = []

    mock_get_adapter = mocker.patch("yara_gen.cli.commands.generate.get_adapter")
    mock_adapter_instance = MagicMock()
    mock_get_adapter.return_value = mock_adapter_instance
    # Allow .load() to be called and return an iterator
    mock_adapter_instance.load.return_value = iter([])

    # Mock Writer
    mocker.patch("yara_gen.cli.commands.generate.YaraWriter")

    # Simulate CLI Execution with Adapter Overrides
    test_args = [
        "yara-gen",
        "--config",
        str(config_file),
        "generate",
        str(adv_file),
        "--benign-dataset",
        str(benign_file),
        "--adversarial-adapter",
        "huggingface",
        "--benign-adapter",
        "csv",
    ]

    mocker.patch.object(sys, "argv", test_args)

    from yara_gen.models.text import DatasetType

    main()

    # Check that get_adapter was called with the overridden types
    # Expected calls:
    # 1. ("huggingface", DatasetType.ADVERSARIAL)
    # 2. ("csv", DatasetType.BENIGN)
    # Order depends on implementation, so checks needs to be robust or order-aware.
    # Implementation:
    # adv_adapter = get_adapter(adv_adapter_type, DatasetType.ADVERSARIAL)
    # benign_adapter = get_adapter(benign_adapter_type, DatasetType.BENIGN)
    # So both are called.

    # We can inspect call_args_list
    assert mock_get_adapter.call_count == 2, "get_adapter should be called twice"

    calls = mock_get_adapter.call_args_list

    # Verify Adversarial Adapter Call
    adv_call_found = any(
        call.args[0] == "huggingface" and call.args[1] == DatasetType.ADVERSARIAL
        for call in calls
    )
    assert adv_call_found, (
        "Adversarial adapter type was not overridden to 'huggingface'"
    )

    # Verify Benign Adapter Call
    benign_call_found = any(
        call.args[0] == "csv" and call.args[1] == DatasetType.BENIGN for call in calls
    )
    assert benign_call_found, "Benign adapter type was not overridden to 'csv'"
