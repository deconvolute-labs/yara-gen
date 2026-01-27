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
        "engine": {"type": "ngram", "min_ngram": 3, "max_ngram": 5, "top_k": 10},
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

    # We pass --set engine.min_ngram=10 and engine.top_k=50 to override defaults
    test_args = [
        "yara-gen",
        "--config",
        str(config_file),
        "--set",
        "engine.min_ngram=10",
        "--set",
        "engine.top_k=50",
        "generate",
        str(adv_file),
        "--benign",
        str(benign_file),
    ]

    mocker.patch.object(sys, "argv", test_args)

    # Run the application
    main()

    # Verify get_engine was called
    assert mock_get_engine.called, "get_engine was not called"

    # Retrieve the configuration object passed to get_engine
    # Signature: get_engine(engine_type, config_model)
    args, _ = mock_get_engine.call_args
    engine_config_arg = args[1]

    # Check if overrides were applied
    # Note: validation ensures these are integers if Pydantic model is correct
    assert engine_config_arg.min_ngram == 10, "min_ngram was not overridden by --set"
    assert engine_config_arg.top_k == 50, "top_k was not overridden by --set"

    # Check that non-overridden values remain as per config.yaml
    assert engine_config_arg.max_ngram == 5, "max_ngram should match config.yaml"


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
        "--benign",
        str(benign_file),
        "--output",
        str(custom_output),
        "--engine",
        "ngram",
    ]

    mocker.patch.object(sys, "argv", test_args)

    main()

    assert mock_get_engine.called
    engine_type_arg = mock_get_engine.call_args[0][0]
    assert engine_type_arg == "ngram", (
        "CLI --engine argument did not override config file"
    )

    # Check Output Path Override
    assert mock_writer_instance.write.called
    write_path = mock_writer_instance.write.call_args[0][1]
    assert write_path == custom_output, (
        "CLI --output argument did not override config file"
    )
