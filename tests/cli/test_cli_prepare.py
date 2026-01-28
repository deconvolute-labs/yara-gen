import argparse
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture

from yara_gen.cli.commands.prepare import run
from yara_gen.constants import AdapterType
from yara_gen.models.text import DatasetType


@pytest.fixture
def run_args(tmp_path: Path) -> argparse.Namespace:
    input_file = tmp_path / "input.txt"
    input_file.touch()
    output_file = tmp_path / "output.jsonl"
    return argparse.Namespace(
        input=input_file,
        output=output_file,
        adapter=AdapterType.RAW_TEXT.value,
        limit=None,
        filter=None,
        set=[],
    )


def test_prepare_command_basic(
    run_args: argparse.Namespace, mocker: MockerFixture
) -> None:
    """Test the basic execution of the prepare command."""
    # Mock dependencies
    mock_adapter = MagicMock()
    mock_adapter.load.return_value = []
    mock_get_adapter = mocker.patch(
        "yara_gen.cli.commands.prepare.get_adapter", return_value=mock_adapter
    )

    # Mock logger to verify output
    mock_logger = mocker.patch("yara_gen.cli.commands.prepare.logger")

    run(run_args)

    # Verify adapter was requested correctly
    # Implicitly verified by return_value, but being explicit:
    mock_get_adapter.assert_called_with(AdapterType.RAW_TEXT.value, DatasetType.RAW)

    # Verify load called
    mock_adapter.load.assert_called_once()

    # Verify success message
    assert mock_logger.info.called
    assert "Successfully wrote" in mock_logger.info.call_args_list[-1][0][0]


def test_prepare_command_limit(
    run_args: argparse.Namespace, mocker: MockerFixture
) -> None:
    """Test the prepare command with a limit."""
    run_args.limit = 2

    # Mock adapter returning infinite stream (or large list)
    mock_adapter = MagicMock()
    # Mock objects conforming to .to_dict()
    mock_item = MagicMock()
    mock_item.to_dict.return_value = {"text": "foo"}
    mock_adapter.load.return_value = [mock_item] * 10

    mocker.patch("yara_gen.cli.commands.prepare.get_adapter", return_value=mock_adapter)

    run(run_args)

    # Check output file has 2 lines
    with run_args.output.open() as f:
        lines = f.readlines()

    assert len(lines) == 2


def test_prepare_command_adapter_config_override(
    run_args: argparse.Namespace, mocker: MockerFixture
) -> None:
    """Test overriding adapter config via --set."""
    run_args.set = ["adapter.chunk_size=512"]

    mock_adapter = MagicMock()
    mock_adapter.load.return_value = []
    mocker.patch("yara_gen.cli.commands.prepare.get_adapter", return_value=mock_adapter)

    run(run_args)

    # Check if load was called with the overridden param
    # Note: 'type' is excluded in the call
    kwargs = mock_adapter.load.call_args.kwargs
    assert kwargs.get("chunk_size") == 512
