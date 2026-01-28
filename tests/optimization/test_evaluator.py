import json

import pytest
import yara

from yara_gen.models.text import GeneratedRule, RuleString
from yara_gen.optimization.evaluator import Evaluator


@pytest.fixture
def evaluator():
    return Evaluator()


@pytest.fixture
def mock_dev_file(tmp_path):
    """Creates a temporary labeled development dataset."""
    data = [
        {"text": "this is an attack", "label": "adversarial"},
        {"text": "this is safe", "label": "benign"},
        {"text": "another attack pattern", "label": "adversarial"},
        {"text": "completely harmless", "label": "benign"},
    ]

    p = tmp_path / "dev.jsonl"
    with open(p, "w") as f:
        for item in data:
            f.write(json.dumps(item) + "\n")
    return p


@pytest.fixture
def dummy_rules():
    r1 = GeneratedRule(
        name="rule_attack",
        score=1.0,
        strings=[RuleString(identifier="$s1", value="attack", score=1.0)],
        condition="any of them",
    )
    r2 = GeneratedRule(
        name="rule_safe",
        score=0.5,
        strings=[RuleString(identifier="$s1", value="safe", score=0.5)],
        condition="any of them",
    )
    return [r1, r2]


def test_evaluate_metrics_calculation(evaluator, mock_dev_file):
    """Test the end-to-end flow with real YARA compilation."""
    r1 = GeneratedRule(
        name="rule_attack",
        score=1.0,
        strings=[RuleString(identifier="$s1", value="attack", score=1.0)],
        condition="any of them",
    )
    r2 = GeneratedRule(
        name="rule_safe",
        score=0.5,
        strings=[RuleString(identifier="$s1", value="safe", score=0.5)],
        condition="any of them",
    )

    metrics = evaluator.evaluate([r1, r2], mock_dev_file)

    assert metrics.tp == 2
    assert metrics.fp == 1
    assert metrics.tn == 1
    assert metrics.fn == 0
    assert 0.66 < metrics.precision < 0.67
    assert metrics.recall == 1.0


def test_evaluate_compilation_error(evaluator, mock_dev_file, dummy_rules, mocker):
    """
    If YARA compilation fails, return zero metrics and log error.
    Using pytest-mock to simulate the SyntaxError.
    """
    # Mock yara.compile to raise SyntaxError
    mocker.patch("yara.compile", side_effect=yara.SyntaxError("Mock Error"))

    # We also mock logger to ensure the error is logged (optional but good practice)
    mock_logger = mocker.patch("yara_gen.optimization.evaluator.logger")

    metrics = evaluator.evaluate(dummy_rules, mock_dev_file)

    assert metrics.tp == 0
    assert metrics.fp == 0

    # Verify the error was logged
    mock_logger.error.assert_called_once()
