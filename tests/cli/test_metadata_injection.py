import argparse
from unittest.mock import MagicMock

from yara_gen.cli.commands.generate import run
from yara_gen.models.config import AppConfig
from yara_gen.models.text import GeneratedRule, RuleString


def test_metadata_injection(mocker):
    mock_load_config = mocker.patch(
        "yara_gen.cli.commands.generate._load_app_configuration"
    )
    mock_init = mocker.patch("yara_gen.cli.commands.generate._initialize_components")
    mock_load_data = mocker.patch("yara_gen.cli.commands.generate._load_pipeline_data")
    mock_write = mocker.patch("yara_gen.cli.commands.generate._write_results")

    # Setup Config
    config = AppConfig(
        output_path="out.yar",
        tags=["global_tag"],
        metadata={"category": "test_category", "confidence": "low"},
    )
    mock_load_config.return_value = config
    mock_load_data.return_value = (MagicMock(), MagicMock())

    # Setup Engine Mock
    mock_engine = MagicMock()
    mock_engine.extract.return_value = [
        GeneratedRule(
            name="rule1",
            tags=["eng_tag"],
            score=0.5,
            metadata={"source": "eng"},  # existing metadata
            strings=[RuleString(value="abc", identifier="$s1", score=0.5)],
            condition="$s1",
        )
    ]
    mock_init.return_value = (mock_engine, MagicMock(), MagicMock())

    # Run
    args = argparse.Namespace(
        input="adv.jsonl",
        benign_dataset="benign.jsonl",
        output=None,
        config=None,
        set=None,
        adversarial_adapter=None,
        benign_adapter=None,
        engine=None,
        rule_date=None,
        tags=None,
        existing_rules=None,
    )
    run(args)

    # Asset
    # Check that _write_results was called with rules containing merged metadata
    assert mock_write.called
    rules = mock_write.call_args[0][0]
    assert len(rules) == 1
    rule = rules[0]

    # Metadata should contain both original and injected values
    assert rule.metadata["source"] == "eng"
    assert rule.metadata["category"] == "test_category"
    assert rule.metadata["confidence"] == "low"

    # Tags should be merged
    assert "global_tag" in rule.tags
    assert "eng_tag" in rule.tags
