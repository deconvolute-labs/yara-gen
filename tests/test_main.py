import sys
from pathlib import Path
from unittest.mock import MagicMock

from yara_gen.main import main
from yara_gen.models.text import GeneratedRule, RuleString


def test_generate_command_deduplication(tmp_path: Path, mocker: MagicMock) -> None:
    """
    Integration test for the 'generate' command with deduplication.

    Scenario:
        - Input: Mocked engine returns 2 rules:
            1. 'rule_dup' containing string "known_malware"
            2. 'rule_new' containing string "zero_day_exploit"
        - Existing Rules: A .yar file containing "known_malware"

    Expected Outcome:
        - The output file should ONLY contain 'rule_new'.
        - 'rule_dup' should be filtered out because "known_malware" matches the
            existing file.
    """

    input_dir = tmp_path / "data"
    input_dir.mkdir()

    # Create dummy input files (content doesn't matter as we mock the engine)
    adv_file = input_dir / "adversarial.jsonl"
    adv_file.write_text(
        '{"text": "xyz", "source": "test", "dataset_type": "adversarial"}',
        encoding="utf-8",
    )

    benign_file = input_dir / "benign.jsonl"
    benign_file.write_text(
        '{"text": "abc", "source": "test", "dataset_type": "benign"}', encoding="utf-8"
    )

    # Create the EXISTING rules file (The Deduplication Source)
    # This rule contains the payload "known_malware"
    existing_rules_file = input_dir / "existing.yar"
    existing_rules_file.write_text(
        """
        rule OldRule {
            strings:
                $s1 = "known_malware"
            condition:
                $s1
        }
    """,
        encoding="utf-8",
    )

    output_file = tmp_path / "output.yar"

    # Mock Internal Components
    # We mock 'get_engine' so we don't need to rely on the actual N-Gram engine
    # finding patterns in our dummy data. We just want to test the filtering logic
    # in main.
    mock_get_engine = mocker.patch("yara_gen.cli.commands.generate.get_engine")
    mock_engine_instance = MagicMock()
    mock_get_engine.return_value = mock_engine_instance

    # Define the Rules that the engine "finds"
    rule_duplicate = GeneratedRule(
        name="auto_duplicate",
        score=0.9,
        strings=[RuleString(value="known_malware", score=1.0)],  # Matches existing!
        metadata={"description": "Should be dropped"},
    )

    rule_new = GeneratedRule(
        name="auto_new_rule",
        score=0.9,
        strings=[RuleString(value="zero_day_exploit", score=1.0)],  # Unique
        metadata={"description": "Should be kept"},
    )

    mock_engine_instance.extract.return_value = [rule_duplicate, rule_new]

    # Mock CLI Arguments
    test_args = [
        "yara-gen",
        "generate",
        str(adv_file),
        "--benign",
        str(benign_file),
        "--output",
        str(output_file),
        "--existing-rules",
        str(existing_rules_file),
        "--engine",
        "ngram",
    ]

    mocker.patch.object(sys, "argv", test_args)

    # Should read args, call our mock engine, filter, and write.
    main()

    assert output_file.exists(), "Output file was not created"

    output_content = output_file.read_text(encoding="utf-8")

    # The unique payload should be present
    assert "zero_day_exploit" in output_content, (
        "The new unique rule was incorrectly filtered out."
    )

    # The duplicate payload should be missing
    assert "known_malware" not in output_content, (
        "The duplicate rule was NOT filtered out."
    )

    # The rule names
    assert "auto_new_rule" in output_content
    assert "auto_duplicate" not in output_content
