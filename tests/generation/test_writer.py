import pytest

from yara_gen.generation.writer import YaraWriter
from yara_gen.models.text import GeneratedRule, RuleString


class TestYaraWriter:
    @pytest.fixture
    def writer(self):
        return YaraWriter()

    @pytest.fixture
    def sample_rule(self):
        return GeneratedRule(
            name="test_rule_01",
            tags=["test"],
            score=1.0,
            metadata={"source": "unit_test"},
            condition="$s1",
            strings=[
                RuleString(
                    value="suspicious string",
                    score=1.0,
                    modifiers=["nocase"],
                    identifier="$s1",
                )
            ],
        )

    def test_write_creates_valid_file(self, writer, sample_rule, tmp_path):
        """Smoke test: writes a file that looks like YARA."""
        output_file = tmp_path / "rules" / "test.yar"

        writer.write([sample_rule], output_file)

        assert output_file.exists()
        content = output_file.read_text("utf-8")

        assert "rule test_rule_01 : test" in content
        assert '$s1 = "suspicious string" nocase' in content
        assert 'source = "unit_test"' in content

    def test_quote_escaping_in_strings(self, writer, tmp_path):
        """
        CRITICAL: If the prompt contains quotes, they must be escaped.
        Prompt: 'say "hello"' -> YARA: "say \"hello\""
        """
        risky_rule = GeneratedRule(
            name="quote_test",
            tags=[],
            score=1.0,
            metadata={},
            condition="$s1",
            strings=[
                RuleString(
                    value='say "hello" now', score=1.0, modifiers=[], identifier="$s1"
                )
            ],
        )
        output_file = tmp_path / "escaped.yar"

        writer.write([risky_rule], output_file)
        content = output_file.read_text("utf-8")

        # We expect the file to contain: "say \"hello\" now"
        # In Python string literal for regex/check, that is:
        expected = r"say \"hello\" now"
        assert expected in content

    def test_backslash_escaping(self, writer, tmp_path):
        """
        CRITICAL: Backslashes must be double-escaped.
        Prompt: C:\Windows -> YARA: C:\\Windows
        """
        path_rule = GeneratedRule(
            name="path_test",
            tags=[],
            score=1.0,
            metadata={},
            condition="$s1",
            strings=[
                RuleString(
                    value=r"C:\Windows\System32",
                    score=1.0,
                    modifiers=[],
                    identifier="$s1",
                )
            ],
        )
        output_file = tmp_path / "backslash.yar"

        writer.write([path_rule], output_file)
        content = output_file.read_text("utf-8")

        # In the file, it should look like: "C:\\Windows\\System32"
        # We search for the double backslash.
        assert r"C:\\Windows\\System32" in content

    def test_metadata_escaping(self, writer, tmp_path):
        """Metadata values should also be escaped."""
        meta_rule = GeneratedRule(
            name="meta_test",
            tags=[],
            score=1.0,
            metadata={"description": 'He said "ignore"'},
            condition="$s1",
            strings=[
                RuleString(value="test", score=1.0, modifiers=[], identifier="$s1")
            ],
        )
        output_file = tmp_path / "meta.yar"

        writer.write([meta_rule], output_file)
        content = output_file.read_text("utf-8")

        assert r'description = "He said \"ignore\""' in content

    def test_empty_list_does_nothing(self, writer, tmp_path):
        """Writing an empty list should not create a file."""
        output_file = tmp_path / "ghost.yar"
        writer.write([], output_file)

        assert not output_file.exists()

    def test_custom_template_support(self, tmp_path):
        """Verify we can swap the Jinja2 template."""
        custom_template = "rule {{ rules[0].name }} { condition: true }"
        writer = YaraWriter(template_str=custom_template)

        rule = GeneratedRule(
            name="simple_rule",
            tags=[],
            score=1.0,
            metadata={},
            condition="$s1",
            strings=[RuleString(value="a", score=1.0, modifiers=[], identifier="$s1")],
        )

        output_file = tmp_path / "simple.yar"
        writer.write([rule], output_file)

        content = output_file.read_text("utf-8")
        assert content.strip() == "rule simple_rule { condition: true }"
