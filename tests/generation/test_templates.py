import pytest
from jinja2 import Environment

from yara_gen.generation.templates import YARA_TEMPLATE
from yara_gen.models.text import GeneratedRule, RuleString


class TestYaraTemplate:
    @pytest.fixture
    def template(self):
        """Create a Jinja2 template from the source string."""
        env = Environment(autoescape=True)
        return env.from_string(YARA_TEMPLATE)

    def test_basic_rendering(self, template):
        """Test rendering a single simple rule."""
        rule = GeneratedRule(
            name="TestRule",
            score=1.0,
            strings=[RuleString(value="evil_string", score=1.0)],
        )

        output = template.render(timestamp="2025-01-01", rules=[rule])

        assert "rule TestRule" in output
        assert '$s1 = "evil_string"' in output
        assert "any of them" in output

    def test_rendering_metadata(self, template):
        """Test that metadata is correctly rendered."""
        rule = GeneratedRule(
            name="MetaRule",
            score=1.0,
            strings=[RuleString(value="foo", score=1.0)],
            metadata={"author": "Unit Test", "severity": "High"},
        )

        output = template.render(timestamp="2025-01-01", rules=[rule])

        # Check metadata block
        assert 'author = "Unit Test"' in output
        assert 'severity = "High"' in output

    def test_rendering_tags(self, template):
        """Test that tags are correctly rendered."""
        rule = GeneratedRule(
            name="TaggedRule",
            tags=["APT", "Trojan"],
            score=1.0,
            strings=[RuleString(value="foo", score=1.0)],
        )

        output = template.render(timestamp="2025-01-01", rules=[rule])

        # Tags appear after rule name
        assert "rule TaggedRule : APT Trojan" in output

    def test_multiple_rules(self, template):
        """Test rendering multiple rules in one file."""
        r1 = GeneratedRule(
            name="Rule1", score=1.0, strings=[RuleString(value="a", score=1)]
        )
        r2 = GeneratedRule(
            name="Rule2", score=1.0, strings=[RuleString(value="b", score=1)]
        )

        output = template.render(timestamp="2025-01-01", rules=[r1, r2])

        assert "rule Rule1" in output
        assert "rule Rule2" in output
