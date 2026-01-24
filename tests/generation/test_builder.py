import re
from datetime import date

from yara_gen.constants import META_AUTHOR
from yara_gen.generation.builder import RuleBuilder


class TestRuleBuilder:
    def test_build_generates_correct_metadata(self):
        """Verify that author, date, and source are injected correctly."""
        text = "system override"
        source = "test_dataset_v1"
        score = 0.88777

        rule = RuleBuilder.build_from_ngram(text, score, source)

        assert rule.metadata["author"] == META_AUTHOR
        assert rule.metadata["source"] == source
        # Date should be today (ISO format)
        assert rule.metadata["date"] == date.today().isoformat()
        # Score should be stringified and rounded
        assert rule.metadata["score"] == "0.8878"

    def test_naming_sanitization(self):
        """
        Ensure names are safe YARA identifiers (alphanumeric + underscores).
        "Ignore! Previous? Instructions." -> "auto_ignore_previous_instructions_..."
        """
        text = "Ignore! Previous? Instructions."
        rule = RuleBuilder.build_from_ngram(text, 1.0, "src")

        # Must start with 'auto_'
        assert rule.name.startswith("auto_")

        # Check for invalid characters in the name (only a-z, 0-9, _)
        # We strip the hash part for the check or just check the whole string
        assert re.match(r"^[a-z0-9_]+$", rule.name)

        # Ensure the slug part is correct ("ignore_previous_instructions")
        assert "ignore_previous_instructions" in rule.name

    def test_naming_truncation(self):
        """
        Ensure extremely long n-grams don't create invalid/unreadable rule names.
        """
        # A very long phrase
        text = "this is a very long phrase that would be annoying as a rule name"
        rule = RuleBuilder.build_from_ngram(text, 1.0, "src")

        # It should take the first 3 words: "this_is_a"
        assert "this_is_a" in rule.name
        # And generally be short enough
        assert len(rule.name) < 60  # auto_ + 25 char slug + hash

    def test_hashing_collision_avoidance(self):
        """
        Two different strings with same prefix should have different names
        due to the hash suffix.
        """
        rule1 = RuleBuilder.build_from_ngram("ignore instructions now", 1.0, "src")
        rule2 = RuleBuilder.build_from_ngram("ignore instructions later", 1.0, "src")

        # Slugs might both be "ignore_instructions" (depending on truncation logic),
        # but the full names must differ.
        assert rule1.name != rule2.name

    def test_score_rounding(self):
        """Scores should be rounded to 4 decimals."""
        rule = RuleBuilder.build_from_ngram("test", 0.123456789, "src")

        # The object attribute
        assert rule.score == 0.1235
        # The string string attribute
        assert rule.strings[0].score == 0.1235
