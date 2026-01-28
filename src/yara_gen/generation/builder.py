import hashlib
import re
from datetime import date

from yara_gen.constants import META_AUTHOR, META_DESC
from yara_gen.models.text import GeneratedRule, RuleString


class RuleBuilder:
    """
    Factory class to construct standardized GeneratedRule objects from raw data.
    Handles naming conventions, hashing, and metadata injection.
    """

    @staticmethod
    def build_from_ngram(
        text: str, score: float, source: str, rule_date: str | None = None
    ) -> GeneratedRule:
        """
        Creates a GeneratedRule from a raw n-gram candidate.

        Args:
            text: The n-gram string (e.g. "ignore previous instructions").
            score: The calculated safety score.
            source: The dataset source name.
            rule_date: Optional fixed date string. Defaults to today.

        Returns:
            A fully formed GeneratedRule object with rich metadata.
        """
        score_val = round(score, 4)

        # Generate smart name
        # Sanitize: "Ignore previous" -> "ignore_previous"
        clean_text = re.sub(r"[^a-zA-Z0-9]+", "_", text).strip("_").lower()

        # Truncate to keep readable (first 3 words or 40 chars)
        short_slug = "_".join(clean_text.split("_")[:3])
        if len(short_slug) > 40:
            short_slug = short_slug[:40]

        # Add hash for uniqueness (collision avoidance)
        text_hash = hashlib.md5(text.encode("utf-8")).hexdigest()[:4]  # noqa
        rule_name = f"auto_{short_slug}_{text_hash}"

        return GeneratedRule(
            name=rule_name,
            tags=["generated", "prompt_injection"],
            score=score_val,
            condition="any of them",
            strings=[
                RuleString(
                    value=text,
                    identifier="$s1",
                    score=score_val,
                    modifiers=["nocase", "wide", "ascii"],
                )
            ],
            metadata={
                "author": META_AUTHOR,
                "description": META_DESC,
                "date": rule_date or date.today().isoformat(),
                "source": source,
                "score": str(score_val),
            },
        )
