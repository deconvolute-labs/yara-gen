import pytest
from scipy import sparse

from yara_gen.engine.ngram import NgramEngine
from yara_gen.models.engine_config import NgramEngineConfig
from yara_gen.models.text import DatasetType, TextSample


@pytest.fixture
def engine():
    """Returns an NgramEngine instance with default config."""
    config = NgramEngineConfig(
        score_threshold=0.5,
        min_ngram=2,  # Small for testing
        max_ngram=5,
        benign_penalty_weight=1.0,
    )
    return NgramEngine(config)


class TestSubsumptionLogic:
    """Tests for _filter_subsumed (Logic Stage 3)."""

    def test_removes_redundant_short_phrase(self, engine):
        """
        Scenario: Longer phrase has similar score.
        Action: Should keep the LONGER phrase (safety).
        """
        candidates = [
            {"text": "ignore previous", "score": 0.9},
            {"text": "ignore previous instructions", "score": 0.95},
        ]

        result = engine._filter_subsumed(candidates)

        assert len(result) == 1
        assert result[0]["text"] == "ignore previous instructions"

    def test_keeps_short_phrase_if_score_is_much_better(self, engine):
        """
        Scenario: Shorter phrase has vastly better score (1.0 vs 0.5).
        Action: Should keep the SHORTER phrase (robustness).
        """
        candidates = [
            {"text": "ignore previous", "score": 1.0},
            {"text": "ignore previous instructions", "score": 0.5},
        ]

        result = engine._filter_subsumed(candidates)

        # Should keep both, or at least the short one.
        # Logic: Short is NOT subsumed because long's score is too low.
        texts = {c["text"] for c in result}
        assert "ignore previous" in texts

    def test_keeps_distinct_phrases(self, engine):
        """
        Scenario: Phrases do not overlap textually.
        Action: Keep both.
        """
        candidates = [
            {"text": "system override", "score": 0.9},
            {"text": "delete database", "score": 0.9},
        ]

        result = engine._filter_subsumed(candidates)

        assert len(result) == 2


class TestSetCoverLogic:
    """Tests for _greedy_set_cover (Logic Stage 4)."""

    def test_selects_best_coverage_rule(self, engine):
        """
        Scenario: 3 candidates.
            - Rule A covers samples [0, 1]
            - Rule B covers samples [2]
            - Rule C covers samples [0, 1, 2] (The 'Perfect' Rule)
        Expected: Rule C should be picked first and cover everything.
        """
        # Mock sparse matrix (Rows=Samples, Cols=Features/Candidates)
        # We have 3 samples, 3 candidates (A, B, C)
        # Col 0 (A): 1, 1, 0
        # Col 1 (B): 0, 0, 1
        # Col 2 (C): 1, 1, 1
        X_adv = sparse.csc_matrix([[1, 0, 1], [1, 0, 1], [0, 1, 1]])

        candidates = [
            {"text": "Rule A", "score": 0.8, "original_index": 0},
            {"text": "Rule B", "score": 0.8, "original_index": 1},
            {"text": "Rule C", "score": 0.9, "original_index": 2},
        ]

        selected = engine._greedy_set_cover(candidates, X_adv, total_samples=3)

        # It should pick Rule C because it covers 3 samples (A covers 2, B covers 1)
        assert len(selected) >= 1
        assert selected[0]["text"] == "Rule C"

        # Since C covers everything, we expect it to stop there
        assert len(selected) == 1

    def test_iterative_selection(self, engine):
        """
        Scenario: No single rule covers everything.
            - Rule A covers [0, 1]
            - Rule B covers [2, 3]
        Expected: Pick both.
        """
        X_adv = sparse.csc_matrix(
            [
                [1, 0],  # Sample 0
                [1, 0],  # Sample 1
                [0, 1],  # Sample 2
                [0, 1],  # Sample 3
            ]
        )

        candidates = [
            {"text": "Rule A", "score": 0.9, "original_index": 0},
            {"text": "Rule B", "score": 0.9, "original_index": 1},
        ]

        selected = engine._greedy_set_cover(candidates, X_adv, total_samples=4)

        assert len(selected) == 2
        texts = {s["text"] for s in selected}
        assert "Rule A" in texts
        assert "Rule B" in texts


class TestFullIntegration:
    """Integration test for the full extract method."""

    def test_extract_identifies_attack_pattern(self, engine):
        """
        Pass real strings and verify the full pipeline finds the common ngram.
        """
        # Adversarial: "attack prompt X" appears in all
        adversarial = [
            TextSample(
                text="this is an attack prompt one",
                source="test",
                dataset_type=DatasetType.ADVERSARIAL,
            ),
            TextSample(
                text="this is an attack prompt two",
                source="test",
                dataset_type=DatasetType.ADVERSARIAL,
            ),
            TextSample(
                text="ignore everything attack prompt three",
                source="test",
                dataset_type=DatasetType.ADVERSARIAL,
            ),
        ]

        # Benign: "this is an" appears here too (should be penalized)
        benign = [
            TextSample(
                text="this is an innocent sentence",
                source="test",
                dataset_type=DatasetType.BENIGN,
            ),
        ]

        # The phrase "attack prompt" appears in 100% of attacks and 0% of benign.
        # The phrase "this is an" appears in 66% of attacks and 100% of
        # benign -> Score < 0.

        rules = engine.extract(adversarial, benign)

        assert len(rules) > 0

        # Check that we found the attack phrase
        rule_strings = [r.strings[0].value for r in rules]
        assert "attack prompt" in rule_strings

        # Check that we eliminated the benign overlap
        assert "this is an" not in rule_strings

    def test_empty_input_returns_empty(self, engine):
        rules = engine.extract([], [])
        assert rules == []
