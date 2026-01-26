from collections.abc import Iterable
from typing import Any

import numpy as np
from sklearn.feature_extraction.text import CountVectorizer

from yara_gen.extraction.base import BaseExtractor
from yara_gen.generation.builder import RuleBuilder
from yara_gen.models.config import NgramConfig
from yara_gen.models.text import GeneratedRule, TextSample
from yara_gen.utils.logger import get_logger

logger = get_logger()


class NgramExtractor(BaseExtractor[NgramConfig]):
    """
    Extraction engine based on Differential N-Gram Analysis.

    This engine identifies phrases that are statistically over-represented in the
    adversarial dataset compared to the benign control set. It uses a subtractive
    scoring model to penalize phrases that appear in safe contexts.

    Algorithm Stages:
    1. Candidate Generation: Find n-grams (3-10 words) appearing in >1% of attacks.
    2. Differential Scoring: Score = P(Attack) - (Lambda * P(Benign)).
    3. Subsumption Filtering: Remove redundant substrings (e.g. remove "ignore previous"
       if "ignore previous instructions" has the same score).
    4. Greedy Set Cover: Select the minimal set of rules that cover the maximum number
       of unique adversarial samples.
    """

    def extract(
        self, adversarial: Iterable[TextSample], benign: Iterable[TextSample]
    ) -> list[GeneratedRule]:
        """
        Executes the Differential N-Gram Analysis pipeline to generate YARA rules.

        The algorithm proceeds in four main stages:

        1.  **Vectorization & Candidate Generation**:
            Converts raw text into n-grams (phrases of length N). Only n-grams
            appearing in at least 1% (`min_df=0.01`) of the adversarial dataset
            are retained as candidates. This step filters out unique noise.

        2.  **Differential Scoring**:
            Calculates a safety score for every candidate using the formula:
            `Score = P(Adversarial) - (Lambda * P(Benign))`
            Where `P` is the document frequency (percentage of samples containing the
            phrase). Candidates with a score below `config.score_threshold` are
            discarded.

        3.  **Subsumption Optimization**:
            Removes redundant substrings. If "ignore previous" and "ignore previous
            instructions" both have high scores, the shorter phrase is removed to
            prefer specific, high-fidelity signatures over generic ones.

        4.  **Greedy Set Cover Optimization**:
            Selects the smallest set of rules that covers the maximum number of
            unique adversarial samples. This ensures the output ruleset is diverse
            and efficient, rather than returning 50 variations of the same phrase.

        Args:
            adversarial (Iterable[TextSample]): The dataset of attack prompts.
            benign (Iterable[TextSample]): The control dataset of safe prompts.

        Returns:
            List[GeneratedRule]: A list of optimized, high-confidence YARA rule objects.

        Raises:
            ValueError: If the adversarial dataset is empty or if vectorization fails
            due
        """
        # 1. Materialize Data
        # We need lists for sklearn. For very large datasets, we would implement
        # `dask` or batching, but for <500k samples, lists are faster and simpler.
        adv_samples = list(adversarial)
        benign_samples = list(benign)

        logger.info(f"Found {len(adv_samples)} adversarial samples.")
        logger.info(f"Found {len(benign_samples)} benign samples.")

        adv_texts: list[str] = [s.text for s in adv_samples]
        benign_texts: list[str] = [s.text for s in benign_samples]
        n_adv = len(adv_texts)
        n_benign = len(benign_texts) if benign_texts else 1

        source_name = "unknown_source"
        if adv_samples:
            source_name = adv_samples[0].source

        if n_adv == 0:
            logger.warning("No adversarial samples provided. Skipping extraction.")
            return []

        logger.info(
            f"Starting extraction on {n_adv} adversarial and {n_benign} benign samples."
        )

        # 2. Vectorization & Counting
        # We use a single vectorizer to handle both datasets. This ensures the
        # vocabulary (feature indices) is identical for efficient numpy operations.
        # min_df=0.01: A phrase must appear in 1% of attacks to be worth checking.
        vectorizer = CountVectorizer(
            ngram_range=(
                self.config.min_ngram_length,
                self.config.max_ngram_length,
            ),
            min_df=0.01,
            binary=True,  # We care about presence (Document Freq), not Count.
            lowercase=True,
            analyzer="word",
        )

        logger.debug("Generating n-gram candidates (this may take a moment)...")
        try:
            # Fit on adversarial to find candidates
            X_adv = vectorizer.fit_transform(adv_texts)
        except ValueError:
            # Usually happens if vocabulary is empty (e.g. documents too short)
            logger.warning("No n-grams met the frequency threshold.")
            return []

        feature_names = vectorizer.get_feature_names_out()
        logger.info(f"Analyzed {len(feature_names)} candidate n-grams.")

        # 3. Benign Cross-Reference
        # We only check benign documents for the *specific* n-grams we found above.
        # This is highly optimized (we don't count random benign words).
        if benign_texts:
            X_benign = vectorizer.transform(benign_texts)
            benign_counts = np.array(X_benign.sum(axis=0)).flatten()
        else:
            benign_counts = np.zeros(len(feature_names))

        adv_counts = np.array(X_adv.sum(axis=0)).flatten()

        # 4. Differential Scoring
        # We calculate frequency vectors.
        # Formula: Score = Freq_Adv - (Penalty * Freq_Benign)
        freq_adv = adv_counts / n_adv
        freq_benign = benign_counts / n_benign

        # Why Subtraction?
        # Ratios (A/B) are unstable for small denominators. Subtraction provides a
        # linear penalty that is easier to reason about.
        scores = freq_adv - (self.config.benign_penalty_weight * freq_benign)

        # Filter by threshold immediately to reduce data size
        threshold_mask = scores >= self.config.score_threshold

        # Extract passing candidates
        candidates = []
        # We need the indices to keep track of X_adv columns for Set Cover
        passing_indices = np.where(threshold_mask)[0]

        for idx in passing_indices:
            candidates.append(
                {
                    "text": feature_names[idx],
                    "score": scores[idx],
                    "original_index": idx,  # Pointer to the sparse matrix column
                }
            )

        logger.info(f"Found {len(candidates)} candidates passing score threshold.")
        if not candidates:
            return []

        # 5. Optimization: Subsumption (String Deduplication)
        # We remove short phrases that are fully contained in longer phrases
        # if the longer phrase has a similar or better score.
        candidates = self._filter_subsumed(candidates)
        logger.info(f"Reduced to {len(candidates)} candidates after subsumption check.")

        # 6. Optimization: Greedy Set Cover
        # We select the smallest set of rules that covers the most adversarial samples.
        selected_candidates = self._greedy_set_cover(candidates, X_adv, n_adv)
        logger.info(f"Selected top {len(selected_candidates)} rules via Set Cover.")

        # 7. Convert to GeneratedRule objects
        return [
            RuleBuilder.build_from_ngram(
                text=c["text"],
                score=c["score"],
                source=source_name,
                rule_date=self.config.rule_date,
            )
            for c in selected_candidates
        ]

    def _filter_subsumed(
        self, candidates: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """
        Removes shorter n-grams that are substrings of longer n-grams with
        equal/better scores.

        Why?
        If we have "ignore previous" (score 0.9) and "ignore previous instructions"
        (score 0.95),
        we prefer the longer one because it is more specific and less likely to FP.

        However, if the shorter one has a MUCH better score (e.g. 1.0 vs 0.5),
        we keep the shorter one because the longer one is missing too many attacks.
        """
        # Sort by length descending (longest first)
        candidates = sorted(candidates, key=lambda x: len(x["text"]), reverse=True)
        kept: list[dict[str, Any]] = []

        # O(N^2) comparison - acceptable for N < 5000 candidates
        for _i, short_cand in enumerate(candidates):
            is_subsumed = False
            for long_cand in kept:
                # Check if 'short' is inside 'long'
                if short_cand["text"] in long_cand["text"]:
                    # Check scores
                    # If the longer phrase is at least 95% as effective as the
                    # short one, we prefer the longer one (safety).
                    if long_cand["score"] >= (short_cand["score"] * 0.95):
                        is_subsumed = True
                        break

            if not is_subsumed:
                kept.append(short_cand)

        return kept

    def _greedy_set_cover(
        self, candidates: list[dict[str, Any]], X_adv: Any, total_samples: int
    ) -> list[dict[str, Any]]:
        """
        Selects candidates based on Marginal Value.

        Algorithm:
        1. Identify which samples are currently 'uncovered'.
        2. Pick the candidate that covers the MOST 'uncovered' samples.
        3. Mark those samples as covered.
        4. Repeat until no candidate adds significant value.

        Args:
            candidates: List of candidate dicts (must have 'original_index').
            X_adv: The full sparse matrix from CountVectorizer.
            total_samples: Number of adversarial samples.
        """
        # Track which samples (rows) have been hit by a selected rule
        covered_mask = np.zeros(total_samples, dtype=bool)
        selected: list[dict[str, Any]] = []

        # We limit the max rules to avoid massive files, but allow up to 50 for now
        MAX_RULES = 50

        # Pre-compute the column vectors for our filtered candidates to avoid sparse
        # indexing in loop
        # Format: {candidate_idx_in_list: dense_boolean_array}
        candidate_vectors = {}
        for i, cand in enumerate(candidates):
            col_idx = cand["original_index"]
            # Convert sparse column to dense boolean array for fast masking
            candidate_vectors[i] = X_adv[:, col_idx].toarray().flatten().astype(bool)

        for _ in range(MAX_RULES):
            best_candidate_idx = -1
            best_new_coverage = 0

            # Find the rule that hits the most UNCOVERED samples
            current_uncovered = ~covered_mask

            # If everything is covered, stop
            if not np.any(current_uncovered):
                break

            for i, _ in enumerate(candidates):
                if i in [x["idx"] for x in selected]:
                    continue

                hits = candidate_vectors[i]
                # Logical AND: Hits matches AND Sample is currently uncovered
                new_hits = np.sum(hits & current_uncovered)

                if new_hits > best_new_coverage:
                    best_new_coverage = new_hits
                    best_candidate_idx = i

            # Stop if diminishing returns (e.g. rule adds < 0.5% coverage)
            # For now, we are strict: if it adds NOTHING, stop.
            if best_candidate_idx == -1 or best_new_coverage == 0:
                break

            # Commit the selection
            selected.append(
                {"idx": best_candidate_idx, **candidates[best_candidate_idx]}
            )
            covered_mask = covered_mask | candidate_vectors[best_candidate_idx]

            logger.debug(
                f"Selected '{candidates[best_candidate_idx]['text']}' "
                f"(New coverage: {best_new_coverage} samples)"
            )

        return selected
