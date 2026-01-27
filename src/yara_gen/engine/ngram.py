import itertools
from collections.abc import Iterable
from typing import Any

import numpy as np
from sklearn.feature_extraction.text import CountVectorizer

from yara_gen.constants import EngineConstants
from yara_gen.engine.base import BaseEngine
from yara_gen.errors import DataError
from yara_gen.generation.builder import RuleBuilder
from yara_gen.models.config import NgramEngineConfig
from yara_gen.models.text import GeneratedRule, TextSample
from yara_gen.utils.logger import get_logger
from yara_gen.utils.progress import ProgressGenerator

logger = get_logger()

PROGRESS_LOG_INTERVAL = 100


class NgramEngine(BaseEngine[NgramEngineConfig]):
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
        # 1. Streaming setup
        # We need to peek at the first adversarial item to get the 'source' name,
        # but we cannot consume the iterator.
        adv_iterator = iter(adversarial)
        try:
            first_adv = next(adv_iterator)
            source_name = first_adv.source
            # Reconstruct the stream: [first_item] + rest_of_iterator
            adv_stream = itertools.chain([first_adv], adv_iterator)
        except StopIteration:
            logger.warning("No adversarial samples provided. Skipping extraction.")
            return []

        # Wrap streams in ProgressGenerator for visibility
        adv_stream_tracked = ProgressGenerator(
            adv_stream,
            desc="Vectorizing Adversarial Samples",
            interval=PROGRESS_LOG_INTERVAL,
        )

        # We create a text generator for the vectorizer
        # Note: We can't access .source anymore after this without complex tee-ing,
        # which is why we peeked above.
        adv_texts = (s.text for s in adv_stream_tracked)

        # Benign is simpler, we just need the texts
        benign_texts = (s.text for s in benign)

        # 2. Vectorization & Counting
        # We use a single vectorizer to handle both datasets. This ensures the
        # vocabulary (feature indices) is identical for efficient numpy operations.
        # min_df=0.01: A phrase must appear in 1% of attacks to be worth checking.
        vectorizer = CountVectorizer(
            ngram_range=(
                self.config.min_ngram,
                self.config.max_ngram,
            ),
            min_df=self.config.min_document_frequency,
            binary=True,  # We care about presence (Document Freq), not Count.
            lowercase=True,
            analyzer="word",
        )

        logger.debug("Generating n-gram candidates ...")
        try:
            # Fit on adversarial to find candidates
            X_adv = vectorizer.fit_transform(adv_texts)
        except ValueError as e:
            # Usually happens if vocabulary is empty (e.g. documents too short)
            raise DataError(
                "No n-grams met the frequency threshold. "
                "The adversarial dataset might be too small or too diverse."
            ) from e

        # Get the actual count from the matrix shape (rows, columns)
        n_adv = X_adv.shape[0]
        feature_names = vectorizer.get_feature_names_out()
        logger.info(
            f"Analyzed {len(feature_names)} candidate n-grams from {n_adv} samples."
        )

        # 3. Benign Cross-Reference
        # Note: vectorizer is already fitted, so we use transform()
        # We handle the case where benign might be empty
        try:
            X_benign = vectorizer.transform(benign_texts)
            benign_counts = np.array(X_benign.sum(axis=0)).flatten()
            n_benign = X_benign.shape[0]
            if n_benign == 0:
                n_benign = 1  # Avoid division by zero
        except ValueError:
            # Likely empty benign set or issues with stream
            logger.debug("Benign set empty or invalid, assuming 0 benign occurrences.")
            benign_counts = np.zeros(len(feature_names))
            n_benign = 1

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

        max_score = np.max(scores) if len(scores) > 0 else 0.0
        avg_score = np.mean(scores) if len(scores) > 0 else 0.0

        logger.info(f"Score Distribution: Max={max_score:.4f}, Mean={avg_score:.4f}")

        if max_score < self.config.score_threshold:
            logger.warning(
                f"Highest scoring candidate ({max_score:.4f}) is below the "
                f"configured threshold ({self.config.score_threshold}). "
                "No rules will be generated. Try using --mode loose or --threshold."
            )

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

        # Pre-compute the column vectors for our filtered candidates to avoid sparse
        # indexing in loop
        # Format: {candidate_idx_in_list: dense_boolean_array}
        candidate_vectors = {}
        for i, cand in enumerate(candidates):
            col_idx = cand["original_index"]
            # Convert sparse column to dense boolean array for fast masking
            candidate_vectors[i] = X_adv[:, col_idx].toarray().flatten().astype(bool)

        for _ in range(EngineConstants.MAX_RULES_PER_RUN.value):
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
