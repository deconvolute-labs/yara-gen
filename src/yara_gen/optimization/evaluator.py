import json
from pathlib import Path

import yara

from yara_gen.generation.writer import YaraWriter
from yara_gen.models.evaluator import EvaluationMetrics
from yara_gen.models.text import GeneratedRule
from yara_gen.utils.logger import get_logger

logger = get_logger()


class Evaluator:
    """
    Compiles generated rules and scans the development dataset to calculate metrics.

    This class bridges the gap between the generated rule objects and the YARA
    execution engine. It handles:
    1.  Converting internal `GeneratedRule` objects into valid YARA source code.
    2.  Compiling the YARA rules using the `yara-python` library.
    3.  Scanning the development dataset to populate the confusion matrix (TP/FP/TN/FN).
    """

    def __init__(self) -> None:
        # We reuse the writer logic but will capture string output
        self.writer = YaraWriter()

    def evaluate(
        self, rules: list[GeneratedRule], dev_set_path: Path
    ) -> EvaluationMetrics:
        """
        Runs the provided rules against the development set and calculates metrics.

        This method compiles the rules into a binary YARA scanner and streams the
        development dataset (JSONL). It compares the scanner's output against the
        'label' field in each JSON record to update the confusion matrix.

        Args:
            rules (list[GeneratedRule]): The list of generated rules to evaluate.
            dev_set_path (Path): The file path to the labeled JSONL development dataset.

        Returns:
            EvaluationMetrics: An object containing counts (TP, FP, etc.) and
                derived metrics (Precision, Recall, F1). If rule compilation fails
                or no rules are provided, returns zeroed metrics.
        """
        if not rules:
            logger.warning("No rules generated. Returning zero metrics.")
            return EvaluationMetrics()

        # Compile Rules
        # We convert our rule objects to a single valid YARA string
        rule_string = self._rules_to_string(rules)

        try:
            # Compile logic
            yara_rules = yara.compile(source=rule_string)
        except yara.SyntaxError as e:
            logger.error(f"Generated rules failed to compile: {e}")
            return EvaluationMetrics()

        # Scan & Score
        metrics = EvaluationMetrics()

        with open(dev_set_path, encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue

                record = json.loads(line)
                text = record.get("text", "")
                label = record.get("label", "benign")  # Default to benign if missing

                # Run YARA
                # We catch exceptions to prevent one bad sample killing the loop
                try:
                    matches = yara_rules.match(data=text)
                    is_match = len(matches) > 0
                except Exception:
                    is_match = False

                # Update Confusion Matrix
                if label == "adversarial":
                    if is_match:
                        metrics.tp += 1
                    else:
                        metrics.fn += 1
                else:  # benign
                    if is_match:
                        metrics.fp += 1
                    else:
                        metrics.tn += 1

        # Calculate Derived Metrics
        metrics.precision = self._safe_div(metrics.tp, metrics.tp + metrics.fp)
        metrics.recall = self._safe_div(metrics.tp, metrics.tp + metrics.fn)
        metrics.f1_score = self._safe_div(
            2 * metrics.precision * metrics.recall, metrics.precision + metrics.recall
        )

        return metrics

    def _rules_to_string(self, rules: list[GeneratedRule]) -> str:
        """
        Converts a list of GeneratedRule objects into a valid YARA rule string.

        Constructs the raw string representation of the YARA rules, including
        metadata, strings, and conditions, formatted correctly for the YARA compiler.

        Args:
            rules (list[GeneratedRule]): The list of rule objects to convert.

        Returns:
            str: A single string containing all rules, ready for `yara.compile()`.
        """
        output = []
        for rule in rules:
            # Header
            output.append(f"rule {rule.name} {{")

            # Meta
            if rule.metadata:
                output.append("    meta:")
                for k, v in rule.metadata.items():
                    # Escape quotes in values
                    val_str = str(v).replace('"', '\\"')
                    output.append(f'        {k} = "{val_str}"')

            # Strings
            output.append("    strings:")
            for s in rule.strings:
                # Assuming text strings for now as per NgramEngine
                # Escape backslashes and double quotes
                safe_val = s.value.replace("\\", "\\\\").replace('"', '\\"')
                mods = " ".join(s.modifiers)
                output.append(f'        {s.identifier} = "{safe_val}" {mods}')

            # Condition
            output.append("    condition:")
            output.append(f"        {rule.condition}")
            output.append("}")
            output.append("")

        return "\n".join(output)

    def _safe_div(self, n: float, d: float) -> float:
        """
        Performs division while handling division-by-zero errors.

        Args:
            n (float): The numerator.
            d (float): The denominator.

        Returns:
            float: The result of n/d, or 0.0 if the denominator is <= 0.
        """
        return n / d if d > 0 else 0.0
