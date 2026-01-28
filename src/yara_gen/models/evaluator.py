from pydantic import BaseModel


class EvaluationMetrics(BaseModel):
    """
    Data container for the performance metrics of a single optimization run.

    Attributes:
        tp (int): True Positives - Adversarial samples correctly matched by rules.
        fp (int): False Positives - Benign samples incorrectly matched by rules.
        tn (int): True Negatives - Benign samples correctly ignored by rules.
        fn (int): False Negatives - Adversarial samples missed by rules.
        precision (float): The accuracy of positive predictions (TP / (TP + FP)).
        recall (float): The ability to find all positive instances (TP / (TP + FN)).
        f1_score (float): The harmonic mean of precision and recall.
    """

    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
