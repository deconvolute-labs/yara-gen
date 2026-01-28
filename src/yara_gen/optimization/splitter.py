import json
import random
from collections.abc import Iterable
from pathlib import Path
from typing import TextIO

from yara_gen.models.text import TextSample
from yara_gen.utils.logger import get_logger

logger = get_logger()


class DataSplitter:
    """
    Manages the creation of training and development splits for optimization.

    This class implements a 'hybrid' splitting strategy designed to balance performance
    with correctness:
    1.  **Training Set**: Written as separate files (`train_adv.jsonl`,
        `train_benign.jsonl`)
        to optimize for the NgramEngine, which processes adversarial and benign streams
        sequentially to build vocabularies and calculate penalties.
    2.  **Development Set**: Written as a single combined file (`dev.jsonl`) with
        explicit labels. This optimizes for the Evaluator, which needs to iterate
        once over the dataset to calculate confusion matrices.

    Attributes:
        output_dir (Path): The directory where split files will be stored.
        seed (int): Random seed used for deterministic splitting.
        train_adv_path (Path): Path to the generated adversarial training file.
        train_benign_path (Path): Path to the generated benign training file.
        dev_path (Path): Path to the generated combined development file.
    """

    def __init__(self, output_dir: Path, seed: int = 42):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.seed = seed
        self._rng = random.Random(seed)  # noqa

        self.train_adv_path = output_dir / "train_adv.jsonl"
        self.train_benign_path = output_dir / "train_benign.jsonl"
        self.dev_path = output_dir / "dev.jsonl"

    def prepare_splits(
        self,
        adv_stream: Iterable[TextSample],
        benign_stream: Iterable[TextSample],
        split_ratio: float,
    ) -> dict[str, int]:
        """
        Reads input streams, shuffles them, and writes split files to disk.

        This method iterates through the provided adversarial and benign streams.
        For each sample, it uses a random float (determined by the seed) to decide
        whether to assign the sample to the Training set or the Development set.

        Args:
            adv_stream (Iterable[TextSample]): The stream of adversarial text samples.
            benign_stream (Iterable[TextSample]): The stream of benign text samples.
            split_ratio (float): The proportion of data (0.0 to 1.0) to allocate to
                the Development set. For example, 0.2 means 20% Dev, 80% Train.

        Returns:
            dict[str, int]: A dictionary containing the counts of samples written to
                each split, e.g., {'train_adv': 800, 'dev_adv': 200, ...}.
        """
        logger.info(f"Preparing optimization datasets in {self.output_dir} ...")

        # Reset files
        for p in [self.train_adv_path, self.train_benign_path, self.dev_path]:
            with open(p, "w") as _:
                pass

        stats = {"train_adv": 0, "train_benign": 0, "dev_adv": 0, "dev_benign": 0}

        # Process Adversarial
        with (
            open(self.train_adv_path, "a", encoding="utf-8") as f_train,
            open(self.dev_path, "a", encoding="utf-8") as f_dev,
        ):
            for sample in adv_stream:
                if self._rng.random() < split_ratio:
                    # To Dev (Combined format needs label)
                    self._write_labeled(f_dev, sample, "adversarial")
                    stats["dev_adv"] += 1
                else:
                    # To Train (Native format)
                    f_train.write(sample.model_dump_json() + "\n")
                    stats["train_adv"] += 1

        # Process Benign
        with (
            open(self.train_benign_path, "a", encoding="utf-8") as f_train,
            open(self.dev_path, "a", encoding="utf-8") as f_dev,
        ):
            for sample in benign_stream:
                if self._rng.random() < split_ratio:
                    # To Dev
                    self._write_labeled(f_dev, sample, "benign")
                    stats["dev_benign"] += 1
                else:
                    # To Train
                    f_train.write(sample.model_dump_json() + "\n")
                    stats["train_benign"] += 1

        logger.info(f"Data Preparation Complete. Stats: {stats}")
        return stats

    def _write_labeled(
        self, file_handle: TextIO, sample: TextSample, label: str
    ) -> None:
        """
        Writes a sample to the development file with an explicit ground-truth label.

        This helper method takes a TextSample, converts it to a dictionary, injects
        the 'label' field (essential for the Evaluator to distinguish True Positives
        from False Positives), and writes it as a JSON line.

        Args:
            file_handle (TextIO): The open file handle for the development set.
            sample (TextSample): The text sample to write.
            label (str): The classification label (e.g. "adversarial", "benign").
        """
        data = sample.model_dump()
        data["label"] = label
        file_handle.write(json.dumps(data) + "\n")
