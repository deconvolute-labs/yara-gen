import json

import pytest

from yara_gen.models.text import DatasetType, TextSample
from yara_gen.optimization.splitter import DataSplitter


@pytest.fixture
def sample_data():
    # Create 100 samples of each type
    adv = [
        TextSample(
            text=f"adv_{i}", source="test_src", dataset_type=DatasetType.ADVERSARIAL
        )
        for i in range(100)
    ]
    benign = [
        TextSample(
            text=f"benign_{i}", source="test_src", dataset_type=DatasetType.BENIGN
        )
        for i in range(100)
    ]
    return adv, benign


def test_prepare_splits_ratio(tmp_path, sample_data):
    """
    Verify that the split ratio approximately respects the requested float.
    With 100 samples and a stable seed, we expect roughly 20 items in dev.
    """
    adv_list, benign_list = sample_data

    # Initialize splitter in a temp directory
    splitter = DataSplitter(output_dir=tmp_path, seed=42)

    # Request 20% Dev, 80% Train
    stats = splitter.prepare_splits(adv_list, benign_list, split_ratio=0.2)

    # 1. Verify Sample Conservation (No data lost)
    assert stats["train_adv"] + stats["dev_adv"] == 100
    assert stats["train_benign"] + stats["dev_benign"] == 100

    # 2. Verify Files Created
    assert (tmp_path / "train_adv.jsonl").exists()
    assert (tmp_path / "train_benign.jsonl").exists()
    assert (tmp_path / "dev.jsonl").exists()

    # 3. Verify Ratio (Approximate check for randomness)
    # With seed 42, we expect deviation to be small
    dev_total = stats["dev_adv"] + stats["dev_benign"]
    assert 30 <= dev_total <= 50  # Roughly 40 items total (20+20)


def test_prepare_splits_labeling(tmp_path, sample_data):
    """
    Verify that the dev set file contains the critical 'label' field
    required by the Evaluator to calculate False Positives.
    """
    adv_list, benign_list = sample_data
    splitter = DataSplitter(output_dir=tmp_path, seed=42)

    # Run split
    splitter.prepare_splits(adv_list, benign_list, split_ratio=0.5)

    dev_file = tmp_path / "dev.jsonl"

    # Read generated file
    with open(dev_file) as f:
        lines = [json.loads(line) for line in f]

    assert len(lines) > 0

    has_adv = False
    has_benign = False

    for item in lines:
        # Check Schema
        assert "label" in item, "Dev set item missing 'label' field"
        assert "text" in item

        # Check Label Correctness
        if "adv_" in item["text"]:
            assert item["label"] == "adversarial"
            has_adv = True
        elif "benign_" in item["text"]:
            assert item["label"] == "benign"
            has_benign = True

    # Ensure we actually tested both types
    assert has_adv, "Dev set contained no adversarial samples"
    assert has_benign, "Dev set contained no benign samples"


def test_determinism(tmp_path, sample_data):
    """
    Verify that using the same seed produces bit-exact identical output files.
    This ensures we can reproduce the 'Best Run' later.
    """
    adv_list, benign_list = sample_data

    # Run 1
    dir1 = tmp_path / "run1"
    s1 = DataSplitter(output_dir=dir1, seed=12345)
    stats1 = s1.prepare_splits(adv_list, benign_list, split_ratio=0.2)

    # Run 2
    dir2 = tmp_path / "run2"
    s2 = DataSplitter(output_dir=dir2, seed=12345)
    stats2 = s2.prepare_splits(adv_list, benign_list, split_ratio=0.2)

    # Compare Stats
    assert stats1 == stats2

    # Compare File Contents
    with open(dir1 / "train_adv.jsonl") as f1, open(dir2 / "train_adv.jsonl") as f2:
        assert f1.read() == f2.read(), (
            "Adversarial train files differ despite same seed"
        )

    with open(dir1 / "dev.jsonl") as f1, open(dir2 / "dev.jsonl") as f2:
        assert f1.read() == f2.read(), "Dev files differ despite same seed"
