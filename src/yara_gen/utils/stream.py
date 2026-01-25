from collections.abc import Generator, Iterable

from yara_gen.models.text import TextSample
from yara_gen.utils.logger import get_logger

logger = get_logger()


def filter_stream(
    stream: Iterable[TextSample], filter_col: str, filter_val: str
) -> Generator[TextSample]:
    """
    Middleware that filters a stream of TextSamples based on a metadata column.

    Args:
        stream: The source iterator of TextSamples.
        filter_col: The metadata key (column name) to check.
        filter_val: The string value that must match for the sample to be kept.

    Yields:
        TextSample: Only the samples where sample.metadata[col] == val.
    """
    total = 0
    kept = 0
    missing_col_count = 0

    logger.info(
        f"Filtering stream: keeping rows where '{filter_col}' == '{filter_val}'"
    )

    for sample in stream:
        total += 1

        # Check metadata first (most common), then fall back to core attributes
        val_in_sample = sample.metadata.get(filter_col)

        # If not in metadata, check if user is filtering by 'source' or 'dataset_type'
        if val_in_sample is None:
            if filter_col == "source":
                val_in_sample = sample.source
            elif filter_col == "dataset_type":
                val_in_sample = sample.dataset_type.value

        if val_in_sample is None:
            missing_col_count += 1
            continue

        # String comparison for robustness (e.g. 1 vs "1")
        if str(val_in_sample) == str(filter_val):
            yield sample
            kept += 1

    dropped = total - kept
    logger.info(f"Filter complete: Kept {kept}/{total} samples (Dropped {dropped})")

    if missing_col_count == total and total > 0:
        logger.warning(
            f"Filter column '{filter_col}' was NOT FOUND in any of the "
            f"{total} samples. Check your column name!"
        )
    elif kept == 0 and total > 0:
        logger.warning(
            f"Filter matched 0 samples! (Verified column '{filter_col}' exists)."
        )
