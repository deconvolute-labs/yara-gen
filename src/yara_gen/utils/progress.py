from collections.abc import Iterable, Iterator
from typing import TypeVar

from yara_gen.utils.logger import get_logger

T = TypeVar("T")
logger = get_logger()


class ProgressGenerator(Iterable[T]):
    """
    A wrapper around an iterator that logs progress at fixed intervals.
    Useful for streaming operations where the total count is unknown.
    """

    def __init__(
        self, iterable: Iterable[T], desc: str = "Processing", interval: int = 1000
    ):
        self.iterable = iterable
        self.desc = desc
        self.interval = interval
        self.count = 0

    def __iter__(self) -> Iterator[T]:
        for item in self.iterable:
            yield item
            self.count += 1
            if self.count % self.interval == 0:
                logger.info(f"{self.desc}: {self.count} items processed ...")

        logger.info(f"{self.desc}: Finished. Total {self.count} items.")
