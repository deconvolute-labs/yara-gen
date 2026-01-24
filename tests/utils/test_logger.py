import logging

import pytest

from yara_gen.utils.logger import get_logger, setup_logger


class TestLogger:
    @pytest.fixture(autouse=True)
    def clean_logger(self):
        """Ensure we start with a fresh logger state for each test if possible,
        or at least reset handlers."""
        logger = logging.getLogger("test_logger")
        logger.handlers = []
        yield
        logger.handlers = []

    def test_setup_logger_creates_logger(self):
        """Test that setup_logger returns a logger with the correct name."""
        logger = setup_logger("test_logger")
        assert logger.name == "test_logger"
        assert isinstance(logger, logging.Logger)
        assert logger.hasHandlers()

    def test_setup_logger_idempotency(self):
        """
        Test that calling setup_logger twice returns the same instance
        without adding dup handlers.
        """
        l1 = setup_logger("test_logger_idem")
        num_handlers = len(l1.handlers)

        l2 = setup_logger("test_logger_idem")
        assert l1 is l2
        assert len(l2.handlers) == num_handlers

    def test_get_logger(self):
        """Test the helper to retrieve an existing logger."""
        l1 = setup_logger("test_retrieval")
        l2 = get_logger("test_retrieval")
        assert l1 is l2
