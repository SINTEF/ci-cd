"""Test fixtures."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _clear_loggers() -> None:
    """Remove handlers from all loggers"""
    import logging

    loggers = [
        logging.getLogger(),
        *(
            _
            for _ in logging.Logger.manager.loggerDict.values()
            if isinstance(_, logging.Logger)
        ),
    ]
    for logger in loggers:
        handlers = getattr(logger, "handlers", [])
        for handler in handlers:
            logger.removeHandler(handler)
