"""CI/CD Tools. Tiny package to run invoke tasks as a standalone program."""

from __future__ import annotations

import logging

__version__ = "2.9.2"
__author__ = "Casper Welzel Andersen"
__author_email__ = "casper.w.andersen@sintef.no"


logging.getLogger("ci_cd").setLevel(logging.DEBUG)
