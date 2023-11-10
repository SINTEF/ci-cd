"""Utilities for handling IO operations."""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from pathlib import Path


def update_file(
    filename: Path, sub_line: tuple[str, str], strip: str | None = None
) -> None:
    """Utility function for tasks to read, update, and write files"""
    if strip is None and filename.suffix == ".md":
        # Keep special white space endings for markdown files
        strip = "\n"
    lines = [
        re.sub(sub_line[0], sub_line[1], line.rstrip(strip))
        for line in filename.read_text(encoding="utf8").splitlines()
    ]
    filename.write_text("\n".join(lines) + "\n", encoding="utf8")
