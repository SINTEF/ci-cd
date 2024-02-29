"""`setver` task.

Set the specified version.
"""

from __future__ import annotations

import logging
import re
import sys
import traceback
from pathlib import Path
from typing import TYPE_CHECKING

from invoke import task

from ci_cd.utils import Emoji, SemanticVersion, error_msg, update_file

# Get logger
LOGGER = logging.getLogger(__name__)


@task(
    help={
        "version": "Version to set. Must be either a SemVer or a PEP 440 version.",
        "package-dir": (
            "Relative path to package dir from the repository root, "
            "e.g. 'src/my_package'."
        ),
        "root-repo-path": (
            "A resolvable path to the root directory of the repository folder."
        ),
        "code-base-update": (
            "'--code-base-update-separator'-separated string defining 'file path', "
            "'pattern', 'replacement string', in that order, for something to update "
            "in the code base. E.g., '{package_dir}/__init__.py,__version__ *= "
            "*('|\").*('|\"),__version__ = \"{version}\"', where '{package_dir}' "
            "and {version} will be exchanged with the given '--package-dir' value and "
            "given '--version' value, respectively. The 'file path' must always "
            "either be relative to the repository root directory or absolute. The "
            "'pattern' should be given as a 'raw' Python string. This input option "
            "can be supplied multiple times."
        ),
        "code-base-update-separator": (
            "The string separator to use for '--code-base-update' values."
        ),
        "fail_fast": (
            "Whether to exit the task immediately upon failure or wait until the end. "
            "Note, no code changes will happen if an error occurs."
        ),
        "test": (
            "Whether to do a dry run or not. If set, the task will not make any "
            "changes to the code base."
        ),
    },
    iterable=["code_base_update"],
)
def setver(
    _,
    package_dir,
    version,
    root_repo_path=".",
    code_base_update=None,
    code_base_update_separator=",",
    test=False,
    fail_fast=False,
):
    """Sets the specified version of specified Python package."""
    if TYPE_CHECKING:  # pragma: no cover
        package_dir: str = package_dir  # type: ignore[no-redef]
        version: str = version  # type: ignore[no-redef]
        root_repo_path: str = root_repo_path  # type: ignore[no-redef]
        code_base_update: list[str] = code_base_update  # type: ignore[no-redef]
        code_base_update_separator: str = code_base_update_separator  # type: ignore[no-redef]
        test: bool = test  # type: ignore[no-redef]
        fail_fast: bool = fail_fast  # type: ignore[no-redef]

    try:
        semantic_version = SemanticVersion(version)
    except ValueError:
        sys.exit(
            "Error: Please specify version as a semantic version (SemVer) or "
            "PEP 440 version. The version may be prepended by a 'v'."
        )

    if not code_base_update:
        init_file = Path(root_repo_path).resolve() / package_dir / "__init__.py"
        if not init_file.exists():
            sys.exit(
                f"{Emoji.CROSS_MARK.value} Error: Could not find the Python package's "
                f"root '__init__.py' file at: {init_file}"
            )

        update_file(
            init_file,
            (
                r'__version__ *= *(?:\'|").*(?:\'|")',
                f'__version__ = "{semantic_version}"',
            ),
        )

        # Success, done
        print(
            f"{Emoji.PARTY_POPPER.value} Bumped version for {package_dir} to "
            f"{semantic_version}."
        )
        return

    # Code base updates were provided
    # First, validate the inputs
    validated_code_base_updates: list[tuple[Path, str, str, str]] = []
    error: bool = False
    for code_update in code_base_update:
        try:
            filepath, pattern, replacement = code_update.split(
                code_base_update_separator
            )
        except ValueError as exc:
            msg = (
                "Could not properly extract 'file path', 'pattern', "
                f"'replacement string' from the '--code-base-update'={code_update}:"
                f"\n{exc}"
            )
            LOGGER.error(msg)
            LOGGER.debug("Traceback: %s", traceback.format_exc())
            if fail_fast:
                sys.exit(f"{Emoji.CROSS_MARK.value} {error_msg(msg)}")
            print(error_msg(msg), file=sys.stderr, flush=True)
            error = True
            continue

        # Resolve file path
        filepath = Path(
            filepath.format(package_dir=package_dir, version=semantic_version)
        )

        if not filepath.is_absolute():
            filepath = Path(root_repo_path).resolve() / filepath

        if not filepath.exists():
            msg = f"Could not find the user-provided file at: {filepath}"
            LOGGER.error(msg)
            if fail_fast:
                sys.exit(f"{Emoji.CROSS_MARK.value} {error_msg(msg)}")
            print(error_msg(msg), file=sys.stderr, flush=True)
            error = True
            continue

        LOGGER.debug(
            """filepath: %s
pattern: %r
replacement (input): %s
replacement (handled): %s
""",
            filepath,
            pattern,
            replacement,
            replacement.format(package_dir=package_dir, version=semantic_version),
        )

        validated_code_base_updates.append(
            (
                filepath,
                pattern,
                replacement.format(package_dir=package_dir, version=semantic_version),
                replacement,
            )
        )

    if error:
        sys.exit(
            f"{Emoji.CROSS_MARK.value} Errors occurred! See printed statements above."
        )

    for (
        filepath,
        pattern,
        replacement,
        input_replacement,
    ) in validated_code_base_updates:
        if test:
            print(
                f"filepath: {filepath}\npattern: {pattern!r}\n"
                f"replacement (input): {input_replacement}\n"
                f"replacement (handled): {replacement}"
            )
            continue

        try:
            update_file(filepath, (pattern, replacement))
        except re.error as exc:
            if validated_code_base_updates[0] != (
                filepath,
                pattern,
                replacement,
                input_replacement,
            ):
                msg = "Some files have already been updated !\n\n "

            msg += (
                f"Could not update file {filepath} according to the given input:\n\n  "
                f"pattern: {pattern}\n  replacement: {replacement}\n\nException: "
                f"{exc}"
            )
            LOGGER.error(msg)
            LOGGER.debug("Traceback: %s", traceback.format_exc())
            sys.exit(f"{Emoji.CROSS_MARK.value} {error_msg(msg)}")

    # Success, done
    print(
        f"{Emoji.PARTY_POPPER.value} Bumped version for {package_dir} to "
        f"{semantic_version}."
    )
