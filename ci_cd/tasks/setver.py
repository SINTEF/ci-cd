"""`setver` task.

Set the specified version.
"""
import logging
import re
import sys
import traceback
from pathlib import Path
from typing import TYPE_CHECKING

from invoke import task

from ci_cd.utils import Emoji, SemanticVersion, update_file

# Get logger
LOGGER = logging.getLogger(__name__)


@task(
    help={
        "version": "Version to set.",
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
            "Whether to exist the task immediately upon failure or wait until the end."
        ),
        "test": "Whether to print extra debugging statements.",
    },
    iterable=["code_base_update"],
)
def setver(  # pylint: disable=too-many-locals
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
        code_base_update_separator: str = code_base_update_separator  # type: ignore[no-redef]  # pylint: disable=line-too-long
        test: bool = test  # type: ignore[no-redef]
        fail_fast: bool = fail_fast  # type: ignore[no-redef]

    match = re.fullmatch(
        (
            r"v?(?P<major>[0-9]+)\.(?P<minor>[0-9]+)\.(?P<patch>[0-9]+)"
            r"(?:-(?P<pre_release>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
            r"(?:\+(?P<build>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
        ),
        version,
    )
    if not match:
        sys.exit(
            "Error: Please specify version as "
            "'Major.Minor.Patch(-Pre-Release+Build Metadata)' or "
            "'vMajor.Minor.Patch(-Pre-Release+Build Metadata)'"
        )
    semantic_version = SemanticVersion(**match.groupdict())

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
    else:
        errors: list[str] = []
        for code_update in code_base_update:
            try:
                filepath, pattern, replacement = code_update.split(
                    code_base_update_separator
                )
            except ValueError:
                msg = traceback.format_exc()
                LOGGER.error(msg)
                if test:
                    print(msg)
                sys.exit(
                    f"{Emoji.CROSS_MARK.value} Error: Could not properly extract "
                    "'file path', 'pattern', 'replacement string' from the "
                    f"'--code-base-update'={code_update}"
                )

            filepath = Path(
                filepath.format(
                    **{"package_dir": package_dir, "version": semantic_version}
                )
            ).resolve()
            if not filepath.exists():
                error_msg = (
                    f"{Emoji.CROSS_MARK.value} Error: Could not find the "
                    f"user-provided file at: {filepath}"
                )
                if fail_fast:
                    sys.exit(error_msg)
                errors.append(error_msg)
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
                replacement.format(
                    **{"package_dir": package_dir, "version": semantic_version}
                ),
            )
            if test:
                print(
                    f"filepath: {filepath}\npattern: {pattern!r}\n"
                    f"replacement (input): {replacement}"
                )
                print(
                    "replacement (handled): "
                    f"{replacement.format(**{'package_dir': package_dir, 'version': semantic_version})}"  # pylint: disable=line-too-long
                )

            try:
                update_file(
                    filepath,
                    (
                        pattern,
                        replacement.format(
                            **{"package_dir": package_dir, "version": semantic_version}
                        ),
                    ),
                )
            except re.error:
                msg = traceback.format_exc()
                LOGGER.error(msg)
                if test:
                    print(msg)
                sys.exit(
                    f"{Emoji.CROSS_MARK.value} Error: Could not update file {filepath}"
                    f" according to the given input:\n\n  pattern: {pattern}\n  "
                    "replacement: "
                    f"{replacement.format(**{'package_dir': package_dir, 'version': semantic_version})}"  # pylint: disable=line-too-long
                )

    print(
        f"{Emoji.PARTY_POPPER.value} Bumped version for {package_dir} to "
        f"{semantic_version}."
    )
