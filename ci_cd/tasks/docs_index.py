"""`create_docs_index` task.

Create the documentation index (home) page from `README.md`.
"""
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from invoke import task

from ci_cd.utils import Emoji

if TYPE_CHECKING:  # pragma: no cover
    from typing import List

    from invoke import Context, Result


@task(
    help={
        "pre-commit": "Whether or not this task is run as a pre-commit hook.",
        "root-repo-path": (
            "A resolvable path to the root directory of the repository folder."
        ),
        "docs-folder": (
            "The folder name for the documentation root folder. "
            "This defaults to 'docs'."
        ),
        "replacement": (
            "A replacement (mapping) to be performed on README.md when creating the "
            "documentation's landing page (index.md). This list ALWAYS includes "
            "replacing '{docs-folder}/' with an empty string, in order to correct "
            "relative links. This input option can be supplied multiple times."
        ),
        "replacement-separator": (
            "String to separate a replacement's 'old' to 'new' parts."
            "Defaults to a comma (,)."
        ),
    },
    iterable=["replacement"],
)
def create_docs_index(  # pylint: disable=too-many-locals
    context,
    pre_commit=False,
    root_repo_path=".",
    docs_folder="docs",
    replacement=None,
    replacement_separator=",",
):
    """Create the documentation index page from README.md."""
    if TYPE_CHECKING:  # pragma: no cover
        context: "Context" = context  # type: ignore[no-redef]
        pre_commit: bool = pre_commit  # type: ignore[no-redef]
        root_repo_path: str = root_repo_path  # type: ignore[no-redef]
        replacement_separator: str = replacement_separator  # type: ignore[no-redef]

    docs_folder: Path = Path(docs_folder)

    if not replacement:
        replacement: "List[str]" = []  # type: ignore[no-redef]
    replacement.append(f"{docs_folder.name}/{replacement_separator}")

    if pre_commit and root_repo_path == ".":
        # Use git to determine repo root
        result: "Result" = context.run("git rev-parse --show-toplevel", hide=True)
        root_repo_path = result.stdout.strip("\n")

    root_repo_path: Path = Path(root_repo_path).resolve()
    readme = root_repo_path / "README.md"
    docs_index = root_repo_path / docs_folder / "index.md"

    content = readme.read_text(encoding="utf8")

    for mapping in replacement:
        try:
            old, new = mapping.split(replacement_separator)
        except ValueError:
            sys.exit(
                "A replacement must only include an 'old' and 'new' part, i.e., be of "
                "exactly length 2 when split by the '--replacement-separator'. The "
                "following replacement did not fulfill this requirement: "
                f"{mapping!r}\n  --replacement-separator={replacement_separator!r}"
            )
        content = content.replace(old, new)

    docs_index.write_text(content, encoding="utf8")

    if pre_commit:
        # Check if there have been any changes.
        # List changes if yes.

        # NOTE: Concerning the weird regular expression, see:
        # http://manpages.ubuntu.com/manpages/precise/en/man1/git-status.1.html
        result: "Result" = context.run(  # type: ignore[no-redef]
            f'git -C "{root_repo_path}" status --porcelain '
            f"{docs_index.relative_to(root_repo_path)}",
            hide=True,
        )
        if result.stdout:
            for line in result.stdout.splitlines():
                if re.match(r"^[? MARC][?MD]", line):
                    sys.exit(
                        f"{Emoji.CURLY_LOOP.value} The landing page has been updated."
                        "\n\nPlease stage it:\n\n"
                        f"  git add {docs_index.relative_to(root_repo_path)}"
                    )
        print(
            f"{Emoji.CHECK_MARK.value} No changes - your landing page is up-to-date !"
        )
