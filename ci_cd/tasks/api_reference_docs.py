"""`create_api_reference_docs` task.

Create Python API reference in the documentation.
This is specifically to be used with the MkDocs and mkdocstrings framework.
"""
# pylint: disable=duplicate-code
import logging
import os
import re
import shutil
import sys
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING

from invoke import task

from ci_cd.utils import Emoji

if TYPE_CHECKING:  # pragma: no cover
    from invoke import Context, Result


LOGGER = logging.getLogger(__file__)
LOGGER.setLevel(logging.DEBUG)


@task(
    help={
        "package-dir": (
            "Relative path to a package dir from the repository root, "
            "e.g., 'src/my_package'. This input option can be supplied multiple times."
        ),
        "pre-clean": "Remove the 'api_reference' sub directory prior to (re)creation.",
        "pre-commit": (
            "Whether or not this task is run as a pre-commit hook. Will return a "
            "non-zero error code if changes were made."
        ),
        "root-repo-path": (
            "A resolvable path to the root directory of the repository folder."
        ),
        "docs-folder": (
            "The folder name for the documentation root folder. "
            "This defaults to 'docs'."
        ),
        "unwanted-folder": (
            "A folder to avoid including into the Python API reference documentation. "
            "Note, only folder names, not paths, may be included. Note, all folders "
            "and their contents with this name will be excluded. Defaults to "
            "'__pycache__'. This input option can be supplied multiple times."
        ),
        "unwanted-file": (
            "A file to avoid including into the Python API reference documentation. "
            "Note, only full file names, not paths, may be included, i.e., filename + "
            "file extension. Note, all files with this names will be excluded. "
            "Defaults to '__init__.py'. This input option can be supplied multiple "
            "times."
        ),
        "full-docs-folder": (
            "A folder in which to include everything - even those without "
            "documentation strings. This may be useful for a module full of data "
            "models or to ensure all class attributes are listed. This input option "
            "can be supplied multiple times."
        ),
        "full-docs-file": (
            "A full relative path to a file in which to include everything - even "
            "those without documentation strings. This may be useful for a file full "
            "of data models or to ensure all class attributes are listed. This input "
            "option can be supplied multiple times."
        ),
        "special-option": (
            "A combination of a relative path to a file and a fully formed "
            "mkdocstrings option that should be added to the generated MarkDown file. "
            "The combination should be comma-separated. Example: "
            "'my_module/py_file.py,show_bases:false'. Encapsulate the value in double "
            'quotation marks (") if including spaces ( ). Important: If multiple '
            "package-dir options are supplied, the relative path MUST include/start "
            "with the package-dir value, e.g., "
            "'\"my_package/my_module/py_file.py,show_bases: false\"'. This input "
            "option can be supplied multiple times. The options will be accumulated "
            "for the same file, if given several times."
        ),
        "relative": (
            "Whether or not to use relative Python import links in the API reference "
            "markdown files."
        ),
        "debug": "Whether or not to print debug statements.",
    },
    iterable=[
        "package_dir",
        "unwanted_folder",
        "unwanted_file",
        "full_docs_folder",
        "full_docs_file",
        "special_option",
    ],
)
def create_api_reference_docs(  # pylint: disable=too-many-locals,too-many-branches,too-many-statements,line-too-long
    context,
    package_dir,
    pre_clean=False,
    pre_commit=False,
    root_repo_path=".",
    docs_folder="docs",
    unwanted_folder=None,
    unwanted_file=None,
    full_docs_folder=None,
    full_docs_file=None,
    special_option=None,
    relative=False,
    debug=False,
):
    """Create the Python API Reference in the documentation."""
    if TYPE_CHECKING:  # pragma: no cover
        context: "Context" = context  # type: ignore[no-redef]
        pre_clean: bool = pre_clean  # type: ignore[no-redef]
        pre_commit: bool = pre_commit  # type: ignore[no-redef]
        root_repo_path: str = root_repo_path  # type: ignore[no-redef]
        docs_folder: str = docs_folder  # type: ignore[no-redef]
        relative: bool = relative  # type: ignore[no-redef]
        debug: bool = debug  # type: ignore[no-redef]

    if not unwanted_folder:
        unwanted_folder: list[str] = ["__pycache__"]  # type: ignore[no-redef]
    if not unwanted_file:
        unwanted_file: list[str] = ["__init__.py"]  # type: ignore[no-redef]
    if not full_docs_folder:
        full_docs_folder: list[str] = []  # type: ignore[no-redef]
    if not full_docs_file:
        full_docs_file: list[str] = []  # type: ignore[no-redef]
    if not special_option:
        special_option: list[str] = []  # type: ignore[no-redef]

    def write_file(full_path: Path, content: str) -> None:
        """Write file with `content` to `full_path`"""
        if full_path.exists():
            cached_content = full_path.read_text(encoding="utf8")
            if content == cached_content:
                del cached_content
                return
            del cached_content
        full_path.write_text(content, encoding="utf8")

    if pre_commit and root_repo_path == ".":
        # Use git to determine repo root
        result: "Result" = context.run("git rev-parse --show-toplevel", hide=True)
        root_repo_path = result.stdout.strip("\n")

    root_repo_path: Path = Path(root_repo_path).resolve()  # type: ignore[no-redef]
    package_dirs: list[Path] = [root_repo_path / _ for _ in package_dir]
    docs_api_ref_dir = root_repo_path / docs_folder / "api_reference"

    LOGGER.debug(
        """package_dirs: %s
docs_api_ref_dir: %s
unwanted_folder: %s
unwanted_file: %s
full_docs_folder: %s
full_docs_file: %s
special_option: %s""",
        package_dirs,
        docs_api_ref_dir,
        unwanted_folder,
        unwanted_file,
        full_docs_folder,
        full_docs_file,
        special_option,
    )
    if debug:
        print("package_dirs:", package_dirs, flush=True)
        print("docs_api_ref_dir:", docs_api_ref_dir, flush=True)
        print("unwanted_folder:", unwanted_folder, flush=True)
        print("unwanted_file:", unwanted_file, flush=True)
        print("full_docs_folder:", full_docs_folder, flush=True)
        print("full_docs_file:", full_docs_file, flush=True)
        print("special_option:", special_option, flush=True)

    special_options_files = defaultdict(list)
    for special_file, option in [_.split(",", maxsplit=1) for _ in special_option]:
        if any("," in _ for _ in (special_file, option)):
            LOGGER.error(
                "Failing for special-option: %s", ",".join([special_file, option])
            )
            if debug:
                print(
                    "Failing for special-option:",
                    ",".join([special_file, option]),
                    flush=True,
                )
            sys.exit(
                "special-option values may only include a single comma (,) to "
                "separate the relative file path and the mkdocstsrings option."
            )
        special_options_files[special_file].append(option)

    LOGGER.debug("special_options_files: %s", special_options_files)
    if debug:
        print("special_options_files:", special_options_files, flush=True)

    if any("/" in _ for _ in unwanted_folder + unwanted_file):
        sys.exit(
            "Unwanted folders and files may NOT be paths. A forward slash (/) was "
            "found in some of them."
        )

    pages_template = 'title: "{name}"\n'
    md_template = "# {name}\n\n::: {py_path}\n"
    no_docstring_template_addition = (
        f"{' ' * 4}options:\n{' ' * 6}show_if_no_docstring: true\n"
    )

    if docs_api_ref_dir.exists() and pre_clean:
        LOGGER.debug("Removing %s", docs_api_ref_dir)
        if debug:
            print(f"Removing {docs_api_ref_dir}", flush=True)
        shutil.rmtree(docs_api_ref_dir, ignore_errors=True)
        if docs_api_ref_dir.exists():
            sys.exit(f"{docs_api_ref_dir} should have been removed!")
    docs_api_ref_dir.mkdir(exist_ok=True)

    LOGGER.debug("Writing file: %s", docs_api_ref_dir / ".pages")
    if debug:
        print(f"Writing file: {docs_api_ref_dir / '.pages'}", flush=True)
    write_file(
        full_path=docs_api_ref_dir / ".pages",
        content=pages_template.format(name="API Reference"),
    )

    single_package = len(package_dirs) == 1
    for package in package_dirs:
        for dirpath, dirnames, filenames in os.walk(package):
            for unwanted in unwanted_folder:
                LOGGER.debug("unwanted: %s\ndirnames: %s", unwanted, dirnames)
                if debug:
                    print("unwanted:", unwanted, flush=True)
                    print("dirnames:", dirnames, flush=True)
                if unwanted in dirnames:
                    # Avoid walking into or through unwanted directories
                    dirnames.remove(unwanted)

            relpath = Path(dirpath).relative_to(
                package if single_package else package.parent
            )
            abspath = (
                package / relpath if single_package else package.parent / relpath
            ).resolve()
            LOGGER.debug("relpath: %s\nabspath: %s", relpath, abspath)
            if debug:
                print("relpath:", relpath, flush=True)
                print("abspath:", abspath, flush=True)

            if not (abspath / "__init__.py").exists():
                # Avoid paths that are not included in the public Python API
                LOGGER.debug("does not exist: %s", abspath / "__init__.py")
                print("does not exist:", abspath / "__init__.py", flush=True)
                continue

            # Create `.pages`
            docs_sub_dir = docs_api_ref_dir / relpath
            docs_sub_dir.mkdir(exist_ok=True)
            LOGGER.debug("docs_sub_dir: %s", docs_sub_dir)
            if debug:
                print("docs_sub_dir:", docs_sub_dir, flush=True)
            if str(relpath) != ".":
                LOGGER.debug("Writing file: %s", docs_sub_dir / ".pages")
                if debug:
                    print(f"Writing file: {docs_sub_dir / '.pages'}", flush=True)
                write_file(
                    full_path=docs_sub_dir / ".pages",
                    content=pages_template.format(name=relpath.name),
                )

            # Create markdown files
            for filename in (Path(_) for _ in filenames):
                if (
                    re.match(r".*\.py$", str(filename)) is None
                    or str(filename) in unwanted_file
                ):
                    # Not a Python file: We don't care about it!
                    # Or filename is in the list of unwanted files:
                    # We don't want it!
                    LOGGER.debug(
                        "%s is not a Python file or is an unwanted file (through user input). Skipping it.",
                        filename,
                    )
                    if debug:
                        print(
                            f"{filename} is not a Python file or is an unwanted file "
                            "(through user input). Skipping it.",
                            flush=True,
                        )
                    continue

                py_path_root = (
                    package.relative_to(root_repo_path) if relative else package.name
                )
                py_path = (
                    f"{py_path_root}/{filename.stem}".replace("/", ".")
                    if str(relpath) == "."
                    or (str(relpath) == package.name and not single_package)
                    else f"{py_path_root}/{relpath if single_package else relpath.relative_to(package.name)}/{filename.stem}".replace(
                        "/", "."
                    )
                )
                LOGGER.debug("filename: %s\npy_path: %s", filename, py_path)
                if debug:
                    print("filename:", filename, flush=True)
                    print("py_path:", py_path, flush=True)

                relative_file_path = (
                    str(filename) if str(relpath) == "." else str(relpath / filename)
                )

                # For special files we want to include EVERYTHING, even if it doesn't
                # have a doc-string
                template = md_template + (
                    no_docstring_template_addition
                    if relative_file_path in full_docs_file
                    or str(relpath) in full_docs_folder
                    else ""
                )

                # Include special options, if any, for certain files.
                if relative_file_path in special_options_files:
                    template += (
                        f"{' ' * 4}options:\n" if "options:\n" not in template else ""
                    )
                    template += "\n".join(
                        f"{' ' * 6}{option}"
                        for option in special_options_files[relative_file_path]
                    )
                    template += "\n"

                LOGGER.debug(
                    "template: %s\nWriting file: %s",
                    template,
                    docs_sub_dir / filename.with_suffix(".md"),
                )
                if debug:
                    print("template:", template, flush=True)
                    print(
                        f"Writing file: {docs_sub_dir / filename.with_suffix('.md')}",
                        flush=True,
                    )

                write_file(
                    full_path=docs_sub_dir / filename.with_suffix(".md"),
                    content=template.format(name=filename.stem, py_path=py_path),
                )

    if pre_commit:
        # Check if there have been any changes.
        # List changes if yes.

        # NOTE: grep returns an exit code of 1 if it doesn't find anything
        # (which will be good in this case).
        # Concerning the weird last grep command see:
        # http://manpages.ubuntu.com/manpages/precise/en/man1/git-status.1.html
        result: "Result" = context.run(  # type: ignore[no-redef]
            f'git -C "{root_repo_path}" status --porcelain '
            f"{docs_api_ref_dir.relative_to(root_repo_path)} | "
            "grep -E '^[? MARC][?MD]' || exit 0",
            hide=True,
        )
        if result.stdout:
            sys.exit(
                f"{Emoji.CURLY_LOOP.value} The following files have been "
                f"changed/added/removed:\n\n{result.stdout}\nPlease stage them:\n\n"
                f"  git add {docs_api_ref_dir.relative_to(root_repo_path)}"
            )
        print(
            f"{Emoji.CHECK_MARK.value} No changes - your API reference documentation "
            "is up-to-date !"
        )
