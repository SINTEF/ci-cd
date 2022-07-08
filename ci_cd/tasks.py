"""Repository management tasks powered by `invoke`.
More information on `invoke` can be found at [pyinvoke.org](http://www.pyinvoke.org/).
"""
# pylint: disable=import-outside-toplevel
import re
import sys
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

from invoke import task

if TYPE_CHECKING:  # pragma: no cover
    from typing import Optional, Tuple, Union

    from invoke import Context, Result


class Emoji(str, Enum):
    """Unicode strings for certain emojis."""

    PARTY_POPPER = "\U0001f389"
    CHECK_MARK = "\u2714"
    CROSS_MARK = "\u274c"
    CURLY_LOOP = "\u27b0"


class SemanticVersion:
    """A semantic version.

    See [SemVer.org](https://semver.org) for more information about semantic
    versioning.

    The semantic version is in this invocation considered to build up in the following
    way:

        <major>.<minor>.<patch>-<pre_release>+<build>

    Where the names in carets are callable attributes for the instance.

    When casting instances of `SemanticVersion` to `str`, the full version will be
    returned, i.e., as shown above, with a minimum of major.minor.patch.

    For example, for the version `1.5`, i.e., `major=1, minor=5`, the returned `str`
    representation will be the full major.minor.patch version: `1.5.0`.
    The `patch` attribute will default to `0` while `pre_release` and `build` will be
    `None`, when asked for explicitly.

    Parameters:
        major (Union[str, int]): The major version.
        minor (Optional[Union[str, int]]): The minor version.
        patch (Optional[Union[str, int]]): The patch version.
        pre_release (Optional[str]): The pre-release part of the version, i.e., the
            part supplied after a minus (`-`), but before a plus (`+`).
        build (Optional[str]): The build metadata part of the version, i.e., the part
            supplied at the end of the version, after a plus (`+`).

    Attributes:
        major (int): The major version.
        minor (int): The minor version.
        patch (int): The patch version.
        pre_release (str): The pre-release part of the version, i.e., the part
            supplied after a minus (`-`), but before a plus (`+`).
        build (str): The build metadata part of the version, i.e., the part supplied at
            the end of the version, after a plus (`+`).

    """

    def __init__(
        self,
        major: "Union[str, int]",
        minor: "Optional[Union[str, int]]" = None,
        patch: "Optional[Union[str, int]]" = None,
        pre_release: "Optional[str]" = None,
        build: "Optional[str]" = None,
    ) -> None:
        self._major = int(major)
        self._minor = int(minor) if minor else 0
        self._patch = int(patch) if patch else 0
        self._pre_release = pre_release if pre_release else None
        self._build = build if build else None

    @property
    def major(self) -> int:
        """The major version."""
        return self._major

    @property
    def minor(self) -> int:
        """The minor version."""
        return self._minor

    @property
    def patch(self) -> int:
        """The patch version."""
        return self._patch

    @property
    def pre_release(self) -> "Union[None, str]":
        """The pre-release part of the version

        This is the part supplied after a minus (`-`), but before a plus (`+`).
        """
        return self._pre_release

    @property
    def build(self) -> "Union[None, str]":
        """The build metadata part of the version.

        This is the part supplied at the end of the version, after a plus (`+`).
        """
        return self._build

    def __str__(self) -> str:
        """Return the full version."""
        return (
            f"{self.major}.{self.minor}.{self.patch}"
            f"{f'-{self.pre_release}' if self.pre_release else ''}"
            f"{f'+{self.build}' if self.build else ''}"
        )

    def __repr__(self) -> str:
        """Return the string representation of the object."""
        return repr(self.__str__())


def update_file(filename: Path, sub_line: "Tuple[str, str]", strip: str = None) -> None:
    """Utility function for tasks to read, update, and write files"""
    lines = [
        re.sub(sub_line[0], sub_line[1], line.rstrip(strip))
        for line in filename.read_text(encoding="utf8").splitlines()
    ]
    filename.write_text("\n".join(lines) + "\n", encoding="utf8")


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
        package_dir: str = package_dir
        version: str = version
        root_repo_path: str = root_repo_path
        code_base_update: list[str] = code_base_update
        code_base_update_separator: str = code_base_update_separator
        test: bool = test
        fail_fast: bool = fail_fast

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
            except ValueError as exc:
                if test:
                    print(f"Caught exception:\n{exc}")
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

            if test:
                print(f"filepath: {filepath}")
                print(f"pattern: {pattern!r}")
                print(f"replacement (input): {replacement}")
                print(
                    "replacement (handled): "
                    f"{replacement.format(**{'package_dir': package_dir, 'version': semantic_version})}"  # pylint: disable=line-too-long
                )

            update_file(
                filepath,
                (
                    pattern,
                    replacement.format(
                        **{"package_dir": package_dir, "version": semantic_version}
                    ),
                ),
            )

    print(
        f"{Emoji.PARTY_POPPER.value} Bumped version for {package_dir} to "
        f"{semantic_version}."
    )


@task(
    help={
        "fail-fast": (
            "Fail immediately if an error occurs. Otherwise, print and ignore all "
            "non-critical errors."
        ),
        "root-repo-path": (
            "A resolvable path to the root directory of the repository folder."
        ),
        "pre-commit": "Whether or not this task is run as a pre-commit hook.",
    }
)
def update_deps(  # pylint: disable=too-many-branches,too-many-locals,too-many-statements
    context, root_repo_path=".", fail_fast=False, pre_commit=False
):
    """Update dependencies in specified Python package's `pyproject.toml`."""
    import tomlkit

    if TYPE_CHECKING:  # pragma: no cover
        context: "Context" = context
        root_repo_path: str = root_repo_path
        fail_fast: bool = fail_fast
        pre_commit: bool = pre_commit

    if pre_commit and root_repo_path == ".":
        # Use git to determine repo root
        result: "Result" = context.run("git rev-parse --show-toplevel", hide=True)
        root_repo_path = result.stdout.strip("\n")

    pyproject_path = Path(root_repo_path).resolve() / "pyproject.toml"
    if not pyproject_path.exists():
        sys.exit(
            "Error: Could not find the Python package repository's 'pyproject.toml' "
            f"file at: {pyproject_path}"
        )

    pyproject = tomlkit.loads(pyproject_path.read_bytes())

    py_version = re.match(
        r"^.*(?P<version>3\.[0-9]+)$",
        pyproject.get("project", {}).get("requires-python", ""),
    ).group("version")

    already_handled_packages = set()
    updated_packages = {}
    dependencies = pyproject.get("project", {}).get("dependencies", [])
    for optional_deps in (
        pyproject.get("project", {}).get("optional-dependencies", {}).values()
    ):
        dependencies.extend(optional_deps)
    for line in dependencies:
        match = re.match(
            r"^(?P<full_dependency>(?P<package>[a-zA-Z0-9-_]+)\S*) "
            r"(?P<operator>>|<|<=|>=|==|!=|~=)"
            r"(?P<version>[0-9]+(?:\.[0-9]+){0,2})"
            r"(?P<extra_op_ver>(?:,(?:>|<|<=|>=|==|!=|~=)"
            r"[0-9]+(?:\.[0-9]+){0,2})*)$",
            line,
        )
        if match is None:
            msg = f"Could not parse package, operator, and version for line:\n  {line}"
            if fail_fast:
                sys.exit(msg)
            print(msg)
        full_dependency_name = match.group("full_dependency")
        package = match.group("package")
        operator = match.group("operator")
        version = match.group("version")
        extra_op_ver = match.group("extra_op_ver")

        # Skip package if already handled
        if package in already_handled_packages:
            continue

        # Check version from PyPI's online package index
        out: "Result" = context.run(
            f"pip index versions --python-version {py_version} {package}",
            hide=True,
        )
        package_latest_version_line = out.stdout.split(sep="\n", maxsplit=1)[0]
        match = re.match(
            r"(?P<package>[a-zA-Z0-9-_]+) \((?P<version>[0-9]+(?:\.[0-9]+){0,2})\)",
            package_latest_version_line,
        )
        if match is None:
            msg = (
                "Could not parse package and version from 'pip index versions' output "
                f"for line:\n  {package_latest_version_line}"
            )
            if fail_fast:
                sys.exit(msg)
            print(msg)

        # Sanity check
        if package != match.group("package"):
            msg = (
                f"Package name parsed from pyproject.toml ({package!r}) does not match"
                " the name returned from 'pip index versions': "
                f"{match.group('package')!r}"
            )
            if fail_fast:
                sys.exit(msg)
            print(msg)

        latest_version = match.group("version").split(".")
        for index, version_part in enumerate(version.split(".")):
            if version_part != latest_version[index]:
                break
        else:
            already_handled_packages.add(package)
            continue

        # Update pyproject.toml
        updated_version = ".".join(latest_version[: len(version.split("."))])
        escaped_full_dependency_name = full_dependency_name.replace(
            "[", "\["  # pylint: disable=anomalous-backslash-in-string
        ).replace(
            "]", "\]"  # pylint: disable=anomalous-backslash-in-string
        )
        update_file(
            pyproject_path,
            (
                rf'"{escaped_full_dependency_name} {operator}.*"',
                f'"{full_dependency_name} {operator}{updated_version}'
                f'{extra_op_ver if extra_op_ver else ""}"',
            ),
        )
        already_handled_packages.add(package)
        updated_packages[full_dependency_name] = f"{operator}{updated_version}"

    if updated_packages:
        print(
            "Successfully updated the following dependencies:\n"
            + "\n".join(
                f"  {package} ({version}{extra_op_ver if extra_op_ver else ''})"
                for package, version in updated_packages.items()
            )
            + "\n"
        )
    else:
        print("No dependency updates available.")


@task(
    help={
        "package-dir": (
            "Relative path to package dir from the repository root, "
            "e.g., 'src/my_package'."
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
        "debug": "Whether or not to print debug statements.",
    },
    iterable=["unwanted_folder", "unwanted_file", "full_docs_folder"],
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
    debug=False,
):
    """Create the Python API Reference in the documentation."""
    import os
    import shutil

    if TYPE_CHECKING:  # pragma: no cover
        context: "Context" = context
        package_dir: str = package_dir
        pre_clean: bool = pre_clean
        pre_commit: bool = pre_commit
        root_repo_path: str = root_repo_path
        docs_folder: str = docs_folder
        debug: bool = debug

    if not unwanted_folder:
        unwanted_folder: list[str] = ["__pycache__"]
    if not unwanted_file:
        unwanted_file: list[str] = ["__init__.py"]

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

    root_repo_path: Path = Path(root_repo_path).resolve()
    package_dir: Path = root_repo_path / package_dir
    docs_api_ref_dir = root_repo_path / docs_folder / "api_reference"
    if debug:
        print("package_dir:", package_dir, flush=True)
        print("docs_api_ref_dir:", docs_api_ref_dir, flush=True)
        print("unwanted_folder:", unwanted_folder, flush=True)
        print("unwanted_file:", unwanted_file, flush=True)
        print("full_docs_folder:", full_docs_folder, flush=True)

    if "/" in any(unwanted_folder + unwanted_file):
        sys.exit(
            "Unwanted folders and files may NOT be paths. A forward slash (/) was "
            "found in some of them."
        )

    pages_template = 'title: "{name}"\n'
    md_template = "# {name}\n\n::: {py_path}\n"
    no_docstring_template = (
        md_template + f"{' ' * 4}options:\n{' ' * 6}show_if_no_docstring: true\n"
    )

    if docs_api_ref_dir.exists() and pre_clean:
        if debug:
            print(f"Removing {docs_api_ref_dir}", flush=True)
        shutil.rmtree(docs_api_ref_dir, ignore_errors=True)
        if docs_api_ref_dir.exists():
            sys.exit(f"{docs_api_ref_dir} should have been removed!")
    docs_api_ref_dir.mkdir(exist_ok=True)

    if debug:
        print(f"Writing file: {docs_api_ref_dir / '.pages'}", flush=True)
    write_file(
        full_path=docs_api_ref_dir / ".pages",
        content=pages_template.format(name="API Reference"),
    )

    for dirpath, dirnames, filenames in os.walk(package_dir):
        for unwanted in unwanted_folder:
            if debug:
                print("unwanted:", unwanted, flush=True)
                print("dirnames:", dirnames, flush=True)
            if unwanted in dirnames:
                # Avoid walking into or through unwanted directories
                dirnames.remove(unwanted)

        relpath = Path(dirpath).relative_to(package_dir)
        abspath = (package_dir / relpath).resolve()
        if debug:
            print("relpath:", relpath, flush=True)
            print("abspath:", abspath, flush=True)

        if not (abspath / "__init__.py").exists():
            # Avoid paths that are not included in the public Python API
            print("does not exist:", abspath / "__init__.py", flush=True)
            continue

        # Create `.pages`
        docs_sub_dir = docs_api_ref_dir / relpath
        docs_sub_dir.mkdir(exist_ok=True)
        if debug:
            print("docs_sub_dir:", docs_sub_dir, flush=True)
        if str(relpath) != ".":
            if debug:
                print(f"Writing file: {docs_sub_dir / '.pages'}", flush=True)
            write_file(
                full_path=docs_sub_dir / ".pages",
                content=pages_template.format(
                    name=str(relpath).rsplit("/", maxsplit=1)[-1]
                ),
            )

        # Create markdown files
        for filename in filenames:
            if re.match(r".*\.py$", filename) is None or filename in unwanted_file:
                # Not a Python file: We don't care about it!
                # Or filename is in the list of unwanted files:
                # We don't want it!
                if debug:
                    print(
                        f"{filename} is not a Python file or is an unwanted file "
                        "(through user input). Skipping it.",
                        flush=True,
                    )
                continue

            basename = filename[: -len(".py")]
            py_path = (
                f"{package_dir.name}/{relpath}/{basename}".replace("/", ".")
                if str(relpath) != "."
                else f"{package_dir.name}/{basename}".replace("/", ".")
            )
            md_filename = filename.replace(".py", ".md")
            if debug:
                print("basename:", basename, flush=True)
                print("py_path:", py_path, flush=True)
                print("md_filename:", md_filename, flush=True)

            # For special folders we want to include EVERYTHING, even if it doesn't
            # have a doc-string
            template = (
                no_docstring_template
                if str(relpath) in full_docs_folder
                else md_template
            )

            if debug:
                print("template:", template, flush=True)
                print(f"Writing file: {docs_sub_dir / md_filename}", flush=True)

            write_file(
                full_path=docs_sub_dir / md_filename,
                content=template.format(name=basename, py_path=py_path),
            )

    if pre_commit:
        # Check if there have been any changes.
        # List changes if yes.

        # NOTE: grep returns an exit code of 1 if it doesn't find anything
        # (which will be good in this case).
        # Concerning the weird last grep command see:
        # http://manpages.ubuntu.com/manpages/precise/en/man1/git-status.1.html
        result: "Result" = context.run(
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
            "A replacement (mappings) to be performed on README.md when creating the "
            "documentation's landing page (index.md). This list ALWAYS includes "
            "replacing '{docs-folder}/' with an empty string to correct relative "
            "links."
        ),
        "replacement-separator": (
            "String to separate a replacement's 'old' to 'new' statement."
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
        context: "Context" = context
        pre_commit: bool = pre_commit
        root_repo_path: str = root_repo_path
        docs_folder: str = docs_folder
        replacement: list[str] = replacement
        replacement_separator: str = replacement_separator

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

        # NOTE: grep returns an exit code of 1 if it doesn't find anything
        # (which will be good in this case).
        # Concerning the weird last grep command see:
        # http://manpages.ubuntu.com/manpages/precise/en/man1/git-status.1.html
        result: "Result" = context.run(
            f'git -C "{root_repo_path}" status --porcelain '
            f"{docs_index.relative_to(root_repo_path)} | "
            "grep -E '^[? MARC][?MD]' || exit 0",
            hide=True,
        )
        if result.stdout:
            sys.exit(
                f"{Emoji.CURLY_LOOP.value} The landing page has been updated.\n\n"
                "Please stage it:\n\n"
                f"  git add {docs_index.relative_to(root_repo_path)}"
            )
        print(
            f"{Emoji.CHECK_MARK.value} No changes - your landing page is up-to-date !"
        )
