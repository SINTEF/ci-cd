"""Repository management tasks powered by `invoke`.
More information on `invoke` can be found at [pyinvoke.org](http://www.pyinvoke.org/).
"""
# pylint: disable=import-outside-toplevel
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from invoke import task

if TYPE_CHECKING:  # pragma: no cover
    from typing import Tuple

    from invoke import Context, Result


REPO_DIR = Path(__file__).resolve().parent.resolve()
REPO_PARENT_DIR = REPO_DIR.parent.resolve()


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
        "repo-folder": (
            "The folder name of the repository, wherein the package dir is located. "
            "This defaults to 'main', as this will be used in the callable workflows."
        ),
    }
)
def setver(_, package_dir, version, repo_folder="main"):
    """Sets the specified version of specified Python package."""
    match = re.fullmatch(
        (
            r"v?(?P<version>[0-9]+(\.[0-9]+){2}"  # Major.Minor.Patch
            r"(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?"  # pre-release
            r"(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?)"  # build metadata
        ),
        version,
    )
    if not match:
        sys.exit(
            "Error: Please specify version as "
            "'Major.Minor.Patch(-Pre-Release+Build Metadata)' or "
            "'vMajor.Minor.Patch(-Pre-Release+Build Metadata)'"
        )
    version = match.group("version")

    init_file: Path = REPO_PARENT_DIR / repo_folder / package_dir / "__init__.py"
    if not init_file.exists():
        sys.exit(
            "Error: Could not find the Python package's root '__init__.py' file at: "
            f"{init_file}"
        )

    update_file(
        init_file,
        (r'__version__ *= *(\'|").*(\'|")', f'__version__ = "{version}"'),
    )

    print(f"Bumped version for {package_dir} to {version}.")


@task(
    help={
        "pre-commit": "Whether or not this task is run as a pre-commit hook",
        "fail-fast": (
            "Fail immediately if an error occurs. Otherwise, print and ignore all "
            "non-critical errors."
        ),
        "repo-folder": (
            "The folder name of the repository, wherein the package dir is located. "
            "This defaults to 'main', as this will be used in the callable workflows."
        ),
    }
)
def update_deps(  # pylint: disable=too-many-branches,too-many-locals,too-many-statements
    context, pre_commit=False, repo_folder="main", fail_fast=False
):
    """Update dependencies in specified Python package's `pyproject.toml`."""
    import tomlkit

    if TYPE_CHECKING:  # pragma: no cover
        context: "Context" = context

    basis_dir = REPO_DIR if pre_commit else REPO_PARENT_DIR
    pyproject_path = basis_dir / repo_folder / "pyproject.toml"
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
        "repo-folder": (
            "The folder name of the repository, wherein the package dir is located. "
            "This defaults to 'main', as this will be used in the callable workflows."
        ),
        "docs-folder": (
            "The folder name for the documentation root folder. "
            "This defaults to 'docs'."
        ),
        "unwanted-dirs": (
            "Comma-separated list of directories to avoid including into the Python API "
            "reference documentation. Note, only directory names, not paths, may be "
            "included. Note, all folders and their contents with these names will be "
            "excluded. Defaults to '__pycache__'."
        ),
        "unwanted-files": (
            "Comma-separated list of files to avoid including into the Python API "
            "reference documentation. Note, only full file names, not paths, may be "
            "included, i.e., filename + file extension. Note, all files with these "
            "names will be excluded. Defaults to '__init__.py'."
        ),
        "full-docs-dirs": (
            "Comma-separated list of directories in which to include everything - even"
            " those without documentation strings. This may be useful for a module "
            "full of data models or to ensure all class attributes are listed."
        ),
        "debug": "Whether or not to print debug statements.",
    }
)
def create_api_reference_docs(  # pylint: disable=too-many-locals,too-many-branches,too-many-statements,line-too-long
    context,
    package_dir,
    pre_clean=False,
    pre_commit=False,
    repo_folder="main",
    docs_folder="docs",
    unwanted_dirs="__pycache__",
    unwanted_files="__init__.py",
    full_docs_dirs="",
    debug=False,
):
    """Create the Python API Reference in the documentation."""
    import os
    import shutil

    def write_file(full_path: Path, content: str) -> None:
        """Write file with `content` to `full_path`"""
        if full_path.exists():
            cached_content = full_path.read_text(encoding="utf8")
            if content == cached_content:
                del cached_content
                return
            del cached_content
        full_path.write_text(content, encoding="utf8")

    basis_dir = REPO_DIR if pre_commit else REPO_PARENT_DIR
    package_dir: Path = basis_dir / repo_folder / package_dir
    docs_api_ref_dir: Path = basis_dir / repo_folder / docs_folder / "api_reference"
    if debug:
        print("package_dir:", package_dir, flush=True)
        print("docs_api_ref_dir:", docs_api_ref_dir, flush=True)
        print(
            "unwanted_dirs + unwanted_files:",
            unwanted_dirs + unwanted_files,
            flush=True,
        )

    if "/" in unwanted_dirs + unwanted_files:
        sys.exit(
            "Unwanted directories and files may NOT be paths. A forward slash (/) was "
            f"found in them. Given\n\n  --unwanted-dirs={unwanted_dirs},\n  "
            f"--unwanted-files={unwanted_files}"
        )

    unwanted_subdirs: list[str] = unwanted_dirs.split(",")
    unwanted_subfiles: list[str] = unwanted_files.split(",")
    no_docstring_dirs: list[str] = full_docs_dirs.split(",")

    if debug:
        print("unwanted_subdirs:", unwanted_subdirs, flush=True)
        print("unwanted_subfiles:", unwanted_subfiles, flush=True)
        print("no_docstring_dirs:", no_docstring_dirs, flush=True)

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
        for unwanted_dir in unwanted_subdirs:
            if debug:
                print("unwanted_dir:", unwanted_dir, flush=True)
                print("dirnames:", dirnames, flush=True)
            if unwanted_dir in dirnames:
                # Avoid walking into or through unwanted directories
                dirnames.remove(unwanted_dir)

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
            if re.match(r".*\.py$", filename) is None or filename in unwanted_subfiles:
                # Not a Python file: We don't care about it!
                # Or filename is in the tuple of unwanted files:
                # We don't want it!
                if debug:
                    print(
                        f"{filename} is not a Python file or is in unwanted_subfiles. Skipping it.",
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
                if str(relpath) in no_docstring_dirs
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
        if TYPE_CHECKING:  # pragma: no cover
            context: "Context" = context

        # NOTE: grep returns an exit code of 1 if it doesn't find anything
        # (which will be good in this case).
        # Concerning the weird last grep command see:
        # http://manpages.ubuntu.com/manpages/precise/en/man1/git-status.1.html
        result: "Result" = context.run(
            f'git -C "{basis_dir / repo_folder}" status --porcelain '
            f"{docs_api_ref_dir.relative_to(basis_dir / repo_folder)} | "
            "grep -E '^[? MARC][?MD]' || exit 0",
            hide=True,
        )
        if result.stdout:
            sys.exit(
                "\u27b0 The following files have been changed/added/removed:\n\n"
                f"{result.stdout}\nPlease stage them:\n\n  git add "
                f"{docs_api_ref_dir.relative_to(basis_dir / repo_folder)}"
            )
        print("\u2714 No changes - your API reference documentation is up-to-date !")


@task(
    help={
        "pre-commit": "Whether or not this task is run as a pre-commit hook.",
        "repo-folder": (
            "The folder name of the repository, wherein the package dir is located. "
            "This defaults to 'main', as this will be used in the callable workflows."
        ),
        "docs-folder": (
            "The folder name for the documentation root folder. "
            "This defaults to 'docs'."
        ),
        "replacements": (
            "List of replacements (mappings) to be performed on README.md when "
            "creating the documentation's landing page (index.md). This list ALWAYS "
            "includes replacing '{docs-folder}/' with an empty string to correct "
            "relative links."
        ),
        "replacements-separator": (
            "String to separate replacement mappings from the 'replacements' input. "
            "Defaults to a pipe (|)."
        ),
        "internal-separator": (
            "String to separate a single mapping's 'old' to 'new' statement. "
            "Defaults to a comma (,)."
        ),
    }
)
def create_docs_index(  # pylint: disable=too-many-locals
    context,
    pre_commit=False,
    repo_folder="main",
    docs_folder="docs",
    replacements="",
    replacements_separator="|",
    internal_separator=",",
):
    """Create the documentation index page from README.md."""
    basis_dir = REPO_DIR if pre_commit else REPO_PARENT_DIR
    readme: Path = basis_dir / repo_folder / "README.md"
    docs_index: Path = basis_dir / repo_folder / docs_folder / "index.md"

    content = readme.read_text(encoding="utf8")

    replacement_mapping = [(f"{docs_folder}/", "")]
    for replacement in replacements.split(replacements_separator):
        new_replacement_map = replacement.split(internal_separator)
        if len(new_replacement_map) != 2:
            sys.exit(
                "A single replacement must only include an 'old' and 'new' part, "
                "i.e., be of exactly length 2 when split by the "
                "'--internal-separator'. The following replacement did not fulfill "
                f"this requirement: {replacement!r}\n  "
                f"--internal-separator={internal_separator!r}\n  "
                f"--replacements-separator={replacements_separator!r}"
            )
        replacement_mapping.append(tuple(new_replacement_map))

    for old, new in replacement_mapping:
        content = content.replace(old, new)

    docs_index.write_text(content, encoding="utf8")

    if pre_commit:
        # Check if there have been any changes.
        # List changes if yes.
        if TYPE_CHECKING:  # pragma: no cover
            context: "Context" = context

        # NOTE: grep returns an exit code of 1 if it doesn't find anything
        # (which will be good in this case).
        # Concerning the weird last grep command see:
        # http://manpages.ubuntu.com/manpages/precise/en/man1/git-status.1.html
        result: "Result" = context.run(
            f'git -C "{basis_dir / repo_folder}" status --porcelain '
            f"{docs_index.relative_to(basis_dir / repo_folder)} | "
            "grep -E '^[? MARC][?MD]' || exit 0",
            hide=True,
        )
        if result.stdout:
            sys.exit(
                f"\u27b0 The landing page has been updated.\n\nPlease stage it:\n\n"
                f"  git add {docs_index.relative_to(basis_dir / repo_folder)}"
            )
        print("\u2714 No changes - your landing page is up-to-date !")
