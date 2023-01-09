"""`update_deps` task.

Update dependencies in a `pyproject.toml` file.
"""
# pylint: disable=duplicate-code
import logging
import re
import sys
from collections import namedtuple
from pathlib import Path
from typing import TYPE_CHECKING

import tomlkit
from invoke import task

from ci_cd.utils import update_file

if TYPE_CHECKING:  # pragma: no cover
    from invoke import Context, Result


LOGGER = logging.getLogger(__file__)
LOGGER.setLevel(logging.DEBUG)


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
    if TYPE_CHECKING:  # pragma: no cover
        context: "Context" = context  # type: ignore[no-redef]
        root_repo_path: str = root_repo_path  # type: ignore[no-redef]
        fail_fast: bool = fail_fast  # type: ignore[no-redef]
        pre_commit: bool = pre_commit  # type: ignore[no-redef]

    VersionSpec = namedtuple(
        "VersionSpec",
        [
            "full_dependency",
            "package",
            "url_version",
            "operator",
            "version",
            "extra_operator_version",
            "environment_marker",
        ],
    )

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

    match = re.match(
        r"^.*(?P<version>3\.[0-9]+)$",
        pyproject.get("project", {}).get("requires-python", ""),
    )
    if not match:
        raise ValueError(
            "No minimum Python version requirement given in pyproject.toml!"
        )
    py_version = match.group("version")

    already_handled_packages = set()
    updated_packages = {}
    dependencies = pyproject.get("project", {}).get("dependencies", [])
    for optional_deps in (
        pyproject.get("project", {}).get("optional-dependencies", {}).values()
    ):
        dependencies.extend(optional_deps)

    error = False
    for line in dependencies:
        match = re.match(
            r"^(?P<full_dependency>(?P<package>[a-zA-Z0-9_.-]+)(?:\s*\[.*\])?)\s*"
            r"(?:(?P<url_version>@\s*\S+)|"
            r"(?P<operator>>|<|<=|>=|==|!=|~=)\s*"
            r"(?P<version>[0-9]+(?:\.[0-9]+){0,2}))?\s*"
            r"(?P<extra_operator_version>(?:,(?:>|<|<=|>=|==|!=|~=)\s*"
            r"[0-9]+(?:\.[0-9]+){0,2}\s*)+)*"
            r"(?P<environment_marker>;.+)*$",
            line,
        )
        if match is None:
            msg = (
                f"Could not parse package and version specification for line:\n  {line}"
            )
            LOGGER.warning(msg)
            if fail_fast:
                sys.exit(msg)
            print(msg)
            error = True
            continue

        version_spec = VersionSpec(**match.groupdict())
        LOGGER.debug("version_spec: %s", version_spec)

        # Skip package if already handled
        if version_spec.package in already_handled_packages:
            continue

        # Skip URL versioned dependencies
        if version_spec.url_version:
            msg = (
                f"Dependency {version_spec.full_dependency!r} is pinned to a URL and "
                "will be skipped."
            )
            LOGGER.info(msg)
            print(msg)
            continue

        # Skip and warn if package is not version-restricted
        if not version_spec.operator and not version_spec.url_version:
            msg = (
                f"Dependency {version_spec.full_dependency!r} is not version "
                "restricted and will be skipped. Consider adding version restrictions."
            )
            LOGGER.warning(msg)
            print(msg)
            continue

        # Check version from PyPI's online package index
        out: "Result" = context.run(
            f"pip index versions --python-version {py_version} {version_spec.package}",
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
            LOGGER.warning(msg)
            if fail_fast:
                sys.exit(msg)
            print(msg)
            already_handled_packages.add(version_spec.package)
            error = True
            continue

        # Sanity check
        if version_spec.package != match.group("package"):
            msg = (
                f"Package name parsed from pyproject.toml ({version_spec.package!r}) "
                "does not match the name returned from 'pip index versions': "
                f"{match.group('package')!r}"
            )
            LOGGER.warning(msg)
            if fail_fast:
                sys.exit(msg)
            print(msg)
            already_handled_packages.add(version_spec.package)
            error = True
            continue

        latest_version = match.group("version").split(".")
        for index, version_part in enumerate(version_spec.version.split(".")):
            if version_part != latest_version[index]:
                break
        else:
            already_handled_packages.add(version_spec.package)
            continue

        if not error:
            # Update pyproject.toml
            updated_version = ".".join(
                latest_version[: len(version_spec.version.split("."))]
            )
            escaped_full_dependency_name = version_spec.full_dependency.replace(
                "[", r"\["
            ).replace("]", r"\]")
            update_file(
                pyproject_path,
                (
                    rf'"{escaped_full_dependency_name} {version_spec.operator}.*"',
                    f'"{version_spec.full_dependency} '
                    f"{version_spec.operator}{updated_version}"
                    f'{version_spec.extra_operator_version if version_spec.extra_operator_version else ""}'  # pylint: disable=line-too-long
                    f'{version_spec.environment_marker if version_spec.environment_marker else ""}"',  # pylint: disable=line-too-long
                ),
            )
            already_handled_packages.add(version_spec.package)
            updated_packages[
                version_spec.full_dependency
            ] = f"{version_spec.operator}{updated_version}"

    if error:
        sys.exit("Errors occurred! See printed statements above.")

    if updated_packages:
        print(
            "Successfully updated the following dependencies:\n"
            + "\n".join(
                f"  {package} ({version}"
                f"{version_spec.extra_operator_version if version_spec.extra_operator_version else ''}"  # pylint: disable=line-too-long
                f"{' ' + version_spec.environment_marker if version_spec.environment_marker else ''})"  # pylint: disable=line-too-long
                for package, version in updated_packages.items()
            )
            + "\n"
        )
    else:
        print("No dependency updates available.")
