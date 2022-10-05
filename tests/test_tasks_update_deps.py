"""Test `ci_cd.tasks.update_deps()`."""
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path


def test_update_deps(tmp_path: "Path") -> None:
    """Check update_deps runs with defaults."""
    import re

    import tomlkit
    from invoke import MockContext

    from ci_cd.tasks import update_deps

    original_dependencies = {
        "invoke": "1.7",
        "tomlkit": "0.11.4",
        "mike": "1.1",
        "pytest": "7.1",
        "pytest-cov": "3.0",
        "pre-commit": "2.20",
        "pylint": "2.13",
    }

    pyproject_file = tmp_path / "pyproject.toml"
    pyproject_file.write_text(
        data=f"""
[project]
requires-python = "~=3.7"

dependencies = [
    "invoke ~={original_dependencies['invoke']}",
    "tomlkit[test,docs] ~={original_dependencies['tomlkit']}",
]

[project.optional-dependencies]
docs = [
    "mike >={original_dependencies['mike']},<3",
]
testing = [
    "pytest ~={original_dependencies['pytest']}",
    "pytest-cov ~={original_dependencies['pytest-cov']}",
]
dev = [
    "mike >={original_dependencies['mike']},<3",
    "pytest ~={original_dependencies['pytest']}",
    "pytest-cov ~={original_dependencies['pytest-cov']}",
    "pre-commit ~={original_dependencies['pre-commit']}",
    "pylint ~={original_dependencies['pylint']}",
]
""",
        encoding="utf8",
    )

    context = MockContext(
        run={
            re.compile(r".*invoke$"): "invoke (1.7.1)\n",
            re.compile(r".*tomlkit$"): "tomlkit (1.0.0)",
            re.compile(r".*mike$"): "mike (1.0.1)",
            re.compile(r".*pytest$"): "pytest (7.1.0)",
            re.compile(r".*pytest-cov$"): "pytest-cov (3.1.0)",
            re.compile(r".*pre-commit$"): "pre-commit (2.20.0)",
            re.compile(r".*pylint$"): "pylint (2.14.0)",
        }
    )

    update_deps(
        context,
        root_repo_path=str(tmp_path),
    )

    pyproject = tomlkit.loads(pyproject_file.read_bytes())

    dependencies: list[str] = pyproject.get("project", {}).get("dependencies", [])
    for optional_deps in (
        pyproject.get("project", {}).get("optional-dependencies", {}).values()
    ):
        dependencies.extend(optional_deps)

    for line in dependencies:
        if any(
            package_name in line
            for package_name in ["invoke ", "pytest ", "pre-commit "]
        ):
            package_name = line.split(maxsplit=1)[0]
            assert line == f"{package_name} ~={original_dependencies[package_name]}"
        elif "tomlkit" in line:
            # Should be three version digits, since the original dependency had three.
            assert line == "tomlkit[test,docs] ~=1.0.0"
        elif "mike" in line:
            assert line == "mike >=1.0,<3"
        elif "pytest-cov" in line:
            assert line == "pytest-cov ~=3.1"
        elif "pylint" in line:
            assert line == "pylint ~=2.14"
        else:
            pytest.fail(f"Unknown package in line: {line}")
