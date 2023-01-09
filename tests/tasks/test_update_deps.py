"""Test `ci_cd.tasks.update_deps()`."""
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path


def test_update_deps(tmp_path: "Path", caplog: pytest.LogCaptureFixture) -> None:
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

# List from https://peps.python.org/pep-0508/#complete-grammar
pep_508 = [
    "A",
    "A.B-C_D",
    "aa",
    "name",
    "name1<=1",
    "name2>=3",
    "name3>=3,<2",
    "name4@http://foo.com",
    "name5 [fred,bar] @ http://foo.com ; python_version=='2.7'",
    "name6[quux, strange];python_version<'2.7' and platform_version=='2'",
    "name7; os_name=='a' or os_name=='b'",
    # Should parse as (a and b) or c
    "name8; os_name=='a' and os_name=='b' or os_name=='c'",
    # Overriding precedence -> a and (b or c)
    "name9; os_name=='a' and (os_name=='b' or os_name=='c')",
    # should parse as a or (b and c)
    "name10; os_name=='a' or os_name=='b' and os_name=='c'",
    # Overriding precedence -> (a or b) and c
    "name11; (os_name=='a' or os_name=='b') and os_name=='c'",
]
""",
        encoding="utf8",
    )

    context = MockContext(
        run={
            **{
                re.compile(r".*invoke$"): "invoke (1.7.1)\n",
                re.compile(r".*tomlkit$"): "tomlkit (1.0.0)",
                re.compile(r".*mike$"): "mike (1.0.1)",
                re.compile(r".*pytest$"): "pytest (7.1.0)",
                re.compile(r".*pytest-cov$"): "pytest-cov (3.1.0)",
                re.compile(r".*pre-commit$"): "pre-commit (2.20.0)",
                re.compile(r".*pylint$"): "pylint (2.14.0)",
                re.compile(r".* A$"): "A (1.2.3)",
                re.compile(r".*A.B-C_D$"): "A.B-C_D (1.2.3)",
                re.compile(r".*aa$"): "aa (1.2.3)",
                re.compile(r".*name$"): "name (1.2.3)",
            },
            **{re.compile(rf".*name{i}$"): f"name{i} (1.2.3)" for i in range(1, 12)},
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
            line.startswith(package_name)
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
        elif any(
            package_name == line for package_name in ["A", "A.B-C_D", "aa", "name"]
        ) or any(
            line.startswith(package_name)
            for package_name in [f"name{i}" for i in range(6, 12)]
        ):
            package_name = line.split(";", maxsplit=1)[0].strip()
            assert (
                f"{package_name!r} is not version restricted and will be skipped."
                in caplog.text
            )
            if ";" in line:
                assert "os_name" in line or (
                    "python_version" in line and "platform_version" in line
                )
        elif "name1" in line:
            assert line == "name1<=1"
        elif "name2" in line:
            assert line == "name2>=3"
        elif "name3" in line:
            assert line == "name3>=3,<2"
        elif "name4" in line:
            assert line == "name4@http://foo.com"
            assert "'name4' is pinned to a URL and will be skipped" in caplog.text
        elif "name5" in line:
            assert line == "name5 [fred,bar] @ http://foo.com ; python_version=='2.7'"
            assert (
                "'name5 [fred,bar]' is pinned to a URL and will be skipped"
                in caplog.text
            )
        else:
            pytest.fail(f"Unknown package in line: {line}")
