"""Test `ci_cd/tasks.py`."""
# pylint: disable=too-many-locals
import pytest


def test_create_api_reference() -> None:
    """Check create_api_reference_docs runs with defaults."""
    import os
    import shutil
    from pathlib import Path
    from tempfile import TemporaryDirectory

    from invoke import MockContext

    from ci_cd.tasks import create_api_reference_docs

    with TemporaryDirectory() as tmpdir:
        root_path = Path(tmpdir).resolve()
        package_dir = root_path / "ci_cd"
        shutil.copytree(
            src=Path(__file__).resolve().parent.parent / "ci_cd",
            dst=package_dir,
        )

        docs_folder = root_path / "docs"
        docs_folder.mkdir()

        create_api_reference_docs(
            MockContext(),
            str(package_dir),
            root_repo_path=str(root_path),
        )

        api_reference_folder = docs_folder / "api_reference"

        assert docs_folder.exists(), f"Parent content: {os.listdir(docs_folder.parent)}"
        assert (
            api_reference_folder.exists()
        ), f"Parent content: {os.listdir(api_reference_folder.parent)}"
        assert {".pages", "main.md", "tasks.md"} == set(
            os.listdir(api_reference_folder)
        )

        assert (api_reference_folder / ".pages").read_text(
            encoding="utf8"
        ) == 'title: "API Reference"\n'
        assert (api_reference_folder / "main.md").read_text(
            encoding="utf8"
        ) == "# main\n\n::: ci_cd.main\n"
        assert (api_reference_folder / "tasks.md").read_text(
            encoding="utf8"
        ) == "# tasks\n\n::: ci_cd.tasks\n"


def test_api_reference_nested_package() -> None:
    """Check create_api_reference_docs generates correct link to sub-nested package
    directory."""
    import os
    import shutil
    from pathlib import Path
    from tempfile import TemporaryDirectory

    from invoke import MockContext

    from ci_cd.tasks import create_api_reference_docs

    with TemporaryDirectory() as tmpdir:
        root_path = Path(tmpdir).resolve()
        package_dir = root_path / "src" / "ci_cd" / "ci_cd"
        shutil.copytree(
            src=Path(__file__).resolve().parent.parent / "ci_cd",
            dst=package_dir,
        )

        docs_folder = root_path / "docs"
        docs_folder.mkdir()

        create_api_reference_docs(
            MockContext(),
            str(package_dir),
            root_repo_path=str(root_path),
        )

        api_reference_folder = docs_folder / "api_reference"

        assert docs_folder.exists(), f"Parent content: {os.listdir(docs_folder.parent)}"
        assert (
            api_reference_folder.exists()
        ), f"Parent content: {os.listdir(api_reference_folder.parent)}"
        assert {".pages", "main.md", "tasks.md"} == set(
            os.listdir(api_reference_folder)
        )

        assert (api_reference_folder / ".pages").read_text(
            encoding="utf8"
        ) == 'title: "API Reference"\n'
        assert (api_reference_folder / "main.md").read_text(
            encoding="utf8"
        ) == "# main\n\n::: src.ci_cd.ci_cd.main\n"
        assert (api_reference_folder / "tasks.md").read_text(
            encoding="utf8"
        ) == "# tasks\n\n::: src.ci_cd.ci_cd.tasks\n"


def test_update_deps() -> None:
    """Check update_deps runs with defaults."""
    import re
    from pathlib import Path
    from tempfile import TemporaryDirectory

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

    with TemporaryDirectory() as tmpdir:
        root_path = Path(tmpdir).resolve()
        pyproject_file = root_path / "pyproject.toml"
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
            root_repo_path=str(root_path),
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
