"""Test `ci_cd.tasks.create_api_reference_docs()`."""
# pylint: disable=too-many-locals
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


def test_default_run(tmp_path: "Path") -> None:
    """Check create_api_reference_docs runs with defaults."""
    import os
    import shutil
    from pathlib import Path

    from invoke import MockContext

    from ci_cd.tasks import create_api_reference_docs

    package_dir = tmp_path / "ci_cd"
    shutil.copytree(
        src=Path(__file__).resolve().parent.parent / "ci_cd",
        dst=package_dir,
    )

    docs_folder = tmp_path / "docs"
    docs_folder.mkdir()

    create_api_reference_docs(
        MockContext(),
        [str(package_dir.relative_to(tmp_path))],
        root_repo_path=str(tmp_path),
    )

    api_reference_folder = docs_folder / "api_reference"

    assert docs_folder.exists(), f"Parent content: {os.listdir(docs_folder.parent)}"
    assert (
        api_reference_folder.exists()
    ), f"Parent content: {os.listdir(api_reference_folder.parent)}"
    assert {".pages", "main.md", "tasks.md"} == set(os.listdir(api_reference_folder))

    assert (api_reference_folder / ".pages").read_text(
        encoding="utf8"
    ) == 'title: "API Reference"\n'
    assert (api_reference_folder / "main.md").read_text(
        encoding="utf8"
    ) == "# main\n\n::: ci_cd.main\n"
    assert (api_reference_folder / "tasks.md").read_text(
        encoding="utf8"
    ) == "# tasks\n\n::: ci_cd.tasks\n"


def test_nested_package(tmp_path: "Path") -> None:
    """Check create_api_reference_docs generates correct link to sub-nested package
    directory."""
    import os
    import shutil
    from pathlib import Path

    from invoke import MockContext

    from ci_cd.tasks import create_api_reference_docs

    package_dir = tmp_path / "src" / "ci_cd" / "ci_cd"
    shutil.copytree(
        src=Path(__file__).resolve().parent.parent / "ci_cd",
        dst=package_dir,
    )

    docs_folder = tmp_path / "docs"
    docs_folder.mkdir()

    create_api_reference_docs(
        MockContext(),
        [str(package_dir.relative_to(tmp_path))],
        root_repo_path=str(tmp_path),
        relative=True,
    )

    api_reference_folder = docs_folder / "api_reference"

    assert docs_folder.exists(), f"Parent content: {os.listdir(docs_folder.parent)}"
    assert (
        api_reference_folder.exists()
    ), f"Parent content: {os.listdir(api_reference_folder.parent)}"
    assert {".pages", "main.md", "tasks.md"} == set(os.listdir(api_reference_folder))

    assert (api_reference_folder / ".pages").read_text(
        encoding="utf8"
    ) == 'title: "API Reference"\n'
    assert (api_reference_folder / "main.md").read_text(
        encoding="utf8"
    ) == "# main\n\n::: src.ci_cd.ci_cd.main\n"
    assert (api_reference_folder / "tasks.md").read_text(
        encoding="utf8"
    ) == "# tasks\n\n::: src.ci_cd.ci_cd.tasks\n"


def test_special_options(tmp_path: "Path") -> None:
    """Check create_api_reference_docs generates correct markdown files with
    `--special-option`."""
    import os
    import shutil
    from pathlib import Path

    from invoke import MockContext

    from ci_cd.tasks import create_api_reference_docs

    package_dir = tmp_path / "src" / "ci_cd"
    shutil.copytree(
        src=Path(__file__).resolve().parent.parent / "ci_cd",
        dst=package_dir,
    )

    docs_folder = tmp_path / "docs"
    docs_folder.mkdir()

    create_api_reference_docs(
        MockContext(),
        [str(package_dir.relative_to(tmp_path))],
        root_repo_path=str(tmp_path),
        full_docs_file=["tasks.py"],
        special_option=[
            'main.py,test_option: "yup"',
            "main.py,another_special_option: true",
            "tasks.py,my_special_option: |"
            f"\n{' ' * 8}multi-line-thing\n{' ' * 8}another line",
        ],
    )

    api_reference_folder = docs_folder / "api_reference"

    assert docs_folder.exists(), f"Parent content: {os.listdir(docs_folder.parent)}"
    assert (
        api_reference_folder.exists()
    ), f"Parent content: {os.listdir(api_reference_folder.parent)}"
    assert {".pages", "main.md", "tasks.md"} == set(os.listdir(api_reference_folder))

    assert (api_reference_folder / ".pages").read_text(
        encoding="utf8"
    ) == 'title: "API Reference"\n'
    assert (
        (api_reference_folder / "main.md").read_text(encoding="utf8")
        == """# main

::: ci_cd.main
    options:
      test_option: "yup"
      another_special_option: true
"""
    )
    assert (
        (api_reference_folder / "tasks.md").read_text(encoding="utf8")
        == """# tasks

::: ci_cd.tasks
    options:
      show_if_no_docstring: true
      my_special_option: |
        multi-line-thing
        another line
"""
    )


def test_special_options_multiple_packages(tmp_path: "Path") -> None:
    """Check create_api_reference_docs generates correct markdown files with
    `--special-option` for a multi-package repository."""
    import os
    import shutil
    from pathlib import Path

    from invoke import MockContext

    from ci_cd.tasks import create_api_reference_docs

    package_dirs = [
        tmp_path / "src" / "ci_cd",
        tmp_path / "src" / "ci_cd_again",
    ]
    for package_dir in package_dirs:
        shutil.copytree(
            src=Path(__file__).resolve().parent.parent / "ci_cd",
            dst=package_dir,
        )

    docs_folder = tmp_path / "docs"
    docs_folder.mkdir()

    create_api_reference_docs(
        MockContext(),
        [str(package_dir.relative_to(tmp_path)) for package_dir in package_dirs],
        root_repo_path=str(tmp_path),
        full_docs_file=["ci_cd_again/tasks.py"],
        special_option=[
            'ci_cd/main.py,test_option: "yup"',
            "ci_cd/main.py,another_special_option: true",
            "ci_cd_again/tasks.py,my_special_option: |"
            f"\n{' ' * 8}multi-line-thing\n{' ' * 8}another line",
        ],
    )

    api_reference_folder = docs_folder / "api_reference"

    assert docs_folder.exists(), f"Parent content: {os.listdir(docs_folder.parent)}"
    assert (
        api_reference_folder.exists()
    ), f"Parent content: {os.listdir(api_reference_folder.parent)}"
    assert {".pages", "ci_cd", "ci_cd_again"} == set(os.listdir(api_reference_folder))
    for package_dir in [api_reference_folder / _ for _ in ["ci_cd", "ci_cd_again"]]:
        assert {".pages", "main.md", "tasks.md"} == set(os.listdir(package_dir))

    assert (api_reference_folder / ".pages").read_text(
        encoding="utf8"
    ) == 'title: "API Reference"\n'
    assert (
        (api_reference_folder / "ci_cd" / "main.md").read_text(encoding="utf8")
        == """# main

::: ci_cd.main
    options:
      test_option: "yup"
      another_special_option: true
"""
    )
    assert (
        (api_reference_folder / "ci_cd" / "tasks.md").read_text(encoding="utf8")
        == """# tasks

::: ci_cd.tasks
"""
    )
    assert (
        (api_reference_folder / "ci_cd_again" / "main.md").read_text(encoding="utf8")
        == """# main

::: ci_cd_again.main
"""
    )
    assert (
        (api_reference_folder / "ci_cd_again" / "tasks.md").read_text(encoding="utf8")
        == """# tasks

::: ci_cd_again.tasks
    options:
      show_if_no_docstring: true
      my_special_option: |
        multi-line-thing
        another line
"""
    )
