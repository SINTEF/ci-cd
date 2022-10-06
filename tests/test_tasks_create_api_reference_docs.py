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
    for package_dir in [api_reference_folder / _.name for _ in package_dirs]:
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


def test_larger_package(tmp_path: "Path") -> None:
    """Check create_api_reference_docs runs with a more 'complete' package."""
    import os
    import shutil
    from pathlib import Path

    from invoke import MockContext

    from ci_cd.tasks import create_api_reference_docs

    package_dir = tmp_path / "ci_cd"
    new_submodules = [
        package_dir / "module",
        package_dir / "module" / "submodule",
        package_dir / "second_module",
    ]
    for destination in [package_dir] + new_submodules:
        shutil.copytree(
            src=Path(__file__).resolve().parent.parent / "ci_cd",
            dst=destination,
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
    assert {".pages", "main.md", "tasks.md", "module", "second_module"} == set(
        os.listdir(api_reference_folder)
    )
    for module_dir in [
        api_reference_folder / _.relative_to(package_dir) for _ in new_submodules
    ]:
        extra_dir_content = {"submodule"} if module_dir.name == "module" else set()
        assert module_dir.exists(), f"Parent content: {os.listdir(module_dir.parent)}"
        assert {".pages", "main.md", "tasks.md"} | extra_dir_content == set(
            os.listdir(module_dir)
        ), f"module_dir: {module_dir.relative_to(api_reference_folder)}"

    assert (api_reference_folder / ".pages").read_text(
        encoding="utf8"
    ) == 'title: "API Reference"\n'
    assert (api_reference_folder / "main.md").read_text(
        encoding="utf8"
    ) == "# main\n\n::: ci_cd.main\n"
    assert (api_reference_folder / "tasks.md").read_text(
        encoding="utf8"
    ) == "# tasks\n\n::: ci_cd.tasks\n"
    for module_dir in [
        api_reference_folder / _.relative_to(package_dir) for _ in new_submodules
    ]:
        py_path = f"{package_dir.name}." + str(
            module_dir.relative_to(api_reference_folder)
        ).replace("/", ".")
        assert (module_dir / ".pages").read_text(
            encoding="utf8"
        ) == f'title: "{module_dir.name}"\n', (
            f"module_dir: {module_dir.relative_to(api_reference_folder)}"
        )
        assert (module_dir / "main.md").read_text(
            encoding="utf8"
        ) == f"# main\n\n::: {py_path}.main\n", (
            f"module_dir: {module_dir.relative_to(api_reference_folder)}"
        )
        assert (module_dir / "tasks.md").read_text(
            encoding="utf8"
        ) == f"# tasks\n\n::: {py_path}.tasks\n", (
            f"module_dir: {module_dir.relative_to(api_reference_folder)}"
        )


def test_larger_multi_packages(tmp_path: "Path") -> None:
    """Check create_api_reference_docs runs with a set of more 'complete' packages."""
    import os
    import shutil
    from pathlib import Path

    from invoke import MockContext

    from ci_cd.tasks import create_api_reference_docs

    package_dirs = [
        tmp_path / "ci_cd",
        tmp_path / "ci_cd_again",
    ]
    new_submodules = [
        "module",
        "module/submodule",
        "second_module",
    ]
    for package_dir in package_dirs:
        for destination in [package_dir] + [package_dir / _ for _ in new_submodules]:
            shutil.copytree(
                src=Path(__file__).resolve().parent.parent / "ci_cd",
                dst=destination,
            )

    docs_folder = tmp_path / "docs"
    docs_folder.mkdir()

    create_api_reference_docs(
        MockContext(),
        [str(package_dir.relative_to(tmp_path)) for package_dir in package_dirs],
        root_repo_path=str(tmp_path),
    )

    api_reference_folder = docs_folder / "api_reference"

    assert docs_folder.exists(), f"Parent content: {os.listdir(docs_folder.parent)}"
    assert (
        api_reference_folder.exists()
    ), f"Parent content: {os.listdir(api_reference_folder.parent)}"
    assert {".pages", "ci_cd", "ci_cd_again"} == set(os.listdir(api_reference_folder))
    for package_dir in [
        api_reference_folder / _.relative_to(tmp_path) for _ in package_dirs
    ]:
        assert {".pages", "main.md", "tasks.md", "module", "second_module"} == set(
            os.listdir(package_dir)
        ), f"package_dir: {package_dir.relative_to(api_reference_folder)}"
        for module_dir in [package_dir / _ for _ in new_submodules]:
            extra_dir_content = {"submodule"} if module_dir.name == "module" else set()
            assert (
                module_dir.exists()
            ), f"Parent content: {os.listdir(module_dir.parent)}"
            assert {".pages", "main.md", "tasks.md"} | extra_dir_content == set(
                os.listdir(module_dir)
            ), f"module_dir: {module_dir.relative_to(api_reference_folder)}"

    assert (api_reference_folder / ".pages").read_text(
        encoding="utf8"
    ) == 'title: "API Reference"\n'
    for package_dir in [
        api_reference_folder / _.relative_to(tmp_path) for _ in package_dirs
    ]:
        assert (package_dir / ".pages").read_text(
            encoding="utf8"
        ) == f'title: "{package_dir.name}"\n'
        assert (package_dir / "main.md").read_text(
            encoding="utf8"
        ) == f"# main\n\n::: {package_dir.name}.main\n"
        assert (package_dir / "tasks.md").read_text(
            encoding="utf8"
        ) == f"# tasks\n\n::: {package_dir.name}.tasks\n"
        for module_dir in [package_dir / _ for _ in new_submodules]:
            py_path = f"{package_dir.name}." + str(
                module_dir.relative_to(package_dir)
            ).replace("/", ".")
            assert (module_dir / ".pages").read_text(
                encoding="utf8"
            ) == f'title: "{module_dir.name}"\n', (
                f"module_dir: {module_dir.relative_to(api_reference_folder)}"
            )
            assert (module_dir / "main.md").read_text(
                encoding="utf8"
            ) == f"# main\n\n::: {py_path}.main\n", (
                f"module_dir: {module_dir.relative_to(api_reference_folder)}"
            )
            assert (module_dir / "tasks.md").read_text(
                encoding="utf8"
            ) == f"# tasks\n\n::: {py_path}.tasks\n", (
                f"module_dir: {module_dir.relative_to(api_reference_folder)}"
            )
