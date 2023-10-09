"""Test `ci_cd.tasks.api_reference_docs`."""
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
        src=Path(__file__).resolve().parent.parent.parent / "ci_cd",
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
    assert {".pages", "main.md", "utils.md", "tasks", "exceptions.md"} == set(
        os.listdir(api_reference_folder)
    )
    assert {
        ".pages",
        "api_reference_docs.md",
        "docs_index.md",
        "setver.md",
        "update_deps.md",
    } == set(os.listdir(api_reference_folder / "tasks"))

    assert (api_reference_folder / ".pages").read_text(
        encoding="utf8"
    ) == 'title: "API Reference"\n'
    assert (api_reference_folder / "main.md").read_text(
        encoding="utf8"
    ) == "# main\n\n::: ci_cd.main\n"
    assert (api_reference_folder / "utils.md").read_text(
        encoding="utf8"
    ) == "# utils\n\n::: ci_cd.utils\n"
    assert (api_reference_folder / "exceptions.md").read_text(
        encoding="utf8"
    ) == "# exceptions\n\n::: ci_cd.exceptions\n"

    assert (api_reference_folder / "tasks" / ".pages").read_text(
        encoding="utf8"
    ) == 'title: "tasks"\n'
    assert (api_reference_folder / "tasks" / "api_reference_docs.md").read_text(
        encoding="utf8"
    ) == "# api_reference_docs\n\n::: ci_cd.tasks.api_reference_docs\n"
    assert (api_reference_folder / "tasks" / "docs_index.md").read_text(
        encoding="utf8"
    ) == "# docs_index\n\n::: ci_cd.tasks.docs_index\n"
    assert (api_reference_folder / "tasks" / "setver.md").read_text(
        encoding="utf8"
    ) == "# setver\n\n::: ci_cd.tasks.setver\n"
    assert (api_reference_folder / "tasks" / "update_deps.md").read_text(
        encoding="utf8"
    ) == "# update_deps\n\n::: ci_cd.tasks.update_deps\n"


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
        src=Path(__file__).resolve().parent.parent.parent / "ci_cd",
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
    assert {".pages", "main.md", "utils.md", "tasks", "exceptions.md"} == set(
        os.listdir(api_reference_folder)
    )
    assert {
        ".pages",
        "api_reference_docs.md",
        "docs_index.md",
        "setver.md",
        "update_deps.md",
    } == set(os.listdir(api_reference_folder / "tasks"))

    assert (api_reference_folder / ".pages").read_text(
        encoding="utf8"
    ) == 'title: "API Reference"\n'
    assert (api_reference_folder / "main.md").read_text(
        encoding="utf8"
    ) == "# main\n\n::: src.ci_cd.ci_cd.main\n"
    assert (api_reference_folder / "utils.md").read_text(
        encoding="utf8"
    ) == "# utils\n\n::: src.ci_cd.ci_cd.utils\n"
    assert (api_reference_folder / "exceptions.md").read_text(
        encoding="utf8"
    ) == "# exceptions\n\n::: src.ci_cd.ci_cd.exceptions\n"

    assert (api_reference_folder / "tasks" / ".pages").read_text(
        encoding="utf8"
    ) == 'title: "tasks"\n'
    assert (api_reference_folder / "tasks" / "api_reference_docs.md").read_text(
        encoding="utf8"
    ) == "# api_reference_docs\n\n::: src.ci_cd.ci_cd.tasks.api_reference_docs\n"
    assert (api_reference_folder / "tasks" / "docs_index.md").read_text(
        encoding="utf8"
    ) == "# docs_index\n\n::: src.ci_cd.ci_cd.tasks.docs_index\n"
    assert (api_reference_folder / "tasks" / "setver.md").read_text(
        encoding="utf8"
    ) == "# setver\n\n::: src.ci_cd.ci_cd.tasks.setver\n"
    assert (api_reference_folder / "tasks" / "update_deps.md").read_text(
        encoding="utf8"
    ) == "# update_deps\n\n::: src.ci_cd.ci_cd.tasks.update_deps\n"


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
        src=Path(__file__).resolve().parent.parent.parent / "ci_cd",
        dst=package_dir,
    )

    docs_folder = tmp_path / "docs"
    docs_folder.mkdir()

    create_api_reference_docs(
        MockContext(),
        [str(package_dir.relative_to(tmp_path))],
        root_repo_path=str(tmp_path),
        full_docs_file=["utils.py"],
        full_docs_folder=["tasks"],
        special_option=[
            'main.py,test_option: "yup"',
            "main.py,another_special_option: true",
            "utils.py,my_special_option: |"
            f"\n{' ' * 8}multi-line-thing\n{' ' * 8}another line",
        ],
    )

    api_reference_folder = docs_folder / "api_reference"

    assert docs_folder.exists(), f"Parent content: {os.listdir(docs_folder.parent)}"
    assert (
        api_reference_folder.exists()
    ), f"Parent content: {os.listdir(api_reference_folder.parent)}"
    assert {".pages", "main.md", "utils.md", "tasks", "exceptions.md"} == set(
        os.listdir(api_reference_folder)
    )
    assert {
        ".pages",
        "api_reference_docs.md",
        "docs_index.md",
        "setver.md",
        "update_deps.md",
    } == set(os.listdir(api_reference_folder / "tasks"))

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
        (api_reference_folder / "utils.md").read_text(encoding="utf8")
        == """# utils

::: ci_cd.utils
    options:
      show_if_no_docstring: true
      my_special_option: |
        multi-line-thing
        another line
"""
    )
    assert (api_reference_folder / "exceptions.md").read_text(
        encoding="utf8"
    ) == "# exceptions\n\n::: ci_cd.exceptions\n"

    assert (api_reference_folder / "tasks" / ".pages").read_text(
        encoding="utf8"
    ) == 'title: "tasks"\n'
    assert (api_reference_folder / "tasks" / "api_reference_docs.md").read_text(
        encoding="utf8"
    ) == (
        "# api_reference_docs\n\n::: ci_cd.tasks.api_reference_docs\n    options:\n"
        "      show_if_no_docstring: true\n"
    )
    assert (api_reference_folder / "tasks" / "docs_index.md").read_text(
        encoding="utf8"
    ) == (
        "# docs_index\n\n::: ci_cd.tasks.docs_index\n    options:\n      "
        "show_if_no_docstring: true\n"
    )
    assert (api_reference_folder / "tasks" / "setver.md").read_text(
        encoding="utf8"
    ) == (
        "# setver\n\n::: ci_cd.tasks.setver\n    options:\n      "
        "show_if_no_docstring: true\n"
    )
    assert (api_reference_folder / "tasks" / "update_deps.md").read_text(
        encoding="utf8"
    ) == (
        "# update_deps\n\n::: ci_cd.tasks.update_deps\n    options:\n      "
        "show_if_no_docstring: true\n"
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
            src=Path(__file__).resolve().parent.parent.parent / "ci_cd",
            dst=package_dir,
        )

    docs_folder = tmp_path / "docs"
    docs_folder.mkdir()

    create_api_reference_docs(
        MockContext(),
        [str(package_dir.relative_to(tmp_path)) for package_dir in package_dirs],
        root_repo_path=str(tmp_path),
        full_docs_file=["ci_cd_again/utils.py"],
        full_docs_folder=["ci_cd_again/tasks"],
        special_option=[
            'ci_cd/main.py,test_option: "yup"',
            "ci_cd/main.py,another_special_option: true",
            "ci_cd_again/utils.py,my_special_option: |"
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
        assert {".pages", "main.md", "utils.md", "tasks", "exceptions.md"} == set(
            os.listdir(package_dir)
        )
        assert {
            ".pages",
            "api_reference_docs.md",
            "docs_index.md",
            "setver.md",
            "update_deps.md",
        } == set(os.listdir(package_dir / "tasks"))

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
        (api_reference_folder / "ci_cd" / "utils.md").read_text(encoding="utf8")
        == """# utils

::: ci_cd.utils
"""
    )
    assert (
        (api_reference_folder / "ci_cd" / "exceptions.md").read_text(encoding="utf8")
        == """# exceptions

::: ci_cd.exceptions
"""
    )
    assert (
        (api_reference_folder / "ci_cd_again" / "main.md").read_text(encoding="utf8")
        == """# main

::: ci_cd_again.main
"""
    )
    assert (
        (api_reference_folder / "ci_cd_again" / "utils.md").read_text(encoding="utf8")
        == """# utils

::: ci_cd_again.utils
    options:
      show_if_no_docstring: true
      my_special_option: |
        multi-line-thing
        another line
"""
    )
    assert (
        (api_reference_folder / "ci_cd_again" / "exceptions.md").read_text(
            encoding="utf8"
        )
        == """# exceptions

::: ci_cd_again.exceptions
"""
    )

    for package_name in ("ci_cd", "ci_cd_again"):
        assert (api_reference_folder / package_name / "tasks" / ".pages").read_text(
            encoding="utf8"
        ) == 'title: "tasks"\n'
        assert (
            api_reference_folder / package_name / "tasks" / "api_reference_docs.md"
        ).read_text(encoding="utf8") == (
            f"# api_reference_docs\n\n::: {package_name}.tasks.api_reference_docs\n"
            + (
                "    options:\n      show_if_no_docstring: true\n"
                if package_name == "ci_cd_again"
                else ""
            )
        )
        assert (
            api_reference_folder / package_name / "tasks" / "docs_index.md"
        ).read_text(encoding="utf8") == (
            f"# docs_index\n\n::: {package_name}.tasks.docs_index\n"
            + (
                "    options:\n      show_if_no_docstring: true\n"
                if package_name == "ci_cd_again"
                else ""
            )
        )
        assert (api_reference_folder / package_name / "tasks" / "setver.md").read_text(
            encoding="utf8"
        ) == (
            f"# setver\n\n::: {package_name}.tasks.setver\n"
            + (
                "    options:\n      show_if_no_docstring: true\n"
                if package_name == "ci_cd_again"
                else ""
            )
        )
        assert (
            api_reference_folder / package_name / "tasks" / "update_deps.md"
        ).read_text(encoding="utf8") == (
            f"# update_deps\n\n::: {package_name}.tasks.update_deps\n"
            + (
                "    options:\n      show_if_no_docstring: true\n"
                if package_name == "ci_cd_again"
                else ""
            )
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
            src=Path(__file__).resolve().parent.parent.parent / "ci_cd",
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
    assert {
        ".pages",
        "main.md",
        "utils.md",
        "tasks",
        "exceptions.md",
        "module",
        "second_module",
    } == set(os.listdir(api_reference_folder))
    for module_dir in [
        api_reference_folder / _.relative_to(package_dir) for _ in new_submodules
    ]:
        extra_dir_content = {"submodule"} if module_dir.name == "module" else set()
        assert module_dir.exists(), f"Parent content: {os.listdir(module_dir.parent)}"
        assert {
            ".pages",
            "main.md",
            "utils.md",
            "tasks",
            "exceptions.md",
        } | extra_dir_content == set(
            os.listdir(module_dir)
        ), f"module_dir: {module_dir.relative_to(api_reference_folder)}"

    assert (api_reference_folder / ".pages").read_text(
        encoding="utf8"
    ) == 'title: "API Reference"\n'
    assert (api_reference_folder / "main.md").read_text(
        encoding="utf8"
    ) == "# main\n\n::: ci_cd.main\n"
    assert (api_reference_folder / "utils.md").read_text(
        encoding="utf8"
    ) == "# utils\n\n::: ci_cd.utils\n"
    assert (api_reference_folder / "exceptions.md").read_text(
        encoding="utf8"
    ) == "# exceptions\n\n::: ci_cd.exceptions\n"

    assert (api_reference_folder / "tasks" / ".pages").read_text(
        encoding="utf8"
    ) == 'title: "tasks"\n'
    assert (api_reference_folder / "tasks" / "api_reference_docs.md").read_text(
        encoding="utf8"
    ) == "# api_reference_docs\n\n::: ci_cd.tasks.api_reference_docs\n"
    assert (api_reference_folder / "tasks" / "docs_index.md").read_text(
        encoding="utf8"
    ) == "# docs_index\n\n::: ci_cd.tasks.docs_index\n"
    assert (api_reference_folder / "tasks" / "setver.md").read_text(
        encoding="utf8"
    ) == "# setver\n\n::: ci_cd.tasks.setver\n"
    assert (api_reference_folder / "tasks" / "update_deps.md").read_text(
        encoding="utf8"
    ) == "# update_deps\n\n::: ci_cd.tasks.update_deps\n"

    for module_dir in [
        api_reference_folder / _.relative_to(package_dir) for _ in new_submodules
    ]:
        py_path = f"{package_dir.name}." + str(
            module_dir.relative_to(api_reference_folder)
        ).replace(os.sep, "/").replace("/", ".")
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
        assert (module_dir / "utils.md").read_text(
            encoding="utf8"
        ) == f"# utils\n\n::: {py_path}.utils\n", (
            f"module_dir: {module_dir.relative_to(api_reference_folder)}"
        )
        assert (module_dir / "exceptions.md").read_text(
            encoding="utf8"
        ) == f"# exceptions\n\n::: {py_path}.exceptions\n", (
            f"module_dir: {module_dir.relative_to(api_reference_folder)}"
        )

        assert (module_dir / "tasks" / ".pages").read_text(
            encoding="utf8"
        ) == 'title: "tasks"\n', (
            f"module_dir: {module_dir.relative_to(api_reference_folder)}"
        )
        assert (module_dir / "tasks" / "api_reference_docs.md").read_text(
            encoding="utf8"
        ) == f"# api_reference_docs\n\n::: {py_path}.tasks.api_reference_docs\n", (
            f"module_dir: {module_dir.relative_to(api_reference_folder)}"
        )
        assert (module_dir / "tasks" / "docs_index.md").read_text(
            encoding="utf8"
        ) == f"# docs_index\n\n::: {py_path}.tasks.docs_index\n", (
            f"module_dir: {module_dir.relative_to(api_reference_folder)}"
        )
        assert (module_dir / "tasks" / "setver.md").read_text(
            encoding="utf8"
        ) == f"# setver\n\n::: {py_path}.tasks.setver\n", (
            f"module_dir: {module_dir.relative_to(api_reference_folder)}"
        )
        assert (module_dir / "tasks" / "update_deps.md").read_text(
            encoding="utf8"
        ) == f"# update_deps\n\n::: {py_path}.tasks.update_deps\n", (
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
                src=Path(__file__).resolve().parent.parent.parent / "ci_cd",
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
        assert {
            ".pages",
            "main.md",
            "utils.md",
            "tasks",
            "exceptions.md",
            "module",
            "second_module",
        } == set(
            os.listdir(package_dir)
        ), f"package_dir: {package_dir.relative_to(api_reference_folder)}"
        for module_dir in [package_dir / _ for _ in new_submodules]:
            extra_dir_content = {"submodule"} if module_dir.name == "module" else set()
            assert (
                module_dir.exists()
            ), f"Parent content: {os.listdir(module_dir.parent)}"
            assert {
                ".pages",
                "main.md",
                "utils.md",
                "tasks",
                "exceptions.md",
            } | extra_dir_content == set(
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
        assert (package_dir / "utils.md").read_text(
            encoding="utf8"
        ) == f"# utils\n\n::: {package_dir.name}.utils\n"
        assert (package_dir / "exceptions.md").read_text(
            encoding="utf8"
        ) == f"# exceptions\n\n::: {package_dir.name}.exceptions\n"

        assert (package_dir / "tasks" / ".pages").read_text(
            encoding="utf8"
        ) == 'title: "tasks"\n'
        assert (package_dir / "tasks" / "api_reference_docs.md").read_text(
            encoding="utf8"
        ) == (
            "# api_reference_docs\n\n::: "
            f"{package_dir.name}.tasks.api_reference_docs\n"
        )
        assert (package_dir / "tasks" / "docs_index.md").read_text(
            encoding="utf8"
        ) == f"# docs_index\n\n::: {package_dir.name}.tasks.docs_index\n"
        assert (package_dir / "tasks" / "setver.md").read_text(
            encoding="utf8"
        ) == f"# setver\n\n::: {package_dir.name}.tasks.setver\n"
        assert (package_dir / "tasks" / "update_deps.md").read_text(
            encoding="utf8"
        ) == f"# update_deps\n\n::: {package_dir.name}.tasks.update_deps\n"

        for module_dir in [package_dir / _ for _ in new_submodules]:
            py_path = f"{package_dir.name}." + str(
                module_dir.relative_to(package_dir)
            ).replace(os.sep, "/").replace("/", ".")
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
            assert (module_dir / "utils.md").read_text(
                encoding="utf8"
            ) == f"# utils\n\n::: {py_path}.utils\n", (
                f"module_dir: {module_dir.relative_to(api_reference_folder)}"
            )
            assert (module_dir / "exceptions.md").read_text(
                encoding="utf8"
            ) == f"# exceptions\n\n::: {py_path}.exceptions\n", (
                f"module_dir: {module_dir.relative_to(api_reference_folder)}"
            )

            assert (module_dir / "tasks" / ".pages").read_text(
                encoding="utf8"
            ) == 'title: "tasks"\n', (
                f"module_dir: {module_dir.relative_to(api_reference_folder)}"
            )
            assert (module_dir / "tasks" / "api_reference_docs.md").read_text(
                encoding="utf8"
            ) == f"# api_reference_docs\n\n::: {py_path}.tasks.api_reference_docs\n", (
                f"module_dir: {module_dir.relative_to(api_reference_folder)}"
            )
            assert (module_dir / "tasks" / "docs_index.md").read_text(
                encoding="utf8"
            ) == f"# docs_index\n\n::: {py_path}.tasks.docs_index\n", (
                f"module_dir: {module_dir.relative_to(api_reference_folder)}"
            )
            assert (module_dir / "tasks" / "setver.md").read_text(
                encoding="utf8"
            ) == f"# setver\n\n::: {py_path}.tasks.setver\n", (
                f"module_dir: {module_dir.relative_to(api_reference_folder)}"
            )
            assert (module_dir / "tasks" / "update_deps.md").read_text(
                encoding="utf8"
            ) == f"# update_deps\n\n::: {py_path}.tasks.update_deps\n", (
                f"module_dir: {module_dir.relative_to(api_reference_folder)}"
            )
