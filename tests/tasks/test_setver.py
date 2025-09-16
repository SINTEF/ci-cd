"""Test `ci_cd.tasks.setver()`."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path


compliant_python_version_schemes: list[tuple[str, str]] = [
    # Simple “major.minor” versioning:
    ("0.1", "0.1.0"),
    ("0.2", "0.2.0"),
    ("0.3", "0.3.0"),
    ("1.0", "1.0.0"),
    ("1.1", "1.1.0"),
    # Simple “major.minor.micro” versioning:
    ("1.1.0", "1.1.0"),
    ("1.1.1", "1.1.1"),
    ("1.1.2", "1.1.2"),
    ("1.2.0", "1.2.0"),
    # “major.minor” versioning with alpha, beta and candidate pre-releases:
    ("0.9", "0.9.0"),
    ("1.0a1", "1.0.0a1"),
    ("1.0a2", "1.0.0a2"),
    ("1.0b1", "1.0.0b1"),
    ("1.0rc1", "1.0.0rc1"),
    ("1.0", "1.0.0"),
    ("1.1a1", "1.1.0a1"),
    # “major.minor” versioning with developmental releases, release candidates and
    # post-releases for minor corrections:
    ("0.9", "0.9.0"),
    ("1.0.dev1", "1.0.0.dev1"),
    ("1.0.dev2", "1.0.0.dev2"),
    ("1.0.dev3", "1.0.0.dev3"),
    ("1.0.dev4", "1.0.0.dev4"),
    ("1.0c1", "1.0.0rc1"),  # Note: “c” is a valid abbreviation for “rc”
    ("1.0c2", "1.0.0rc2"),  # Note: “c” is a valid abbreviation for “rc”
    ("1.0", "1.0.0"),
    ("1.0.post1", "1.0.0.post1"),
    ("1.1.dev1", "1.1.0.dev1"),
    # Date based releases, using an incrementing serial within each year, skipping zero:
    ("2012.1", "2012.1.0"),
    ("2012.2", "2012.2.0"),
    ("2012.3", "2012.3.0"),
    ("2012.15", "2012.15.0"),
    ("2013.1", "2013.1.0"),
    ("2013.2", "2013.2.0"),
    # Another collection of valid versions from PEP 440:
    ("1.dev0", "1.0.0.dev0"),
    ("1.0.dev456", "1.0.0.dev456"),
    ("1.0a1", "1.0.0a1"),
    ("1.0a2.dev456", "1.0.0a2.dev456"),
    ("1.0a12.dev456", "1.0.0a12.dev456"),
    ("1.0a12", "1.0.0a12"),
    ("1.0b1.dev456", "1.0.0b1.dev456"),
    ("1.0b2", "1.0.0b2"),
    ("1.0b2.post345.dev456", "1.0.0b2.post345.dev456"),
    ("1.0b2.post345", "1.0.0b2.post345"),
    ("1.0rc1.dev456", "1.0.0rc1.dev456"),
    ("1.0rc1", "1.0.0rc1"),
    ("1.0", "1.0.0"),
    ("1.0+abc.5", "1.0.0+abc.5"),
    ("1.0+abc.7", "1.0.0+abc.7"),
    ("1.0+5", "1.0.0+5"),
    ("1.0.post456.dev34", "1.0.0.post456.dev34"),
    ("1.0.post456", "1.0.0.post456"),
    ("1.0.15", "1.0.15"),
    ("1.1.dev1", "1.1.0.dev1"),
]


def test_setver(tmp_path: Path) -> None:
    """Test setver runs with defaults."""
    from invoke import MockContext

    from ci_cd.tasks.setver import setver

    # Create __init__.py file
    package_dir = tmp_path / "src" / "my_package"
    package_dir.mkdir(parents=True)
    (package_dir / "__init__.py").write_text("__version__ = '0.0.0'\n")

    setver(
        MockContext(),
        package_dir=package_dir.relative_to(tmp_path),
        version="0.1.0",
        root_repo_path=tmp_path,
    )

    # Check __init__.py file
    assert (package_dir / "__init__.py").read_text() == '__version__ = "0.1.0"\n'


@pytest.mark.parametrize(
    ("version", "expected_version"),
    compliant_python_version_schemes,
    ids=[f"{v} -> {ev}" for v, ev in compliant_python_version_schemes],
)
def test_setver_python_version(
    tmp_path: Path, version: str, expected_version: str
) -> None:
    """Test setver runs with Python version."""
    from invoke import MockContext

    from ci_cd.tasks.setver import setver

    # Create __init__.py file
    package_dir = tmp_path / "src" / "my_package"
    package_dir.mkdir(parents=True)
    (package_dir / "__init__.py").write_text("__version__ = '0.0.0'\n")

    setver(
        MockContext(),
        package_dir=package_dir.relative_to(tmp_path),
        version=version,
        root_repo_path=tmp_path,
    )

    # Check __init__.py file
    assert (
        package_dir / "__init__.py"
    ).read_text() == f'__version__ = "{expected_version}"\n'


def test_invalid_version() -> None:
    """Test setver emits an error and stops when given an invalid version."""
    from invoke import MockContext

    from ci_cd.tasks.setver import setver
    from ci_cd.utils.versions import SemanticVersion

    invalid_version = "invalid"

    # Ensure the version is invalid
    with pytest.raises(ValueError, match="cannot be parsed"):
        SemanticVersion(invalid_version)

    with pytest.raises(
        SystemExit,
        match=(
            r"Please specify version as a semantic version \(SemVer\) or PEP 440 "
            r"version\..*"
        ),
    ):
        setver(MockContext(), package_dir="does not matter", version="invalid")


@pytest.mark.parametrize(
    "variant", ["absolute path", "relative path", "package_dir variable"]
)
def test_setver_with_code_base_update_variants(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, variant: str
) -> None:
    """Test setver runs with code_base_update."""
    from invoke import MockContext

    from ci_cd.tasks.setver import setver

    # Create __init__.py file
    package_dir = tmp_path / "src" / "my_package"
    package_dir.mkdir(parents=True)
    (package_dir / "__init__.py").write_text("__version__ = '0.0.0'\n")

    # Create a file to update
    file_to_update = package_dir / "file_to_update"
    file_to_update.write_text("version = '0.0.0'\n")

    # Create a file outside package_dir to update
    outside_file_to_update = tmp_path / "outside_file_to_update"
    outside_file_to_update.write_text(
        "https://example.com/something/0.0.0/update-previous-path-part\n"
    )

    # Prepare setver inputs
    if variant == "absolute path":
        filepaths: list[str | Path] = [
            file_to_update.resolve(),
            outside_file_to_update.resolve(),
        ]
    elif variant == "relative path":
        filepaths = [
            file_to_update.relative_to(tmp_path),
            outside_file_to_update.relative_to(tmp_path),
        ]
    elif variant == "package_dir variable":
        filepaths = [
            f"{{package_dir}}/{file_to_update.relative_to(package_dir)}",
            outside_file_to_update.resolve(),
        ]

    new_version = "0.1.0"

    # Run setver
    setver(
        MockContext(),
        package_dir=package_dir.relative_to(tmp_path),
        version=new_version,
        root_repo_path=tmp_path,
        code_base_update=[
            f"{filepaths[0]},version = '.*',version = '{{version}}'",
            f"{filepaths[1]},something/.*/update-previous,something/{{version}}/update-previous",
        ],
        code_base_update_separator=",",
    )

    # Check logs
    assert f"filepath: {(package_dir / '__init__.py').resolve()}" not in caplog.text
    assert f"filepath: {file_to_update.resolve()}" in caplog.text
    assert f"filepath: {outside_file_to_update.resolve()}" in caplog.text

    # Check __init__.py file was NOT updated (not in code_base_update)
    assert (package_dir / "__init__.py").read_text() == "__version__ = '0.0.0'\n"

    # Check file_to_update WAS updated (in code_base_update)
    assert file_to_update.read_text() == f"version = '{new_version}'\n"

    # Check outside_file_to_update WAS updated (in code_base_update)
    assert (
        outside_file_to_update.read_text()
        == f"https://example.com/something/{new_version}/update-previous-path-part\n"
    )


@pytest.mark.parametrize(
    ("version", "expected_version"),
    compliant_python_version_schemes,
    ids=[f"{v} -> {ev}" for v, ev in compliant_python_version_schemes],
)
@pytest.mark.parametrize(
    "version_part",
    [
        "ALL",
        "major",
        "minor",
        "patch",
        "pre_release",
        "build",
        "epoch",
        "release",
        "pre",
        "post",
        "dev",
        "local",
        "public",
        "base_version",
        "micro",
    ],
)
def test_setver_with_code_base_update_version_parts(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    version: str,
    expected_version: str,
    version_part: str,
) -> None:
    """Test setver runs with code_base_update."""
    from invoke import MockContext

    from ci_cd.tasks.setver import setver
    from ci_cd.utils.versions import SemanticVersion

    python_specific_version_parts = [
        "epoch",
        "release",
        "pre",
        "post",
        "dev",
        "local",
        "public",
        "base_version",
        "micro",
    ]

    # Create __init__.py file
    package_dir = tmp_path / "src" / "my_package"
    package_dir.mkdir(parents=True)
    (package_dir / "__init__.py").write_text("__version__ = '0.0.0'\n")

    # Create a file to update
    file_to_update = package_dir / "file_to_update"
    file_to_update.write_text("version = '0.0.0'\n")

    # Create a file outside package_dir to update
    outside_file_to_update = tmp_path / "outside_file_to_update"
    outside_file_to_update.write_text(
        "https://example.com/something/0.0.0/update-previous-path-part\n"
    )

    replacements = (
        [
            "version = '{version}'",
            "something/{version}/update-previous",
        ]
        if version_part == "ALL"
        else [
            f"version = '{{version.{version_part}}}'",
            f"something/{{version.{version_part}}}/update-previous",
        ]
    )

    semantic_version = SemanticVersion(version)

    # Explicitly extract the expected version if Python version-specific parts are
    # requested
    if version_part != "ALL":
        if version_part in python_specific_version_parts:
            expected_version = getattr(
                semantic_version.as_python_version(shortened=False), version_part
            )
        else:
            expected_version = getattr(semantic_version, version_part)

        print(f"Updated expected version: {expected_version}")

    # Run setver
    setver(
        MockContext(),
        package_dir=package_dir.relative_to(tmp_path),
        version=version,
        root_repo_path=tmp_path,
        code_base_update=[
            f"{file_to_update.resolve()},version = '.*',{replacements[0]}",
            f"{outside_file_to_update.resolve()},something/.*/update-previous,{replacements[1]}",
        ],
        code_base_update_separator=",",
    )

    # Check logs
    assert f"filepath: {(package_dir / '__init__.py').resolve()}" not in caplog.text
    assert f"filepath: {file_to_update.resolve()}" in caplog.text
    assert f"filepath: {outside_file_to_update.resolve()}" in caplog.text

    # Check __init__.py file was NOT updated (not in code_base_update)
    assert (package_dir / "__init__.py").read_text() == "__version__ = '0.0.0'\n"

    # Check file_to_update WAS updated (in code_base_update)
    assert file_to_update.read_text() == f"version = '{expected_version}'\n"

    # Check outside_file_to_update WAS updated (in code_base_update)
    assert (
        outside_file_to_update.read_text()
        == f"https://example.com/something/{expected_version}/update-previous-path-part\n"
    )


def test_init_file_not_found() -> None:
    """Test setver emits an error and stops when the __init__.py file is not found."""
    from pathlib import Path

    from invoke import MockContext

    from ci_cd.tasks.setver import setver

    assert not (Path.cwd() / "does not matter" / "__init__.py").exists()

    with pytest.raises(
        SystemExit,
        match=r"Could not find the Python package's root '__init__\.py' file",
    ):
        setver(MockContext(), package_dir="does not matter", version="0.1.0")


@pytest.mark.parametrize("fail_fast", [True, False])
def test_invalid_code_base_update(fail_fast: bool) -> None:
    """Test setver emits an error and stops when given an invalid code_base_update
    concerning the splitter."""
    from invoke import MockContext

    from ci_cd.tasks.setver import setver

    error_msg = (
        "Could not properly extract"
        if fail_fast
        else "Errors occurred! See printed statements above."
    )

    with pytest.raises(SystemExit, match=error_msg):
        setver(
            MockContext(),
            package_dir="does not matter",
            version="0.1.0",
            code_base_update=["invalid"],
            fail_fast=fail_fast,
        )


@pytest.mark.parametrize("fail_fast", [True, False])
def test_invalid_code_base_filepaths(fail_fast: bool) -> None:
    """Test setver emits an error and stops when given invalid file paths in
    code_base_update."""
    from invoke import MockContext

    from ci_cd.tasks.setver import setver

    if fail_fast:
        error_msg = "Could not find the user-provided file at:"
    else:
        error_msg = "Errors occurred! See printed statements above."

    with pytest.raises(SystemExit, match=error_msg):
        setver(
            MockContext(),
            package_dir="does not matter",
            version="0.1.0",
            code_base_update=["invalid,invalid,invalid again"],
            fail_fast=fail_fast,
        )


@pytest.mark.parametrize("fail_fast", [True, False])
def test_invalid_code_base_update_regex(
    fail_fast: bool, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Test setver emits an error and stops when given invalid regex in
    code_base_update."""
    from invoke import MockContext

    from ci_cd.tasks.setver import setver

    # No matter fail_fast, the error message will be the same, since this happens after
    # the logic of failing fast. Here we just fail.
    error_msg = "Could not update file"

    # Create __init__.py file
    package_dir = tmp_path / "src" / "my_package"
    package_dir.mkdir(parents=True)
    (package_dir / "__init__.py").write_text("__version__ = '0.0.0'\n")

    # Create a file to update
    file_to_update = package_dir / "file_to_update"
    file_to_update.write_text("version = '0.0.0'\n")

    with pytest.raises(SystemExit, match=error_msg):
        # Here the regex is invalid because the first parenthesis is being escaped
        setver(
            MockContext(),
            package_dir="does not matter",
            version="0.1.0",
            code_base_update=[rf"{file_to_update.resolve()},\(?:'|\"),{{version}}"],
            code_base_update_separator=",",
            fail_fast=fail_fast,
        )
    assert "Some files have already been updated !" not in caplog.text

    # Test extra message if files were already updated
    with pytest.raises(
        SystemExit, match="Some files have already been updated !\n\n " + error_msg
    ):
        setver(
            MockContext(),
            package_dir="does not matter",
            version="0.1.0",
            code_base_update=[
                rf"{file_to_update.resolve()},version = '.*',version = '{{version}}",
                rf"{file_to_update.resolve()},version = \(?:'|\").*',version = "
                rf"'{{version}}",
            ],
            code_base_update_separator=",",
            fail_fast=fail_fast,
        )
    assert "Some files have already been updated !" in caplog.text
