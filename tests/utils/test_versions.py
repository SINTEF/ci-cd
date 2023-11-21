"""Tests for utils/versions.py"""
# pylint: disable=too-many-lines
from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from ci_cd.utils.versions import (
        IgnoreEntry,
        IgnoreRules,
        IgnoreUpdateTypes,
        IgnoreVersions,
    )


def test_semanticversion() -> None:
    """Test SemanticVersion class."""
    from ci_cd.utils.versions import SemanticVersion

    valid_inputs = [
        "1.0.0",
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-0.3.7",
        "1.0.0-x.7.z.92",
        "1.0.0-alpha+001",
        "1.0.0+20130313144700",
        "1.0.0-beta+exp.sha.5114f85",
        "1.0.0-beta.11+exp.sha.5114f85",
        "1.0.0-rc.1+exp.sha.5114f85",
        ({"major": 1, "minor": 0, "patch": 0}, "1.0.0"),
        ({"major": 1, "minor": 0, "patch": 0, "pre_release": "alpha"}, "1.0.0-alpha"),
        (
            {"major": 1, "minor": 0, "patch": 0, "pre_release": "alpha.1"},
            "1.0.0-alpha.1",
        ),
        ({"major": 1, "minor": 0, "patch": 0, "pre_release": "0.3.7"}, "1.0.0-0.3.7"),
        (
            {"major": 1, "minor": 0, "patch": 0, "pre_release": "x.7.z.92"},
            "1.0.0-x.7.z.92",
        ),
        (
            {
                "major": 1,
                "minor": 0,
                "patch": 0,
                "pre_release": "alpha",
                "build": "001",
            },
            "1.0.0-alpha+001",
        ),
        (
            {"major": 1, "minor": 0, "patch": 0, "build": "20130313144700"},
            "1.0.0+20130313144700",
        ),
        (
            {
                "major": 1,
                "minor": 0,
                "patch": 0,
                "pre_release": "beta",
                "build": "exp.sha.5114f85",
            },
            "1.0.0-beta+exp.sha.5114f85",
        ),
        (
            {
                "major": 1,
                "minor": 0,
                "patch": 0,
                "pre_release": "beta.11",
                "build": "exp.sha.5114f85",
            },
            "1.0.0-beta.11+exp.sha.5114f85",
        ),
        (
            {
                "major": 1,
                "minor": 0,
                "patch": 0,
                "pre_release": "rc.1",
                "build": "exp.sha.5114f85",
            },
            "1.0.0-rc.1+exp.sha.5114f85",
        ),
    ]
    for input_ in valid_inputs:
        value = (
            SemanticVersion(**input_[0]) == input_[1]
            if isinstance(input_, tuple)
            else isinstance(SemanticVersion(input_), SemanticVersion)
        )
        assert value, f"Failed for input: {input_}. SemanticVersion: {value}"

    for input_ in valid_inputs:
        if isinstance(input_, str):
            assert isinstance(
                SemanticVersion(version=input_), SemanticVersion
            ), f"Failed for input: {input_}"


def test_semanticversion_invalid() -> None:
    """Test SemanticVersion class with invalid inputs."""
    from ci_cd.utils.versions import SemanticVersion

    invalid_inputs = [
        ("1.0.0-", "cannot be parsed as a semantic version"),
        ("1.0.0-+", "cannot be parsed as a semantic version"),
        ("1.0.0-.", "cannot be parsed as a semantic version"),
        ("1.0.0-..", "cannot be parsed as a semantic version"),
        ("1.0.0-+.", "cannot be parsed as a semantic version"),
        ("1.0.0-+..", "cannot be parsed as a semantic version"),
        (
            {"version": "1.0.0", "major": 1, "minor": 0, "patch": 0},
            "version cannot be specified along with other parameters",
        ),
        (
            {"major": 1, "patch": 0},
            "Minor must be given if patch is given",
        ),
        (
            {
                "major": 1,
                "minor": 0,
                "pre_release": "alpha",
            },
            "Patch must be given if pre_release is given",
        ),
        (
            {
                "major": 1,
                "minor": 0,
                "build": "001",
            },
            "Patch must be given if build is given",
        ),
        ("", "At least major must be given"),
        ({}, "At least major must be given"),
    ]
    for input_, exc_msg in invalid_inputs:
        with pytest.raises(ValueError, match=exc_msg):
            SemanticVersion(  # pylint: disable=expression-not-assigned
                **input_
            ) if isinstance(input_, dict) else SemanticVersion(input_)


def test_semanticversion_invalid_comparisons() -> None:
    """Test invalid comparisons with SemanticVersion class."""
    import operator

    from ci_cd.utils.versions import SemanticVersion

    operators_mapping = {
        ">": operator.gt,
        "<": operator.lt,
        "<=": operator.le,
        ">=": operator.ge,
        "==": operator.eq,
        "!=": operator.ne,
    }

    for operator_ in ("<", "<=", ">", ">=", "==", "!="):
        with pytest.raises(
            NotImplementedError, match="comparison not implemented between"
        ):
            operators_mapping[operator_](SemanticVersion("1.0.0"), 1)
        with pytest.raises(
            NotImplementedError, match="comparison not implemented between"
        ):
            operators_mapping[operator_](SemanticVersion("1.0.0"), "test")


def test_semanticversion_next_version() -> None:
    """Test the next_version method of SemanticVersion class."""
    from ci_cd.utils.versions import SemanticVersion

    valid_inputs = [
        ("1.0.0", "major", "2.0.0"),
        ("1.0.0", "minor", "1.1.0"),
        ("1.0.0", "patch", "1.0.1"),
    ]

    for version, version_part, next_version in valid_inputs:
        assert SemanticVersion(version).next_version(version_part) == next_version


def test_semanticversion_next_version_invalid() -> None:
    """Test the next_version method of SemanticVersion class with invalid inputs."""
    from ci_cd.utils.versions import SemanticVersion

    invalid_inputs = [
        "invalid",
        "pre_release",
        "build",
    ]

    for version_part in invalid_inputs:
        with pytest.raises(ValueError, match="version_part must be one of"):
            SemanticVersion("1.0.0").next_version(version_part)


def _parametrize_ignore_version() -> (
    "dict[str, tuple[str, str, IgnoreVersions, IgnoreUpdateTypes, bool]]"
):
    """Utility function for `test_ignore_version()`.

    The parametrized inputs are created in this function in order to have more
    meaningful IDs in the runtime overview.
    """
    test_cases: "list[tuple[str, str, IgnoreVersions, IgnoreUpdateTypes, bool]]" = [
        ("1.1.1", "2.2.2", [{"operator": ">", "version": "2.2.2"}], {}, False),
        ("1.1.1", "2.2.2", [{"operator": ">", "version": "2.2"}], {}, True),
        ("1.1.1", "2.2.2", [{"operator": ">", "version": "2"}], {}, True),
        ("1.1.1", "2.2.2", [{"operator": ">=", "version": "2.2.2"}], {}, True),
        ("1.1.1", "2.2.2", [{"operator": ">=", "version": "2.2"}], {}, True),
        ("1.1.1", "2.2.2", [{"operator": ">=", "version": "2"}], {}, True),
        ("1.1.1", "2.2.2", [{"operator": "<", "version": "2.2.2"}], {}, False),
        ("1.1.1", "2.2.2", [{"operator": "<", "version": "2.2"}], {}, False),
        ("1.1.1", "2.2.2", [{"operator": "<", "version": "2"}], {}, False),
        ("1.1.1", "2.2.2", [{"operator": "<=", "version": "2.2.2"}], {}, True),
        ("1.1.1", "2.2.2", [{"operator": "<=", "version": "2.2"}], {}, False),
        ("1.1.1", "2.2.2", [{"operator": "<=", "version": "2"}], {}, False),
        ("1.1.1", "2.2.2", [{"operator": "==", "version": "2.2.2"}], {}, True),
        ("1.1.1", "2.2.2", [{"operator": "==", "version": "2.2"}], {}, False),
        ("1.1.1", "2.2.2", [{"operator": "==", "version": "2"}], {}, False),
        ("1.1.1", "2.2.2", [{"operator": "!=", "version": "2.2.2"}], {}, False),
        ("1.1.1", "2.2.2", [{"operator": "!=", "version": "2.2"}], {}, True),
        ("1.1.1", "2.2.2", [{"operator": "!=", "version": "2"}], {}, True),
        ("1.1.1", "2.2.2", [{"operator": "~=", "version": "2.2.2"}], {}, True),
        ("1.1.1", "2.2.2", [{"operator": "~=", "version": "2.2"}], {}, True),
        ("1.1.1", "1.1.2", [{"operator": "~=", "version": "1.1"}], {}, True),
        ("1.1.1", "1.1.2", [{"operator": "~=", "version": "1.0"}], {}, True),
        ("1.1.1", "1.1.2", [{"operator": "~=", "version": "1.2"}], {}, False),
        ("1.1.1", "2.2.2", [], {"version-update": ["major"]}, True),
        ("1.1.1", "2.2.2", [], {"version-update": ["minor"]}, False),
        ("1.1.1", "2.2.2", [], {"version-update": ["patch"]}, False),
        ("1.1.1", "1.2.2", [], {"version-update": ["major"]}, False),
        ("1.1.1", "2.1.2", [], {"version-update": ["minor"]}, False),
        ("1.1.1", "2.2.1", [], {"version-update": ["patch"]}, False),
        ("1.1.1", "1.2.1", [], {"version-update": ["minor"]}, True),
        ("1.1.1", "1.1.2", [], {"version-update": ["patch"]}, True),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": ">", "version": "2.2.2"}],
            {"version-update": ["major"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": ">", "version": "2.2.2"}],
            {"version-update": ["minor"]},
            False,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": ">", "version": "2.2.2"}],
            {"version-update": ["patch"]},
            False,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": ">", "version": "2.2"}],
            {"version-update": ["major"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": ">", "version": "2.2"}],
            {"version-update": ["minor"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": ">", "version": "2.2"}],
            {"version-update": ["patch"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": ">", "version": "2"}],
            {"version-update": ["major"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": ">", "version": "2"}],
            {"version-update": ["minor"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": ">", "version": "2"}],
            {"version-update": ["patch"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": ">=", "version": "2.2.2"}],
            {"version-update": ["major"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": ">=", "version": "2.2.2"}],
            {"version-update": ["minor"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": ">=", "version": "2.2.2"}],
            {"version-update": ["patch"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": ">=", "version": "2.2"}],
            {"version-update": ["major"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": ">=", "version": "2.2"}],
            {"version-update": ["minor"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": ">=", "version": "2.2"}],
            {"version-update": ["patch"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": ">=", "version": "2"}],
            {"version-update": ["major"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": ">=", "version": "2"}],
            {"version-update": ["minor"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": ">=", "version": "2"}],
            {"version-update": ["patch"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "<", "version": "2.2.2"}],
            {"version-update": ["major"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "<", "version": "2.2.2"}],
            {"version-update": ["minor"]},
            False,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "<", "version": "2.2.2"}],
            {"version-update": ["patch"]},
            False,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "<", "version": "2.2"}],
            {"version-update": ["major"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "<", "version": "2.2"}],
            {"version-update": ["minor"]},
            False,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "<", "version": "2.2"}],
            {"version-update": ["patch"]},
            False,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "<", "version": "2"}],
            {"version-update": ["major"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "<", "version": "2"}],
            {"version-update": ["minor"]},
            False,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "<", "version": "2"}],
            {"version-update": ["patch"]},
            False,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "<=", "version": "2.2.2"}],
            {"version-update": ["major"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "<=", "version": "2.2.2"}],
            {"version-update": ["minor"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "<=", "version": "2.2.2"}],
            {"version-update": ["patch"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "<=", "version": "2.2"}],
            {"version-update": ["major"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "<=", "version": "2.2"}],
            {"version-update": ["minor"]},
            False,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "<=", "version": "2.2"}],
            {"version-update": ["patch"]},
            False,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "<=", "version": "2"}],
            {"version-update": ["major"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "<=", "version": "2"}],
            {"version-update": ["minor"]},
            False,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "<=", "version": "2"}],
            {"version-update": ["patch"]},
            False,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "==", "version": "2.2.2"}],
            {"version-update": ["major"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "==", "version": "2.2.2"}],
            {"version-update": ["minor"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "==", "version": "2.2.2"}],
            {"version-update": ["patch"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "==", "version": "2.2"}],
            {"version-update": ["major"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "==", "version": "2.2"}],
            {"version-update": ["minor"]},
            False,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "==", "version": "2.2"}],
            {"version-update": ["patch"]},
            False,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "==", "version": "2"}],
            {"version-update": ["major"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "==", "version": "2"}],
            {"version-update": ["minor"]},
            False,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "==", "version": "2"}],
            {"version-update": ["patch"]},
            False,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "!=", "version": "2.2.2"}],
            {"version-update": ["major"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "!=", "version": "2.2.2"}],
            {"version-update": ["minor"]},
            False,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "!=", "version": "2.2.2"}],
            {"version-update": ["patch"]},
            False,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "!=", "version": "2.2"}],
            {"version-update": ["major"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "!=", "version": "2.2"}],
            {"version-update": ["minor"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "!=", "version": "2.2"}],
            {"version-update": ["patch"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "!=", "version": "2"}],
            {"version-update": ["major"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "!=", "version": "2"}],
            {"version-update": ["minor"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "!=", "version": "2"}],
            {"version-update": ["patch"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "~=", "version": "2.2.2"}],
            {"version-update": ["major"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "~=", "version": "2.2.2"}],
            {"version-update": ["minor"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "~=", "version": "2.2.2"}],
            {"version-update": ["patch"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "~=", "version": "2.2"}],
            {"version-update": ["major"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "~=", "version": "2.2"}],
            {"version-update": ["minor"]},
            True,
        ),
        (
            "1.1.1",
            "2.2.2",
            [{"operator": "~=", "version": "2.2"}],
            {"version-update": ["patch"]},
            True,
        ),
        (
            "1.1.1",
            "1.1.2",
            [{"operator": "~=", "version": "1.1"}],
            {"version-update": ["major"]},
            True,
        ),
        (
            "1.1.1",
            "1.1.2",
            [{"operator": "~=", "version": "1.1"}],
            {"version-update": ["minor"]},
            True,
        ),
        (
            "1.1.1",
            "1.1.2",
            [{"operator": "~=", "version": "1.1"}],
            {"version-update": ["patch"]},
            True,
        ),
        (
            "1.1.1",
            "1.1.2",
            [{"operator": "~=", "version": "1.0"}],
            {"version-update": ["major"]},
            True,
        ),
        (
            "1.1.1",
            "1.1.2",
            [{"operator": "~=", "version": "1.0"}],
            {"version-update": ["minor"]},
            True,
        ),
        (
            "1.1.1",
            "1.1.2",
            [{"operator": "~=", "version": "1.0"}],
            {"version-update": ["patch"]},
            True,
        ),
        (
            "1.1.1",
            "1.1.2",
            [{"operator": "~=", "version": "1.2"}],
            {"version-update": ["major"]},
            False,
        ),
        (
            "1.1.1",
            "1.1.2",
            [{"operator": "~=", "version": "1.2"}],
            {"version-update": ["minor"]},
            False,
        ),
        (
            "1.1.1",
            "1.1.2",
            [{"operator": "~=", "version": "1.2"}],
            {"version-update": ["patch"]},
            True,
        ),
        ("1.1.1", "1.1.2", [], {}, True),
    ]
    res: "dict[str, tuple[str, str, IgnoreVersions, IgnoreUpdateTypes, bool]]" = {}
    for test_case in test_cases:
        if test_case[2] and test_case[3]:
            operator_version = ",".join(
                f"{_['operator']}{_['version']}" for _ in test_case[2]
            )
            res[
                f"{operator_version} + "
                f"semver-{test_case[3]['version-update']}-latest={test_case[1]}"
            ] = test_case
        elif test_case[2]:
            res[
                ",".join(f"{_['operator']}{_['version']}" for _ in test_case[2])
            ] = test_case
        elif test_case[3]:
            res[
                f"semver-{test_case[3]['version-update']}-latest={test_case[1]}"
            ] = test_case
        else:
            res["no rules"] = test_case
    assert len(res) == len(test_cases)
    return res


@pytest.mark.parametrize(
    argnames=("current", "latest", "version_rules", "semver_rules", "expected_outcome"),
    argvalues=list(_parametrize_ignore_version().values()),
    ids=list(_parametrize_ignore_version()),
)
def test_ignore_version(
    current: str,
    latest: str,
    version_rules: "IgnoreVersions",
    semver_rules: "IgnoreUpdateTypes",
    expected_outcome: bool,
) -> None:
    """Check the expected ignore rules are resolved correctly."""
    from ci_cd.utils.versions import ignore_version

    assert (
        ignore_version(
            current=current.split("."),
            latest=latest.split("."),
            version_rules=version_rules,
            semver_rules=semver_rules,
        )
        == expected_outcome
    ), f"""Failed for:
  current={current.split(".")}
  latest={latest.split(".")}
  version_rules={version_rules}
  semver_rules={semver_rules}

Expected outcome: {expected_outcome}
Instead, ignore_version() is {not expected_outcome}
"""


@pytest.mark.parametrize(
    argnames=("entries", "separator", "expected_outcome"),
    argvalues=[
        (
            ["dependency-name=test...versions=>2.2.2"],
            "...",
            {"test": {"versions": [">2.2.2"]}},
        ),
        (
            [
                "dependency-name=test...versions=>2.2.2..."
                "update-types=version-update:semver-patch"
            ],
            "...",
            {
                "test": {
                    "versions": [">2.2.2"],
                    "update-types": ["version-update:semver-patch"],
                }
            },
        ),
        (
            [
                "dependency-name=test;versions=>2.2.2;"
                "update-types=version-update:semver-patch"
            ],
            ";",
            {
                "test": {
                    "versions": [">2.2.2"],
                    "update-types": ["version-update:semver-patch"],
                }
            },
        ),
        (
            [
                "dependency-name=test...versions=>2.2.2..."
                "update-types=version-update:semver-patch",
                "dependency-name=test...versions=<3",
            ],
            "...",
            {
                "test": {
                    "versions": [">2.2.2", "<3"],
                    "update-types": ["version-update:semver-patch"],
                }
            },
        ),
        (
            [
                "dependency-name=test;versions=>2.2.2;"
                "update-types=version-update:semver-patch",
                "dependency-name=test;versions=<3",
            ],
            ";",
            {
                "test": {
                    "versions": [">2.2.2", "<3"],
                    "update-types": ["version-update:semver-patch"],
                }
            },
        ),
        (
            [
                "dependency-name=test...versions=>2.2.2..."
                "update-types=version-update:semver-patch",
                "dependency-name=test...versions=<3..."
                "update-types=version-update:semver-major",
            ],
            "...",
            {
                "test": {
                    "versions": [">2.2.2", "<3"],
                    "update-types": [
                        "version-update:semver-patch",
                        "version-update:semver-major",
                    ],
                }
            },
        ),
        (
            [
                "dependency-name=test;versions=>2.2.2;"
                "update-types=version-update:semver-patch",
                "dependency-name=test;versions=<3;"
                "update-types=version-update:semver-major",
            ],
            ";",
            {
                "test": {
                    "versions": [">2.2.2", "<3"],
                    "update-types": [
                        "version-update:semver-patch",
                        "version-update:semver-major",
                    ],
                }
            },
        ),
        (["dependency-name=test"], "...", {"test": {}}),
    ],
)
def test_parse_ignore_entries(
    entries: list[str],
    separator: str,
    expected_outcome: "dict[str, IgnoreEntry]",
) -> None:
    """Check the `--ignore` option values are parsed as expected."""
    from ci_cd.utils.versions import parse_ignore_entries

    parsed_entries = parse_ignore_entries(
        entries=entries,
        separator=separator,
    )
    assert (
        parsed_entries == expected_outcome
    ), f"""Failed for:
  entries={entries}
  separator={separator}

Expected outcome:
{expected_outcome}

Instead, parse_ignore_entries() returned:
{parsed_entries}
"""


@pytest.mark.parametrize(
    argnames=("rules", "expected_outcome"),
    argvalues=[
        ({"versions": [">2.2.2"]}, ([{"operator": ">", "version": "2.2.2"}], {})),
        (
            {"versions": [">2.2.2"], "update-types": ["version-update:semver-patch"]},
            ([{"operator": ">", "version": "2.2.2"}], {"version-update": ["patch"]}),
        ),
        (
            {
                "versions": [">2.2.2", "<3"],
                "update-types": ["version-update:semver-patch"],
            },
            (
                [
                    {"operator": ">", "version": "2.2.2"},
                    {"operator": "<", "version": "3"},
                ],
                {"version-update": ["patch"]},
            ),
        ),
        (
            {
                "versions": [">2.2.2", "<3"],
                "update-types": [
                    "version-update:semver-patch",
                    "version-update:semver-major",
                ],
            },
            (
                [
                    {"operator": ">", "version": "2.2.2"},
                    {"operator": "<", "version": "3"},
                ],
                {"version-update": ["patch", "major"]},
            ),
        ),
        ({}, ([{"operator": ">=", "version": "0"}], {})),
    ],
)
def test_parse_ignore_rules(
    rules: "IgnoreRules",
    expected_outcome: "tuple[IgnoreVersions, IgnoreUpdateTypes]",
) -> None:
    """Check a specific set of ignore rules is parsed as expected."""
    from ci_cd.utils.versions import parse_ignore_rules

    parsed_rules = parse_ignore_rules(rules=rules)
    assert (
        parsed_rules == expected_outcome
    ), f"""Failed for:
  rules={rules}

Expected outcome:
{expected_outcome}

Instead, parse_ignore_rules() returned:
{parsed_rules}
"""


def test_ignore_version_fails() -> None:
    """Ensure `InputParserError` is raised for unknown ignore options."""
    from ci_cd.exceptions import InputError, InputParserError
    from ci_cd.utils.versions import ignore_version

    # This is only true when using `_ignore_version_rules_semver()`
    # with pytest.raises(
    #     InputParserError, match="only supports the following operators:"
    # ):
    #     ignore_version(
    #         current="1.1.1".split("."),
    #         latest="2.2.2".split("."),
    #         version_rules=[{"operator": "===", "version": "2.2.2"}],
    #         semver_rules={},
    #     )

    with pytest.raises(
        InputParserError, match=r"^Only valid values for 'version-update' are.*"
    ):
        ignore_version(
            current="1.1.1".split("."),
            latest="2.2.2".split("."),
            version_rules=[],
            semver_rules={"version-update": ["build"]},  # type: ignore[list-item]
        )

    with pytest.raises(InputError):
        ignore_version(
            current="1.1.1".split("."),
            latest="2.2.2".split("."),
            version_rules=[{"operator": "~=", "version": "2"}],
            semver_rules={},
        )


@pytest.mark.parametrize(
    ["requires_python", "expected_outcome"],
    [
        # Minimum operators
        # >=
        (">=3.6", "3.6"),
        (">=3.6,<3.10", "3.6"),
        (">=3.6,<3.10,!=3.6.0", "3.6.1"),
        # ~=
        ("~=3.6", "3.6"),
        ("~=3.6,<3.10", "3.6"),
        ("~=3.6,<3.10,!=3.6.0", "3.6.1"),
        ("~=3.6.1", "3.6.1"),
        ("~=3.6.1,<3.10", "3.6.1"),
        ("~=3.6.1,<3.10,!=3.6.1", "3.6.2"),
        # ==
        ("==3.6", "3.6"),
        # >
        (">3.6", "3.7"),
        (">3.6,<3.10", "3.7"),
        (">3.6,<3.10,!=3.6.1,!=3.7", "3.7.1"),
        (">3.6.0", "3.6.1"),
        (">3.6.0,<3.10", "3.6.1"),
        (">3.6.0,<3.10,!=3.6.1,!=3.7", "3.6.2"),
        # Maximum operators
        # <=
        ("<=3.6", "3.6"),
        ("<=3.6.5", "3.6.5"),
        ("<=3.6.5,!=3.6.4", "3.6.5"),
        # <
        ("<3.6", "3.5"),
        ("<3.6.5", "3.6.4"),
        ("<3.6.5,!=3.6.4", "3.6.3"),
    ],
    ids=[
        ">=3.6",
        ">=3.6,<3.10",
        ">=3.6,<3.10,!=3.6.0",
        "~=3.6",
        "~=3.6,<3.10",
        "~=3.6,<3.10,!=3.6.0",
        "~=3.6.1",
        "~=3.6.1,<3.10",
        "~=3.6.1,<3.10,!=3.6.1",
        "==3.6",
        ">3.6",
        ">3.6,<3.10",
        ">3.6,<3.10,!=3.6.1,!=3.7",
        ">3.6.0",
        ">3.6.0,<3.10",
        ">3.6.0,<3.10,!=3.6.1,!=3.7",
        "<=3.6",
        "<=3.6.5",
        "<=3.6.5,!=3.6.4",
        "<3.6",
        "<3.6.5",
        "<3.6.5,!=3.6.4",
    ],
)
def test_get_min_max_py_version(requires_python: str, expected_outcome: str) -> None:
    """Test `get_min_max_py_version()`."""
    from packaging.markers import Marker

    from ci_cd.utils.versions import get_min_max_py_version

    test_value = requires_python

    if "python_version" in requires_python:
        test_value = Marker(requires_python)

    assert get_min_max_py_version(test_value) == expected_outcome
