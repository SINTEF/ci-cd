"""Tests for utils.py"""
import pytest


def test_semanticversion() -> None:
    """Test SemanticVersion class."""
    from ci_cd.utils import SemanticVersion

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
    assert all(
        SemanticVersion(**input_[0]) == input_[1]
        if isinstance(input_, tuple)
        else isinstance(SemanticVersion(input_), SemanticVersion)
        for input_ in valid_inputs
    )
    assert all(
        isinstance(SemanticVersion(version=input_), SemanticVersion)
        for input_ in valid_inputs
        if isinstance(input_, str)
    )


def test_semanticversion_invalid() -> None:
    """Test SemanticVersion class with invalid inputs."""
    from ci_cd.utils import SemanticVersion

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

    from ci_cd.utils import SemanticVersion

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
    from ci_cd.utils import SemanticVersion

    valid_inputs = [
        ("1.0.0", "major", "2.0.0"),
        ("1.0.0", "minor", "1.1.0"),
        ("1.0.0", "patch", "1.0.1"),
    ]

    for version, version_part, next_version in valid_inputs:
        assert SemanticVersion(version).next_version(version_part) == next_version


def test_semanticversion_next_version_invalid() -> None:
    """Test the next_version method of SemanticVersion class with invalid inputs."""
    from ci_cd.utils import SemanticVersion

    invalid_inputs = [
        "invalid",
        "pre_release",
        "build",
    ]

    for version_part in invalid_inputs:
        with pytest.raises(ValueError, match="version_part must be one of"):
            SemanticVersion("1.0.0").next_version(version_part)
