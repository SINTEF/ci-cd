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
        {"major": 1, "minor": 0, "patch": 0},
        {"major": 1, "minor": 0, "patch": 0, "pre_release": "alpha"},
        {"major": 1, "minor": 0, "patch": 0, "pre_release": "alpha.1"},
        {"major": 1, "minor": 0, "patch": 0, "pre_release": "0.3.7"},
        {"major": 1, "minor": 0, "patch": 0, "pre_release": "x.7.z.92"},
        {"major": 1, "minor": 0, "patch": 0, "pre_release": "alpha", "build": "001"},
        {"major": 1, "minor": 0, "patch": 0, "build": "20130313144700"},
        {
            "major": 1,
            "minor": 0,
            "patch": 0,
            "pre_release": "beta",
            "build": "exp.sha.5114f85",
        },
        {
            "major": 1,
            "minor": 0,
            "patch": 0,
            "pre_release": "beta.11",
            "build": "exp.sha.5114f85",
        },
        {
            "major": 1,
            "minor": 0,
            "patch": 0,
            "pre_release": "rc.1",
            "build": "exp.sha.5114f85",
        },
    ]
    assert all(
        isinstance(SemanticVersion(**input_), SemanticVersion)
        if isinstance(input_, dict)
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
    ]
    for input_, exc_msg in invalid_inputs:
        with pytest.raises(ValueError, match=exc_msg):
            SemanticVersion(  # pylint: disable=expression-not-assigned
                **input_
            ) if isinstance(input_, dict) else SemanticVersion(input_)
