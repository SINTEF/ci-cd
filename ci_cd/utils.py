"""Repository management tasks powered by `invoke`.
More information on `invoke` can be found at [pyinvoke.org](http://www.pyinvoke.org/).
"""
import logging
import re
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, no_type_check

if TYPE_CHECKING:  # pragma: no cover
    from typing import Any, Optional, Tuple, Union


LOGGER = logging.getLogger(__file__)
LOGGER.setLevel(logging.DEBUG)


class Emoji(str, Enum):
    """Unicode strings for certain emojis."""

    PARTY_POPPER = "\U0001f389"
    CHECK_MARK = "\u2714"
    CROSS_MARK = "\u274c"
    CURLY_LOOP = "\u27b0"


class SemanticVersion(str):
    """A semantic version.

    See [SemVer.org](https://semver.org) for more information about semantic
    versioning.

    The semantic version is in this invocation considered to build up in the following
    way:

        <major>.<minor>.<patch>-<pre_release>+<build>

    Where the names in carets are callable attributes for the instance.

    When casting instances of `SemanticVersion` to `str`, the full version will be
    returned, i.e., as shown above, with a minimum of major.minor.patch.

    For example, for the version `1.5`, i.e., `major=1, minor=5`, the returned `str`
    representation will be the full major.minor.patch version: `1.5.0`.
    The `patch` attribute will default to `0` while `pre_release` and `build` will be
    `None`, when asked for explicitly.

    Precedence for comparing versions is done according to the rules outlined in point
    11 of the specification found at [SemVer.org](https://semver.org/#spec-item-11).

    Parameters:
        major (Union[str, int]): The major version.
        minor (Optional[Union[str, int]]): The minor version.
        patch (Optional[Union[str, int]]): The patch version.
        pre_release (Optional[str]): The pre-release part of the version, i.e., the
            part supplied after a minus (`-`), but before a plus (`+`).
        build (Optional[str]): The build metadata part of the version, i.e., the part
            supplied at the end of the version, after a plus (`+`).

    Attributes:
        major (int): The major version.
        minor (int): The minor version.
        patch (int): The patch version.
        pre_release (str): The pre-release part of the version, i.e., the part
            supplied after a minus (`-`), but before a plus (`+`).
        build (str): The build metadata part of the version, i.e., the part supplied at
            the end of the version, after a plus (`+`).

    """

    _REGEX = (
        r"^(?P<major>0|[1-9]\d*)(?:\.(?P<minor>0|[1-9]\d*))?(?:\.(?P<patch>0|[1-9]\d*))?"
        r"(?:-(?P<pre_release>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
        r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
        r"(?:\+(?P<build>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
    )

    @no_type_check
    def __new__(
        cls, version: "Optional[str]" = None, **kwargs: "Union[str, int]"
    ) -> "SemanticVersion":
        return super().__new__(
            cls, version if version else cls._build_version(**kwargs)
        )

    def __init__(
        self,
        version: "Optional[str]" = None,
        *,
        major: "Union[str, int]" = "",
        minor: "Optional[Union[str, int]]" = None,
        patch: "Optional[Union[str, int]]" = None,
        pre_release: "Optional[str]" = None,
        build: "Optional[str]" = None,
    ) -> None:
        if version is not None:
            if major or minor or patch or pre_release or build:
                raise ValueError(
                    "version cannot be specified along with other parameters"
                )

            match = re.match(self._REGEX, version)
            if match is None:
                raise ValueError(
                    f"version ({version}) cannot be parsed as a semantic version "
                    "according to the SemVer.org regular expression"
                )
            major, minor, patch, pre_release, build = match.groups()

        self._major = int(major)
        self._minor = int(minor) if minor else 0
        self._patch = int(patch) if patch else 0
        self._pre_release = pre_release if pre_release else None
        self._build = build if build else None

    @classmethod
    def _build_version(
        cls,
        major: "Optional[Union[str, int]]" = None,
        minor: "Optional[Union[str, int]]" = None,
        patch: "Optional[Union[str, int]]" = None,
        pre_release: "Optional[str]" = None,
        build: "Optional[str]" = None,
    ) -> str:
        """Build a version from the given parameters."""
        if major is None:
            raise ValueError("At least major must be given")
        version = str(major)
        if minor is not None:
            version += f".{minor}"
        if patch is not None:
            if minor is None:
                raise ValueError("Minor must be given if patch is given")
            version += f".{patch}"
        if pre_release is not None:
            # semver spec #9: A pre-release version MAY be denoted by appending a
            # hyphen and a series of dot separated identifiers immediately following
            # the patch version.
            # https://semver.org/#spec-item-9
            if patch is None:
                raise ValueError("Patch must be given if pre_release is given")
            version += f"-{pre_release}"
        if build is not None:
            # semver spec #10: Build metadata MAY be denoted by appending a plus sign
            # and a series of dot separated identifiers immediately following the patch
            # or pre-release version.
            # https://semver.org/#spec-item-10
            if patch is None:
                raise ValueError("Patch must be given if build is given")
            version += f"+{build}"
        return version

    @property
    def major(self) -> int:
        """The major version."""
        return self._major

    @property
    def minor(self) -> int:
        """The minor version."""
        return self._minor

    @property
    def patch(self) -> int:
        """The patch version."""
        return self._patch

    @property
    def pre_release(self) -> "Union[None, str]":
        """The pre-release part of the version

        This is the part supplied after a minus (`-`), but before a plus (`+`).
        """
        return self._pre_release

    @property
    def build(self) -> "Union[None, str]":
        """The build metadata part of the version.

        This is the part supplied at the end of the version, after a plus (`+`).
        """
        return self._build

    def __str__(self) -> str:
        """Return the full version."""
        return (
            f"{self.major}.{self.minor}.{self.patch}"
            f"{f'-{self.pre_release}' if self.pre_release else ''}"
            f"{f'+{self.build}' if self.build else ''}"
        )

    def __repr__(self) -> str:
        """Return the string representation of the object."""
        return repr(self.__str__())

    def _validate_other_type(self, other: "Any") -> "SemanticVersion":
        """Initial check/validation of `other` before rich comparisons."""
        not_implemented_exc = NotImplementedError(
            f"Rich comparison not implemented between {self.__class__.__name__} and "
            f"{type(other)}"
        )

        if isinstance(other, self.__class__):
            return other

        if isinstance(other, str):
            try:
                return self.__class__(other)
            except (TypeError, ValueError) as exc:
                raise not_implemented_exc from exc

        raise not_implemented_exc

    def __lt__(self, other: "Any") -> bool:
        """Less than (`<`) rich comparison."""
        other_semver = self._validate_other_type(other)

        if self.major < other_semver.major:
            return True
        if self.major == other_semver.major:
            if self.minor < other_semver.minor:
                return True
            if self.minor == other_semver.minor:
                if self.patch < other_semver.patch:
                    return True
                if self.patch == other_semver.patch:
                    if self.pre_release is None:
                        return False
                    if other_semver.pre_release is None:
                        return True
                    return self.pre_release < other_semver.pre_release
        return False

    def __le__(self, other: "Any") -> bool:
        """Less than or equal to (`<=`) rich comparison."""
        return self.__lt__(other) or self.__eq__(other)

    def __eq__(self, other: "Any") -> bool:
        """Equal to (`==`) rich comparison."""
        other_semver = self._validate_other_type(other)

        return (
            self.major == other_semver.major
            and self.minor == other_semver.minor
            and self.patch == other_semver.patch
            and self.pre_release == other_semver.pre_release
        )

    def __ne__(self, other: "Any") -> bool:
        """Not equal to (`!=`) rich comparison."""
        return not self.__eq__(other)

    def __ge__(self, other: "Any") -> bool:
        """Greater than or equal to (`>=`) rich comparison."""
        return not self.__lt__(other)

    def __gt__(self, other: "Any") -> bool:
        """Greater than (`>`) rich comparison."""
        return not self.__le__(other)

    def next_version(self, version_part: str) -> "SemanticVersion":
        """Return the next version for the specified version part.

        Parameters:
            version_part: The version part to increment.

        Returns:
            The next version.

        Raises:
            ValueError: If the version part is not one of `major`, `minor`, or `patch`.

        """
        if version_part not in ("major", "minor", "patch"):
            raise ValueError(
                "version_part must be one of 'major', 'minor', or 'patch', not "
                f"{version_part!r}"
            )

        if version_part == "major":
            return self.__class__(f"{self.major + 1}.0.0")
        if version_part == "minor":
            return self.__class__(f"{self.major}.{self.minor + 1}.0")

        return self.__class__(f"{self.major}.{self.minor}.{self.patch + 1}")


def update_file(
    filename: Path, sub_line: "Tuple[str, str]", strip: "Optional[str]" = None
) -> None:
    """Utility function for tasks to read, update, and write files"""
    if strip is None and filename.suffix == ".md":
        # Keep special white space endings for markdown files
        strip = "\n"
    lines = [
        re.sub(sub_line[0], sub_line[1], line.rstrip(strip))
        for line in filename.read_text(encoding="utf8").splitlines()
    ]
    filename.write_text("\n".join(lines) + "\n", encoding="utf8")
