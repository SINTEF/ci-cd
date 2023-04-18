"""Repository management tasks powered by `invoke`.
More information on `invoke` can be found at [pyinvoke.org](http://www.pyinvoke.org/).
"""
import logging
import re
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

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

    def __init__(
        self,
        version: "Optional[str]" = None,
        major: "Optional[Union[str, int]]" = None,
        minor: "Optional[Union[str, int]]" = None,
        patch: "Optional[Union[str, int]]" = None,
        pre_release: "Optional[str]" = None,
        build: "Optional[str]" = None,
    ) -> None:
        if version:
            if major or minor or patch or pre_release or build:
                raise ValueError(
                    "version cannot be specified along with other parameters"
                )

            if not isinstance(version, str):
                try:
                    version = str(version)
                except (TypeError, ValueError) as exc:
                    raise TypeError("version must be a str") from exc

            match = re.match(self._REGEX, version)
            if match is None:
                raise ValueError(
                    "version cannot be parsed as a semantic version according to the "
                    "SemVer.org regular expression"
                )
            major, minor, patch, pre_release, build = match.groups()

        elif not major:
            raise ValueError("At least major or version must be given")

        self._major = int(major)
        self._minor = int(minor) if minor else 0
        self._patch = int(patch) if patch else 0
        self._pre_release = pre_release if pre_release else None
        self._build = build if build else None

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

    def __hash__(self) -> int:
        return hash(self.__str__())

    def _check_other_comparison(self, other: "Any") -> "SemanticVersion":
        """Initial check/validation before rich comparisons."""
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
        other_semver = self._check_other_comparison(other)

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
        other_semver = self._check_other_comparison(other)

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
                        return True
                    if other_semver.pre_release is None:
                        return True
                    return self.pre_release <= other_semver.pre_release
        return False

    def __eq__(self, other: "Any") -> bool:
        """Equal to (`==`) rich comparison."""
        other_semver = self._check_other_comparison(other)

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
        other_semver = self._check_other_comparison(other)

        if self.major > other_semver.major:
            return True
        if self.major == other_semver.major:
            if self.minor > other_semver.minor:
                return True
            if self.minor == other_semver.minor:
                if self.patch > other_semver.patch:
                    return True
                if self.patch == other_semver.patch:
                    if self.pre_release is None:
                        return True
                    if other_semver.pre_release is None:
                        return False
                    return self.pre_release >= other_semver.pre_release
        return False

    def __gt__(self, other: "Any") -> bool:
        """Greater than (`>`) rich comparison."""
        other_semver = self._check_other_comparison(other)

        if self.major > other_semver.major:
            return True
        if self.major == other_semver.major:
            if self.minor > other_semver.minor:
                return True
            if self.minor == other_semver.minor:
                if self.patch > other_semver.patch:
                    return True
                if self.patch == other_semver.patch:
                    if self.pre_release is None:
                        return False
                    if other_semver.pre_release is None:
                        return False
                    return self.pre_release > other_semver.pre_release
        return False


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
