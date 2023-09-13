"""Repository management tasks powered by `invoke`.
More information on `invoke` can be found at [pyinvoke.org](http://www.pyinvoke.org/).
"""
import logging
import platform
import re
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, no_type_check

from pip._vendor.packaging.requirements import InvalidRequirement, Requirement
from pip._vendor.packaging.specifiers import (
    InvalidSpecifier,
    Specifier,
    SpecifierSet,
    _IndividualSpecifier,
)

if TYPE_CHECKING:  # pragma: no cover
    from typing import Any, Iterator, Optional, Union

    from pip._vendor.packaging.specifiers import LegacySpecifier

    ParsedSpecifier = Union[Specifier, LegacySpecifier]


LOGGER = logging.getLogger(__file__)
LOGGER.setLevel(logging.DEBUG)


class Emoji(str, Enum):
    """Unicode strings for certain emojis."""

    def __new__(cls, value: str) -> "Emoji":
        obj = str.__new__(cls, value)
        if platform.system() == "Windows":
            # Windows does not support unicode emojis, so we replace them with
            # their corresponding unicode escape sequences
            obj._value_ = value.encode("unicode_escape").decode("utf-8")
        else:
            obj._value_ = value
        return obj

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

        self._original_version = self._build_version(
            major, minor, patch, pre_release, build
        )

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
    def original_version(self) -> str:
        """The original version string used to create the instance."""
        return self._original_version

    @property
    def number_of_original_core_version_parts(self) -> int:
        """The original semantic version parts used to create the instance,
        ignoring pre-relase and build."""
        match = re.match(self._REGEX, self.original_version)
        if match is None:
            raise AssertionError
        major, minor, patch, _, _ = match.groups()
        return len([part for part in (major, minor, patch) if part])

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

    @classmethod
    def _validate_other_type(cls, other: "Any") -> "SemanticVersion":
        """Initial check/validation of `other` before rich comparisons."""
        not_implemented_exc = NotImplementedError(
            f"Rich comparison not implemented between {cls.__name__} and "
            f"{type(other)}"
        )

        if isinstance(other, cls):
            return other

        if isinstance(other, str):
            try:
                return cls(other)
            except (TypeError, ValueError) as exc:
                raise not_implemented_exc from exc

        raise not_implemented_exc

    def __lt__(self, other: "Any") -> bool:
        """Less than (`<`) rich comparison."""
        if isinstance(other, SemanticVersionRange):
            return self < other.lower

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
        if isinstance(other, SemanticVersionRange):
            return self in other

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

    def next_version(self, version_part: "Optional[str]" = None) -> "SemanticVersion":
        """Return the next version for the specified version part.

        Parameters:
            version_part: The version part to increment.

        Returns:
            The next version.

        Raises:
            ValueError: If the version part is not one of `major`, `minor`, or `patch`.

        """
        # Deduce "original_version" for new instance, disregard pre-release and build
        match = re.match(self._REGEX, self.original_version)
        if match is None:
            raise AssertionError
        _, minor, patch, _, _ = match.groups()

        if not version_part:
            # Determine what version part to increment based on the original version
            version_part = "patch" if patch else "minor" if minor else "major"

        if version_part == "major":
            incremented_version = str(self.major + 1)
            if minor:
                incremented_version += ".0"
            if patch:
                incremented_version += ".0"
        elif version_part == "minor":
            incremented_version = f"{self.major}.{self.minor + 1}"
            if patch:
                incremented_version += ".0"
        elif version_part == "patch":
            incremented_version = f"{self.major}.{self.minor}.{self.patch + 1}"
        else:
            raise ValueError(
                "version_part must be one of 'major', 'minor', or 'patch', not "
                f"{version_part!r}"
            )

        return self.__class__(incremented_version)


class SortableSpecifier(Specifier):
    """A sortable specifier."""

    _sorted_operators = ["===", "==", "~=", ">=", ">", "<", "<=", "!="]

    def __lt__(self, other: "Any") -> bool:
        """Less than (`<`) rich comparison."""
        if isinstance(other, _IndividualSpecifier):
            return self._sorted_operators.index(
                self.operator
            ) < self._sorted_operators.index(other.operator)
        if isinstance(other, str):
            try:
                other = self.__class__(other)
            except InvalidSpecifier as exc:
                raise NotImplementedError from exc
            return self._sorted_operators.index(
                self.operator
            ) < self._sorted_operators.index(other.operator)

        raise NotImplementedError


class SemanticVersionRange:
    """A range of semantic versions.

    The implementation relies on the pip package `packaging` for parsing the version
    requirements and checking if a version is in the range.
    """

    _arbritrary_upper_limit = "9" * 3

    def __init__(self, specifier: "Union[SpecifierSet, Requirement, str]") -> None:
        if isinstance(specifier, str):
            try:
                specifier = Requirement(specifier).specifier
            except InvalidRequirement:
                try:
                    specifier = SpecifierSet(specifier)  # type: ignore[arg-type]
                except InvalidSpecifier as exc:
                    raise ValueError(
                        f"specifier ({specifier}) cannot be parsed as a requirement "
                        "or specifier set"
                    ) from exc
        elif isinstance(specifier, Requirement):
            specifier = specifier.specifier
        if not isinstance(specifier, SpecifierSet):
            raise TypeError(
                f"specifier must be of type {SpecifierSet.__name__}, "
                f"{Requirement.__name__}, or str, not {type(specifier).__name__}"
            )

        self._specifier = self._sanitize_specifier_set(specifier)
        self._lower = self._determine_lower()
        self._upper = self._determine_upper()

    def _sanitize_specifier_set(self, specifier_set: "SpecifierSet") -> "SpecifierSet":
        """Sanitize the specifier set."""
        if not specifier_set:
            return specifier_set

        # Check all version specifiers are semantic
        for specifier in specifier_set:
            try:
                SemanticVersion(specifier.version)
            except ValueError as exc:
                raise ValueError(
                    f"Specifier {specifier} is not a semantic version specifier"
                ) from exc

        # Check single-use operators are used only once
        if (
            len(
                [
                    specifier
                    for specifier in specifier_set
                    if specifier.operator in ("<", "<=")
                ]
            )
            > 1
        ):
            raise ValueError(
                "Multiple upper bound specifiers ('<', '<=') found in specifier set "
                f"{specifier_set}. Instead, consider using the != operator. For "
                "example, to avoid a complete minor range: !=1.*"
            )
        if (
            len(
                [
                    specifier
                    for specifier in specifier_set
                    if specifier.operator in (">", ">=", "~=")
                ]
            )
            > 1
        ):
            raise ValueError(
                "Multiple lower bound specifiers ('>', '>=', '~=') found in specifier "
                f"set {specifier_set}. Instead, consider using the != operator. For "
                "example, to avoid a complete minor range: !=1.*"
            )
        if (
            len(
                [specifier for specifier in specifier_set if specifier.operator == "=="]
            )
            > 1
        ):
            raise ValueError(
                "Single-use specifier '==' found multiple times in specifier set "
                f"{specifier_set}."
            )

        # Check no other specifiers are given if equals is given
        if (
            any(specifier.operator == "==" for specifier in specifier_set)
            and len(specifier_set) > 1
        ):
            raise ValueError(
                "Specifier set erroneously contains specifiers alongside a '==' "
                "specifier"
            )

        # Check that the version range is not "flipped"
        apparent_range = [None, None]
        for specifier in specifier_set:
            if specifier.operator in (">", ">=", "~="):
                apparent_range[0] = SemanticVersion(specifier.version)
            elif specifier.operator in ("<", "<="):
                apparent_range[1] = SemanticVersion(specifier.version)
            else:
                continue
        if (
            apparent_range[0]
            and apparent_range[1]
            and apparent_range[0] > apparent_range[1]
        ):
            raise ValueError(
                f"Version range from specifier set {specifier_set} is 'flipped'. I.e.,"
                " the apparent lower bound is larger than the apparent upper bound."
            )

        return specifier_set

    def __contains__(self, version: "str") -> bool:
        """Check if the given version is in the range."""
        return version in self._specifier

    def __str__(self) -> str:
        """Return the string representation of the object."""
        return str(self._specifier)

    def __repr__(self) -> str:
        """Return the string representation of the object."""
        return f"<{self.__class__.__name__}({str(self)!r})>"

    @property
    def lower(self) -> SemanticVersion:
        """The lower bound of the range."""
        return self._lower

    @lower.setter
    def lower(self, value: "Union[SemanticVersion, str]") -> None:
        """Set the lower bound of the range."""
        if isinstance(value, str):
            value = SemanticVersion(value)

        if not isinstance(value, SemanticVersion):
            raise TypeError(
                f"lower must be of type {SemanticVersion.__name__} or str, not "
                f"{type(value).__name__}"
            )

        if value > self._upper:
            raise ValueError(
                f"lower ({value}) cannot be greater than upper ({self._upper})"
            )
        if value not in self and value != SemanticVersion("0"):
            raise ValueError(
                f"lower ({value}) is not in the range ({self}) and is not '0'"
            )

        self._lower = value

    @property
    def upper(self) -> SemanticVersion:
        """The upper bound of the range."""
        return self._upper

    @upper.setter
    def upper(self, value: "Union[SemanticVersion, str]") -> None:
        """Set the upper bound of the range."""
        if isinstance(value, str):
            value = SemanticVersion(value)

        if not isinstance(value, SemanticVersion):
            raise TypeError(
                f"upper must be of type {SemanticVersion.__name__} or str, not "
                f"{type(value).__name__}"
            )

        if value < self._lower:
            raise ValueError(
                f"upper ({value}) cannot be less than lower ({self._lower})"
            )
        if value not in self:
            raise ValueError(f"upper ({value}) is not in the range ({self})")

        self._upper = value

    @property
    def operators(self) -> tuple[str, ...]:
        """The operators used in the specifier."""
        return tuple(specifier.operator for specifier in self._specifier)

    def version_from_operator(self, operator: str) -> SemanticVersion:
        """Return the raw string version for the given operator."""
        for specifier in self._specifier:
            if specifier.operator == operator:
                return SemanticVersion(specifier.version)
        raise ValueError(
            f"Operator {operator} not found in specifier set {self._specifier}"
        )

    def _determine_lower(self) -> SemanticVersion:
        """Determine the lower version range limit based on the specifier."""

        def __next_version(version: SemanticVersion) -> SemanticVersion:
            """Return the next version of the given version."""
            if version.patch < int(self._arbritrary_upper_limit):
                return version.next_version("patch")
            if version.minor < int(self._arbritrary_upper_limit):
                return version.next_version("minor")
            if version.major >= int(self._arbritrary_upper_limit):
                raise ValueError(
                    f"Major version for {version} exceeds {self.__class__.__name__}'s "
                    "internal upper limit"
                )
            return version.next_version("major")

        if not self._specifier:
            return SemanticVersion("0")

        lower = None
        for specifier in self._specifier:
            if specifier.operator == ">=":
                lower = SemanticVersion(specifier.version)
                break
            if specifier.operator == "==":
                lower = SemanticVersion(specifier.version)
                break
            if specifier.operator == "~=":
                lower = SemanticVersion(specifier.version)
                break

            if specifier.operator == ">":
                next_version = __next_version(SemanticVersion(specifier.version))
                while next_version not in self and next_version <= SemanticVersion(
                    self._arbritrary_upper_limit
                ):
                    next_version = __next_version(next_version)

                lower = (
                    min(SemanticVersion(specifier.version).next_version("patch"), lower)
                    if lower and lower != SemanticVersion("0")
                    else SemanticVersion(specifier.version).next_version("patch")
                )
            elif specifier.operator in ("<", "<=", "!="):
                lower = lower or SemanticVersion("0")
            else:
                # The arbitrary operator (===) is not supported
                raise NotImplementedError(
                    f"Specifier operator {specifier.operator} not implemented"
                )
        if lower is None:
            raise ValueError(f"Could not determine lower bound for {self}")
        return lower

    def _determine_upper(self) -> SemanticVersion:
        """Determine the upper version range limit based on the specifier."""

        def __previous_version(version: SemanticVersion) -> SemanticVersion:
            """Return the previous version of the given version."""
            if version.patch > 0:
                return SemanticVersion(
                    major=version.major, minor=version.minor, patch=version.patch - 1
                )
            if version.minor > 0:
                return SemanticVersion(
                    major=version.major,
                    minor=version.minor - 1,
                    patch=self._arbritrary_upper_limit,
                )
            if version.major <= 0:
                raise ValueError(f"Cannot determine previous version for {version}")
            return SemanticVersion(
                major=version.major - 1,
                minor=self._arbritrary_upper_limit,
                patch=self._arbritrary_upper_limit,
            )

        if not self._specifier:
            # An arbitrary upper limit major version
            return SemanticVersion(self._arbritrary_upper_limit)

        upper = None
        for specifier in self._specifier:
            if specifier.operator == "<=":
                upper = SemanticVersion(specifier.version)
                break
            if specifier.operator == "==":
                upper = SemanticVersion(specifier.version)
                break

            if specifier.operator == "<":
                previous_version = __previous_version(
                    SemanticVersion(specifier.version)
                )
                while (
                    previous_version not in self
                    and previous_version != SemanticVersion("0")
                ):
                    previous_version = __previous_version(previous_version)
                upper = (
                    max(previous_version, upper)
                    if (
                        upper and upper != SemanticVersion(self._arbritrary_upper_limit)
                    )
                    else previous_version
                )
            elif specifier.operator in (">", ">=", "!=", "~="):
                upper = upper or SemanticVersion(self._arbritrary_upper_limit)
            else:
                # The arbitrary operator (===) is not supported
                raise NotImplementedError(
                    f"Specifier operator {specifier.operator} not implemented"
                )
        if upper is None:
            raise ValueError(f"Could not determine upper bound for {self}")
        return upper

    def __gt__(self, other: "Any") -> bool:
        """Greater than (`>`) rich comparison."""
        if isinstance(other, self.__class__):
            other_semver = SemanticVersion(other.upper)
        else:
            other_semver = SemanticVersion._validate_other_type(other)

        return self.upper > other_semver

    def __eq__(self, other: "Any") -> bool:
        """Equal to (`==`) rich comparison."""
        if isinstance(other, self.__class__):
            return self._specifier == other._specifier

        other_semver = SemanticVersion._validate_other_type(other)

        return other_semver in self

    def __ne__(self, other: "Any") -> bool:
        """Not equal to (`!=`) rich comparison."""
        return not self.__eq__(other)

    def __lt__(self, other: "Any") -> bool:
        """Less than (`<`) rich comparison."""
        if isinstance(other, self.__class__):
            other_semver = SemanticVersion(other.lower)
        else:
            other_semver = SemanticVersion._validate_other_type(other)

        return self.lower < other_semver

    def __ge__(self, other: "Any") -> bool:
        """Greater than or equal to (`>=`) rich comparison."""
        return not self.__lt__(other)

    def __le__(self, other: "Any") -> bool:
        """Less than or equal to (`<=`) rich comparison."""
        return self.__lt__(other) or self.__eq__(other)

    def __and__(self, other: "Any") -> "SemanticVersionRange":
        """Intersection (`&`) of two version ranges."""
        if isinstance(other, self.__class__):
            return self.__class__(str(self) + "," + str(other))
        if isinstance(other, SemanticVersion):
            return self.__class__(str(self) + "," + str(other))
        if isinstance(other, str):
            return self.__class__(str(self) + "," + other)
        raise NotImplementedError(
            f"Intersection between {self.__class__.__name__} and {type(other).__name__} "
            "not implemented"
        )

    def __iter__(self) -> "Iterator[SortableSpecifier]":
        """Iterate over the range, or rather, the underlying SpecifierSet."""
        return iter(
            SortableSpecifier(spec=str(_), prereleases=_.prereleases or None)
            for _ in self._specifier
        )


def update_file(
    filename: Path, sub_line: tuple[str, str], strip: "Optional[str]" = None
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
