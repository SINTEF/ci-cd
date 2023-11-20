"""Handle versions."""
# pylint: disable=too-many-lines
from __future__ import annotations

import logging
import operator
import re
from typing import TYPE_CHECKING, no_type_check

from packaging.markers import Marker, default_environment
from packaging.specifiers import InvalidSpecifier, Specifier, SpecifierSet
from packaging.version import VERSION_PATTERN, Version

from ci_cd.exceptions import InputError, InputParserError, UnableToResolve

if TYPE_CHECKING:  # pragma: no cover
    from typing import Any, Literal, Optional, Union

    from packaging.requirements import Requirement

    IgnoreEntry = dict[Literal["dependency-name", "versions", "update-types"], str]

    IgnoreRules = dict[Literal["versions", "update-types"], list[str]]
    IgnoreRulesCollection = dict[str, IgnoreRules]

    IgnoreVersions = list[dict[Literal["operator", "version"], str]]
    IgnoreUpdateTypes = dict[
        Literal["version-update"], list[Literal["major", "minor", "patch"]]
    ]


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

    _PYTHON_VERSION: "Optional[Version]" = None

    @no_type_check
    def __new__(
        cls,
        version: "Optional[Union[str, Version]]" = None,
        **kwargs: "Union[str, int]",
    ) -> "SemanticVersion":
        return super().__new__(
            cls, str(version) if version else cls._build_version(**kwargs)
        )

    def __init__(
        self,
        version: "Optional[Union[str, Version]]" = None,
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

            if isinstance(version, Version):
                self._PYTHON_VERSION = version
                version = ".".join(version.release)

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
            next_version = f"{self.major + 1}.0.0"
        elif version_part == "minor":
            next_version = f"{self.major}.{self.minor + 1}.0"
        else:
            next_version = f"{self.major}.{self.minor}.{self.patch + 1}"

        return self.__class__(next_version)

    def previous_version(
        self, version_part: str, max_filler: "Optional[Union[str, int]]" = 99
    ) -> "SemanticVersion":
        """Return the previous version for the specified version part.

        Parameters:
            version_part: The version part to decrement.
            max_filler: The maximum value for the version part to decrement.

        Returns:
            The previous version.

        Raises:
            ValueError: If the version part is not one of `major`, `minor`, or `patch`.

        """
        if version_part not in ("major", "minor", "patch"):
            raise ValueError(
                "version_part must be one of 'major', 'minor', or 'patch', not "
                f"{version_part!r}"
            )

        if max_filler is None:
            max_filler = 99
        elif isinstance(max_filler, str):
            max_filler = int(max_filler)

        if not isinstance(max_filler, int):
            raise TypeError("max_filler must be an integer, string or None")

        if version_part == "major":
            prev_version = f"{self.major - 1}.{max_filler}.{max_filler}"

        elif version_part == "minor":
            prev_version = (
                f"{self.major -1 }.{max_filler}.{max_filler}"
                if self.minor == 0
                else f"{self.major}.{self.minor - 1}.{max_filler}"
            )

        else:
            if self.patch == 0:
                prev_version = (
                    f"{self.major - 1}.{max_filler}.{max_filler}"
                    if self.minor == 0
                    else f"{self.major}.{self.minor - 1}.{max_filler}"
                )
            else:
                prev_version = f"{self.major}.{self.minor}.{self.patch - 1}"

        return self.__class__(prev_version)

    def shortened(self) -> str:
        """Return a shortened version of the version.

        The shortened version is the full version, but without the patch and/or minor
        version if they are `0`, and without the pre-release and build metadata parts.

        Returns:
            The shortened version.

        """
        if self.patch == 0:
            if self.minor == 0:
                return str(self.major)
            return f"{self.major}.{self.minor}"
        return f"{self.major}.{self.minor}.{self.patch}"


def parse_ignore_entries(entries: list[str], separator: str) -> "IgnoreRulesCollection":
    """Parser for the `--ignore` option.

    The `--ignore` option values are given as key/value-pairs in the form:
    `key=value...key=value`. Here `...` is the separator value supplied by
    `--ignore-separator`.

    Parameters:
        entries: The list of supplied `--ignore` options.
        separator: The supplied `--ignore-separator` value.

    Returns:
        A parsed mapping of dependencies to ignore rules.

    """
    ignore_entries: "IgnoreRulesCollection" = {}

    for entry in entries:
        pairs = entry.split(separator, maxsplit=2)
        for pair in pairs:
            if separator in pair:
                raise InputParserError(
                    "More than three key/value-pairs were given for an `--ignore` "
                    "option, while there are only three allowed key names. Input "
                    f"value: --ignore={entry!r}"
                )

        ignore_entry: "IgnoreEntry" = {}
        for pair in pairs:
            match = re.match(
                r"^(?P<key>dependency-name|versions|update-types)=(?P<value>.*)$",
                pair,
            )
            if match is None:
                raise InputParserError(
                    f"Could not parse ignore configuration: {pair!r} (part of the "
                    f"ignore option: {entry!r})"
                )
            if match.group("key") in ignore_entry:
                raise InputParserError(
                    "An ignore configuration can only be given once per option. The "
                    f"configuration key {match.group('key')!r} was found multiple "
                    f"times in the option {entry!r}"
                )

            ignore_entry[match.group("key")] = match.group("value").strip()  # type: ignore[index]  # pylint: disable=line-too-long

        if "dependency-name" not in ignore_entry:
            raise InputError(
                "Ignore option entry missing required 'dependency-name' "
                f"configuration. Ignore option entry: {entry}"
            )

        dependency_name: str = ignore_entry.pop("dependency-name", "")
        if dependency_name not in ignore_entries:
            ignore_entries[dependency_name] = {
                key: [value] for key, value in ignore_entry.items()  # type: ignore[misc]
            }
        else:
            for key, value in ignore_entry.items():
                ignore_entries[dependency_name][key].append(value)  # type: ignore[index]

    return ignore_entries


def parse_ignore_rules(
    rules: "IgnoreRules",
) -> "tuple[IgnoreVersions, IgnoreUpdateTypes]":
    """Parser for a specific set of ignore rules.

    Parameters:
        rules: A set of ignore rules for one or more packages.

    Returns:
        A tuple of the parsed 'versions' and 'update-types' entries as dictionaries.

    """
    if not rules:
        # Ignore package altogether
        return [{"operator": ">=", "version": "0"}], {}

    versions: "IgnoreVersions" = []
    update_types: "IgnoreUpdateTypes" = {}

    if "versions" in rules:
        for versions_entry in rules["versions"]:
            match = re.match(
                r"^(?P<operator>>|<|<=|>=|==|!=|~=)\s*"
                r"(?P<version>[0-9]+(?:\.[0-9]+){0,2})$",
                versions_entry,
            )
            if match is None:
                raise InputParserError(
                    "Ignore option's 'versions' value cannot be parsed. It "
                    "must be a single operator followed by a version number.\n"
                    f"Unparseable 'versions' value: {versions_entry!r}"
                )
            versions.append(match.groupdict())  # type: ignore[arg-type]

    if "update-types" in rules:
        update_types["version-update"] = []
        for update_type_entry in rules["update-types"]:
            match = re.match(
                r"^version-update:semver-(?P<semver_part>major|minor|patch)$",
                update_type_entry,
            )
            if match is None:
                raise InputParserError(
                    "Ignore option's 'update-types' value cannot be parsed."
                    " It must be either: 'version-update:semver-major', "
                    "'version-update:semver-minor' or "
                    "'version-update:semver-patch'.\nUnparseable 'update-types' "
                    f"value: {update_type_entry!r}"
                )
            update_types["version-update"].append(match.group("semver_part"))  # type: ignore[arg-type]  # pylint: disable=line-too-long

    return versions, update_types


def create_ignore_rules(specifier_set: SpecifierSet) -> "IgnoreRules":
    """Create ignore rules based on version specifier set.

    The only ignore rules needed are related to versions that should be explicitly
    avoided, i.e., the `!=` operator. All other specifiers should require an explicit
    ignore rule by the user, if no update should be suggested.
    """
    return {
        "versions": [
            f"=={specifier.version}"
            for specifier in specifier_set
            if specifier.operator == "!="
        ]
    }


def _ignore_version_rules_semver(
    latest: list[str], version_rules: "IgnoreVersions"
) -> bool:  # pragma: no cover
    """Determine whether to ignore package based on `versions` input.

    Explicitly parsing as a SemanticVersion, not expecting Python (pip)-specific
    version specification.

    NOTE: While this function is currently not used, it is intended to be kept for a
        future support of multiple frameworks (not just Python/pip).
    """
    semver_latest = SemanticVersion(".".join(latest))
    operators_mapping = {
        ">": operator.gt,
        "<": operator.lt,
        "<=": operator.le,
        ">=": operator.ge,
        "==": operator.eq,
        "!=": operator.ne,
    }

    decision_version_rules = []
    for version_rule in version_rules:
        decision_version_rule = False
        semver_version_rule = SemanticVersion(version_rule["version"])

        if version_rule["operator"] in operators_mapping:
            if operators_mapping[version_rule["operator"]](
                semver_latest, semver_version_rule
            ):
                decision_version_rule = True
        elif "~=" == version_rule["operator"]:
            # The '~=' operator is a special case, as it's not a direct comparison
            # operator, but rather a range operator. The '~=' operator is used to
            # specify a minimum version, but with some flexibility in the last part.
            # E.g., '~=2.0' is equivalent to '>=2.0.0, <2.1.0' or '>=2.0, <2.1' or
            # '>=2.0, ==2.*'.
            # Furthermore, ~=X is not allowed. A minor version MUST be specified.

            if "." not in version_rule["version"]:
                raise InputError(
                    "Ignore option value error. For the 'versions' config key, when "
                    "using the '~=' operator more than a single version part MUST be "
                    "specified. E.g., '~=2' is disallowed, instead use '~=2.0' or "
                    "similar."
                )

            upper_limit = (
                "major" if version_rule["version"].count(".") == 1 else "minor"
            )

            if (
                semver_version_rule
                <= semver_latest
                < semver_version_rule.next_version(upper_limit)
            ):
                decision_version_rule = True
        else:
            raise InputParserError(
                "Ignore option value error. The 'versions' config key only "
                "supports the following operators: '>', '<', '<=', '>=', '==', "
                "'!=', '~='.\n"
                f"Unparseable 'versions' value: {version_rule!r}"
            )

        decision_version_rules.append(decision_version_rule)

    # If ALL version rules AND'ed together are True, ignore the version.
    return bool(decision_version_rules and all(decision_version_rules))


def _ignore_version_rules_specifier_set(
    latest: list[str], version_rules: "IgnoreVersions"
) -> bool:
    """Determine whether to ignore package based on `versions` input.

    Use Python (pip)-specific version specification.
    """
    if not version_rules:
        return False

    try:
        specifier_set = SpecifierSet(
            ",".join(f"{_['operator']}{_['version']}" for _ in version_rules)
        )
    except InvalidSpecifier as exc:
        raise InputError("Invalid version specifier") from exc
    return SemanticVersion(".".join(latest)) in specifier_set


def _ignore_semver_rules(
    current: list[str],
    latest: list[str],
    semver_rules: "IgnoreUpdateTypes",
) -> bool:
    """If ANY of the semver rules are True, ignore the version."""
    if any(
        _ not in ["major", "minor", "patch"] for _ in semver_rules["version-update"]
    ):
        raise InputParserError(
            f"Only valid values for 'version-update' are 'major', 'minor', and "
            f"'patch' (you gave {semver_rules['version-update']!r})."
        )

    if "major" in semver_rules["version-update"]:
        if latest[0] != current[0]:
            return True

    elif "minor" in semver_rules["version-update"]:
        if (
            len(latest) >= 2
            and len(current) >= 2
            and latest[1] > current[1]
            and latest[0] == current[0]
        ):
            return True

    elif "patch" in semver_rules["version-update"]:
        if (
            len(latest) >= 3
            and len(current) >= 3
            and latest[2] > current[2]
            and latest[0] == current[0]
            and latest[1] == current[1]
        ):
            return True

    return False


def ignore_version(
    current: list[str],
    latest: list[str],
    version_rules: "IgnoreVersions",
    semver_rules: "IgnoreUpdateTypes",
) -> bool:
    """Determine whether the latest version can be ignored.

    Parameters:
        current: The current version as a list of version parts. It's expected, but not
            required, the version is a semantic version.
        latest: The latest version as a list of version parts. It's expected, but not
            required, the version is a semantic version.
        version_rules: Version ignore rules.
        semver_rules: Semantic version ignore rules.

    Returns:
        Whether or not the latest version can be ignored based on the version and
        semantic version ignore rules.

    """
    # ignore all updates
    if not version_rules and not semver_rules:
        # A package name has been specified without specific rules, ignore all updates
        # for package.
        return True

    # version rules
    if _ignore_version_rules_specifier_set(latest, version_rules):
        return True

    # semver rules
    if "version-update" in semver_rules and _ignore_semver_rules(
        current, latest, semver_rules
    ):
        return True

    return False


def regenerate_requirement(
    requirement: "Requirement",
    *,
    name: "Optional[str]" = None,
    extras: "Optional[set[str]]" = None,
    specifier: "Optional[Union[SpecifierSet, str]]" = None,
    url: "Optional[str]" = None,
    marker: "Optional[Union[Marker, str]]" = None,
    post_name_space: bool = False,
) -> str:
    """Regenerate a requirement string including the given parameters.

    Parameters:
        requirement: The requirement to regenerate and fallback to.
        name: A new name to use for the requirement.
        extras: New extras to use for the requirement.
        specifier: A new specifier set to use for the requirement.
        url: A new URL to use for the requirement.
        marker: A new marker to use for the requirement.
        post_name_space: Whether or not to add a single space after the name (possibly
            including extras), but before the specifier.

    Returns:
        The regenerated requirement string.

    """
    updated_dependency = name or requirement.name

    if extras or requirement.extras:
        formatted_extras = ",".join(sorted(extras or requirement.extras))
        updated_dependency += f"[{formatted_extras}]"

    if post_name_space:
        updated_dependency += " "

    if specifier or requirement.specifier:
        if specifier and not isinstance(specifier, SpecifierSet):
            specifier = SpecifierSet(specifier)
        updated_dependency += ",".join(
            str(_)
            for _ in sorted(
                specifier or requirement.specifier,
                key=lambda spec: spec.operator,  # type: ignore[attr-defined]
                reverse=True,
            )
        )

    if url or requirement.url:
        updated_dependency += f"@ {url or requirement.url}"
        if marker or requirement.marker:
            updated_dependency += " "

    if marker or requirement.marker:
        updated_dependency += f"; {marker or requirement.marker}"

    return updated_dependency


def update_specifier_set(  # pylint: disable=too-many-statements
    latest_version: "Union[SemanticVersion, str]", current_specifier_set: SpecifierSet
) -> SpecifierSet:
    """Update the specifier set to include the latest version."""
    logger = logging.getLogger(__name__)

    epoch = 0

    if isinstance(latest_version, str):
        match = re.search(rf"(?ix){VERSION_PATTERN}", latest_version)
        if match is None:
            try:
                latest_version = SemanticVersion(latest_version)
            except ValueError as exc:
                raise UnableToResolve(
                    "Invalid version string given for latest version: "
                    f"{latest_version!r}"
                ) from exc
        else:
            # Only use `release` part, but store `epoch` if given
            epoch = match.group("epoch")
            if epoch:
                epoch = int(epoch)

            release = match.group("release")
            if not release or not isinstance(release, str):
                raise UnableToResolve(
                    "Invalid version string given for latest version: "
                    f"{latest_version!r}"
                )

            latest_version = SemanticVersion(release)

    if not isinstance(latest_version, SemanticVersion):
        raise TypeError(
            "latest_version must be a SemanticVersion or a string, got: type "
            f"{type(latest_version)}"
        )

    new_specifier_set = set(current_specifier_set)
    updated_specifiers = []
    split_latest_version = latest_version.split(".")

    logger.debug(
        "Received latest version: %s and current specifier set: %s",
        latest_version,
        current_specifier_set,
    )

    if latest_version in current_specifier_set:
        # The latest version is already included in the specifier set.
        # Update specifier set if the latest version is included via a `~=` or a `==`
        # operator.
        for specifier in current_specifier_set:
            if specifier.operator in ["~=", "=="]:
                split_specifier_version = specifier.version.split(".")
                updated_version = ".".join(
                    split_latest_version[: len(split_specifier_version)]
                )
                updated_specifiers.append(f"{specifier.operator}{updated_version}")
                new_specifier_set.remove(specifier)
                break
        else:
            # The latest version is already included in the specifier set, and the set
            # does not need updating. To communicate this, make updated_specifiers
            # non-empty, but include only an empty string.
            updated_specifiers.append("")
    else:
        # The latest version is *not* included in the specifier set.
        # Expect the latest version to be greater than the current version range.
        for specifier in current_specifier_set:
            # Simply expand the range if the version range is capped through a specifier
            # using either of the `<` or `<=` operators.
            if specifier.operator == "<=":
                split_specifier_version = specifier.version.split(".")
                updated_version = ".".join(
                    split_latest_version[: len(split_specifier_version)]
                )

                if epoch > 0:
                    updated_version = f"{epoch}!{updated_version}"

                updated_specifiers.append(f"{specifier.operator}{updated_version}")
                new_specifier_set.remove(specifier)
                break

            if specifier.operator == "<":
                # Update to include latest version by upping to the next
                # version up from the latest version
                split_specifier_version = specifier.version.split(".")

                # Up only the last version segment of the latest version according to
                # what version segments are defined in the specifier version.
                if len(split_specifier_version) == 1:
                    updated_version = str(latest_version.next_version("major").major)
                elif len(split_specifier_version) == 2:
                    updated_version = ".".join(
                        latest_version.next_version("minor").split(".")[:2]
                    )
                elif len(split_specifier_version) == 3:
                    updated_version = latest_version.next_version("patch")
                else:
                    raise UnableToResolve(
                        "Invalid/unable to handle number of version parts: "
                        f"{len(split_specifier_version)}"
                    )

                if epoch > 0:
                    updated_version = f"{epoch}!{updated_version}"

                updated_specifiers.append(f"{specifier.operator}{updated_version}")
                new_specifier_set.remove(specifier)
                break

            if specifier.operator == "~=":
                # Expand and change ~= to >= and < operators if the latest version
                # changes major version. Otherwise, update to include latest version as
                # the minimum version
                current_version = SemanticVersion(specifier.version)

                if latest_version.major > current_version.major:
                    # Expand and change ~= to >= and < operators

                    # >= current_version (fully padded)
                    updated_specifiers.append(f">={current_version}")

                    # < next major version up from latest_version
                    updated_specifiers.append(
                        f"<{str(latest_version.next_version('major').major)}"
                    )
                else:
                    # Keep the ~= operator, but update to include the latest version as
                    # the minimum version
                    split_specifier_version = specifier.version.split(".")
                    updated_version = ".".join(
                        split_latest_version[: len(split_specifier_version)]
                    )
                    updated_specifiers.append(f"{specifier.operator}{updated_version}")

                new_specifier_set.remove(specifier)
                break

    # Finally, add updated specifier(s) to new specifier set or raise.
    if updated_specifiers:
        # If updated_specifiers includes only an empty string, it means that the
        # current specifier set is valid as is and already includes the latest version
        if updated_specifiers != [""]:
            # Otherwise, add updated specifier(s) to new specifier set
            new_specifier_set |= set(Specifier(_) for _ in updated_specifiers)
    else:
        raise UnableToResolve(
            "Cannot resolve how to update specifier set to include latest version."
        )

    return SpecifierSet(",".join(str(_) for _ in new_specifier_set))


def _semi_valid_python_version(version: SemanticVersion) -> bool:
    """Check if a version is a valid Python version.

    This check is only semi-valid, since it only checks that each individual
    version part is valid within any range of the others.
    E.g., 3.6.15 is valid, but 3.6.18 is not, since 18 is not a valid patch version
    for Python 3.6, however, it is a valid patch version for Python 3.8.

    The major version is a hard requirement, so if it's not valid, then an exception
    is raised.

    """
    if version.major not in range(1, 3 + 1):
        # Not a valid Python major version (1, 2, or 3)
        raise ValueError(
            f"Invalid Python major version: {version.major}. Expected 1, 2, or 3."
        )

    if version.minor not in range(0, 12 + 1) or version.patch not in range(0, 18 + 1):
        # Either:
        #   Not a valid Python minor version (0, 1, 2, ..., 12)
        #   Not a valid Python patch version (0, 1, 2, ..., 18)
        return False
    return True


def get_min_max_py_version(  # pylint: disable=too-many-branches,too-many-statements
    requires_python: "Union[str, Marker]",
) -> str:
    """Get minimum or maximum Python version from `requires_python`.

    This also works for parsing requirement markers specifying validity for a specific
    `python_version`.

    _A minimum version will be preferred._

    This means all the minimum operators will be checked first, and if none of them
    match, then all the maximum operators will be checked.
    See below to understand which operators are minimum and which are maximum.

    Note:
        The first operator to match will be used, so if a minimum operator matches,
        then the maximum operators will not be checked.

    Whether it will minimum or maximum will depend on the operator:
    Minimum: `>=`, `==`, `~=`, `>`
    Maximum: `<=`, `<`

    Returns:
        The minimum or maximum Python version.
        E.g., if `requires_python` is `">=3.6"`, then `"3.6"` (min) will be returned,
        and if `requires_python` is `Marker("python_version < '3.6'")`, then `"3.5.99"`
        (max) will be returned.

    """
    if isinstance(requires_python, Marker):
        match = re.search(
            r"python_version\s*"
            r"(?P<operator>==|!=|<=|>=|<|>|~=)\s*"
            r"('|\")(?P<version>[0-9]+(?:\.[0-9]+)*)('|\")",
            str(requires_python),
        )

        if match is None:
            raise UnableToResolve("Could not retrieve 'python_version' marker.")

        requires_python = f"{match.group('operator')}{match.group('version')}"

    try:
        specifier_set = SpecifierSet(requires_python)
    except InvalidSpecifier as exc:
        raise UnableToResolve(
            "Cannot parse 'requires_python' as a specifier set."
        ) from exc

    py_version = ""
    min_or_max = "min"

    length_to_part_mapping = {
        1: "major",
        2: "minor",
        3: "patch",
    }

    # Minimum
    for specifier in specifier_set:
        if specifier.operator in [">=", "==", "~="]:
            py_version = specifier.version
            break

        if specifier.operator == ">":
            split_version = specifier.version.split(".")
            parsed_version = SemanticVersion(specifier.version)

            if len(split_version) == 1:
                py_version = str(parsed_version.next_version("major").major)
            elif len(split_version) == 2:
                py_version = ".".join(
                    parsed_version.next_version("minor").split(".")[:2]
                )
            elif len(split_version) == 3:
                py_version = str(parsed_version.next_version("patch"))

            break
    else:
        # Maximum
        min_or_max = "max"

        for specifier in specifier_set:
            if specifier.operator == "<=":
                py_version = specifier.version
                break

            if specifier.operator == "<":
                split_version = specifier.version.split(".")
                parsed_version = SemanticVersion(specifier.version)

                if parsed_version == SemanticVersion("0"):
                    raise UnableToResolve(
                        f"{specifier} is not a valid Python version specifier."
                    )

                if len(split_version) not in length_to_part_mapping:
                    raise UnableToResolve(
                        f"{specifier} is not a valid Python version specifier. It was "
                        "expected to be a major, minor, or patch version specifier."
                    )

                # Fill with 0's and shorten. This is an attempt to return a full range
                # of previous versions.
                py_version = str(
                    parsed_version.previous_version(
                        length_to_part_mapping[len(split_version)],
                        max_filler=0,
                    ).shortened()
                )

                break
        else:
            raise UnableToResolve(
                "Cannot determine min/max Python version from version specifier(s): "
                f"{specifier_set}"
            )

    if py_version not in specifier_set:
        split_py_version = py_version.split(".")
        parsed_py_version = SemanticVersion(py_version)

        while (
            not _semi_valid_python_version(parsed_py_version)
            or py_version not in specifier_set
        ):
            if min_or_max == "min":
                if (  # Largest value for a Python version patch part
                    parsed_py_version.patch >= 18
                ):
                    parsed_py_version = parsed_py_version.next_version("minor")
                elif (  # Largest value for a Python version minor part
                    parsed_py_version.minor >= 12
                ):
                    parsed_py_version = parsed_py_version.next_version("major")
                else:
                    parsed_py_version = parsed_py_version.next_version("patch")
            else:
                parsed_py_version = parsed_py_version.previous_version(
                    length_to_part_mapping[len(split_py_version)],
                    # Largest value for any part of a Python version (patch)
                    max_filler=18,
                )

            py_version = parsed_py_version.shortened()
            split_py_version = py_version.split(".")

    return py_version


def find_minimum_py_version(marker: "Marker", project_py_version: str) -> str:
    """Find the minimum Python version from a marker."""
    split_py_version = project_py_version.split(".")

    def _next_version(_version: SemanticVersion) -> SemanticVersion:
        if len(split_py_version) == 1:
            return _version.next_version("major")
        if len(split_py_version) == 2:
            return _version.next_version("minor")
        return _version.next_version("patch")

    min_py_version = SemanticVersion(project_py_version)

    environment_keys = default_environment().keys()
    empty_environment = {key: "" for key in environment_keys}
    python_version_centric_environment = empty_environment
    python_version_centric_environment.update({"python_version": min_py_version})

    while not _semi_valid_python_version(min_py_version) or not marker.evaluate(
        environment=python_version_centric_environment
    ):
        min_py_version = _next_version(min_py_version)
        python_version_centric_environment.update({"python_version": min_py_version})

    return min_py_version.shortened()
