"""`update_deps` task.

Update dependencies in a `pyproject.toml` file.
"""
# pylint: disable=duplicate-code
from __future__ import annotations

import logging
import operator
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import tomlkit
from invoke import task
from pip._vendor.packaging.requirements import Requirement

from ci_cd.exceptions import CICDException, InputError, InputParserError
from ci_cd.utils import Emoji, SemanticVersion, SemanticVersionRange, update_file

if TYPE_CHECKING:  # pragma: no cover
    from typing import Literal

    from invoke import Context, Result


LOGGER = logging.getLogger(__file__)
LOGGER.setLevel(logging.DEBUG)


@task(
    help={
        "fail-fast": (
            "Fail immediately if an error occurs. Otherwise, print and ignore all "
            "non-critical errors."
        ),
        "root-repo-path": (
            "A resolvable path to the root directory of the repository folder."
        ),
        "pre-commit": "Whether or not this task is run as a pre-commit hook.",
        "ignore": (
            "Ignore-rules based on the `ignore` config option of Dependabot. It "
            "should be of the format: key=value...key=value, i.e., an ellipsis "
            "(`...`) separator and then equal-sign-separated key/value-pairs. "
            "Alternatively, the `--ignore-separator` can be set to something else to "
            "overwrite the ellipsis. The only supported keys are: `dependency-name`, "
            "`versions`, and `update-types`. Can be supplied multiple times per "
            "`dependency-name`."
        ),
        "ignore-separator": (
            "Value to use instead of ellipsis (`...`) as a separator in `--ignore` "
            "key/value-pairs."
        ),
    },
    iterable=["ignore"],
)
def update_deps(  # pylint: disable=too-many-branches,too-many-locals,too-many-statements
    context,
    root_repo_path=".",
    fail_fast=False,
    pre_commit=False,
    ignore=None,
    ignore_separator="...",
):
    """Update dependencies in specified Python package's `pyproject.toml`."""
    if TYPE_CHECKING:  # pragma: no cover
        context: "Context" = context  # type: ignore[no-redef]
        root_repo_path: str = root_repo_path  # type: ignore[no-redef]
        fail_fast: bool = fail_fast  # type: ignore[no-redef]
        pre_commit: bool = pre_commit  # type: ignore[no-redef]
        ignore_separator: str = ignore_separator  # type: ignore[no-redef]

    if not ignore:
        ignore: list[str] = []  # type: ignore[no-redef]

    try:
        ignore_rules = parse_ignore_entries(ignore, ignore_separator)
    except InputError as exc:
        sys.exit(
            f"{Emoji.CROSS_MARK.value} Error: Could not parse ignore options.\n"
            f"Exception: {exc}"
        )
    LOGGER.debug("Parsed ignore rules: %s", ignore_rules)

    if pre_commit and root_repo_path == ".":
        # Use git to determine repo root
        result: "Result" = context.run("git rev-parse --show-toplevel", hide=True)
        root_repo_path = result.stdout.strip("\n")

    pyproject_path = Path(root_repo_path).resolve() / "pyproject.toml"
    if not pyproject_path.exists():
        sys.exit(
            f"{Emoji.CROSS_MARK.value} Error: Could not find the Python package "
            f"repository's 'pyproject.toml' file at: {pyproject_path}"
        )

    pyproject = tomlkit.loads(pyproject_path.read_bytes())

    match = re.match(
        r"^.*(?P<version>3\.[0-9]+)$",
        pyproject.get("project", {}).get("requires-python", ""),
    )
    if not match:
        raise CICDException(
            "No minimum Python version requirement given in pyproject.toml!"
        )
    py_version = match.group("version")

    already_handled_packages = set()
    updated_packages = {}
    dependencies: list[str] = pyproject.get("project", {}).get("dependencies", [])
    for optional_deps in (
        pyproject.get("project", {}).get("optional-dependencies", {}).values()
    ):
        dependencies.extend(optional_deps)

    error = False
    for dependency in dependencies:
        parsed_requirement = Requirement(dependency)
        LOGGER.debug("parsed_requirement: %r", parsed_requirement)

        # Skip package if already handled
        if parsed_requirement.name in already_handled_packages:
            continue

        # Skip URL versioned dependencies
        if parsed_requirement.url:
            msg = (
                f"Dependency {parsed_requirement.name!r} is pinned to a URL and "
                "will be skipped."
            )
            LOGGER.info(msg)
            print(msg, flush=True)
            already_handled_packages.add(parsed_requirement.name)
            continue

        # Skip and warn if package is not version-restricted
        if not parsed_requirement.specifier:
            msg = (
                f"Dependency {parsed_requirement.name!r} is not version "
                "restricted and will be skipped. Consider adding version restrictions."
            )
            LOGGER.warning(msg)
            print(msg, flush=True)
            already_handled_packages.add(parsed_requirement.name)
            continue

        # Check version from PyPI's online package index
        out: "Result" = context.run(
            f"pip index versions --python-version {py_version} {parsed_requirement.name}",
            hide=True,
        )
        package_latest_version_line = out.stdout.split(sep="\n", maxsplit=1)[0]
        match = re.match(
            r"(?P<package>[a-zA-Z0-9-_]+) \((?P<version>[0-9]+(?:\.[0-9]+){0,2})\)",
            package_latest_version_line,
        )
        if match is None:
            msg = (
                "Could not parse package and version from 'pip index versions' output "
                f"for line:\n  {package_latest_version_line}"
            )
            LOGGER.warning(msg)
            if fail_fast:
                sys.exit(f"{Emoji.CROSS_MARK.value} {msg}")
            print(msg, flush=True)
            already_handled_packages.add(parsed_requirement.name)
            error = True
            continue

        # Sanity check
        if parsed_requirement.name != match.group("package"):
            msg = (
                "Package name parsed from pyproject.toml "
                f"({parsed_requirement.name!r}) does not match the name returned from "
                f"'pip index versions': {match.group('package')!r}"
            )
            LOGGER.warning(msg)
            if fail_fast:
                sys.exit(f"{Emoji.CROSS_MARK.value} {msg}")
            print(msg, flush=True)
            already_handled_packages.add(parsed_requirement.name)
            error = True
            continue

        # Check whether pyproject.toml already uses the latest version
        try:
            current_version_range = SemanticVersionRange(parsed_requirement)
        except ValueError as exc:
            msg = (
                f"Could not parse version range specifier set for package "
                f"{parsed_requirement.name!r} from pyproject.toml: {exc}"
            )
            LOGGER.warning(msg)
            if fail_fast:
                sys.exit(f"{Emoji.CROSS_MARK.value} {msg}")
            print(msg, flush=True)
            already_handled_packages.add(parsed_requirement.name)
            error = True
            continue

        latest_version = match.group("version")
        if latest_version in current_version_range:
            if ">=" in current_version_range.operators:
                # Not updating version, since minimum version is already satisfied
                already_handled_packages.add(parsed_requirement.name)
                continue
            if "~=" in current_version_range.operators:
                # Maybe update version, since the ~= specifier is used
                # NOTE: This may be wrong if there are multiple ~= specifiers,
                # expecting only one, though
                version = current_version_range.version_from_operator("~=")
                for index, version_part in enumerate(version.split(".")):
                    if version_part != latest_version.split(".")[index]:
                        break
                else:
                    # Not updating version, since the minimum version range matches the
                    # latest version
                    already_handled_packages.add(parsed_requirement.name)
                    continue

        # Apply ignore rules
        if parsed_requirement.name in ignore_rules or "*" in ignore_rules:
            versions: "list[dict[Literal['operator', 'version'], str]]" = []
            update_types: "dict[Literal['version-update'], list[Literal['major', 'minor', 'patch']]]" = (  # pylint: disable=line-too-long
                {}
            )

            if "*" in ignore_rules:
                versions, update_types = parse_ignore_rules(ignore_rules["*"])

            if parsed_requirement.name in ignore_rules:
                parsed_rules = parse_ignore_rules(ignore_rules[parsed_requirement.name])

                versions.extend(parsed_rules[0])
                update_types.update(parsed_rules[1])

            LOGGER.debug(
                "Ignore rules:\nversions: %s\nupdate_types: %s", versions, update_types
            )

            if ignore_version(
                # Cast to str() to ensure a split on a padded version
                current=str(current_version_range.lower).split("."),
                latest=latest_version.split("."),
                version_rules=versions,
                semver_rules=update_types,
            ):
                already_handled_packages.add(parsed_requirement.name)
                continue

        # Update specifiers
        updated_version_range = None
        if latest_version > current_version_range:
            spec_operator = "<="
            if spec_operator in current_version_range.operators:
                # Update to include latest version
                n_version_parts = current_version_range.version_from_operator(
                    spec_operator
                ).number_of_original_core_version_parts
                updated_specifier_version = ".".join(
                    latest_version.split(".")[:n_version_parts]
                )
                updated_specifier = f"{spec_operator}{updated_specifier_version}"
                updated_specifier_set = [
                    str(_) for _ in current_version_range if _.operator != spec_operator
                ]
                updated_specifier_set.append(updated_specifier)
                updated_version_range = SemanticVersionRange(
                    ",".join(updated_specifier_set)
                )
            else:
                spec_operator = "~="
                if spec_operator in current_version_range.operators:
                    # Expand and change ~= to >= and < operators if the latest version
                    # changes major version.
                    # Otherwise, update to include latest version as the minimum version
                    current_version = current_version_range.version_from_operator(
                        spec_operator
                    )
                    parsed_latest_version = SemanticVersion(latest_version)

                    if parsed_latest_version.major > current_version.major:
                        # Expand and change ~= to >= and < operators
                        # >= current_version
                        specifier_set_updates = [f">={current_version}"]
                        # < next major version up from latest_version
                        specifier_set_updates.append(
                            f"<{str(parsed_latest_version.next_version('major').major)}"
                        )
                    else:
                        # Keep the ~= operator, but update to include the latest
                        # version as the minimum version
                        updated_specifier_version = ".".join(
                            latest_version.split(".")[
                                : current_version.number_of_original_core_version_parts
                            ]
                        )
                        specifier_set_updates = [
                            f"{spec_operator}{updated_specifier_version}"
                        ]

                    updated_specifier_set = [
                        str(_)
                        for _ in current_version_range
                        if _.operator != spec_operator
                    ]
                    updated_specifier_set.extend(specifier_set_updates)
                    updated_version_range = SemanticVersionRange(
                        ",".join(updated_specifier_set)
                    )
                else:
                    spec_operator = "<"
                    if spec_operator in current_version_range.operators:
                        # Update to include latest version by upping to the next
                        # version up from the latest version
                        n_version_parts = current_version_range.version_from_operator(
                            spec_operator
                        ).number_of_original_core_version_parts
                        parsed_latest_version = SemanticVersion(latest_version)
                        if n_version_parts == 1:
                            updated_specifier_version = str(
                                parsed_latest_version.next_version("major").major
                            )
                        elif n_version_parts == 2:
                            updated_specifier_version = ".".join(
                                parsed_latest_version.next_version("minor").split(".")[
                                    :2
                                ]
                            )
                        elif n_version_parts == 3:
                            updated_specifier_version = (
                                parsed_latest_version.next_version("patch")
                            )
                        else:
                            raise CICDException(
                                f"Invalid number of version parts: {n_version_parts}"
                            )
                        updated_specifier = (
                            f"{spec_operator}{updated_specifier_version}"
                        )
                        updated_specifier_set = [
                            str(_)
                            for _ in current_version_range
                            if _.operator != spec_operator
                        ]
                        updated_specifier_set.append(updated_specifier)
                        updated_version_range = SemanticVersionRange(
                            ",".join(updated_specifier_set)
                        )
        elif latest_version in current_version_range:
            for spec_operator in ["~=", "=="]:
                if spec_operator in current_version_range.operators:
                    n_version_parts = current_version_range.version_from_operator(
                        spec_operator
                    ).number_of_original_core_version_parts
                    updated_version = ".".join(
                        latest_version.split(".")[:n_version_parts]
                    )
                    updated_specifier = f"{spec_operator}{updated_version}"
                    updated_specifier_set = [
                        str(_)
                        for _ in current_version_range
                        if _.operator != spec_operator
                    ]
                    updated_specifier_set.append(updated_specifier)
                    updated_version_range = SemanticVersionRange(
                        ",".join(updated_specifier_set)
                    )
                    break
        else:
            msg = (
                "Could not determine how to update to the latest version using the "
                f"version range specifier set: {current_version_range}. "
                f"Package: {parsed_requirement.name}. Latest version: {latest_version}"
            )
            LOGGER.warning(msg)
            if fail_fast:
                sys.exit(f"{Emoji.CROSS_MARK.value} {msg}")
            print(msg, flush=True)
            already_handled_packages.add(parsed_requirement.name)
            error = True
            continue

        LOGGER.debug("updated_version_range: %s", updated_version_range)
        if updated_version_range is None:
            msg = (
                "Could not determine how to update to the latest version using the "
                f"version range specifier set: {current_version_range}. "
                f"Package: {parsed_requirement.name}. Latest version: {latest_version}"
            )
            LOGGER.warning(msg)
            if fail_fast:
                sys.exit(f"{Emoji.CROSS_MARK.value} {msg}")
            print(msg, flush=True)
            already_handled_packages.add(parsed_requirement.name)
            error = True
            continue

        if not error:
            # Update pyproject.toml
            updated_dependency = parsed_requirement.name
            if parsed_requirement.extras:
                formatted_extras = ",".join(sorted(parsed_requirement.extras))
                updated_dependency += f"[{formatted_extras}]"
            match = re.search(
                rf"{parsed_requirement.name}(?:\[.*\])?(?P<space>\s)+", dependency
            )
            if match:
                updated_dependency += match.group("space")
            updated_dependency += ",".join(
                str(_) for _ in sorted(updated_version_range)
            )  # Specifier set
            if parsed_requirement.marker:
                updated_dependency += f"; {parsed_requirement.marker}"

            update_file(pyproject_path, (re.escape(dependency), updated_dependency))
            already_handled_packages.add(parsed_requirement.name)
            updated_packages[parsed_requirement.name] = str(updated_version_range) + (
                f"; {parsed_requirement.marker}" if parsed_requirement.marker else ""
            )

    if error:
        sys.exit(
            f"{Emoji.CROSS_MARK.value} Errors occurred! See printed statements above."
        )

    if updated_packages:
        print(
            f"{Emoji.PARTY_POPPER.value} Successfully updated the following "
            "dependencies:\n"
            + "\n".join(
                f"  {package} ({version})"
                for package, version in updated_packages.items()
            )
            + "\n",
            flush=True,
        )
    else:
        print(f"{Emoji.CHECK_MARK.value} No dependency updates available.", flush=True)


def parse_ignore_entries(
    entries: list[str], separator: str
) -> 'dict[str, dict[Literal["versions", "update-types"], list[str]]]':
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
    ignore_entries: 'dict[str, dict[Literal["versions", "update-types"], list[str]]]' = (
        {}
    )

    for entry in entries:
        pairs = entry.split(separator, maxsplit=2)
        for pair in pairs:
            if separator in pair:
                raise InputParserError(
                    "More than three key/value-pairs were given for an `--ignore` "
                    "option, while there are only three allowed key names. Input "
                    f"value: --ignore={entry}"
                )

        ignore_entry: 'dict[Literal["dependency-name", "versions", "update-types"], str]' = (  # pylint: disable=line-too-long
            {}
        )
        for pair in pairs:
            match = re.match(
                r"^(?P<key>dependency-name|versions|update-types)=(?P<value>.*)$",
                pair,
            )
            if match is None:
                raise InputParserError(
                    f"Could not parse ignore configuration: {pair!r} (part of the "
                    f"ignore option: {entry!r}"
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
    rules: "dict[Literal['versions', 'update-types'], list[str]]",
) -> "tuple[list[dict[Literal['operator', 'version'], str]], dict[Literal['version-update'], list[Literal['major', 'minor', 'patch']]]]":  # pylint: disable=line-too-long
    """Parser for a specific set of ignore rules.

    Parameters:
        rules: A set of ignore rules for one or more packages.

    Returns:
        A tuple of the parsed 'versions' and 'update-types' entries as dictionaries.

    """
    if not rules:
        # Ignore package altogether
        return [{"operator": ">=", "version": "0"}], {}

    versions: 'list[dict[Literal["operator", "version"], str]]' = []
    update_types: "dict[Literal['version-update'], list[Literal['major', 'minor', 'patch']]]" = (  # pylint: disable=line-too-long
        {}
    )

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


def _ignore_version_rules(
    latest: list[str],
    version_rules: "list[dict[Literal['operator', 'version'], str]]",
) -> bool:
    """Determine whether to ignore package based on `versions` input."""
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


def _ignore_semver_rules(
    current: list[str],
    latest: list[str],
    semver_rules: "dict[Literal['version-update'], list[Literal['major', 'minor', 'patch']]]",  # pylint: disable=line-too-long
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
    version_rules: "list[dict[Literal['operator', 'version'], str]]",
    semver_rules: "dict[Literal['version-update'], list[Literal['major', 'minor', 'patch']]]",  # pylint: disable=line-too-long
) -> bool:
    """Determine whether the latest version can be ignored.

    Parameters:
        current: The current version as a list of version parts. It's expected, but not
            required, to be a semantic version.
        latest: The latest version as a list of version parts. It's expected, but not
            required, to be a semantic version.
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
    if _ignore_version_rules(latest, version_rules):
        return True

    # semver rules
    if "version-update" in semver_rules and _ignore_semver_rules(
        current, latest, semver_rules
    ):
        return True

    return False
