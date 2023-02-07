"""`update_deps` task.

Update dependencies in a `pyproject.toml` file.
"""
# pylint: disable=duplicate-code
import logging
import operator
import re
import sys
from collections import namedtuple
from pathlib import Path
from typing import TYPE_CHECKING

import tomlkit
from invoke import task

from ci_cd.exceptions import CICDException, InputError, InputParserError
from ci_cd.utils import update_file

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

    VersionSpec = namedtuple(
        "VersionSpec",
        [
            "full_dependency",
            "package",
            "url_version",
            "operator",
            "version",
            "extra_operator_version",
            "environment_marker",
        ],
    )

    try:
        ignore_rules = parse_ignore_entries(ignore, ignore_separator)
    except InputError as exc:
        sys.exit(f"Error: Could not parse ignore options.\nException: {exc}")
    LOGGER.debug("Parsed ignore rules: %s", ignore_rules)

    if pre_commit and root_repo_path == ".":
        # Use git to determine repo root
        result: "Result" = context.run("git rev-parse --show-toplevel", hide=True)
        root_repo_path = result.stdout.strip("\n")

    pyproject_path = Path(root_repo_path).resolve() / "pyproject.toml"
    if not pyproject_path.exists():
        sys.exit(
            "Error: Could not find the Python package repository's 'pyproject.toml' "
            f"file at: {pyproject_path}"
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
    dependencies = pyproject.get("project", {}).get("dependencies", [])
    for optional_deps in (
        pyproject.get("project", {}).get("optional-dependencies", {}).values()
    ):
        dependencies.extend(optional_deps)

    error = False
    for line in dependencies:
        match = re.match(
            r"^(?P<full_dependency>(?P<package>[a-zA-Z0-9_.-]+)(?:\s*\[.*\])?)\s*"
            r"(?:"
            r"(?P<url_version>@\s*\S+)|"
            r"(?P<operator>>|<|<=|>=|==|!=|~=)\s*"
            r"(?P<version>[0-9]+(?:\.[0-9]+){0,2})"
            r")?\s*"
            r"(?P<extra_operator_version>(?:,(?:>|<|<=|>=|==|!=|~=)\s*"
            r"[0-9]+(?:\.[0-9]+){0,2}\s*)+)*"
            r"(?P<environment_marker>;.+)*$",
            line,
        )
        if match is None:
            msg = (
                f"Could not parse package and version specification for line:\n  {line}"
            )
            LOGGER.warning(msg)
            if fail_fast:
                sys.exit(msg)
            print(msg)
            error = True
            continue

        version_spec = VersionSpec(**match.groupdict())
        LOGGER.debug("version_spec: %s", version_spec)

        # Skip package if already handled
        if version_spec.package in already_handled_packages:
            continue

        # Skip URL versioned dependencies
        if version_spec.url_version:
            msg = (
                f"Dependency {version_spec.full_dependency!r} is pinned to a URL and "
                "will be skipped."
            )
            LOGGER.info(msg)
            print(msg)
            continue

        # Skip and warn if package is not version-restricted
        if not version_spec.operator and not version_spec.url_version:
            msg = (
                f"Dependency {version_spec.full_dependency!r} is not version "
                "restricted and will be skipped. Consider adding version restrictions."
            )
            LOGGER.warning(msg)
            print(msg)
            continue

        # Check version from PyPI's online package index
        out: "Result" = context.run(
            f"pip index versions --python-version {py_version} {version_spec.package}",
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
                sys.exit(msg)
            print(msg)
            already_handled_packages.add(version_spec.package)
            error = True
            continue

        # Sanity check
        if version_spec.package != match.group("package"):
            msg = (
                f"Package name parsed from pyproject.toml ({version_spec.package!r}) "
                "does not match the name returned from 'pip index versions': "
                f"{match.group('package')!r}"
            )
            LOGGER.warning(msg)
            if fail_fast:
                sys.exit(msg)
            print(msg)
            already_handled_packages.add(version_spec.package)
            error = True
            continue

        # Check whether pyproject.toml already uses the latest version
        latest_version = match.group("version").split(".")
        for index, version_part in enumerate(version_spec.version.split(".")):
            if version_part != latest_version[index]:
                break
        else:
            already_handled_packages.add(version_spec.package)
            continue

        # Apply ignore rules
        if version_spec.package in ignore_rules or "*" in ignore_rules:
            versions: "list[dict[Literal['operator', 'version'], str]]" = []
            update_types: "dict[Literal['version-update'], list[Literal['major', 'minor', 'patch']]]" = (  # pylint: disable=line-too-long
                {}
            )

            if "*" in ignore_rules:
                versions, update_types = parse_ignore_rules(ignore_rules["*"])

            if version_spec.package in ignore_rules:
                parsed_rules = parse_ignore_rules(ignore_rules[version_spec.package])

                versions.extend(parsed_rules[0])
                update_types.update(parsed_rules[1])

            if ignore_version(
                current=version_spec.version.split("."),
                latest=latest_version,
                version_rules=versions,
                semver_rules=update_types,
            ):
                already_handled_packages.add(version_spec.package)
                continue

        if not error:
            # Update pyproject.toml
            updated_version = ".".join(
                latest_version[: len(version_spec.version.split("."))]
            )
            escaped_full_dependency_name = version_spec.full_dependency.replace(
                "[", r"\["
            ).replace("]", r"\]")
            update_file(
                pyproject_path,
                (
                    rf'"{escaped_full_dependency_name} {version_spec.operator}.*"',
                    f'"{version_spec.full_dependency} '
                    f"{version_spec.operator}{updated_version}"
                    f'{version_spec.extra_operator_version if version_spec.extra_operator_version else ""}'  # pylint: disable=line-too-long
                    f'{version_spec.environment_marker if version_spec.environment_marker else ""}"',  # pylint: disable=line-too-long
                ),
            )
            already_handled_packages.add(version_spec.package)
            updated_packages[
                version_spec.full_dependency
            ] = f"{version_spec.operator}{updated_version}"

    if error:
        sys.exit("Errors occurred! See printed statements above.")

    if updated_packages:
        print(
            "Successfully updated the following dependencies:\n"
            + "\n".join(
                f"  {package} ({version}"
                f"{version_spec.extra_operator_version if version_spec.extra_operator_version else ''}"  # pylint: disable=line-too-long
                f"{' ' + version_spec.environment_marker if version_spec.environment_marker else ''})"  # pylint: disable=line-too-long
                for package, version in updated_packages.items()
            )
            + "\n"
        )
    else:
        print("No dependency updates available.")


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
        split_version_rule = version_rule.get("version", "").split(".")

        if version_rule.get("operator", "") in operators_mapping:
            # Extend version rule with zeros if needed
            if len(split_version_rule) < len(latest):
                split_version_rule.extend(
                    ["0"] * (len(latest) - len(split_version_rule))
                )
            if len(split_version_rule) != len(latest):
                raise CICDException("Zero-filling failed for version.")

            any_all_logic = (
                all
                if "=" in version_rule["operator"] and version_rule["operator"] != "!="
                else any
            )
            if any_all_logic(
                operators_mapping[version_rule["operator"]](
                    latest_part, version_rule_part
                )
                for latest_part, version_rule_part in zip(latest, split_version_rule)
            ):
                decision_version_rule = True
        elif "~=" == version_rule.get("operator", ""):
            if len(split_version_rule) == 1:
                raise InputError(
                    "Ignore option value error. For the 'versions' config key, when "
                    "using the '~=' operator more than a single version part MUST be "
                    "specified. E.g., '~=2' is disallowed, instead use '~=2.0' or "
                    "similar."
                )

            if all(
                latest_part >= version_rule_part
                for latest_part, version_rule_part in zip(latest, split_version_rule)
            ) and all(
                latest_part == version_rule_part
                for latest_part, version_rule_part in zip(
                    latest[:-1], split_version_rule[:-1]
                )
            ):
                decision_version_rule = True
        elif version_rule.get("operator", ""):
            # Should not be possible to reach if using `parse_ignore_rules()`
            # But for completion, and understanding, this is still kept.
            raise InputParserError(
                "Unknown ignore options 'versions' config value operator: "
                f"{version_rule['operator']}"
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
    if _ignore_version_rules(latest, version_rules):
        return True

    # semver rules
    if "version-update" in semver_rules and _ignore_semver_rules(
        current, latest, semver_rules
    ):
        return True

    return False
