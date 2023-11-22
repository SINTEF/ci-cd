#!/usr/bin/env python3
"""Run pre-commit hooks on all files in the repository.

File used to test running the hooks in the CI/CD pipeline independently of the shell.
"""
from __future__ import annotations

import subprocess  # nosec
import sys

SUCCESSFUL_FAILURES_MAPPING = {
    "docs-api-reference": "The following files have been changed/added/removed:",
    "docs-landing-page": "The landing page has been updated.",
    "update-pyproject": "Successfully updated the following dependencies:",
    "set-version": "Bumped version for ci_cd to 0.0.0.",
}


def main(hook: str, options: list[str]) -> None:
    """Run pre-commit hooks on all files in the repository."""
    run_pre_commit = (
        "pre-commit run -c .github/utils/.pre-commit-config_testing.yaml "
        "--all-files --verbose"
    )

    result = subprocess.run(
        f"{run_pre_commit} {' '.join(_ for _ in options)} {hook}",
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,  # nosec
    )

    if result.returncode != 0:
        if SUCCESSFUL_FAILURES_MAPPING[hook] in result.stdout.decode():
            print(f"Successfully failed {hook} hook.\n\n", flush=True)
            print(result.stdout.decode(), flush=True)
        else:
            sys.exit(result.stdout.decode())
    print(f"Successfully ran {hook} hook.\n\n", flush=True)
    print(result.stdout.decode(), flush=True)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise sys.exit("Missing arguments")

    # "Parse" arguments
    # The first argument should be the hook name
    if sys.argv[1] not in SUCCESSFUL_FAILURES_MAPPING:
        raise sys.exit(
            f"Invalid hook name: {sys.argv[1]}\n"
            "The hook name should be the first argument. Any number of hook options "
            "can then follow."
        )

    try:
        main(
            hook=sys.argv[1],
            options=sys.argv[2:] if len(sys.argv) > 2 else [],
        )
    except Exception as exc:  # pylint: disable=broad-except
        sys.exit(str(exc))
