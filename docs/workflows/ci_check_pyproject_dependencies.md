# CI - Check pyproject.toml dependencies

**File to use:** `ci_check_pyproject_dependencies.yml`

This workflow runs an [Invoke](https://pyinvoke.org) task to check dependencies in a `pyproject.toml` file.

The reason for having this workflow and not using [Dependabot](https://github.com/dependabot/dependabot-core) is because it seems to not function properly with this use case.

!!! warning
    If a PAT is not passed through for the `PAT` secret and `GITHUB_TOKEN` is used, beware that any other CI/CD jobs that run for, e.g., pull request events, may not run since `GITHUB_TOKEN`-generated PRs are designed to not start more workflows to avoid escalation.
    Hence, if it is important to run CI/CD workflows for pull requests, consider passing a PAT as a secret to this workflow represented by the `PAT` secret.

## Ignoring dependencies

To ignore or configure how specific dependencies should be updated, the `ignore` input option can be utilized.
This is done by specifying a line per dependency that contains ellipsis-separated (`...`) key/value-pairs of:

| **Key** | **Description** |
|:---:|:--- |
| `dependency-name` | Ignore updates for dependencies with matching names, optionally using `*` to match zero or more characters. |
| `versions` | Ignore specific versions or ranges of versions. Examples: `~=1.0.5`, `>= 1.0.5,<2`, `>=0.1.1`. |
| `update-types` | Ignore types of updates, such as [SemVer](https://semver.org) `major`, `minor`, `patch` updates on version updates (for example: `version-update:semver-patch` will ignore patch updates). This can be combined with `dependency-name=*` to ignore particular `update-types` for all dependencies. |

!!! note "Supported `update-types` values"
    Currently, only `version-update:semver-major`, `version-update:semver-minor`, and `version-update:semver-patch` are supported options for `update-types`.

The `ignore` option is essentially similar to [the `ignore` option of Dependabot](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file#ignore).
If `versions` and `update-types` are used together, they will both be respected jointly.

Here is an example of different lines given as value for the `ignore` option that accomplishes different things:

```yaml
# ...
jobs:
  check-dependencies:
    uses: SINTEF/ci-cd/.github/workflows/ci_check_pyproject_dependencies.yml@v2.2.1
    with:
      # ...
      # For Sphinx, ignore all updates for/from version 4.5.0 and up / keep the minimum version for Sphinx at 4.5.0.
      # For pydantic, ignore all patch updates
      # For numpy, ignore any and all updates
      ignore: |
        dependency-name=Sphinx...versions=>=4.5.0
        dependency-name=pydantic...update-types=version-update:semver-patch
        dependency-name=numpy
# ...
```

## Expectations

The repository contains the following:

- (**required**) A repository root `pyproject.toml` file with the Python package's dependencies.

## Inputs

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `git_username` | A git username (used to set the 'user.name' config option). | **_Yes_** | | _string_ |
| `git_email` | A git user's email address (used to set the 'user.email' config option). | **_Yes_** | | _string_ |
| `permanent_dependencies_branch` | The branch name for the permanent dependency updates branch. | No | ci/dependency-updates | _string_ |
| `python_version` | The Python version to use for the workflow. | No | 3.9 | _string_ |
| `install_extras` | Any extras to install from the local repository through 'pip'. Must be encapsulated in square parentheses (`[]`) and be separated by commas (`,`) without any spaces.</br></br>Example: `'[dev,release]'`. | No | _Empty string_ | _string_ |
| `pr_body_file` | Relative path to PR body file from the root of the repository.</br></br>Example: `'.github/utils/pr_body_deps_check.txt'`. | No | _Empty string_ | _string_ |
| `fail_fast` | Whether the task to update dependencies should fail if any error occurs. | No | `false` | _boolean_ |
| `pr_labels` | A comma separated list of strings of GitHub labels to use for the created PR. | No | _Empty string_ | _string_ |
| `ignore` | Create ignore conditions for certain dependencies. A multi-line string of ignore rules, where each line is an ellipsis-separated (`...`) string of key/value-pairs. One line per dependency. This option is similar to [the `ignore` option of Dependabot](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file#ignore). | No | _Empty string_ | _string_

## Secrets

| **Name** | **Description** | **Required** |
|:--- |:--- |:---:|
| `PAT` | A personal access token (PAT) with rights to update the `permanent_dependencies_branch`. This will fallback on `GITHUB_TOKEN`. | No |

## Usage example

The following is an example of how a workflow may look that calls _CI - Check pyproject.toml dependencies_.
It is meant to be complete as is.

```yaml
name: CI - Check dependencies

on:
  schedule:
    - cron: "30 5 * * 1"
  workflow_dispatch:

jobs:
  check-dependencies:
    name: Call external workflow
    uses: SINTEF/ci-cd/.github/workflows/ci_check_pyproject_dependencies.yml@v2.2.1
    if: github.repository_owner == 'SINTEF'
    with:
      git_username: "Casper Welzel Andersen"
      git_email: "CasperWA@github.com"
      permanent_dependencies_branch: "ci/dependency-updates"
      python_version: "3.9"
      install_extras: "[dev]"
      pr_labels: "CI/CD"
    secrets:
      PAT: ${{ secrets.PAT }}
```
