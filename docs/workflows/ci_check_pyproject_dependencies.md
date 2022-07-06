---
title: CI - Check pyproject.toml dependencies
---
<!-- markdownlint-disable-next-line MD025 -->
# CI - Check pyproject.toml dependencies (`ci_check_pyproject_dependencies.yml`)

This workflow runs an [Invoke](https://pyinvoke.org) task to check dependencies in a `pyproject.toml` file.

The reason for having this workflow and not using [Dependabot](https://github.com/dependabot/dependabot-core) is because it seems to not function properly with this use case.

!!! warning
    If a PAT is not passed through for the `PAT` secret and `GITHUB_TOKEN` is used, beware that any other CI/CD jobs that run for, e.g., pull request events, may not run since `GITHUB_TOKEN`-generated PRs are designed to not start more workflows to avoid escalation.
    Hence, if it is important to run CI/CD workflows for pull requests, consider passing a PAT as a secret to this workflow represented by the `PAT` secret.

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
    uses: CasperWA/ci-cd/.github/workflows/ci_check_pyproject_dependencies.yml@v1
    if: github.repository_owner == 'CasperWA'
    inputs:
      git_username: "Casper Welzel Andersen"
      git_email: "CasperWA@github.com"
      permanent_dependencies_branch: "ci/dependency-updates"
      python_version: "3.9"
      install_extras: "[dev]"
      pr_labels: "CI/CD"
    secrets:
      PAT: ${{ secrets.PAT }}
```
