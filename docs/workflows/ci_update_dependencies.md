# CI - Update dependencies PR
<!-- markdownlint-disable MD038 -->

**File to use:** `ci_update_dependencies.yml`

This workflow creates a PR if there are any updates in the `permanent_dependencies_branch` branch that have not been included in the `default_repo_branch` branch.

This workflow works nicely together with the [CI - Check pyproject.toml dependencies](./ci_check_pyproject_dependencies.md) workflow, and the same value for `permanent_dependencies_branch` should be used.
In this way, this workflow can be called on a schedule to update the dependencies that have been merged into the `permanent_dependencies_branch` branch into the `default_repo_branch` branch.

The main point of having this workflow is to have a single PR, which can be squash merged, to merge several dependency updates performed by [Dependabot](https://github.com/dependabot/dependabot-core) or similar.

As a "bonus" this workflow supports updating [pre-commit](https://pre-commit.com) hooks.

!!! note "PR branch name"
    The generated branch for the PR will be named `ci/update-dependencies`.

!!! warning
    If a PAT is not passed through for the `PAT` secret and `GITHUB_TOKEN` is used, beware that any other CI/CD jobs that run for, e.g., pull request events, may not run since `GITHUB_TOKEN`-generated PRs are designed to not start more workflows to avoid escalation.
    Hence, if it is important to run CI/CD workflows for pull requests, consider passing a PAT as a secret to this workflow represented by the `PAT` secret.

!!! important
    If this is to be used together with the [CI/CD - New updates to default branch](./ci_cd_updated_default_branch.md) workflow, the `pr_body_file` supplied (if any) should be immutable within the first 8 lines, i.e., no check boxes or similar in the first 8 lines.
    Indeed, it is recommended to not supply a `pr_body_file` in this case.

## Expectations

There are no expectations of the repo when using this workflow.

## Inputs

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `git_username` | A git username (used to set the 'user.name' config option). | **_Yes_** | | _string_ |
| `git_email` | A git user's email address (used to set the 'user.email' config option). | **_Yes_** | | _string_ |
| `permanent_dependencies_branch` | The branch name for the permanent dependency updates branch. | No | ci/dependency-updates | _string_ |
| `default_repo_branch` | The branch name of the repository's default branch. More specifically, the branch the PR should target. | No | main | _string_ |
| `pr_body_file` | Relative path to PR body file from the root of the repository.</br></br>Example: `'.github/utils/pr_body_update_deps.txt'`. | No | _Empty string_ | _string_ |
| `pr_labels` | A comma separated list of strings of GitHub labels to use for the created PR. | No | _Empty string_ | _string_ |
| `extra_to_dos` | A multi-line string (insert `\n` to create line breaks) with extra 'to do' checks. Should start with `- [ ] `.</br></br>See also [Single vs multi-line input](index.md#single-vs-multi-line-input). | No | _Empty string_ | _string_ |
| `update_pre-commit` | Whether or not to update pre-commit hooks as part of creating the PR. | No | `false` | _boolean_ |
| `python_version` | The Python version to use for the workflow.</br></br>**Note**: This is only relevant if `update_pre-commit` is `true`. | No | 3.9 | _string_ |
| `install_extras` | Any extras to install from the local repository through 'pip'. Must be encapsulated in square parentheses (`[]`) and be separated by commas (`,`) without any spaces.</br></br>Example: `'[dev,pre-commit]'`.</br></br>**Note**: This is only relevant if `update_pre-commit` is `true`. | No | _Empty string_ | _string_ |
| `skip_pre-commit_hooks` | A comma-separated list of pre-commit hook IDs to skip when running `pre-commit` after updating hooks.</br></br>**Note**: This is only relevant if `update_pre-commit` is `true`. | No | _Empty string_ | _string_ |

## Secrets

| **Name** | **Description** | **Required** |
|:--- |:--- |:---:|
| `PAT` | A personal access token (PAT) with rights to create PRs. This will fallback on `GITHUB_TOKEN`. | No |

## Usage example

The following is an example of how a workflow may look that calls _CI - Update dependencies PR_.
It is meant to be complete as is.

```yaml
name: CI - Update dependencies

on:
  schedule:
    - cron: "30 6 * * 3"
  workflow_dispatch:

jobs:
  check-dependencies:
    name: Call external workflow
    uses: SINTEF/ci-cd/.github/workflows/ci_update_dependencies.yml@v2.6.0
    if: github.repository_owner == 'SINTEF'
    with:
      git_username: "Casper Welzel Andersen"
      git_email: "CasperWA@github.com"
      permanent_dependencies_branch: "ci/dependency-updates"
      default_repo_branch: stable
      pr_labels: "CI/CD"
      extra_to_dos: "- [ ] Make sure the PR is **squash** merged, with a sensible commit message.\n- [ ] Check related `requirements*.txt` files are updated accordingly."
      update_pre-commit: true
      python_version: "3.9"
      install_extras: "[pre-commit]"
      skip_pre-commit_hooks: "pylint,pylint-models"
    secrets:
      PAT: ${{ secrets.PAT }}
```
