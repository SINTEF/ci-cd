# CI - Activate auto-merging for PRs

**File to use:** `ci_automerge_prs.yml`

Activate auto-merging for a PR.

It is possible to introduce changes to the PR head branch prior to activating the auto-merging, if so desired.
This is done by setting `perform_changes` to `'true'` and setting the other inputs accordingly, as they are now required.
See [Inputs](#inputs) below for a full overview of the available inputs.

The `changes` input can be both a path to a bash file that should be run, or a multi-line string of bash commands to run.
Afterwards any and all changes in the repository will be committed and pushed to the PR head branch.

The motivation for being able to run changes prior to auto-merging, is to update or affect the repository files according to the specific PR being auto-merged.
Usually auto-merging is activated for [dependabot](https://docs.github.com/en/code-security/dependabot) branches, i.e., when a dependency/requirement is updated.
Hence, the changes could include updating this dependency in documentation files or similar, where it will not be updated otherwise.

!!! note "PR branch name"
    The generated branch for the PR will be named `ci/update-pyproject`.

## Expectations

The `PAT` secret must represent a user with the rights to activate auto-merging.

This workflow can _only_ be called if the triggering event from the caller workflow is `pull_request_target`.

## Inputs

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `runner` | The runner to use for the workflow. Note, the callable workflow expects a Linux/Unix system.. | No | ubuntu-latest | _string_ |
| `perform_changes` | Whether or not to perform and commit changes to the PR branch prior to activating auto-merge. | No | | _boolean_ |
| `git_username` | A git username (used to set the 'user.name' config option).</br>**Required** if `perform_changes` is 'true'. | No | | _string_ |
| `git_email` | A git user's email address (used to set the 'user.email' config option).</br>**Required** if `perform_changes` is 'true'. | No | | _string_ |
| `changes` | A file to run in the local repository (relative path from the root of the repository) or a multi-line string of bash commands to run.</br>**Required** if `perform_changes` is 'true'.</br></br>See also [Single vs multi-line input](index.md#single-vs-multi-line-input). | No | | _string_ |

## Secrets

| **Name** | **Description** | **Required** |
|:--- |:--- |:---:|
| `PAT` | A personal access token (PAT) with rights to activate auto-merging. This will fallback on `GITHUB_TOKEN`. | No |

## Usage example

The following is an example of how a workflow may look that calls _CI - Activate auto-merging for PRs_.
It is meant to be complete as is.

```yaml
name: CI - Activate auto-merging for Dependabot PRs

on:
  pull_request_target:
    branches:
    - ci/dependency-updates

jobs:
  update-dependency-branch:
    name: Call external workflow
    uses: SINTEF/ci-cd/.github/workflows/ci_automerge_prs.yml@v2.8.3
    if: github.repository_owner == 'SINTEF' && ( ( startsWith(github.event.pull_request.head.ref, 'dependabot/') && github.actor == 'dependabot[bot]' ) || ( github.event.pull_request.head.ref == 'ci/update-pyproject' && github.actor == 'CasperWA' ) )
    secrets:
      PAT: ${{ secrets.RELEASE_PAT }}
```

A couple of usage examples when adding changes:

Here, referencing a bash script file for the changes.

```yaml
name: CI - Activate auto-merging for Dependabot PRs

on:
  pull_request_target:
    branches:
    - ci/dependency-updates

jobs:
  update-dependency-branch:
    name: Call external workflow
    uses: SINTEF/ci-cd/.github/workflows/ci_automerge_prs.yml@v2.8.3
    if: github.repository_owner == 'SINTEF' && ( ( startsWith(github.event.pull_request.head.ref, 'dependabot/') && github.actor == 'dependabot[bot]' ) || ( github.event.pull_request.head.ref == 'ci/update-pyproject' && github.actor == 'CasperWA' ) )
    with:
      perform_changes: true
      git_username: "Casper Welzel Andersen"
      git_email: "CasperWA@github.com"
      changes: ".ci/pre_automerge.sh"
    secrets:
      PAT: ${{ secrets.RELEASE_PAT }}
```

Here, writing out the changes explicitly in the job.

```yaml
name: CI - Activate auto-merging for Dependabot PRs

on:
  pull_request_target:
    branches:
    - ci/dependency-updates

jobs:
  update-dependency-branch:
    name: Call external workflow
    uses: SINTEF/ci-cd/.github/workflows/ci_automerge_prs.yml@v2.8.3
    if: github.repository_owner == 'SINTEF' && ( ( startsWith(github.event.pull_request.head.ref, 'dependabot/') && github.actor == 'dependabot[bot]' ) || ( github.event.pull_request.head.ref == 'ci/update-pyproject' && github.actor == 'CasperWA' ) )
    with:
      perform_changes: true
      git_username: "Casper Welzel Andersen"
      git_email: "CasperWA@github.com"
      changes: |
        PYTHON="$(python --version || :)"
        if [ -z "${PYTHON}" ]; then
          echo "Python not detected on the system."
          exit 1
        fi

        PIP="$(python -m pip --version || :)"
        if [ -z "${PIP}" ]; then
          echo "pip not detected to be installed for ${PYTHON}."
          exit 1
        fi

        echo "Python: ${PYTHON}"
        echo "pip: ${PIP}"

        python -m pip install -U pip
        pip install -U setuptools wheel
        pip install pre-commit

        pre-commit autoupdate
        pre-commit run --all-files || :
    secrets:
      PAT: ${{ secrets.RELEASE_PAT }}
```
