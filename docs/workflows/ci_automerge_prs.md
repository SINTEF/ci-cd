# CI - Activate auto-merging for PRs

**File to use:** `ci_automerge_prs.yml`

Activate auto-merging for a PR.

## Expectations

The `PAT` secret must represent a user with the rights to activate auto-merging.

This workflow can _only_ be called if the triggering event from the caller workflow is `pull_request_target`.

## Inputs

There are no inputs for this workflow.

## Secrets

| **Name** | **Description** | **Required** |
|:--- |:--- |:---:|
| `PAT` | A personal access token (PAT) with rights to update the `permanent_dependencies_branch`. This will fallback on `GITHUB_TOKEN`. | No |

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
    uses: CasperWA/ci-cd/.github/workflows/ci_automerge_prs.yml@v1
    if: github.repository_owner == 'CasperWA' && ( ( startsWith(github.event.pull_request.head.ref, 'dependabot/') && github.actor == 'dependabot[bot]' ) || ( github.event.pull_request.head.ref == 'ci/update-pyproject' && github.actor == 'CasperWA' ) )
    secrets:
      PAT: ${{ secrets.RELEASE_PAT }}
```
