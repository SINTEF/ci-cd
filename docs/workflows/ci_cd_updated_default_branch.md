# CI/CD - New updates to default branch

**File to use:** `ci_cd_updated_default_branch.yml`

Keep your `permanent_dependencies_branch` branch up-to-date with changes in your main development branch, i.e., the `default_repo_branch`.

Furthermore, this workflow can optionally update the `latest` [mike](https://github.com/jimporter/mike)+[MkDocs](https://www.mkdocs.org)+[GitHub Pages](https://pages.github.com/)-framework documentation release alias, which represents the `default_repo_branch`.

!!! warning
    If a PAT is not passed through for the `PAT` secret and `GITHUB_TOKEN` is used, beware that any other CI/CD jobs that run for, e.g., pull request events, may not run since `GITHUB_TOKEN`-generated PRs are designed to not start more workflows to avoid escalation.
    Hence, if it is important to run CI/CD workflows for pull requests, consider passing a PAT as a secret to this workflow represented by the `PAT` secret.

!!! important
    If this is to be used together with the [CI - Update dependencies PR](./ci_update_dependencies.md) workflow, the `pr_body_file` supplied to that workflow (if any) should match the `update_depednencies_pr_body_file` input in this workflow and be immutable within the first 8 lines, i.e., no check boxes or similar in the first 8 lines.
    Indeed, it is recommended to not supply `pr_body_file` to the [CI - Update dependencies PR](./ci_update_dependencies.md) workflow as well as to not supply the `update_dependencies_pr_body_file` in this workflow in this case.

!!! note
    Concerning the changelog generator, the specific input `changelog_exclude_labels` defaults to a list of different labels if not supplied, hence, if supplied, one might want to include these labels alongside any extra labels.
    The default value is given here as a help:  
    `'duplicate,question,invalid,wontfix'`

## Expectations

The repository contains the following:

- (**required**) A single Python package is contained in the `package_dir` directory.
- (**required**) _Only if also updating the documentation_, then the documentation should be contained in a root `docs` directory.
- (**required**) _Only if also updating the documentation_, then a root `README.md` file must exist and desired to be used as the documentation's landing page if the `update_docs_landing_page` is set to `true`, which is the default.

## Inputs

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `git_username` | A git username (used to set the 'user.name' config option). | **_Yes_** | | _string_ |
| `git_email` | A git user's email address (used to set the 'user.email' config option). | **_Yes_** | | _string_ |
| `permanent_dependencies_branch` | The branch name for the permanent dependency updates branch. | No | ci/dependency-updates | _string_ |
| `default_repo_branch` | The branch name of the repository's default branch. More specifically, the branch the PR should target. | No | main | _string_ |
| `update_dependencies_pr_body_file` | Relative path to a PR body file from the root of the repository, which is used in the 'CI - Update dependencies PR' workflow, if used.</br></br>Example: `'.github/utils/pr_body_update_deps.txt'`. | No | _Empty string_ | _string_ |
| `update_docs` | Whether or not to also run the 'docs' workflow job. | No | `false` | _boolean_ |
| `update_python_api_ref` | Whether or not to update the Python API documentation reference.</br></br>**Note**: If this is 'true', 'package_dir' is _required_. | No | `true` | _boolean_ |
| `package_dir` | Path to the Python package directory relative to the repository directory.</br></br>Example: `'src/my_package'`.</br></br>**Important**: This is _required_ if 'update_docs' and 'update_python_api_ref' are 'true'. | **_Yes_ (if 'update_docs' and 'update_python_api_ref' are 'true')** | | _string_ |
| `update_docs_landing_page` | Whether or not to update the documentation landing page. The landing page will be based on the root README.md file. | No | `true` | _boolean_ |
| `python_version` | The Python version to use for the workflow.</br></br>**Note**: This is only relevant if `update_pre-commit` is `true`. | No | 3.9 | _string_ |
| `doc_extras` | Any extras to install from the local repository through 'pip'. Must be encapsulated in square parentheses (`[]`) and be separated by commas (`,`) without any spaces.</br></br>Example: `'[docs]'`. | No | _Empty string_ | _string_ |
| `exclude_dirs` | Comma-separated list of directories to exclude in the Python API reference documentation. Note, only directory names, not paths, may be included. Note, all folders and their contents with these names will be excluded. Defaults to `'__pycache__'`. **Important**: When a user value is set, the preset value is overwritten - hence `'__pycache__'` should be included in the user value if one wants to exclude these directories. | No | \_\_pycache\_\_ | _string_ |
| `exclude_files` | Comma-separated list of files to exclude in the Python API reference documentation. Note, only full file names, not paths, may be included, i.e., filename + file extension. Note, all files with these names will be excluded. Defaults to `'__init__.py'`. **Important**: When a user value is set, the preset value is overwritten - hence `'__init__.py'` should be included in the user value if one wants to exclude these files. | No | \_\_init\_\_.py | _string_ |
| `full_docs_dirs` | Comma-separated list of directories in which to include everything - even those without documentation strings. This may be useful for a module full of data models or to ensure all class attributes are listed. | No | _Empty string_ | _string_ |
| `landing_page_replacements` | List of replacements (mappings) to be performed on README.md when creating the documentation's landing page (index.md). This list _always_ includes replacing `'docs/'` with an empty string to correct relative links, i.e., this cannot be overwritten. By default `'(LICENSE)'` is replaced by `'(LICENSE.md)'`. | No | (LICENSE),(LICENSE.md) | _string_ |
| `landing_page_replacements_separator` | String to separate replacement mappings from the 'replacements' input. Defaults to a pipe (`\|`). | No | \| | _string_ |
| `landing_page_replacements_mapping_separator` | String to separate a single mapping's 'old' to 'new' statement. Defaults to a comma (`,`). | No | , | _string_ |
| `test` | Whether to do a "dry run", i.e., run the workflow, but avoid pushing to 'permanent_dependencies_branch' branch and deploying documentation (if 'update_docs' is 'true'). | No | `false` | _boolean_ |
| `changelog_exclude_tags_regex` | A regular expression matching any tags that should be excluded from the CHANGELOG.md. | No | _Empty string_ | _string_ |
| `changelog_exclude_labels` | Comma-separated list of labels to exclude from the CHANGELOG.md. | No | _Empty string_ | _string_ |

## Secrets

| **Name** | **Description** | **Required** |
|:--- |:--- |:---:|
| `PAT` | A personal access token (PAT) with rights to update the `permanent_dependencies_branch`. This will fallback on `GITHUB_TOKEN`. | No |

## Usage example

The following is an example of how a workflow may look that calls _CI/CD - New updates to default branch_.
It is meant to be complete as is.

```yaml
name: CI - Activate auto-merging for Dependabot PRs

on:
  push:
    branches:
    - stable

jobs:
  updates-to-stable:
    name: Call external workflow
    uses: CasperWA/ci-cd/.github/workflows/ci_cd_updated_default_branch.yml@v1
    if: github.repository_owner == 'CasperWA'
    inputs:
      git_username: "Casper Welzel Andersen"
      git_email: "CasperWA@github.com"
      default_repo_branch: stable
      permanent_dependencies_branch: "ci/dependency-updates"
      update_docs: true
      package_dir: my_python_package
      doc_extras: "[docs]"
      exclude_files: __init__.py,config.py
      full_docs_dirs: models
      landing_page_replacements: "(LICENSE);(LICENSE.md)|(tools);(../tools)"
      landing_page_replacements_mapping_separator: ";"
    secrets:
      PAT: ${{ secrets.PAT }}
```
