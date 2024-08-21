# CI/CD - New updates to default branch

**File to use:** `ci_cd_updated_default_branch.yml`

Keep your `permanent_dependencies_branch` branch up-to-date with changes in your main development branch, i.e., the `default_repo_branch`.

Furthermore, this workflow can optionally update the `latest` [mike](https://github.com/jimporter/mike)+[MkDocs](https://www.mkdocs.org)+[GitHub Pages](https://pages.github.com/)-framework documentation release alias, which represents the `default_repo_branch`.
The workflow also alternatively supports the [Sphinx](https://www.sphinx-doc.org/) framework.

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

If used together with the [Update API Reference in Documentation](../hooks/docs_api_reference.md#using-it-together-with-cicd-workflows), please align the `relative` input with the `--relative` option, when running the hook.
See the [proper section](../hooks/docs_api_reference.md#using-it-together-with-cicd-workflows) to understand why and how these options and inputs should be aligned.

## Expectations

The repository contains the following:

- (**required**) At least one Python package exists that can be pointed to for the `package_dirs` input.
- (**required**) _Only if also updating the documentation_, then the documentation should be contained in a root `docs` directory.
- (**required**) _Only if also updating the documentation_, then a root `README.md` file must exist and desired to be used as the documentation's landing page if the `update_docs_landing_page` is set to `true`, which is the default.

## Inputs

The following inputs are general inputs for the workflow as a whole.

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `git_username` | A git username (used to set the 'user.name' config option). | **_Yes_** | | _string_ |
| `git_email` | A git user's email address (used to set the 'user.email' config option). | **_Yes_** | | _string_ |
| `default_repo_branch` | The branch name of the repository's default branch. More specifically, the branch the PR should target. | No | main | _string_ |
| `test` | Whether to do a "dry run", i.e., run the workflow, but avoid pushing to 'permanent_dependencies_branch' branch and deploying documentation (if 'update_docs' is 'true'). | No | `false` | _boolean_ |
| `pip_index_url` | A URL to a PyPI repository index. | No | `https://pypi.org/simple/` | _string_ |
| `pip_extra_index_urls` | A space-delimited string of URLs to additional PyPI repository indices. | No | _Empty string_ | _string_ |

Inputs related to updating the permanent dependencies branch.

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `update_dependencies_branch` | Whether or not to update the permanent dependencies branch. | No | `true` | _boolean_ |
| `permanent_dependencies_branch` | The branch name for the permanent dependency updates branch. | No | ci/dependency-updates | _string_ |
| `update_dependencies_pr_body_file` | Relative path to a PR body file from the root of the repository, which is used in the 'CI - Update dependencies PR' workflow, if used.</br></br>Example: `'.github/utils/pr_body_update_deps.txt'`. | No | _Empty string_ | _string_ |

Inputs related to building and releasing the documentation.

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `update_docs` | Whether or not to also run the 'docs' workflow job. | No | `false` | _boolean_ |
| `update_python_api_ref` | Whether or not to update the Python API documentation reference.</br></br>**Note**: If this is 'true', 'package_dirs' is _required_. | No | `true` | _boolean_ |
| `package_dirs` | A multi-line string of paths to Python package directories relative to the repository directory to be considered for creating the Python API reference documentation.</br></br>Example: `'src/my_package'`.</br></br>**Important**: This is _required_ if 'update_docs' and 'update_python_api_ref' are 'true'.</br></br>See also [Single vs multi-line input](index.md#single-vs-multi-line-input). | **_Yes_ (if 'update_docs' and 'update_python_api_ref' are 'true')** | | _string_ |
| `update_docs_landing_page` | Whether or not to update the documentation landing page. The landing page will be based on the root README.md file. | No | `true` | _boolean_ |
| `python_version` | The Python version to use for the workflow.</br></br>**Note**: This is only relevant if `update_pre-commit` is `true`. | No | 3.9 | _string_ |
| `doc_extras` | Any extras to install from the local repository through 'pip'. Must be encapsulated in square parentheses (`[]`) and be separated by commas (`,`) without any spaces.</br></br>Example: `'[docs]'`. | No | _Empty string_ | _string_ |
| `relative` | Whether or not to use install the local Python package(s) as an editable. | No | `false` | _boolean_ |
| `exclude_dirs` | A multi-line string of directories to exclude in the Python API reference documentation. Note, only directory names, not paths, may be included. Note, all folders and their contents with these names will be excluded. Defaults to `'__pycache__'`.</br></br>**Important**: When a user value is set, the preset value is overwritten - hence `'__pycache__'` should be included in the user value if one wants to exclude these directories.</br></br>See also [Single vs multi-line input](index.md#single-vs-multi-line-input). | No | \_\_pycache\_\_ | _string_ |
| `exclude_files` | A multi-line string of files to exclude in the Python API reference documentation. Note, only full file names, not paths, may be included, i.e., filename + file extension. Note, all files with these names will be excluded. Defaults to `'__init__.py'`.</br></br>**Important**: When a user value is set, the preset value is overwritten - hence `'__init__.py'` should be included in the user value if one wants to exclude these files.</br></br>See also [Single vs multi-line input](index.md#single-vs-multi-line-input). | No | \_\_init\_\_.py | _string_ |
| `full_docs_dirs` | A multi-line string of directories in which to include everything - even those without documentation strings. This may be useful for a module full of data models or to ensure all class attributes are listed.</br></br>See also [Single vs multi-line input](index.md#single-vs-multi-line-input). | No | _Empty string_ | _string_ |
| `full_docs_files` | A multi-line string of relative paths to files in which to include everything - even those without documentation strings. This may be useful for a file full of data models or to ensure all class attributes are listed.</br></br>See also [Single vs multi-line input](index.md#single-vs-multi-line-input). | No | _Empty string_ | _string_ |
| `special_file_api_ref_options` | A multi-line string of combinations of a relative path to a Python file and a fully formed mkdocstrings option that should be added to the generated MarkDown file for the Python API reference documentation.</br>Example: `my_module/py_file.py,show_bases:false`.</br></br>Encapsulate the value in double quotation marks (`"`) if including spaces ( ).</br></br>**Important**: If multiple `package_dirs` are supplied, the relative path MUST include/start with the appropriate 'package_dir' value, e.g., `"my_package/my_module/py_file.py,show_bases: false"`.</br></br>See also [Single vs multi-line input](index.md#single-vs-multi-line-input). | No | _Empty string_ | _string_ |
| `landing_page_replacements` | A multi-line string of replacements (mappings) to be performed on README.md when creating the documentation's landing page (index.md). This list _always_ includes replacing `'docs/'` with an empty string to correct relative links, i.e., this cannot be overwritten. By default `'(LICENSE)'` is replaced by `'(LICENSE.md)'`.</br></br>See also [Single vs multi-line input](index.md#single-vs-multi-line-input). | No | (LICENSE),(LICENSE.md) | _string_ |
| `landing_page_replacement_separator` | String to separate a mapping's 'old' to 'new' parts. Defaults to a comma (`,`). | No | , | _string_ |
| `changelog_exclude_tags_regex` | A regular expression matching any tags that should be excluded from the CHANGELOG.md. | No | _Empty string_ | _string_ |
| `changelog_exclude_labels` | Comma-separated list of labels to exclude from the CHANGELOG.md. | No | _Empty string_ | _string_ |
| `docs_framework` | The documentation framework to use. This can only be either `'mkdocs'` or `'sphinx'`. | No | mkdocs | _string_ |
| `system_dependencies` | A single (space-separated) or multi-line string of Ubuntu APT packages to install prior to building the documentation.</br></br>See also [Single vs multi-line input](index.md#single-vs-multi-line-input). | No | _Empty string_ | _string_ |

Finally, inputs related _only_ to the Sphinx framework when building and releasing the documentation.

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `sphinx-build_options` | Single (space-separated) or multi-line string of command-line options to use when calling `sphinx-build`.</br></br>See also [Single vs multi-line input](index.md#single-vs-multi-line-input). | No | _Empty string_ | _string_ |
| `docs_folder` | The path to the root documentation folder relative to the repository root. | No | docs | _string_ |
| `build_target_folder` | The path to the target folder for the documentation build relative to the repository root. | No | site | _string_ |

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
    uses: SINTEF/ci-cd/.github/workflows/ci_cd_updated_default_branch.yml@v2.8.0
    if: github.repository_owner == 'SINTEF'
    with:
      git_username: "Casper Welzel Andersen"
      git_email: "CasperWA@github.com"
      default_repo_branch: stable
      permanent_dependencies_branch: "ci/dependency-updates"
      update_docs: true
      package_dirs: |
        my_python_package
        my_other_python_package
      doc_extras: "[docs]"
      exclude_files: __init__.py,config.py
      full_docs_dirs: models
      landing_page_replacements: "(LICENSE);(LICENSE.md)|(tools);(../tools)"
      landing_page_replacements_mapping_separator: ";"
    secrets:
      PAT: ${{ secrets.PAT }}
```
