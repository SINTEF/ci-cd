# CD - Release
<!-- markdownlint-disable MD007 -->

**File to use:** `cd_release.yml`

There are 2 jobs in this workflow, which run in sequence.

First, an update & publish job, which updates the version in the package's root `__init__.py` file through an [Invoke](https://pyinvoke.org) task.
The newly created tag (created due to the caller workflow running `on.release.types.published`) will be updated accordingly, as will the publish branch (defaults to `main`).

Secondly, a job to update the documentation is run, however, this can be deactivated.
The job expects the documentation to be setup with the [mike](https://github.com/jimporter/mike)+[MkDocs](https://www.mkdocs.org)+[GitHub Pages](https://pages.github.com/) framework.

For more information about the specific changelog inputs, see the related [changelog generator](https://github.com/github-changelog-generator/github-changelog-generator) actually used, specifically the [list of configuration options](https://github.com/github-changelog-generator/github-changelog-generator/wiki/Advanced-change-log-generation-examples).

!!! note
    Concerning the changelog generator, the specific input `changelog_exclude_labels` defaults to a list of different labels if not supplied, hence, if supplied, one might want to include these labels alongside any extra labels.
    The default value is given here as a help:  
    `'duplicate,question,invalid,wontfix'`

The `changelog_exclude_tags_regex` is also used to remove tags in a list of tags to consider when evaluating the "previous version".
This is specifically for adding a changelog to the GitHub release body.

If used together with the [Update API Reference in Documentation](../hooks/docs_api_reference.md#using-it-together-with-cicd-workflows), please align the `relative` input with the `--relative` option, when running the hook.
See the [proper section](../hooks/docs_api_reference.md#using-it-together-with-cicd-workflows) to understand why and how these options and inputs should be aligned.

## Updating instances of version in repository files

The content of repository files can be updated to use the new version where necessary.
This is done through the `version_update_changes` (and `version_update_changes_separator`) inputs.

To see an example of how to use the `version_update_changes` (and `version_update_changes_separator`) see for example the [workflow used by the SINTEF/ci-cd repository](https://github.com/SINTEF/ci-cd/blob/v2.0.0/.github/workflows/_local_cd_release.yml) calling the _CD Release_ workflow.

Some notes to consider and respect when using `version_update_changes` are:

- The value of `version_update_changes_separator` applies to _all_ lines given in `version_update_changes`, meaning it should be a character, or series of characters, which will not be part of the actual content.
- Specifically, concerning the 'raw' Python string 'pattern' the following applies:

    - **Always** escape double quotes (`"`).
      This is done by prefixing it with a backslash (`\`): `\"`.
    - Escape special bash/sh characters, e.g., back tick (`` ` ``).
    - Escape special Python regular expression characters, if they are not used for their intended purpose in this 'raw' string.
      See the [`re` library documentation](https://docs.python.org/3/library/re.html) for more information.

Concerning the 'replacement string' part, the `package_dirs` input and full semantic version can be substituted in dynamically by wrapping either `package_dir` or `version` in curly braces (`{}`).
Indeed, for the version, one can specify sub-parts of the version to use, e.g., if one desires to only use the major version, this can be done by using the `major` attribute: `{version.major}`.
The full list of version attributes are: `major`, `minor`, `patch`, `pre_release`, and `build`.
More can be used, e.g., to only insert the major.minor version: `{version.major}.{version.minor}`.

For the 'file path' part, `package_dir` wrapped in curly braces (`{}`) will also be substituted at run time with each line from the possibly multi-line `package_dirs` input.
E.g., `{package_dir}/__init__.py` will become `ci_cd/__init__.py` if the `package_dirs` input was `'ci_cd'`.

## Expectations

This workflow should _only_ be used for releasing a single modern Python package.

The repository contains the following:

- (**required**) A Python package root `__init__.py` file with `__version__` defined.
- (**required**) The workflow is run for a tag that starts with `v` followed by a full semantic version.
  This will automatically be the case for a GitHub release, which creates a new tag that starts with `v`.
  See [SemVer.org](https://semver.org) for more information about semantic versioning.

## Inputs

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `git_username` | A git username (used to set the 'user.name' config option). | **_Yes_** | | _string_ |
| `git_email` | A git user's email address (used to set the 'user.email' config option). | **_Yes_** | | _string_ |
| `python_package` | Whether or not this is a Python package, where the version should be updated in the `'package_dir'/__init__.py` for the possibly several 'package_dir' lines given in the `package_dirs` input and a build and release to PyPI should be performed. | No | `true` | _boolean_ |
| `package_dirs` |  single or multi-line string of paths to Python package directories relative to the repository directory to have its `__version__` value updated.</br></br>Example: `'src/my_package'`.</br></br>**Important**: This is _required_ if 'python_package' is 'true', which is the default. | **_Yes_ (if 'python_package' is 'true'** | | _string_ |
| `release_branch` | The branch name to release/publish from. | No | main | _string_ |
| `install_extras` | Any extras to install from the local repository through 'pip'. Must be encapsulated in square parentheses (`[]`) and be separated by commas (`,`) without any spaces.</br></br>Example: `'[dev,release]'`. | No | _Empty string_ | _string_ |
| `relative` | Whether or not to use install the local Python package(s) as an editable. | No | `false` | _boolean_ |
| `python_version_build` | The Python version to use for the workflow when building the package. | No | 3.9 | _string_ |
| `python_version_docs` | The Python version to use for the workflow when building the documentation. | No | 3.9 | _string_ |
| `version_update_changes` | A single or multi-line string of changes to be implemented in the repository files upon updating the version. The string should be made up of three parts: 'file path', 'pattern', and 'replacement string'. These are separated by the 'version_update_changes_separator' value.</br>The 'file path' must _always_ either be relative to the repository root directory or absolute.</br>The 'pattern' should be given as a 'raw' Python string. | No | _Empty string_ | _string_ |
| `version_update_changes_separator` | The separator to use for 'version_update_changes' when splitting the three parts of each string. | No | , | _string_ |
| `build_cmd` | The package build command, e.g., `'pip install flit && flit build'` or `'python -m build'` (default). | No | `python -m build` | _string_ |
| `tag_message_file` | Relative path to a release tag message file from the root of the repository.</br></br>Example: `'.github/utils/release_tag_msg.txt'`. | No | _Empty string_ | _string_ |
| `publish_on_pypi` | Whether or not to publish on PyPI.</br></br>**Note**: This is only relevant if 'python_package' is 'true', which is the default. | No | `true` | _boolean_ |
| `test` | Whether to use the TestPyPI repository index instead of PyPI. | No | `false` | _boolean_ |
| `update_docs` | Whether or not to also run the 'docs' workflow job. | No | `false` | _boolean_ |
| `doc_extras` | Any extras to install from the local repository through 'pip'. Must be encapsulated in square parentheses (`[]`) and be separated by commas (`,`) without any spaces.</br></br>Note, if this is empty, 'install_extras' will be used as a fallback.</br></br>Example: `'[docs]'`. | No | _Empty string_ | _string_ |
| `changelog_exclude_tags_regex` | A regular expression matching any tags that should be excluded from the CHANGELOG.md. | No | _Empty string_ | _string_ |
| `changelog_exclude_labels` | Comma-separated list of labels to exclude from the CHANGELOG.md. | No | _Empty string_ | _string_ |

## Secrets

| **Name** | **Description** | **Required** |
|:--- |:--- |:---:|
| `PyPI_token` | A PyPI token for publishing the built package to PyPI.</br></br>**Important**: This is _required_ if both 'python_package' and 'publish_on_pypi' are 'true'. Both are 'true' by default. | **_Yes_ (if 'python_package' and 'publish_on_pypi' are 'true')** |
| `PAT` | A personal access token (PAT) with rights to update the `release_branch`. This will fallback on `GITHUB_TOKEN`. | No |

## Usage example

The following is an example of how a workflow may look that calls _CD - Release_.
It is meant to be complete as is.

```yaml
name: CD - Publish

on:
  release:
    types:
    - published

jobs:
  publish:
    name: Publish package and documentation
    uses: SINTEF/ci-cd/.github/workflows/cd_release.yml@v2.0.0
    if: github.repository == 'SINTEF/my-python-package' && startsWith(github.ref, 'refs/tags/v')
    with:
      git_username: "Casper Welzel Andersen"
      git_email: "CasperWA@github.com"
      release_branch: stable
      package_dirs: my_python_package
      install_extras: "[dev,build]"
      build_cmd: "pip install flit && flit build"
      tag_message_file: ".github/utils/release_tag_msg.txt"
      update_docs: true
      doc_extras: "[docs]"
      exclude_labels: "skip_changelog,duplicate"
    secrets:
      PyPI_token: ${{ secrets.PYPI_TOKEN }}
      PAT: ${{ secrets.PAT }}
```
