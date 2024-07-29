# CD - Release
<!-- markdownlint-disable MD007 -->

!!! warning "Important"
    The default for `publish_on_pypi` has changed from `true` to `false` in version `2.8.0`.

    To keep using the previous behaviour, set `publish_on_pypi: true` in the workflow file.

    This change has been introduced to push for the use of PyPI's [Trusted Publisher](https://docs.pypi.org/trusted-publishers/) feature, which is not yet supported by reusable/callable workflows.

    See the [Using PyPI's Trusted Publisher](#using-pypis-trusted-publisher) section for more information on how to migrate to this feature.

**File to use:** `cd_release.yml`

There are 2 jobs in this workflow, which run in sequence.

First, an update & publish job, which updates the version in the package's root `__init__.py` file through an [Invoke](https://pyinvoke.org) task.
The newly created tag (created due to the caller workflow running `on.release.types.published`) will be updated accordingly, as will the publish branch (defaults to `main`).

Secondly, a job to update the documentation is run, however, this can be deactivated.
The job expects the documentation to be setup with either the [mike](https://github.com/jimporter/mike)+[MkDocs](https://www.mkdocs.org)+[GitHub Pages](https://pages.github.com/) framework or the [Sphinx](https://www.sphinx-doc.org/) framework.

For more information about the specific changelog inputs, see the related [changelog generator](https://github.com/github-changelog-generator/github-changelog-generator) actually used, specifically the [list of configuration options](https://github.com/github-changelog-generator/github-changelog-generator/wiki/Advanced-change-log-generation-examples).

!!! note
    Concerning the changelog generator, the specific input `changelog_exclude_labels` defaults to a list of different labels if not supplied, hence, if supplied, one might want to include these labels alongside any extra labels.
    The default value is given here as a help:  
    `'duplicate,question,invalid,wontfix'`

The `changelog_exclude_tags_regex` is also used to remove tags in a list of tags to consider when evaluating the "previous version".
This is specifically for adding a changelog to the GitHub release body.

If used together with the [Update API Reference in Documentation](../hooks/docs_api_reference.md#using-it-together-with-cicd-workflows), please align the `relative` input with the `--relative` option, when running the hook.
See the [proper section](../hooks/docs_api_reference.md#using-it-together-with-cicd-workflows) to understand why and how these options and inputs should be aligned.

## Using PyPI's Trusted Publisher

PyPI has introduced a feature called [Trusted Publisher](https://docs.pypi.org/trusted-publishers/) which allows for a more secure way of publishing packages using [OpenID Connect (OIDC)](https://openid.net/connect/).
This feature is [not yet supported by reusable/callable workflows](https://github.com/pypa/gh-action-pypi-publish/tree/release/v1?tab=readme-ov-file#trusted-publishing), but can be used by setting up a GitHub Action workflow in your repository that calls the `cd_release.yml` workflow in one job, setting the `publish_on_pypi` input to `false` and the `upload_distribution` input to `true`, and then using the uploaded artifact to publish the package to PyPI in a subsequent job.

In this way you can still benefit from the `cd_release.yml` dynamically updated workflow, while using PyPI's Trusted Publisher feature.

!!! info
    The artifact name is statically set to `dist`.
    If the workflow is run multiple times, the artifact will be overwritten.
    Retention time for the artifact is kept at the GitHub default (currently 90 days).

!!! warning "Important"
    The `id-token:write` permission is required by the PyPI upload action for Trusted Publishers.

The following is an example of how a workflow may look that calls _CD - Release_ and uses the uploaded built distribution artifact to publish the package to PyPI.
Note, the non-default `dists` directory is chosen for the built distribution, and the artifact is downloaded to the `my-dists` directory.

```yaml
name: CD - Publish

on:
  release:
    types:
    - published

jobs:
  build:
    name: Build distribution & publish documentation
    if: github.repository == 'SINTEF/my-python-package' && startsWith(github.ref, 'refs/tags/v')
    uses: SINTEF/ci-cd/.github/workflows/cd_release.yml@v2.8.0
    with:
      # General
      git_username: "Casper Welzel Andersen"
      git_email: "CasperWA@github.com"
      release_branch: stable

      # Build distribution
      python_package: true
      package_dirs: my_python_package
      install_extras: "[dev,build]"
      build_libs: build
      build_cmd: "python -m build -o dists"
      build_dir: dists
      publish_on_pypi: false
      upload_distribution: true

      # Publish documentation
      update_docs: true
      doc_extras: "[docs]"
      docs_framework: mkdocs

    secrets:
      PAT: ${{ secrets.PAT }}

  publish:
    name: Publish to PyPI
    needs: build
    runs-on: ubuntu-latest

    # Using environments is recommended by PyPI when using Trusted Publishers
    environment: release

    # The id-token:write permission is required by the PyPI upload action for
    # Trusted Publishers
    permissions:
      id-token: write

    steps:
      - name: Download distribution
        uses: actions/download-artifact@v4
        with:
          name: dist  # The artifact will always be called 'dist'
          path: my-dists

      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1
        with:
          # The path to the distribution to upload
          package-dir: my-dists
```

## Updating instances of version in repository files

The content of repository files can be updated to use the new version where necessary.
This is done through the `version_update_changes` (and `version_update_changes_separator`) inputs.

To see an example of how to use the `version_update_changes` (and `version_update_changes_separator`) see for example the [workflow used by the SINTEF/ci-cd repository](https://github.com/SINTEF/ci-cd/blob/v2.8.0/.github/workflows/_local_cd_release.yml) calling the _CD Release_ workflow.

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
- (**required**) The workflow is run for a git tag only.
  This will automatically be the case for a GitHub release.
  The tag name must be a valid semantic version.
  See [SemVer.org](https://semver.org) for more information about semantic versioning.
  It is expected, but not required, that the tag name starts with a `v`, e.g., `v1.0.0`.

## Inputs

The following inputs are general inputs for the workflow as a whole.

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `git_username` | A git username (used to set the 'user.name' config option). | **_Yes_** | | _string_ |
| `git_email` | A git user's email address (used to set the 'user.email' config option). | **_Yes_** | | _string_ |
| `release_branch` | The branch name to release/publish from. | **_Yes_** | main | _string_ |
| `install_extras` | Any extras to install from the local repository through 'pip'. Must be encapsulated in square parentheses (`[]`) and be separated by commas (`,`) without any spaces.</br></br>Example: `'[dev,release]'`. | No | _Empty string_ | _string_ |
| `relative` | Whether or not to use install the local Python package(s) as an editable. | No | `false` | _boolean_ |
| `test` | Whether to use the TestPyPI repository index instead of PyPI as well as output debug statements in both workflow jobs. | No | `false` | _boolean_ |

Inputs related to updating the version, building and releasing the Python package to PyPI.

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `publish_on_pypi` | Whether or not to publish on PyPI.</br></br>**Note**: This is only relevant if 'python_package' is 'true', which is the default.</br></br>**Important**: The default has changed from `true` to `false` to push for the use of PyPI's [Trusted Publisher](https://docs.pypi.org/trusted-publishers/) feature.</br>See the [Using PyPI's Trusted Publisher](#using-pypis-trusted-publisher) section for more information on how to migrate to this feature. | **Yes (will be non-required in v2.9)** | `false` | _boolean_ |
| `python_package` | Whether or not this is a Python package, where the version should be updated in the `'package_dir'/__init__.py` for the possibly several 'package_dir' lines given in the `package_dirs` input and a build and release to PyPI should be performed. | No | `true` | _boolean_ |
| `python_version_build` | The Python version to use for the workflow when building the package. | No | 3.9 | _string_ |
| `package_dirs` | A multi-line string of paths to Python package directories relative to the repository directory to have its `__version__` value updated.</br></br>Example: `'src/my_package'`.</br></br>**Important**: This is _required_ if 'python_package' is 'true', which is the default.</br></br>See also [Single vs multi-line input](index.md#single-vs-multi-line-input). | **_Yes_ (if 'python_package' is 'true')** | | _string_ |
| `version_update_changes` | A multi-line string of changes to be implemented in the repository files upon updating the version. The string should be made up of three parts: 'file path', 'pattern', and 'replacement string'. These are separated by the 'version_update_changes_separator' value.</br>The 'file path' must _always_ either be relative to the repository root directory or absolute.</br>The 'pattern' should be given as a 'raw' Python string.</br></br>See also [Single vs multi-line input](index.md#single-vs-multi-line-input). | No | _Empty string_ | _string_ |
| `version_update_changes_separator` | The separator to use for 'version_update_changes' when splitting the three parts of each string. | No | , | _string_ |
| `build_libs` | A space-separated list of packages to install via PyPI (`pip install`). | No | _Empty string_ | _string_ |
| `build_cmd` | The package build command, e.g., `'flit build'` or `'python -m build'`. | No | `python -m build --outdir dist .` | _string_ |
| `build_dir` | The directory where the built distribution is located. This should reflect the directory used in the build command or by default by the build library. | No | `dist` | _string_ |
| `tag_message_file` | Relative path to a release tag message file from the root of the repository.</br></br>Example: `'.github/utils/release_tag_msg.txt'`. | No | _Empty string_ | _string_ |
| `changelog_exclude_tags_regex` | A regular expression matching any tags that should be excluded from the CHANGELOG.md. | No | _Empty string_ | _string_ |
| `changelog_exclude_labels` | Comma-separated list of labels to exclude from the CHANGELOG.md. | No | _Empty string_ | _string_ |
| `upload_distribution` | Whether or not to upload the built distribution as an artifact.</br></br>**Note**: This is only relevant if 'python_package' is 'true', which is the default. | No | `true` | _boolean_ |

Inputs related to building and releasing the documentation in general.

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `update_docs` | Whether or not to also run the 'docs' workflow job. | No | `false` | _boolean_ |
| `python_version_docs` | The Python version to use for the workflow when building the documentation. | No | 3.9 | _string_ |
| `doc_extras` | Any extras to install from the local repository through 'pip'. Must be encapsulated in square parentheses (`[]`) and be separated by commas (`,`) without any spaces.</br></br>Note, if this is empty, 'install_extras' will be used as a fallback.</br></br>Example: `'[docs]'`. | No | _Empty string_ | _string_ |
| `docs_framework` | The documentation framework to use. This can only be either `'mkdocs'` or `'sphinx'`. | No | mkdocs | _string_ |
| `system_dependencies` | A single (space-separated) or multi-line string of Ubuntu APT packages to install prior to building the documentation.</br></br>See also [Single vs multi-line input](index.md#single-vs-multi-line-input). | No | _Empty string_ | _string_ |

Inputs related _only_ to the **MkDocs** framework.

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `mkdocs_update_latest` | Whether or not to update the 'latest' alias to point to `release_branch`. | No | `true` | _boolean_ |

Finally, inputs related _only_ to the **Sphinx** framework.

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `sphinx-build_options` | Single (space-separated) or multi-line string of command-line options to use when calling `sphinx-build`.</br></br>See also [Single vs multi-line input](index.md#single-vs-multi-line-input). | No | _Empty string_ | _string_ |
| `docs_folder` | The path to the root documentation folder relative to the repository root. | No | docs | _string_ |
| `build_target_folder` | The path to the target folder for the documentation build relative to the repository root. | No | site | _string_ |

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
    uses: SINTEF/ci-cd/.github/workflows/cd_release.yml@v2.8.0
    if: github.repository == 'SINTEF/my-python-package' && startsWith(github.ref, 'refs/tags/v')
    with:
      # General
      git_username: "Casper Welzel Andersen"
      git_email: "CasperWA@github.com"
      release_branch: stable

      # Publish distribution
      package_dirs: my_python_package
      install_extras: "[dev,build]"
      build_cmd: "pip install flit && flit build"
      tag_message_file: ".github/utils/release_tag_msg.txt"
      changelog_exclude_labels: "skip_changelog,duplicate"
      publish_on_pypi: true

      # Publish documentation
      update_docs: true
      doc_extras: "[docs]"
    secrets:
      PyPI_token: ${{ secrets.PYPI_TOKEN }}
      PAT: ${{ secrets.PAT }}
```
