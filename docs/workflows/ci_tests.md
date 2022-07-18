# CI - Tests
<!-- markdownlint-disable MD024 -->

**File to use:** `ci_tests.yml`

A basic set of CI tests.

Several different basic test jobs are available in this workflow.
By default, they will all run and should be actively "turned off".

## CI jobs

The following sections summarizes each job and the individual inputs necessary for it to function or to adjust how it runs.
Note, a full list of possible inputs and secrets will be given in a separate table at the end of this page.

### Run `pre-commit`

Run the [`pre-commit`](https://pre-commit.com) tool for all files in the repository according to the repository's configuration file.

#### Expectations

`pre-commit` should be setup for the repository.
For more information about `pre-commit`, please see the tool's website: [pre-commit.com](https://pre-commit.com).

This job **should not be run** _if_ the repository does not implement `pre-commit`.

#### Inputs

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `run_pre-commit` | Run the `pre-commit` test job. | No | `true` | _boolean_ |
| `python_version` | The Python version to use for the workflow. | No | 3.9 | _string_ |
| `install_extras` | Any extras to install from the local repository through 'pip'. Must be encapsulated in square parentheses (`[]`) and be separated by commas (`,`) without any spaces.</br></br>Example: `'[dev,pre-commit]'`. | No | _Empty string_ | _string_ |
| `skip_pre-commit_hooks` | A comma-separated list of pre-commit hook IDs to skip when running `pre-commit` after updating hooks. | No | _Empty string_ | _string_ |

### Run `pylint` & `safety`

Run the [`pylint`](https://pylint.pycqa.org/) and/or [`safety`](https://github.com/pyupio/safety) tools.

The `pylint` tool can be run in different ways.
Either it is run once and the `pylint_targets` is a required input, while `pylint_options` is a single- or multi-line optional input.
Or `pylint_runs` is used, a single- or multi-line input, to explicitly write out all `pylint` options and target(s) one line at a time.
For each line in `pylint_runs`, `pylint` will be executed.

Using `pylint_runs` is useful if you have a section of your code, which should be run with a custom set of options, otherwise it is recommended to instead simply use the `pylint_targets` and optionally also `pylint_options` inputs.

The `safety` tool checks all installed Python packages, hence the `install_extras` input should be given as to install _all_ possible dependencies.

#### Expectations

There are no expectations or pre-requisites.
`pylint` and `safety` can be run without a pre-configuration.

#### Inputs

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `run_pylint` | Run the `pylint` test job. | No | `true` | _boolean_ |
| `run_safety` | Run the `safety` test job. | No | `true` | _boolean_ |
| `python_version` | The Python version to use for the workflow. | No | 3.9 | _string_ |
| `install_extras` | Any extras to install from the local repository through 'pip'. Must be encapsulated in square parentheses (`[]`) and be separated by commas (`,`) without any spaces.</br></br>Example: `'[dev,pre-commit]'`. | No | _Empty string_ | _string_ |
| `pylint_targets` | Space-separated string of pylint file and folder targets.</br></br>**Note**, this is only valid if `pylint_runs` is not defined. | **Yes, if `pylint_runs` is not defined** | _Empty string_ | _string_ |
| `pylint_options` | Single space-separated or multi-line string of pylint command line options.</br></br>**Note**, this is only valid if `pylint_runs` is not defined. | No | _Empty string_ | _string_ |
| `pylint_runs` | Single or multi-line string with each line representing a separate pylint run/execution. This should include all desired options and targets.</br></br>**Important**, the inputs `pylint_options` and `pylint_targets` will be ignored if this is defined. | No | _Empty string_ | _string_ |
| `safety_options` | Single space-separated or multi-line string of safety command line options. | No | _Empty string_ | _string_ |

### Build distribution package

Test building the Python package.

This job is equivalent to building the package in the [_CD - Release_](./cd_release.md) workflow, but will not publish anything.

#### Expectations

The repository should be a "buildable" Python package.

#### Inputs

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `run_build_package` | Run the `build package` test job. | No | `true` | _boolean_ |
| `python_version` | The Python version to use for the workflow. | No | 3.9 | _string_ |
| `build_libs` | A space-separated list of packages to install via PyPI (`pip install`). | No | _Empty string_ | _string_ |
| `build_cmd` | The package build command, e.g., `'flit build'` or `'python -m build'` (default). | No | `python -m build` | _string_ |

### Build MkDocs Documentation

Test building the documentation within the [MkDocs](https://www.mkdocs.org) framework.

!!! note
    If using [mike](https://github.com/jimporter/mike), note that this will _not_ be tested, as this would be equivalent to testing mike itself and whether it can build a MkDocs documentation, which should never be part of a repository that uses these tools.

#### Expectations

Is is expected that documentation exists, which is using the MkDocs framework.
This requires at minimum a `mkdocs.yml` configuration file.

#### Inputs

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `run_build_docs` | Run the `build package` test job. | No | `true` | _boolean_ |
| `update_python_api_ref` | Whether or not to update the Python API documentation reference.</br></br>**Note**: If this is `true`, `package_dir` is _required_. | No | `true` | _boolean_ |
| `update_docs_landing_page` | Whether or not to update the documentation landing page. The landing page will be based on the root README.md file. | No | `true` | _boolean_ |
| `python_version` | The Python version to use for the workflow. | No | 3.9 | _string_ |
| `install_extras` | Any extras to install from the local repository through 'pip'. Must be encapsulated in square parentheses (`[]`) and be separated by commas (`,`) without any spaces.</br></br>**Example**: `'[dev,docs]'`. | No | _Empty string_ | _string_ |
| `package_dir` | Path to the Python package directory relative to the repository directory.</br></br>**Example**: `'src/my_package'`. | **Yes, if `update_python_api_ref` is `true` (default)** | _Empty string_ | _string_ |
| `exclude_dirs` | A single or multi-line string of directories to exclude in the Python API reference documentation. Note, only directory names, not paths, may be included. Note, all folders and their contents with these names will be excluded. Defaults to `'__pycache__'`.</br></br>**Important**: When a user value is set, the preset value is overwritten - hence `'__pycache__'` should be included in the user value if one wants to exclude these directories. | No | \_\_pycache\_\_ | _string_ |
| `exclude_files` | A single or multi-line string of files to exclude in the Python API reference documentation. Note, only full file names, not paths, may be included, i.e., filename + file extension. Note, all files with these names will be excluded. Defaults to `'__init__.py'`.</br></br>**Important**: When a user value is set, the preset value is overwritten - hence `'__init__.py'` should be included in the user value if one wants to exclude these files. | No | \_\_init\_\_.py | _string_ |
| `full_docs_dirs` | A single or multi-line string of directories in which to include everything - even those without documentation strings. This may be useful for a module full of data models or to ensure all class attributes are listed. | No | _Empty string_ | _string_ |
| `landing_page_replacements` | A single or multi-line string of replacements (mappings) to be performed on README.md when creating the documentation's landing page (index.md). This list _always_ includes replacing `'docs/'` with an empty string to correct relative links, i.e., this cannot be overwritten. By default `'(LICENSE)'` is replaced by `'(LICENSE.md)'`. | No | (LICENSE),(LICENSE.md) | _string_ |
| `landing_page_replacement_separator` | String to separate a mapping's 'old' to 'new' parts. Defaults to a comma (`,`). | No | , | _string_ |
| `debug` | The package build command, e.g., `'flit build'` or `'python -m build'` (default). | No | `python -m build` | _string_ |

## Usage example

The following is an example of how a workflow may look that calls _CI - Tests_.
It is meant to be complete as is.

```yaml
name: CI - Tests

on:
  pull_request:
  pull:
    branches:
    - 'main'

jobs:
  tests:
    name: Run basic tests
    uses: CasperWA/ci-cd/.github/workflows/ci_tests.yml@v1
    with:
      python_version: "3.8"
      install_extras: "[dev,docs]"
      skip_pre-commit_hooks: pylint
      pylint_options: --rcfile=pyproject.toml
      pylint_targets: my_python_package
      build_libs: flit
      build_cmd: flit build
      update_python_api_ref: false
      update_docs_landing_page: false
```

Here is another example using `pylint_runs` instead of `pylint_targets` and `pylint_options`.

```yaml
name: CI - Tests

on:
  pull_request:
  pull:
    branches:
    - 'main'

jobs:
  tests:
    name: Run basic tests
    uses: CasperWA/ci-cd/.github/workflows/ci_tests.yml@v1
    with:
      python_version: "3.8"
      install_extras: "[dev,docs]"
      skip_pre-commit_hooks: pylint
      pylint_runs: |
        --rcfile=pyproject.toml --ignore-paths=tests/ my_python_package
        --rcfile=pyproject.toml --disable=import-outside-toplevel,redefined-outer-name tests
      build_libs: flit
      build_cmd: flit build
      update_python_api_ref: false
      update_docs_landing_page: false
```

## Full list of inputs

Here follows the full list of inputs available for this workflow.
However, it is recommended to instead refer to the job-specific tables of inputs when considering which inputs to provide.

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `run_pre-commit` | Run the `pre-commit` test job. | No | `true` | _boolean_ |
| `skip_pre-commit_hooks` | A comma-separated list of pre-commit hook IDs to skip when running `pre-commit` after updating hooks. | No | _Empty string_ | _string_ |
| `run_pylint` | Run the `pylint` test job. | No | `true` | _boolean_ |
| `run_safety` | Run the `safety` test job. | No | `true` | _boolean_ |
| `pylint_targets` | Space-separated string of pylint file and folder targets.</br></br>**Note**, this is only valid if `pylint_runs` is not defined. | **Yes, if `pylint_runs` is not defined** | _Empty string_ | _string_ |
| `pylint_options` | Single space-separated or multi-line string of pylint command line options.</br></br>**Note**, this is only valid if `pylint_runs` is not defined. | No | _Empty string_ | _string_ |
| `pylint_runs` | Single or multi-line string with each line representing a separate pylint run/execution. This should include all desired options and targets.</br></br>**Important**, the inputs `pylint_options` and `pylint_targets` will be ignored if this is defined. | No | _Empty string_ | _string_ |
| `safety_options` | Single space-separated or multi-line string of safety command line options. | No | _Empty string_ | _string_ |
| `run_build_package` | Run the `build package` test job. | No | `true` | _boolean_ |
| `build_libs` | A space-separated list of packages to install via PyPI (`pip install`). | No | _Empty string_ | _string_ |
| `build_cmd` | The package build command, e.g., `'flit build'` or `'python -m build'` (default). | No | `python -m build` | _string_ |
| `run_build_docs` | Run the `build package` test job. | No | `true` | _boolean_ |
| `update_python_api_ref` | Whether or not to update the Python API documentation reference.</br></br>**Note**: If this is `true`, `package_dir` is _required_. | No | `true` | _boolean_ |
| `update_docs_landing_page` | Whether or not to update the documentation landing page. The landing page will be based on the root README.md file. | No | `true` | _boolean_ |
| `python_version` | The Python version to use for the workflow. | No | 3.9 | _string_ |
| `install_extras` | Any extras to install from the local repository through 'pip'. Must be encapsulated in square parentheses (`[]`) and be separated by commas (`,`) without any spaces.</br></br>**Example**: `'[dev,docs]'`. | No | _Empty string_ | _string_ |
| `package_dir` | Path to the Python package directory relative to the repository directory.</br></br>**Example**: `'src/my_package'`. | **Yes, if `update_python_api_ref` is `true` (default)** | _Empty string_ | _string_ |
| `exclude_dirs` | A single or multi-line string of directories to exclude in the Python API reference documentation. Note, only directory names, not paths, may be included. Note, all folders and their contents with these names will be excluded. Defaults to `'__pycache__'`.</br></br>**Important**: When a user value is set, the preset value is overwritten - hence `'__pycache__'` should be included in the user value if one wants to exclude these directories. | No | \_\_pycache\_\_ | _string_ |
| `exclude_files` | A single or multi-line string of files to exclude in the Python API reference documentation. Note, only full file names, not paths, may be included, i.e., filename + file extension. Note, all files with these names will be excluded. Defaults to `'__init__.py'`.</br></br>**Important**: When a user value is set, the preset value is overwritten - hence `'__init__.py'` should be included in the user value if one wants to exclude these files. | No | \_\_init\_\_.py | _string_ |
| `full_docs_dirs` | A single or multi-line string of directories in which to include everything - even those without documentation strings. This may be useful for a module full of data models or to ensure all class attributes are listed. | No | _Empty string_ | _string_ |
| `landing_page_replacements` | A single or multi-line string of replacements (mappings) to be performed on README.md when creating the documentation's landing page (index.md). This list _always_ includes replacing `'docs/'` with an empty string to correct relative links, i.e., this cannot be overwritten. By default `'(LICENSE)'` is replaced by `'(LICENSE.md)'`. | No | (LICENSE),(LICENSE.md) | _string_ |
| `landing_page_replacement_separator` | String to separate a mapping's 'old' to 'new' parts. Defaults to a comma (`,`). | No | , | _string_ |
| `debug` | The package build command, e.g., `'flit build'` or `'python -m build'` (default). | No | `python -m build` | _string_ |
