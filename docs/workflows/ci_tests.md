# CI - Tests
<!-- markdownlint-disable MD024 MD046 -->

**File to use:** `ci_tests.yml`

A basic set of CI tests.

Several different basic test jobs are available in this workflow.
By default, they will all run and should be actively "turned off".

## CI jobs

The following sections summarizes each job and the individual inputs necessary for it to function or to adjust how it runs.
Note, a full list of possible inputs and secrets will be given in a separate table at the end of this page.

### Global/General inputs

These inputs are general and apply to all jobs in this workflow.

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `runner` | The runner to use for the workflow. Note, the callable workflow expects a Linux/Unix system.. | No | ubuntu-latest | _string_ |
| `install_extras` | Any extras to install from the local repository through 'pip'. Must be encapsulated in square parentheses (`[]`) and be separated by commas (`,`) without any spaces.</br></br>Example: `'[dev,pre-commit]'`. | No | _Empty string_ | _string_ |

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
| `python_version_pre-commit` | The Python version to use for the `pre-commit` test job. | No | 3.9 | _string_ |
| `pip_index_url_pre-commit` | A URL to a PyPI repository index. | No | `https://pypi.org/simple/` | _string_ |
| `pip_extra_index_urls_pre-commit` | A space-delimited string of URLs to additional PyPI repository indices. | No | _Empty string_ | _string_ |
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
| `python_version_pylint_safety` | The Python version to use for the `pylint` and `safety` test jobs. | No | 3.9 | _string_ |
| `pip_index_url_pylint_safety` | A URL to a PyPI repository index. | No | `https://pypi.org/simple/` | _string_ |
| `pip_extra_index_urls_pylint_safety` | A space-delimited string of URLs to additional PyPI repository indices. | No | _Empty string_ | _string_ |
| `pylint_targets` | Space-separated string of pylint file and folder targets.</br></br>**Note**: This is only valid if `pylint_runs` is not defined. | **Yes, if `pylint_runs` is not defined** | _Empty string_ | _string_ |
| `pylint_options` | Single (space-separated) or multi-line string of pylint command line options.</br></br>**Note**: This is only valid if `pylint_runs` is not defined.</br></br>See also [Single vs multi-line input](index.md#single-vs-multi-line-input). | No | _Empty string_ | _string_ |
| `pylint_runs` | Multi-line string with each line representing a separate pylint run/execution. This should include all desired options and targets.</br></br>**Important**: The inputs `pylint_options` and `pylint_targets` will be ignored if this is defined.</br></br>See also [Single vs multi-line input](index.md#single-vs-multi-line-input). | No | _Empty string_ | _string_ |
| `safety_options` | Single (space-separated) or multi-line string of safety command line options.</br></br>See also [Single vs multi-line input](index.md#single-vs-multi-line-input). | No | _Empty string_ | _string_ |

### Build distribution package

Test building the Python package.

This job is equivalent to building the package in the [_CD - Release_](./cd_release.md) workflow, but will not publish anything.

#### Expectations

The repository should be a "buildable" Python package.

#### Inputs

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `run_build_package` | Run the `build package` test job. | No | `true` | _boolean_ |
| `python_version_package` | The Python version to use for the `build package` test job. | No | 3.9 | _string_ |
| `pip_index_url_package` | A URL to a PyPI repository index. | No | `https://pypi.org/simple/` | _string_ |
| `pip_extra_index_urls_package` | A space-delimited string of URLs to additional PyPI repository indices. | No | _Empty string_ | _string_ |
| `build_libs` | A space-separated list of packages to install via PyPI (`pip install`). | No | _Empty string_ | _string_ |
| `build_cmd` | The package build command, e.g., `'flit build'` or `'python -m build'` (default). | No | `python -m build` | _string_ |

### Build Documentation

Test building the documentation.

Two frameworks are supported: [MkDocs](https://www.mkdocs.org) and [Sphinx](https://www.sphinx-doc.org/).

By **default** the MkDocs framework is used.
To use the Sphinx framework set the input `use_sphinx` to `true`.
The input `use_mkdocs` can also explicitly be set to `true` for more transparent documentation in your workflow.

Note, if both `use_sphinx` and `use_mkdocs` are `false` (as is the default value for both), the workflow will fallback to using MkDocs, i.e., it is equivalent to setting `use_mkdocs` to `true`.

!!! note "For _MkDocs_ users"
    If using [mike](https://github.com/jimporter/mike), note that this will _not_ be tested, as this would be equivalent to testing mike itself and whether it can build a MkDocs documentation, which should never be part of a repository that uses these tools.

    If used together with the [Update API Reference in Documentation](../hooks/docs_api_reference.md#using-it-together-with-cicd-workflows), please align the `relative` input with the `--relative` option, when running the hook.
    See the [proper section](../hooks/docs_api_reference.md#using-it-together-with-cicd-workflows) to understand why and how these options and inputs should be aligned.

#### Expectations

Is is expected that documentation exists, which is using either the MkDocs framework or the Sphinx framework.
For MkDocs, this requires at minimum a `mkdocs.yml` configuration file.
For Sphinx, it requires at minimum the files created from running `sphinx-quickstart`.

#### Inputs

General inputs for building the documentation:

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `run_build_docs` | Run the `build package` test job. | No | `true` | _boolean_ |
| `python_version_docs` | The Python version to use for the `build documentation` test job. | No | 3.9 | _string_ |
| `pip_index_url_docs` | A URL to a PyPI repository index. | No | `https://pypi.org/simple/` | _string_ |
| `pip_extra_index_urls_docs` | A space-delimited string of URLs to additional PyPI repository indices. | No | _Empty string_ | _string_ |
| `relative` | Whether or not to use the locally installed Python package(s), and install it as an editable. | No | `false` | _boolean_ |
| `system_dependencies` | A single (space-separated) or multi-line string of Ubuntu APT packages to install prior to building the documentation.</br></br>See also [Single vs multi-line input](index.md#single-vs-multi-line-input). | No | _Empty string_ | _string_ |
| `warnings_as_errors` | Build the documentation in 'strict' mode, treating warnings as errors.</br></br>**Important**: If this is set to `false`, beware that the documentation may _not_ be rendered or built as one may have intended.</br></br>Default: `true`. | No | `true` | _boolean_ |
| `use_mkdocs` | Whether or not to build the documentation using the MkDocs framework. Mutually exclusive with `use_sphinx`. | No | `false` | _boolean_ |
| `use_sphinx` | Whether or not to build the documentation using the Sphinx framework. Mutually exclusive with `use_mkdocs`. | No | `false` | _boolean_ |

MkDocs-specific inputs:

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `update_python_api_ref` | Whether or not to update the Python API documentation reference.</br></br>**Note**: If this is `true`, `package_dirs` is _required_. | No | `true` | _boolean_ |
| `update_docs_landing_page` | Whether or not to update the documentation landing page. The landing page will be based on the root README.md file. | No | `true` | _boolean_ |
| `package_dirs` | A multi-line string of path to Python package directories relative to the repository directory to be considered for creating the Python API reference documentation.</br></br>**Example**: `'src/my_package'`.</br></br>See also [Single vs multi-line input](index.md#single-vs-multi-line-input). | **Yes, if `update_python_api_ref` is `true` (default)** | _Empty string_ | _string_ |
| `exclude_dirs` | A multi-line string of directories to exclude in the Python API reference documentation. Note, only directory names, not paths, may be included. Note, all folders and their contents with these names will be excluded. Defaults to `'__pycache__'`.</br></br>**Important**: When a user value is set, the preset value is overwritten - hence `'__pycache__'` should be included in the user value if one wants to exclude these directories.</br></br>See also [Single vs multi-line input](index.md#single-vs-multi-line-input). | No | \_\_pycache\_\_ | _string_ |
| `exclude_files` | A multi-line string of files to exclude in the Python API reference documentation. Note, only full file names, not paths, may be included, i.e., filename + file extension. Note, all files with these names will be excluded. Defaults to `'__init__.py'`.</br></br>**Important**: When a user value is set, the preset value is overwritten - hence `'__init__.py'` should be included in the user value if one wants to exclude these files.</br></br>See also [Single vs multi-line input](index.md#single-vs-multi-line-input). | No | \_\_init\_\_.py | _string_ |
| `full_docs_dirs` | A multi-line string of directories in which to include everything - even those without documentation strings. This may be useful for a module full of data models or to ensure all class attributes are listed.</br></br>See also [Single vs multi-line input](index.md#single-vs-multi-line-input). | No | _Empty string_ | _string_ |
| `full_docs_files` | A multi-line string of relative paths to files in which to include everything - even those without documentation strings. This may be useful for a file full of data models or to ensure all class attributes are listed.</br></br>See also [Single vs multi-line input](index.md#single-vs-multi-line-input). | No | _Empty string_ | _string_ |
| `special_file_api_ref_options` | A multi-line string of combinations of a relative path to a Python file and a fully formed mkdocstrings option that should be added to the generated MarkDown file for the Python API reference documentation.</br>Example: `my_module/py_file.py,show_bases:false`.</br></br>Encapsulate the value in double quotation marks (`"`) if including spaces ( ).</br></br>**Important**: If multiple `package_dirs` are supplied, the relative path MUST include/start with the appropriate 'package_dir' value, e.g., `"my_package/my_module/py_file.py,show_bases: false"`.</br></br>See also [Single vs multi-line input](index.md#single-vs-multi-line-input). | No | _Empty string_ | _string_ |
| `landing_page_replacements` | A multi-line string of replacements (mappings) to be performed on README.md when creating the documentation's landing page (index.md). This list _always_ includes replacing `'docs/'` with an empty string to correct relative links, i.e., this cannot be overwritten. By default `'(LICENSE)'` is replaced by `'(LICENSE.md)'`.</br></br>See also [Single vs multi-line input](index.md#single-vs-multi-line-input). | No | (LICENSE),(LICENSE.md) | _string_ |
| `landing_page_replacement_separator` | String to separate a mapping's 'old' to 'new' parts. Defaults to a comma (`,`). | No | , | _string_ |
| `debug` | Whether to do print extra debug statements. | No | `false` | _boolean_ |

Sphinx-specific inputs:

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `sphinx-build_options` | Single (space-separated) or multi-line string of command-line options to use when calling `sphinx-build`.</br></br>**Note**: The `-W` option will be added if `warnings_as_errors` is `true` (default).</br></br>See also [Single vs multi-line input](index.md#single-vs-multi-line-input). | No | _Empty string_ | _string_ |
| `docs_folder` | The path to the root documentation folder relative to the repository root. | No | docs | _string_ |
| `build_target_folder` | The path to the target folder for the documentation build relative to the repository root. | No | site | _string_ |

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
    uses: SINTEF/ci-cd/.github/workflows/ci_tests.yml@v2.8.3
    with:
      python_version_pylint_safety: "3.8"
      python_version_docs: "3.9"
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
    uses: SINTEF/ci-cd/.github/workflows/ci_tests.yml@v2.8.3
    with:
      python_version_pylint_safety: "3.8"
      python_version_docs: "3.9"
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

See also [General information](index.md#general-information).

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `runner` | The runner to use for the workflow. Note, the callable workflow expects a Linux/Unix system.. | No | ubuntu-latest | _string_ |
| `install_extras` | Any extras to install from the local repository through 'pip'. Must be encapsulated in square parentheses (`[]`) and be separated by commas (`,`) without any spaces.</br></br>Example: `'[dev,pre-commit]'`. | No | _Empty string_ | _string_ |
| `run_pre-commit` | Run the `pre-commit` test job. | No | `true` | _boolean_ |
| `python_version_pre-commit` | The Python version to use for the `pre-commit` test job. | No | 3.9 | _string_ |
| `pip_index_url_pre-commit` | A URL to a PyPI repository index. | No | `https://pypi.org/simple/` | _string_ |
| `pip_extra_index_urls_pre-commit` | A space-delimited string of URLs to additional PyPI repository indices. | No | _Empty string_ | _string_ |
| `skip_pre-commit_hooks` | A comma-separated list of pre-commit hook IDs to skip when running `pre-commit` after updating hooks. | No | _Empty string_ | _string_ |
| `run_pylint` | Run the `pylint` test job. | No | `true` | _boolean_ |
| `run_safety` | Run the `safety` test job. | No | `true` | _boolean_ |
| `python_version_pylint_safety` | The Python version to use for the `pylint` and `safety` test jobs. | No | 3.9 | _string_ |
| `pip_index_url_pylint_safety` | A URL to a PyPI repository index. | No | `https://pypi.org/simple/` | _string_ |
| `pip_extra_index_urls_pylint_safety` | A space-delimited string of URLs to additional PyPI repository indices. | No | _Empty string_ | _string_ |
| `pylint_targets` | Space-separated string of pylint file and folder targets.</br></br>**Note**: This is only valid if `pylint_runs` is not defined. | **Yes, if `pylint_runs` is not defined** | _Empty string_ | _string_ |
| `pylint_options` | Single (space-separated) or multi-line string of pylint command line options.</br></br>**Note**: This is only valid if `pylint_runs` is not defined. | No | _Empty string_ | _string_ |
| `pylint_runs` | Single or multi-line string with each line representing a separate pylint run/execution. This should include all desired options and targets.</br></br>**Important**: The inputs `pylint_options` and `pylint_targets` will be ignored if this is defined. | No | _Empty string_ | _string_ |
| `safety_options` | Single (space-separated) or multi-line string of safety command line options. | No | _Empty string_ | _string_ |
| `run_build_package` | Run the `build package` test job. | No | `true` | _boolean_ |
| `python_version_package` | The Python version to use for the `build package` test job. | No | 3.9 | _string_ |
| `pip_index_url_package` | A URL to a PyPI repository index. | No | `https://pypi.org/simple/` | _string_ |
| `pip_extra_index_urls_package` | A space-delimited string of URLs to additional PyPI repository indices. | No | _Empty string_ | _string_ |
| `build_libs` | A space-separated list of packages to install via PyPI (`pip install`). | No | _Empty string_ | _string_ |
| `build_cmd` | The package build command, e.g., `'flit build'` or `'python -m build'` (default). | No | `python -m build` | _string_ |
| `run_build_docs` | Run the `build package` test job. | No | `true` | _boolean_ |
| `python_version_docs` | The Python version to use for the `build documentation` test job. | No | 3.9 | _string_ |
| `pip_index_url_docs` | A URL to a PyPI repository index. | No | `https://pypi.org/simple/` | _string_ |
| `pip_extra_index_urls_docs` | A space-delimited string of URLs to additional PyPI repository indices. | No | _Empty string_ | _string_ |
| `relative` | Whether or not to use the locally installed Python package(s), and install it as an editable. | No | `false` | _boolean_ |
| `system_dependencies` | A single (space-separated) or multi-line string of Ubuntu APT packages to install prior to building the documentation. | No | _Empty string_ | _string_ |
| `warnings_as_errors` | Build the documentation in 'strict' mode, treating warnings as errors.</br></br>**Important**: If this is set to `false`, beware that the documentation may _not_ be rendered or built as one may have intended.</br></br>Default: `true`. | No | `true` | _boolean_ |
| `use_mkdocs` | Whether or not to build the documentation using the MkDocs framework. Mutually exclusive with `use_sphinx`. | No | `false` | _boolean_ |
| `use_sphinx` | Whether or not to build the documentation using the Sphinx framework. Mutually exclusive with `use_mkdocs`. | No | `false` | _boolean_ |
| `update_python_api_ref` | Whether or not to update the Python API documentation reference.</br></br>**Note**: If this is `true`, `package_dirs` is _required_. | No | `true` | _boolean_ |
| `update_docs_landing_page` | Whether or not to update the documentation landing page. The landing page will be based on the root README.md file. | No | `true` | _boolean_ |
| `package_dirs` | A multi-line string of path to Python package directories relative to the repository directory to be considered for creating the Python API reference documentation.</br></br>**Example**: `'src/my_package'`. | **Yes, if `update_python_api_ref` is `true` (default)** | _Empty string_ | _string_ |
| `exclude_dirs` | A multi-line string of directories to exclude in the Python API reference documentation. Note, only directory names, not paths, may be included. Note, all folders and their contents with these names will be excluded. Defaults to `'__pycache__'`.</br></br>**Important**: When a user value is set, the preset value is overwritten - hence `'__pycache__'` should be included in the user value if one wants to exclude these directories. | No | \_\_pycache\_\_ | _string_ |
| `exclude_files` | A multi-line string of files to exclude in the Python API reference documentation. Note, only full file names, not paths, may be included, i.e., filename + file extension. Note, all files with these names will be excluded. Defaults to `'__init__.py'`.</br></br>**Important**: When a user value is set, the preset value is overwritten - hence `'__init__.py'` should be included in the user value if one wants to exclude these files. | No | \_\_init\_\_.py | _string_ |
| `full_docs_dirs` | A multi-line string of directories in which to include everything - even those without documentation strings. This may be useful for a module full of data models or to ensure all class attributes are listed. | No | _Empty string_ | _string_ |
| `full_docs_files` | A multi-line string of relative paths to files in which to include everything - even those without documentation strings. This may be useful for a file full of data models or to ensure all class attributes are listed. | No | _Empty string_ | _string_ |
| `special_file_api_ref_options` | A multi-line string of combinations of a relative path to a Python file and a fully formed mkdocstrings option that should be added to the generated MarkDown file for the Python API reference documentation.</br>Example: `my_module/py_file.py,show_bases:false`.</br></br>Encapsulate the value in double quotation marks (`"`) if including spaces ( ).</br></br>**Important**: If multiple `package_dirs` are supplied, the relative path MUST include/start with the appropriate 'package_dir' value, e.g., `"my_package/my_module/py_file.py,show_bases: false"`. | No | _Empty string_ | _string_ |
| `landing_page_replacements` | A multi-line string of replacements (mappings) to be performed on README.md when creating the documentation's landing page (index.md). This list _always_ includes replacing `'docs/'` with an empty string to correct relative links, i.e., this cannot be overwritten. By default `'(LICENSE)'` is replaced by `'(LICENSE.md)'`. | No | (LICENSE),(LICENSE.md) | _string_ |
| `landing_page_replacement_separator` | String to separate a mapping's 'old' to 'new' parts. Defaults to a comma (`,`). | No | , | _string_ |
| `debug` | Whether to do print extra debug statements. | No | `false` | _boolean_ |
| `sphinx-build_options` | Single or multi-line string of command-line options to use when calling `sphinx-build`.</br></br>**Note**: The `-W` option will be added if `warnings_as_errors` is `true` (default). | No | _Empty string_ | _string_ |
| `docs_folder` | The path to the root documentation folder relative to the repository root. | No | docs | _string_ |
| `build_target_folder` | The path to the target folder for the documentation build relative to the repository root. | No | site | _string_ |
