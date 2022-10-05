# Update API Reference in Documentation

**pre-commit hook _id_:** `docs-api-reference`

Run this hook to update the API Reference section of your documentation.

The hook walks through a package directory, finding all Python files and creating a markdown file matching it along with recreating the Python API tree under the `docs/api_reference/` folder.

The hook will run when any Python file is changed in the repository.

The hook expects the documentation to be setup with the [MkDocs](https://www.mkdocs.org) framework, including the [mkdocstrings](https://mkdocstrings.github.io/) plugin for parsing in the Python class/function and method doc-strings, as well as the [awesome-pages](https://github.com/lukasgeiter/mkdocs-awesome-pages-plugin) plugin for providing proper titles in the table-of-contents navigation.

## Using it together with CI/CD workflows

If this hook is being used together with the workflow [_CI - Tests_](../workflows/ci_tests.md#build-mkdocs-documentation), to test if the documentation can be built, or [_CD - Release_](../workflows/cd_release.md) and/or [_CI/CD - New updates to default branch_](../workflows/ci_cd_updated_default_branch.md), to build and publish the documentation upon a release or push to the default branch, it is necessary to understand the way the Python API modules are referenced in the markdown files under `docs/api_reference/`.

By default, the references refer to the Python import path of a module.
However, should a package be installed as an editable installation, i.e., using `pip install -e`, then the relative path from the repository root will be used.

This differentiation is only relevant for repositories, where these two cases are not aligned, such as when the Python package folder is in a nested folder, e.g., `src/my_package/`.

In order to remedy this, there are a single configuration in each workflow and this hooks that needs to be set to the same value.
For this hook, the option name is `--relative` and the value for using the relative path, i.e., an editable installation, is to simply include this toggle option.
If the option is _not_ included, then a non-editable installation is assumed, i.e., the `-e` option is _not_ used when installing the package, and a proper resolvable Python import statement is used as a link in the API reference markdown files.
The latter is the default.

For the workflows, one should set the configuration option `relative` to `true` to use the relative path, i.e., an editable installation.
And likewise set `relative` to `false` if a proper resolvable Python import statement is to be used, without forcing the `-e` option.
The latter is the default.

## Expectations

It is **required** to specify the `--package-dir` argument at least once through the `args` key.

Otherwise, as noted above, without the proper framework, the created markdown files will not bring about the desired result in a built documentation.

## Options

Any of these options can be given through the `args` key when defining the hook.

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `--package-dir` | Relative path to a package dir from the repository root, e.g., 'src/my_package'.</br></br>This input option can be supplied multiple times. | **_Yes_** | | _string_ |
| `--docs-folder` | The folder name for the documentation root folder. | No | docs | _string_ |
| `--unwanted-folder` | A folder to avoid including into the Python API reference documentation. If this is not supplied, it will default to `__pycache__`.</br></br>**Note**: Only folder names, not paths, may be included.</br></br>**Note**: All folders and their contents with these names will be excluded.</br></br>This input option can be supplied multiple times. | No | \_\_pycache\_\_ | _string_ |
| `--unwanted-file` | A file to avoid including into the Python API reference documentation. If this is not supplied, it will default to `__init__.py`</br></br>**Note**: Only full file names, not paths, may be included, i.e., filename + file extension.</br></br>**Note**: All files with these names will be excluded.</br></br>This input option can be supplied multiple times. | No | \_\_init\_\_.py | _string_ |
| `--full-docs-folder` | A folder in which to include everything - even those without documentation strings. This may be useful for a module full of data models or to ensure all class attributes are listed.</br></br>This input option can be supplied multiple times. | No | _Empty string_ | _string_ |
| `--full-docs-file` | A full relative path to a file in which to include everything - even those without documentation strings. This may be useful for a file full of data models or to ensure all class attributes are listed.</br></br>This input option can be supplied multiple times. | No | _Empty string_ | _string_ |
| `--special-option` | A combination of a relative path to a file and a fully formed mkdocstrings option that should be added to the generated MarkDown file. The combination should be comma-separated.</br>Example:
`my_module/py_file.py,show_bases:false`.</br></br>Encapsulate the value in double quotation marks (`"`) if including spaces ( ).</br></br>**Important**: If multiple package-dir options are supplied, the relative path MUST include/start with the package-dir value, e.g., `"my_package/my_module/py_file.py,show_bases: false"`.</br></br>This input option can be supplied multiple times. The options will be accumulated
for the same file, if given several times. | No | _Empty string_ | _string_ |
| `--relative` | Whether or not to use relative Python import links in the API reference markdown files. See section [Using it together with CI/CD workflows](#using-it-together-with-cicd-workflows) above. | No | `False` | _boolean_ |
| `--debug` | Whether or not to print debug statements. | No | `False` | _boolean_ |

## Usage example

The following is an example of how an addition of the _Update API Reference in Documentation_ hook into a `.pre-commit-config.yaml` file may look.
It is meant to be complete as is.

```yaml
repos:
  - repo: https://github.com/SINTEF/ci-cd
    rev: v1
    hooks:
    - id: docs-api-reference
      args:
      - --package-dir
      - src/my_python_package
      - --package-dir
      - src/my_other_python_package
      - --full-docs-folder
      - models
      - --full-docs-folder
      - data
```
