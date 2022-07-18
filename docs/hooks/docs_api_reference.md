# Update API Reference in Documentation

**pre-commit hook _id_:** `docs-api-reference`

Run this hook to update the API Reference section of your documentation.

The hook walks through a package directory, finding all Python files and creating a markdown file matching it along with recreating the Python API tree under the `docs/api_reference/` folder.

The hook will run when any Python file is changed in the repository.

The hook expects the documentation to be setup with the [MkDocs](https://www.mkdocs.org) framework, including the [mkdocstrings](https://mkdocstrings.github.io/) plugin for parsing in the Python class/function and method doc-strings, as well as the [awesome-pages](https://github.com/lukasgeiter/mkdocs-awesome-pages-plugin) plugin for providing proper titles in the table-of-contents navigation.

## Expectations

It is **required** to specify the `--package-dir` argument through the `args` key.

Otherwise, as noted above, without the proper framework, the created markdown files will not bring about the desired result in a built documentation.

## Options

Any of these options can be given through the `args` key when defining the hook.

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `--package-dir` | Relative path to package dir from the repository root, e.g., 'src/my_package'. | **_Yes_** | | _string_ |
| `--docs-folder` | The folder name for the documentation root folder. | No | docs | _string_ |
| `--unwanted-folder` | A folder to avoid including into the Python API reference documentation. If this is not supplied, it will default to `__pycache__`.</br></br>**Note**: Only folder names, not paths, may be included.</br></br>**Note**: All folders and their contents with these names will be excluded.</br></br>This input option can be supplied multiple times. | No | \_\_pycache\_\_ | _string_ |
| `--unwanted-file` | A file to avoid including into the Python API reference documentation. If this is not supplied, it will default to `__init__.py`</br></br>**Note**: Only full file names, not paths, may be included, i.e., filename + file extension.</br></br>**Note**: All files with these names will be excluded.</br></br>This input option can be supplied multiple times. | No | \_\_init\_\_.py | _string_ |
| `--full-docs-folder` | A folder in which to include everything - even those without documentation strings. This may be useful for a module full of data models or to ensure all class attributes are listed.</br></br>This input option can be supplied multiple times. | No | _Empty string_ | _string_ |
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
      - my_python_package
      - --full-docs-folder
      - models
      - --full-docs-folder
      - data
```
