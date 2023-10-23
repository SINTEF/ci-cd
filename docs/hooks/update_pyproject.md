# Update dependencies in `pyproject.toml`

**pre-commit hook _id_:** `update-pyproject`

Run this hook to update the dependencies in your `pyproject.toml` file.

The hook utilizes `pip index versions` to determine the latest version available for all required and optional dependencies listed in your `pyproject.toml` file.
It checks this based on the Python version listed as the minimum supported Python version by the package (defined through the `requires-python` key in your `pyproject.toml` file).

## Ignoring dependencies

To ignore or configure how specific dependencies should be updated, the `--ignore` argument option can be utilized.
This is done by specifying a line per dependency that contains `--ignore-separator`-separated (defaults to ellipsis (`...`)) key/value-pairs of:

| **Key** | **Description** |
|:---:|:--- |
| `dependency-name` | Ignore updates for dependencies with matching names, optionally using `*` to match zero or more characters. |
| `versions` | Ignore specific versions or ranges of versions. Examples: `~=1.0.5`, `>= 1.0.5,<2`, `>=0.1.1`. |
| `update-types` | Ignore types of updates, such as [SemVer](https://semver.org) `major`, `minor`, `patch` updates on version updates (for example: `version-update:semver-patch` will ignore patch updates). This can be combined with `dependency-name=*` to ignore particular `update-types` for all dependencies. |

!!! note "Supported `update-types` values"
    Currently, only `version-update:semver-major`, `version-update:semver-minor`, and `version-update:semver-patch` are supported options for `update-types`.

The `--ignore` option is essentially similar to [the `ignore` option of Dependabot](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file#ignore).
If `versions` and `update-types` are used together, they will both be respected jointly.

Here are some examples of different values that may be given for the `--ignore` option that accomplishes different things:

- _Value_: `dependency-name=Sphinx...versions=>=4.5.0`  
  _Accomplishes_: For Sphinx, ignore all updates for/from version 4.5.0 and up / keep the minimum version for Sphinx at 4.5.0.

- _Value_: `dependency-name=pydantic...update-types=version-update:semver-patch`  
  _Accomplishes_: For pydantic, ignore all patch updates.

- _Value_: `dependency-name=numpy`  
  _Accomplishes_: For NumPy, ignore any and all updates.

[Below](#usage-example) is a usage example, where some of the example values above are implemented.

## Expectations

It is **required** that the root `pyproject.toml` exists.

A minimum Python version for the Python package should be specified in the `pyproject.toml` file through the `requires-python` key.

An active internet connection and for PyPI not to be down.

## Options

Any of these options can be given through the `args` key when defining the hook.

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `--root-repo-path` | A resolvable path to the root directory of the repository folder, where the `pyproject.toml` file can be found. | No | `.` | _string_ |
| `--fail-fast` | Fail immediately if an error occurs. Otherwise, print and ignore all non-critical errors. | No | `False` | _boolean_ |
| `--ignore` | Ignore-rules based on the `ignore` config option of Dependabot.</br></br>It should be of the format: `key=value...key=value`, i.e., an ellipsis (`...`) separator and then equal-sign-separated key/value-pairs.</br>Alternatively, the `--ignore-separator` can be set to something else to overwrite the ellipsis.</br></br>The only supported keys are: `dependency-name`, `versions`, and `update-types`.</br></br>Can be supplied multiple times per `dependency-name`. | No | | _string_ |
| `--ignore-separator` | Value to use instead of ellipsis (`...`) as a separator in `--ignore` key/value-pairs. | No | | _string_ |
| `--verbose` | Whether or not to print debug statements. | No | `False` | _boolean_ |

## Usage example

The following is an example of how an addition of the _Update dependencies in `pyproject.toml`_ hook into a `.pre-commit-config.yaml` file may look.
It is meant to be complete as is.

```yaml
repos:
  - repo: https://github.com/SINTEF/ci-cd
    rev: v2.5.2
    hooks:
    - id: update-pyproject
      args:
      - --fail-fast
      - --ignore-separator=//
      - --ignore
      - dependency-name=Sphinx//versions=>=4.5.0
      - --ignore
      - dependency-name=numpy
```
