# Update Landing Page (index.md) for Documentation

**pre-commit hook _id_:** `docs-landing-page`

Run this hook to update the landing page (root `index.md` file) for your documentation.

The hook copies the root `README.md` file into the root of your documentation folder, renaming it to `index.md` and implementing any replacements specified.

The hook will run when the root `README.md` file is changed in the repository.

The hook expects the documentation to be a framework that can build markdown files for deploying a documentation site.

## Expectations

It is **required** that the root `README.md` exists and the documentation's landing page is named `index.md` and can be found in the root of the documentation folder.

## Options

Any of these options can be given through the `args` key when defining the hook.

| **Name** | **Description** | **Required** | **Default** | **Type** |
|:--- |:--- |:---:|:---:|:---:|
| `--docs-folder` | The folder name for the documentation root folder. | No | docs | _string_ |
| `--replacements` | List of replacements (mappings) to be performed on `README.md` when creating the documentation's landing page (`index.md`). This list _always_ includes replacing '`--docs-folder`/' with an empty string to correct relative links. | No | (LICENSE),(LICENSE.md) | _string_ |
| `--replacements-separator` | String to separate replacement mappings from the `--replacements` input. Defaults to a pipe (`\|`). | No | \| | _string_ |
| `--internal-separator` | String to separate a single mapping's 'old' to 'new' statement. Defaults to a comma (`,`). | No | , | _string_ |

## Usage example

The following is an example of how an addition of the _Update Landing Page (index.md) for Documentation_ hook into a `.pre-commit-config.yaml` file may look.
It is meant to be complete as is.

```yaml
repos:
  - repo: https://github.com/CasperWA/ci-cd
    rev: v1
    hooks:
    - id: docs-landing-page
      args:
      # Replace `(LICENSE)` with `(LICENSE.md)` (i.e., don't overwrite the default)
      # Replace `(tools/` with `(`
      - '--replacements="(LICENSE);(LICENSE.md)|(tools/;("'
      - '--internal-separator=;'
```
