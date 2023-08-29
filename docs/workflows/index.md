# GitHub Actions callable/reusable Workflows

<!-- markdownlint-disable MD046 -->

This section contains all the available callable/reusable workflows:

- [CD - Release (`cd_release.yml`)](./cd_release.md)
- [CI - Activate auto-merging for PRs (`ci_automerge_prs.yml`)](./ci_automerge_prs.md)
- [CI/CD - New updates to default branch (`ci_cd_updated_default_branch.yml`))](./ci_cd_updated_default_branch.md)
- [CI - Check pyproject.toml dependencies (`ci_check_pyproject_dependencies.yml`)](./ci_check_pyproject_dependencies.md)
- [CI - Tests (`ci_tests.yml`)](./ci_tests.md)
- [CI - Update dependencies PR (`ci_update_dependencies.yml`)](./ci_update_dependencies.md)

## General information

### Single vs multi-line input

For inputs specifying single or multi-line input values, the following rules apply:

1. If only "multi-line" is mentioned, it means that the input value _can_ be a single line, but it **must not** be a multi-valued single line (see [examples below](#multi-line-input)).
2. If only "single" is mentioned, it means that the input value **must** be a single line (the workflow might fail if it is not).

    !!! note

        There is currently no input parameter that is explicitly single line only.
        Instead, one should consider the input parameter to be single line only if it is not explicitly mentioned as multi-line.

3. If both "single" and "multi-line" is mentioned, it means that multiple values can be specified, but they must be separated _either_ over several, separate lines **or** within a single line by a space.

Here are some examples:

#### Multi-line input

**Accepted** input styles:

```yaml
# Two separate version update changes:
version_update_changes: |
  "file/path,pattern,replacement string"
  "another/file/path,pattern,replacement string"

# A single version update change
version_update_changes: |
  "file/path,pattern,replacement string"

# A single version update change, different formatting for input
version_update_changes: "file/path,pattern,replacement string"
```

**Disallowed** input styles:

```yaml
# Two separate version update changes:
version_update_changes: "file/path,pattern,replacement string another/file/path,pattern,replacement string"
```

#### Single line input

**Accepted** input styles:

```yaml
# A single git username:
git_username: "Casper Welzel Andersen"

# A single git username, different formatting for input
git_username: |
  "Casper Welzel Andersen"
```

**Disallowed** input styles:

```yaml
# Two separate git usernames:
git_username: |
  "Casper Welzel Andersen"
  "Francesca L. Bleken"

# Two separate git usernames, different formatting for input
git_username: "Casper Welzel Andersen Francesca L. Bleken"
```

!!! warning

    It is important to note that the disallowed examples will work without fault in this case (might not always be true for other parameters).
    But the git username will be a single string, combining the names in succession, instead of being two separate values.

#### Single or multi-line input

**Accepted** input styles:

```yaml
# A single system dependency:
system_dependencies: "graphviz"

# A single system dependency, different formatting for input
system_dependencies: |
  "graphviz"

# Two separate system dependencies:
system_dependencies: |
  "graphviz"
  "Sphinx"

# Two separate system dependencies, different formatting for input
system_dependencies: "graphviz Sphinx"
```

**Disallowed** input styles:

```yaml
# Use of custom separator:
system_dependencies: "graphviz,Sphinx"
```
