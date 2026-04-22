# Agent Guidelines

## Development Setup

Install in editable mode with all dev dependencies:

```bash
pip install -e ".[dev]"
```

## Pre-commit

After editing any files, always run `pre-commit run -a` until it exits with success. If it keeps failing, inspect the output and fix the reported issues before retrying.

Always invoke `pre-commit` using the full path to the virtual environment binary rather than relying on a system-level installation. Use the first path that exists:

```bash
PRE_COMMIT=
for p in venv/bin/pre-commit .venv/bin/pre-commit ~/.venv/ci-cd/bin/pre-commit; do
  [ -x "$p" ] && { PRE_COMMIT="$p"; break; }
done
[ -n "$PRE_COMMIT" ] || { echo "pre-commit not found; ask the user for the correct path" >&2; exit 1; }
# Then invoke via the resolved path, e.g.:
"$PRE_COMMIT" run -a
```

If none of these exist, the guard will exit with an error. In that case, ask the user for the correct path before proceeding.

## Branching

Always create a new branch from an up-to-date `main` before making changes. Never commit directly to `main`.

```bash
git switch main && git pull origin main
git switch -c <initials>/<short-description>
```

Branch names follow the pattern `<initials>/<short-description>`, e.g. `cwa/add-reranker` or `tfh/fix-auth-timeout`. Both components use only lowercase letters and hyphens; `/` is the separator between them. Use the initials of the person you are working on behalf of; if unsure, derive them from `git config user.name` or ask. For branches created autonomously without a specific person to attribute them to, use `ai` as the prefix (e.g. `ai/fix-auth-timeout`).

## Commits

Write clear, imperative commit messages that describe *what* and *why*, not *how*. Keep the subject line under 72 characters. Reference relevant issue numbers where applicable (e.g. `Fix vectorizer cleanup (#123)`).

### Bot account

Each contributor working with an AI agent is encouraged to configure a dedicated GitHub bot account for AI-authored commits and PRs, so that AI activity is clearly distinguishable from human work in the repository history. The bot account to use, and how it is configured, is left to each contributor — a common approach is to set `GITHUB_TOKEN`, `GIT_AUTHOR_NAME`, `GIT_AUTHOR_EMAIL`, `GIT_COMMITTER_NAME`, and `GIT_COMMITTER_EMAIL` in the agent's environment so that commits and PRs are attributed to the bot without affecting the contributor's own git identity. Prefer a fine-grained PAT scoped to this repository with only the permissions the workflow actually needs (typically **Contents: read/write** and **Pull requests: read/write**), and avoid exposing it in logs or shell history. Store it in a secure secret store rather than in a shell profile or `.env` file.

## Testing

Run the test suite before opening a pull request:

```bash
pytest

# Run a single test file
pytest tests/tasks/test_setver.py

# Run a single test by name
pytest tests/tasks/test_setver.py -k "test_name"
```

Use the pytest binary from the virtual environment, following the same discovery order as for `pre-commit` above.

All tests must pass and no new warnings should be introduced — the suite is configured to treat warnings as errors.

## Pull Requests

Open pull requests against `main` on GitHub (`SINTEF/ci-cd`) using the `gh` CLI:

```bash
gh pr create --title "<title>" --base main --reviewer "@copilot" --body "$(cat <<'EOF'
<description>

## Squash commit message

<details>
<summary>Click to view squash commit message</summary>

> <initial commit message(s)>

</details>
EOF
)"
```

Request a review from Copilot (`@copilot`) whenever possible. If the reviewer cannot be added (e.g. the feature is not enabled on the repository, or the PR was opened by a bot account that lacks permission to request Copilot reviews), omit the `--reviewer` flag and continue without it. In the latter case, ask the human contributor to request the Copilot review manually from their own account.

After opening the PR, always verify that the Copilot review was actually requested — `gh pr create` can silently succeed without adding the reviewer:

```bash
gh pr view <number> --json reviewRequests -q '.reviewRequests[].login'
```

If `copilot` does not appear in the output, inform the user and ask them to request the Copilot review manually from their own account.

Requesting a Copilot review requires **GitHub CLI v2.88.0 or later**. Before opening a PR, verify the installed version:

```bash
gh --version
```

If the version is older than 2.88.0, report this to the user and suggest upgrading.

PRs are **squash-merged**. GitHub collects all commit messages into the squash commit body by default, but this is rarely well-structured. Instead, maintain a dedicated `## Squash commit message` section at the bottom of the PR description that is kept up to date as commits are added. When the PR is eventually merged, this section can be copy-pasted verbatim as the final commit message.

The canonical format for the section is:

```markdown
## Squash commit message

<details>
<summary>Click to view squash commit message</summary>

> Subject line here
>
> Optional body paragraph.

</details>
```

The `## Squash commit message` heading must appear literally at the start of a line (not inside the `<details>` block) so the trimming command below can locate it reliably. The message lines are prefixed with `>` to make them easy to identify and copy.

**Each time a new commit is pushed**, rewrite the section using `gh pr edit`:

```bash
CURRENT_BODY=$(gh pr view <number> --json body -q .body)
TRIMMED=$(printf '%s\n' "$CURRENT_BODY" | sed '/^## Squash commit message/,$d')
gh pr edit <number> --body "$(printf '%s\n' "$TRIMMED"; cat <<'EOF'
## Squash commit message

<details>
<summary>Click to view squash commit message</summary>

> <updated subject line>
>
> <updated body>

</details>
EOF
)"
```

The section should always reflect the full intended squash commit message — not a log of every individual commit. Write it in the same imperative style as regular commit messages. The final message should be a concise summary of the entire PR, including the main change and any relevant context or motivation.

### Iterate on a PR

When explicitly told to iterate on an existing PR, do the following:

- Address the Copilot review, if any.
  If no Copilot review is available, stop the iteration.
- Push updates to the PR branch, if any.
  If there are no more updates to push, ensure any outstanding review comments are addressed (e.g. by replying to them with a justification if you choose not to implement the suggested change), then stop the iteration.
- While CI runs, reply to all review comments (implement accepted suggestions, justify rejected ones) and complete any other local tasks that do not require pushing new commits. Do not push any new commits until CI has finished.
- Wait for all CI checks for the pushed updates to pass.
- Ask for a re-review from `@copilot`, wait for it to finish.
- Address the new Copilot review, on and on until a Copilot review comes back with no suggested changes or repeated suggested changes that have previously been rejected.
- Once Copilot accepts the PR, perform a self-review: read through all changes on the branch with fresh eyes and consider whether anything is unclear, incorrect, or could be improved. If you find issues that require changes, implement them, push the updates, inform the human contributor of what changed and why, and request a new re-review from `@copilot` before treating the PR as accepted again. If you find no issues, inform the human contributor that the self-review found no further code changes.
- As the very last step before stopping the iteration, review the PR description for accuracy and completeness: update the summary to reflect the final state of the changes, and rewrite the squash commit message to be a clean, concise summary of the entire PR.

Make sure to write short and clear replies to justify your decisions as comments to the review, when possible.
If you disagree with a suggested change, explain why you choose not to implement it instead of silently ignoring it. This helps the reviewer understand your perspective and can lead to a more productive discussion.
Resolve a review comment once the suggested change has been implemented and there is no ongoing discussion that still needs reviewer visibility. If you reject a suggestion, or if there are still open questions or disagreements about an implemented change, leave the comment unresolved and reply briefly with your reasoning so human maintainers can follow the discussion.

### Sizing and scope

- **One logical change per PR.** A PR should represent a single coherent feature, fix, or refactor. If a task naturally splits into independent pieces, open separate PRs.
- **Keep PRs reviewable.** Aim for under ~400 changed lines excluding auto-generated files. If a change must be larger, add extra context in the PR description to help the reviewer.
- **Limit concurrent open PRs.** Avoid opening more than 3–4 PRs at once. Prefer landing existing PRs before opening new ones to prevent review pile-up and merge conflicts.
- **Don't bundle unrelated changes.** Opportunistic refactors, formatting fixes, or dependency bumps that are unrelated to the PR's stated goal belong in a separate PR.

### PR description

Include:

- A short summary of what the change does and why.
- Any non-obvious decisions or trade-offs made.
- Testing steps or notes on how to verify the change.

## Release Process

Releases are triggered manually. The steps below cover the full process from deciding the version number to verifying the CI release workflow.

Throughout this section, `<version>` refers to the bare version number without a `v` prefix (e.g. `2.9.2`). The `v` prefix is written explicitly wherever it is needed (e.g. `v<version>` → `v2.9.2`).

### 1. Determine the version bump

First, ensure local refs are up to date:

```bash
git fetch --tags origin
```

Then inspect all commits to `main` since the last release tag:

```bash
last_tag=$(git tag --list 'v*' --sort=-version:refname | head -n 1)
git log "${last_tag}..origin/main" --oneline
```

Use [Semantic Versioning](https://semver.org/):

- **Major bump** (`(MAJOR+1).0.0`) — one or more breaking changes were introduced (e.g. removed or renamed workflow inputs, changed behaviour that callers depend on).
- **Minor bump** (`MAJOR.(MINOR+1).0`) — one or more new user-facing features were added.
- **Patch bump** (`MAJOR.MINOR.(PATCH+1)`) — only bug fixes, dependency updates, dev-tool updates, or internal/repo-tooling changes (e.g. adding `AGENTS.md`).

### 2. Create a milestone

Create a GitHub milestone named after the new version (e.g. `v2.9.2`):

```bash
gh api repos/SINTEF/ci-cd/milestones --method POST -f title="v<version>"
```

### 3. Publish the release

Create and publish the GitHub release. Use the version string as both the tag name and the title, targeting `main`. Do not add a body — the CI workflow appends the generated changelog automatically.

```bash
gh release create v<version> --title "v<version>" --target main --notes ""
```

### 4. Monitor the release workflow

Publishing the release triggers the `CD - Release` workflow. Find the run ID by filtering on the release workflow:

```bash
gh run list --workflow _local_cd_release.yml --limit 3 --json databaseId,status,url
```

Then watch it to completion:

```bash
gh run watch <run-id>
```

The workflow updates the changelog, bumps the package version, and commits back to `main`. All jobs must finish with a green tick before the release is considered done.

## Codebase References

External documentation and non-obvious architectural notes that are useful context when working on this codebase:

### Invoke tasks

Administrative tasks are implemented as [Invoke](https://www.pyinvoke.org/) tasks under [`ci_cd/tasks/`](ci_cd/tasks/). Each module covers a distinct concern:

- [`api_reference_docs.py`](ci_cd/tasks/api_reference_docs.py) — generates MkDocs API reference pages from source modules
- [`docs_index.py`](ci_cd/tasks/docs_index.py) — keeps the docs index in sync with the repository README
- [`setver.py`](ci_cd/tasks/setver.py) — bumps the package version in `pyproject.toml` and other relevant files
- [`update_deps.py`](ci_cd/tasks/update_deps.py) — updates pinned dependency versions across the project

Tasks are exposed via the `ci-cd` CLI entry point. Run `ci-cd --list` to see all available tasks. All binaries should be run from the virtual environment, following the same discovery order as for `pre-commit` above.

### Reusable workflows

The primary purpose of this repository is to provide reusable GitHub Actions workflows and pre-commit hooks for other Python package repositories. The workflows are documented in [`docs/workflows/`](docs/workflows/) and exposed under [`.github/workflows/`](.github/workflows/). The canonical documentation lives at the MkDocs site generated from that directory.

This repository is self-referential — it consumes its own reusable workflows (e.g. `cd_release.yml`, `ci_cd_updated_default_branch.yml`) for its own CI/CD.

### Auto-generated documentation

[`docs/api_reference/`](docs/api_reference/) is auto-generated via the `docs-api-reference` pre-commit hook (which runs `ci-cd create-api-reference-docs`) — do not edit those files manually.
