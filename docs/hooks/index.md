# pre-commit Hooks

[pre-commit](https://pre-commit.com) is an excellent tool for running CI tasks prior to committing new changes.
The tasks are called "hooks" and are run in a separate virtual environment.
The hooks usually change files in-place, meaning after pre-commit is run during a `git commit` command, the changed files can be reviewed and re-staged and committed.

Through [CasperWA/ci-cd](https://github.com/CasperWA/ci-cd) several hooks are available, mainly related to the [GitHub Actions callable/reusable workflows](../workflows/index.md) that are also available in this repository.

This section contains all the available pre-commit hooks:

- [Update API Reference in Documentation](./docs_api_reference.md)
- [Update Landing Page (index.md) for Documentation](./docs_landig_page.md)
