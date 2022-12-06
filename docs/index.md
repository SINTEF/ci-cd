# CI/CD tools

**Current version to use:** `v1`

Use tried and tested continuous integration (CI) and continuous deployment (CD) tools from this repository.

Currently, the repository offers GitHub Actions callable/reusable workflows and [pre-commit](https://pre-commit.com) hooks.

## GitHub Actions callable/reusable Workflows

This repository contains reusable workflows for GitHub Actions.

They are mainly for usage with modern Python package repositories.

### Available workflows

The callable, reusable workflows available from this repository are described in detail in this documentation under the [Workflows](./workflows/index.md) section.

### General usage

See the [GitHub Docs](https://docs.github.com/en/actions/using-workflows/reusing-workflows#calling-a-reusable-workflow) on the topic of calling a reusable workflow to understand how one can incoporate one of these workflows in your workflow.

!!! note
    Workflow-level set `env` context variables cannot be used when setting input values for the called workflow.
    See the [GitHub documentation](https://docs.github.com/en/actions/learn-github-actions/contexts#env-context) for more information on the `env` context.

Under the [Workflows](./workflows/index.md) section for each available workflow, a usage example will be given.

## pre-commit hooks

This repository contains hooks for keeping the documentation up-to-date, making available a few [invoke](https://pyinvoke.org) tasks used in the reusable workflows.

By implementing and using these hooks together with the workflows, one may ensure no extra commits are created during the workflow run to update the documentation.

### Available hooks

The pre-commit hooks available from this repository are described in detail in this documentation under the [Hooks](./hooks/index.md) section.

<!-- markdownlint-disable-next-line MD024 -->
### General usage

Add the hooks to your `.pre-commit-config.yaml` file.
See the [pre-commit webpage](https://pre-commit.com) for more information about how to use pre-commit.

Under the [Hooks](./hooks/index.md) section for each available hook, a usage example will be given.

## License & copyright

This repository licensed under the  [MIT LICENSE](LICENSE.md) with copyright &copy; 2022 Casper Welzel Andersen ([CasperWA](https://github.com/CasperWA)) & SINTEF ([on GitHub](https://github.com/SINTEF)).

## Funding support

This repository has been supported by the following projects:

- **OntoTrans** (2020-2024) that receives funding from the European Union’s Horizon 2020 Research and Innovation Programme, under Grant Agreement n. 862136.

- **OpenModel** (2021-2025) receives funding from the European Union’s Horizon 2020 Research and Innovation Programme - DT-NMBP-11-2020 Open Innovation Platform for Materials Modelling, under Grant Agreement no: 953167.
