# CI/CD tools

This repository contains reusable workflows for GitHub Actions as well as [`pre-commit`](https://pre-commit.com) hooks.

They are mainly for usage with modern Python package repositories.

**All available workflows and more detailed information can be found in the documentation [here](https://SINTEF.github.io/ci-cd).**

## Usage

See the [GitHub Docs](https://docs.github.com/en/actions/using-workflows/reusing-workflows#calling-a-reusable-workflow) on the topic of calling a reusable workflow to understand how one can incoporate one of these workflows in your workflow.

> **Note**: Workflow-level set `env` context variables cannot be used when setting input values for the called workflow.
> See the [GitHub documentation](https://docs.github.com/en/actions/learn-github-actions/contexts#env-context) for more information on the `env` context.

See the [pre-commit website](https://pre-commit.com) to learn more about how to use and configure pre-commit in your repository.

## License & copyright

This repository is licensed under the [MIT LICENSE](LICENSE) with copyright &copy; 2022 Casper Welzel Andersen ([CasperWA](https://github.com/CasperWA)) & SINTEF ([on GitHub](https://github.com/SINTEF)).

## Funding support

This repository has been supported by the following projects:

- **OntoTrans** (2020-2024) that receives funding from the European Union’s Horizon 2020 Research and Innovation Programme, under Grant Agreement n. 862136.

- **OpenModel** (2021-2025) receives funding from the European Union’s Horizon 2020 Research and Innovation Programme - DT-NMBP-11-2020 Open Innovation Platform for Materials Modelling, under Grant Agreement no: 953167.
