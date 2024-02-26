# Changelog

## [v2.7.3](https://github.com/SINTEF/ci-cd/tree/v2.7.3) (2024-02-14)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v2.7.2...v2.7.3)

**Fixed bugs:**

- Use `git add -- .` instead of `git commit -a` [\#236](https://github.com/SINTEF/ci-cd/issues/236)

**Merged pull requests:**

- \[Auto-generated\] Update dependencies [\#241](https://github.com/SINTEF/ci-cd/pull/241) ([TEAM4-0](https://github.com/TEAM4-0))
- Use git add -- . instead of git commit -a [\#240](https://github.com/SINTEF/ci-cd/pull/240) ([CasperWA](https://github.com/CasperWA))
- \[Auto-generated\] Update dependencies [\#239](https://github.com/SINTEF/ci-cd/pull/239) ([TEAM4-0](https://github.com/TEAM4-0))

## [v2.7.2](https://github.com/SINTEF/ci-cd/tree/v2.7.2) (2024-01-13)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v2.7.1...v2.7.2)

**Fixed bugs:**

- Support first release [\#232](https://github.com/SINTEF/ci-cd/issues/232)

**Closed issues:**

- Use ruff instead of pylint \(and isort\) in code base [\#191](https://github.com/SINTEF/ci-cd/issues/191)

**Merged pull requests:**

- \[Auto-generated\] Update dependencies [\#235](https://github.com/SINTEF/ci-cd/pull/235) ([TEAM4-0](https://github.com/TEAM4-0))
- Go through another env var to set --since-tag [\#233](https://github.com/SINTEF/ci-cd/pull/233) ([CasperWA](https://github.com/CasperWA))
- \[Auto-generated\] Update dependencies [\#231](https://github.com/SINTEF/ci-cd/pull/231) ([TEAM4-0](https://github.com/TEAM4-0))
- Update to ruff \(instead of pylint \(and isort\)\) [\#192](https://github.com/SINTEF/ci-cd/pull/192) ([CasperWA](https://github.com/CasperWA))

## [v2.7.1](https://github.com/SINTEF/ci-cd/tree/v2.7.1) (2023-12-07)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v2.7.0...v2.7.1)

## [v2.7.0](https://github.com/SINTEF/ci-cd/tree/v2.7.0) (2023-12-07)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v2.6.0...v2.7.0)

**Implemented enhancements:**

- Toggle allowing invalid package name chars [\#208](https://github.com/SINTEF/ci-cd/issues/208)
- Support all newer Python versions [\#207](https://github.com/SINTEF/ci-cd/issues/207)
- Support not using a permanent dependencies branch [\#183](https://github.com/SINTEF/ci-cd/issues/183)

**Fixed bugs:**

- Support epoch and post version segments [\#221](https://github.com/SINTEF/ci-cd/issues/221)
- Utilize `packaging.version.Version` [\#220](https://github.com/SINTEF/ci-cd/pull/220) ([CasperWA](https://github.com/CasperWA))

**Closed issues:**

- Update to non-deprecated inputs in Actions [\#216](https://github.com/SINTEF/ci-cd/issues/216)

**Merged pull requests:**

- \[Auto-generated\] Update dependencies [\#228](https://github.com/SINTEF/ci-cd/pull/228) ([TEAM4-0](https://github.com/TEAM4-0))
- Toggle for skipping dependency if it cannot be parsed [\#224](https://github.com/SINTEF/ci-cd/pull/224) ([CasperWA](https://github.com/CasperWA))
- \[Auto-generated\] Update dependencies [\#223](https://github.com/SINTEF/ci-cd/pull/223) ([TEAM4-0](https://github.com/TEAM4-0))
- Use non-deprecated actions inputs [\#219](https://github.com/SINTEF/ci-cd/pull/219) ([CasperWA](https://github.com/CasperWA))
- Support Python 3.11, 3.12 and 3.13 [\#205](https://github.com/SINTEF/ci-cd/pull/205) ([CasperWA](https://github.com/CasperWA))
- Make using dependencies branch toggleable [\#184](https://github.com/SINTEF/ci-cd/pull/184) ([CasperWA](https://github.com/CasperWA))

## [v2.6.0](https://github.com/SINTEF/ci-cd/tree/v2.6.0) (2023-11-17)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v2.5.3...v2.6.0)

**Implemented enhancements:**

- Modularize `update_deps.py` further [\#148](https://github.com/SINTEF/ci-cd/issues/148)

**Fixed bugs:**

- Ensure version dependency ranges are respected when updating [\#141](https://github.com/SINTEF/ci-cd/issues/141)

**Merged pull requests:**

- \[Auto-generated\] Update dependencies [\#214](https://github.com/SINTEF/ci-cd/pull/214) ([TEAM4-0](https://github.com/TEAM4-0))
- \[Auto-generated\] Check & update dependencies \(`pyproject.toml`\) [\#213](https://github.com/SINTEF/ci-cd/pull/213) ([TEAM4-0](https://github.com/TEAM4-0))
- \[Auto-generated\] Check & update dependencies \(`pyproject.toml`\) [\#206](https://github.com/SINTEF/ci-cd/pull/206) ([TEAM4-0](https://github.com/TEAM4-0))
- \[Auto-generated\] Update dependencies [\#204](https://github.com/SINTEF/ci-cd/pull/204) ([TEAM4-0](https://github.com/TEAM4-0))
- Handle version specifiers [\#190](https://github.com/SINTEF/ci-cd/pull/190) ([CasperWA](https://github.com/CasperWA))

## [v2.5.3](https://github.com/SINTEF/ci-cd/tree/v2.5.3) (2023-10-25)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v2.5.2...v2.5.3)

**Implemented enhancements:**

- Avoid warning for inter-relative extra dependencies [\#198](https://github.com/SINTEF/ci-cd/issues/198)
- Allow branch name customization [\#196](https://github.com/SINTEF/ci-cd/issues/196)

**Fixed bugs:**

- A PR is not opened for CI - Check dependencies [\#195](https://github.com/SINTEF/ci-cd/issues/195)
- Ignore options not parseable [\#194](https://github.com/SINTEF/ci-cd/issues/194)

**Merged pull requests:**

- Add project name by default to `already_handled_packages` [\#202](https://github.com/SINTEF/ci-cd/pull/202) ([CasperWA](https://github.com/CasperWA))
- Customize branch name [\#201](https://github.com/SINTEF/ci-cd/pull/201) ([CasperWA](https://github.com/CasperWA))
- Handle package-specifier spacing [\#197](https://github.com/SINTEF/ci-cd/pull/197) ([CasperWA](https://github.com/CasperWA))

## [v2.5.2](https://github.com/SINTEF/ci-cd/tree/v2.5.2) (2023-10-04)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v2.5.1...v2.5.2)

**Implemented enhancements:**

- Toggle `latest` alias MkDocs release [\#187](https://github.com/SINTEF/ci-cd/issues/187)

**Merged pull requests:**

- \[Auto-generated\] Update dependencies [\#189](https://github.com/SINTEF/ci-cd/pull/189) ([TEAM4-0](https://github.com/TEAM4-0))
- Add `mkdocs_update_latest` bool input [\#188](https://github.com/SINTEF/ci-cd/pull/188) ([CasperWA](https://github.com/CasperWA))
- \[Auto-generated\] Update dependencies [\#185](https://github.com/SINTEF/ci-cd/pull/185) ([TEAM4-0](https://github.com/TEAM4-0))
- \[Auto-generated\] Update dependencies [\#177](https://github.com/SINTEF/ci-cd/pull/177) ([TEAM4-0](https://github.com/TEAM4-0))

## [v2.5.1](https://github.com/SINTEF/ci-cd/tree/v2.5.1) (2023-08-30)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v2.5.0...v2.5.1)

**Fixed bugs:**

- Regression in `--full-docs-dir` input [\#174](https://github.com/SINTEF/ci-cd/issues/174)
- Too strict release tag name requirements [\#172](https://github.com/SINTEF/ci-cd/issues/172)

**Merged pull requests:**

- Fix --full-docs-dir regression [\#175](https://github.com/SINTEF/ci-cd/pull/175) ([CasperWA](https://github.com/CasperWA))
- Remove requirement for release to start with 'v' [\#173](https://github.com/SINTEF/ci-cd/pull/173) ([CasperWA](https://github.com/CasperWA))

## [v2.5.0](https://github.com/SINTEF/ci-cd/tree/v2.5.0) (2023-08-29)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v2.4.0...v2.5.0)

**Fixed bugs:**

- `pylint_options` not working as intended [\#169](https://github.com/SINTEF/ci-cd/issues/169)
- Pre-commit for documentation not working on windows [\#160](https://github.com/SINTEF/ci-cd/issues/160)

**Merged pull requests:**

- Parse `pylint_options` depending on newlines [\#170](https://github.com/SINTEF/ci-cd/pull/170) ([CasperWA](https://github.com/CasperWA))
- Support Windows for pre-commit hook usage [\#165](https://github.com/SINTEF/ci-cd/pull/165) ([CasperWA](https://github.com/CasperWA))
- \[Auto-generated\] Update dependencies [\#159](https://github.com/SINTEF/ci-cd/pull/159) ([TEAM4-0](https://github.com/TEAM4-0))
- \[Auto-generated\] Update dependencies [\#156](https://github.com/SINTEF/ci-cd/pull/156) ([TEAM4-0](https://github.com/TEAM4-0))
- \[Auto-generated\] Update dependencies [\#154](https://github.com/SINTEF/ci-cd/pull/154) ([TEAM4-0](https://github.com/TEAM4-0))

## [v2.4.0](https://github.com/SINTEF/ci-cd/tree/v2.4.0) (2023-05-23)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v2.3.1...v2.4.0)

**Implemented enhancements:**

- Automatically merge CI workflow to update deps [\#101](https://github.com/SINTEF/ci-cd/issues/101)
- Support Sphinx for documentation building [\#90](https://github.com/SINTEF/ci-cd/issues/90)
- Add hook for using the `update-deps` task [\#24](https://github.com/SINTEF/ci-cd/issues/24)

**Fixed bugs:**

- Flawed logic [\#152](https://github.com/SINTEF/ci-cd/issues/152)
- Error in workflow [\#150](https://github.com/SINTEF/ci-cd/issues/150)
- Issues with the ignore-functionality of `ci-cd update-deps` [\#130](https://github.com/SINTEF/ci-cd/issues/130)

**Closed issues:**

- Error in .github/workflows/ci\_automerge\_prs.yml which makes automerging fail in outside repos [\#139](https://github.com/SINTEF/ci-cd/issues/139)

**Merged pull requests:**

- Fix logic for checking documentation framework [\#153](https://github.com/SINTEF/ci-cd/pull/153) ([CasperWA](https://github.com/CasperWA))
- Fix typos in workflows [\#151](https://github.com/SINTEF/ci-cd/pull/151) ([CasperWA](https://github.com/CasperWA))
- \[Auto-generated\] Update dependencies [\#143](https://github.com/SINTEF/ci-cd/pull/143) ([TEAM4-0](https://github.com/TEAM4-0))
- Fix ignore functionality \(especially for 'version' rules\) [\#140](https://github.com/SINTEF/ci-cd/pull/140) ([CasperWA](https://github.com/CasperWA))
- Add `update-pyproject` pre-commit hook [\#128](https://github.com/SINTEF/ci-cd/pull/128) ([CasperWA](https://github.com/CasperWA))
- Activate auto-merge for pyproject.toml update PRs [\#114](https://github.com/SINTEF/ci-cd/pull/114) ([CasperWA](https://github.com/CasperWA))
- Support Sphinx [\#92](https://github.com/SINTEF/ci-cd/pull/92) ([CasperWA](https://github.com/CasperWA))

## [v2.3.1](https://github.com/SINTEF/ci-cd/tree/v2.3.1) (2023-04-13)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v2.3.0...v2.3.1)

**Merged pull requests:**

- \[Auto-generated\] Update dependencies [\#138](https://github.com/SINTEF/ci-cd/pull/138) ([TEAM4-0](https://github.com/TEAM4-0))
- \[Auto-generated\] Update dependencies [\#131](https://github.com/SINTEF/ci-cd/pull/131) ([TEAM4-0](https://github.com/TEAM4-0))

## [v2.3.0](https://github.com/SINTEF/ci-cd/tree/v2.3.0) (2023-03-24)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v2.2.1...v2.3.0)

**Implemented enhancements:**

- Use GH usernames for release changelogs [\#102](https://github.com/SINTEF/ci-cd/issues/102)

**Fixed bugs:**

- Wrongly named option used in callable workflow [\#125](https://github.com/SINTEF/ci-cd/issues/125)
- Use codecov upload token [\#119](https://github.com/SINTEF/ci-cd/issues/119)

**Merged pull requests:**

- Use CODECOV\_TOKEN secret in CI [\#127](https://github.com/SINTEF/ci-cd/pull/127) ([CasperWA](https://github.com/CasperWA))
- Use the proper "ignore" option name for update-deps [\#126](https://github.com/SINTEF/ci-cd/pull/126) ([CasperWA](https://github.com/CasperWA))
- Use GitHub usernames in changelogs for releases [\#115](https://github.com/SINTEF/ci-cd/pull/115) ([CasperWA](https://github.com/CasperWA))

## [v2.2.1](https://github.com/SINTEF/ci-cd/tree/v2.2.1) (2023-03-15)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v2.2.0...v2.2.1)

**Fixed bugs:**

- Typo in auto-merge callable workflow [\#117](https://github.com/SINTEF/ci-cd/issues/117)
- Fix GH Actions variable naming [\#120](https://github.com/SINTEF/ci-cd/pull/120) ([CasperWA](https://github.com/CasperWA))
- Fix typo in auto merge workflow [\#118](https://github.com/SINTEF/ci-cd/pull/118) ([CasperWA](https://github.com/CasperWA))

**Merged pull requests:**

- \[Auto-generated\] Update dependencies [\#121](https://github.com/SINTEF/ci-cd/pull/121) ([TEAM4-0](https://github.com/TEAM4-0))

## [v2.2.0](https://github.com/SINTEF/ci-cd/tree/v2.2.0) (2023-03-10)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v2.1.0...v2.2.0)

**Implemented enhancements:**

- Add API reference documentation for this repository [\#113](https://github.com/SINTEF/ci-cd/issues/113)
- Allow to skip or keep dependency at certain level [\#95](https://github.com/SINTEF/ci-cd/issues/95)

**Fixed bugs:**

- `fail_fast` should still make `update-deps` task fail [\#112](https://github.com/SINTEF/ci-cd/issues/112)

**Merged pull requests:**

- Implement `ignore` option for `update-deps` task [\#111](https://github.com/SINTEF/ci-cd/pull/111) ([CasperWA](https://github.com/CasperWA))
- Add API reference documentation for `ci-cd` [\#110](https://github.com/SINTEF/ci-cd/pull/110) ([CasperWA](https://github.com/CasperWA))
- Update Python API [\#109](https://github.com/SINTEF/ci-cd/pull/109) ([CasperWA](https://github.com/CasperWA))
- \[Auto-generated\] Update dependencies [\#107](https://github.com/SINTEF/ci-cd/pull/107) ([TEAM4-0](https://github.com/TEAM4-0))

## [v2.1.0](https://github.com/SINTEF/ci-cd/tree/v2.1.0) (2023-02-07)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v2.0.0...v2.1.0)

**Implemented enhancements:**

- Use custom token when possible [\#104](https://github.com/SINTEF/ci-cd/issues/104)
- Extend "automerge" workflow with changes [\#69](https://github.com/SINTEF/ci-cd/issues/69)

**Closed issues:**

- Acknowledge testing dependencies in pyproject.toml [\#93](https://github.com/SINTEF/ci-cd/issues/93)

**Merged pull requests:**

- Always try to use `PAT` prior to `GITHUB_TOKEN` [\#105](https://github.com/SINTEF/ci-cd/pull/105) ([CasperWA](https://github.com/CasperWA))
- \[Auto-generated\] Update dependencies [\#103](https://github.com/SINTEF/ci-cd/pull/103) ([TEAM4-0](https://github.com/TEAM4-0))
- \[Auto-generated\] Update dependencies [\#97](https://github.com/SINTEF/ci-cd/pull/97) ([TEAM4-0](https://github.com/TEAM4-0))
- Changes prior to auto-merge [\#88](https://github.com/SINTEF/ci-cd/pull/88) ([CasperWA](https://github.com/CasperWA))

## [v2.0.0](https://github.com/SINTEF/ci-cd/tree/v2.0.0) (2022-12-06)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v1.3.5...v2.0.0)

**Implemented enhancements:**

- Make `test: true` actually work for "CD - Release" [\#83](https://github.com/SINTEF/ci-cd/issues/83)

**Fixed bugs:**

- Bad usage of backticks in warning message [\#79](https://github.com/SINTEF/ci-cd/issues/79)

**Closed issues:**

- Drop using a `vMAJOR` dynamic tag [\#81](https://github.com/SINTEF/ci-cd/issues/81)

**Merged pull requests:**

- \[Auto-generated\] Update dependencies [\#85](https://github.com/SINTEF/ci-cd/pull/85) ([TEAM4-0](https://github.com/TEAM4-0))
- Changed to vMajor tag for pre-commit in ci\_update\_dependencies.yml [\#82](https://github.com/SINTEF/ci-cd/pull/82) ([francescalb](https://github.com/francescalb))
- Use quotes instead of backticks in warning message [\#80](https://github.com/SINTEF/ci-cd/pull/80) ([CasperWA](https://github.com/CasperWA))

## [v1.3.5](https://github.com/SINTEF/ci-cd/tree/v1.3.5) (2022-11-17)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v1.3.4...v1.3.5)

**Fixed bugs:**

- Undo commit d525ea0f069b6615aa352a7f385c21b31f29b985 [\#77](https://github.com/SINTEF/ci-cd/issues/77)

**Merged pull requests:**

- Make `--strict` toggleable for `mkdocs build` [\#78](https://github.com/SINTEF/ci-cd/pull/78) ([CasperWA](https://github.com/CasperWA))
- \[Auto-generated\] Update dependencies [\#76](https://github.com/SINTEF/ci-cd/pull/76) ([TEAM4-0](https://github.com/TEAM4-0))

## [v1.3.4](https://github.com/SINTEF/ci-cd/tree/v1.3.4) (2022-10-31)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v1.3.3...v1.3.4)

**Implemented enhancements:**

- Support setting full versions in pre-commit config [\#72](https://github.com/SINTEF/ci-cd/issues/72)

**Merged pull requests:**

- Only freeze repo hook version if using 'v1' [\#73](https://github.com/SINTEF/ci-cd/pull/73) ([CasperWA](https://github.com/CasperWA))

## [v1.3.3](https://github.com/SINTEF/ci-cd/tree/v1.3.3) (2022-10-12)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v1.3.2...v1.3.3)

**Implemented enhancements:**

- Support setting python version restrictions in dependencies [\#70](https://github.com/SINTEF/ci-cd/issues/70)

**Merged pull requests:**

- Extend dependency spec regex [\#71](https://github.com/SINTEF/ci-cd/pull/71) ([CasperWA](https://github.com/CasperWA))

## [v1.3.2](https://github.com/SINTEF/ci-cd/tree/v1.3.2) (2022-10-10)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v1.3.1...v1.3.2)

**Fixed bugs:**

- Don't change `.pages` in API ref hook [\#66](https://github.com/SINTEF/ci-cd/issues/66)

**Merged pull requests:**

- \[Auto-generated\] Update dependencies [\#68](https://github.com/SINTEF/ci-cd/pull/68) ([TEAM4-0](https://github.com/TEAM4-0))
- Ensure `.pages` does not get mkdocstrings option [\#67](https://github.com/SINTEF/ci-cd/pull/67) ([CasperWA](https://github.com/CasperWA))

## [v1.3.1](https://github.com/SINTEF/ci-cd/tree/v1.3.1) (2022-10-06)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v1.3.0...v1.3.1)

**Fixed bugs:**

- Nested modules not represented properly [\#64](https://github.com/SINTEF/ci-cd/issues/64)

**Merged pull requests:**

- Ensure API reference documentation works for multiple large packages [\#65](https://github.com/SINTEF/ci-cd/pull/65) ([CasperWA](https://github.com/CasperWA))

## [v1.3.0](https://github.com/SINTEF/ci-cd/tree/v1.3.0) (2022-10-05)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v1.2.2...v1.3.0)

**Implemented enhancements:**

- Custom API ref file options [\#57](https://github.com/SINTEF/ci-cd/issues/57)
- Test installing Python package after building it [\#56](https://github.com/SINTEF/ci-cd/issues/56)
- Support multi-package repositories [\#55](https://github.com/SINTEF/ci-cd/issues/55)
- Use custom Python version for CI tests [\#54](https://github.com/SINTEF/ci-cd/issues/54)

**Fixed bugs:**

- Local workflows out-of-date [\#62](https://github.com/SINTEF/ci-cd/issues/62)
- Invoke task "update docs index" missing defaults [\#53](https://github.com/SINTEF/ci-cd/issues/53)

**Closed issues:**

- Documentation issue [\#52](https://github.com/SINTEF/ci-cd/issues/52)

**Merged pull requests:**

- Update local workflows with new input names [\#63](https://github.com/SINTEF/ci-cd/pull/63) ([CasperWA](https://github.com/CasperWA))
- Custom Python versions for jobs [\#61](https://github.com/SINTEF/ci-cd/pull/61) ([CasperWA](https://github.com/CasperWA))
- Custom API reference options [\#60](https://github.com/SINTEF/ci-cd/pull/60) ([CasperWA](https://github.com/CasperWA))
- Fix documentation typos [\#59](https://github.com/SINTEF/ci-cd/pull/59) ([CasperWA](https://github.com/CasperWA))
- Support multiple packages in the same repo [\#58](https://github.com/SINTEF/ci-cd/pull/58) ([CasperWA](https://github.com/CasperWA))
- \[Auto-generated\] Update dependencies [\#50](https://github.com/SINTEF/ci-cd/pull/50) ([TEAM4-0](https://github.com/TEAM4-0))
- \[Auto-generated\] Update dependencies [\#48](https://github.com/SINTEF/ci-cd/pull/48) ([TEAM4-0](https://github.com/TEAM4-0))

## [v1.2.2](https://github.com/SINTEF/ci-cd/tree/v1.2.2) (2022-08-24)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v1.2.1...v1.2.2)

**Fixed bugs:**

- API reference links depends on installation type [\#46](https://github.com/SINTEF/ci-cd/issues/46)

**Merged pull requests:**

- API reference links corrections [\#47](https://github.com/SINTEF/ci-cd/pull/47) ([CasperWA](https://github.com/CasperWA))

## [v1.2.1](https://github.com/SINTEF/ci-cd/tree/v1.2.1) (2022-08-23)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v1.2.0...v1.2.1)

**Fixed bugs:**

- Properly point to API reference files [\#44](https://github.com/SINTEF/ci-cd/issues/44)

**Merged pull requests:**

- Add unit tests for tasks [\#45](https://github.com/SINTEF/ci-cd/pull/45) ([CasperWA](https://github.com/CasperWA))
- \[Auto-generated\] Update dependencies [\#43](https://github.com/SINTEF/ci-cd/pull/43) ([TEAM4-0](https://github.com/TEAM4-0))

## [v1.2.0](https://github.com/SINTEF/ci-cd/tree/v1.2.0) (2022-07-18)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v1.1.2...v1.2.0)

**Implemented enhancements:**

- Add workflow for "standard" CI tests [\#23](https://github.com/SINTEF/ci-cd/issues/23)
- Add local CI tests [\#22](https://github.com/SINTEF/ci-cd/issues/22)

**Fixed bugs:**

- Update all mentions of `CasperWA` to `SINTEF` [\#37](https://github.com/SINTEF/ci-cd/issues/37)
- Hook not working due to task error [\#32](https://github.com/SINTEF/ci-cd/issues/32)

**Closed issues:**

- Credit funding projects [\#35](https://github.com/SINTEF/ci-cd/issues/35)
- Update documentation title and README [\#29](https://github.com/SINTEF/ci-cd/issues/29)

**Merged pull requests:**

- \[Auto-generated\] Update dependencies [\#39](https://github.com/SINTEF/ci-cd/pull/39) ([TEAM4-0](https://github.com/TEAM4-0))
- Convert to SINTEF owner instead of CasperWA [\#38](https://github.com/SINTEF/ci-cd/pull/38) ([CasperWA](https://github.com/CasperWA))
- Update README title and description + funding [\#36](https://github.com/SINTEF/ci-cd/pull/36) ([CasperWA](https://github.com/CasperWA))
- Basic CI tests workflow [\#33](https://github.com/SINTEF/ci-cd/pull/33) ([CasperWA](https://github.com/CasperWA))

## [v1.1.2](https://github.com/SINTEF/ci-cd/tree/v1.1.2) (2022-07-08)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v1.1.1...v1.1.2)

**Implemented enhancements:**

- Update package version [\#28](https://github.com/SINTEF/ci-cd/pull/28) ([CasperWA](https://github.com/CasperWA))

**Fixed bugs:**

- Fix usage of invoke tasks for lists [\#30](https://github.com/SINTEF/ci-cd/issues/30)
- Default `args` for `docs-landing-page` doesn't work [\#27](https://github.com/SINTEF/ci-cd/issues/27)
- Update internal Python package along with releases [\#26](https://github.com/SINTEF/ci-cd/issues/26)

**Merged pull requests:**

- Default `args` fix for `docs-landing-page` hook [\#31](https://github.com/SINTEF/ci-cd/pull/31) ([CasperWA](https://github.com/CasperWA))

## [v1.1.1](https://github.com/SINTEF/ci-cd/tree/v1.1.1) (2022-07-06)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v1.1.0...v1.1.1)

**Fixed bugs:**

- Hooks not working externally [\#21](https://github.com/SINTEF/ci-cd/issues/21)

**Merged pull requests:**

- Use invoke as library [\#25](https://github.com/SINTEF/ci-cd/pull/25) ([CasperWA](https://github.com/CasperWA))

## [v1.1.0](https://github.com/SINTEF/ci-cd/tree/v1.1.0) (2022-07-06)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v1.0.1...v1.1.0)

**Implemented enhancements:**

- New pre-commit hooks for invoke tasks [\#16](https://github.com/SINTEF/ci-cd/issues/16)

**Merged pull requests:**

- First pre-commit hooks [\#20](https://github.com/SINTEF/ci-cd/pull/20) ([CasperWA](https://github.com/CasperWA))

## [v1.0.1](https://github.com/SINTEF/ci-cd/tree/v1.0.1) (2022-07-06)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v1.0.0...v1.0.1)

**Fixed bugs:**

- Ensure PREVIOUS\_VERSION can be retrieved if input not given [\#19](https://github.com/SINTEF/ci-cd/issues/19)
- Fix condition for running steps in CI/CD workflow [\#18](https://github.com/SINTEF/ci-cd/issues/18)

**Closed issues:**

- Update documentation to `@v1` [\#15](https://github.com/SINTEF/ci-cd/issues/15)

## [v1.0.0](https://github.com/SINTEF/ci-cd/tree/v1.0.0) (2022-07-06)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v0.1.0...v1.0.0)

**Implemented enhancements:**

- Use proper option for changelog generator instead of moving file afterwards [\#13](https://github.com/SINTEF/ci-cd/issues/13)
- Update CHANGELOG with unreleased stuff when updating default branch [\#11](https://github.com/SINTEF/ci-cd/issues/11)
- Update to new repo name [\#8](https://github.com/SINTEF/ci-cd/issues/8)
- Allow testing/debugging CI/CD workflow [\#6](https://github.com/SINTEF/ci-cd/issues/6)
- Make "FIRST\_RELEASE" bool more robust [\#3](https://github.com/SINTEF/ci-cd/issues/3)

**Fixed bugs:**

- Exclude tags from PREVIOUS\_VERSION in release workflow [\#17](https://github.com/SINTEF/ci-cd/issues/17)
- Update local workflow for updated CI/CD workflow [\#12](https://github.com/SINTEF/ci-cd/issues/12)
- Fix links for various "default" PR bodies and tag messages [\#9](https://github.com/SINTEF/ci-cd/issues/9)
- API Reference creation not working [\#7](https://github.com/SINTEF/ci-cd/issues/7)
- Ensure the permanent dependencies branch is always updated [\#4](https://github.com/SINTEF/ci-cd/issues/4)

**Closed issues:**

- Update documentation with new inputs for CI/CD workflow [\#14](https://github.com/SINTEF/ci-cd/issues/14)
- Workflow overview in documentation [\#5](https://github.com/SINTEF/ci-cd/issues/5)

**Merged pull requests:**

- Update repo and workflow title names [\#10](https://github.com/SINTEF/ci-cd/pull/10) ([CasperWA](https://github.com/CasperWA))

## [v0.1.0](https://github.com/SINTEF/ci-cd/tree/v0.1.0) (2022-07-05)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/15676e5c3b8ecb7291ab14c228b927883d0df8f5...v0.1.0)

**Merged pull requests:**

- New workflow triggering changes with new default branch changes [\#1](https://github.com/SINTEF/ci-cd/pull/1) ([CasperWA](https://github.com/CasperWA))



\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
