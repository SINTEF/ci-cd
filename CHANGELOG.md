# Changelog

## [Unreleased](https://github.com/SINTEF/ci-cd/tree/HEAD)

[Full Changelog](https://github.com/SINTEF/ci-cd/compare/v1.3.5...HEAD)

**Fixed bugs:**

- Bad usage of backticks in warning message [\#79](https://github.com/SINTEF/ci-cd/issues/79)

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
