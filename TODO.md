# TODO

Last updated: 2026-03-16

## Priority

- Merge or close the remaining dependency PRs after rerunning current branch protection:
  - `#39` `wat`
  - `#52` `getrandom`
- Investigate and fix the failing dependency PRs before merging:
  - `#49` `actions/upload-artifact`
  - `#51` `wasmtime`
  - `#53` `rust-cache`
  - `#54` `cosign-installer`
  - `#55` `sbom-action`
- Keep the atomic file-write hardening and executable-bit preservation tests in place as future refactors touch install paths.

## Notes

- Audit fixes already landed for temp-file creation and Unix mode preservation.
- Several dependabot branches are clean but need branch-protection reruns after base-branch movement.
