# TODO

Last updated: 2026-07-07

## Priority

- Dependency PR follow-up remediated in this branch:
  - `#39` `wat`: applied locally in `Cargo.lock`.
  - `#52` `getrandom`: applied locally in `Cargo.lock`.
  - `#53` `rust-cache`: applied locally in GitHub workflow pins.
  - `#49` `actions/upload-artifact`: already closed upstream.
  - `#51` `wasmtime`: already closed upstream after failing checks.
  - `#54` `cosign-installer`: already closed upstream.
  - `#55` `sbom-action`: already closed upstream.
- Keep the atomic file-write hardening and executable-bit preservation tests in place as future refactors touch install paths.

## Notes

- Audit fixes already landed for temp-file creation and Unix mode preservation.
- `cargo release-v0-check` and `./scripts/check-keys-digest-usage.sh` are the
  local closeout gates for the dependency follow-up.
