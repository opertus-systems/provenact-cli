# Conformance Matrix (v0)

This document maps each normative source in `SPEC.md` to current enforcement
evidence in tests, vectors, and command flows.

Status legend:
- `covered`: enforced with direct automated tests/vectors.
- `partial`: some rules enforced, but not complete against the normative file.
- `gap`: no direct automated enforcement yet.

## Mirror Source Pin

- `spec/` + `test-vectors/` mirror source:
  `opertus-systems/provenact-spec@e76349a330342875e17f9c9fdaeb88f2e31011b4`
  (recorded in `sync-manifest.json`).

## Matrix

| Normative Source | Current Enforcement Evidence | Status | Notes |
| --- | --- | --- | --- |
| `spec/threat-model.md` | `cli/provenact-cli/tests/threat_model_gates.rs` + `docs/threat-model-controls.md` | covered | Threat-model checklist gates are explicit and automated where applicable |
| `spec/compatibility.md` | `cli/provenact-cli/tests/compatibility.rs`, CLI command surface (`run` requires `--receipt`; `experimental-*` commands explicitly separated), schema gating in verifier parsers | covered | Stable command surface and experimental command separation are regression-tested |
| `spec/hashing.md` | `core/verifier/src/lib.rs` unit tests for artifact/snapshot/receipt hashes; receipt vectors in `test-vectors/receipt/`; snapshot vectors in `test-vectors/registry/snapshot/` | covered | JCS-based receipt/snapshot hashing verified; snapshot entries enforce `sha256` + `md5` format |
| `spec/packaging.md` | `cli/provenact-cli/tests/pack_sign.rs`, `cli/provenact-cli/tests/e2e_flow.rs`, `cli/provenact-cli/tests/archive.rs` | covered | Deterministic pack/sign flows and canonical deterministic `skill.tar.zst` writer profile are regression-tested |
| `spec/install.md` | `cli/provenact-cli/src/install.rs` + `cli/provenact-cli/tests/install.rs` | covered | Content-addressed install flow (`load -> hash -> verify -> validate -> store -> index`) is implemented and regression-tested |
| `spec/install/index.schema.json` | `cli/provenact-cli/src/install.rs` writes index shape + `cli/provenact-cli/tests/install.rs` validates persisted index content | covered | Index schema fields are exercised by install success path and enforced by deterministic writer |
| `spec/install/meta.schema.json` | `cli/provenact-cli/src/install.rs` writes store metadata + `cli/provenact-cli/tests/install.rs` asserts `meta.json` presence in content store | covered | Installed artifact metadata shape is produced on every successful install |
| `spec/conformance.md` | `cargo conformance` alias + test suites in `core/verifier/tests/` and `cli/provenact-cli/tests/` | covered | CI workflow runs `cargo conformance` |
| `spec/skill-format.md` | `cli/provenact-cli/tests/skill_format.rs`, manifest/provenance/signatures parsing, fixture bundle hash linkage, and CLI verify flow | covered | Bundle-level artifact, manifest hash, signatures linkage, provenance parsing, and verify path are regression-tested |
| `spec/skill-format/manifest.schema.json` | `parse_manifest_json` + `core/verifier/tests/skill_format_vectors.rs` + `test-vectors/skill-format/manifest/` | covered | Good/bad manifest vectors enforced |
| `spec/skill-format/provenance.schema.json` | `parse_provenance_json` + `core/verifier/tests/provenance_vectors.rs` + `test-vectors/skill-format/provenance/` | covered | Good/bad provenance vectors enforced |
| `spec/skill-format/signatures.schema.json` | `parse_signatures_json` + `core/verifier/tests/skill_format_vectors.rs` + `test-vectors/skill-format/signatures/` | covered | Good/bad signatures vectors enforced |
| `spec/policy/policy.schema.json` | `core/verifier/tests/policy_vectors.rs` using `test-vectors/policy/{valid,invalid}` | covered | Schema-aligned policy constraints enforced in parser |
| `spec/policy/policy.md` | trusted signer + capability ceiling checks in verifier; CLI `run` tests | covered | Deny-by-default policy behavior exercised |
| `spec/policy/capability-evaluation.md` | `core/verifier/tests/capability_eval_vectors.rs` | covered | Boundary-safe fs prefix cases included |
| `spec/execution-receipt.schema.json` | `parse_receipt_json`, `core/verifier/tests/receipt_vectors.rs`, CLI `verify-receipt` tests | covered | Good/bad receipt fixtures included |
| `spec/registry/registry.md` | `verify_snapshot_hash` + `parse_snapshot_json` + `core/verifier/tests/registry_snapshot_vectors.rs` + `test-vectors/registry/snapshot/` | covered | Snapshot hash preimage rules + required entry `sha256`/`md5` checks enforced via vectors |
| `spec/registry/snapshot.schema.json` | `parse_snapshot_json` + `core/verifier/tests/registry_snapshot_vectors.rs` + `test-vectors/registry/snapshot/` | covered | Good/bad snapshot vectors enforce entry object shape and digest formats |

## Draft Coverage (Non-Normative)

| Draft Source | Current Enforcement Evidence | Status | Notes |
| --- | --- | --- | --- |
| `spec/skill-format/manifest.v1.experimental.schema.json` | `core/verifier/tests/manifest_v1_draft_vectors.rs` + `test-vectors/skill-format/manifest-v1/` + CLI experimental validation tests | covered | Includes `1.0.0-draft` and strict `1.1.0-draft` contract vectors (hash mismatch, selector mismatch, determinism violations, capability/effect mismatch) |
| `spec/execution-receipt.v1.experimental.schema.json` | `core/verifier/tests/receipt_v1_draft_vectors.rs` + `test-vectors/receipt-v1/` + CLI receipt verification tests | covered | Includes `1.1.0-draft` receipt contract fields and tamper rejection for contract/schema/effects hash-bound fields |

## Remaining Hardening Opportunities

No blocking conformance gaps are currently known for normative sources listed in
`SPEC.md`, and no normative rows are currently marked `partial` or `gap`.
