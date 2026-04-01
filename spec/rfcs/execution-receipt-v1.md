# RFC: Execution Receipt v1 (Draft)

Status: Draft  
Owner: Provenact Maintainers  
Last Updated: 2026-02-19

This RFC is non-normative until promoted into `SPEC.md`.

## 1. Summary

Define deterministic receipt contracts for:
- `1.0.0-draft` (baseline v1 draft)
- `1.1.0-draft` (contract-bound v1 draft)

`1.1.0-draft` extends receipt integrity with manifest contract binding and typed
side-effect ledger fields.

## 2. Goals

- Preserve cryptographic binding to artifact/policy/IO.
- Keep receipt hash deterministic and self-verifiable.
- Make typed runtime effects auditable.
- Keep semantics independent from agent orchestration.

## 3. Common Required Fields

Both draft versions require:
- `schema_version`
- `artifact`
- `manifest_hash`
- `policy_hash`
- `bundle_hash`
- `inputs_hash`
- `outputs_hash`
- `runtime_version_digest`
- `result_digest`
- `caps_requested`
- `caps_granted`
- `caps_used`
- `result`
- `runtime`
- `started_at`
- `finished_at`
- `timestamp_strategy`
- `receipt_hash`

## 4. `1.1.0-draft` Required Extensions

Additional required fields:
- `contract_hash`
- `instructions_hash`
- `input_schema_hash`
- `output_schema_hash`
- `effects_used`

`effects_used[*]` fields:
- `kind`
- `selector`
- `calls`
- `bytes_in`
- `bytes_out`
- `denied_calls`

## 5. Hashing Rules

`receipt_hash = sha256(JCS(receipt_payload_without_receipt_hash))`

For `1.1.0-draft`, hash preimage includes the contract-binding and effect-ledger
fields listed above.

Verification must reject any tampering of those fields via hash mismatch.

## 6. Verification Semantics

Receipt verification confirms:
1. schema-level validity for `1.0.0-draft` or `1.1.0-draft`
2. digest field format validity
3. deterministic hash correctness over canonical payload
4. result/runtime field consistency

## 7. Failure Receipt Semantics

For contract-enabled runs (`manifest.schema_version = 1.1.0-draft`):
- failures after runtime start emit `1.1.0-draft` receipts
- failure `result.code` is deterministic (`execution_error`,
  `duration_limit_exceeded`, `output_limit_exceeded`, `output_not_json`,
  `output_schema_mismatch`, etc.)
- `effects_used` includes denied-call counters when runtime denies effects

## 8. Compatibility

- `verify-receipt` must accept and verify both `1.0.0-draft` and
  `1.1.0-draft`.
- `1.0.0-draft` receipts must not include the `1.1.0-draft` required extension
  fields.

## 9. Security Notes

- Receipt integrity is cryptographic, not trust-in-runtime by assertion.
- Side effects are auditable only to the extent host ABI events are captured.
- No workflow/planner metadata is included; execution substrate boundary is
  preserved.
