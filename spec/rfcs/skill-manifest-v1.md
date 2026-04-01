# RFC: Skill Manifest v1 (Draft)

Status: Draft  
Owner: Provenact Maintainers  
Last Updated: 2026-02-19

This RFC is non-normative until promoted into `SPEC.md`.

## 1. Summary

Define a versioned manifest contract for experimental v1 schema lines:
- `1.0.0-draft` (baseline draft)
- `1.1.0-draft` (contract-enforced draft)

`1.1.0-draft` adds a manifest-embedded, declarative `tool_contract` for
immutable instructions, typed side effects, determinism declaration, and runtime
limits.

## 2. Scope Boundary

This RFC is execution substrate scope only:
- packaging
- verification
- capability/effect authorization
- deterministic audit artifacts

Out of scope:
- planning/orchestration
- autonomous tool selection
- scheduler/memory loops

## 3. Schema Versions

### `1.0.0-draft`

Required fields:
- `schema_version`
- `id`
- `name`
- `version`
- `entrypoint`
- `artifact`
- `inputs_schema`
- `outputs_schema`
- `capabilities`
- `signers`

`inputs_schema`/`outputs_schema` MAY be inline JSON Schema objects or URI refs.

### `1.1.0-draft`

All `1.0.0-draft` required fields plus required `tool_contract`.

For strict runtime enforcement in this draft, `inputs_schema` and
`outputs_schema` MUST be inline JSON Schema objects (URI refs are rejected).

## 4. `tool_contract` (v1.1)

Required fields:
- `schema_version`: must be `1.1.0-draft`
- `instructions`
- `effects`
- `determinism`
- `limits`

### 4.1 `instructions`

- `format`: `text/plain | text/markdown`
- `text`: immutable instruction payload
- `hash`: `sha256:<64hex>`

Verifier rule: `hash` MUST equal `sha256(text)`.

### 4.2 `effects`

`effects[*].kind` enum:
- `fs.read`
- `fs.read_tree`
- `fs.write`
- `net.http`
- `kv.read`
- `kv.write`
- `queue.publish`
- `queue.consume`
- `time.now`
- `random.bytes`

`effects[*].selector` is strictly typed by kind:
- fs kinds: `path_prefix`
- `net.http`: `url_prefix` + `methods` (this draft: exactly `["GET"]`)
- kv kinds: `key`
- queue kinds: `topic`
- time/random: empty selector object

`effects[*].limits`:
- `max_calls`
- `max_bytes_in`
- `max_bytes_out`

### 4.3 `determinism`

- `mode`: `deterministic | requires_capabilities`
- `required_capabilities`: list of nondeterminism capabilities

Rules:
- `deterministic` mode forbids `time.now`, `random.bytes`, `net.http` effects.
- `requires_capabilities` mode requires non-empty `required_capabilities`.
- Declared required capabilities must be present in `effects`.

### 4.4 `limits`

- `max_duration_ms`
- `max_memory_bytes`
- `max_input_bytes`
- `max_output_bytes`
- `max_effect_events`

All values must be positive integers.

## 5. Capability/Effect Equivalence Rule

For `1.1.0-draft`, runtime must derive canonical coarse capabilities from
`tool_contract.effects` and require exact set equality with
`manifest.capabilities` after normalization.

This dual declaration prevents drift between coarse policy controls and typed
runtime effect declarations.

## 6. Failure Semantics

Manifest parse/validation MUST fail for:
- unsupported `schema_version`
- missing required v1 fields
- malformed or incompatible effect selectors
- instructions hash mismatch
- deterministic mode violations
- capability/effect set mismatch
- URI schema refs in `1.1.0-draft`

## 7. Canonicalization and Integrity

- Hashing and signing remain aligned with `spec/hashing.md`.
- Canonical JSON remains RFC 8785 (JCS).
- No implicit/defaulted fields may influence signed preimages.

## 8. Rollout

- Experimental-first: `--allow-experimental` gate required.
- Stable v0 remains unchanged.
- `1.1.0-draft` strict contract enforcement is mandatory when selected.
