# Policy Rollout Modes

`provenact-cli run` supports staged capability-ceiling rollout with:

```bash
--policy-mode <audit|warn|enforce>
```

Default mode is `enforce`.

## Modes

- `enforce`: capability-ceiling findings are fatal.
- `warn`: capability-ceiling findings are logged to stderr and execution
  continues.
- `audit`: capability-ceiling findings are logged to stderr and execution
  continues.

`audit` and `warn` downgrade only `enforce_capability_ceiling` findings for
declared manifest capabilities. These modes are for policy migration and
staged rollout.

## Hard Stops In Every Mode

The following gates remain fatal in `audit`, `warn`, and `enforce`:

- bundle artifact and manifest hash mismatches
- malformed manifests, signatures, policies, keys, inputs, or receipts
- missing or mismatched `--keys-digest`
- invalid Ed25519 signatures
- untrusted manifest signer sets
- signatures by signers not declared in the manifest
- missing trusted signature set
- experimental schema usage without `--allow-experimental`
- contract schema/input/output/effect violations
- runtime traps, fuel exhaustion, and resource limit failures

Rollout modes do not add agency, orchestration, scheduling, or tool selection.
They only adjust whether a capability-ceiling finding blocks a single verified
execution.
