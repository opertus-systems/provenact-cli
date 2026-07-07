# Key Rotation Fixture

This fixture supports the operator key-rotation drill in
`docs/key-rotation-drill.md`.

- `public-keys.v1.json`: current trusted signer set.
- `public-keys.v2.json`: rotated trusted signer set with an added signer.

The fixture is intentionally small. It proves trust-anchor digest pinning:
commands must fail when the key file bytes and `--keys-digest` pin diverge, even
when the key material still contains the signer needed by the test bundle.
