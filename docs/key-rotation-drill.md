# Key Rotation Drill

This drill proves that trust-anchor digest pinning fails closed during keyset
rotation.

## Fixture

Use:
- `test-vectors/good/minimal-zero-cap/` as the signed bundle.
- `test-vectors/key-rotation/public-keys.v1.json` as the current keyset.
- `test-vectors/key-rotation/public-keys.v2.json` as the rotated keyset.

## Commands

From repo root:

```bash
BUNDLE=test-vectors/good/minimal-zero-cap
KEYS_V1=test-vectors/key-rotation/public-keys.v1.json
KEYS_V2=test-vectors/key-rotation/public-keys.v2.json

DIGEST_V1="$(shasum -a 256 "$KEYS_V1" | awk '{print "sha256:"$1}')"
DIGEST_V2="$(shasum -a 256 "$KEYS_V2" | awk '{print "sha256:"$1}')"

cargo run -q -p provenact-cli --bin provenact-cli -- verify \
  --bundle "$BUNDLE" \
  --keys "$KEYS_V1" \
  --keys-digest "$DIGEST_V1"

! cargo run -q -p provenact-cli --bin provenact-cli -- verify \
  --bundle "$BUNDLE" \
  --keys "$KEYS_V2" \
  --keys-digest "$DIGEST_V1"

cargo run -q -p provenact-cli --bin provenact-cli -- verify \
  --bundle "$BUNDLE" \
  --keys "$KEYS_V2" \
  --keys-digest "$DIGEST_V2"
```

## Expected Results

- The first command succeeds with the current keyset and current digest.
- The second command fails because the rotated keyset does not match the old
  digest pin.
- The third command succeeds after the digest pin is updated for the rotated
  keyset.

Record the command output and both digest values in the release audit packet.
