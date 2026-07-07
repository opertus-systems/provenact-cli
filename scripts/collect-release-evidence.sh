#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ID="${1:-$(date '+%Y%m%d-%H%M%S')}"
OUT_DIR="${RELEASE_EVIDENCE_DIR:-$ROOT_DIR/target/release-evidence/$RUN_ID}"
CLI=(cargo run -q -p provenact-cli --bin provenact-cli --)

mkdir -p "$OUT_DIR"

log_run() {
  local name="$1"
  shift
  local log="$OUT_DIR/$name.log"
  echo "== $name ==" | tee "$log"
  echo "command: $*" | tee -a "$log"
  "$@" 2>&1 | tee -a "$log"
}

{
  echo "run_id=$RUN_ID"
  echo "created_at=$(date '+%Y-%m-%dT%H:%M:%S%z')"
  echo "git_commit=$(git -C "$ROOT_DIR" rev-parse HEAD)"
  echo "git_branch=$(git -C "$ROOT_DIR" branch --show-current || true)"
  echo "git_status_short=$(git -C "$ROOT_DIR" status --short | wc -l | tr -d ' ')"
} > "$OUT_DIR/metadata.txt"

log_run conformance cargo conformance
log_run cli-tests cargo test -p provenact-cli
log_run keys-digest-usage "$ROOT_DIR/scripts/check-keys-digest-usage.sh"

BUNDLE="$ROOT_DIR/test-vectors/good/minimal-zero-cap"
KEYS_V1="$ROOT_DIR/test-vectors/key-rotation/public-keys.v1.json"
KEYS_V2="$ROOT_DIR/test-vectors/key-rotation/public-keys.v2.json"
DIGEST_V1="$(shasum -a 256 "$KEYS_V1" | awk '{print "sha256:"$1}')"
DIGEST_V2="$(shasum -a 256 "$KEYS_V2" | awk '{print "sha256:"$1}')"

{
  echo "keys_v1=$KEYS_V1"
  echo "keys_v1_digest=$DIGEST_V1"
  echo "keys_v2=$KEYS_V2"
  echo "keys_v2_digest=$DIGEST_V2"
} > "$OUT_DIR/key-rotation-digests.txt"

log_run key-rotation-current "${CLI[@]}" verify \
  --bundle "$BUNDLE" \
  --keys "$KEYS_V1" \
  --keys-digest "$DIGEST_V1"

if "${CLI[@]}" verify \
  --bundle "$BUNDLE" \
  --keys "$KEYS_V2" \
  --keys-digest "$DIGEST_V1" > "$OUT_DIR/key-rotation-stale-pin.log" 2>&1; then
  echo "expected stale key digest pin to fail" | tee -a "$OUT_DIR/key-rotation-stale-pin.log"
  exit 1
fi
echo "stale key digest pin failed as expected" >> "$OUT_DIR/key-rotation-stale-pin.log"

log_run key-rotation-rotated "${CLI[@]}" verify \
  --bundle "$BUNDLE" \
  --keys "$KEYS_V2" \
  --keys-digest "$DIGEST_V2"

if command -v gh >/dev/null 2>&1; then
  gh run list --limit 20 > "$OUT_DIR/github-runs.txt" 2>&1 || true
fi

if command -v syft >/dev/null 2>&1; then
  syft dir:"$ROOT_DIR" -o spdx-json > "$OUT_DIR/sbom.spdx.json" 2> "$OUT_DIR/syft.log" || true
else
  echo "syft not installed" > "$OUT_DIR/syft.log"
fi

if command -v trivy >/dev/null 2>&1; then
  trivy fs --quiet --format json --output "$OUT_DIR/trivy-fs.json" "$ROOT_DIR" \
    > "$OUT_DIR/trivy.log" 2>&1 || true
else
  echo "trivy not installed" > "$OUT_DIR/trivy.log"
fi

echo "OK release evidence collected: $OUT_DIR"
