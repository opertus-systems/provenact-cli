mod common;

use std::fs;
use std::process::Command;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use common::{temp_dir, vectors_root};
use ed25519_dalek::SigningKey;
use provenact_verifier::{
    parse_receipt_json, parse_receipt_v1_draft_json, sha256_prefixed, verify_receipt_hash,
    verify_receipt_v1_draft_hash,
};
use serde_json::{Map, Value};
use wat::parse_str as wat_parse_str;

#[test]
fn e2e_fixture_verify_run_verify_receipt() {
    let fixture = vectors_root().join("good/verify-run-verify-receipt");
    let temp = temp_dir("e2e_fixture");
    let bundle_dir = temp.join("bundle");
    let wasm_path = temp.join("skill.wasm");
    let manifest_path = temp.join("manifest.json");
    let keys_path = temp.join("public-keys.json");
    let receipt_path = temp.join("receipt.json");

    let wat = fs::read_to_string(fixture.join("skill.wat")).expect("fixture wat should exist");
    let wasm = wat_parse_str(&wat).expect("fixture wat should compile");
    fs::write(&wasm_path, &wasm).expect("wasm write should succeed");
    let artifact = sha256_prefixed(&wasm);

    let mut manifest: Map<String, Value> = serde_json::from_slice(
        &fs::read(fixture.join("manifest.base.json")).expect("manifest base"),
    )
    .expect("manifest base should parse");
    manifest.insert("artifact".to_string(), Value::String(artifact.clone()));
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("manifest should encode"),
    )
    .expect("manifest write should succeed");

    let secret_key_b64 =
        fs::read_to_string(fixture.join("signer-secret-key.txt")).expect("secret key should exist");
    let secret_key_bytes = STANDARD
        .decode(secret_key_b64.trim().as_bytes())
        .expect("secret key should decode");
    let secret_key = SigningKey::from_bytes(
        &secret_key_bytes
            .as_slice()
            .try_into()
            .expect("secret key should be 32 bytes"),
    );
    fs::write(temp.join("signing.key"), secret_key_b64.as_bytes())
        .expect("signing key write should succeed");
    fs::write(
        &keys_path,
        format!(
            "{{\"alice.dev\":\"{}\"}}",
            STANDARD.encode(secret_key.verifying_key().to_bytes())
        ),
    )
    .expect("keys write should succeed");

    let pack = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["pack", "--bundle"])
        .arg(&bundle_dir)
        .args(["--wasm"])
        .arg(&wasm_path)
        .args(["--manifest"])
        .arg(&manifest_path)
        .output()
        .expect("pack should run");
    assert!(pack.status.success(), "{:?}", pack);

    let sign = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["sign", "--bundle"])
        .arg(&bundle_dir)
        .args(["--signer", "alice.dev", "--secret-key"])
        .arg(temp.join("signing.key"))
        .output()
        .expect("sign should run");
    assert!(sign.status.success(), "{:?}", sign);

    let verify = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["verify", "--bundle"])
        .arg(&bundle_dir)
        .args(["--keys"])
        .arg(&keys_path)
        .args(["--keys-digest"])
        .arg(sha256_prefixed(
            &fs::read(&keys_path).expect("keys should exist"),
        ))
        .output()
        .expect("verify should run");
    assert!(verify.status.success(), "{:?}", verify);

    let run = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["run", "--bundle"])
        .arg(&bundle_dir)
        .args(["--keys"])
        .arg(&keys_path)
        .args(["--keys-digest"])
        .arg(sha256_prefixed(
            &fs::read(&keys_path).expect("keys should exist"),
        ))
        .args(["--policy"])
        .arg(fixture.join("policy.json"))
        .args(["--input"])
        .arg(fixture.join("input.json"))
        .args(["--receipt"])
        .arg(&receipt_path)
        .output()
        .expect("run should run");
    assert!(run.status.success(), "{:?}", run);

    let verify_receipt = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["verify-receipt", "--receipt"])
        .arg(&receipt_path)
        .output()
        .expect("verify-receipt should run");
    assert!(verify_receipt.status.success(), "{:?}", verify_receipt);

    let receipt_raw = fs::read(&receipt_path).expect("receipt should exist");
    let receipt = parse_receipt_json(&receipt_raw).expect("receipt should parse");
    verify_receipt_hash(&receipt).expect("receipt hash should verify");
    assert_eq!(receipt.artifact, artifact);
    assert!(
        receipt.caps_used.is_empty(),
        "expected no used capabilities"
    );
}

#[test]
fn pack_requires_allow_experimental_for_draft_schema_version() {
    let fixture = vectors_root().join("good/verify-run-verify-receipt");
    let temp = temp_dir("e2e_experimental_gate");
    let bundle_dir = temp.join("bundle");
    let wasm_path = temp.join("skill.wasm");
    let manifest_path = temp.join("manifest.json");

    let wat = fs::read_to_string(fixture.join("skill.wat")).expect("fixture wat should exist");
    let wasm = wat_parse_str(&wat).expect("fixture wat should compile");
    fs::write(&wasm_path, &wasm).expect("wasm write should succeed");
    let artifact = sha256_prefixed(&wasm);

    let mut manifest: Map<String, Value> = serde_json::from_slice(
        &fs::read(fixture.join("manifest.base.json")).expect("manifest base"),
    )
    .expect("manifest base should parse");
    manifest.insert(
        "schema_version".to_string(),
        Value::String("1.0.0-draft".to_string()),
    );
    manifest.insert(
        "id".to_string(),
        Value::String("provenact.e2e.experimental".to_string()),
    );
    manifest.insert(
        "inputs_schema".to_string(),
        serde_json::json!({ "type": "object" }),
    );
    manifest.insert(
        "outputs_schema".to_string(),
        serde_json::json!({ "type": "object" }),
    );
    manifest.insert("artifact".to_string(), Value::String(artifact));
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("manifest should encode"),
    )
    .expect("manifest write should succeed");

    let pack_without_gate = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["pack", "--bundle"])
        .arg(&bundle_dir)
        .args(["--wasm"])
        .arg(&wasm_path)
        .args(["--manifest"])
        .arg(&manifest_path)
        .output()
        .expect("pack should run");
    assert!(
        !pack_without_gate.status.success(),
        "{:?}",
        pack_without_gate
    );
    assert!(
        String::from_utf8_lossy(&pack_without_gate.stderr)
            .contains("requires --allow-experimental"),
        "{:?}",
        pack_without_gate
    );

    let pack_with_gate = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["pack", "--bundle"])
        .arg(&bundle_dir)
        .args(["--wasm"])
        .arg(&wasm_path)
        .args(["--manifest"])
        .arg(&manifest_path)
        .arg("--allow-experimental")
        .output()
        .expect("pack should run");
    assert!(pack_with_gate.status.success(), "{:?}", pack_with_gate);
}

#[test]
fn e2e_contract_manifest_pack_sign_verify_run_verify_receipt() {
    let temp = temp_dir("e2e_contract_v1_1");
    let bundle_dir = temp.join("bundle");
    let wasm_path = temp.join("skill.wasm");
    let manifest_path = temp.join("manifest.json");
    let signing_key_path = temp.join("signing.key");
    let keys_path = temp.join("public-keys.json");
    let policy_path = temp.join("policy.json");
    let input_path = temp.join("input.json");
    let receipt_path = temp.join("receipt.json");

    let wat = r#"(module
  (import "provenact" "output_write" (func $output_write (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{\"ok\":true}")
  (func (export "run") (result i32)
    i32.const 0
    i32.const 11
    call $output_write
    drop
    i32.const 0
  )
)"#;
    let wasm = wat_parse_str(wat).expect("wat should compile");
    fs::write(&wasm_path, &wasm).expect("wasm write should succeed");
    let artifact = sha256_prefixed(&wasm);

    let manifest = serde_json::json!({
      "schema_version": "1.1.0-draft",
      "id": "provenact.e2e.contract.v1_1",
      "name": "e2e.contract.v1_1",
      "version": "0.1.0",
      "entrypoint": "run",
      "artifact": artifact,
      "inputs_schema": {
        "type": "object",
        "required": ["msg"],
        "properties": { "msg": { "type": "string" } },
        "additionalProperties": false
      },
      "outputs_schema": {
        "type": "object",
        "required": ["ok"],
        "properties": { "ok": { "type": "boolean" } },
        "additionalProperties": false
      },
      "capabilities": [],
      "signers": ["alice.dev"],
      "tool_contract": {
        "schema_version": "1.1.0-draft",
        "instructions": {
          "format": "text/plain",
          "text": "Echo input JSON as output JSON.",
          "hash": "sha256:d8c62139b7a0df514cf3851023843f03a787fab72ef90087cd2f2246a2755da6"
        },
        "effects": [],
        "determinism": {
          "mode": "deterministic",
          "required_capabilities": []
        },
        "limits": {
          "max_duration_ms": 5000,
          "max_memory_bytes": 1048576,
          "max_input_bytes": 4096,
          "max_output_bytes": 4096,
          "max_effect_events": 16
        }
      }
    });
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("manifest encode"),
    )
    .expect("manifest write should succeed");

    let signing_key = SigningKey::from_bytes(&[52u8; 32]);
    fs::write(
        &signing_key_path,
        STANDARD.encode(signing_key.to_bytes()).as_bytes(),
    )
    .expect("signing key write should succeed");
    fs::write(
        &keys_path,
        format!(
            "{{\"alice.dev\":\"{}\"}}",
            STANDARD.encode(signing_key.verifying_key().to_bytes())
        ),
    )
    .expect("keys write should succeed");

    fs::write(
        &policy_path,
        serde_json::to_vec_pretty(&serde_json::json!({
          "version": 1,
          "trusted_signers": ["alice.dev"],
          "capability_ceiling": {
            "exec": false,
            "time": false
          }
        }))
        .expect("policy encode"),
    )
    .expect("policy write should succeed");
    fs::write(&input_path, br#"{"msg":"hello"}"#).expect("input write should succeed");

    let pack = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["pack", "--bundle"])
        .arg(&bundle_dir)
        .args(["--wasm"])
        .arg(&wasm_path)
        .args(["--manifest"])
        .arg(&manifest_path)
        .arg("--allow-experimental")
        .output()
        .expect("pack should run");
    assert!(pack.status.success(), "{:?}", pack);

    let sign = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["sign", "--bundle"])
        .arg(&bundle_dir)
        .args(["--signer", "alice.dev", "--secret-key"])
        .arg(&signing_key_path)
        .arg("--allow-experimental")
        .output()
        .expect("sign should run");
    assert!(sign.status.success(), "{:?}", sign);

    let keys_digest = sha256_prefixed(&fs::read(&keys_path).expect("keys should exist"));
    let verify = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["verify", "--bundle"])
        .arg(&bundle_dir)
        .args(["--keys"])
        .arg(&keys_path)
        .args(["--keys-digest"])
        .arg(&keys_digest)
        .arg("--allow-experimental")
        .output()
        .expect("verify should run");
    assert!(verify.status.success(), "{:?}", verify);

    let run = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["run", "--bundle"])
        .arg(&bundle_dir)
        .args(["--keys"])
        .arg(&keys_path)
        .args(["--keys-digest"])
        .arg(&keys_digest)
        .args(["--policy"])
        .arg(&policy_path)
        .args(["--input"])
        .arg(&input_path)
        .args(["--receipt"])
        .arg(&receipt_path)
        .args(["--allow-experimental", "--receipt-format", "v1-draft"])
        .output()
        .expect("run should run");
    assert!(run.status.success(), "{:?}", run);

    let verify_receipt = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["verify-receipt", "--receipt"])
        .arg(&receipt_path)
        .output()
        .expect("verify-receipt should run");
    assert!(verify_receipt.status.success(), "{:?}", verify_receipt);

    let receipt_raw = fs::read(&receipt_path).expect("receipt should exist");
    let receipt = parse_receipt_v1_draft_json(&receipt_raw).expect("receipt should parse");
    verify_receipt_v1_draft_hash(&receipt).expect("receipt hash should verify");
    assert_eq!(receipt.schema_version, "1.1.0-draft");
    assert!(receipt.contract_hash.is_some());
    assert!(receipt.instructions_hash.is_some());
    assert!(receipt.input_schema_hash.is_some());
    assert!(receipt.output_schema_hash.is_some());
    assert!(receipt.effects_used.is_some());
}
