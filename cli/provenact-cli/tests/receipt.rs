mod common;

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use common::{temp_dir, wasm_with_i32_entrypoint, write};
use ed25519_dalek::SigningKey;
use provenact_verifier::sha256_prefixed;
use serde_json::Value;
use wat::parse_str as wat_parse_str;

fn make_receipt() -> PathBuf {
    let root = temp_dir("verify_receipt");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");
    let keys_path = root.join("public-keys.json");
    let policy_path = root.join("policy.json");
    let input_path = root.join("input.json");
    let receipt_path = root.join("receipt.json");

    let wasm = wasm_with_i32_entrypoint("run", 42);
    write(&wasm_path, &wasm);
    let artifact = sha256_prefixed(&wasm);
    let manifest = format!(
        "{{\"name\":\"echo.minimal\",\"version\":\"0.1.0\",\"entrypoint\":\"run\",\"artifact\":\"{artifact}\",\"capabilities\":[],\"signers\":[\"alice.dev\"]}}"
    );
    write(&manifest_path, manifest.as_bytes());

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

    let signing_key = SigningKey::from_bytes(&[33u8; 32]);
    write(
        &secret_key_path,
        STANDARD.encode(signing_key.to_bytes()).as_bytes(),
    );
    let sign = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["sign", "--bundle"])
        .arg(&bundle_dir)
        .args(["--signer", "alice.dev", "--secret-key"])
        .arg(&secret_key_path)
        .output()
        .expect("sign should run");
    assert!(sign.status.success(), "{:?}", sign);

    let keys = format!(
        "{{\"alice.dev\":\"{}\"}}",
        STANDARD.encode(signing_key.verifying_key().to_bytes())
    );
    write(&keys_path, keys.as_bytes());
    let policy = r#"{
      "version": 1,
      "trusted_signers": ["alice.dev"],
      "capability_ceiling": {
        "exec": false,
        "time": false
      }
    }"#;
    write(&policy_path, policy.as_bytes());
    write(&input_path, br#"{}"#);

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
        .arg(&policy_path)
        .args(["--input"])
        .arg(&input_path)
        .args(["--receipt"])
        .arg(&receipt_path)
        .output()
        .expect("run should run");
    assert!(run.status.success(), "{:?}", run);
    receipt_path
}

fn make_receipt_v1_draft() -> PathBuf {
    let root = temp_dir("verify_receipt_v1");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");
    let keys_path = root.join("public-keys.json");
    let policy_path = root.join("policy.json");
    let input_path = root.join("input.json");
    let receipt_path = root.join("receipt-v1.json");

    let wasm = wasm_with_i32_entrypoint("run", 42);
    write(&wasm_path, &wasm);
    let artifact = sha256_prefixed(&wasm);
    let manifest = format!(
        "{{\"name\":\"echo.minimal\",\"version\":\"0.1.0\",\"entrypoint\":\"run\",\"artifact\":\"{artifact}\",\"capabilities\":[],\"signers\":[\"alice.dev\"]}}"
    );
    write(&manifest_path, manifest.as_bytes());

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

    let signing_key = SigningKey::from_bytes(&[34u8; 32]);
    write(
        &secret_key_path,
        STANDARD.encode(signing_key.to_bytes()).as_bytes(),
    );
    let sign = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["sign", "--bundle"])
        .arg(&bundle_dir)
        .args(["--signer", "alice.dev", "--secret-key"])
        .arg(&secret_key_path)
        .output()
        .expect("sign should run");
    assert!(sign.status.success(), "{:?}", sign);

    let keys = format!(
        "{{\"alice.dev\":\"{}\"}}",
        STANDARD.encode(signing_key.verifying_key().to_bytes())
    );
    write(&keys_path, keys.as_bytes());
    let policy = r#"{
      "version": 1,
      "trusted_signers": ["alice.dev"],
      "capability_ceiling": {
        "exec": false,
        "time": false
      }
    }"#;
    write(&policy_path, policy.as_bytes());
    write(&input_path, br#"{}"#);

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
        .arg(&policy_path)
        .args(["--input"])
        .arg(&input_path)
        .args(["--receipt"])
        .arg(&receipt_path)
        .args(["--receipt-format", "v1-draft", "--allow-experimental"])
        .output()
        .expect("run should run");
    assert!(run.status.success(), "{:?}", run);
    receipt_path
}

fn make_receipt_v1_1_contract() -> PathBuf {
    let root = temp_dir("verify_receipt_v1_1_contract");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");
    let keys_path = root.join("public-keys.json");
    let policy_path = root.join("policy.json");
    let input_path = root.join("input.json");
    let receipt_path = root.join("receipt-v1.1.json");

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
    write(&wasm_path, &wasm);
    let artifact = sha256_prefixed(&wasm);
    let manifest = serde_json::json!({
      "schema_version": "1.1.0-draft",
      "id": "provenact.receipt.contract",
      "name": "receipt.contract",
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
          "max_duration_ms": 2000,
          "max_memory_bytes": 1048576,
          "max_input_bytes": 4096,
          "max_output_bytes": 4096,
          "max_effect_events": 8
        }
      }
    });
    write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest)
            .expect("manifest should serialize")
            .as_slice(),
    );

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

    let signing_key = SigningKey::from_bytes(&[39u8; 32]);
    write(
        &secret_key_path,
        STANDARD.encode(signing_key.to_bytes()).as_bytes(),
    );
    let sign = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["sign", "--bundle"])
        .arg(&bundle_dir)
        .args(["--signer", "alice.dev", "--secret-key"])
        .arg(&secret_key_path)
        .arg("--allow-experimental")
        .output()
        .expect("sign should run");
    assert!(sign.status.success(), "{:?}", sign);

    let keys = format!(
        "{{\"alice.dev\":\"{}\"}}",
        STANDARD.encode(signing_key.verifying_key().to_bytes())
    );
    write(&keys_path, keys.as_bytes());
    let policy = r#"{
      "version": 1,
      "trusted_signers": ["alice.dev"],
      "capability_ceiling": {
        "exec": false,
        "time": false
      }
    }"#;
    write(&policy_path, policy.as_bytes());
    write(&input_path, br#"{"msg":"hello"}"#);

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
        .arg(&policy_path)
        .args(["--input"])
        .arg(&input_path)
        .args(["--receipt"])
        .arg(&receipt_path)
        .args(["--allow-experimental", "--receipt-format", "v1-draft"])
        .output()
        .expect("run should run");
    assert!(run.status.success(), "{:?}", run);
    receipt_path
}

#[test]
fn verify_receipt_succeeds_for_valid_receipt() {
    let receipt_path = make_receipt();
    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["verify-receipt", "--receipt"])
        .arg(&receipt_path)
        .output()
        .expect("verify-receipt should run");
    assert!(output.status.success(), "{:?}", output);
}

#[test]
fn verify_receipt_fails_for_tampered_receipt() {
    let receipt_path = make_receipt();
    let raw = fs::read(&receipt_path).expect("receipt should exist");
    let mut value: Value = serde_json::from_slice(&raw).expect("receipt json should parse");
    value["outputs_hash"] = Value::String(
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string(),
    );
    fs::write(
        &receipt_path,
        serde_json::to_vec_pretty(&value).expect("receipt json should serialize"),
    )
    .expect("tamper write should succeed");

    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["verify-receipt", "--receipt"])
        .arg(&receipt_path)
        .output()
        .expect("verify-receipt should run");
    assert!(!output.status.success(), "{:?}", output);
}

#[test]
fn verify_receipt_succeeds_for_valid_v1_draft_receipt() {
    let receipt_path = make_receipt_v1_draft();
    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["verify-receipt", "--receipt"])
        .arg(&receipt_path)
        .output()
        .expect("verify-receipt should run");
    assert!(output.status.success(), "{:?}", output);
}

#[test]
fn verify_receipt_succeeds_for_valid_v1_1_contract_receipt() {
    let receipt_path = make_receipt_v1_1_contract();
    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["verify-receipt", "--receipt"])
        .arg(&receipt_path)
        .output()
        .expect("verify-receipt should run");
    assert!(output.status.success(), "{:?}", output);
}

#[test]
fn verify_receipt_fails_for_tampered_v1_1_contract_hash() {
    let receipt_path = make_receipt_v1_1_contract();
    let raw = fs::read(&receipt_path).expect("receipt should exist");
    let mut value: Value = serde_json::from_slice(&raw).expect("receipt json should parse");
    value["contract_hash"] = Value::String(
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string(),
    );
    fs::write(
        &receipt_path,
        serde_json::to_vec_pretty(&value).expect("receipt json should serialize"),
    )
    .expect("tamper write should succeed");

    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["verify-receipt", "--receipt"])
        .arg(&receipt_path)
        .output()
        .expect("verify-receipt should run");
    assert!(!output.status.success(), "{:?}", output);
}

#[test]
fn verify_receipt_fails_for_tampered_v1_1_effects_used() {
    let receipt_path = make_receipt_v1_1_contract();
    let raw = fs::read(&receipt_path).expect("receipt should exist");
    let mut value: Value = serde_json::from_slice(&raw).expect("receipt json should parse");
    value["effects_used"] = serde_json::json!([
      {
        "kind": "fs.read",
        "selector": "/tmp/provenact",
        "calls": 9,
        "bytes_in": 0,
        "bytes_out": 0,
        "denied_calls": 0
      }
    ]);
    fs::write(
        &receipt_path,
        serde_json::to_vec_pretty(&value).expect("receipt json should serialize"),
    )
    .expect("tamper write should succeed");

    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["verify-receipt", "--receipt"])
        .arg(&receipt_path)
        .output()
        .expect("verify-receipt should run");
    assert!(!output.status.success(), "{:?}", output);
}

#[test]
fn verify_receipt_fails_for_tampered_v1_1_schema_hash() {
    let receipt_path = make_receipt_v1_1_contract();
    let raw = fs::read(&receipt_path).expect("receipt should exist");
    let mut value: Value = serde_json::from_slice(&raw).expect("receipt json should parse");
    value["input_schema_hash"] = Value::String(
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
    );
    fs::write(
        &receipt_path,
        serde_json::to_vec_pretty(&value).expect("receipt json should serialize"),
    )
    .expect("tamper write should succeed");

    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["verify-receipt", "--receipt"])
        .arg(&receipt_path)
        .output()
        .expect("verify-receipt should run");
    assert!(!output.status.success(), "{:?}", output);
}
