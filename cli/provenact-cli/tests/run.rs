mod common;

use std::fs;
use std::process::Command;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use common::{
    temp_dir, wasm_with_i32_entrypoint, wasm_with_infinite_loop, wasm_with_memory_growth_trap,
    write,
};
use ed25519_dalek::SigningKey;
use provenact_verifier::{
    parse_receipt_json, parse_receipt_v1_draft_json, sha256_prefixed, verify_receipt_hash,
    verify_receipt_v1_draft_hash,
};
use serde_json::json;
use wat::parse_str as wat_parse_str;

#[test]
fn run_emits_valid_receipt_after_verification_and_policy_check() {
    let root = temp_dir("run_ok");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");
    let keys_path = root.join("public-keys.json");
    let policy_path = root.join("policy.json");
    let input_path = root.join("input.json");
    let receipt_path = root.join("receipt.json");

    let wasm = wasm_with_i32_entrypoint("run", 7);
    write(&wasm_path, &wasm);
    let artifact = sha256_prefixed(&wasm);
    let manifest = format!(
        "{{\"name\":\"echo.minimal\",\"version\":\"0.1.0\",\"entrypoint\":\"run\",\"artifact\":\"{artifact}\",\"capabilities\":[{{\"kind\":\"env\",\"value\":\"HOME\"}}],\"signers\":[\"alice.dev\"]}}"
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

    let signing_key = SigningKey::from_bytes(&[21u8; 32]);
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
        "env": ["HOME"],
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
        .output()
        .expect("run should run");
    assert!(run.status.success(), "{:?}", run);

    let receipt_raw = fs::read(&receipt_path).expect("receipt should exist");
    let receipt = parse_receipt_json(&receipt_raw).expect("receipt should parse");
    verify_receipt_hash(&receipt).expect("receipt hash should verify");
    assert_eq!(receipt.artifact, artifact);
    assert_eq!(receipt.inputs_hash, sha256_prefixed(br#"{"msg":"hello"}"#));
    assert_eq!(receipt.outputs_hash, sha256_prefixed(b"7"));
}

#[test]
fn run_denies_capability_outside_policy_ceiling() {
    let root = temp_dir("run_policy_deny");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");
    let keys_path = root.join("public-keys.json");
    let policy_path = root.join("policy.yaml");
    let input_path = root.join("input.json");
    let receipt_path = root.join("receipt.json");

    let wasm = wasm_with_i32_entrypoint("run", 1);
    write(&wasm_path, &wasm);
    let artifact = sha256_prefixed(&wasm);
    let manifest = format!(
        "{{\"name\":\"echo.minimal\",\"version\":\"0.1.0\",\"entrypoint\":\"run\",\"artifact\":\"{artifact}\",\"capabilities\":[{{\"kind\":\"net\",\"value\":\"https://example.com/api\"}}],\"signers\":[\"alice.dev\"]}}"
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

    let signing_key = SigningKey::from_bytes(&[22u8; 32]);
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
    let policy = r#"
version: 1
trusted_signers: ["alice.dev"]
capability_ceiling:
  net: ["https://api.open-meteo.com"]
  exec: false
  time: false
"#;
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
    assert!(!run.status.success(), "{:?}", run);

    let stderr = String::from_utf8(run.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("capability denied"), "stderr was: {stderr}");
    assert!(!receipt_path.exists(), "receipt should not exist on deny");
}

#[test]
fn run_warn_and_audit_policy_modes_allow_capability_ceiling_finding() {
    let root = temp_dir("run_policy_mode_warn_audit");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");
    let keys_path = root.join("public-keys.json");
    let policy_path = root.join("policy.yaml");
    let input_path = root.join("input.json");

    let wasm = wasm_with_i32_entrypoint("run", 5);
    write(&wasm_path, &wasm);
    let artifact = sha256_prefixed(&wasm);
    let manifest = format!(
        "{{\"name\":\"echo.minimal\",\"version\":\"0.1.0\",\"entrypoint\":\"run\",\"artifact\":\"{artifact}\",\"capabilities\":[{{\"kind\":\"net\",\"value\":\"https://example.com/api\"}}],\"signers\":[\"alice.dev\"]}}"
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

    let signing_key = SigningKey::from_bytes(&[40u8; 32]);
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
    let policy = r#"
version: 1
trusted_signers: ["alice.dev"]
capability_ceiling:
  net: ["https://api.open-meteo.com"]
  exec: false
  time: false
"#;
    write(&policy_path, policy.as_bytes());
    write(&input_path, br#"{}"#);
    let keys_digest = sha256_prefixed(&fs::read(&keys_path).expect("keys should exist"));

    for mode in ["warn", "audit"] {
        let receipt_path = root.join(format!("receipt-{mode}.json"));
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
            .args(["--policy-mode", mode])
            .output()
            .expect("run should run");

        assert!(run.status.success(), "{mode}: {run:?}");
        assert!(receipt_path.exists(), "{mode}: receipt should exist");
        let stderr = String::from_utf8(run.stderr).expect("stderr should be utf8");
        assert!(
            stderr.contains(&format!("policy-mode {mode}: capability ceiling finding")),
            "{mode}: stderr was: {stderr}"
        );
    }
}

#[test]
fn run_rejects_unknown_policy_mode() {
    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["run", "--policy-mode", "observe"])
        .output()
        .expect("run should run");
    assert!(!output.status.success(), "{:?}", output);
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("unsupported --policy-mode"),
        "stderr was: {stderr}"
    );
}

#[test]
fn run_fails_when_require_cosign_without_cert_identity() {
    let root = temp_dir("run_require_cosign_no_cert_identity");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");
    let keys_path = root.join("public-keys.json");
    let cosign_pub_path = root.join("cosign.pub");
    let policy_path = root.join("policy.json");
    let input_path = root.join("input.json");
    let receipt_path = root.join("receipt.json");

    let wasm = wasm_with_i32_entrypoint("run", 9);
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

    let signing_key = SigningKey::from_bytes(&[31u8; 32]);
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
    write(&cosign_pub_path, b"dummy cosign public key");

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
        .args(["--oci-ref", "ghcr.io/acme/echo:0.1.0"])
        .args(["--cosign-key"])
        .arg(&cosign_pub_path)
        .arg("--require-cosign")
        .output()
        .expect("run should run");
    assert!(!run.status.success(), "{:?}", run);
    let stderr = String::from_utf8(run.stderr).expect("stderr should be utf8");
    assert!(
        stderr
            .contains("--cosign-cert-identity is required when cosign verification is configured"),
        "stderr was: {stderr}"
    );
    assert!(
        !receipt_path.exists(),
        "receipt should not exist on failed run"
    );
}

#[test]
fn run_stops_infinite_loop_on_fuel_exhaustion() {
    let root = temp_dir("run_fuel_exhaustion");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");
    let keys_path = root.join("public-keys.json");
    let policy_path = root.join("policy.json");
    let input_path = root.join("input.json");
    let receipt_path = root.join("receipt.json");

    let wasm = wasm_with_infinite_loop("run");
    write(&wasm_path, &wasm);
    let artifact = sha256_prefixed(&wasm);
    let manifest = format!(
        "{{\"name\":\"loop.minimal\",\"version\":\"0.1.0\",\"entrypoint\":\"run\",\"artifact\":\"{artifact}\",\"capabilities\":[],\"signers\":[\"alice.dev\"]}}"
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

    let signing_key = SigningKey::from_bytes(&[23u8; 32]);
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
    assert!(!run.status.success(), "{:?}", run);
    let stderr = String::from_utf8(run.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("fuel exhausted"), "stderr was: {stderr}");
    assert!(!receipt_path.exists(), "receipt should not exist on trap");
}

#[test]
fn run_stops_memory_growth_abuse() {
    let root = temp_dir("run_memory_limit");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");
    let keys_path = root.join("public-keys.json");
    let policy_path = root.join("policy.json");
    let input_path = root.join("input.json");
    let receipt_path = root.join("receipt.json");

    let wasm = wasm_with_memory_growth_trap("run", 1024);
    write(&wasm_path, &wasm);
    let artifact = sha256_prefixed(&wasm);
    let manifest = format!(
        "{{\"name\":\"memory.minimal\",\"version\":\"0.1.0\",\"entrypoint\":\"run\",\"artifact\":\"{artifact}\",\"capabilities\":[],\"signers\":[\"alice.dev\"]}}"
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

    let signing_key = SigningKey::from_bytes(&[24u8; 32]);
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
    assert!(!run.status.success(), "{:?}", run);
    let stderr = String::from_utf8(run.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("wasm execution failed"),
        "stderr was: {stderr}"
    );
    assert!(!receipt_path.exists(), "receipt should not exist on trap");
}

#[test]
fn run_emits_v1_draft_receipt_with_security_digests() {
    let root = temp_dir("run_v1_draft_ok");
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

    let signing_key = SigningKey::from_bytes(&[25u8; 32]);
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

    let receipt_raw = fs::read(&receipt_path).expect("receipt should exist");
    let receipt = parse_receipt_v1_draft_json(&receipt_raw).expect("receipt should parse");
    verify_receipt_v1_draft_hash(&receipt).expect("receipt hash should verify");
    assert_eq!(receipt.schema_version, "1.0.0-draft");
    assert_eq!(receipt.timestamp_strategy, "local_untrusted_unix_seconds");
    assert_eq!(receipt.artifact, artifact);
}

#[test]
fn run_rejects_v1_draft_receipt_without_allow_experimental() {
    let root = temp_dir("run_v1_draft_gate");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");
    let keys_path = root.join("public-keys.json");
    let policy_path = root.join("policy.json");
    let input_path = root.join("input.json");
    let receipt_path = root.join("receipt-v1.json");

    let wasm = wasm_with_i32_entrypoint("run", 1);
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

    let signing_key = SigningKey::from_bytes(&[26u8; 32]);
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
        .args(["--receipt-format", "v1-draft"])
        .output()
        .expect("run should run");
    assert!(!run.status.success(), "{:?}", run);
    let stderr = String::from_utf8(run.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("requires --allow-experimental"),
        "stderr was: {stderr}"
    );
}

#[test]
fn run_rejects_keys_digest_mismatch() {
    let root = temp_dir("run_keys_digest_mismatch");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");
    let keys_path = root.join("public-keys.json");
    let policy_path = root.join("policy.json");
    let input_path = root.join("input.json");
    let receipt_path = root.join("receipt.json");

    let wasm = wasm_with_i32_entrypoint("run", 3);
    write(&wasm_path, &wasm);
    let artifact = sha256_prefixed(&wasm);
    let manifest = format!(
        "{{\"name\":\"keys.minimal\",\"version\":\"0.1.0\",\"entrypoint\":\"run\",\"artifact\":\"{artifact}\",\"capabilities\":[],\"signers\":[\"alice.dev\"]}}"
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

    let signing_key = SigningKey::from_bytes(&[25u8; 32]);
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
        .args([
            "--keys-digest",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ])
        .args(["--policy"])
        .arg(&policy_path)
        .args(["--input"])
        .arg(&input_path)
        .args(["--receipt"])
        .arg(&receipt_path)
        .output()
        .expect("run should run");
    assert!(!run.status.success(), "{:?}", run);
    let stderr = String::from_utf8(run.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("public keys digest mismatch"),
        "stderr was: {stderr}"
    );
    assert!(
        !receipt_path.exists(),
        "receipt should not exist on digest mismatch"
    );
}

#[test]
fn run_requires_keys_digest_flag() {
    let root = temp_dir("run_keys_digest_required");
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");
    let keys_path = root.join("public-keys.json");
    let policy_path = root.join("policy.json");
    let input_path = root.join("input.json");
    let receipt_path = root.join("receipt.json");

    let wasm = wasm_with_i32_entrypoint("run", 5);
    write(&wasm_path, &wasm);
    let artifact = sha256_prefixed(&wasm);
    let manifest = format!(
        "{{\"name\":\"digest.required\",\"version\":\"0.1.0\",\"entrypoint\":\"run\",\"artifact\":\"{artifact}\",\"capabilities\":[],\"signers\":[\"alice.dev\"]}}"
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

    let signing_key = SigningKey::from_bytes(&[27u8; 32]);
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
        .args(["--policy"])
        .arg(&policy_path)
        .args(["--input"])
        .arg(&input_path)
        .args(["--receipt"])
        .arg(&receipt_path)
        .output()
        .expect("run should run");
    assert!(!run.status.success(), "{:?}", run);
    let stderr = String::from_utf8(run.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("usage:"), "stderr was: {stderr}");
}

struct ContractBundlePaths {
    bundle_dir: std::path::PathBuf,
    keys_path: std::path::PathBuf,
    policy_path: std::path::PathBuf,
    input_path: std::path::PathBuf,
    receipt_path: std::path::PathBuf,
}

fn make_contract_bundle(
    test_name: &str,
    wasm: &[u8],
    capabilities: serde_json::Value,
    effects: serde_json::Value,
    input_json: &[u8],
) -> ContractBundlePaths {
    let root = temp_dir(test_name);
    let wasm_path = root.join("input.wasm");
    let manifest_path = root.join("input.manifest.json");
    let bundle_dir = root.join("bundle");
    let secret_key_path = root.join("signing.key");
    let keys_path = root.join("public-keys.json");
    let policy_path = root.join("policy.json");
    let input_path = root.join("input.json");
    let receipt_path = root.join("receipt-v1.1.json");

    write(&wasm_path, wasm);
    let artifact = sha256_prefixed(wasm);
    let manifest = json!({
      "schema_version": "1.1.0-draft",
      "id": format!("provenact.{test_name}"),
      "name": format!("{test_name}.manifest"),
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
      "capabilities": capabilities,
      "signers": ["alice.dev"],
      "tool_contract": {
        "schema_version": "1.1.0-draft",
        "instructions": {
          "format": "text/plain",
          "text": "Echo input JSON as output JSON.",
          "hash": "sha256:d8c62139b7a0df514cf3851023843f03a787fab72ef90087cd2f2246a2755da6"
        },
        "effects": effects,
        "determinism": {
          "mode": "deterministic",
          "required_capabilities": []
        },
        "limits": {
          "max_duration_ms": 5000,
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

    let signing_key = SigningKey::from_bytes(&[41u8; 32]);
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
        "fs": { "read": ["/tmp/provenact"] },
        "exec": false,
        "time": false
      }
    }"#;
    write(&policy_path, policy.as_bytes());
    write(&input_path, input_json);

    ContractBundlePaths {
        bundle_dir,
        keys_path,
        policy_path,
        input_path,
        receipt_path,
    }
}

#[test]
fn run_contract_enabled_requires_v1_draft_receipt_format() {
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
    let fixture = make_contract_bundle(
        "run_contract_requires_v1_receipt",
        &wasm,
        json!([]),
        json!([]),
        br#"{"msg":"hello"}"#,
    );

    let run = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["run", "--bundle"])
        .arg(&fixture.bundle_dir)
        .args(["--keys"])
        .arg(&fixture.keys_path)
        .args(["--keys-digest"])
        .arg(sha256_prefixed(
            &fs::read(&fixture.keys_path).expect("keys should exist"),
        ))
        .args(["--policy"])
        .arg(&fixture.policy_path)
        .args(["--input"])
        .arg(&fixture.input_path)
        .args(["--receipt"])
        .arg(&fixture.receipt_path)
        .arg("--allow-experimental")
        .output()
        .expect("run should run");
    assert!(!run.status.success(), "{:?}", run);
    let stderr = String::from_utf8(run.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("contract-enabled manifests require --receipt-format v1-draft"),
        "stderr was: {stderr}"
    );
}

#[test]
fn run_contract_rejects_input_schema_mismatch_before_execution() {
    let wasm = wasm_with_i32_entrypoint("run", 7);
    let fixture = make_contract_bundle(
        "run_contract_input_schema_mismatch",
        &wasm,
        json!([]),
        json!([]),
        br#"{"bad":"field"}"#,
    );

    let run = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["run", "--bundle"])
        .arg(&fixture.bundle_dir)
        .args(["--keys"])
        .arg(&fixture.keys_path)
        .args(["--keys-digest"])
        .arg(sha256_prefixed(
            &fs::read(&fixture.keys_path).expect("keys should exist"),
        ))
        .args(["--policy"])
        .arg(&fixture.policy_path)
        .args(["--input"])
        .arg(&fixture.input_path)
        .args(["--receipt"])
        .arg(&fixture.receipt_path)
        .args(["--allow-experimental", "--receipt-format", "v1-draft"])
        .output()
        .expect("run should run");
    assert!(!run.status.success(), "{:?}", run);
    let stderr = String::from_utf8(run.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("input schema validation failed"),
        "stderr was: {stderr}"
    );
    assert!(
        !fixture.receipt_path.exists(),
        "input schema mismatch should fail before runtime receipt generation"
    );
}

#[test]
fn run_contract_writes_failure_receipt_for_output_schema_violation() {
    let wasm = wasm_with_i32_entrypoint("run", 7);
    let fixture = make_contract_bundle(
        "run_contract_output_schema_mismatch",
        &wasm,
        json!([]),
        json!([]),
        br#"{"msg":"hello"}"#,
    );

    let run = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["run", "--bundle"])
        .arg(&fixture.bundle_dir)
        .args(["--keys"])
        .arg(&fixture.keys_path)
        .args(["--keys-digest"])
        .arg(sha256_prefixed(
            &fs::read(&fixture.keys_path).expect("keys should exist"),
        ))
        .args(["--policy"])
        .arg(&fixture.policy_path)
        .args(["--input"])
        .arg(&fixture.input_path)
        .args(["--receipt"])
        .arg(&fixture.receipt_path)
        .args(["--allow-experimental", "--receipt-format", "v1-draft"])
        .output()
        .expect("run should run");
    assert!(!run.status.success(), "{:?}", run);
    let stderr = String::from_utf8(run.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("output schema validation failed"),
        "stderr was: {stderr}"
    );

    let receipt_raw = fs::read(&fixture.receipt_path).expect("failure receipt should exist");
    let receipt = parse_receipt_v1_draft_json(&receipt_raw).expect("receipt should parse");
    verify_receipt_v1_draft_hash(&receipt).expect("receipt hash should verify");
    assert_eq!(receipt.schema_version, "1.1.0-draft");
    assert_eq!(receipt.result.status, "failure");
    assert_eq!(receipt.result.code, "output_schema_mismatch");
}
