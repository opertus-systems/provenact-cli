mod common;

use std::process::Command;

use common::vectors_root;

#[test]
fn experimental_validate_manifest_v1_accepts_good_vector() {
    let manifest_path = vectors_root().join("skill-format/manifest-v1/good/basic-draft.json");
    let out = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["experimental-validate-manifest-v1", "--manifest"])
        .arg(&manifest_path)
        .output()
        .expect("command should run");
    assert!(out.status.success(), "{:?}", out);
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .contains("OK experimental-validate-manifest-v1 id=provenact.echo.minimal"),
        "{:?}",
        out
    );
}

#[test]
fn experimental_validate_manifest_v1_accepts_good_contract_vector() {
    let manifest_path = vectors_root().join("skill-format/manifest-v1/good/contract-v1.1.json");
    let out = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["experimental-validate-manifest-v1", "--manifest"])
        .arg(&manifest_path)
        .output()
        .expect("command should run");
    assert!(out.status.success(), "{:?}", out);
}

#[test]
fn experimental_validate_manifest_v1_rejects_bad_vector() {
    let manifest_path = vectors_root().join("skill-format/manifest-v1/bad/missing_id.json");
    let out = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["experimental-validate-manifest-v1", "--manifest"])
        .arg(&manifest_path)
        .output()
        .expect("command should run");
    assert!(!out.status.success(), "{:?}", out);
}

#[test]
fn experimental_validate_manifest_v1_rejects_bad_contract_vector() {
    let manifest_path = vectors_root()
        .join("skill-format/manifest-v1/bad/contract_instructions_hash_mismatch.json");
    let out = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["experimental-validate-manifest-v1", "--manifest"])
        .arg(&manifest_path)
        .output()
        .expect("command should run");
    assert!(!out.status.success(), "{:?}", out);
}

#[test]
fn experimental_validate_receipt_v1_accepts_good_vector() {
    let receipt_path = vectors_root().join("receipt-v1/good/basic-success.json");
    let out = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["experimental-validate-receipt-v1", "--receipt"])
        .arg(&receipt_path)
        .output()
        .expect("command should run");
    assert!(out.status.success(), "{:?}", out);
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .contains("OK experimental-validate-receipt-v1 artifact=sha256:aaaaaaaa"),
        "{:?}",
        out
    );
}

#[test]
fn experimental_validate_receipt_v1_accepts_good_contract_vector() {
    let receipt_path = vectors_root().join("receipt-v1/good/contract-success-1.1.json");
    let out = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["experimental-validate-receipt-v1", "--receipt"])
        .arg(&receipt_path)
        .output()
        .expect("command should run");
    assert!(out.status.success(), "{:?}", out);
}

#[test]
fn experimental_validate_receipt_v1_rejects_bad_vector() {
    let receipt_path = vectors_root().join("receipt-v1/bad/missing_policy_hash.json");
    let out = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["experimental-validate-receipt-v1", "--receipt"])
        .arg(&receipt_path)
        .output()
        .expect("command should run");
    assert!(!out.status.success(), "{:?}", out);
}

#[test]
fn experimental_validate_receipt_v1_rejects_bad_contract_vector() {
    let receipt_path =
        vectors_root().join("receipt-v1/bad/contract_missing_required_fields_1.1.json");
    let out = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["experimental-validate-receipt-v1", "--receipt"])
        .arg(&receipt_path)
        .output()
        .expect("command should run");
    assert!(!out.status.success(), "{:?}", out);
}
