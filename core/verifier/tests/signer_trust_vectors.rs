use std::fs;
use std::path::{Path, PathBuf};

use provenact_verifier::{
    parse_manifest_json, parse_policy_document, parse_signatures_json, verify_trusted_signers,
    VerifyError,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct SignerTrustVector {
    cases: Vec<SignerTrustCase>,
}

#[derive(Debug, Deserialize)]
struct SignerTrustCase {
    name: String,
    expect: String,
    manifest: Value,
    signatures: Value,
    policy: Value,
}

fn vector_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors/signer-trust/drift.json")
        .canonicalize()
        .expect("signer trust vector should exist")
}

#[test]
fn signer_trust_vectors_match_expected_outcomes() {
    let raw = fs::read(vector_path()).expect("signer trust vector should be readable");
    let vector: SignerTrustVector =
        serde_json::from_slice(&raw).expect("signer trust vector should parse");
    assert!(!vector.cases.is_empty(), "expected signer trust cases");

    for case in vector.cases {
        let manifest_raw =
            serde_json::to_vec(&case.manifest).expect("manifest case should serialize");
        let signatures_raw =
            serde_json::to_vec(&case.signatures).expect("signatures case should serialize");
        let policy_raw = serde_json::to_vec(&case.policy).expect("policy case should serialize");
        let manifest = parse_manifest_json(&manifest_raw)
            .unwrap_or_else(|err| panic!("manifest should parse for {}: {err}", case.name));
        let signatures = parse_signatures_json(&signatures_raw)
            .unwrap_or_else(|err| panic!("signatures should parse for {}: {err}", case.name));
        let policy = parse_policy_document(&policy_raw)
            .unwrap_or_else(|err| panic!("policy should parse for {}: {err}", case.name));

        let outcome = verify_trusted_signers(&manifest, &signatures, &policy);
        match case.expect.as_str() {
            "ok" => assert!(outcome.is_ok(), "{}: {outcome:?}", case.name),
            "untrusted_manifest_signers" => assert!(
                matches!(outcome, Err(VerifyError::UntrustedManifestSigners)),
                "{}: {outcome:?}",
                case.name
            ),
            "signature_signer_not_declared" => assert!(
                matches!(outcome, Err(VerifyError::SignatureSignerNotDeclared(_))),
                "{}: {outcome:?}",
                case.name
            ),
            "untrusted_signature_set" => assert!(
                matches!(outcome, Err(VerifyError::UntrustedSignatureSet)),
                "{}: {outcome:?}",
                case.name
            ),
            other => panic!("unsupported expected outcome for {}: {other}", case.name),
        }
    }
}
