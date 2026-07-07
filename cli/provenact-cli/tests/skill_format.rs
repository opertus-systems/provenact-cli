use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use provenact_verifier::{
    compute_manifest_hash, parse_manifest_json, parse_provenance_json, parse_signatures_json,
    verify_artifact_hash,
};

fn vectors_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors")
        .canonicalize()
        .expect("test vectors should exist")
}

fn load_sorted_files(path: &Path) -> Vec<PathBuf> {
    let mut files = fs::read_dir(path)
        .expect("vector dir should be readable")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    files.sort();
    files
}

#[test]
fn skill_format_schema_vectors_parse_and_reject_as_expected() {
    let root = vectors_root().join("skill-format");

    for path in load_sorted_files(&root.join("manifest/good")) {
        let raw = fs::read(&path).expect("manifest vector should be readable");
        parse_manifest_json(&raw)
            .unwrap_or_else(|err| panic!("expected valid manifest {}: {err}", path.display()));
    }
    for path in load_sorted_files(&root.join("manifest/bad")) {
        let raw = fs::read(&path).expect("manifest vector should be readable");
        assert!(
            parse_manifest_json(&raw).is_err(),
            "expected invalid manifest to fail: {}",
            path.display()
        );
    }

    for path in load_sorted_files(&root.join("provenance/good")) {
        let raw = fs::read(&path).expect("provenance vector should be readable");
        parse_provenance_json(&raw)
            .unwrap_or_else(|err| panic!("expected valid provenance {}: {err}", path.display()));
    }
    for path in load_sorted_files(&root.join("provenance/bad")) {
        let raw = fs::read(&path).expect("provenance vector should be readable");
        assert!(
            parse_provenance_json(&raw).is_err(),
            "expected invalid provenance to fail: {}",
            path.display()
        );
    }

    for path in load_sorted_files(&root.join("signatures/good")) {
        let raw = fs::read(&path).expect("signatures vector should be readable");
        parse_signatures_json(&raw)
            .unwrap_or_else(|err| panic!("expected valid signatures {}: {err}", path.display()));
    }
    for path in load_sorted_files(&root.join("signatures/bad")) {
        let raw = fs::read(&path).expect("signatures vector should be readable");
        assert!(
            parse_signatures_json(&raw).is_err(),
            "expected invalid signatures to fail: {}",
            path.display()
        );
    }
}

#[test]
fn skill_format_good_bundle_links_artifact_manifest_and_signature_hashes() {
    let bundle = vectors_root().join("good/minimal-zero-cap");
    let wasm = fs::read(bundle.join("skill.wasm")).expect("skill.wasm should be readable");
    let manifest_raw =
        fs::read(bundle.join("manifest.json")).expect("manifest should be readable");
    let signatures_raw =
        fs::read(bundle.join("signatures.json")).expect("signatures should be readable");
    let keys = bundle.join("public-keys.json");

    let manifest = parse_manifest_json(&manifest_raw).expect("manifest should parse");
    let signatures = parse_signatures_json(&signatures_raw).expect("signatures should parse");
    verify_artifact_hash(&wasm, &manifest.artifact).expect("artifact hash should match");
    assert_eq!(manifest.artifact, signatures.artifact);
    assert_eq!(
        compute_manifest_hash(&manifest).expect("manifest hash should compute"),
        signatures.manifest_hash
    );

    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .args(["verify", "--bundle"])
        .arg(&bundle)
        .args(["--keys"])
        .arg(&keys)
        .args(["--keys-digest"])
        .arg(provenact_verifier::sha256_prefixed(
            &fs::read(&keys).expect("keys should be readable"),
        ))
        .output()
        .expect("verify should run");
    assert!(output.status.success(), "{output:?}");
}
