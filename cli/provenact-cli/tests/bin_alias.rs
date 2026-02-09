use std::process::Command;

#[test]
fn provenact_alias_binary_is_executable() {
    let output = Command::new(env!("CARGO_BIN_EXE_provenact"))
        .output()
        .expect("alias binary should run");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("usage:"), "{stderr}");
}
