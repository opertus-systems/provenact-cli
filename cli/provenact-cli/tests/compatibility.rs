use std::process::Command;

#[test]
fn stable_and_experimental_command_surface_is_explicit() {
    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .output()
        .expect("cli should run");
    assert!(!output.status.success(), "{output:?}");

    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    for command in [
        "pack",
        "sign",
        "verify",
        "inspect",
        "run",
        "verify-receipt",
        "verify-registry-entry",
    ] {
        assert!(
            stderr.contains(&format!("provenact-cli {command}")),
            "usage missing stable command {command}: {stderr}"
        );
    }

    assert!(
        stderr.contains("experimental-validate-manifest-v1"),
        "usage should label manifest v1 validation as experimental: {stderr}"
    );
    assert!(
        stderr.contains("experimental-validate-receipt-v1"),
        "usage should label receipt v1 validation as experimental: {stderr}"
    );
}

#[test]
fn unknown_command_fails_closed() {
    let output = Command::new(env!("CARGO_BIN_EXE_provenact-cli"))
        .arg("workflow")
        .output()
        .expect("cli should run");
    assert!(!output.status.success(), "{output:?}");

    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(
        stderr.contains("usage:"),
        "unknown command should return usage: {stderr}"
    );
}
