//! The isolation checker must fail loudly on a setup that is not isolated.
//!
//! It is the only artefact that verifies the separate-user deployment, which
//! could not be exercised end to end on the development machine. A checker that
//! passes a broken setup would be worse than none: it would certify exactly the
//! configuration where `cat` still reads the real values.

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

fn script() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/check_anonym_isolation.sh")
}

#[test]
fn missing_arguments_are_a_usage_error() {
    let output = Command::new("bash")
        .arg(script())
        .output()
        .expect("run checker");
    assert_eq!(output.status.code(), Some(64));
}

#[test]
fn a_world_readable_file_is_reported_as_not_isolated() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("kayit.csv");
    std::fs::write(&target, "tckn 10000000146").unwrap();

    let output = Command::new("bash")
        .arg(script())
        .arg("nobody")
        .arg(&target)
        .output()
        .expect("run checker");

    assert!(
        !output.status.success(),
        "a file the agent can read must not pass isolation"
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("can read") && text.contains("bypassed with cat"),
        "the reason must name the actual weakness: {text}"
    );
    assert!(
        !text.contains("10000000146"),
        "the checker must not print the data it is protecting: {text}"
    );
}

/// A check that could not run must not read as a pass.
///
/// `sudo -n` fails outright when a password is required, which is the normal
/// state on a personal machine. Reporting that as "the server cannot read it,
/// your setup is broken" told a correctly configured operator the opposite of
/// the truth, so the two cases are now distinguished and an unrunnable check
/// exits 2 rather than 0.
#[test]
fn an_unverifiable_check_is_neither_a_pass_nor_a_failure() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("kayit.csv");
    std::fs::write(&target, "tckn 10000000146").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o000)).unwrap();

    let output = Command::new("bash")
        .arg(script())
        .arg("nobody")
        .arg(&target)
        .output()
        .expect("run checker");
    let text = String::from_utf8_lossy(&output.stdout);

    // Only meaningful where sudo actually needs a password; where it does not,
    // the checker reaches a real verdict and this case does not arise.
    if text.contains("skip ") {
        assert_eq!(
            output.status.code(),
            Some(2),
            "an unrunnable check must not exit 0: {text}"
        );
        assert!(
            text.contains("unproven"),
            "the summary must say the boundary is unproven: {text}"
        );
        assert!(
            !text.contains("Isolation holds"),
            "silence is not confirmation: {text}"
        );
    }

    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
}

#[test]
fn a_file_nobody_can_read_is_reported_as_broken_not_secure() {
    // The trap the development machine fell into: chmod 000 under one account
    // locks out the server too, which looks secure and simply does not work.
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("kayit.csv");
    std::fs::write(&target, "tckn 10000000146").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o000)).unwrap();

    let output = Command::new("bash")
        .arg(script())
        .arg("nobody")
        .arg(&target)
        .output()
        .expect("run checker");
    let text = String::from_utf8_lossy(&output.stdout);

    if text.contains("cannot read the file directly") {
        // Either it proved the server is locked out too, or it could not ask.
        // Both must refuse to certify the setup.
        assert!(
            text.contains("broken, not secure") || text.contains("skip "),
            "locking everyone out must never be reported as isolation: {text}"
        );
        assert!(!output.status.success());
        assert!(!text.contains("Isolation holds"), "{text}");
    }

    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
}
