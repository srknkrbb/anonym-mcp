//! The binary must answer a human immediately.
//!
//! Its normal mode reads JSON-RPC from stdin, so a person who installs it and
//! runs `anonym-mcp --help` to see what it is would otherwise stare at a
//! process that hangs with no output. That happened, hence these tests.

use std::io::Write;
use std::process::{Command, Stdio};

fn binary() -> std::path::PathBuf {
    let mut path = std::env::current_exe().expect("test binary path");
    path.pop(); // deps/
    path.pop(); // debug/
    path.join("anonym-mcp")
}

#[test]
fn help_returns_immediately_instead_of_waiting_on_stdin() {
    let output = Command::new(binary())
        .arg("--help")
        .stdin(Stdio::null())
        .output()
        .expect("run --help");
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("MCP server"), "{text}");
    assert!(text.contains("ANONYM_ROOTS"), "{text}");
    assert!(text.contains("read_anonymized"), "{text}");
}

#[test]
fn version_is_reported() {
    let output = Command::new(binary())
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .expect("run --version");
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).starts_with("anonym-mcp "),
        "unexpected version output"
    );
}

#[test]
fn an_unknown_argument_fails_loudly_rather_than_starting_a_server() {
    let output = Command::new(binary())
        .arg("--nonsense")
        .stdin(Stdio::null())
        .output()
        .expect("run with a bad argument");
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unexpected argument"),
        "the mistake must be named"
    );
}

/// Every argument is inspected, not just the first. `--version --bogus` printed
/// the version and exited 0, swallowing the mistake, because the parsing loop
/// returned on its first iteration.
#[test]
fn a_bad_argument_after_a_good_one_is_still_caught() {
    let output = Command::new(binary())
        .args(["--version", "--bogus"])
        .stdin(Stdio::null())
        .output()
        .expect("run with a trailing bad argument");
    assert_eq!(
        output.status.code(),
        Some(2),
        "the mistake must not be swallowed"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--bogus"),
        "the offending argument must be named"
    );
}

#[test]
fn stdio_mode_still_answers_a_client() {
    let mut child = Command::new(binary())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn server");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n")
        .unwrap();
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("collect output");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("\"protocolVersion\""), "{text}");
    assert!(text.contains("anonym-mcp"), "{text}");
}
