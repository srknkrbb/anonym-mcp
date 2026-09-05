//! The installer must survive replacing a binary that is currently running.
//!
//! An MCP server is normally running, launched by the agent, so an upgrade
//! lands on a live process. Writing over it corrupts the image being executed
//! and the next run dies with SIGKILL ("Killed: 9"), which is how this was
//! found. Unlinking first leaves the running process with its own intact inode.
//!
//! Measured, because the first explanation of this was wrong. Overwriting an
//! *idle* binary is harmless. Overwriting a *running* one gives exit 137. Two
//! independent things prevent it: unlinking first, and re-signing afterwards.
//! The first version of this test did both, so it passed even with the unlink
//! removed and proved nothing. Each is now checked on its own.

#![cfg(target_os = "macos")]

use std::process::{Command, Stdio};

fn source_binary() -> std::path::PathBuf {
    let mut dir = std::env::current_exe().expect("test binary");
    dir.pop(); // deps/
    dir.pop(); // debug/
    dir.join("anonym-mcp")
}

fn sign(path: &std::path::Path) {
    let _ = Command::new("codesign")
        .args(["--force", "--sign", "-"])
        .arg(path)
        .output();
}

fn runs(path: &std::path::Path) -> bool {
    Command::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

#[test]
fn replacing_a_running_binary_by_unlinking_first_keeps_it_runnable() {
    let source = source_binary();
    if !source.exists() {
        eprintln!("anonym-mcp not built; skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let installed = dir.path().join("anonym-mcp");

    std::fs::copy(&source, &installed).unwrap();
    sign(&installed);
    assert!(runs(&installed), "the freshly installed binary must run");

    // Hold it open the way an MCP client does: stdin stays attached, so the
    // process is alive while the upgrade happens.
    let mut child = Command::new(&installed)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn server");

    // Unlink-then-copy, with no re-signing, so this measures the unlink alone.
    std::fs::remove_file(&installed).unwrap();
    std::fs::copy(&source, &installed).unwrap();

    assert!(
        runs(&installed),
        "unlinking before copying must keep the binary runnable on its own"
    );

    drop(child.stdin.take());
    let _ = child.wait();
}

/// The failure the installer exists to prevent, asserted directly. If this ever
/// stops reproducing, the rm-then-copy dance is cargo cult and should go.
#[test]
fn overwriting_a_running_binary_in_place_breaks_it() {
    let source = source_binary();
    if !source.exists() {
        eprintln!("anonym-mcp not built; skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let installed = dir.path().join("anonym-mcp");
    std::fs::copy(&source, &installed).unwrap();
    sign(&installed);
    assert!(runs(&installed));

    let mut child = Command::new(&installed)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn server");

    // No unlink, no re-sign: the naive `cp over it` an installer would do.
    std::fs::copy(&source, &installed).unwrap();
    let survived = runs(&installed);

    drop(child.stdin.take());
    let _ = child.wait();

    assert!(
        !survived,
        "overwriting a running binary no longer breaks it; the installer's \
         rm-then-copy is then unnecessary and this test should be deleted"
    );
}

/// Re-signing repairs an in-place overwrite, which is the second, independent
/// protection the installer applies.
#[test]
fn re_signing_repairs_an_in_place_overwrite() {
    let source = source_binary();
    if !source.exists() {
        eprintln!("anonym-mcp not built; skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let installed = dir.path().join("anonym-mcp");
    std::fs::copy(&source, &installed).unwrap();
    sign(&installed);
    assert!(runs(&installed));

    let mut child = Command::new(&installed)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn server");

    std::fs::copy(&source, &installed).unwrap();
    sign(&installed);

    assert!(
        runs(&installed),
        "re-signing after an overwrite must make the binary runnable again"
    );

    drop(child.stdin.take());
    let _ = child.wait();
}
