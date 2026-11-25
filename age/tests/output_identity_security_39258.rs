#![cfg(all(feature = "cli-common", unix))]

use age::cli_common::file_io::{OutputFormat, OutputWriter};
use std::{
    fs,
    io::{ErrorKind, Write},
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir() -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "rage-output-identity-gsb39258-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn writer(path: &std::path::Path, allow_overwrite: bool) -> OutputWriter {
    OutputWriter::new(
        Some(path.display().to_string()),
        allow_overwrite,
        OutputFormat::Binary,
        0o600,
        false,
    )
    .unwrap()
}

#[test]
fn ordinary_new_file_is_created_with_requested_mode() {
    let dir = temp_dir();
    let path = dir.join("ordinary.txt");

    let mut output = writer(&path, false);
    assert!(!path.exists());
    output.write_all(b"plaintext").unwrap();

    assert_eq!(fs::read(&path).unwrap(), b"plaintext");
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn explicit_force_overwrites_checked_regular_file() {
    let dir = temp_dir();
    let path = dir.join("forced.txt");
    fs::write(&path, b"old content with a longer tail").unwrap();

    let mut output = writer(&path, true);
    output.write_all(b"new").unwrap();
    drop(output);

    assert_eq!(fs::read(&path).unwrap(), b"new");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn explicit_stdout_remains_available() {
    let output = OutputWriter::new(
        Some("-".to_string()),
        true,
        OutputFormat::Binary,
        0o600,
        false,
    )
    .unwrap();
    assert!(matches!(output, OutputWriter::Stdout(_)));
}

#[test]
fn force_creation_blocks_symlink_inserted_after_construction() {
    let dir = temp_dir();
    let output_path = dir.join("output");
    let protected_target = dir.join("protected");
    fs::write(&protected_target, b"keep").unwrap();

    let mut output = writer(&output_path, true);
    symlink(&protected_target, &output_path).unwrap();

    let error = output.write_all(b"secret").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&protected_target).unwrap(), b"keep");

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn force_write_rejects_preexisting_symlink() {
    let dir = temp_dir();
    let output_path = dir.join("output-link");
    let protected_target = dir.join("protected");
    fs::write(&protected_target, b"keep").unwrap();
    symlink(&protected_target, &output_path).unwrap();

    let mut output = writer(&output_path, true);
    let error = output.write_all(b"secret").unwrap_err();

    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
    assert_eq!(fs::read(&protected_target).unwrap(), b"keep");

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn forbid_overwrite_dangling_symlink_fails_closed() {
    let dir = temp_dir();
    let output_path = dir.join("dangling-link");
    symlink(dir.join("missing-target"), &output_path).unwrap();

    let mut output = writer(&output_path, false);
    let error = output.write_all(b"secret").unwrap_err();

    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn force_open_rejects_regular_identity_swap_before_truncation() {
    let dir = temp_dir();
    let output_path = dir.join("output");
    let protected_target = dir.join("protected");
    fs::write(&output_path, b"checked old output").unwrap();
    fs::write(&protected_target, b"keep").unwrap();

    let mut output = writer(&output_path, true);
    fs::remove_file(&output_path).unwrap();
    symlink(&protected_target, &output_path).unwrap();

    output.write_all(b"secret").unwrap_err();
    assert_eq!(fs::read(&protected_target).unwrap(), b"keep");

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn swapped_dangling_symlink_does_not_create_external_target() {
    let dir = temp_dir();
    let output_path = dir.join("output");
    let protected_target = dir.join("would-be-created");
    fs::write(&output_path, b"checked old output").unwrap();

    let mut output = writer(&output_path, true);
    fs::remove_file(&output_path).unwrap();
    symlink(&protected_target, &output_path).unwrap();

    output.write_all(b"secret").unwrap_err();
    assert!(!protected_target.exists());

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn later_path_replacement_fails_before_next_write() {
    let dir = temp_dir();
    let output_path = dir.join("output");
    let protected_target = dir.join("protected");

    let mut output = writer(&output_path, true);
    output.write_all(b"first").unwrap();

    fs::write(&protected_target, b"keep").unwrap();
    fs::remove_file(&output_path).unwrap();
    symlink(&protected_target, &output_path).unwrap();

    output.write_all(b"second").unwrap_err();
    assert_eq!(fs::read(&protected_target).unwrap(), b"keep");

    fs::remove_dir_all(dir).unwrap();
}
