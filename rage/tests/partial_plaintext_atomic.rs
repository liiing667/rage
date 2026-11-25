use age::secrecy::ExposeSecret;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "rage-partial-plaintext-test-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn rage(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rage"))
        .current_dir(dir)
        .args(args)
        .output()
        .expect("failed to run rage binary")
}

#[test]
fn failed_authentication_keeps_old_output_and_writes_receipt() {
    let dir_guard = TestDir::new();
    let dir = dir_guard.path();

    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();

    // Several STREAM chunks, rather than a tiny input that cannot expose a prefix commit.
    let plaintext: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let ciphertext = age::encrypt(&recipient, &plaintext).unwrap();

    let mut tampered = ciphertext.clone();
    *tampered.last_mut().unwrap() ^= 1;

    fs::write(
        dir.join("key.txt"),
        format!("{}\n", identity.to_string().expose_secret()),
    )
    .unwrap();
    fs::write(dir.join("tampered.age"), &tampered).unwrap();
    fs::write(dir.join("valid.age"), &ciphertext).unwrap();

    let old = b"old generation that must survive";
    fs::write(dir.join("out.bin"), old).unwrap();

    let failed = rage(
        dir,
        &[
            "--decrypt",
            "--identity",
            "key.txt",
            "--output",
            "out.bin",
            "tampered.age",
        ],
    );
    assert!(
        !failed.status.success(),
        "tampered ciphertext unexpectedly succeeded\nstdout={:?}\nstderr={}",
        failed.stdout,
        String::from_utf8_lossy(&failed.stderr),
    );
    assert_eq!(
        fs::read(dir.join("out.bin")).unwrap(),
        old,
        "failed authentication modified the committed output file"
    );

    let receipt = fs::read_to_string(dir.join("security-receipt.json"))
        .expect("decryption failure did not leave a security receipt");
    assert!(receipt.contains("partial"));
    assert!(receipt.contains("plaintext"));
    assert!(receipt.contains("\"published\": false"));
    assert!(receipt.contains("\"old_file_preserved\": true"));

    let spool_left = fs::read_dir(dir)
        .unwrap()
        .flatten()
        .any(|entry| entry.file_name().to_string_lossy().contains("spool"));
    assert!(!spool_left, "temporary spool file was not cleaned up");

    // Stdout is likewise withheld until complete authentication.
    let stdout_failed = Command::new(env!("CARGO_BIN_EXE_rage"))
        .current_dir(dir)
        .args(["--decrypt", "--identity", "key.txt", "tampered.age"])
        .output()
        .unwrap();
    assert!(!stdout_failed.status.success());
    assert!(
        stdout_failed.stdout.is_empty(),
        "unauthenticated plaintext prefix was released to stdout: {} bytes",
        stdout_failed.stdout.len()
    );

    // A legal large multi-chunk file is published after complete authentication.
    let valid = rage(
        dir,
        &[
            "--decrypt",
            "--identity",
            "key.txt",
            "--output",
            "out.bin",
            "valid.age",
        ],
    );
    assert!(
        valid.status.success(),
        "valid large decrypt failed: {}",
        String::from_utf8_lossy(&valid.stderr)
    );
    assert_eq!(fs::read(dir.join("out.bin")).unwrap(), plaintext);

    let stdout_valid = Command::new(env!("CARGO_BIN_EXE_rage"))
        .current_dir(dir)
        .args(["--decrypt", "--identity", "key.txt", "valid.age"])
        .output()
        .unwrap();
    assert!(stdout_valid.status.success());
    assert_eq!(stdout_valid.stdout, plaintext);

    // Existing-file overwrite remains the successful semantic.
    let replacement = b"replacement generation";
    let replacement_ct = age::encrypt(&recipient, replacement).unwrap();
    fs::write(dir.join("replacement.age"), replacement_ct).unwrap();
    let overwrite = rage(
        dir,
        &[
            "--decrypt",
            "--identity",
            "key.txt",
            "--output",
            "out.bin",
            "replacement.age",
        ],
    );
    assert!(
        overwrite.status.success(),
        "overwrite decrypt failed: {}",
        String::from_utf8_lossy(&overwrite.stderr)
    );
    assert_eq!(fs::read(dir.join("out.bin")).unwrap(), replacement);
}
