use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "rage-secret-redaction-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn rage_bin() -> &'static str {
    env!("CARGO_BIN_EXE_rage")
}

fn read_receipt(dir: &PathBuf) -> String {
    fs::read_to_string(dir.join("security-receipt.json"))
        .expect("a reviewable security receipt must be written")
}

#[test]
fn invalid_identity_file_diagnostic_is_redacted_and_receipted() {
    let dir = unique_dir("identity-file");
    let identity = dir.join("identity.txt");
    let secret = "AGE-SECRET-KEY-TESTFIXTUREDONOTDISPLAY";
    fs::write(&identity, format!("{secret}\n")).unwrap();

    let output = Command::new(rage_bin())
        .current_dir(&dir)
        .args(["--decrypt", "--identity", identity.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains(secret),
        "identity secret leaked into stderr: {stderr}"
    );
    assert!(stderr.contains("non-identity data on line 1"));
    assert!(stderr.contains("str4d.xyz/rage/report"));

    let receipt = read_receipt(&dir);
    assert!(receipt.contains("secret"));
    assert!(receipt.contains("redacted"));
    assert!(receipt.contains("rage.decrypt.identity_read"));
    assert!(!receipt.contains(secret));
}

#[test]
fn identity_passed_as_filename_is_redacted_but_category_remains() {
    let dir = unique_dir("identity-argument");
    let secret = "AGE-SECRET-KEY-ARGUMENTMARKER123456";

    let output = Command::new(rage_bin())
        .current_dir(&dir)
        .args(["--decrypt", "--identity", secret])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains(secret), "secret argument leaked: {stderr}");
    assert!(stderr.contains("[REDACTED_IDENTITY]"));
    assert!(stderr.contains("Identity file not found"));
    assert!(stderr.contains("str4d.xyz/rage/report"));

    let receipt = read_receipt(&dir);
    assert!(receipt.contains("identity_argument"));
    assert!(!receipt.contains(secret));
}

#[test]
fn passphrase_value_to_boolean_flag_is_redacted_in_clap_diagnostic() {
    let dir = unique_dir("passphrase-argument");
    let passphrase = "distinct-passphrase-marker-789";
    let arg = format!("--passphrase={passphrase}");

    let output = Command::new(rage_bin())
        .current_dir(&dir)
        .args(["--encrypt", arg.as_str()])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains(passphrase),
        "passphrase leaked into clap diagnostic: {stderr}"
    );
    assert!(stderr.contains("[REDACTED_PASSPHRASE]"));
    assert!(stderr.contains("--passphrase"));
    assert!(stderr.contains("Usage"));

    let receipt = read_receipt(&dir);
    assert!(receipt.contains("passphrase"));
    assert!(receipt.contains("redacted"));
    assert!(!receipt.contains(passphrase));
}
