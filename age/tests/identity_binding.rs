use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use age::secrecy::{ExposeSecret, SecretString};
use age::{
    Callbacks, DecryptError, IdentityBindingError, IdentityFile, RecipientBindingStatus,
    encrypted::Identity as EncryptedIdentity, x25519,
};

const PASSPHRASE: &str = "correct horse binding phrase";
const PLAINTEXT: &[u8] = b"subject and generation are bound";

#[derive(Clone)]
struct TestCallbacks(Arc<Mutex<Option<SecretString>>>);

impl TestCallbacks {
    fn once(passphrase: &str) -> Self {
        Self(Arc::new(Mutex::new(Some(SecretString::from(
            passphrase.to_owned(),
        )))))
    }
}

impl Callbacks for TestCallbacks {
    fn display_message(&self, _message: &str) {}

    fn confirm(&self, _message: &str, _yes_string: &str, _no_string: Option<&str>) -> Option<bool> {
        None
    }

    fn request_public_string(&self, _description: &str) -> Option<String> {
        None
    }

    fn request_passphrase(&self, _description: &str) -> Option<SecretString> {
        self.0.lock().unwrap().take()
    }
}

fn identity_text(identity: &x25519::Identity, comment: Option<&str>) -> String {
    let secret = identity.to_string().expose_secret().to_owned();
    match comment {
        Some(comment) => format!("{comment}\n{secret}\n"),
        None => format!("{secret}\n"),
    }
}

fn encrypt_with_passphrase(plaintext: &[u8]) -> Vec<u8> {
    let encryptor = age::Encryptor::with_user_passphrase(SecretString::from(PASSPHRASE.to_owned()));
    let mut ciphertext = Vec::new();
    let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();
    ciphertext
}

fn encrypt_to_identity(identity: &x25519::Identity, plaintext: &[u8]) -> Vec<u8> {
    let recipient = identity.to_public();
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .unwrap();
    let mut ciphertext = Vec::new();
    let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();
    ciphertext
}

fn binding_error_from_io(error: std::io::Error) -> IdentityBindingError {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<IdentityBindingError>())
        .expect("io error should contain IdentityBindingError")
        .clone()
}

#[test]
fn legitimate_comment_binds_generation_and_subject() {
    let identity = x25519::Identity::generate();
    let recipient = identity.to_public().to_string();
    let input = identity_text(
        &identity,
        Some(&format!(
            "# generated: rotation-2026-11-25\n# public key: {recipient}"
        )),
    );

    let file = IdentityFile::from_buffer(input.as_bytes()).unwrap();
    let report = file.binding_report();

    assert!(report.is_complete());
    assert_eq!(report.generation, "rotation-2026-11-25");
    assert_eq!(
        report.claimed_generation.as_deref(),
        Some("rotation-2026-11-25")
    );
    assert_eq!(report.bindings.len(), 1);
    let binding = &report.bindings[0];
    assert_eq!(binding.status, RecipientBindingStatus::Verified);
    assert_eq!(binding.subject_evidence(), recipient);
    assert_eq!(binding.declared_recipients, vec![recipient]);
    assert!(binding.generation.contains("rotation-2026-11-25"));
    assert!(report.to_json().contains("\"complete\":true"));
}

#[test]
fn standard_created_comment_is_generation_evidence() {
    let identity = x25519::Identity::generate();
    let recipient = identity.to_public().to_string();
    let input = identity_text(
        &identity,
        Some(&format!(
            "# created: 2026-11-25T08:00:00+08:00\n# public key: {recipient}"
        )),
    );

    let report = IdentityFile::from_buffer(input.as_bytes())
        .unwrap()
        .binding_report();

    assert_eq!(report.generation, "2026-11-25T08:00:00+08:00");
    assert_eq!(report.bindings[0].status, RecipientBindingStatus::Verified);
}

#[test]
fn comment_free_identity_files_remain_supported_and_are_audited() {
    let identity = x25519::Identity::generate();
    let recipient = identity.to_public().to_string();
    let input = identity_text(&identity, None);

    let file = IdentityFile::from_buffer(input.as_bytes()).unwrap();
    let report = file.binding_report();

    assert!(report.is_complete());
    assert!(report.claimed_generation.is_none());
    assert!(report.generation.starts_with("identity-gen-"));
    assert_eq!(report.bindings.len(), 1);
    assert_eq!(
        report.bindings[0].status,
        RecipientBindingStatus::NoRecipientComment
    );
    assert_eq!(report.bindings[0].subject_evidence(), recipient);
    assert!(report.bindings[0].declared_recipients.is_empty());
}

#[test]
fn recipient_comment_mismatch_is_rejected_with_evidence() {
    let actual = x25519::Identity::generate();
    let declared = x25519::Identity::generate().to_public().to_string();
    let actual_recipient = actual.to_public().to_string();
    let input = identity_text(
        &actual,
        Some(&format!(
            "# generation: mismatch-fixture-gen-7\n# public key: {declared}"
        )),
    );

    let error = match IdentityFile::from_buffer(input.as_bytes()) {
        Err(error) => error,
        Ok(_) => panic!("mismatched recipient comment must be rejected"),
    };
    let binding = binding_error_from_io(error);
    let report = binding.report();

    assert!(!report.is_complete());
    assert_eq!(report.generation, "mismatch-fixture-gen-7");
    assert_eq!(report.bindings[0].status, RecipientBindingStatus::Mismatch);
    assert_eq!(report.bindings[0].declared_recipients, vec![declared]);
    assert_eq!(report.bindings[0].subject_evidence(), actual_recipient);

    let json = report.to_json();
    assert!(json.contains("\"complete\":false"));
    assert!(json.contains("mismatch-fixture-gen-7"));
    assert!(json.contains("subject_evidence"));
}

fn decrypt_encrypted_identity(inner: &str, outer: &[u8]) -> Result<Vec<u8>, DecryptError> {
    let encrypted_inner = encrypt_with_passphrase(inner.as_bytes());
    let identity = EncryptedIdentity::from_buffer(
        &encrypted_inner[..],
        Some("test-encrypted-identity.age".to_owned()),
        TestCallbacks::once(PASSPHRASE),
        None,
    )
    .unwrap()
    .expect("passphrase-encrypted identity should be recognized");

    let decryptor = age::Decryptor::new(outer).unwrap();
    let mut reader = decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity))?;
    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)?;
    Ok(plaintext)
}

#[test]
fn encrypted_identity_with_matching_comment_decrypts() {
    let identity = x25519::Identity::generate();
    let recipient = identity.to_public().to_string();
    let inner = identity_text(
        &identity,
        Some(&format!(
            "# generation: good-gen\n# public key: {recipient}"
        )),
    );
    let outer = encrypt_to_identity(&identity, PLAINTEXT);

    assert_eq!(
        decrypt_encrypted_identity(&inner, &outer).unwrap(),
        PLAINTEXT
    );
}

#[test]
fn encrypted_identity_without_comment_decrypts() {
    let identity = x25519::Identity::generate();
    let inner = identity_text(&identity, None);
    let outer = encrypt_to_identity(&identity, PLAINTEXT);

    assert_eq!(
        decrypt_encrypted_identity(&inner, &outer).unwrap(),
        PLAINTEXT
    );
}

#[test]
fn encrypted_identity_binding_report_is_reusable_for_decryption() {
    let identity = x25519::Identity::generate();
    let recipient = identity.to_public().to_string();
    let inner = identity_text(
        &identity,
        Some(&format!(
            "# generation: report-method-gen\n# public key: {recipient}"
        )),
    );
    let encrypted_inner = encrypt_with_passphrase(inner.as_bytes());
    let encrypted_identity = EncryptedIdentity::from_buffer(
        &encrypted_inner[..],
        Some("report-method.ageidentity".to_owned()),
        TestCallbacks::once(PASSPHRASE),
        None,
    )
    .unwrap()
    .unwrap();

    let report = encrypted_identity.binding_report().unwrap();
    assert_eq!(report.generation, "report-method-gen");
    assert_eq!(report.bindings[0].subject_evidence(), recipient);

    let outer = encrypt_to_identity(&identity, PLAINTEXT);
    let decryptor = age::Decryptor::new(&outer[..]).unwrap();
    let mut reader = decryptor
        .decrypt(std::iter::once(&encrypted_identity as &dyn age::Identity))
        .unwrap();
    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext).unwrap();
    assert_eq!(plaintext, PLAINTEXT);
}

#[test]
fn encrypted_identity_mismatch_is_not_reported_as_success() {
    let actual = x25519::Identity::generate();
    let wrong = x25519::Identity::generate().to_public().to_string();
    let actual_recipient = actual.to_public().to_string();
    let inner = identity_text(
        &actual,
        Some(&format!(
            "# generation: encrypted-mismatch-gen-9\n# public key: {wrong}"
        )),
    );
    let outer = encrypt_to_identity(&actual, PLAINTEXT);

    let error = decrypt_encrypted_identity(&inner, &outer).unwrap_err();
    let DecryptError::IdentityBinding(binding) = error else {
        panic!("expected identity binding error, got {error:?}");
    };
    let report = binding.report();
    assert!(!report.is_complete());
    assert_eq!(report.generation, "encrypted-mismatch-gen-9");
    assert_eq!(report.bindings[0].declared_recipients, vec![wrong]);
    assert_eq!(report.bindings[0].subject_evidence(), actual_recipient);
}
