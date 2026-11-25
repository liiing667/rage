use std::collections::HashSet;
use std::io::{Read, Write};
use std::iter;

use age::{
    DecryptError, EncryptError, Encryptor, Identity as AgeIdentity, Recipient as AgeRecipient,
    x25519,
};
use age_core::format::{FileKey, Stanza};
use age_core::secrecy::ExposeSecret;

struct DuplicateRecipient(x25519::Recipient);

impl AgeRecipient for DuplicateRecipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), EncryptError> {
        let (mut stanzas, labels) = self.0.wrap_file_key(file_key)?;
        let duplicate = Stanza {
            tag: stanzas[0].tag.clone(),
            args: stanzas[0].args.clone(),
            body: stanzas[0].body.clone(),
        };
        stanzas.push(duplicate);
        Ok((stanzas, labels))
    }
}

struct ConflictingRecipient {
    identity: x25519::Recipient,
    other: x25519::Recipient,
}

impl AgeRecipient for ConflictingRecipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), EncryptError> {
        let (mut stanzas, labels) = self.identity.wrap_file_key(file_key)?;

        let conflicting_file_key =
            FileKey::new(Box::new(file_key.expose_secret().map(|byte| byte ^ 0xff)));
        let (mut conflicting, _) = self.identity.wrap_file_key(&conflicting_file_key)?;
        stanzas.append(&mut conflicting);

        let (mut other, _) = self.other.wrap_file_key(file_key)?;
        stanzas.append(&mut other);

        Ok((stanzas, labels))
    }
}

fn encrypt(recipient: &impl AgeRecipient, plaintext: &[u8]) -> Vec<u8> {
    let encryptor = Encryptor::with_recipients(iter::once(recipient as _)).unwrap();
    let mut ciphertext = vec![];
    let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();
    ciphertext
}

fn decrypt(identity: &x25519::Identity, ciphertext: &[u8]) -> Result<Vec<u8>, DecryptError> {
    let decryptor = age::Decryptor::new(ciphertext)?;
    let mut plaintext = vec![];
    decryptor
        .decrypt(iter::once(identity as &dyn AgeIdentity))?
        .read_to_end(&mut plaintext)?;
    Ok(plaintext)
}

#[test]
fn legal_multiple_recipients_and_noise_stanzas_remain_supported() {
    let identity = x25519::Identity::generate();
    let other_identity = x25519::Identity::generate();
    let recipients = [identity.to_public(), other_identity.to_public()];
    let plaintext = b"valid multi-recipient header";

    let encryptor =
        Encryptor::with_recipients(recipients.iter().map(|recipient| recipient as _)).unwrap();
    let mut ciphertext = vec![];
    let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();

    // The normal encryption path also adds an unknown (noise) stanza to the header.
    assert_eq!(decrypt(&identity, &ciphertext).unwrap(), plaintext);
    assert_eq!(decrypt(&other_identity, &ciphertext).unwrap(), plaintext);
}

#[test]
fn duplicate_stanzas_for_one_identity_are_rejected() {
    let identity = x25519::Identity::generate();
    let recipient = DuplicateRecipient(identity.to_public());
    let ciphertext = encrypt(&recipient, b"duplicate recipient stanza");

    assert!(matches!(
        decrypt(&identity, &ciphertext),
        Err(DecryptError::InvalidHeader)
    ));
}

#[test]
fn conflicting_stanzas_for_one_identity_are_rejected() {
    let identity = x25519::Identity::generate();
    let other_identity = x25519::Identity::generate();
    let recipient = ConflictingRecipient {
        identity: identity.to_public(),
        other: other_identity.to_public(),
    };
    let ciphertext = encrypt(&recipient, b"conflicting recipient stanza");

    assert!(matches!(
        decrypt(&identity, &ciphertext),
        Err(DecryptError::InvalidHeader)
    ));
    assert_eq!(
        decrypt(&other_identity, &ciphertext).unwrap(),
        b"conflicting recipient stanza"
    );
}
