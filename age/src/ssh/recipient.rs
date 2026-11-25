use std::collections::HashSet;
use std::fmt;

use age_core::{
    format::{FileKey, Stanza},
    primitives::{aead_encrypt, hkdf},
    secrecy::ExposeSecret,
};
use base64::{
    Engine,
    prelude::{BASE64_STANDARD, BASE64_STANDARD_NO_PAD},
};
use curve25519_dalek::edwards::EdwardsPoint;
use nom::{
    IResult, Parser,
    branch::alt,
    bytes::streaming::{is_not, tag},
    combinator::map_opt,
    sequence::{pair, preceded, separated_pair},
};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use rsa::{Oaep, traits::PublicKeyParts};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

use super::{
    EncryptedKey, SSH_ED25519_KEY_PREFIX, SSH_ED25519_RECIPIENT_KEY_LABEL,
    SSH_ED25519_RECIPIENT_TAG, SSH_RSA_KEY_PREFIX, SSH_RSA_OAEP_LABEL, SSH_RSA_RECIPIENT_TAG,
    UnsupportedKey,
    identity::{Identity, UnencryptedKey},
    read_ssh, ssh_tag,
};
use crate::{
    error::EncryptError,
    util::read::{encoded_str, str_while_encoded},
};

/// A key that can be used to encrypt a file to a recipient.
#[derive(Clone, Debug)]
pub enum Recipient {
    /// An ssh-rsa public key.
    SshRsa(Vec<u8>, rsa::RsaPublicKey),
    /// An ssh-ed25519 public key.
    SshEd25519(Vec<u8>, EdwardsPoint),
}

pub(crate) enum ParsedRecipient {
    Supported(Recipient),
    RsaModulusTooLarge,
    RsaModulusTooSmall,
    Unsupported(String),
}

/// Error conditions when parsing an SSH recipient.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseRecipientKeyError {
    /// The string is a parseable value that should be ignored. This case is for handling
    /// SSH recipient types that may occur in files we want to be able to parse, but that
    /// we do not directly support.
    Ignore,
    /// The string is not a valid SSH recipient.
    Invalid(&'static str),
    /// The string is an `ssh-rsa` public key with a modulus larger than we support.
    RsaModulusTooLarge,
    /// The string is a weak `ssh-rsa` public key with a modulus smaller than 2048 bits.
    RsaModulusTooSmall,
    /// The string is a parseable value that corresponds to an unsupported SSH key type.
    Unsupported(String),
}

impl std::str::FromStr for Recipient {
    type Err = ParseRecipientKeyError;

    /// Parses an SSH recipient from a string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match ssh_recipient(rsa::RsaPublicKey::MAX_SIZE)(s) {
            Ok((_, ParsedRecipient::Supported(pk))) => Ok(pk),
            Ok((_, ParsedRecipient::RsaModulusTooLarge)) => {
                Err(ParseRecipientKeyError::RsaModulusTooLarge)
            }
            Ok((_, ParsedRecipient::RsaModulusTooSmall)) => {
                Err(ParseRecipientKeyError::RsaModulusTooSmall)
            }
            Ok((_, ParsedRecipient::Unsupported(key_type))) => {
                Err(ParseRecipientKeyError::Unsupported(key_type))
            }
            _ => Err(ParseRecipientKeyError::Invalid("invalid SSH recipient")),
        }
    }
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Recipient::SshRsa(ssh_key, _) => {
                write!(
                    f,
                    "{} {}",
                    SSH_RSA_KEY_PREFIX,
                    BASE64_STANDARD.encode(ssh_key)
                )
            }
            Recipient::SshEd25519(ssh_key, _) => {
                write!(
                    f,
                    "{} {}",
                    SSH_ED25519_KEY_PREFIX,
                    BASE64_STANDARD.encode(ssh_key)
                )
            }
        }
    }
}

impl Recipient {
    /// Returns the SSH key-type prefix for this recipient.
    #[must_use]
    pub fn key_algorithm(&self) -> &'static str {
        match self {
            Recipient::SshRsa(..) => SSH_RSA_KEY_PREFIX,
            Recipient::SshEd25519(..) => SSH_ED25519_KEY_PREFIX,
        }
    }

    /// Returns the canonical SSH wire encoding of the public key.
    ///
    /// This is the only value used to derive the age recipient tag and SSH
    /// fingerprint. Comments, terminal control sequences, and other trailing
    /// text in a public-key line are not part of this byte string.
    #[must_use]
    pub fn canonical_key_blob(&self) -> &[u8] {
        match self {
            Recipient::SshRsa(ssh_key, _) | Recipient::SshEd25519(ssh_key, _) => ssh_key,
        }
    }

    /// Returns the raw SHA-256 digest of [`Self::canonical_key_blob`].
    #[must_use]
    pub fn sha256_fingerprint(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_key_blob()).into()
    }

    /// Returns the conventional base64 SSH SHA-256 fingerprint, for example
    /// `SHA256:...`.
    #[must_use]
    pub fn sha256_fingerprint_string(&self) -> String {
        format!(
            "SHA256:{}",
            BASE64_STANDARD_NO_PAD.encode(self.sha256_fingerprint())
        )
    }

    /// Returns the conventional `SHA256:` SSH fingerprint.
    ///
    /// This is an alias for [`Self::sha256_fingerprint_string`]. The value is
    /// computed only from [`Self::canonical_key_blob`].
    #[must_use]
    pub fn fingerprint(&self) -> String {
        self.sha256_fingerprint_string()
    }

    pub(crate) fn recipient_tag(&self) -> [u8; 4] {
        ssh_tag(self.canonical_key_blob())
    }

    fn rsa(pk: rsa::RsaPublicKey) -> Self {
        let mut ssh_key = Vec::new();
        cookie_factory::r#gen(super::write_ssh::rsa_pubkey(&pk), &mut ssh_key)
            .expect("serializing to a Vec cannot fail");
        Recipient::SshRsa(ssh_key, pk)
    }

    fn ed25519(pk: EdwardsPoint) -> Self {
        fn ssh_string(bytes: &[u8]) -> Vec<u8> {
            let mut encoded = Vec::with_capacity(4 + bytes.len());
            encoded.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            encoded.extend_from_slice(bytes);
            encoded
        }

        let encoded_point = pk.compress().to_bytes();
        let mut ssh_key = ssh_string(SSH_ED25519_KEY_PREFIX.as_bytes());
        ssh_key.extend_from_slice(&ssh_string(&encoded_point));
        Recipient::SshEd25519(ssh_key, pk)
    }
}

impl PartialEq for Recipient {
    /// Compares recipients by their canonical public-key body.
    ///
    /// Two textual recipient lines with different comments or control
    /// characters are equal when their canonical keys are equal.
    fn eq(&self, other: &Self) -> bool {
        self.canonical_key_blob() == other.canonical_key_blob()
    }
}

impl Eq for Recipient {}

impl TryFrom<Identity> for Recipient {
    type Error = ParseRecipientKeyError;

    fn try_from(identity: Identity) -> Result<Self, Self::Error> {
        match identity {
            Identity::Unencrypted(UnencryptedKey::SshRsa(ssh_key, _))
            | Identity::Unencrypted(UnencryptedKey::SshEd25519(ssh_key, _))
            | Identity::Encrypted(EncryptedKey { ssh_key, .. }) => {
                match read_ssh::rsa_pubkey(rsa::RsaPublicKey::MAX_SIZE)(&ssh_key) {
                    Ok((_, pk)) => {
                        if let Some(pk) = pk {
                            Ok(Recipient::rsa(pk))
                        } else {
                            Err(ParseRecipientKeyError::RsaModulusTooLarge)
                        }
                    }
                    _ => {
                        if let Ok((_, pk)) = read_ssh::ed25519_pubkey(&ssh_key) {
                            Ok(Recipient::ed25519(pk))
                        } else if let Ok((_, key_type)) = read_ssh::string(&ssh_key) {
                            Err(ParseRecipientKeyError::Unsupported(
                                String::from_utf8_lossy(key_type).to_string(),
                            ))
                        } else {
                            Err(ParseRecipientKeyError::Invalid(
                                "Invalid SSH pubkey in SSH privkey",
                            ))
                        }
                    }
                }
            }
            Identity::Unsupported(
                UnsupportedKey::Hardware(key_type) | UnsupportedKey::Type(key_type),
            ) => Err(ParseRecipientKeyError::Unsupported(key_type)),
            Identity::Unsupported(_) => Err(ParseRecipientKeyError::Ignore),
        }
    }
}

impl crate::Recipient for Recipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), EncryptError> {
        let mut rng = UnwrapErr(SysRng);

        let stanzas = match self {
            Recipient::SshRsa(_, pk) => {
                let encrypted_file_key = pk
                    .encrypt(
                        &mut rng,
                        Oaep::<Sha256>::new_with_label(SSH_RSA_OAEP_LABEL),
                        file_key.expose_secret(),
                    )
                    .expect("pubkey is valid and file key is not too long");

                let encoded_tag = BASE64_STANDARD_NO_PAD.encode(self.recipient_tag());

                vec![Stanza {
                    tag: SSH_RSA_RECIPIENT_TAG.to_owned(),
                    args: vec![encoded_tag],
                    body: encrypted_file_key,
                }]
            }
            Recipient::SshEd25519(ssh_key, ed25519_pk) => {
                let pk: X25519PublicKey = ed25519_pk.to_montgomery().to_bytes().into();

                let esk = EphemeralSecret::random_from_rng(&mut rng);
                let epk: X25519PublicKey = (&esk).into();

                let tweak: StaticSecret =
                    hkdf(ssh_key, SSH_ED25519_RECIPIENT_KEY_LABEL, &[]).into();
                let shared_secret =
                    tweak.diffie_hellman(&(*esk.diffie_hellman(&pk).as_bytes()).into());

                let mut salt = [0; 64];
                salt[..32].copy_from_slice(epk.as_bytes());
                salt[32..].copy_from_slice(pk.as_bytes());

                let enc_key = hkdf(
                    &salt,
                    SSH_ED25519_RECIPIENT_KEY_LABEL,
                    shared_secret.as_bytes(),
                );
                let encrypted_file_key = aead_encrypt(&enc_key, file_key.expose_secret());

                let encoded_tag = BASE64_STANDARD_NO_PAD.encode(self.recipient_tag());
                let encoded_epk = BASE64_STANDARD_NO_PAD.encode(epk.as_bytes());

                vec![Stanza {
                    tag: SSH_ED25519_RECIPIENT_TAG.to_owned(),
                    args: vec![encoded_tag, encoded_epk],
                    body: encrypted_file_key,
                }]
            }
        };

        Ok((stanzas, HashSet::new()))
    }
}

fn ssh_rsa_pubkey(max_size: usize) -> impl Fn(&str) -> IResult<&str, ParsedRecipient> {
    move |input: &str| {
        preceded(
            pair(tag(SSH_RSA_KEY_PREFIX), tag(" ")),
            map_opt(
                str_while_encoded(BASE64_STANDARD_NO_PAD),
                |ssh_key| match read_ssh::rsa_pubkey(max_size)(&ssh_key) {
                    Ok((_, Some(pk))) => Some(if pk.n().bits() < 2048 {
                        ParsedRecipient::RsaModulusTooSmall
                    } else {
                        ParsedRecipient::Supported(Recipient::rsa(pk))
                    }),
                    Ok((_, None)) => Some(ParsedRecipient::RsaModulusTooLarge),
                    Err(_) => None,
                },
            ),
        )
        .parse(input)
    }
}

fn ssh_ed25519_pubkey(input: &str) -> IResult<&str, ParsedRecipient> {
    preceded(
        pair(tag(SSH_ED25519_KEY_PREFIX), tag(" ")),
        map_opt(
            encoded_str(51, BASE64_STANDARD_NO_PAD),
            |ssh_key| match read_ssh::ed25519_pubkey(&ssh_key) {
                Ok((_, pk)) => Some(ParsedRecipient::Supported(Recipient::ed25519(pk))),
                Err(_) => None,
            },
        ),
    )
    .parse(input)
}

fn ssh_ignore_pubkey(input: &str) -> IResult<&str, ParsedRecipient> {
    // We rely on the invariant that SSH public keys are always of the form
    // `key_type Base64(string(key_type) || ...)` to detect valid pubkeys.
    map_opt(
        separated_pair(
            is_not(" "),
            tag(" "),
            str_while_encoded(BASE64_STANDARD_NO_PAD),
        ),
        |(key_type, ssh_key)| {
            read_ssh::string_tag(key_type)(&ssh_key)
                .map(|_| ParsedRecipient::Unsupported(key_type.to_string()))
                .ok()
        },
    )
    .parse(input)
}

pub(crate) fn ssh_recipient(max_size: usize) -> impl Fn(&str) -> IResult<&str, ParsedRecipient> {
    move |input| {
        alt((
            ssh_rsa_pubkey(max_size),
            ssh_ed25519_pubkey,
            ssh_ignore_pubkey,
        ))
        .parse(input)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{ParseRecipientKeyError, Recipient};

    pub(crate) const TEST_SSH_RSA_PK: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDE7nIXTGNuaRBN9toI/wNALuQec8mvlt0iJ7o3OaD2UvoKHJ7S8rmIn4FiQDUed/Vac3OhUibei1k+TBmm16u2Rj3klgWZOIDgi8d4vXKI5N3YBhxr3jsQ+kz1c+iZ4z/tTtz306+4K46XViVMWwyyg9j82Jn41mOAy9vdeDIfQ5fLeaGqn5KwlT61GNkZ+ozWK/ZNlQIlNCcoXxhJULIs9XrtczWyVBAea1nlDo0WHODePxoJjmsNHrpQXn5mf9O83xs10qfTUjnRUt48jRmedFy4tcra3QGmSTQ3KZne+wXXSb0cIpXLGvZjQSPHgG1hc4r3uBpiSzvesGLv79XL alice@rust";
    pub(crate) const TEST_SSH_ED25519_PK: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN alice@rust";
    const TEST_SSH_UNSUPPORTED_PK: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHFliOyIZs1gxGF3fmDxFykQhE88wy6AKDGFBfn0R6ZuvRmENABZQa9+pj9hMki+LX0qDJbmHTiWDbYv/cmFt/Q=";
    const TEST_SSH_INVALID_PK: &str = "ecdsa-sha2-nistp256 AAAAC3NzaC1lZDI1NTE5AAAAIHsKLqeplhpW+uObz5dvMgjz1OxfM/XXUB+VHtZ6isGN alice@rust";

    #[test]
    fn ssh_rsa_encoding() {
        let pk: Recipient = TEST_SSH_RSA_PK.parse().unwrap();
        assert_eq!(pk.to_string() + " alice@rust", TEST_SSH_RSA_PK);
    }

    #[test]
    fn ssh_ed25519_encoding() {
        let pk: Recipient = TEST_SSH_ED25519_PK.parse().unwrap();
        assert_eq!(pk.to_string() + " alice@rust", TEST_SSH_ED25519_PK);
    }

    #[test]
    fn ssh_unsupported_key_type() {
        let pk: Result<Recipient, ParseRecipientKeyError> = TEST_SSH_UNSUPPORTED_PK.parse();
        assert_eq!(
            pk.unwrap_err(),
            ParseRecipientKeyError::Unsupported("ecdsa-sha2-nistp256".to_string()),
        );
    }

    #[test]
    fn ssh_invalid_encoding() {
        let pk: Result<Recipient, ParseRecipientKeyError> = TEST_SSH_INVALID_PK.parse();
        assert_eq!(
            pk.unwrap_err(),
            ParseRecipientKeyError::Invalid("invalid SSH recipient")
        );
    }

    #[test]
    fn comments_and_control_characters_do_not_change_identity() {
        for public_key in [TEST_SSH_RSA_PK, TEST_SSH_ED25519_PK] {
            let trusted: Recipient = public_key.parse().unwrap();
            let canonical_line = trusted.to_string();

            let variants = [
                format!("{canonical_line} attacker@example"),
                format!("{canonical_line}\toperator-comment"),
                format!("{canonical_line} comment with \u{0000} NUL"),
                format!("{canonical_line} \u{001b}[2J forged terminal output"),
                format!("{canonical_line}\u{0007}\r\n"),
            ];

            for variant in variants {
                let parsed: Recipient = variant.parse().unwrap();
                assert_eq!(parsed, trusted);
                assert_eq!(
                    parsed.canonical_key_blob(),
                    trusted.canonical_key_blob(),
                    "comment/control bytes changed canonical key body"
                );
                assert_eq!(
                    parsed.sha256_fingerprint(),
                    trusted.sha256_fingerprint(),
                    "comment/control bytes changed fingerprint"
                );
                assert_eq!(parsed.recipient_tag(), trusted.recipient_tag());
                assert!(parsed.sha256_fingerprint_string().starts_with("SHA256:"));
                assert_eq!(parsed.to_string(), canonical_line);
            }
        }
    }
}
