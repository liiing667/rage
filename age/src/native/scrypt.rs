//! The "scrypt" passphrase-based recipient type, native to age.

use std::collections::HashSet;
use std::iter;
use std::time::Duration;

use age_core::{
    format::{FILE_KEY_BYTES, FileKey, Stanza},
    primitives::{aead_decrypt, aead_encrypt},
    secrecy::{ExposeSecret, SecretString},
};
use base64::{Engine, prelude::BASE64_STANDARD_NO_PAD};
use rand::{
    Rng,
    distr::{Alphanumeric, SampleString},
    rand_core::UnwrapErr,
    rngs::SysRng,
};
use zeroize::Zeroize;

use crate::{
    error::{DecryptError, EncryptError},
    primitives::scrypt,
    util::read::{base64_arg, decimal_digit_arg},
};

pub(crate) const SCRYPT_RECIPIENT_TAG: &str = "scrypt";
const SCRYPT_SALT_LABEL: &[u8] = b"age-encryption.org/v1/scrypt";
const ONE_SECOND: Duration = Duration::from_secs(1);

/// The default maximum scrypt work factor that will be accepted when decrypting.
///
/// This matches the limit accepted by the age test vectors and the reference
/// implementation. Bounding the work factor before any scrypt allocation or
/// computation prevents a malicious header from forcing an unbounded amount of CPU
/// and memory usage before the file can be authenticated.
///
/// Applications that need to decrypt files with a higher work factor can opt in
/// explicitly with [`Identity::set_max_work_factor`].
pub const DEFAULT_MAX_WORK_FACTOR: u8 = 22;

const SALT_LEN: usize = 16;
const ENCRYPTED_FILE_KEY_BYTES: usize = FILE_KEY_BYTES + 16;

/// Pick an scrypt work factor that will take around 1 second on this device.
///
/// Guaranteed to return a valid work factor (less than 64), and capped at
/// [`DEFAULT_MAX_WORK_FACTOR`] so that files encrypted with the default work factor
/// can always be decrypted with the default maximum work factor.
fn target_scrypt_work_factor() -> u8 {
    let measure_duration = |log_n| {
        // Platforms that have a functional SystemTime::now():
        #[cfg(not(all(target_arch = "wasm32", not(target_os = "wasi"))))]
        {
            use std::time::SystemTime;
            let start = SystemTime::now();
            scrypt(&[], log_n, "").expect("log_n < 64");
            SystemTime::now().duration_since(start).ok()
        }

        // Platforms that can use Performance timer
        #[cfg(all(target_arch = "wasm32", not(target_os = "wasi"), feature = "web-sys"))]
        {
            web_sys::window().and_then(|window| {
                { window.performance() }.map(|performance| {
                    let start = performance.now();
                    scrypt(&[], log_n, "").expect("log_n < 64");
                    Duration::from_secs_f64((performance.now() - start) / 1_000e0)
                })
            })
        }

        // Platforms where SystemTime::now() panics:
        #[cfg(all(
            target_arch = "wasm32",
            not(target_os = "wasi"),
            not(feature = "web-sys")
        ))]
        {
            None
        }
    };

    // Time a work factor that should always be fast.
    let mut log_n = 10;
    let mut duration: Option<Duration> = measure_duration(log_n);
    while duration.map(|d| d.is_zero()).unwrap_or(false) {
        // On some newer platforms, the work factor may be so fast that it is cannot be
        // measured. Increase the work factor until we can measure something.
        log_n += 1;
        duration = measure_duration(log_n);
    }

    duration
        .map(|mut d| {
            // Use duration as a proxy for CPU usage, which scales linearly with N.
            while d < ONE_SECOND && log_n < 63 {
                log_n += 1;
                d *= 2;
            }
            log_n
        })
        .unwrap_or({
            // Couldn't measure, so guess. This is roughly 1 second on a modern machine.
            18
        })
        .min(DEFAULT_MAX_WORK_FACTOR)
}

/// A passphrase-based recipient. Anyone with the passphrase can decrypt the file.
///
/// If an `scrypt::Recipient` is used, it must be the only recipient for the file: it
/// can't be mixed with other recipient types and can't be used multiple times for the
/// same file.
///
/// This API should only be used with a passphrase that was provided by (or generated
/// for) a human. For programmatic use cases, instead generate an [`x25519::Identity`].
///
/// [`x25519::Identity`]: crate::x25519::Identity
pub struct Recipient {
    passphrase: SecretString,
    log_n: u8,
}

impl Recipient {
    /// Constructs a new `Recipient` with the given passphrase.
    ///
    /// The scrypt work factor is picked to target about 1 second for encryption or
    /// decryption on this device, capped at [`DEFAULT_MAX_WORK_FACTOR`]. Override it
    /// with [`Self::set_work_factor`].
    pub fn new(passphrase: SecretString) -> Self {
        Self {
            passphrase,
            log_n: target_scrypt_work_factor(),
        }
    }

    /// Sets the scrypt work factor to `N = 2^log_n`.
    ///
    /// This method must be called before [`Self::wrap_file_key`] to have an effect.
    ///
    /// [`Self::wrap_file_key`]: crate::Recipient::wrap_file_key
    ///
    /// # Panics
    ///
    /// Panics if `log_n == 0` or `log_n >= 64`.
    pub fn set_work_factor(&mut self, log_n: u8) {
        assert!(0 < log_n && log_n < 64);
        self.log_n = log_n;
    }
}

impl crate::Recipient for Recipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), EncryptError> {
        let mut rng = UnwrapErr(SysRng);

        let mut salt = [0; SALT_LEN];
        rng.fill_bytes(&mut salt);

        let mut inner_salt = [0; SCRYPT_SALT_LABEL.len() + SALT_LEN];
        inner_salt[..SCRYPT_SALT_LABEL.len()].copy_from_slice(SCRYPT_SALT_LABEL);
        inner_salt[SCRYPT_SALT_LABEL.len()..].copy_from_slice(&salt);

        let enc_key =
            scrypt(&inner_salt, self.log_n, self.passphrase.expose_secret()).expect("log_n < 64");
        let encrypted_file_key = aead_encrypt(&enc_key, file_key.expose_secret());

        let encoded_salt = BASE64_STANDARD_NO_PAD.encode(salt);

        let label = Alphanumeric.sample_string(&mut rng, 32);

        Ok((
            vec![Stanza {
                tag: SCRYPT_RECIPIENT_TAG.to_owned(),
                args: vec![encoded_salt, format!("{}", self.log_n)],
                body: encrypted_file_key,
            }],
            iter::once(label).collect(),
        ))
    }
}

/// A passphrase-based identity. Anyone with the passphrase can decrypt the file.
///
/// The identity caps the amount of work that the [`Decryptor`] might have to do to
/// process received files. Work factors above [`DEFAULT_MAX_WORK_FACTOR`] are rejected
/// before any scrypt memory is allocated or computation begins, which prevents malicious
/// files from causing a denial of service. This limit can be raised explicitly with
/// [`Self::set_max_work_factor`] for files that are known to use a higher work factor.
///
/// [`Decryptor`]: crate::Decryptor
pub struct Identity {
    passphrase: SecretString,
    target_work_factor: u8,
    max_work_factor: u8,
}

impl Identity {
    /// Constructs a new `Identity` with the given passphrase.
    pub fn new(passphrase: SecretString) -> Self {
        let target_work_factor = target_scrypt_work_factor();

        // Bound the work factor we will accept by default. This is deliberately a
        // fixed protocol limit rather than a machine-specific value: otherwise a fast
        // machine can derive a limit that permits multi-gigabyte scrypt allocations
        // from an unauthenticated, attacker-controlled file header.
        let max_work_factor = target_work_factor
            .saturating_add(4)
            .min(DEFAULT_MAX_WORK_FACTOR);

        Self {
            passphrase,
            target_work_factor,
            max_work_factor,
        }
    }

    /// Sets the maximum accepted scrypt work factor to `N = 2^max_log_n`.
    ///
    /// This method must be called before [`Self::unwrap_stanza`] to have an effect.
    ///
    /// # Security
    ///
    /// This sets the bounds on CPU/memory cost. The default is
    /// [`DEFAULT_MAX_WORK_FACTOR`]. Large values can allow attempted decryption of a
    /// malicious file that takes hours and tens of GiB of RAM, so only raise this for
    /// files you trust to use a higher work factor.
    ///
    /// [`Self::unwrap_stanza`]: crate::Identity::unwrap_stanza
    pub fn set_max_work_factor(&mut self, max_log_n: u8) {
        self.max_work_factor = max_log_n;
    }
}

/// Returns the work factor declared by a scrypt recipient stanza.
///
/// Returns `None` if the stanza is not a well-formed scrypt stanza. The caller is
/// expected to let [`Identity::unwrap_stanza`] report the appropriate header error in
/// that case.
pub(crate) fn declared_work_factor(stanza: &Stanza) -> Option<u8> {
    if stanza.tag != SCRYPT_RECIPIENT_TAG {
        return None;
    }

    match &stanza.args[..] {
        [salt, log_n]
            if stanza.body.len() == ENCRYPTED_FILE_KEY_BYTES
                && base64_arg::<_, SALT_LEN, 18>(salt).is_some() =>
        {
            decimal_digit_arg(log_n)
        }
        _ => None,
    }
}

impl crate::Identity for Identity {
    fn max_work_factor(&self) -> Option<u8> {
        Some(self.max_work_factor)
    }

    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, DecryptError>> {
        if stanza.tag != SCRYPT_RECIPIENT_TAG {
            return None;
        }

        // Enforce valid and canonical stanza format.
        // https://c2sp.org/age#scrypt-recipient-stanza
        let (salt, log_n) = match &stanza.args[..] {
            [salt, log_n] => match (
                base64_arg::<_, SALT_LEN, 18>(salt),
                decimal_digit_arg(log_n),
            ) {
                (Some(salt), Some(log_n)) => (salt, log_n),
                _ => return Some(Err(DecryptError::InvalidHeader)),
            },
            _ => return Some(Err(DecryptError::InvalidHeader)),
        };
        if stanza.body.len() != ENCRYPTED_FILE_KEY_BYTES {
            return Some(Err(DecryptError::InvalidHeader));
        }

        // Enforce the resource limit before allocating scrypt's scratch space or
        // performing any key derivation.
        if log_n > self.max_work_factor {
            return Some(Err(DecryptError::ExcessiveWork {
                required: log_n,
                target: self.target_work_factor,
            }));
        }

        let mut inner_salt = [0; SCRYPT_SALT_LABEL.len() + SALT_LEN];
        inner_salt[..SCRYPT_SALT_LABEL.len()].copy_from_slice(SCRYPT_SALT_LABEL);
        inner_salt[SCRYPT_SALT_LABEL.len()..].copy_from_slice(&salt);

        let enc_key = match scrypt(&inner_salt, log_n, self.passphrase.expose_secret()) {
            Ok(k) => k,
            Err(_) => {
                return Some(Err(DecryptError::ExcessiveWork {
                    required: log_n,
                    target: self.target_work_factor,
                }));
            }
        };

        // This AEAD is not robust, so an attacker could craft a message that decrypts
        // under two different keys (meaning two different passphrases) and then use an
        // error side-channel in an online decryption oracle to learn if either key is
        // correct. This is deemed acceptable because the use case (an online decryption
        // oracle) is not recommended, and the security loss is only one bit. This also
        // does not bypass any scrypt work, but that work can be precomputed in an online
        // oracle scenario.
        Some(
            aead_decrypt(&enc_key, FILE_KEY_BYTES, &stanza.body)
                .map(|mut pt| {
                    // It's ours!
                    FileKey::init_with_mut(|file_key| {
                        file_key.copy_from_slice(&pt);
                        pt.zeroize();
                    })
                })
                .map_err(DecryptError::from),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity as _;

    fn test_identity() -> Identity {
        Identity::new(SecretString::from("password".to_owned()))
    }

    fn test_stanza(log_n: u8) -> Stanza {
        Stanza {
            tag: SCRYPT_RECIPIENT_TAG.to_owned(),
            args: vec!["rF0/NwblUHHTpgQgRpe5CQ".to_owned(), log_n.to_string()],
            body: vec![0; ENCRYPTED_FILE_KEY_BYTES],
        }
    }

    #[test]
    fn default_work_factor_limits() {
        let recipient = Recipient::new(SecretString::from("password".to_owned()));
        assert!(recipient.log_n <= DEFAULT_MAX_WORK_FACTOR);

        let identity = test_identity();
        assert!(identity.target_work_factor <= DEFAULT_MAX_WORK_FACTOR);
        assert!(identity.max_work_factor <= DEFAULT_MAX_WORK_FACTOR);

        // A work factor one above the protocol limit must be rejected before scrypt is
        // invoked. If this regresses on a fast machine, the test will attempt an
        // 8 GiB scrypt computation instead of returning immediately.
        match identity.unwrap_stanza(&test_stanza(DEFAULT_MAX_WORK_FACTOR + 1)) {
            Some(Err(DecryptError::ExcessiveWork { required, .. })) => {
                assert_eq!(required, DEFAULT_MAX_WORK_FACTOR + 1);
            }
            _ => panic!("work factor above the default limit should be rejected"),
        }
    }

    #[test]
    fn explicit_higher_work_factor_is_preserved() {
        let mut identity = test_identity();
        identity.set_max_work_factor(DEFAULT_MAX_WORK_FACTOR + 1);
        assert_eq!(identity.max_work_factor, DEFAULT_MAX_WORK_FACTOR + 1);
    }
}
