use std::fmt;
use std::io;

macro_rules! wfl {
    ($f:ident, $message_id:literal) => {
        write!($f, "{}", $crate::fl!($message_id))
    };

    ($f:ident, $message_id:literal, $($args:expr),* $(,)?) => {
        write!($f, "{}", $crate::fl!($message_id, $($args), *))
    };
}

macro_rules! wlnfl {
    ($f:ident, $message_id:literal) => {
        writeln!($f, "{}", $crate::fl!($message_id))
    };

    ($f:ident, $message_id:literal, $($args:expr),* $(,)?) => {
        writeln!($f, "{}", $crate::fl!($message_id, $($args), *))
    };
}

pub(crate) enum EncryptError {
    Age(age::EncryptError),
    BrokenPipe {
        is_stdout: bool,
        source: io::Error,
    },
    IdentityRead(age::cli_common::ReadError),
    Io(io::Error),
    MixedIdentityAndPassphrase,
    MixedRecipientAndPassphrase,
    MixedRecipientsFileAndPassphrase,
    PassphraseTimedOut,
    #[cfg(not(unix))]
    PassphraseWithoutFileArgument,
    PluginNameFlag,
}

impl From<age::EncryptError> for EncryptError {
    fn from(e: age::EncryptError) -> Self {
        match e {
            age::EncryptError::Io(e) => EncryptError::Io(e),
            _ => EncryptError::Age(e),
        }
    }
}

impl From<age::cli_common::ReadError> for EncryptError {
    fn from(e: age::cli_common::ReadError) -> Self {
        EncryptError::IdentityRead(e)
    }
}

impl From<io::Error> for EncryptError {
    fn from(e: io::Error) -> Self {
        EncryptError::Io(e)
    }
}

impl fmt::Display for EncryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptError::Age(e @ age::EncryptError::MissingRecipients) => {
                writeln!(f, "{e}")?;
                wfl!(f, "rec-enc-missing-recipients")
            }
            EncryptError::Age(e) => write!(f, "{e}"),
            EncryptError::BrokenPipe { is_stdout, source } => {
                if *is_stdout {
                    wlnfl!(f, "err-enc-broken-stdout", err = source.to_string())?;
                    wfl!(f, "rec-enc-broken-stdout")
                } else {
                    wfl!(f, "err-enc-broken-file", err = source.to_string())
                }
            }
            EncryptError::IdentityRead(e) => write!(f, "{e}"),
            EncryptError::Io(e) => write!(f, "{e}"),
            EncryptError::MixedIdentityAndPassphrase => {
                wfl!(f, "err-enc-mixed-identity-passphrase")
            }
            EncryptError::MixedRecipientAndPassphrase => {
                wfl!(f, "err-enc-mixed-recipient-passphrase")
            }
            EncryptError::MixedRecipientsFileAndPassphrase => {
                wfl!(f, "err-enc-mixed-recipients-file-passphrase")
            }
            EncryptError::PassphraseTimedOut => wfl!(f, "err-passphrase-timed-out"),
            #[cfg(not(unix))]
            EncryptError::PassphraseWithoutFileArgument => {
                wfl!(f, "err-enc-passphrase-without-file")
            }
            EncryptError::PluginNameFlag => {
                wfl!(f, "err-enc-plugin-name-flag")
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct DetectedPowerShellCorruptionError;

impl fmt::Display for DetectedPowerShellCorruptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        wlnfl!(f, "err-detected-powershell-corruption")?;
        wfl!(f, "rec-detected-powershell-corruption")
    }
}

impl std::error::Error for DetectedPowerShellCorruptionError {}

pub(crate) enum DecryptError {
    Age(age::DecryptError),
    ArmorFlag,
    IdentityRead(age::cli_common::ReadError),
    Io(io::Error),
    MissingIdentities {
        stdin_identity: bool,
    },
    MixedIdentityAndPassphrase,
    MixedIdentityAndPluginName,
    PassphraseFlag,
    PassphraseTimedOut,
    #[cfg(not(unix))]
    PassphraseWithoutFileArgument,
    RecipientFlag,
    RecipientsFileFlag,
}

impl From<age::DecryptError> for DecryptError {
    fn from(e: age::DecryptError) -> Self {
        DecryptError::Age(e)
    }
}

impl From<age::plugin::ResolveError> for DecryptError {
    fn from(e: age::plugin::ResolveError) -> Self {
        DecryptError::Age(age::DecryptError::PluginResolve(e))
    }
}

impl From<age::cli_common::ReadError> for DecryptError {
    fn from(e: age::cli_common::ReadError) -> Self {
        DecryptError::IdentityRead(e)
    }
}

impl From<io::Error> for DecryptError {
    fn from(e: io::Error) -> Self {
        DecryptError::Io(e)
    }
}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecryptError::Age(e) => match e {
                age::DecryptError::ExcessiveWork { required, .. } => {
                    writeln!(f, "{e}")?;
                    wfl!(f, "rec-dec-excessive-work", wf = required)
                }
                _ => write!(f, "{e}"),
            },
            DecryptError::ArmorFlag => {
                wlnfl!(f, "err-dec-armor-flag")?;
                wfl!(f, "rec-dec-armor-flag")
            }
            DecryptError::IdentityRead(e) => write!(f, "{e}"),
            DecryptError::Io(e) => write!(f, "{e}"),
            DecryptError::MissingIdentities { stdin_identity } => {
                wlnfl!(f, "err-dec-missing-identities")?;
                if *stdin_identity {
                    wfl!(f, "rec-dec-missing-identities-stdin")
                } else {
                    wfl!(f, "rec-dec-missing-identities")
                }
            }
            DecryptError::MixedIdentityAndPassphrase => {
                wfl!(f, "err-dec-mixed-identity-passphrase")
            }
            DecryptError::MixedIdentityAndPluginName => {
                wfl!(f, "err-mixed-identity-and-plugin-name")
            }
            DecryptError::PassphraseFlag => {
                wlnfl!(f, "err-dec-passphrase-flag")?;
                wfl!(f, "rec-dec-passphrase-flag")
            }
            DecryptError::PassphraseTimedOut => wfl!(f, "err-passphrase-timed-out"),
            #[cfg(not(unix))]
            DecryptError::PassphraseWithoutFileArgument => {
                wfl!(f, "err-dec-passphrase-without-file-win")
            }
            DecryptError::RecipientFlag => {
                wlnfl!(f, "err-dec-recipient-flag")?;
                wfl!(f, "rec-dec-recipient-flag")
            }
            DecryptError::RecipientsFileFlag => {
                wlnfl!(f, "err-dec-recipients-file-flag")?;
                wfl!(f, "rec-dec-recipient-flag")
            }
        }
    }
}

pub(crate) enum Error {
    Decryption(DecryptError),
    Encryption(EncryptError),
    IdentityFlagAmbiguous,
    MixedEncryptAndDecrypt,
    SameInputAndOutput(String),
}

impl From<DecryptError> for Error {
    fn from(e: DecryptError) -> Self {
        Error::Decryption(e)
    }
}

impl From<EncryptError> for Error {
    fn from(e: EncryptError) -> Self {
        Error::Encryption(e)
    }
}

impl Error {
    /// Stable, non-user-facing identity of the diagnostic category.
    ///
    /// Redaction must preserve this code and the underlying enum variants so
    /// callers and audits can still classify failures.
    pub(crate) fn diagnostic_code(&self) -> &'static str {
        match self {
            Error::Decryption(e) => e.diagnostic_code(),
            Error::Encryption(e) => e.diagnostic_code(),
            Error::IdentityFlagAmbiguous => "rage.identity_flag_ambiguous",
            Error::MixedEncryptAndDecrypt => "rage.mixed_encrypt_and_decrypt",
            Error::SameInputAndOutput(_) => "rage.same_input_and_output",
        }
    }

    pub(crate) fn category(&self) -> &'static str {
        match self {
            Error::Decryption(_) => "decryption",
            Error::Encryption(_) => "encryption",
            Error::IdentityFlagAmbiguous => "arguments.identity_ambiguous",
            Error::MixedEncryptAndDecrypt => "arguments.mixed_mode",
            Error::SameInputAndOutput(_) => "io.same_input_output",
        }
    }
}

impl EncryptError {
    pub(crate) fn diagnostic_code(&self) -> &'static str {
        match self {
            EncryptError::Age(_) => "rage.encrypt.age",
            EncryptError::BrokenPipe { .. } => "rage.encrypt.broken_pipe",
            EncryptError::IdentityRead(_) => "rage.encrypt.identity_read",
            EncryptError::Io(_) => "rage.encrypt.io",
            EncryptError::MixedIdentityAndPassphrase => "rage.encrypt.mixed_identity_passphrase",
            EncryptError::MixedRecipientAndPassphrase => "rage.encrypt.mixed_recipient_passphrase",
            EncryptError::MixedRecipientsFileAndPassphrase => {
                "rage.encrypt.mixed_recipients_file_passphrase"
            }
            EncryptError::PassphraseTimedOut => "rage.encrypt.passphrase_timeout",
            #[cfg(not(unix))]
            EncryptError::PassphraseWithoutFileArgument => "rage.encrypt.passphrase_without_file",
            EncryptError::PluginNameFlag => "rage.encrypt.plugin_name_flag",
        }
    }
}

impl DecryptError {
    pub(crate) fn diagnostic_code(&self) -> &'static str {
        match self {
            DecryptError::Age(_) => "rage.decrypt.age",
            DecryptError::ArmorFlag => "rage.decrypt.armor_flag",
            DecryptError::IdentityRead(_) => "rage.decrypt.identity_read",
            DecryptError::Io(_) => "rage.decrypt.io",
            DecryptError::MissingIdentities { .. } => "rage.decrypt.missing_identities",
            DecryptError::MixedIdentityAndPassphrase => "rage.decrypt.mixed_identity_passphrase",
            DecryptError::MixedIdentityAndPluginName => "rage.decrypt.mixed_identity_plugin_name",
            DecryptError::PassphraseFlag => "rage.decrypt.passphrase_flag",
            DecryptError::PassphraseTimedOut => "rage.decrypt.passphrase_timeout",
            #[cfg(not(unix))]
            DecryptError::PassphraseWithoutFileArgument => "rage.decrypt.passphrase_without_file",
            DecryptError::RecipientFlag => "rage.decrypt.recipient_flag",
            DecryptError::RecipientsFileFlag => "rage.decrypt.recipients_file_flag",
        }
    }
}

// The diagnostic body is rendered as `Display`. Rust's `Termination` machinery
// prints `Debug` for the error returned from `main`; that implementation is the
// public stderr consumer and the single boundary where secrets are redacted.
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Decryption(e) => writeln!(f, "{e}")?,
            Error::Encryption(e) => writeln!(f, "{e}")?,
            Error::IdentityFlagAmbiguous => wlnfl!(f, "err-identity-ambiguous")?,
            Error::MixedEncryptAndDecrypt => wlnfl!(f, "err-mixed-encrypt-decrypt")?,
            Error::SameInputAndOutput(filename) => {
                wlnfl!(f, "err-same-input-and-output", filename = filename.as_str())?
            }
        }
        writeln!(f)?;
        writeln!(f, "[ {} ]", crate::fl!("err-ux-A"))?;
        write!(
            f,
            "[ {}: https://str4d.xyz/rage/report {} ]",
            crate::fl!("err-ux-B"),
            crate::fl!("err-ux-C")
        )
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let diagnostic = format!("{self}");
        f.write_str(&crate::redact::redact_globally(&diagnostic))
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Decryption(DecryptError::Age(e)) => Some(e),
            Error::Decryption(DecryptError::IdentityRead(e)) => Some(e),
            Error::Decryption(DecryptError::Io(e)) => Some(e),
            Error::Encryption(EncryptError::Age(e)) => Some(e),
            Error::Encryption(EncryptError::IdentityRead(e)) => Some(e),
            Error::Encryption(EncryptError::Io(e)) => Some(e),
            Error::Encryption(EncryptError::BrokenPipe { source, .. }) => Some(source),
            _ => None,
        }
    }
}
