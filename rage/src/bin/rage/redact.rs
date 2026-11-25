use std::ffi::OsStr;
use std::sync::{OnceLock, RwLock};

use age::secrecy::{ExposeSecret, SecretString};

pub(crate) const REDACTED_IDENTITY: &str = "[REDACTED_IDENTITY]";
pub(crate) const REDACTED_PASSPHRASE: &str = "[REDACTED_PASSPHRASE]";
pub(crate) const REDACTED_PRIVATE_KEY: &str = "[REDACTED_PRIVATE_KEY]";

const AGE_SECRET_PREFIX: &str = "AGE-SECRET-KEY-";
const PLUGIN_IDENTITY_PREFIX: &str = "AGE-PLUGIN-";

/// Secret values that are not recognizable by syntax alone.
///
/// Pattern-based redaction catches structured age identities. Exact values are
/// used for passphrases and other secrets observed during process startup or
/// interactive input.
#[derive(Debug, Default, Clone)]
pub(crate) struct SecretRedactor {
    exact: Vec<String>,
    passphrase_argument_seen: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct RedactionFindings {
    pub identity_matches: usize,
    pub passphrase_matches: usize,
    pub private_key_matches: usize,
    pub exact_matches: usize,
    pub passphrase_argument_seen: bool,
}

impl RedactionFindings {
    pub(crate) fn secret_kinds(&self) -> Vec<String> {
        let mut kinds = Vec::new();
        if self.identity_matches > 0 {
            kinds.push("identity".to_owned());
        }
        if self.passphrase_matches > 0 || self.exact_matches > 0 {
            kinds.push("passphrase".to_owned());
        }
        if self.private_key_matches > 0 {
            kinds.push("private_key_block".to_owned());
        }
        if self.identity_matches == 0
            && self.passphrase_matches == 0
            && self.private_key_matches == 0
            && self.exact_matches == 0
            && self.passphrase_argument_seen
        {
            kinds.push("passphrase_argument".to_owned());
        }
        kinds
    }

    pub(crate) fn redaction_performed(&self) -> bool {
        self.identity_matches
            + self.passphrase_matches
            + self.private_key_matches
            + self.exact_matches
            > 0
    }
}

impl SecretRedactor {
    pub(crate) fn from_args_os<I, S>(args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut redactor = Self::default();
        for arg in args {
            let arg = arg.as_ref().to_string_lossy();
            if let Some(value) = arg.strip_prefix("--passphrase=") {
                redactor.passphrase_argument_seen = true;
                if !value.is_empty() {
                    redactor.add_exact(value);
                }
            }
        }
        redactor
    }

    pub(crate) fn add_passphrase(&mut self, passphrase: &SecretString) {
        self.add_exact(passphrase.expose_secret());
    }

    pub(crate) fn add_exact(&mut self, secret: impl Into<String>) {
        let secret = secret.into();
        // Empty values carry no diagnostic information; very short values are
        // still retained because exact matching is safer than relying on syntax.
        if !secret.is_empty() && !self.exact.iter().any(|s| s == &secret) {
            self.exact.push(secret);
        }
    }

    pub(crate) fn redact_detailed(&self, text: &str) -> (String, RedactionFindings) {
        let mut findings = RedactionFindings {
            passphrase_argument_seen: self.passphrase_argument_seen,
            ..RedactionFindings::default()
        };

        let mut redacted = redact_structured_secrets(text, &mut findings);

        for secret in &self.exact {
            if secret.is_empty() {
                continue;
            }
            if redacted.contains(secret) {
                let count = redacted.matches(secret.as_str()).count();
                findings.exact_matches += count;
                redacted = redacted.replace(secret, REDACTED_PASSPHRASE);
            }
        }

        (redacted, findings)
    }
}

static GLOBAL_REDACTOR: OnceLock<RwLock<SecretRedactor>> = OnceLock::new();

fn global_redactor() -> &'static RwLock<SecretRedactor> {
    GLOBAL_REDACTOR.get_or_init(|| RwLock::new(SecretRedactor::default()))
}

pub(crate) fn init_from_args_os<I, S>(args: I)
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let configured = SecretRedactor::from_args_os(args);
    if let Ok(mut global) = global_redactor().write() {
        *global = configured;
    }
}

pub(crate) fn register_passphrase(passphrase: &SecretString) {
    if let Ok(mut global) = global_redactor().write() {
        global.add_passphrase(passphrase);
    }
}

pub(crate) fn redact_globally(text: &str) -> String {
    let Ok(global) = global_redactor().read() else {
        let mut findings = RedactionFindings::default();
        return redact_structured_secrets(text, &mut findings);
    };
    global.redact_detailed(text).0
}

pub(crate) fn global_snapshot() -> SecretRedactor {
    global_redactor()
        .read()
        .map(|global| global.clone())
        .unwrap_or_default()
}

pub(crate) fn looks_like_secret_identity(value: &str) -> bool {
    contains_ci_prefix(value, AGE_SECRET_PREFIX)
        || contains_ci_prefix(value, PLUGIN_IDENTITY_PREFIX)
        || value.contains("PRIVATE KEY-----")
}

fn contains_ci_prefix(haystack: &str, prefix: &str) -> bool {
    haystack
        .as_bytes()
        .windows(prefix.len())
        .any(|window| window.eq_ignore_ascii_case(prefix.as_bytes()))
}

fn starts_with_ci_at(text: &str, offset: usize, prefix: &str) -> bool {
    let Some(candidate) = text.as_bytes().get(offset..offset + prefix.len()) else {
        return false;
    };
    candidate.eq_ignore_ascii_case(prefix.as_bytes())
}

fn redact_structured_secrets(input: &str, findings: &mut RedactionFindings) -> String {
    let mut output = String::with_capacity(input.len());
    let mut index = 0;

    while index < input.len() {
        if let Some(block_end) = private_key_block_end(input, index) {
            output.push_str(REDACTED_PRIVATE_KEY);
            findings.private_key_matches += 1;
            index = block_end;
            continue;
        }

        let prefix = if starts_with_ci_at(input, index, AGE_SECRET_PREFIX) {
            Some(AGE_SECRET_PREFIX)
        } else if starts_with_ci_at(input, index, PLUGIN_IDENTITY_PREFIX) {
            Some(PLUGIN_IDENTITY_PREFIX)
        } else {
            None
        };

        if let Some(prefix) = prefix {
            let data_start = index + prefix.len();
            let mut end = data_start;
            while end < input.len() {
                let ch = input[end..].chars().next().unwrap();
                if is_secret_terminator(ch) {
                    break;
                }
                end += ch.len_utf8();
            }

            // A prefix without any data is ordinary prose, not a secret value.
            if end > data_start {
                findings.identity_matches += 1;
                output.push_str(REDACTED_IDENTITY);
                index = end;
                continue;
            }
        }

        let ch = input[index..].chars().next().unwrap();
        output.push(ch);
        index += ch.len_utf8();
    }

    output
}

fn is_secret_terminator(ch: char) -> bool {
    ch.is_whitespace()
        || matches!(
            ch,
            '\'' | '"' | '`' | ',' | ';' | ')' | ']' | '}' | '<' | '>'
        )
}

fn private_key_block_end(input: &str, index: usize) -> Option<usize> {
    let begin = input[index..].find("-----BEGIN")?;
    if begin != 0 {
        return None;
    }
    let header_end = input[index..].find("PRIVATE KEY-----")?;
    let search_from = index + header_end + "PRIVATE KEY-----".len();
    let end_marker_rel = input[search_from..].find("-----END")?;
    let end_marker = search_from + end_marker_rel;
    let dash_end_rel = input[end_marker..].find("-----")?;
    Some(end_marker + dash_end_rel + "-----".len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_uppercase_age_identity() {
        let text = "Identity file not found: AGE-SECRET-KEY-ONE-TWO_3\nHint";
        let (redacted, findings) = SecretRedactor::default().redact_detailed(text);
        assert!(!redacted.contains("ONE-TWO"));
        assert!(redacted.contains(REDACTED_IDENTITY));
        assert!(redacted.contains("Hint"));
        assert_eq!(findings.identity_matches, 1);
    }

    #[test]
    fn redacts_lowercase_and_quoted_identity() {
        let text = "bad key 'age-secret-key-abcdef' here";
        let redactor = SecretRedactor::default();
        let (redacted, _) = redactor.redact_detailed(text);
        assert!(!redacted.contains("abcdef"));
        assert!(redacted.contains("'[REDACTED_IDENTITY]'"));
    }

    #[test]
    fn redacts_exact_passphrase_without_removing_hint_words() {
        let redactor = SecretRedactor::from_args_os([
            "rage",
            "--encrypt",
            "--passphrase=correct horse marker",
        ]);
        let text = "unexpected value 'correct horse marker' for '--passphrase'";
        let (redacted, findings) = redactor.redact_detailed(text);
        assert!(!redacted.contains("correct horse marker"));
        assert!(redacted.contains(REDACTED_PASSPHRASE));
        assert!(redacted.contains("unexpected value"));
        assert!(redacted.contains("--passphrase"));
        assert!(findings.passphrase_argument_seen);
    }

    #[test]
    fn preserves_normal_filename() {
        let text = "Identity file not found: /home/user/keys/rage-key.txt";
        let (redacted, findings) = SecretRedactor::default().redact_detailed(text);
        assert_eq!(redacted, text);
        assert!(!findings.redaction_performed());
    }
}
