use std::{
    fmt,
    fs::File,
    io::{self, BufRead},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use zeroize::Zeroize;

use crate::{
    Callbacks, DecryptError, EncryptError, IdentityFileConvertError, NoCallbacks,
    util::LimitedReader, x25519,
};

#[cfg(feature = "cli-common")]
use crate::cli_common::file_io::InputReader;

#[cfg(feature = "plugin")]
use crate::plugin;

const IDENTITY_SIZE_LIMIT: usize = 1 << 24; // 16 MiB

static BINDING_GENERATION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The verification state of a recipient comment bound to a parsed identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecipientBindingStatus {
    /// The identity had no recipient comment, which remains a valid format.
    NoRecipientComment,
    /// Every parseable X25519 recipient comment matched the identity's public key.
    Verified,
    /// A recipient comment named a different X25519 subject.
    Mismatch,
}

impl RecipientBindingStatus {
    /// Returns a stable, machine-readable status token.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoRecipientComment => "no_recipient_comment",
            Self::Verified => "verified",
            Self::Mismatch => "mismatch",
        }
    }
}

/// Evidence binding a recipient claim in comments to the actual parsed subject.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecipientBinding {
    /// One-based line number of the identity line.
    pub line_number: usize,
    /// The claimed key generation, if present, or the audit generation otherwise.
    pub generation: String,
    /// The generation or creation marker parsed from comments.
    pub claimed_generation: Option<String>,
    /// Canonical recipients parsed from adjacent comments.
    pub declared_recipients: Vec<String>,
    /// The recipient cryptographically derived from the parsed identity.
    pub subject_recipient: String,
    /// The result of comparing the claim(s) with the subject evidence.
    pub status: RecipientBindingStatus,
}

impl RecipientBinding {
    /// Returns the subject evidence as its canonical Bech32 recipient.
    pub fn subject_evidence(&self) -> &str {
        &self.subject_recipient
    }

    /// Returns `true` if no conflicting recipient claim is present.
    pub fn is_bound(&self) -> bool {
        !matches!(self.status, RecipientBindingStatus::Mismatch)
    }
}

/// A generation-tagged set of identity-to-recipient binding evidences.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct IdentityBindingReport {
    /// The claimed generation when available, otherwise [`Self::audit_generation`].
    pub generation: String,
    /// Process-local generation identifying this parse and evidence set.
    pub audit_generation: String,
    /// The generation/creation marker claimed by the identity file.
    pub claimed_generation: Option<String>,
    /// The identity file name, if one was provided.
    pub filename: Option<String>,
    /// Binding evidence for every native identity in parse order.
    pub bindings: Vec<RecipientBinding>,
}

impl IdentityBindingReport {
    /// Returns `true` if every parsed subject is either uncommented or verified.
    pub fn is_complete(&self) -> bool {
        self.bindings.iter().all(RecipientBinding::is_bound)
    }

    /// Returns canonical subject recipients in parse order.
    pub fn subject_evidence(&self) -> impl Iterator<Item = &str> + '_ {
        self.bindings.iter().map(RecipientBinding::subject_evidence)
    }

    /// Serializes the report as a JSON object.
    ///
    /// The audit generation is unique per parse; all other fields are stable for a given
    /// identity file. This output contains only public recipient strings and metadata.
    pub fn to_json(&self) -> String {
        fn quote(value: &str) -> String {
            let mut out = String::with_capacity(value.len() + 2);
            out.push('"');
            for ch in value.chars() {
                match ch {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    ch if (ch as u32) < 0x20 => {
                        out.push_str(&format!("\\u{:04x}", ch as u32));
                    }
                    ch => out.push(ch),
                }
            }
            out.push('"');
            out
        }

        let bindings = self
            .bindings
            .iter()
            .map(|b| {
                let declared = b
                    .declared_recipients
                    .iter()
                    .map(|r| quote(r))
                    .collect::<Vec<_>>()
                    .join(",");
                let claimed_generation = b
                    .claimed_generation
                    .as_deref()
                    .map(quote)
                    .unwrap_or_else(|| "null".to_owned());
                format!(
                    "{{\"line_number\":{},\"generation\":{},\"claimed_generation\":{},\
                     \"declared_recipients\":[{}],\"subject_evidence\":{},\"status\":{}}}",
                    b.line_number,
                    quote(&b.generation),
                    claimed_generation,
                    declared,
                    quote(&b.subject_recipient),
                    quote(b.status.as_str()),
                )
            })
            .collect::<Vec<_>>()
            .join(",");

        let claimed_generation = self
            .claimed_generation
            .as_deref()
            .map(quote)
            .unwrap_or_else(|| "null".to_owned());
        let filename = self
            .filename
            .as_deref()
            .map(quote)
            .unwrap_or_else(|| "null".to_owned());

        format!(
            "{{\"schema_version\":1,\"event\":\"identity_subject_binding\",\
             \"generation\":{},\"audit_generation\":{},\"claimed_generation\":{},\
             \"filename\":{},\"complete\":{},\"bindings\":[{}]}}",
            quote(&self.generation),
            quote(&self.audit_generation),
            claimed_generation,
            filename,
            self.is_complete(),
            bindings,
        )
    }
}

/// A recipient comment did not match the subject derived from the identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityBindingError {
    report: IdentityBindingReport,
}

impl IdentityBindingError {
    /// Returns the generation-tagged evidence describing the mismatch.
    pub fn report(&self) -> &IdentityBindingReport {
        &self.report
    }

    fn into_io_error(self) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, self)
    }
}

impl fmt::Display for IdentityBindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mismatch = self
            .report
            .bindings
            .iter()
            .find(|b| b.status == RecipientBindingStatus::Mismatch);
        if let Some(mismatch) = mismatch {
            write!(
                f,
                "identity recipient binding mismatch on line {} (generation={}, declared={}, subject_evidence={})",
                mismatch.line_number,
                mismatch.generation,
                mismatch
                    .declared_recipients
                    .first()
                    .map(String::as_str)
                    .unwrap_or("unknown"),
                mismatch.subject_evidence(),
            )
        } else {
            f.write_str("identity recipient binding verification failed")
        }
    }
}

impl std::error::Error for IdentityBindingError {}

fn new_audit_generation() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let sequence = BINDING_GENERATION_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("identity-gen-{}-{nanos}-{sequence}", std::process::id())
}

#[derive(Default)]
struct PendingComments {
    declared_recipients: Vec<String>,
    claimed_generation: Option<String>,
}

impl PendingComments {
    fn reset(&mut self) {
        self.declared_recipients.clear();
        self.claimed_generation = None;
    }

    fn observe(&mut self, comment: &str) {
        if self.claimed_generation.is_none() {
            self.claimed_generation = extract_generation_marker(comment);
        }

        for token in comment.split_whitespace() {
            let candidate = token.trim_matches(|c: char| {
                matches!(
                    c,
                    ':' | ',' | ';' | '.' | '(' | ')' | '[' | ']' | '<' | '>' | '"' | '\'' | '`'
                )
            });
            if let Ok(recipient) = candidate.parse::<x25519::Recipient>() {
                let canonical = recipient.to_string();
                if !self.declared_recipients.contains(&canonical) {
                    self.declared_recipients.push(canonical);
                }
            }
        }
    }

    fn take_binding(
        &mut self,
        line_number: usize,
        audit_generation: &str,
        subject_recipient: String,
    ) -> RecipientBinding {
        let status = if self.declared_recipients.is_empty() {
            RecipientBindingStatus::NoRecipientComment
        } else if self
            .declared_recipients
            .iter()
            .all(|recipient| recipient == &subject_recipient)
        {
            RecipientBindingStatus::Verified
        } else {
            RecipientBindingStatus::Mismatch
        };
        let claimed_generation = self.claimed_generation.clone();
        let generation = claimed_generation
            .clone()
            .unwrap_or_else(|| audit_generation.to_owned());

        let binding = RecipientBinding {
            line_number,
            generation,
            claimed_generation,
            declared_recipients: std::mem::take(&mut self.declared_recipients),
            subject_recipient,
            status,
        };
        self.reset();
        binding
    }
}

fn extract_generation_marker(comment: &str) -> Option<String> {
    let body = comment.trim_start_matches('#').trim();
    // ASCII lowering preserves byte offsets, unlike Unicode lowercasing.
    let lower = body.to_ascii_lowercase();

    for key in ["generation", "generated", "created"] {
        if let Some(index) = lower.find(key) {
            let after_key = body[index + key.len()..].trim_start();
            if let Some(value) = after_key.strip_prefix([':', '=']) {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value.to_owned());
                }
            }
        }
    }

    // rage-keygen's standard comment is "# created: <RFC 3339 timestamp>".
    body.split_whitespace()
        .map(|token| token.trim_end_matches([',', ';', '.', ')']))
        .find(|token| {
            token.as_bytes().get(4) == Some(&b'-')
                && token.as_bytes().get(7) == Some(&b'-')
                && token.contains('T')
        })
        .map(str::to_owned)
}

/// The supported kinds of identities within an [`IdentityFile`].
#[derive(Clone)]
enum IdentityFileEntry {
    /// The standard age identity type.
    Native(x25519::Identity),
    /// A plugin-compatible identity.
    #[cfg(feature = "plugin")]
    #[cfg_attr(docsrs, doc(cfg(feature = "plugin")))]
    Plugin(plugin::Identity),
}

impl IdentityFileEntry {
    #[allow(unused_variables)]
    pub(crate) fn into_identity(
        self,
        callbacks: impl Callbacks,
    ) -> Result<Box<dyn crate::Identity + Send + Sync>, DecryptError> {
        match self {
            IdentityFileEntry::Native(i) => Ok(Box::new(i)),
            #[cfg(feature = "plugin")]
            IdentityFileEntry::Plugin(i) => Ok(Box::new(
                crate::plugin::Plugin::new(i.plugin())
                    .map_err(DecryptError::PluginResolve)
                    .map(|plugin| {
                        crate::plugin::IdentityPluginV1::from_parts(plugin, vec![i], callbacks)
                    })?,
            )),
        }
    }
}

/// A list of identities that has been parsed from some input file.
///
/// The maximum supported file size is 16 MiB.
pub struct IdentityFile<C: Callbacks> {
    filename: Option<String>,
    identities: Vec<IdentityFileEntry>,
    generation: String,
    bindings: Vec<RecipientBinding>,
    pub(crate) callbacks: C,
}

impl IdentityFile<NoCallbacks> {
    /// Parses one or more identities from a file containing valid UTF-8.
    pub fn from_file(filename: String) -> io::Result<Self> {
        File::open(&filename)
            .map(io::BufReader::new)
            .and_then(|data| IdentityFile::parse_identities(Some(filename), data))
    }

    /// Parses one or more identities from a buffered input containing valid UTF-8.
    pub fn from_buffer<R: io::BufRead>(data: R) -> io::Result<Self> {
        Self::parse_identities(None, data)
    }

    /// Parses one or more identities from an [`InputReader`];
    #[cfg(feature = "cli-common")]
    pub fn from_input_reader(reader: InputReader) -> io::Result<Self> {
        let filename = reader.filename().map(String::from);
        Self::parse_identities(filename, io::BufReader::new(reader))
    }

    fn parse_identities<R: io::BufRead>(filename: Option<String>, data: R) -> io::Result<Self> {
        let mut identities = vec![];
        let mut bindings = vec![];
        let audit_generation = new_audit_generation();

        let data = LimitedReader::new(data, IDENTITY_SIZE_LIMIT);
        let mut comments = PendingComments::default();

        for (line_number, line) in data.lines().enumerate() {
            let mut line = line?;
            if line.is_empty() {
                line.zeroize();
                continue;
            }
            if line.starts_with('#') {
                comments.observe(&line);
                line.zeroize();
                continue;
            }

            match line.parse::<x25519::Identity>() {
                Ok(identity) => {
                    let subject_recipient = identity.to_public().to_string();
                    bindings.push(comments.take_binding(
                        line_number + 1,
                        &audit_generation,
                        subject_recipient,
                    ));
                    identities.push(IdentityFileEntry::Native(identity));
                }
                _ => {
                    if let Some(identity) = {
                        #[cfg(feature = "plugin")]
                        {
                            line.parse::<plugin::Identity>().ok()
                        }

                        #[cfg(not(feature = "plugin"))]
                        None
                    } {
                        #[cfg(feature = "plugin")]
                        {
                            identities.push(IdentityFileEntry::Plugin(identity));
                            comments.reset();
                        }

                        // Add a binding to provide a type when plugins are disabled.
                        #[cfg(not(feature = "plugin"))]
                        let _: () = identity;
                    } else {
                        line.zeroize();

                        // Return a line number in place of the line, so we don't leak the file
                        // contents in error messages.
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            if let Some(filename) = filename {
                                format!(
                                    "identity file {} contains non-identity data on line {}",
                                    filename,
                                    line_number + 1
                                )
                            } else {
                                format!(
                                    "identity file contains non-identity data on line {}",
                                    line_number + 1
                                )
                            },
                        ));
                    }
                }
            }

            line.zeroize();
        }

        if bindings
            .iter()
            .any(|b| b.status == RecipientBindingStatus::Mismatch)
        {
            let report = IdentityBindingReport {
                generation: bindings
                    .iter()
                    .find_map(|b| b.claimed_generation.clone())
                    .unwrap_or_else(|| audit_generation.clone()),
                audit_generation: audit_generation.clone(),
                claimed_generation: bindings.iter().find_map(|b| b.claimed_generation.clone()),
                filename: filename.clone(),
                bindings: bindings.clone(),
            };
            return Err(IdentityBindingError { report }.into_io_error());
        }

        Ok(IdentityFile {
            filename,
            identities,
            generation: audit_generation,
            bindings,
            callbacks: NoCallbacks,
        })
    }
}

impl<C: Callbacks> IdentityFile<C> {
    /// Sets the provided callbacks on this identity file, so that if this is an encrypted
    /// identity, it can potentially be decrypted.
    pub fn with_callbacks<D: Callbacks>(self, callbacks: D) -> IdentityFile<D> {
        IdentityFile {
            filename: self.filename,
            identities: self.identities,
            generation: self.generation,
            bindings: self.bindings,
            callbacks,
        }
    }

    /// Writes a recipients file containing the recipients corresponding to the identities
    /// in this file.
    ///
    /// Returns an error if this file is empty, or if it contains plugin identities (which
    /// can only be converted by the plugin binary itself).
    pub fn write_recipients_file<W: io::Write>(
        &self,
        mut output: W,
    ) -> Result<(), IdentityFileConvertError> {
        if self.identities.is_empty() {
            return Err(IdentityFileConvertError::NoIdentities {
                filename: self.filename.clone(),
            });
        }

        for identity in &self.identities {
            match identity {
                IdentityFileEntry::Native(sk) => writeln!(output, "{}", sk.to_public())
                    .map_err(IdentityFileConvertError::FailedToWriteOutput)?,
                #[cfg(feature = "plugin")]
                IdentityFileEntry::Plugin(id) => {
                    return Err(IdentityFileConvertError::IdentityFileContainsPlugin {
                        filename: self.filename.clone(),
                        plugin_name: id.plugin().to_string(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Returns recipients for the identities in this file.
    ///
    /// Plugin identities will be merged into one [`Recipient`] per unique plugin.
    ///
    /// [`Recipient`]: crate::Recipient
    pub fn to_recipients(&self) -> Result<Vec<Box<dyn crate::Recipient + Send>>, EncryptError> {
        let mut recipients = RecipientsAccumulator::new();
        recipients.with_identities_ref(self);
        recipients.build(
            #[cfg(feature = "plugin")]
            self.callbacks.clone(),
        )
    }

    /// Returns generation-tagged binding evidence for this parsed identity file.
    ///
    /// Recipient comments that conflict with a parsed identity are rejected while parsing,
    /// so returned reports always have [`IdentityBindingReport::is_complete`] equal to `true`.
    pub fn binding_report(&self) -> IdentityBindingReport {
        let claimed_generation = self
            .bindings
            .iter()
            .find_map(|binding| binding.claimed_generation.clone());
        IdentityBindingReport {
            generation: claimed_generation
                .clone()
                .unwrap_or_else(|| self.generation.clone()),
            audit_generation: self.generation.clone(),
            claimed_generation,
            filename: self.filename.clone(),
            bindings: self.bindings.clone(),
        }
    }

    /// Returns the identities in this file.
    pub(crate) fn to_identities(
        &self,
    ) -> impl Iterator<Item = Result<Box<dyn crate::Identity + Send + Sync>, DecryptError>> + '_
    {
        self.identities
            .iter()
            .map(|entry| entry.clone().into_identity(self.callbacks.clone()))
    }

    /// Returns the identities in this file.
    pub fn into_identities(
        self,
    ) -> Result<Vec<Box<dyn crate::Identity + Send + Sync>>, DecryptError> {
        self.identities
            .into_iter()
            .map(|entry| entry.into_identity(self.callbacks.clone()))
            .collect()
    }
}

pub(crate) struct RecipientsAccumulator {
    recipients: Vec<Box<dyn crate::Recipient + Send>>,
    #[cfg(feature = "plugin")]
    plugin_recipients: Vec<plugin::Recipient>,
    #[cfg(feature = "plugin")]
    plugin_identities: Vec<plugin::Identity>,
}

impl RecipientsAccumulator {
    pub(crate) fn new() -> Self {
        Self {
            recipients: vec![],
            #[cfg(feature = "plugin")]
            plugin_recipients: vec![],
            #[cfg(feature = "plugin")]
            plugin_identities: vec![],
        }
    }

    #[cfg(feature = "cli-common")]
    pub(crate) fn push(&mut self, recipient: Box<dyn crate::Recipient + Send>) {
        self.recipients.push(recipient);
    }

    #[cfg(feature = "plugin")]
    pub(crate) fn push_plugin(&mut self, recipient: plugin::Recipient) {
        self.plugin_recipients.push(recipient);
    }

    #[cfg(feature = "armor")]
    pub(crate) fn extend(
        &mut self,
        iter: impl IntoIterator<Item = Box<dyn crate::Recipient + Send>>,
    ) {
        self.recipients.extend(iter);
    }

    #[cfg(feature = "cli-common")]
    pub(crate) fn with_identities<C: Callbacks>(&mut self, identity_file: IdentityFile<C>) {
        for entry in identity_file.identities {
            match entry {
                IdentityFileEntry::Native(i) => self.recipients.push(Box::new(i.to_public())),
                #[cfg(feature = "plugin")]
                IdentityFileEntry::Plugin(i) => self.plugin_identities.push(i),
            }
        }
    }

    pub(crate) fn with_identities_ref<C: Callbacks>(&mut self, identity_file: &IdentityFile<C>) {
        for entry in &identity_file.identities {
            match entry {
                IdentityFileEntry::Native(i) => self.recipients.push(Box::new(i.to_public())),
                #[cfg(feature = "plugin")]
                IdentityFileEntry::Plugin(i) => self.plugin_identities.push(i.clone()),
            }
        }
    }

    #[cfg_attr(not(feature = "plugin"), allow(unused_mut))]
    pub(crate) fn build(
        mut self,
        #[cfg(feature = "plugin")] callbacks: impl Callbacks,
    ) -> Result<Vec<Box<dyn crate::Recipient + Send>>, EncryptError> {
        #[cfg(feature = "plugin")]
        {
            // Collect the names of the required plugins.
            let mut plugin_names = self
                .plugin_recipients
                .iter()
                .map(|r| r.plugin())
                .chain(self.plugin_identities.iter().map(|i| i.plugin()))
                .collect::<Vec<_>>();
            plugin_names.sort_unstable();
            plugin_names.dedup();

            // Find the required plugins.
            for plugin_name in plugin_names {
                self.recipients.push(Box::new(
                    plugin::RecipientPluginV1::new(
                        plugin_name,
                        &self.plugin_recipients,
                        &self.plugin_identities,
                        callbacks.clone(),
                    )
                    .map_err(EncryptError::PluginResolve)?,
                ))
            }
        }

        Ok(self.recipients)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use age_core::secrecy::ExposeSecret;
    use std::io::BufReader;

    use super::{IdentityFile, IdentityFileEntry};

    pub(crate) const TEST_SK: &str =
        "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";

    fn valid_secret_key_encoding(keydata: &str, num_keys: usize) {
        let buf = BufReader::new(keydata.as_bytes());
        let f = IdentityFile::from_buffer(buf).unwrap();
        assert_eq!(f.identities.len(), num_keys);
        match &f.identities[0] {
            IdentityFileEntry::Native(identity) => {
                assert_eq!(identity.to_string().expose_secret(), TEST_SK)
            }
            #[cfg(feature = "plugin")]
            IdentityFileEntry::Plugin(_) => panic!(),
        }
    }

    #[test]
    fn secret_key_encoding() {
        valid_secret_key_encoding(TEST_SK, 1);
    }

    #[test]
    fn secret_key_lf() {
        valid_secret_key_encoding(&format!("{TEST_SK}\n"), 1);
    }

    #[test]
    fn two_secret_keys_lf() {
        valid_secret_key_encoding(&format!("{TEST_SK}\n{TEST_SK}"), 2);
    }

    #[test]
    fn secret_key_with_comment_lf() {
        valid_secret_key_encoding(&format!("# Foo bar baz\n{TEST_SK}"), 1);
        valid_secret_key_encoding(&format!("{TEST_SK}\n# Foo bar baz"), 1);
    }

    #[test]
    fn secret_key_with_empty_line_lf() {
        valid_secret_key_encoding(&format!("\n\n{TEST_SK}"), 1);
    }

    #[test]
    fn secret_key_crlf() {
        valid_secret_key_encoding(&format!("{TEST_SK}\r\n"), 1);
    }

    #[test]
    fn two_secret_keys_crlf() {
        valid_secret_key_encoding(&format!("{TEST_SK}\r\n{TEST_SK}"), 2);
    }

    #[test]
    fn secret_key_with_comment_crlf() {
        valid_secret_key_encoding(&format!("# Foo bar baz\r\n{TEST_SK}"), 1);
        valid_secret_key_encoding(&format!("{TEST_SK}\r\n# Foo bar baz"), 1);
    }

    #[test]
    fn secret_key_with_empty_line_crlf() {
        valid_secret_key_encoding(&format!("\r\n\r\n{TEST_SK}"), 1);
    }

    #[test]
    fn incomplete_secret_key_encoding() {
        let buf = BufReader::new(&TEST_SK.as_bytes()[..4]);
        assert!(IdentityFile::from_buffer(buf).is_err());
    }
}
