//! Durable, non-secret evidence for plugin frame transactions.
//!
//! Plugin replies are applied only after the complete frame sequence has been
//! received, including its terminal `done` frame. This module records the
//! operation boundary so a failed or truncated plugin reply can be reviewed
//! without retaining recipient plaintext, file keys, identities, or passphrases.

use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::Write as IoWrite;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{DecryptError, EncryptError, Error};

const RECEIPT_PATH: &str = "security-receipt.json";
const RECEIPT_LOG_PATH: &str = "security-receipt.jsonl";

#[derive(Debug, Clone)]
pub(crate) struct OperationAudit {
    operation: &'static str,
    input: Option<String>,
    output: Option<String>,
    generation: String,
    plugin_requested: bool,
}

impl OperationAudit {
    pub(crate) fn new(
        operation: &'static str,
        input: Option<String>,
        output: Option<String>,
        plugin_requested: bool,
    ) -> Self {
        static GENERATION_COUNTER: AtomicU64 = AtomicU64::new(0);

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let generation = format!(
            "{}-{nanos}-{}",
            std::process::id(),
            GENERATION_COUNTER.fetch_add(1, Ordering::Relaxed)
        );

        Self {
            operation,
            input,
            output,
            generation,
            plugin_requested,
        }
    }
}

/// Returns whether the command line explicitly asks for a plugin recipient, identity, or
/// plugin-only decryption mode.
pub(crate) fn plugin_requested(
    plugin_name: &Option<String>,
    recipients: &[String],
    identities: &[String],
) -> bool {
    plugin_name.is_some()
        || recipients
            .iter()
            .any(|recipient| recipient.parse::<age::plugin::Recipient>().is_ok())
        || identities
            .iter()
            .any(|identity| identity.parse::<age::plugin::Identity>().is_ok())
}

fn reason_code(error: &Error) -> &'static str {
    match error {
        Error::Encryption(EncryptError::Age(age::EncryptError::Plugin(_))) => {
            "plugin_rejected_reply"
        }
        Error::Encryption(EncryptError::Age(age::EncryptError::PluginResolve(_))) => {
            "plugin_resolve_failed"
        }
        Error::Encryption(EncryptError::Age(age::EncryptError::MissingRecipients)) => {
            "missing_recipients"
        }
        Error::Encryption(EncryptError::Age(age::EncryptError::IncompatibleRecipients {
            ..
        })) => "incompatible_recipients",
        Error::Encryption(EncryptError::Age(age::EncryptError::InvalidRecipientLabels(_))) => {
            "invalid_recipient_labels"
        }
        Error::Encryption(EncryptError::Age(age::EncryptError::MixedRecipientAndPassphrase)) => {
            "mixed_recipient_and_passphrase"
        }
        Error::Encryption(EncryptError::BrokenPipe { .. }) => "broken_pipe",
        Error::Encryption(EncryptError::Io(e))
        | Error::Encryption(EncryptError::Age(age::EncryptError::Io(e))) => io_reason(e),
        Error::Encryption(_) => "encrypt_rejected",
        Error::Decryption(DecryptError::Age(age::DecryptError::Plugin(_))) => {
            "plugin_rejected_reply"
        }
        Error::Decryption(DecryptError::Age(age::DecryptError::PluginResolve(_))) => {
            "plugin_resolve_failed"
        }
        Error::Decryption(DecryptError::Age(age::DecryptError::InvalidHeader)) => "invalid_header",
        Error::Decryption(DecryptError::Age(age::DecryptError::NoMatchingKeys)) => {
            "no_matching_identity"
        }
        Error::Decryption(DecryptError::Age(age::DecryptError::DecryptionFailed)) => {
            "payload_authentication_failed"
        }
        Error::Decryption(DecryptError::Age(age::DecryptError::InvalidMac)) => {
            "header_authentication_failed"
        }
        Error::Decryption(DecryptError::Age(age::DecryptError::KeyDecryptionFailed)) => {
            "key_decryption_failed"
        }
        Error::Decryption(DecryptError::Age(age::DecryptError::ExcessiveWork { .. })) => {
            "excessive_work"
        }
        Error::Decryption(DecryptError::Age(age::DecryptError::Io(e)))
        | Error::Decryption(DecryptError::Io(e)) => io_reason(e),
        Error::Decryption(DecryptError::MissingIdentities { .. }) => "missing_identities",
        Error::Decryption(_) => "decrypt_rejected",
        Error::IdentityFlagAmbiguous => "identity_flag_ambiguous",
        Error::MixedEncryptAndDecrypt => "mixed_operations",
        Error::SameInputAndOutput(_) => "same_input_and_output",
    }
}

fn io_reason(error: &std::io::Error) -> &'static str {
    let message = error.to_string().to_ascii_lowercase();
    if message.contains("terminal done")
        || message.contains("invalid response")
        || message.contains("unexpected response")
        || (message.contains("plugin") && message.contains("died"))
    {
        "plugin_frame_incomplete"
    } else if message.contains("incomplete header") {
        "incomplete_header"
    } else {
        "output_or_input_io_error"
    }
}

fn plugin_error(error: &Error) -> bool {
    matches!(
        error,
        Error::Encryption(EncryptError::Age(age::EncryptError::Plugin(_)))
            | Error::Encryption(EncryptError::Age(age::EncryptError::PluginResolve(_)))
            | Error::Decryption(DecryptError::Age(age::DecryptError::Plugin(_)))
            | Error::Decryption(DecryptError::Age(age::DecryptError::PluginResolve(_)))
    )
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            character if (character as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", character as u32);
            }
            character => out.push(character),
        }
    }
    out.push('"');
    out
}

fn render(audit: &OperationAudit, result: &Result<(), Error>) -> String {
    let recorded_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let rejected = result.is_err();
    let plugin_failure = result.as_ref().err().map(plugin_error).unwrap_or(false);
    let plugin_session = audit.plugin_requested || plugin_failure;
    let terminal_frame_seen = plugin_session && !rejected;
    let reason = result
        .as_ref()
        .err()
        .map(reason_code)
        .unwrap_or("complete_frame_committed");
    let status = if rejected { "rejected" } else { "published" };
    let commit = if rejected {
        "withheld-until-terminal-frame"
    } else {
        "committed-after-terminal-frame"
    };
    let output_kind = match audit.output.as_deref() {
        None | Some("-") => "stdout",
        Some(_) => "file",
    };

    let mut out = String::new();
    out.push_str("{\n");
    let mut field = |name: &str, value: String, comma: bool| {
        let _ = write!(out, "  \"{name}\": {value}");
        if comma {
            out.push(',');
        }
        out.push('\n');
    };

    field("schema_version", "1".to_owned(), true);
    field(
        "task_id",
        json_escape("rage-t08-plugin-frame-transaction"),
        true,
    );
    field("event", json_escape("plugin_frame_transaction"), true);
    field(
        "risk",
        json_escape("partial recipient results published from an incomplete plugin reply"),
        true,
    );
    field("status", json_escape(status), true);
    field("reason_code", json_escape(reason), true);
    field("operation", json_escape(audit.operation), true);
    field("recorded_at", json_escape(&recorded_at), true);
    field("generation", json_escape(&audit.generation), true);
    field(
        "input",
        audit
            .input
            .as_deref()
            .map(json_escape)
            .unwrap_or_else(|| "null".to_owned()),
        true,
    );
    field(
        "output",
        audit
            .output
            .as_deref()
            .map(json_escape)
            .unwrap_or_else(|| "null".to_owned()),
        true,
    );
    field("output_kind", json_escape(output_kind), true);
    field(
        "plugin_session",
        if plugin_session { "true" } else { "false" }.to_owned(),
        true,
    );
    field("terminal_frame_required", "true".to_owned(), true);
    field(
        "terminal_frame_seen",
        if terminal_frame_seen { "true" } else { "false" }.to_owned(),
        true,
    );
    field("frame_commit", json_escape(commit), true);
    field(
        "partial_recipient_results_published",
        "false".to_owned(),
        true,
    );
    field(
        "commit_boundary",
        json_escape("a plugin reply is committed only after a complete terminal done frame"),
        true,
    );
    field("message", json_escape(""), false);
    out.push('}');
    out
}

/// Writes a best-effort receipt. Audit failure must not change the CLI result.
pub(crate) fn write_receipt(audit: &OperationAudit, result: &Result<(), Error>) {
    let json = render(audit, result);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let temporary = format!(".{RECEIPT_PATH}.{}.{nonce}.tmp", std::process::id());

    if write_atomic(&temporary, RECEIPT_PATH, &json).is_ok() {
        let mut line = json.clone();
        line.push('\n');
        if let Ok(mut file) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(RECEIPT_LOG_PATH)
        {
            let _ = file.write_all(line.as_bytes());
        }
    }
}

fn write_atomic(temporary: &str, destination: &str, contents: &str) -> std::io::Result<()> {
    {
        let mut file = fs::File::create(Path::new(temporary))?;
        file.write_all(contents.as_bytes())?;
        file.sync_all().ok();
    }
    fs::rename(temporary, destination)
}
