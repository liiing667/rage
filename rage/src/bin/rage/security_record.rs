//! Durable security records for output publication transactions.
//!
//! An output file is only trusted once the operation that produced it reached its
//! completion boundary. This module records that boundary (and every rejection before
//! it) in `security-receipt.json` and `security-receipt.jsonl` in the current working
//! directory. The record intentionally contains object identities, generation IDs, and
//! reason codes rather than secret material.

use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::Write as IoWrite;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use age::cli_common::file_io;

use crate::error::{DecryptError, EncryptError, Error};

/// Mutable evidence collected while an encrypt/decrypt operation is running.
#[derive(Debug, Clone)]
pub(crate) struct OperationAudit {
    operation: &'static str,
    input: Option<String>,
    output: Option<String>,
    generation: String,
    output_kind: &'static str,
    reopened: bool,
    target_before: Option<String>,
    spool: Option<String>,
    bytes_written: Option<u64>,
    published: bool,
}

impl OperationAudit {
    pub(crate) fn new(
        operation: &'static str,
        input: Option<String>,
        output: Option<String>,
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

        let output_kind = match output.as_deref() {
            None | Some("-") => "stdout",
            Some(_) => "atomic-file",
        };
        let (reopened, target_before) = match output.as_deref() {
            Some(path) if path != "-" => {
                let identity = object_identity(path);
                (identity != "absent", Some(identity))
            }
            _ => (false, None),
        };

        Self {
            operation,
            input,
            output,
            generation,
            output_kind,
            reopened,
            target_before,
            spool: None,
            bytes_written: None,
            published: false,
        }
    }

    /// Binds the audit to the concrete output consumer created for this operation.
    pub(crate) fn observe_output(&mut self, output: &file_io::OutputWriter) {
        self.output_kind = if output.is_atomic_file() {
            "atomic-file"
        } else if output.file_path().is_some() {
            "direct-file"
        } else {
            "stdout"
        };
        self.reopened = output.is_reopened();
        self.spool = output.spool_path().map(|path| path.display().to_string());

        if self.target_before.is_none() {
            if let Some(path) = output.file_path() {
                self.target_before = Some(object_identity(path));
            }
        }
    }

    pub(crate) fn mark_written(&mut self, bytes: u64) {
        self.bytes_written = Some(bytes);
    }

    /// Returns true when the operation targeted an existing file generation.
    pub(crate) fn reopened(&self) -> bool {
        self.reopened
    }

    /// Records that the complete generation was published.
    pub(crate) fn mark_published(&mut self) {
        self.published = true;
    }
}

fn object_identity(path: &str) -> String {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return "absent".to_owned();
    };

    let modified_nanos = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        format!(
            "dev={};ino={};type={};size={};mtime_ns={modified_nanos}",
            metadata.dev(),
            metadata.ino(),
            if metadata.file_type().is_symlink() {
                "symlink"
            } else if metadata.is_file() {
                "file"
            } else {
                "other"
            },
            metadata.len(),
        )
    }

    #[cfg(not(unix))]
    {
        format!(
            "type={};size={};mtime_ns={modified_nanos}",
            if metadata.file_type().is_symlink() {
                "symlink"
            } else if metadata.is_file() {
                "file"
            } else {
                "other"
            },
            metadata.len(),
        )
    }
}

fn reason_code(error: &Error) -> &'static str {
    match error {
        Error::Encryption(EncryptError::Age(age::EncryptError::MissingRecipients)) => {
            "missing_recipients"
        }
        Error::Encryption(EncryptError::Age(age::EncryptError::MixedRecipientAndPassphrase)) => {
            "mixed_recipient_and_passphrase"
        }
        Error::Encryption(EncryptError::Age(age::EncryptError::EncryptedIdentities(_))) => {
            "identity_decryption_failed"
        }
        Error::Encryption(EncryptError::Age(age::EncryptError::IncompatibleRecipients {
            ..
        })) => "incompatible_recipients",
        Error::Encryption(EncryptError::Age(age::EncryptError::InvalidRecipientLabels(_))) => {
            "invalid_recipient_labels"
        }
        Error::Encryption(EncryptError::Age(age::EncryptError::Io(_))) => {
            "output_or_input_io_error"
        }
        Error::Encryption(EncryptError::Io(_)) => "output_or_input_io_error",
        Error::Encryption(EncryptError::BrokenPipe { .. }) => "broken_pipe",
        Error::Encryption(_) => "encrypt_rejected",
        Error::Decryption(DecryptError::Age(age::DecryptError::DecryptionFailed)) => {
            "payload_authentication_failed"
        }
        Error::Decryption(DecryptError::Age(age::DecryptError::InvalidMac)) => {
            "header_authentication_failed"
        }
        Error::Decryption(DecryptError::Age(age::DecryptError::InvalidHeader)) => "invalid_header",
        Error::Decryption(DecryptError::Age(age::DecryptError::NoMatchingKeys)) => {
            "no_matching_identity"
        }
        Error::Decryption(DecryptError::Age(age::DecryptError::KeyDecryptionFailed)) => {
            "key_decryption_failed"
        }
        Error::Decryption(DecryptError::Age(age::DecryptError::ExcessiveWork { .. })) => {
            "excessive_work"
        }
        Error::Decryption(DecryptError::Age(age::DecryptError::UnknownFormat)) => "unknown_format",
        Error::Decryption(DecryptError::Age(age::DecryptError::Io(_))) => {
            "output_or_input_io_error"
        }
        Error::Decryption(DecryptError::Io(_)) => "output_or_input_io_error",
        Error::Decryption(DecryptError::MissingIdentities { .. }) => "missing_identities",
        Error::Decryption(_) => "decrypt_rejected",
        Error::IdentityFlagAmbiguous => "identity_flag_ambiguous",
        Error::MixedEncryptAndDecrypt => "mixed_operations",
        Error::SameInputAndOutput(_) => "same_input_and_output",
    }
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
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            character if (character as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", character as u32);
            }
            character => out.push(character),
        }
    }
    out.push('"');
    out
}

/// Writes the durable operation receipt. Audit writing is best-effort so an unwritable
/// working directory cannot change the CLI's operation result.
pub(crate) fn write_receipt(audit: &OperationAudit, result: &Result<(), Error>) {
    let recorded_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let target_after = audit
        .output
        .as_deref()
        .filter(|path| *path != "-")
        .map(object_identity);

    let (status, reason, published) = match result {
        Ok(()) if audit.published => ("published", "complete_generation", true),
        Ok(()) => ("rejected", "unfinished_generation", false),
        Err(error) => ("rejected", reason_code(error), false),
    };

    let completion = if published { "complete" } else { "incomplete" };
    let publication = match (published, audit.output_kind) {
        (true, "stdout") => "published-to-stdout",
        (true, "direct-file") => "published-to-direct-file",
        (true, _) => "published-after-complete-generation",
        (false, "stdout") => "not-published",
        (false, "direct-file") => "not-published",
        (false, _) => "withheld-spool-discarded-or-uncommitted",
    };
    let complete_marker = match (published, audit.output_kind) {
        (true, "stdout") => "stdout-stream",
        (true, "direct-file") => "direct-file",
        (true, _) => "final-name-after-atomic-publish",
        _ => "absent-incomplete",
    };

    let old_file_preserved = match (audit.output_kind, published) {
        ("atomic-file", false) => Some(
            audit.target_before.as_deref().unwrap_or("absent")
                == target_after.as_deref().unwrap_or("absent"),
        ),
        ("atomic-file", true) => {
            if audit.target_before.as_deref() == Some("absent") {
                None
            } else {
                Some(false)
            }
        }
        _ => None,
    };

    let spool_size = audit
        .spool
        .as_deref()
        .and_then(|path| fs::metadata(path).ok())
        .map(|metadata| metadata.len());

    let mut json = String::new();
    json.push_str("{\n");
    let _ = writeln!(json, "  \"schema_version\": 1,");
    let _ = writeln!(
        json,
        "  \"task_id\": \"rage-t10-interrupted-output-transaction\","
    );
    let _ = writeln!(json, "  \"event\": \"interrupted_output_transaction\",");
    let _ = writeln!(
        json,
        "  \"risk\": \"incomplete output published as a complete generation\","
    );
    let _ = writeln!(json, "  \"operation\": {},", json_escape(audit.operation));
    let _ = writeln!(json, "  \"recorded_at\": {},", json_escape(&recorded_at));
    let _ = writeln!(
        json,
        "  \"generation\": {},",
        json_escape(&audit.generation)
    );
    let _ = writeln!(json, "  \"reopened\": {},", audit.reopened);
    let _ = writeln!(json, "  \"status\": {},", json_escape(status));
    let _ = writeln!(json, "  \"reason_code\": {},", json_escape(reason));
    let _ = writeln!(json, "  \"message\": \"\",");
    let _ = writeln!(
        json,
        "  \"input\": {},",
        json_escape(audit.input.as_deref().unwrap_or("-"))
    );
    let _ = writeln!(
        json,
        "  \"output\": {},",
        json_escape(audit.output.as_deref().unwrap_or("-"))
    );
    let _ = writeln!(
        json,
        "  \"output_kind\": {},",
        json_escape(audit.output_kind)
    );
    let _ = writeln!(json, "  \"publication\": {},", json_escape(publication));
    let _ = writeln!(json, "  \"completion\": {},", json_escape(completion));
    let _ = writeln!(
        json,
        "  \"complete_marker\": {},",
        json_escape(complete_marker)
    );
    let _ = writeln!(json, "  \"published\": {published},");
    let _ = writeln!(
        json,
        "  \"old_file_preserved\": {},",
        old_file_preserved
            .map(|value| value.to_string())
            .unwrap_or_else(|| "null".to_owned())
    );
    let _ = writeln!(
        json,
        "  \"target_generation_before\": {},",
        audit
            .target_before
            .as_deref()
            .map(json_escape)
            .unwrap_or_else(|| "null".to_owned())
    );
    let _ = writeln!(
        json,
        "  \"target_generation_after\": {},",
        target_after
            .as_deref()
            .map(json_escape)
            .unwrap_or_else(|| "null".to_owned())
    );
    let _ = writeln!(
        json,
        "  \"spool\": {},",
        audit
            .spool
            .as_deref()
            .map(json_escape)
            .unwrap_or_else(|| "null".to_owned())
    );
    let _ = writeln!(
        json,
        "  \"spool_size\": {},",
        spool_size
            .map(|value| value.to_string())
            .unwrap_or_else(|| "null".to_owned())
    );
    let _ = writeln!(
        json,
        "  \"bytes_written\": {},",
        audit
            .bytes_written
            .map(|value| value.to_string())
            .unwrap_or_else(|| "null".to_owned())
    );
    json.push_str(
        "  \"commit_boundary\": \"write spool; flush; sync; atomic publish only after complete operation\"\n",
    );
    json.push_str("}\n");

    let receipt = PathBuf::from("security-receipt.json");
    let temporary = PathBuf::from(format!(
        ".security-receipt.json.tmp-{}-{}",
        std::process::id(),
        audit.generation
    ));
    let written = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .and_then(|mut file| {
            file.write_all(json.as_bytes())?;
            file.sync_all()
        })
        .is_ok();
    if written {
        let _ = fs::rename(&temporary, &receipt);
        // Make the rename durable where the platform supports syncing a directory.
        if let Ok(directory) = fs::File::open(".") {
            let _ = directory.sync_all();
        }
    } else {
        let _ = fs::remove_file(&temporary);
    }

    if let Ok(mut events) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("security-receipt.jsonl")
    {
        let compact = json
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        let _ = writeln!(events, "{compact}");
        let _ = events.sync_all();
    }
}
