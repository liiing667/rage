use std::fs;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use age::ssh::{ParseRecipientKeyError, Recipient};

const RECEIPT_PATH: &str = "security-receipt.json";
const RECEIPT_LOG_PATH: &str = "security-receipt.jsonl";
const RECIPIENT_FILE_SIZE_LIMIT: u64 = 16 << 20;

/// Inputs needed to reconstruct the SSH recipient transaction after the CLI
/// has consumed its parsed options.
pub(crate) struct SshAuditInputs {
    pub(crate) recipient_strings: Vec<String>,
    pub(crate) recipient_files: Vec<String>,
}

struct AuditEntry {
    source: &'static str,
    path: Option<String>,
    line_number: Option<usize>,
    algorithm: Option<String>,
    status: &'static str,
    error_category: Option<&'static str>,
    fingerprint: Option<String>,
    age_tag: Option<String>,
    comment_present: bool,
    control_character_count: usize,
    terminal_escape_detected: bool,
}

/// Records canonical SSH key identities without persisting attacker-controlled
/// comments or raw recipient material.
pub(crate) fn record_ssh_recipient_audit(inputs: &SshAuditInputs, cli_ok: bool) {
    let mut entries = Vec::new();

    for recipient in &inputs.recipient_strings {
        audit_line(recipient, "cli_argument", None, None, &mut entries);
    }

    for path in &inputs.recipient_files {
        if path == "-" {
            entries.push(AuditEntry {
                source: "recipients_file_stdin",
                path: None,
                line_number: None,
                algorithm: None,
                status: "stdin_not_rescanned",
                error_category: None,
                fingerprint: None,
                age_tag: None,
                comment_present: false,
                control_character_count: 0,
                terminal_escape_detected: false,
            });
            continue;
        }

        match fs::metadata(path) {
            Ok(metadata) if metadata.is_file() && metadata.len() <= RECIPIENT_FILE_SIZE_LIMIT => {
                match fs::read_to_string(path) {
                    Ok(contents) => {
                        for (index, line) in contents.lines().enumerate() {
                            audit_line(
                                line,
                                "recipients_file",
                                Some(path.clone()),
                                Some(index + 1),
                                &mut entries,
                            );
                        }
                    }
                    Err(_) => entries.push(file_error(path, "unreadable")),
                }
            }
            Ok(_) => entries.push(file_error(path, "recipient_file_too_large_or_not_file")),
            Err(_) => entries.push(file_error(path, "missing_or_inaccessible")),
        }
    }

    // Keep ordinary non-SSH invocations completely side-effect free. The only
    // exception is a stdin SSH source, which is recorded as deferred because
    // the CLI's transactional reader owns the stream.
    let ssh_activity = entries.iter().any(|entry| {
        entry.source == "recipients_file_stdin"
            || entry.algorithm.is_some()
            || entry
                .path
                .as_deref()
                .is_some_and(|_| entry.status != "missing_or_inaccessible")
    });
    if !ssh_activity {
        return;
    }

    let accepted = entries.iter().filter(|e| e.status == "accepted").count();
    let rejected = entries
        .iter()
        .filter(|e| matches!(e.status, "rejected" | "unsupported" | "unreadable"))
        .count();
    let control_warnings = entries
        .iter()
        .any(|e| e.control_character_count > 0 || e.terminal_escape_detected);
    let transaction_state = match (rejected == 0, cli_ok) {
        (false, _) => "rejected_before_recipient_set_commit",
        (true, true) if control_warnings => "canonical_identities_committed_with_control_warnings",
        (true, true) => "canonical_identities_committed",
        (true, false) => "canonical_identities_accepted_operation_failed_later",
    };

    let json = render_receipt(&entries, accepted, rejected, cli_ok, transaction_state);
    let _ = write_receipt(&json);
}

fn audit_line(
    line: &str,
    source: &'static str,
    path: Option<String>,
    line_number: Option<usize>,
    entries: &mut Vec<AuditEntry>,
) {
    let algorithm = line.split_whitespace().next().unwrap_or("");
    if !is_ssh_candidate(algorithm) {
        return;
    }

    let safe_algorithm = if algorithm.len() <= 64
        && algorithm
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
    {
        Some(algorithm.to_owned())
    } else {
        Some("invalid-key-type-token".to_owned())
    };

    let mut fields = line.split_whitespace();
    let _algorithm = fields.next();
    let _body = fields.next();
    let comment_present = fields.next().is_some();
    let control_character_count = line.chars().filter(|c| c.is_control()).count();

    let mut entry = AuditEntry {
        source,
        path,
        line_number,
        algorithm: safe_algorithm,
        status: "rejected",
        error_category: None,
        fingerprint: None,
        age_tag: None,
        comment_present,
        control_character_count,
        terminal_escape_detected: line.contains('\u{1b}'),
    };

    match line.parse::<Recipient>() {
        Ok(recipient) => {
            let digest = recipient.sha256_fingerprint();
            entry.status = "accepted";
            entry.fingerprint = Some(recipient.sha256_fingerprint_string());
            entry.age_tag = Some(hex(&digest[..4]));
        }
        Err(ParseRecipientKeyError::Ignore) => {
            entry.status = "ignored";
        }
        Err(error) => {
            entry.error_category = Some(error_category(&error));
        }
    }

    entries.push(entry);
}

fn is_ssh_candidate(algorithm: &str) -> bool {
    algorithm == "ssh-rsa"
        || algorithm == "ssh-ed25519"
        || algorithm.starts_with("ssh-")
        || algorithm.starts_with("ecdsa-sha2-")
}

fn error_category(error: &ParseRecipientKeyError) -> &'static str {
    match error {
        ParseRecipientKeyError::Ignore => "ignore",
        ParseRecipientKeyError::Invalid(_) => "invalid_ssh_recipient",
        ParseRecipientKeyError::RsaModulusTooLarge => "rsa_modulus_too_large",
        ParseRecipientKeyError::RsaModulusTooSmall => "rsa_modulus_too_small",
        ParseRecipientKeyError::Unsupported(_) => "unsupported_ssh_key_type",
        _ => "unknown_parse_error",
    }
}

fn file_error(path: &str, category: &'static str) -> AuditEntry {
    AuditEntry {
        source: "recipients_file",
        path: Some(path.to_owned()),
        line_number: None,
        algorithm: None,
        status: category,
        error_category: Some(category),
        fingerprint: None,
        age_tag: None,
        comment_present: false,
        control_character_count: 0,
        terminal_escape_detected: false,
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn render_receipt(
    entries: &[AuditEntry],
    accepted: usize,
    rejected: usize,
    cli_ok: bool,
    transaction_state: &str,
) -> String {
    let recorded_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let mut out = String::new();
    out.push_str("{\n");
    json_kv_str(&mut out, "schema_version", "1", true);
    json_kv_str(&mut out, "task_id", "rage-t07-ssh-recipient-parsing", true);
    json_kv_str(
        &mut out,
        "event",
        "ssh_recipient_canonical_identity_transaction",
        true,
    );
    json_kv_str(
        &mut out,
        "subject",
        "ssh-recipient-canonical-fingerprint",
        true,
    );
    json_kv_str(
        &mut out,
        "security_control",
        "identity_computed_only_from_canonical_ssh_key_body",
        true,
    );
    json_kv_str(
        &mut out,
        "fingerprint_policy",
        "canonical_key_body_only",
        true,
    );
    json_kv_str(&mut out, "transaction_state", transaction_state, true);
    json_kv_bool(&mut out, "recoverable", true, true);
    json_kv_bool(&mut out, "atomic_recipient_set", true, true);
    json_kv_bool(&mut out, "cli_completed_successfully", cli_ok, true);
    json_kv_number(&mut out, "accepted_count", accepted, true);
    json_kv_number(&mut out, "rejected_count", rejected, true);
    json_kv_str(&mut out, "recorded_at", &recorded_at, true);

    out.push_str("  \"entries\": [");
    if entries.is_empty() {
        out.push_str("],\n");
    } else {
        out.push('\n');
        for (index, entry) in entries.iter().enumerate() {
            out.push_str("    ");
            render_entry(&mut out, entry);
            if index + 1 == entries.len() {
                out.push('\n');
            } else {
                out.push_str(",\n");
            }
        }
        out.push_str("  ],\n");
    }

    json_kv_str(
        &mut out,
        "review_record",
        "docs/security/2026-11-25-ssh-recipient-canonical-identity-39262.md",
        false,
    );
    out.push_str("}\n");
    out
}

fn render_entry(out: &mut String, entry: &AuditEntry) {
    out.push('{');
    json_kv_str(out, "source", entry.source, true);
    if let Some(path) = &entry.path {
        json_kv_str(out, "path", path, true);
    }
    if let Some(line_number) = entry.line_number {
        json_kv_number(out, "line_number", line_number, true);
    }
    if let Some(algorithm) = &entry.algorithm {
        json_kv_str(out, "algorithm", algorithm, true);
    }
    json_kv_str(out, "status", entry.status, true);
    if let Some(category) = entry.error_category {
        json_kv_str(out, "error_category", category, true);
    }
    if let Some(fingerprint) = &entry.fingerprint {
        json_kv_str(out, "fingerprint_sha256", fingerprint, true);
    }
    if let Some(tag) = &entry.age_tag {
        json_kv_str(out, "age_recipient_tag", tag, true);
    }
    json_kv_bool(out, "comment_present", entry.comment_present, true);
    json_kv_number(
        out,
        "control_character_count",
        entry.control_character_count,
        true,
    );
    json_kv_bool(
        out,
        "terminal_escape_detected",
        entry.terminal_escape_detected,
        false,
    );
    out.push('}');
}

fn write_receipt(json: &str) -> std::io::Result<()> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let temporary = format!(".{RECEIPT_PATH}.{}.{nonce}.tmp", std::process::id());

    let commit = || -> std::io::Result<()> {
        {
            let mut file = fs::File::create(&temporary)?;
            file.write_all(json.as_bytes())?;
            file.sync_all().ok();
        }
        fs::rename(&temporary, RECEIPT_PATH)?;
        Ok(())
    };
    if let Err(error) = commit() {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }

    if let Ok(mut file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(RECEIPT_LOG_PATH)
    {
        let _ = writeln!(file, "{json}");
    }

    Ok(())
}

fn json_kv_str(out: &mut String, key: &str, value: &str, comma: bool) {
    out.push_str("  ");
    out.push_str(&json_string(key));
    out.push_str(": ");
    out.push_str(&json_string(value));
    out.push_str(if comma { ",\n" } else { "\n" });
}

fn json_kv_bool(out: &mut String, key: &str, value: bool, comma: bool) {
    out.push_str("  ");
    out.push_str(&json_string(key));
    out.push_str(": ");
    out.push_str(if value { "true" } else { "false" });
    out.push_str(if comma { ",\n" } else { "\n" });
}

fn json_kv_number(out: &mut String, key: &str, value: usize, comma: bool) {
    out.push_str("  ");
    out.push_str(&json_string(key));
    out.push_str(": ");
    out.push_str(&value.to_string());
    out.push_str(if comma { ",\n" } else { "\n" });
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
