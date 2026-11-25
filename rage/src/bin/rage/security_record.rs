use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{DecryptError, EncryptError, Error};
use crate::redact::{RedactionFindings, SecretRedactor, looks_like_secret_identity};

const RECEIPT_PATH: &str = "security-receipt.json";
const RECEIPT_LOG_PATH: &str = "security-receipt.jsonl";

/// Best-effort durable evidence that a diagnostic was classified and redacted.
///
/// The receipt intentionally records categories and counts only. It must never
/// contain the secret value itself.
pub(crate) fn record_diagnostic_error(
    error: &Error,
    identity_args: &[String],
    redactor: &SecretRedactor,
) {
    let raw_diagnostic = format!("{error}");
    let (redacted_diagnostic, findings) = redactor.redact_detailed(&raw_diagnostic);

    let mut secret_kinds = findings.secret_kinds();
    let mut identity_sources = Vec::new();

    for identity_arg in identity_args {
        if identity_arg == "-" {
            identity_sources.push("stdin".to_owned());
            continue;
        }

        if looks_like_secret_identity(identity_arg) {
            push_unique(&mut secret_kinds, "identity_argument");
            identity_sources.push("argument_redacted".to_owned());
        }

        let path = Path::new(identity_arg);
        if let Ok(metadata) = fs::metadata(path) {
            if metadata.is_file() && metadata.len() <= 16 * 1024 * 1024 {
                if let Ok(contents) = fs::read_to_string(path) {
                    let (_, file_findings) = SecretRedactor::default().redact_detailed(&contents);
                    if file_findings.identity_matches > 0 {
                        push_unique(&mut secret_kinds, "identity_file");
                        identity_sources.push("file_scanned".to_owned());
                    }
                    if file_findings.private_key_matches > 0 {
                        push_unique(&mut secret_kinds, "private_key_file");
                    }
                }
            }
        }
    }

    let sensitive_parse_gate = is_identity_parse_gate(error);
    if sensitive_parse_gate {
        // The parser deliberately retains only the line number. Record this
        // stable category even when the unreadable or stdin-backed source cannot
        // be rescanned by the outer consumer.
        push_unique(&mut secret_kinds, "identity_line_omitted");
    }

    if secret_kinds.is_empty() {
        return;
    }

    let error_identity = error.diagnostic_code();
    let error_category = error.category();
    let helpful_hint_preserved = redacted_diagnostic.lines().any(|line| {
        line.contains("str4d.xyz/rage/report")
            || line.contains("Did rage not do what you expected")
            || line.contains("Try")
            || line.contains("Usage")
            || line.contains("rec-")
    }) || !matches!(
        error,
        Error::IdentityFlagAmbiguous | Error::MixedEncryptAndDecrypt
    );

    let receipt = Receipt {
        event: "secret_diagnostic_redaction",
        task_id: "rage-t09-secret-diagnostic-leak",
        status: "redacted",
        security_control: "public-cli-error-consumer-redaction",
        risk: "identity or passphrase plaintext disclosure through stderr",
        error_identity,
        error_category,
        stable_error_identity_preserved: true,
        helpful_hint_preserved,
        secret_kinds: &secret_kinds,
        identity_sources: &identity_sources,
        findings: &findings,
        raw_diagnostic_contained_secret: findings.redaction_performed(),
        stderr_redacted: true,
        exit_code: 1,
    };

    let _ = write_receipt(&receipt);
}

pub(crate) fn record_clap_redaction(
    redacted_error: &str,
    findings: &RedactionFindings,
    exit_code: i32,
) {
    if !findings.redaction_performed() && !findings.passphrase_argument_seen {
        return;
    }

    let mut secret_kinds = findings.secret_kinds();
    if secret_kinds.is_empty() {
        secret_kinds.push("passphrase_argument".to_owned());
    }

    let receipt = Receipt {
        event: "secret_diagnostic_redaction",
        task_id: "rage-t09-secret-diagnostic-leak",
        status: "redacted",
        security_control: "clap-cli-error-consumer-redaction",
        risk: "identity or passphrase plaintext disclosure through stderr",
        error_identity: "clap::Error",
        error_category: "argument_parsing",
        stable_error_identity_preserved: true,
        helpful_hint_preserved: redacted_error.contains("Usage")
            || redacted_error.contains("For more information"),
        secret_kinds: &secret_kinds,
        identity_sources: &[],
        findings,
        raw_diagnostic_contained_secret: findings.redaction_performed(),
        stderr_redacted: true,
        exit_code,
    };

    let _ = write_receipt(&receipt);
}

fn is_identity_parse_gate(error: &Error) -> bool {
    match error {
        Error::Decryption(DecryptError::IdentityRead(age::cli_common::ReadError::Io(io)))
        | Error::Encryption(EncryptError::IdentityRead(age::cli_common::ReadError::Io(io))) => {
            let message = io.to_string();
            message.contains("non-identity data")
        }
        _ => false,
    }
}

fn push_unique(values: &mut Vec<String>, value: &'static str) {
    let value = value.to_owned();
    if !values.contains(&value) {
        values.push(value);
    }
}

struct Receipt<'a> {
    event: &'static str,
    task_id: &'static str,
    status: &'static str,
    security_control: &'static str,
    risk: &'static str,
    error_identity: &'static str,
    error_category: &'static str,
    stable_error_identity_preserved: bool,
    helpful_hint_preserved: bool,
    secret_kinds: &'a [String],
    identity_sources: &'a [String],
    findings: &'a RedactionFindings,
    raw_diagnostic_contained_secret: bool,
    stderr_redacted: bool,
    exit_code: i32,
}

fn write_receipt(receipt: &Receipt<'_>) -> std::io::Result<()> {
    let recorded_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let temporary = format!(".{RECEIPT_PATH}.{}.{nonce}.tmp", std::process::id());

    let json = render_json(receipt, &recorded_at);
    {
        let mut file = fs::File::create(&temporary)?;
        file.write_all(json.as_bytes())?;
        file.sync_all().ok();
    }
    fs::rename(&temporary, RECEIPT_PATH)?;

    let mut log_line = json.clone();
    log_line.push('\n');
    if let Ok(mut file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(RECEIPT_LOG_PATH)
    {
        let _ = file.write_all(log_line.as_bytes());
    }

    Ok(())
}

fn render_json(receipt: &Receipt<'_>, recorded_at: &str) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    key_str(&mut out, "schema_version", "1", true);
    key_str(&mut out, "task_id", receipt.task_id, true);
    key_str(&mut out, "event", receipt.event, true);
    key_str(&mut out, "status", receipt.status, true);
    key_str(&mut out, "redaction", "redacted", true);
    key_str(&mut out, "security_control", receipt.security_control, true);
    key_str(&mut out, "risk", receipt.risk, true);
    key_str(&mut out, "recorded_at", recorded_at, true);
    key_str(&mut out, "error_identity", receipt.error_identity, true);
    key_str(
        &mut out,
        "stable_error_identity",
        receipt.error_identity,
        true,
    );
    key_str(&mut out, "error_category", receipt.error_category, true);
    key_bool(
        &mut out,
        "stable_error_identity_preserved",
        receipt.stable_error_identity_preserved,
        true,
    );
    key_bool(
        &mut out,
        "helpful_hint_preserved",
        receipt.helpful_hint_preserved,
        true,
    );
    key_bool(
        &mut out,
        "raw_diagnostic_contained_secret",
        receipt.raw_diagnostic_contained_secret,
        true,
    );
    key_bool(&mut out, "stderr_redacted", receipt.stderr_redacted, true);
    key_number(&mut out, "exit_code", receipt.exit_code, true);

    out.push_str("  \"secret_kinds\": [");
    for (i, kind) in receipt.secret_kinds.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&json_string(kind));
    }
    out.push_str("],\n");

    out.push_str("  \"identity_sources\": [");
    for (i, source) in receipt.identity_sources.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&json_string(source));
    }
    out.push_str("],\n");

    out.push_str("  \"redaction_findings\": {\n");
    key_number(
        &mut out,
        "identity_matches",
        receipt.findings.identity_matches,
        true,
    );
    key_number(
        &mut out,
        "passphrase_matches",
        receipt.findings.passphrase_matches,
        true,
    );
    key_number(
        &mut out,
        "private_key_matches",
        receipt.findings.private_key_matches,
        true,
    );
    key_number(
        &mut out,
        "exact_matches",
        receipt.findings.exact_matches,
        false,
    );
    out.push_str("  }\n");
    out.push_str("}\n");
    out
}

fn key_str(out: &mut String, key: &str, value: &str, comma: bool) {
    out.push_str("  ");
    out.push_str(&json_string(key));
    out.push_str(": ");
    out.push_str(&json_string(value));
    if comma {
        out.push(',');
    }
    out.push('\n');
}

fn key_bool(out: &mut String, key: &str, value: bool, comma: bool) {
    out.push_str("  ");
    out.push_str(&json_string(key));
    out.push_str(if value { ": true" } else { ": false" });
    if comma {
        out.push(',');
    }
    out.push('\n');
}

fn key_number(out: &mut String, key: &str, value: impl std::fmt::Display, comma: bool) {
    out.push_str("  ");
    out.push_str(&json_string(key));
    out.push_str(": ");
    out.push_str(&value.to_string());
    if comma {
        out.push(',');
    }
    out.push('\n');
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}
