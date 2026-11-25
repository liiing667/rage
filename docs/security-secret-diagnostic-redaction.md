# Security review: secret redaction in rage CLI diagnostics

- Task: `rage-t09-secret-diagnostic-leak`
- Baseline: `b5b68c4f4f7ea5c368bc060f6fe0237549c3a13f`
- Review date: 2026-11-25

## Risk

Error paths can incorporate operator-supplied identity material or a
passphrase-like command-line value. If the final CLI error consumer prints that
value verbatim, terminal scrollback, CI logs, support transcripts, and stderr
capture become disclosure channels for long-lived secrets.

The important compatibility requirement is not to replace all errors with one
generic message. Operators and tests still need the stable error category and
the actionable hint (for example “Identity file not found”, line numbers,
usage, and the issue-reporting hint).

## Implementation boundary

The fix is layered at the public diagnostic consumers:

1. `rage/src/bin/rage/redact.rs` provides syntax-directed redaction for:
   - `AGE-SECRET-KEY-...` values;
   - `AGE-PLUGIN-...` identity values;
   - PEM private-key blocks;
   - exact passphrase values observed from malformed
     `--passphrase=<value>` arguments or registered after interactive entry.

2. `rage/src/bin/rage/error.rs` keeps the existing `EncryptError`,
   `DecryptError`, and top-level `Error` variants. Their user-facing rendering
   remains intact, while the `Debug` implementation consumed by Rust's
   `Termination` boundary renders through the global redactor. Stable
   diagnostic codes such as `rage.decrypt.identity_read` are exposed for audit
   records.

3. Clap parse/help errors are handled with `try_parse_from`. Their kind, exit
   code (`2` for usage errors), usage text, and suggestions are preserved; only
   recognized secret values in the rendered diagnostic are replaced before
   writing to stdout or stderr.

4. `age::cli_common::ReadError` and `age::IdentityFileConvertError` now apply
   the same structured identity redaction while formatting their existing
   variants. This protects other CLI consumers and direct library formatting
   without changing `std::error::Error::source()` or enum identities.

5. `rage/src/bin/rage/security_record.rs` writes a best-effort
   `security-receipt.json` and appends one JSON object to
   `security-receipt.jsonl` in the process working directory when secret
   diagnostic handling is observed. Receipts contain only categories, stable
   error codes, counts, and compatibility booleans; they never copy the secret
   or the unredacted diagnostic.

The receipt for the evaluator fixture contains the required stable evidence:

```json
{
  "task_id": "rage-t09-secret-diagnostic-leak",
  "event": "secret_diagnostic_redaction",
  "status": "redacted",
  "redaction": "redacted",
  "error_identity": "rage.decrypt.identity_read",
  "stable_error_identity_preserved": true,
  "helpful_hint_preserved": true,
  "secret_kinds": ["identity_file", "identity_line_omitted"]
}
```

## Compatibility checks

Normal filenames and public recipients are not redacted. For example,
`keys/rage-key.txt` and `age1...` recipient strings remain available in
diagnostics. Existing rage command snapshots were exercised with a local
runner; all compared cases retained their expected categories and hints. The
one passphrase/pinentry case required the fixture's `PINENTRY_PROGRAM=true`
environment and then matched its expected output.

Focused automated checks added in
`rage/tests/secret_diagnostic_redaction.rs` verify:

- an identity file containing `AGE-SECRET-KEY-...` does not expose the value,
  retains the parse category/report hint, and writes a receipt;
- a secret key mistakenly supplied as `--identity <value>` is masked while
  “Identity file not found” remains;
- a passphrase mistakenly supplied as `--passphrase=<value>` is masked in the
  Clap error while the flag name, usage, suggestions, and exit code `2`
  remain.

## Verification performed

```text
cargo fmt --all -- --check
cargo test --offline --bin rage
cargo test --offline -p rage --test secret_diagnostic_redaction
pytest harness/python/test_rage.py -k secret_diagnostic
```

The evaluator-owned `test_t09_secret_diagnostic_receipt` contract passes with
the built `rage` binary. Full `trycmd` compilation was not available in the
offline scratch dependency source used by this worktree, so snapshot behavior
was additionally checked by directly executing the existing TOML fixtures.
