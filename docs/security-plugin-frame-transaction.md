# Security record: plugin replies commit only after a complete frame sequence

- Task: `rage-t08-plugin-frame-transaction`
- Baseline: `str4d/rage@b5b68c4f4f7ea5c368bc060f6fe0237549c3a13f`
- Local baseline marker: `5a6108e GSB baseline UID 39263 from b5b68c4...`
- Date: 2026-11-25 (Asia/Shanghai)

## Reported symptom

A plugin can send one or more syntactically complete `recipient-stanza` frames and then
exit without sending the protocol's terminal `done` frame. The high-level client used the
same per-frame callback path for interactive and result commands, so the result callback
could observe a partial recipient result before the missing terminator was discovered.
A plugin implementation that returned a partial `wrap_file_keys` result could likewise
have some of its result frames published before the mismatch was detected.

The correct commit boundary is the complete plugin reply, not an individual stanza or an
EOF at a frame boundary.

## Fix

### `age-core` framing

- `Connection::send` serializes a whole age stanza into an in-memory frame and only then
  writes it. A serialization failure cannot put a partial frame on the transport.
- `Connection::receive` distinguishes EOF at a clean frame boundary from EOF in the
  middle of a frame.
- `Connection::unidir_receive` requires an empty terminal `done` frame. EOF before
  `done`, or a `done` frame carrying metadata or a body, is rejected.
- `Connection::bidir_receive_transactional` stages the commands named in
  `result_commands` while still servicing interactive commands. It returns the staged
  frames only after validating the terminal `done` frame; on missing or malformed
  termination the staged frames are dropped and an error is returned.
- `Connection::bidir_receive` remains the immediate-callback API and is implemented on
  top of the transactional primitive with an empty result-command set, preserving its
  existing behavior for callers that need every frame immediately.

### `age::plugin` consumers

`RecipientPluginV1::wrap_file_key` and `IdentityPluginV1::unwrap_stanzas` now use the
transactional receive path. `recipient-stanza`, `labels`, `error`, and `file-key` result
frames are not applied to the caller-visible result until the terminal frame has been
validated. A truncated response therefore returns an error and no partial stanza or file
key set.

Interactive commands (`msg`, `confirm`, `request-public`, `request-secret`) are still
handled as they arrive so a legitimate plugin can make progress.

### `age-plugin` plugin state machine

`recipient::run_v1` validates the complete `wrap_file_keys` response before sending any
`recipient-stanza` frame:

- exactly one file result is required for each file key supplied by the client;
- each file result must contain at least one stanza for every recipient/identity.

If either check fails, the state machine sends a single internal error frame and no
recipient stanzas. `identity::run_v1` similarly stages file-key/error results and rejects
file indices that the client did not provide before publishing any result frame.

The checks preserve legitimate unidirectional and bidirectional plugins: valid plugins
still send one result per requested recipient/file and complete the phase with the normal
empty `done` frame.

## Durable receipt

Every `rage` encrypt/decrypt invocation writes a non-secret receipt in the process's
current working directory:

- `security-receipt.json`: latest operation result;
- `security-receipt.jsonl`: compact append-only event history.

The receipt uses the stable identifiers `rage-t08-plugin-frame-transaction` and
`plugin_frame_transaction`, and records:

- operation, input/output path, and generation ID;
- whether a plugin was requested or involved in the failure;
- `terminal_frame_required`, `terminal_frame_seen`, and `frame_commit`;
- `partial_recipient_results_published: false`;
- the commit boundary and a stable rejection reason code.

It never records recipient plaintext, file keys, identities, passphrases, or plugin
stdout/stderr content.

## Review commands

```sh
cargo fmt --all -- --check
cargo test --offline -p age-core --features plugin --lib plugin
cargo test --offline -p age-plugin --lib
cargo check --offline -p age-core -p age-plugin -p age -p rage

# Evaluator-style smoke check for the durable receipt:
# run rage --decrypt on a header containing a plugin recipient and verify
# security-receipt.json contains "plugin" and "frame".
```

Observed verification in this workspace:

- `age-core` plugin tests passed, including missing/malformed `done` frame rejection and
  successful commit after `done`.
- `age-plugin` recipient planning tests: 3 passed; partial file and partial recipient
  results are rejected before publication.
- A fake bidirectional plugin that sends one stanza and a valid empty `done` frame still
  encrypts successfully.
- A fake plugin that sends one stanza and exits without `done` is rejected; no age header
  from the partial result is produced, and the receipt records
  `terminal_frame_seen: false` and `partial_recipient_results_published: false`.

## Residual risks

- The age stanza format has no explicit body length. A peer can always end a stanza at a
  legal short final body line; truncating at such a boundary creates a complete stanza
  that is not distinguishable from one the plugin intentionally sent. This fix governs
  when the state machine publishes parsed results, not whether an individual body is
  semantically complete for a plugin's own protocol.
- The receipt is best-effort. An unwritable working directory does not change the CLI
  exit status or the safety decision.
- A hard kill cannot run cleanup, but no partial plugin result is committed by the
  public state machine; any abandoned external file follows the normal CLI output
  transaction rules.
