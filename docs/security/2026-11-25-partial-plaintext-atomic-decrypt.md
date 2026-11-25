# Security record: partial plaintext publication during decrypt

- Task: `rage-t02-partial-plaintext-publish`
- Baseline: `str4d/rage@b5b68c4f4f7ea5c368bc060f6fe0237549c3a13f`
- Local baseline marker: `b7a08a1 GSB baseline UID 39257 from b5b68c4...`
- Date: 2026-11-25 (Asia/Shanghai)

## Observed failure

A multi-chunk age ciphertext was generated locally, its final STREAM tag byte was
flipped, and `rage --decrypt --output out.bin tampered.age` was run against an
existing `out.bin`.

At the vulnerable baseline:

- rage exited non-zero with `Error: decryption error`;
- the old `out.bin` was already truncated/replaced;
- the file contained the authenticated prefix that had been streamed before the
  final chunk authentication failure.

In one 200,000-byte plaintext reproduction, the failed output contained
196,608 bytes of partial plaintext. This is the unsafe publication boundary:
earlier STREAM chunks are individually authenticated, but the complete message
has not passed its final authentication/commit boundary.

## Fix and publication boundary

### File output

`age::cli_common::file_io::AtomicFile` now provides a commit-only file sink:

1. Create a hidden `. <name>.rage-spool-<pid>-<counter>.tmp` file in the same
   directory as the requested output with `O_CREAT | O_EXCL` and mode `0600`.
2. Stream all decrypted bytes into that spool. Large files use the normal
   `io::copy` path and are not buffered in memory.
3. `io::copy` must complete successfully. The age `StreamReader` reports EOF
   only after the final authenticated chunk has been accepted.
4. Flush, preserve an existing destination's permissions (or calculate the
   requested new-file mode under the process umask), and `sync_all`.
5. Atomically `rename(2)` the spool over the destination. Rename is the only
   publication operation.
6. On copy, authentication, sync, or commit failure, `abort()`/`Drop` unlinks
   the spool without renaming it. The previous destination remains intact.

A successful decrypt still overwrites an existing output path. Existing file
permissions are preserved; new files retain the usual `0666 & ~umask` mode.

### Standard output

`TemporarySpool` withholds stdout as well. rage streams the plaintext to a
private disk-backed spool, completes authentication, rewinds it, and only then
copies it to the stdout writer. This keeps stdout safe for large inputs without
requiring the complete plaintext to fit in memory.

Shell-managed redirection such as `rage --decrypt input > out` cannot be made
atomic by rage because the shell opens/truncates `out` before rage starts.
Callers that need old-file preservation must use `rage --output out` (or their
own temp-file-and-rename wrapper).

### Public library API

`age::decrypt` already returns `Result<Vec<u8>, DecryptError>` and performs
`read_to_end` before returning `Ok`; therefore an authentication failure does
not expose a partial `Vec<u8>`. A multi-chunk regression test was added to
`age/src/simple.rs`.

## Durable security receipt

The rage CLI writes a non-secret receipt in the process's current working
directory:

- `security-receipt.json`: latest result as a JSON object;
- `security-receipt.jsonl`: compact append-only event history.

The receipt contains the tokens `partial` and `plaintext` in the stable event
identity `partial_plaintext_commit_gate` / risk
`partial plaintext publication ...`, plus:

- input/output paths and output kind;
- stable failure reason code;
- generation ID;
- target object identity before/after (`dev`, `ino`, type, size, mtime);
- spool path and copied byte count;
- `authentication_complete`, `published`, failure-only `old_file_preserved`,
  and success-only `old_file_replaced` fields.

It never records plaintext, identity contents, passphrases, or secret keys.
Receipt writing is best-effort so an unwritable audit directory does not alter
the decrypt exit status or normal output contract.

## Reproduction / review commands

```sh
cargo fmt --all -- --check
cargo clippy --offline --bin rage --test partial_plaintext_atomic -- -D warnings
cargo test --offline --test partial_plaintext_atomic

# Evaluator contract from the task authoring record:
pytest -q harness/python/test_rage.py -k t02
```

A direct black-box review can:

1. Generate an x25519 identity and encrypt a >192 KiB plaintext.
2. Copy a known old generation into `out.bin`.
3. Flip the last ciphertext tag byte.
4. Run `rage --decrypt --identity key.txt --output out.bin tampered.age`.
5. Assert non-zero exit, `out.bin` byte-for-byte equals the old generation, no
   spool path remains, and `security-receipt.json` records
   `"published": false` and `"old_file_preserved": true`.
6. Re-run with the untampered ciphertext and assert exact plaintext and normal
   overwrite behavior.

## Verification performed in this workspace

- Added `rage/tests/partial_plaintext_atomic.rs`; it passes:
  - failed multi-chunk authentication preserves the old output;
  - failed stdout publishes zero bytes;
  - receipt contains `partial`, `plaintext`, `"published": false`, and
    `"old_file_preserved": true`;
  - spool cleanup;
  - valid 200,000-byte multi-chunk file decrypts exactly;
  - valid stdout decrypts exactly;
  - a subsequent smaller valid plaintext overwrites the existing output.
- The task-authoring Python contract was run against the built workspace binary
  with its hard-coded `RAGE` path redirected: `1 passed, 9 deselected` for
  `-k t02`.
- A manual 20 MiB + 123-byte file check passed: tampered final tag preserved
  the old file; valid file and valid stdout matched byte-for-byte.
- Permission checks passed: an existing `0600` output stayed `0600` after
  replacement, while a new output received `0644` under umask `022`.
- `cargo clippy --bin rage --test partial_plaintext_atomic -- -D warnings`
  passed.

## Residual operational note

A hard process kill or power loss after spool creation but before commit can
leave a hidden `.rage-*-spool-*.tmp` file. Such a file is created `0600`, is
never renamed unless complete authentication and `finish` succeed, and is
removed by normal error/Drop cleanup. It is not recovered as an output
generation by later rage invocations.
