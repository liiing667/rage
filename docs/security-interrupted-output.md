# Interrupted output transactions

## Reported issue

`rage` previously wrote file output in place. If encryption or decryption was interrupted
(for example by `SIGKILL`, a crash, or a transient I/O error), the destination path could
contain a prefix of the new generation. Downstream consumers had no way to tell that
prefix apart from a complete ciphertext or plaintext file.

## Security guarantee

For file destinations, `rage` now publishes a new generation only after the complete
operation has succeeded:

1. Output bytes are written to a hidden spool file in the destination directory.
2. The spool is flushed and `sync_all`-ed.
3. The spool is atomically published under the destination name (rename for an explicit
   overwrite, hard-link-without-replace for `rage-keygen`).
4. The parent directory is synced on Unix.

If the operation fails or the process exits before step 3, the destination is not
replaced. The previous complete generation remains readable. If there was no previous
generation, the destination remains absent.

The spool name has the form:

```text
.<destination>.rage-spool-<pid>-<counter>.tmp
```

That name is the durable **incomplete** marker. It is deliberately distinct from the
final destination name, which is the **complete** marker: a file is a committed output
only under its final name.

When a later operation targets the same destination, `rage` best-effort removes spools
whose recorded PID is no longer alive. A spool belonging to a live concurrent writer is
never touched.

## Consumer behavior

Both public file consumers in `age::cli_common::file_io` reject spool paths:

- `InputReader` refuses to reopen one as input.
- `OutputWriter` refuses to reopen one as an output destination.

This keeps an abandoned transaction from being consumed or extended on a later run.
Completed files remain ordinary age files and stay interoperable. Non-regular
destinations such as `/dev/null`, FIFOs, and `/dev/stdout` are written directly because
atomically replacing them with a regular file would change their meaning.

Standard output is intentionally unchanged: it is a stream, not a reopened file, and is
flushed without a spool or completion marker.

## Reviewable receipt

A `rage` encrypt/decrypt invocation that reopens an existing output generation, or that
is rejected, writes `security-receipt.json` and appends one compact JSON event to
`security-receipt.jsonl` in the current working directory. The record is written for both
success and failure, including validation failures before an output file is touched.

Important fields:

| Field | Meaning |
| --- | --- |
| `operation` | `encrypt` or `decrypt` |
| `generation` | unique ID of this operation |
| `reopened` | whether the destination existed when the operation started |
| `status` | `published` or `rejected` |
| `reason_code` | stable machine-readable rejection reason |
| `publication` | whether output was published, withheld, or sent to stdout |
| `completion` | `complete` or `incomplete` |
| `complete_marker` | how completion is represented |
| `target_generation_before` / `target_generation_after` | object identity (`dev`, `ino`, type, size, mtime) before and after |
| `old_file_preserved` | whether a rejected operation left the previous generation unchanged |
| `spool` / `spool_size` | incomplete transaction artifact, if one was created |
| `bytes_written` | bytes copied from the source |
| `commit_boundary` | the publication rule applied |

The receipt contains paths and object identities only; it does not include plaintext,
keys, passphrases, or other secret material.

## Residual risks

- A process killed with `SIGKILL` cannot run destructors, so a spool file may remain. It
  is never published, is clearly named, and is rejected by both file consumers.
- A partial file created by an older `rage` version before this change cannot be
  distinguished from an intentionally truncated plaintext file. Replacing that path with
  a new successful generation removes it; a failed run leaves it untouched.
- Standard output is a stream: a consumer of a pipe may still observe a prefix if the
  process is interrupted. This is inherent to streaming and is outside the file
  transaction guarantee.
