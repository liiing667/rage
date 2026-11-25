# Encrypted identity recipient/subject binding review（可复核安全记录）

本文件是 UID 39260 的安全处理记录，配套回归测试为
[`age/tests/identity_binding.rs`](../age/tests/identity_binding.rs)，机器可读样例见
[`docs/security/encrypted-identity-binding-record.json`](./security/encrypted-identity-binding-record.json)。

- Baseline: [`str4d/rage@b5b68c4f4f7ea5c368bc060f6fe0237549c3a13f`](https://github.com/str4d/rage/commit/b5b68c4f4f7ea5c368bc060f6fe0237549c3a13f)
- Local baseline commit: `65338fc` (`GSB baseline UID 39260`)
- Scope: public `age::encrypted::Identity` consumer and the `IdentityFile` parser used after passphrase decryption.

## Reproduced failure

A generated identity file contains a public recipient comment:

```text
# created: 2026-11-25T08:27:08+08:00
# public key: age1snajvqhy2epvu3qks9ayxwaenfsq2ckp7s8nreawwvw8vckgjp5sy3grdp
AGE-SECRET-KEY-...
```

Replacing only the `# public key:` comment with another valid recipient leaves the
secret key unchanged. Before this patch:

- `rage-keygen -y mismatch.key` derived and printed the **actual** recipient.
- ciphertext encrypted to that actual recipient decrypted successfully with the file.
- `rage -d -i mismatch.key ciphertext` exited `0`; the conflicting comment was ignored.
- the public `age::encrypted::Identity` API likewise decrypted the inner identity and
  then reported cryptographic success without binding the commented recipient to the
  decrypted subject.

Thus a caller that treated the commented recipient as the file's subject could record a
“complete success” for the wrong public identity.

## Security invariant now enforced

For every native X25519 identity line, the implementation:

1. derives `subject_evidence` directly from the parsed secret;
2. collects and canonicalizes valid `age1...` recipient claims from adjacent comments;
3. binds the evidence to a `generation` marker:
   - an explicit `generation:` / `generated:` marker,
   - the standard `# created: <RFC 3339 timestamp>` value, or
   - a unique audit generation (`identity-gen-<pid>-<time>-<counter>`) when no marker exists;
4. accepts:
   - a matching recipient comment (`verified`), and
   - no recipient comment (`no_recipient_comment`);
5. rejects a non-matching recipient claim (`mismatch`) before the identity can be used.

A mismatch is returned as an `io::Error` containing the cloneable
`age::IdentityBindingError` evidence. The encrypted-identity layer maps that to
`DecryptError::IdentityBinding(IdentityBindingError)` and poisons the cached encrypted
identity state. The report's `complete` field is `true` only when every binding is
`verified` or `no_recipient_comment`.

A public consumer can persist the machine-readable evidence without logging secret
material:

```rust,no_run
# use age::encrypted::Identity;
# fn demo(identity: &Identity<impl std::io::Read, impl age::Callbacks>)
# -> Result<(), age::DecryptError> {
let report = identity.binding_report()?;
std::fs::write("identity-binding-record.json", report.to_json())
    .map_err(age::DecryptError::Io)?;
# Ok(())
# }
```

Comment parsing is intentionally limited to syntactically valid X25519 recipient
strings; arbitrary prose and plugin recipients do not become native claims.

The commented recipient is never used as cryptographic authority. The authoritative
`subject_evidence` is the public key derived from the parsed secret. In an encrypted
identity file, the comment, generation marker, and secret are inside the
passphrase-authenticated age payload; AEAD decryption must succeed before this comparison
runs. A cleartext identity comment is mutable metadata, so the implementation fails
closed on conflict rather than treating that metadata as an assertion.

## Compatibility cases retained

The regression tests cover all required compatibility paths:

- standard `# created:` + matching `# public key:` identity file;
- explicit `# generation:` metadata with a matching recipient;
- identity file containing only `AGE-SECRET-KEY-...` and no comments;
- encrypted identity containing a matching commented key;
- encrypted identity containing a comment-free key;
- successful use of `encrypted::Identity::binding_report()` followed by decryption;
- cleartext and encrypted mismatch fixtures fail with generation/subject evidence.

The directly parseable native X25519 repository fixtures under
`rage/tests/cmd/**/key.txt` and `age/tests/testdata/*_x25519_key.txt` were checked:
their recipient comments match their secret-derived subjects and remain accepted.
SSH fixtures continue through the separate SSH identity parser.
The existing `age::encrypted::tests::TEST_ENCRYPTED_IDENTITY` fixture also returns
`complete=true` with status `verified` and its original `2021-08-22T04:13:47+01:00`
generation marker.

## Reproducible evidence

Run the focused public-API regression suite:

```sh
cargo test -p age --test identity_binding
```

The suite is added at
[`age/tests/identity_binding.rs`](../age/tests/identity_binding.rs). In the review
workspace it was also executed by linking that exact test file into an isolated Cargo
package because the supplied in-tree vendored development dependencies were incomplete;
result: **8 passed; 0 failed**.

Additional checks performed:

```sh
cargo fmt --all -- --check
cargo clippy -p age --all-features --lib
cargo doc -p age --no-deps --all-features
cargo build -p rage --bins
```

Post-fix CLI reproduction with a mutated comment:

```text
$ rage-keygen -y mismatch.key
Error: ... identity recipient binding mismatch on line 3
  (generation=2026-11-25T08:27:08+08:00,
   declared=age1snaj...,
   subject_evidence=age1wt69...)
exit=1

$ rage -d -i mismatch.key secret.age
Error: identity recipient binding mismatch on line 3 ...
exit=1
```

The unchanged matching file and the comment-free secret-only file both decrypt the same
ciphertext successfully with exit code `0`.

A machine-readable sample report generated through `IdentityBindingReport::to_json` is
stored in
[`encrypted-identity-binding-record.json`](./security/encrypted-identity-binding-record.json).
The `audit_generation` value is intentionally unique per parser invocation; the claimed
`generation`, recipient claims, and subject evidence are stable for the fixture.
