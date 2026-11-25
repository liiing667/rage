# Security record: unauthenticated scrypt work-factor denial of service

- **Status:** Fixed
- **Affected revision:** `str4d/rage@b5b68c4f4f7ea5c368bc060f6fe0237549c3a13f`
  (age crate 0.12.1 / rage 0.12.1)
- **Component:** `age::scrypt` decryption and the `rage -d` CLI
- **Severity:** Denial of service (resource exhaustion) before authentication
- **CVE:** Not assigned

## Summary

A passphrase-encrypted age file declares its scrypt work factor in the
unauthenticated header (`-> scrypt <salt> <logN>`). Before this fix,
`age::scrypt::Identity` chose its default maximum accepted work factor as the
locally measured target plus four:

```rust
let max_work_factor = target_work_factor + 4;
```

The target is measured from the current machine (about one second of scrypt
work). On a fast machine the resulting default maximum can exceed the age
protocol limit of 22. A malicious file could therefore declare `logN = 23` (or
the largest value allowed by the machine's derived limit) and cause the CLI to
allocate multiple GiB of memory and perform many seconds of key derivation
before the work factor was rejected or any authentication succeeded.

## Impact

An attacker who can supply a file to decrypt can force significant CPU and
memory consumption without knowing the passphrase and without producing a valid
header MAC. Repeated attempts can exhaust memory or starve other work. On a
machine where the measured target is 19, the previous default maximum was 23,
which permits an 8 GiB scrypt allocation for the age testkit vector
`scrypt_work_factor_23`.

## Root cause

The resource limit was derived from a machine benchmark rather than from a
protocol/security constant, and the public `age::Decryptor` did not inspect the
declared work factor at all. The limit was only applied inside
`scrypt::Identity::unwrap_stanza`, using a value that could vary from one host
to another.

## Fix

1. `age::scrypt::DEFAULT_MAX_WORK_FACTOR` is a fixed public constant of `22`,
   matching the maximum accepted by the age test vectors and reference
   implementation.
2. `scrypt::Identity::new` caps its default maximum at this constant, and
   `target_scrypt_work_factor` also caps the default encryption target so that
   files created with default parameters remain decryptable by default.
3. `age::Decryptor` enforces the effective limit while obtaining the payload
   key, before calling `Identity::unwrap_stanzas` and therefore before any
   scrypt allocation or computation. It honours an explicitly raised limit
   reported by a supplied scrypt identity.
4. `DecryptError::ExcessiveWork` display formatting now uses checked arithmetic,
   so an extreme declared work factor cannot panic while the error is printed.

Legitimate default files continue to decrypt. Callers that deliberately use a
higher work factor can still opt in:

```rust
let mut identity = age::scrypt::Identity::new(passphrase);
identity.set_max_work_factor(30);
```

or from the CLI:

```console
rage -d --max-work-factor 30 file.age
```

## Verification

Regression coverage:

- `age::scrypt::tests::default_work_factor_limits` verifies that the default
  target and maximum are at most 22, that work factor 23 is rejected, and that
  the rejection happens before scrypt is invoked.
- `age::scrypt::tests::explicit_higher_work_factor_is_preserved` verifies that
  an explicit higher limit is retained.
- `age::protocol::tests::decryptor_rejects_excessive_scrypt_work_before_identities`
  verifies that the public decryptor rejects work factor 23 with no identities
  supplied, proving the limit is enforced before identity processing.
- The official age testkit vectors, including `scrypt_work_factor_23`, continue
  to pass.

Suggested review commands:

```console
cargo test -p age --lib scrypt
cargo test -p age --test testkit
cargo test -p age
```

To reproduce the original issue before applying the fix, decrypt the testkit
vector `age/tests/testdata/testkit/scrypt_work_factor_23` with a default
`scrypt::Identity` on a machine whose measured target is at least 19. The old
code attempts an 8 GiB scrypt computation; the fixed code returns
`DecryptError::ExcessiveWork` immediately.

## Compatibility

- Default passphrase files (work factor at most 22) are unaffected.
- `scrypt::Identity::set_max_work_factor` and `rage --max-work-factor` can still
  raise the limit explicitly for trusted files.
- Non-scrypt identities and headers are unaffected.
