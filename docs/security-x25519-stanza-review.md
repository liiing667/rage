# X25519 recipient stanza duplicate/conflict review

## Scope

This review covers native X25519 recipient stanzas consumed by the public
`age::Decryptor` API.

Baseline: `str4d/rage@b5b68c4f4f7ea5c368bc060f6fe0237549c3a13f`.

## Security invariant

For any one X25519 identity, at most one X25519 recipient stanza in a header may
successfully unwrap to a file key. A header that contains either:

- an exact duplicate X25519 recipient stanza, or
- two distinct X25519 recipient stanzas addressed to the same identity,

is rejected with `DecryptError::InvalidHeader`.

The check only considers `X25519` stanzas that the identity can unwrap.
Stanzas for other recipients, malformed/unrelated X25519 stanzas that do not
match this identity, and unknown/noise stanza tags continue to be ignored as
they were before.

## Review evidence

The regression tests in
[`age/tests/x25519_stanza_security.rs`](../age/tests/x25519_stanza_security.rs)
exercise the public decryptor and establish that:

1. A header with distinct legal recipients remains decryptable by each
   recipient.
2. The normal grease/noise stanza added during encryption does not prevent
   decryption.
3. A header containing two stanzas for the same X25519 identity is rejected,
   even when both stanzas wrap the same file key.
4. A header containing conflicting file-key claims for one X25519 identity is
   rejected for that identity, while an unrelated legal recipient can still
   decrypt.
