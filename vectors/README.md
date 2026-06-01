# Conformance vectors

Test vectors an implementation can check itself against. Each file is JSON with a `description` and one
or more `cases`.

## Deterministic construction vectors (here)

These depend only on byte/string construction rules, not on key material, so they are fully specified in
this repository:

- [`aad.json`](aad.json) — the additional-authenticated-data layout from SPEC §4:
  `AAD = UTF8(repoId) || 0x1F || int64BE(payloadVersion) || int64BE(keyEpoch)`. Each case gives the
  inputs and the expected AAD as lowercase hex.
- [`key-binding-message.json`](key-binding-message.json) — the canonical key-binding message from
  SPEC §9: `utf8(ed25519PublicKey + "|" + x25519PublicKey)`. Each case gives the inputs and the expected
  message as a UTF-8 string.

## Crypto round-trip vectors (generated)

Vectors that require key material — challenge/sign/token, data-key wrap/unwrap under
`X25519-HKDF-SHA256-AESGCM-v1`, payload encrypt/decrypt, and key rotation — are produced by a conformant
reference implementation's vector generator, because they embed freshly generated keys and signatures.
An implementation proves conformance by generating its own and cross-verifying against another
conformant implementation (decrypt what it encrypts, verify what it signs), and by reproducing the
deterministic vectors above exactly.
