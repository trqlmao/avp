# Conformance vectors

Test vectors an implementation can check itself against. Each file is JSON with a `description` and one
or more `cases`. The conformance runner in [`../examples/conformance`](../examples/conformance) loads and
checks every file here with Node's `crypto`.

[`index.json`](index.json) is a machine-readable index of these files: each entry gives the file, its
`kind` (deterministic / rfc-primitive / composition), the spec section, and the published RFC anchors,
so a harness can enumerate the vectors instead of hardcoding filenames.

## Deterministic construction vectors

These depend only on byte/string construction rules, not on key material, so they are fully specified in
this repository:

- [`aad.json`](aad.json), the additional-authenticated-data layout from SPEC §4:
  `AAD = UTF8(repoId) || 0x1F || int64BE(payloadVersion) || int64BE(keyEpoch)`. Each case gives the
  inputs and the expected AAD as lowercase hex.
- [`key-binding-message.json`](key-binding-message.json), the canonical key-binding message from
  SPEC §9: `utf8(ed25519PublicKey + "|" + x25519PublicKey)`. Each case gives the inputs and the expected
  message as a UTF-8 string.
- [`federation.json`](federation.json), the federation handshake and addressing from SPEC §8. Unlike the
  others it uses top-level `tokens` and `uris` arrays rather than `cases`. Each token case (the invite
  request and the repo locator) is a **decode oracle**: base64url-decoding `base64url` MUST yield
  `decoded`. `canonicalJson` is the recommended minified encoding (members in the order shown) and
  `base64url` is its base64url (RFC 4648 §5, no padding) form; the runner round-trips both directions and
  validates `decoded` against its schema `$def`. Each `avp://` URI case pins parse and format of
  `avp://<host>/<repoId>` (the host is the authority, with an optional port; the repoId is the single
  opaque path segment).

## Cryptographic primitive vectors (RFC-anchored)

Each primitive AVP relies on is pinned to a **published RFC test vector**, so a conformant
implementation reproduces a known-good output and cannot drift on the primitive itself:

- [`hkdf.json`](hkdf.json), HKDF-SHA256 (RFC 5869). Cases `rfc5869-tc1` (RFC 5869 Appendix A.1) and
  `rfc5869-tc3` (Appendix A.3, the zero-length-salt case that exercises the empty-salt → 32 zero bytes
  rule). Each case gives `ikmHex`/`saltHex`/`infoHex`/`length` and the expected `prkHex` (extract step)
  and `okmHex` (expand step).
- [`x25519.json`](x25519.json), X25519 ECDH (RFC 7748), raw 32-byte little-endian keys, **unhashed**
  shared secret. Cases `rfc7748-vec1` and `rfc7748-vec2` are the RFC 7748 §5.2 single-iteration vectors;
  `rfc7748-dh` is the RFC 7748 §6.1 Diffie-Hellman example. Note: RFC 7748 prints the `vec2` input
  u-coordinate with its most-significant bit set; RFC 7748 §5 requires masking that bit before decoding,
  and the committed value is already masked so every conformant decoder (whether or not it masks
  internally) agrees byte-for-byte. The `rfc7748-dh` keypairs (Alice = recipient, Bob = ephemeral) are
  reused by `key-wrap.json`, anchoring the wrap composition's shared secret to a published vector.
- [`ed25519.json`](ed25519.json), Ed25519 sign/verify (RFC 8032), raw 32-byte keys. Cases
  `rfc8032-test2` and `rfc8032-test3` are the RFC 8032 §7.1 vectors. The runner derives the public key
  from the seed, reproduces the (deterministic) signature byte-for-byte, and verifies it.

## Composition vectors (generated, three-way cross-verified)

These exercise the full AVP envelope composition (SPEC §4). They embed fixed keys/IVs so they are
reproducible, and their correctness is established by **three independent sources agreeing byte-for-byte**
(see "Three-way verification" below):

- [`payload-aead.json`](payload-aead.json), AES-256-GCM payload encryption with the AVP AAD: 12-byte
  IV, 128-bit tag **appended** to the ciphertext, `AAD = UTF8(repoId) || 0x1F || int64BE(payloadVersion)
  || int64BE(keyEpoch)`. The runner re-encrypts (deterministic given key+iv+aad) and asserts equality
  with the committed ciphertext, decrypts and asserts plaintext recovery, and asserts that decryption
  **fails** when the epoch bound into the AAD is changed (rollback/replay protection).
- [`key-wrap.json`](key-wrap.json), the default wrap scheme `X25519-HKDF-SHA256-AESGCM-v1`:
  `sharedSecret = X25519(ephemeralPriv, recipientPub)`;
  `KEK = HKDF-SHA256(ikm=sharedSecret, salt=ephemeralPubRaw, info=UTF8("avp/rdk-wrap/v1"), L=32)`;
  `wrappedCiphertext = AES-256-GCM(KEK, iv, aad=UTF8("avp/rdk-wrap/v1"), plaintext=dataKey)` with the
  16-byte tag appended. The `WrappedKey` on the wire is `{schemeId, ephemeralPublicKey, iv, ciphertext}`;
  the case additionally carries `recipientPrivateKeyB64` (**not** part of the wire format, only so a
  checker can unwrap) plus the intermediate `sharedSecretHex`/`kekHex` for cross-reference. The recipient
  and ephemeral keypairs are the RFC 7748 §6.1 Alice and Bob keypairs, so the shared secret equals the
  published RFC 7748 §6.1 value. The runner recomputes the shared secret and KEK, re-wraps and asserts
  equality with the committed ciphertext, and unwraps and asserts data-key recovery.

## Three-way verification

The composition vectors are public and must not contain mistakes, so each was confirmed by **three
independent sources agreeing byte-for-byte** before being committed:

1. **Published RFC test vectors**, every primitive carries at least one published anchor: HKDF-SHA256
   from RFC 5869 (Test Cases 1 and 3), X25519 from RFC 7748 (§5.2 vectors and the §6.1 DH example), and
   Ed25519 from RFC 8032 (§7.1 TEST 2 and TEST 3). The composition vectors are anchored to RFC 7748 §6.1
   via the wrap keypairs. The Node runner reproduces every published output exactly.
2. **The reference implementation (Java)**, the `lol.trq.alts` crypto primitives independently agree
   with every vector: its HKDF and X25519 reproduce the primitive outputs, it verifies (and reproduces)
   the Ed25519 signatures, its `PayloadCipher` decrypts the payload-aead vector under the AVP AAD and
   recovers the plaintext (and rejects a tampered epoch), and its `X25519HkdfAesGcmKeyWrap` unwraps the
   key-wrap vector and recovers the data key. This was verified with a throwaway harness against the
   library's compiled primitives.
3. **The Node conformance runner**, reproduces every primitive output and round-trips every composition
   vector (decrypt/unwrap and assert recovery) with Node's `crypto`; see the runner's
   [`README.md`](../examples/conformance/README.md). `bun run test` must pass.

An implementation proves conformance by reproducing the deterministic and RFC-anchored vectors exactly,
and by round-tripping the composition vectors (decrypting/unwrapping what a peer encrypted/wrapped,
verifying what a peer signed).

## Negative vectors

- [`negative.json`](negative.json), a bank of MUST-reject cases. Each case starts from a valid
  construction (the seeds of `payload-aead.json`, `key-wrap.json`, and `ed25519.json`) and applies one
  mutation: a flipped GCM tag, a flipped body bit, truncation, a missing tag, a wrong AAD repoId /
  payloadVersion / keyEpoch, a wrong data key, a wrong recipient or ephemeral wrap key, a wrong message,
  or a wrong public key. A conformant implementation MUST reject every case: `payload-decrypt` and
  `key-unwrap` fail authentication, and `ed25519-verify` returns false. Passing the positive vectors is
  not enough; an implementation that accepts a tampered or replayed envelope is not conformant. Wire
  base64 strictness is implementation-specific and is intentionally not tested here.

## Regenerating the vectors

[`generate.ts`](generate.ts) is the reproducible derivation of these files. It reuses the vector-tested
reference crypto so it cannot drift from the runner.

- `bun vectors/generate.ts --check` re-derives every committed positive vector's value fields from its
  documented seeds and asserts the committed file matches, then asserts `negative.json` equals the
  generator's output. This is the provenance and drift gate; CI runs it. It does not rewrite the
  RFC-anchored and cross-verified positive files (their reviewed prose and formatting are preserved).
- `bun vectors/generate.ts --write` regenerates `negative.json`, which the generator owns.
