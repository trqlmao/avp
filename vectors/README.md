# Conformance vectors

Test vectors an implementation can check itself against. Each file is JSON with a `description` and one
or more `cases`. The conformance runner in [`../examples/conformance`](../examples/conformance) loads and
checks every file here with Node's `crypto`.

[`index.json`](index.json) is a machine-readable index of these files: each entry gives the file, its
`kind` (deterministic / rfc-primitive / composition / negative), the spec section, and the published
anchors, so a harness can enumerate the vectors instead of hardcoding filenames.

## AVP 0.5 construction vectors (generated)

These pin the 0.5 byte constructions. They are derived only from fixed seeds (listed in each file under
`seeds`) by [`generate.ts`](generate.ts), which owns them.

- [`bip39-english.txt`](bip39-english.txt), the BIP39 English wordlist, a byte copy of the upstream
  `bitcoin/bips` `bip-0039/english.txt` (2048 words, LF, trailing newline, SHA-256
  `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`, checked by `generate.ts --check`).
- [`bip39-owner.json`](bip39-owner.json), the owner identity of SPEC §3.1: entropy to the 24-word mnemonic,
  the PBKDF2 seed (empty passphrase), and the HKDF owner Ed25519 and X25519 keys. Its `anchors` are three
  256-bit cases of the Trezor reference vectors (`trezor/python-mnemonic` `vectors.json`, passphrase
  `TREZOR`), which pin entropy, mnemonic, and seed against an external implementation.
- [`manifest.json`](manifest.json), a four-state owner-signed chain (genesis, add members, remove a member
  with a two-id frontier, policy flip) for SPEC §4.1 and §4.2: the CE bytes `S`, the owner signature,
  `manifestHash`, and the seq 1 `repoId`. The wire lists are stored in descending order so an encoder that
  does not sort fails.
- [`commit.json`](commit.json), three commits (root, single parent, three-parent merge) for SPEC §4.3: the
  header bytes, `commitId`, author signature, AAD v2 bytes, and the AES-256-GCM ciphertext. Each commit
  cites a `manifest.json` state; the removal frontier in `manifest.json` names two of these commits.

The CE constructions have no published anchor, so the runner also re-derives every case by a second,
hand-written assembly of the SPEC layout (raw byte concatenation, independent of the encoder under test).

## Deterministic construction vectors

- [`federation.json`](federation.json), the join tokens and addressing (SPEC §11). Unlike the
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

## Composition vectors (three-way cross-verified)

This exercises the default wrap scheme (SPEC §4.4). They embed fixed keys/IVs so they are
reproducible, and their correctness is established by **three independent sources agreeing byte-for-byte**
(see "Three-way verification" below):

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
   the Ed25519 signatures, and its `X25519HkdfAesGcmKeyWrap` unwraps the
   key-wrap vector and recovers the data key. This was verified with a throwaway harness against the
   library's compiled primitives.
3. **The Node conformance runner**, reproduces every primitive output and round-trips every composition
   vector (decrypt/unwrap and assert recovery) with Node's `crypto`; see the runner's
   [`README.md`](../examples/conformance/README.md). `bun run test` must pass.

An implementation proves conformance by reproducing the deterministic and RFC-anchored vectors exactly,
and by round-tripping the composition vectors (decrypting/unwrapping what a peer encrypted/wrapped,
verifying what a peer signed).

The 0.5 construction vectors (`bip39-owner.json`, `manifest.json`, `commit.json`) are verified by the
Trezor BIP39 reference vectors and the RFC-anchored primitives, by the Node runner, and by the runner's
second, hand-written assembly of every CE layout; the rebuilt Rust and Java references reproduce them
byte-for-byte as their third source.

## Negative vectors

- [`negative.json`](negative.json), a bank of MUST-reject cases. Each case starts from a valid
  construction (the seeds of `key-wrap.json` and `ed25519.json`) and applies one mutation: a flipped GCM
  tag, a flipped body bit, truncation, a wrong recipient or ephemeral wrap key, a wrong message, or a wrong
  public key. A conformant implementation MUST reject every case: `key-unwrap` fails authentication, and
  `ed25519-verify` returns false. Passing the positive vectors is not enough; an implementation that
  accepts a tampered input is not conformant. Wire
  base64 strictness is implementation-specific and is intentionally not tested here.

## Regenerating the vectors

[`generate.ts`](generate.ts) is the reproducible derivation of these files. It reuses the vector-tested
reference crypto so it cannot drift from the runner.

- `bun vectors/generate.ts --check` re-derives every committed positive vector's value fields from its
  documented seeds and asserts the committed file matches, checks the wordlist hash and the Trezor anchors,
  then asserts `negative.json` and the 0.5 construction files equal the generator's output. This is the
  provenance and drift gate; CI runs it. It does not rewrite the RFC-anchored and cross-verified positive
  files (their reviewed prose and formatting are preserved).
- `bun vectors/generate.ts --write` regenerates the files the generator owns: `negative.json`,
  `bip39-owner.json`, `manifest.json`, and `commit.json`.
