# AVP conformance runner

A tiny test runner that checks the repository's vectors against the byte and
cryptographic constructions defined in the [spec](../../SPEC.md), plus
schema/example/index/openapi consistency.

## AVP 0.5 constructions

- **CE writer** (SPEC section 4.1): `test/vectors.test.ts` pins every item of
  the canonical encoding (`tag`, `bytes`, `str`, `i64`, `bool`, `count`)
  against literal bytes from the SPEC table, including an `i64` above 2^32.
- **Owner identity** (SPEC section 3.1): for
  [`vectors/bip39-owner.json`](../../vectors/bip39-owner.json) it checks
  entropy to 24-word mnemonic and back, the PBKDF2 seed, and the HKDF owner
  Ed25519 and X25519 keys, over the pinned wordlist
  [`vectors/bip39-english.txt`](../../vectors/bip39-english.txt). Three Trezor
  reference vectors (passphrase `TREZOR`) anchor the BIP39 steps externally,
  and every reject path (word count, unknown word, checksum) is asserted.
- **Manifest state** (SPEC section 4.2): for
  [`vectors/manifest.json`](../../vectors/manifest.json) it checks the CE bytes
  of each state, the owner signature, `manifestHash`, and the seq 1 `repoId`,
  with the list input order shuffled.
- **Commit and AAD v2** (SPEC section 4.3): for
  [`vectors/commit.json`](../../vectors/commit.json) it checks the header
  bytes, `commitId`, the author signature, the AAD v2 bytes, and the
  AES-256-GCM ciphertext, for every parent order.

The manifest and commit tests also re-derive each case by a second, hand
written assembly of the SPEC layout (raw `Buffer` concatenation, no
`CeWriter`), since these constructions have no external anchor.

## Cryptographic vectors (Node `crypto`)

These use Node's built-in `crypto` (`hkdfSync`, `pbkdf2Sync`, `diffieHellman`
over X25519 `KeyObject`s imported from raw keys, `aes-256-gcm` via
`createCipheriv`/`createDecipheriv` with `setAAD` and the appended auth tag, and
Ed25519 `sign`/`verify`). The primitive helpers live in
[`src/crypto.ts`](src/crypto.ts).

- **HKDF-SHA256** (RFC 5869), reproduces the `okm` for each case in
  [`vectors/hkdf.json`](../../vectors/hkdf.json).
- **X25519** (RFC 7748), reproduces the raw, unhashed shared secret for each
  case in [`vectors/x25519.json`](../../vectors/x25519.json).
- **Ed25519** (RFC 8032), for each case in
  [`vectors/ed25519.json`](../../vectors/ed25519.json) it derives the public key
  from the seed, reproduces the deterministic signature byte-for-byte, and
  verifies it.
- **Key wrap** `X25519-HKDF-SHA256-AESGCM-v1` (SPEC section 4.4), for
  [`vectors/key-wrap.json`](../../vectors/key-wrap.json) it recomputes the
  shared secret and KEK, re-wraps and asserts the ciphertext matches, and
  unwraps with the recipient private key and asserts data-key recovery.
- **Negative bank**, every case of
  [`vectors/negative.json`](../../vectors/negative.json) is rejected.

## Layout

```
src/constructions.ts   CE writer, manifest state, commit header, AAD v2
src/bip39.ts           BIP39 mnemonic, seed, and owner keys
src/crypto.ts          HKDF / PBKDF2 / SHA / X25519 / Ed25519 / AES-GCM / wrap helpers (node:crypto)
src/vectors.ts         loads vectors/*.json relative to the repo root; wire JSON converters
test/vectors.test.ts   the CE writer items
test/bip39.test.ts     owner identity
test/manifest.test.ts  manifest state, signature, hash, repoId
test/commit.test.ts    commit header, id, signature, AAD v2, payload AEAD
test/crypto.test.ts    the RFC-anchored primitives and the key wrap
test/negative.test.ts  the MUST-reject bank
```

## Build and run

Requires Node 20+ (uses the built-in `node:test` runner and `node --import tsx`).

```sh
bun install
bun run typecheck    # tsc --noEmit
bun run test         # node --import tsx --test test/*.test.ts
```

## Caveats

This is **illustrative reference tooling, not production code**. It checks the
vectors shipped in this repository; passing it is necessary but not sufficient
for full protocol conformance (see SPEC section 14). It performs no network I/O.
The cryptographic checks use Node's `crypto` to reproduce and round-trip the
committed vectors; they do not constitute a security review of an
implementation.
