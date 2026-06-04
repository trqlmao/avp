# AVP conformance runner

A tiny test runner that checks the repository's vectors against the byte/string
and cryptographic constructions defined in the [spec](../../SPEC.md). It covers
both the encoding-only constructions and the full cryptographic envelope.

## Deterministic constructions (no key material)

- **AAD layout** (SPEC section 4): for each case in
  [`vectors/aad.json`](../../vectors/aad.json) it recomputes

  ```
  AAD = UTF8(repoId) || 0x1F || int64BE(payloadVersion) || int64BE(keyEpoch)
  ```

  the UTF-8 bytes of `repoId`, a single `0x1F` separator byte, then the
  big-endian 8-byte two's-complement encodings of `payloadVersion` and
  `keyEpoch`, hex-encodes the result, and asserts it equals `expectedAadHex`.

- **Key-binding message** (SPEC section 9): for each case in
  [`vectors/key-binding-message.json`](../../vectors/key-binding-message.json) it
  asserts that `ed25519PublicKey + "|" + x25519PublicKey` equals
  `expectedMessageUtf8`.

## Cryptographic vectors (Node `crypto`)

These use Node's built-in `crypto` (`hkdfSync`, `diffieHellman` over X25519
`KeyObject`s imported from raw keys, `aes-256-gcm` via `createCipheriv`/
`createDecipheriv` with `setAAD` and the appended auth tag, and Ed25519
`sign`/`verify`). The primitive helpers live in
[`src/crypto.ts`](src/crypto.ts).

- **HKDF-SHA256** (RFC 5869), reproduces the `okm` for each case in
  [`vectors/hkdf.json`](../../vectors/hkdf.json).
- **X25519** (RFC 7748), reproduces the raw, unhashed shared secret for each
  case in [`vectors/x25519.json`](../../vectors/x25519.json).
- **Ed25519** (RFC 8032), for each case in
  [`vectors/ed25519.json`](../../vectors/ed25519.json) it derives the public key
  from the seed, reproduces the deterministic signature byte-for-byte, and
  verifies it.
- **Payload AEAD** (SPEC section 4), for
  [`vectors/payload-aead.json`](../../vectors/payload-aead.json) it asserts the
  AAD layout, re-encrypts and asserts the ciphertext matches, decrypts and
  asserts plaintext recovery, and asserts a tampered AAD epoch is rejected.
- **Key wrap** `X25519-HKDF-SHA256-AESGCM-v1` (SPEC section 4), for
  [`vectors/key-wrap.json`](../../vectors/key-wrap.json) it recomputes the
  shared secret and KEK, re-wraps and asserts the ciphertext matches, and
  unwraps with the recipient private key and asserts data-key recovery.

The RFC-anchored cases reproduce published outputs byte-for-byte; the
composition cases additionally round-trip. The same vectors were independently
cross-checked against the Java reference implementation
(`lol.trq.alts`); see [`vectors/README.md`](../../vectors/README.md) for the
three-way verification.

## Layout

```
src/constructions.ts   the AAD and key-binding-message constructions
src/crypto.ts          HKDF / X25519 / Ed25519 / AES-GCM / wrap helpers (node:crypto)
src/vectors.ts         loads vectors/*.json relative to the repo root
test/vectors.test.ts   node:test suite for the deterministic constructions
test/crypto.test.ts    node:test suite for the cryptographic vectors
```

## Build and run

Requires Node 20+ (uses the built-in `node:test` runner and `node --import tsx`).

```sh
bun install
bun run typecheck    # tsc --noEmit
bun run test             # node --import tsx --test test/*.test.ts
```

## Caveats

This is **illustrative reference tooling, not production code**. It checks the
vectors shipped in this repository; passing it is necessary but not sufficient
for full protocol conformance (see SPEC section 11). It performs no network I/O.
The cryptographic checks use Node's `crypto` to reproduce and round-trip the
committed vectors; they do not constitute a security review of an
implementation.
