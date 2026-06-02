# AVP conformance runner

A tiny test runner that checks the repository's **deterministic** vectors against
the byte/string constructions defined in the [spec](../../SPEC.md). It exercises
the two constructions that depend only on encoding rules (not on key material),
so they are fully reproducible from this repository alone:

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

The crypto round-trip vectors (challenge/sign/token, key wrap/unwrap, rotation)
are **not** covered here — they embed freshly generated keys and are verified by
cross-checking conformant implementations, as
[`vectors/README.md`](../../vectors/README.md) describes.

## Layout

```
src/constructions.ts   the AAD and key-binding-message constructions
src/vectors.ts         loads vectors/*.json relative to the repo root
test/vectors.test.ts   node:test suite asserting each case
```

## Build and run

Requires Node 20+ (uses the built-in `node:test` runner and `node --import tsx`).

```sh
npm install
npm run typecheck    # tsc --noEmit
npm test             # node --import tsx --test test/vectors.test.ts
```

## Caveats

This is **illustrative reference tooling, not production code**. It only checks
the deterministic-construction vectors shipped in this repository; passing it is
necessary but not sufficient for full protocol conformance (see SPEC section 11).
It performs no network I/O and no cryptography — it only re-derives byte layouts
and string concatenations and compares them to the committed vectors.
