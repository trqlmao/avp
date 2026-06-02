/**
 * Deterministic byte/string constructions from the AVP specification.
 *
 * These reproduce the parts of the wire contract that depend only on encoding
 * rules (not on key material), so they can be checked against the repository's
 * `vectors/` files exactly:
 *
 *   - the additional-authenticated-data (AAD) layout from SPEC section 4, and
 *   - the canonical anti-MITM key-binding message from SPEC section 9.
 *
 * Illustrative reference code, not production. SPDX-License-Identifier: MIT
 */

/**
 * Encodes a signed 64-bit integer as 8 big-endian two's-complement bytes.
 *
 * Uses `BigInt64Array`-equivalent semantics via `Buffer.writeBigInt64BE`, which
 * produces the two's-complement encoding the spec mandates for negative values.
 * This is the `int64BE(...)` primitive referenced by the AAD layout in SPEC
 * section 4.
 *
 * @param value - The integer to encode. A `number` is coerced to `bigint`; it
 *   must fit in the signed 64-bit range, otherwise `writeBigInt64BE` throws a
 *   `RangeError`.
 * @returns An 8-byte `Buffer` holding the big-endian two's-complement encoding.
 */
export function int64BE(value: number | bigint): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeBigInt64BE(BigInt(value), 0);
  return buf;
}

/**
 * Builds the AVP additional-authenticated-data (AAD) for a payload ciphertext.
 *
 * SPEC section 4:
 *   AAD = UTF8(repoId) || 0x1F || int64BE(payloadVersion) || int64BE(keyEpoch)
 *
 * The single `0x1F` (ASCII unit separator) sits between the repo id and the
 * fixed-width counters. The two counters are each an 8-byte big-endian
 * two's-complement integer (see {@link int64BE}).
 *
 * @param repoId - The repository id; its UTF-8 bytes form the AAD prefix.
 * @param payloadVersion - The monotonic payload version counter, encoded as the
 *   first `int64BE` field.
 * @param keyEpoch - The key-rotation epoch counter, encoded as the second
 *   `int64BE` field.
 * @returns The concatenated AAD bytes as a `Buffer`.
 */
export function buildAad(repoId: string, payloadVersion: number | bigint, keyEpoch: number | bigint): Buffer {
  return Buffer.concat([
    Buffer.from(repoId, "utf8"),
    Buffer.from([0x1f]),
    int64BE(payloadVersion),
    int64BE(keyEpoch),
  ]);
}

/**
 * Lowercase-hex encoding of the AAD for a payload ciphertext (SPEC section 4).
 *
 * Convenience wrapper over {@link buildAad} for comparison against the
 * `expectedAadHex` fields in `vectors/aad.json`.
 *
 * @param repoId - The repository id; see {@link buildAad}.
 * @param payloadVersion - The payload version counter; see {@link buildAad}.
 * @param keyEpoch - The key-rotation epoch counter; see {@link buildAad}.
 * @returns The AAD bytes encoded as a lowercase hexadecimal string.
 */
export function buildAadHex(repoId: string, payloadVersion: number | bigint, keyEpoch: number | bigint): string {
  return buildAad(repoId, payloadVersion, keyEpoch).toString("hex");
}

/**
 * Builds the canonical anti-MITM key-binding message (SPEC section 9).
 *
 *   bindingMessage = utf8( ed25519PublicKey + "|" + x25519PublicKey )
 *
 * The inputs are the member's base64 Ed25519 and X25519 public keys; the single
 * separator is U+007C ("|"). The returned string is exactly the text whose
 * UTF-8 bytes the IdP signs.
 *
 * @param ed25519PublicKey - The member's base64-encoded Ed25519 public key (its
 *   member id); placed before the separator.
 * @param x25519PublicKey - The member's base64-encoded X25519 public key; placed
 *   after the separator.
 * @returns The canonical binding-message string `ed25519PublicKey + "|" +
 *   x25519PublicKey`.
 */
export function buildKeyBindingMessage(ed25519PublicKey: string, x25519PublicKey: string): string {
  return ed25519PublicKey + "|" + x25519PublicKey;
}
