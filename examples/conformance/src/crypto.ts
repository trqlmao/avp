/**
 * Node `crypto` reimplementations of the AVP cryptographic primitives and the
 * default wrap-scheme composition (SPEC section 4), used to reproduce the
 * `vectors/` crypto vectors byte-for-byte and to round-trip the AEAD/key-wrap
 * vectors.
 *
 * Every construction here is pinned to a published RFC where one exists:
 *   - HKDF-SHA256  : RFC 5869
 *   - X25519 ECDH  : RFC 7748 (raw 32-byte little-endian keys, unhashed secret)
 *   - Ed25519      : RFC 8032 (raw 32-byte keys)
 *   - AES-256-GCM  : the payload/key-wrap AEAD (12-byte IV, 128-bit appended tag)
 *
 * Illustrative reference code, not production. SPDX-License-Identifier: MIT
 */

import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  hkdfSync,
  sign as edSign,
  verify as edVerify,
  type KeyObject,
} from "node:crypto";

/** DER prefix for an X25519 PKCS#8 private key wrapping a raw 32-byte scalar (RFC 8410). */
const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
/** DER prefix for an X25519 SubjectPublicKeyInfo wrapping a raw 32-byte public key (RFC 8410). */
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");
/** DER prefix for an Ed25519 PKCS#8 private key wrapping a raw 32-byte seed (RFC 8410). */
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
/** DER prefix for an Ed25519 SubjectPublicKeyInfo wrapping a raw 32-byte public key (RFC 8410). */
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function requireLen(name: string, raw: Buffer, len: number): Buffer {
  if (raw.length !== len) {
    throw new Error(`${name} must be ${len} bytes, got ${raw.length}`);
  }
  return raw;
}

/**
 * HKDF-SHA256 extract-then-expand (RFC 5869).
 *
 * An empty `salt` is treated by `hkdfSync` as the all-zero salt of one hash
 * length, exactly as RFC 5869 §2.2 specifies, so it reproduces Test Case 3.
 *
 * @param ikm - Input keying material.
 * @param salt - Salt (may be empty).
 * @param info - Context/application info (may be empty).
 * @param length - Desired output length in bytes.
 * @returns The `length`-byte output keying material (OKM).
 */
export function hkdfSha256(ikm: Buffer, salt: Buffer, info: Buffer, length: number): Buffer {
  return Buffer.from(hkdfSync("sha256", ikm, salt, info, length));
}

/**
 * Imports a raw 32-byte little-endian X25519 private scalar into a KeyObject.
 *
 * @param raw - The raw 32-byte scalar.
 * @returns A private {@link KeyObject}.
 */
export function importX25519Private(raw: Buffer): KeyObject {
  return createPrivateKey({
    key: Buffer.concat([X25519_PKCS8_PREFIX, requireLen("X25519 scalar", raw, 32)]),
    format: "der",
    type: "pkcs8",
  });
}

/**
 * Imports a raw 32-byte little-endian X25519 public key (u-coordinate) into a
 * KeyObject.
 *
 * @param raw - The raw 32-byte public key.
 * @returns A public {@link KeyObject}.
 */
export function importX25519Public(raw: Buffer): KeyObject {
  return createPublicKey({
    key: Buffer.concat([X25519_SPKI_PREFIX, requireLen("X25519 public key", raw, 32)]),
    format: "der",
    type: "spki",
  });
}

/**
 * The raw 32-byte X25519 public key for a private KeyObject.
 *
 * @param priv - An X25519 private {@link KeyObject}.
 * @returns The raw 32-byte public key.
 */
export function x25519PublicRaw(priv: KeyObject): Buffer {
  const jwk = createPublicKey(priv).export({ format: "jwk" }) as { x: string };
  return Buffer.from(jwk.x, "base64url");
}

/**
 * X25519 ECDH (RFC 7748): the raw 32-byte shared secret, unhashed.
 *
 * @param priv - This party's X25519 private {@link KeyObject}.
 * @param pub - The peer's X25519 public {@link KeyObject}.
 * @returns The raw 32-byte shared secret.
 */
export function x25519(priv: KeyObject, pub: KeyObject): Buffer {
  return diffieHellman({ privateKey: priv, publicKey: pub });
}

/**
 * Imports a raw 32-byte Ed25519 seed into a private KeyObject (RFC 8032).
 *
 * @param seed - The raw 32-byte secret seed.
 * @returns A private {@link KeyObject}.
 */
export function importEd25519Private(seed: Buffer): KeyObject {
  return createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, requireLen("Ed25519 seed", seed, 32)]),
    format: "der",
    type: "pkcs8",
  });
}

/**
 * Imports a raw 32-byte Ed25519 public key into a public KeyObject (RFC 8032).
 *
 * @param raw - The raw 32-byte public key.
 * @returns A public {@link KeyObject}.
 */
export function importEd25519Public(raw: Buffer): KeyObject {
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, requireLen("Ed25519 public key", raw, 32)]),
    format: "der",
    type: "spki",
  });
}

/**
 * The raw 32-byte Ed25519 public key for a private KeyObject.
 *
 * @param priv - An Ed25519 private {@link KeyObject}.
 * @returns The raw 32-byte public key.
 */
export function ed25519PublicRaw(priv: KeyObject): Buffer {
  const jwk = createPublicKey(priv).export({ format: "jwk" }) as { x: string };
  return Buffer.from(jwk.x, "base64url");
}

/**
 * Ed25519 signature over a message (RFC 8032). The PureEdDSA algorithm takes a
 * null digest algorithm in Node.
 *
 * @param priv - The Ed25519 private {@link KeyObject}.
 * @param message - The message bytes.
 * @returns The 64-byte signature.
 */
export function ed25519Sign(priv: KeyObject, message: Buffer): Buffer {
  return edSign(null, message, priv);
}

/**
 * Verifies an Ed25519 signature (RFC 8032).
 *
 * @param pub - The Ed25519 public {@link KeyObject}.
 * @param message - The message bytes.
 * @param signature - The 64-byte signature.
 * @returns Whether the signature is valid.
 */
export function ed25519Verify(pub: KeyObject, message: Buffer, signature: Buffer): boolean {
  return edVerify(null, message, pub, signature);
}

/**
 * AES-256-GCM encryption with the 128-bit tag appended to the ciphertext, as
 * AVP transmits it (SPEC section 4).
 *
 * @param key - The 32-byte AES key.
 * @param iv - The 12-byte IV.
 * @param aad - The additional authenticated data.
 * @param plaintext - The plaintext bytes.
 * @returns `ciphertext || tag` (the 16-byte GCM tag appended).
 */
export function aesGcmEncrypt(key: Buffer, iv: Buffer, aad: Buffer, plaintext: Buffer): Buffer {
  const cipher = createCipheriv("aes-256-gcm", requireLen("AES-256 key", key, 32), requireLen("GCM IV", iv, 12));
  cipher.setAAD(aad);
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([body, cipher.getAuthTag()]);
}

/**
 * AES-256-GCM decryption of a `ciphertext || tag` blob (SPEC section 4). Throws
 * if the tag does not verify (wrong key, tampered data, or mismatched AAD).
 *
 * @param key - The 32-byte AES key.
 * @param iv - The 12-byte IV.
 * @param aad - The additional authenticated data; must match the encrypt-time value.
 * @param ciphertextWithTag - `ciphertext || tag` (16-byte tag appended).
 * @returns The recovered plaintext.
 */
export function aesGcmDecrypt(key: Buffer, iv: Buffer, aad: Buffer, ciphertextWithTag: Buffer): Buffer {
  const tag = ciphertextWithTag.subarray(ciphertextWithTag.length - 16);
  const body = ciphertextWithTag.subarray(0, ciphertextWithTag.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", requireLen("AES-256 key", key, 32), requireLen("GCM IV", iv, 12));
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]);
}

/** The HKDF `info` and wrap-GCM AAD label for the default wrap scheme (SPEC section 4). */
export const WRAP_INFO = Buffer.from("avp/rdk-wrap/v1", "utf8");

/** The schemeId of the default wrap scheme (SPEC section 4). */
export const WRAP_SCHEME_ID = "X25519-HKDF-SHA256-AESGCM-v1";

/**
 * Derives the 32-byte key-encryption key (KEK) for the default wrap scheme:
 * `HKDF-SHA256(ikm = X25519(.,.), salt = ephemeralPubRaw, info = "avp/rdk-wrap/v1", L = 32)`
 * (SPEC section 4 step 3).
 *
 * @param sharedSecret - The raw 32-byte X25519 shared secret.
 * @param ephemeralPubRaw - The raw 32-byte ephemeral public key (the HKDF salt).
 * @returns The 32-byte KEK.
 */
export function wrapKek(sharedSecret: Buffer, ephemeralPubRaw: Buffer): Buffer {
  return hkdfSha256(sharedSecret, ephemeralPubRaw, WRAP_INFO, 32);
}
