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
 *   - SHA-256/512  : FIPS 180-4
 *   - PBKDF2       : RFC 8018 (HMAC-SHA512, for the BIP39 seed of SPEC section 3.1)
 *
 * Illustrative reference code, not production. SPDX-License-Identifier: MIT
 */

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  hkdfSync,
  pbkdf2Sync,
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
 * SHA-256 (FIPS 180-4) of the concatenation of `parts`.
 *
 * @param parts - The byte strings to hash, in order.
 * @returns The 32-byte digest.
 */
export function sha256(...parts: Uint8Array[]): Buffer {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
}

/**
 * SHA-512 (FIPS 180-4) of the concatenation of `parts`.
 *
 * @param parts - The byte strings to hash, in order.
 * @returns The 64-byte digest.
 */
export function sha512(...parts: Uint8Array[]): Buffer {
  const h = createHash("sha512");
  for (const p of parts) h.update(p);
  return h.digest();
}

/**
 * PBKDF2-HMAC-SHA512 (RFC 8018), as the BIP39 seed derivation uses it (SPEC section 3.1).
 *
 * @param password - The password bytes.
 * @param salt - The salt bytes.
 * @param iterations - The iteration count.
 * @param length - The output length in bytes.
 * @returns The derived key.
 */
export function pbkdf2Sha512(password: Buffer, salt: Buffer, iterations: number, length: number): Buffer {
  return pbkdf2Sync(password, salt, iterations, length, "sha512");
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

/** The field prime of edwards25519, `2^255 - 19`. */
const ED25519_P = (1n << 255n) - 19n;
/** The prime order of the edwards25519 base point, `2^252 + 27742317777372353535851937790883648493`. */
const ED25519_L = (1n << 252n) + 27742317777372353535851937790883648493n;

/**
 * The libsodium `has_small_order` blocklist: with the sign bit cleared, the eight small-order points of
 * edwards25519 have five encodings (`y` = 0, 1, the two order-8 values, and `p - 1`), followed here by
 * the non-canonical encodings `p` and `p + 1` of `y` = 0 and 1.
 */
const ED25519_SMALL_ORDER = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
].map((h) => Buffer.from(h, "hex"));

/** Reads bytes as an unsigned little-endian integer. */
function littleEndian(b: Uint8Array): bigint {
  let x = 0n;
  for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]);
  return x;
}

/** Whether a 32-byte point encoding is that of a small-order point, ignoring the sign bit. */
function isSmallOrder(p: Uint8Array): boolean {
  return ED25519_SMALL_ORDER.some((e) => {
    for (let i = 0; i < 31; i++) if (p[i] !== e[i]) return false;
    return (p[31] & 0x7f) === e[31];
  });
}

/** Whether a 32-byte point encoding is canonical: its `y` field, sign bit cleared, is below `p`. */
function isCanonicalPoint(p: Uint8Array): boolean {
  const y = Buffer.from(p);
  y[31] &= 0x7f;
  return littleEndian(y) < ED25519_P;
}

/**
 * The strict pre-checks of SPEC 2 on a raw public key and signature: neither the key nor `R` is a
 * small-order or non-canonical point encoding, and `S` is below the group order `L`. Node's
 * OpenSSL verification is cofactorless and makes none of these checks itself.
 *
 * @param publicKey - The raw 32-byte public key.
 * @param signature - The 64-byte signature.
 * @returns Whether the inputs pass every pre-check.
 */
export function ed25519StrictInputsOk(publicKey: Uint8Array, signature: Uint8Array): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  const r = signature.subarray(0, 32);
  if (isSmallOrder(publicKey) || !isCanonicalPoint(publicKey)) return false;
  if (isSmallOrder(r) || !isCanonicalPoint(r)) return false;
  return littleEndian(signature.subarray(32, 64)) < ED25519_L;
}

/**
 * Verifies an Ed25519 signature strictly (SPEC 2): the pre-checks of {@link ed25519StrictInputsOk},
 * then RFC 8032 verification.
 *
 * @param pub - The Ed25519 public {@link KeyObject}.
 * @param message - The message bytes.
 * @param signature - The 64-byte signature.
 * @returns Whether the signature is valid.
 */
export function ed25519Verify(pub: KeyObject, message: Buffer, signature: Buffer): boolean {
  const jwk = pub.export({ format: "jwk" }) as { x?: string };
  if (typeof jwk.x !== "string") return false;
  if (!ed25519StrictInputsOk(Buffer.from(jwk.x, "base64url"), signature)) return false;
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


/**
 * Wraps a secret to a recipient with the default wrap scheme (SPEC section 4.4), with the ephemeral
 * private key and IV supplied by the caller so the result is reproducible. Real clients MUST pick a
 * fresh random ephemeral key and IV for every wrap; this deterministic form exists for vectors.
 *
 * @param recipientPubRaw - The recipient's raw 32-byte X25519 public key.
 * @param ephemeralPrivRaw - The raw 32-byte ephemeral X25519 private key.
 * @param iv - The 12-byte AES-GCM IV.
 * @param secret - The secret to wrap (a 32-byte data key for `avp/rdk-wrap/v1`).
 * @param info - The scheme label, bound as both the HKDF info and the GCM AAD.
 * @returns The raw `WrappedKey` fields.
 */
export function wrapSecret(
  recipientPubRaw: Buffer,
  ephemeralPrivRaw: Buffer,
  iv: Buffer,
  secret: Buffer,
  info: Buffer = WRAP_INFO,
): { schemeId: string; ephemeralPublicKey: Buffer; iv: Buffer; ciphertext: Buffer } {
  const eph = importX25519Private(ephemeralPrivRaw);
  const ephemeralPublicKey = x25519PublicRaw(eph);
  const shared = x25519(eph, importX25519Public(recipientPubRaw));
  const kek = hkdfSha256(shared, ephemeralPublicKey, info, 32);
  return { schemeId: WRAP_SCHEME_ID, ephemeralPublicKey, iv, ciphertext: aesGcmEncrypt(kek, iv, info, secret) };
}
