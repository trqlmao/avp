/**
 * High-level AVP cryptographic constructions for the TypeScript reference client.
 *
 * This module reimplements the low-level primitives from the canonical vector-tested
 * source (`examples/conformance/src/crypto.ts`) using `node:crypto` builtins, and
 * composes them into the high-level functions needed by the client:
 *   - AAD construction (SPEC section 4)
 *   - Payload AEAD: `encryptPayload` / `decryptPayload`
 *   - Key wrap:     `wrapDataKey` / `unwrapDataKey`
 *   - Key generation / import helpers
 *
 * Canonical primitive reference: `examples/conformance/src/crypto.ts`
 * (every low-level construction there is vector-tested against `vectors/*.json`).
 *
 * Wire encoding: standard base64 with padding for all key, IV, and ciphertext fields.
 *
 * Illustrative reference code, not production. SPDX-License-Identifier: MIT
 */

import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  type KeyObject,
} from "node:crypto";

// ─── DER constants ────────────────────────────────────────────────────────────

/** DER prefix for an X25519 PKCS#8 private key wrapping a raw 32-byte scalar (RFC 8410). */
const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
/** DER prefix for an X25519 SubjectPublicKeyInfo wrapping a raw 32-byte public key (RFC 8410). */
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

// ─── Low-level primitives (mirror of conformance/src/crypto.ts) ───────────────

/**
 * HKDF-SHA256 extract-then-expand (RFC 5869).
 *
 * @param ikm - Input keying material.
 * @param salt - Salt (may be empty; RFC 5869 §2.2 replaces empty with HashLen zeroes).
 * @param info - Context/application info.
 * @param length - Desired output length in bytes.
 * @returns The `length`-byte output keying material.
 */
function hkdfSha256(ikm: Buffer, salt: Buffer, info: Buffer, length: number): Buffer {
  return Buffer.from(hkdfSync("sha256", ikm, salt, info, length));
}

/**
 * Imports a raw 32-byte X25519 private scalar into a KeyObject (RFC 8410 PKCS#8 DER).
 *
 * @param raw - The raw 32-byte scalar.
 * @returns A private X25519 {@link KeyObject}.
 */
export function importX25519Private(raw: Buffer): KeyObject {
  if (raw.length !== 32) throw new Error(`X25519 scalar must be 32 bytes, got ${raw.length}`);
  return createPrivateKey({
    key: Buffer.concat([X25519_PKCS8_PREFIX, raw]),
    format: "der",
    type: "pkcs8",
  });
}

/**
 * Imports a raw 32-byte X25519 public key (u-coordinate) into a KeyObject (RFC 8410 SPKI DER).
 *
 * @param raw - The raw 32-byte public key.
 * @returns A public X25519 {@link KeyObject}.
 */
function importX25519Public(raw: Buffer): KeyObject {
  if (raw.length !== 32) throw new Error(`X25519 public key must be 32 bytes, got ${raw.length}`);
  return createPublicKey({
    key: Buffer.concat([X25519_SPKI_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}

/**
 * The raw 32-byte X25519 public key for a private X25519 KeyObject.
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
function x25519(priv: KeyObject, pub: KeyObject): Buffer {
  return diffieHellman({ privateKey: priv, publicKey: pub });
}

/**
 * AES-256-GCM encryption. The 16-byte GCM auth tag is appended to the ciphertext,
 * matching the AVP wire convention (SPEC section 4).
 *
 * @param key - The 32-byte AES key.
 * @param iv - The 12-byte IV.
 * @param aad - Additional authenticated data.
 * @param plaintext - Bytes to encrypt.
 * @returns `ciphertext || tag` (tag appended).
 */
function aesGcmEncrypt(key: Buffer, iv: Buffer, aad: Buffer, plaintext: Buffer): Buffer {
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(aad);
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([body, cipher.getAuthTag()]);
}

/**
 * AES-256-GCM decryption of a `ciphertext || tag` blob. Throws if the tag does not
 * verify (wrong key, tampered data, or mismatched AAD).
 *
 * @param key - The 32-byte AES key.
 * @param iv - The 12-byte IV.
 * @param aad - Additional authenticated data; must match encrypt-time value.
 * @param ciphertextWithTag - `ciphertext || tag` (16-byte tag appended).
 * @returns The recovered plaintext.
 */
function aesGcmDecrypt(key: Buffer, iv: Buffer, aad: Buffer, ciphertextWithTag: Buffer): Buffer {
  const tag = ciphertextWithTag.subarray(ciphertextWithTag.length - 16);
  const body = ciphertextWithTag.subarray(0, ciphertextWithTag.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]);
}

// ─── AVP-specific constants ────────────────────────────────────────────────────

/** The HKDF `info` label and AES-GCM AAD for data-key wrapping (SPEC section 4). */
export const WRAP_INFO = Buffer.from("avp/rdk-wrap/v1", "utf8");

/** The schemeId of the default data-key wrap scheme (SPEC section 4). */
export const WRAP_SCHEME_ID = "X25519-HKDF-SHA256-AESGCM-v1";

// ─── AAD construction ──────────────────────────────────────────────────────────

/**
 * Builds the AVP additional-authenticated-data (AAD) for a payload ciphertext.
 *
 * SPEC section 4:
 *   AAD = UTF8(repoId) || 0x1F || int64BE(payloadVersion) || int64BE(keyEpoch)
 *
 * @param repoId - The repository id.
 * @param payloadVersion - The monotonic payload version counter.
 * @param keyEpoch - The key-rotation epoch counter.
 * @returns The concatenated AAD bytes.
 */
export function buildAad(repoId: string, payloadVersion: number | bigint, keyEpoch: number | bigint): Buffer {
  const versionBuf = Buffer.alloc(8);
  versionBuf.writeBigInt64BE(BigInt(payloadVersion), 0);
  const epochBuf = Buffer.alloc(8);
  epochBuf.writeBigInt64BE(BigInt(keyEpoch), 0);
  return Buffer.concat([Buffer.from(repoId, "utf8"), Buffer.from([0x1f]), versionBuf, epochBuf]);
}

/**
 * Builds the canonical anti-MITM key-binding message (SPEC section 9).
 *
 *   bindingMessage = UTF8(ed25519PublicKey + "|" + x25519PublicKey)
 *
 * @param edPubB64 - The member's base64-encoded Ed25519 public key.
 * @param xPubB64 - The member's base64-encoded X25519 public key.
 * @returns The UTF-8 bytes of the binding message.
 */
export function keyBindingMessage(edPubB64: string, xPubB64: string): Buffer {
  return Buffer.from(edPubB64 + "|" + xPubB64, "utf8");
}

// ─── Payload AEAD ─────────────────────────────────────────────────────────────

/**
 * Describes the wire shape of an encrypted payload envelope (SPEC section 4).
 * All byte fields are standard base64 with padding.
 */
export interface EncryptedEnvelopeFields {
  repoId: string;
  payloadVersion: number;
  keyEpoch: number;
  /** Base64 12-byte AES-GCM IV. */
  iv: string;
  /** Base64 AES-GCM ciphertext with the 16-byte auth tag appended. */
  ciphertext: string;
}

/**
 * AES-256-GCM-encrypts `plaintext` into an envelope, binding `(repoId, payloadVersion,
 * keyEpoch)` into the AAD (SPEC section 4). A fresh random 12-byte IV is generated
 * per call.
 *
 * @param dataKey - The 32-byte repo data key.
 * @param repoId - Repo this envelope belongs to.
 * @param version - Payload version counter for this write.
 * @param epoch - Key epoch this data key belongs to.
 * @param plaintext - Plaintext bytes to encrypt.
 * @returns The encrypted envelope (all byte fields standard base64).
 */
export function encryptPayload(
  dataKey: Buffer,
  repoId: string,
  version: number,
  epoch: number,
  plaintext: Buffer,
): EncryptedEnvelopeFields {
  const iv = randomBytes(12);
  const aad = buildAad(repoId, version, epoch);
  const ciphertext = aesGcmEncrypt(dataKey, iv, aad, plaintext);
  return {
    repoId,
    payloadVersion: version,
    keyEpoch: epoch,
    iv: iv.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
}

/**
 * Decrypts an encrypted payload envelope, rebuilding the AAD from the envelope's own
 * `(repoId, payloadVersion, keyEpoch)`. A tampered counter causes authentication to
 * fail (throws).
 *
 * @param dataKey - The 32-byte repo data key.
 * @param env - The encrypted envelope.
 * @returns The recovered plaintext bytes.
 */
export function decryptPayload(dataKey: Buffer, env: EncryptedEnvelopeFields): Buffer {
  const iv = Buffer.from(env.iv, "base64");
  const ciphertextWithTag = Buffer.from(env.ciphertext, "base64");
  const aad = buildAad(env.repoId, env.payloadVersion, env.keyEpoch);
  return aesGcmDecrypt(dataKey, iv, aad, ciphertextWithTag);
}

// ─── Key wrap ─────────────────────────────────────────────────────────────────

/**
 * Describes the wire shape of a wrapped repo data key (SPEC section 4).
 * All byte fields are standard base64 with padding.
 */
export interface WrappedKeyFields {
  schemeId: string;
  /** Base64 raw 32-byte ephemeral X25519 public key. */
  ephemeralPublicKey: string;
  /** Base64 12-byte AES-GCM IV. */
  iv: string;
  /** Base64 AES-GCM ciphertext of the wrapped data key (tag appended). */
  ciphertext: string;
}

/**
 * Wraps a 32-byte data key to a recipient's X25519 public key using the default scheme
 * X25519-HKDF-SHA256-AESGCM-v1 (SPEC section 4):
 *
 *   1. Generate an ephemeral X25519 keypair.
 *   2. `shared = X25519(ephemeralPriv, recipientPub)` (raw, unhashed).
 *   3. `kek = HKDF-SHA256(ikm=shared, salt=ephemeralPubRaw, info="avp/rdk-wrap/v1", L=32)`.
 *   4. `ct = AES-256-GCM(kek, iv, aad="avp/rdk-wrap/v1", plaintext=dataKey)` (tag appended).
 *
 * @param recipientX25519PubB64 - The recipient's base64 raw 32-byte X25519 public key.
 * @param dataKey - The 32-byte data key to wrap.
 * @returns The {@link WrappedKeyFields} (all byte fields standard base64).
 */
export function wrapDataKey(recipientX25519PubB64: string, dataKey: Buffer): WrappedKeyFields {
  const recipientPubRaw = Buffer.from(recipientX25519PubB64, "base64");
  const recipientPub = importX25519Public(recipientPubRaw);

  // Generate a fresh ephemeral X25519 keypair.
  const ephemeralPriv = generateX25519().privateKey;
  const ephemeralPubRaw = x25519PublicRaw(ephemeralPriv);

  // Unhashed shared secret.
  const shared = x25519(ephemeralPriv, recipientPub);

  // KEK = HKDF-SHA256(ikm=shared, salt=ephemeralPub, info=WRAP_INFO, L=32).
  const kek = hkdfSha256(shared, ephemeralPubRaw, WRAP_INFO, 32);

  // Wrap: AES-256-GCM(kek, iv, aad=WRAP_INFO, plaintext=dataKey).
  const iv = randomBytes(12);
  const ciphertext = aesGcmEncrypt(kek, iv, WRAP_INFO, dataKey);

  return {
    schemeId: WRAP_SCHEME_ID,
    ephemeralPublicKey: ephemeralPubRaw.toString("base64"),
    iv: iv.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
}

/**
 * Unwraps a wrapped data key using the recipient's X25519 private key. Reverses
 * {@link wrapDataKey}; throws if the scheme is unrecognised or the auth tag fails.
 *
 * @param recipientPriv - The recipient's X25519 private key (a {@link KeyObject} produced
 *   by {@link importX25519Private} or {@link generateX25519}).
 * @param wrappedKey - The wrapped key to unwrap.
 * @returns The recovered 32-byte data key.
 */
export function unwrapDataKey(recipientPriv: KeyObject, wrappedKey: WrappedKeyFields): Buffer {
  if (wrappedKey.schemeId !== WRAP_SCHEME_ID) {
    throw new Error(`unsupported wrap scheme "${wrappedKey.schemeId}"`);
  }
  const ephemeralPubRaw = Buffer.from(wrappedKey.ephemeralPublicKey, "base64");
  const ephemeralPub = importX25519Public(ephemeralPubRaw);

  const shared = x25519(recipientPriv, ephemeralPub);
  const kek = hkdfSha256(shared, ephemeralPubRaw, WRAP_INFO, 32);

  const iv = Buffer.from(wrappedKey.iv, "base64");
  const ciphertextWithTag = Buffer.from(wrappedKey.ciphertext, "base64");

  return aesGcmDecrypt(kek, iv, WRAP_INFO, ciphertextWithTag);
}

// ─── Key generation / import helpers ──────────────────────────────────────────

/**
 * Generates a fresh X25519 keypair for data-key wrapping.
 *
 * @returns An object with the private key as a {@link KeyObject} and the raw 32-byte
 *   public key as a `Buffer` (for base64-encoding onto the wire).
 */
export function generateX25519(): { privateKey: KeyObject; publicKeyRaw: Buffer } {
  const { privateKey } = generateKeyPairSync("x25519");
  const publicKeyRaw = x25519PublicRaw(privateKey);
  return { privateKey, publicKeyRaw };
}

/**
 * Encodes a raw byte buffer as standard base64 with padding (the AVP wire encoding
 * for all key, IV, and ciphertext fields).
 *
 * @param raw - The bytes to encode.
 * @returns The standard base64 string.
 */
export function toBase64(raw: Buffer): string {
  return raw.toString("base64");
}

/**
 * Decodes a standard base64 string (with or without padding) into a Buffer.
 *
 * @param b64 - The base64 string to decode.
 * @returns The decoded bytes.
 */
export function fromBase64(b64: string): Buffer {
  return Buffer.from(b64, "base64");
}
