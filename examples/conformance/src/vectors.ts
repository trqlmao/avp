/**
 * Loads the AVP deterministic test vectors from the repository's `vectors/`
 * directory. The path is resolved relative to this file so the runner works
 * regardless of the current working directory.
 *
 * Illustrative reference code, not production. SPDX-License-Identifier: MIT
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
// examples/conformance/src -> repo root (three levels up: src -> conformance -> examples -> root).
const vectorsDir = join(here, "..", "..", "..", "vectors");

/**
 * One case from `vectors/aad.json`: the inputs to the AAD construction (SPEC
 * section 4) paired with the expected lowercase-hex output.
 */
export interface AadCase {
  /** Repository id whose UTF-8 bytes form the AAD prefix. */
  repoId: string;
  /** Payload version counter encoded as the first `int64BE` field. */
  payloadVersion: number;
  /** Key-rotation epoch counter encoded as the second `int64BE` field. */
  keyEpoch: number;
  /** Expected AAD bytes, lowercase-hex encoded. */
  expectedAadHex: string;
}

/**
 * One case from `vectors/key-binding-message.json`: the two member public keys
 * paired with the expected canonical binding message (SPEC section 9).
 */
export interface KeyBindingMessageCase {
  /** Member's base64-encoded Ed25519 public key (its member id). */
  ed25519PublicKey: string;
  /** Member's base64-encoded X25519 public key. */
  x25519PublicKey: string;
  /** Expected binding message: `ed25519PublicKey + "|" + x25519PublicKey`. */
  expectedMessageUtf8: string;
}

/**
 * Shape shared by every vector file under `vectors/`: a human-readable
 * `description` plus an array of `cases`.
 *
 * @typeParam C - The per-case type (e.g. {@link AadCase}).
 */
interface VectorFile<C> {
  /** Human-readable description of what the file's cases cover. */
  description: string;
  /** The vector cases to check. */
  cases: C[];
}

/**
 * Reads and parses a vector file from the repository's `vectors/` directory.
 *
 * @typeParam C - The per-case type the file's `cases` array is parsed into.
 * @param name - The vector file name relative to `vectors/` (e.g. `"aad.json"`).
 * @returns The parsed {@link VectorFile}.
 * @throws If the file cannot be read or its contents are not valid JSON.
 */
function loadVector<C>(name: string): VectorFile<C> {
  const raw = readFileSync(join(vectorsDir, name), "utf8");
  return JSON.parse(raw) as VectorFile<C>;
}

/**
 * Loads the AAD-layout vectors (SPEC section 4) from `vectors/aad.json`.
 *
 * @returns The parsed vector file of {@link AadCase} entries.
 * @throws If `vectors/aad.json` is missing or not valid JSON.
 */
export function loadAadVectors(): VectorFile<AadCase> {
  return loadVector<AadCase>("aad.json");
}

/**
 * Loads the key-binding-message vectors (SPEC section 9) from
 * `vectors/key-binding-message.json`.
 *
 * @returns The parsed vector file of {@link KeyBindingMessageCase} entries.
 * @throws If `vectors/key-binding-message.json` is missing or not valid JSON.
 */
export function loadKeyBindingMessageVectors(): VectorFile<KeyBindingMessageCase> {
  return loadVector<KeyBindingMessageCase>("key-binding-message.json");
}

/**
 * One case from `vectors/hkdf.json`: HKDF-SHA256 inputs (hex) and the expected
 * PRK and OKM (hex). RFC 5869.
 */
export interface HkdfCase {
  /** Case label. */
  name: string;
  /** Provenance note (RFC citation, etc.). */
  source: string;
  /** Hash name (always "SHA-256" here). */
  hash: string;
  /** Input keying material, lowercase hex. */
  ikmHex: string;
  /** Salt, lowercase hex (empty string = no salt). */
  saltHex: string;
  /** Context info, lowercase hex (empty string = none). */
  infoHex: string;
  /** Desired output length in bytes. */
  length: number;
  /** Expected pseudo-random key from the extract step, lowercase hex. */
  prkHex: string;
  /** Expected output keying material from the expand step, lowercase hex. */
  okmHex: string;
}

/**
 * One case from `vectors/x25519.json`: an X25519 ECDH agreement with raw
 * little-endian keys and the expected raw shared secret. RFC 7748.
 */
export interface X25519Case {
  /** Case label. */
  name: string;
  /** Provenance note (RFC citation, etc.). */
  source: string;
  /** Private scalar, lowercase hex. */
  scalarHex: string;
  /** Peer public u-coordinate, lowercase hex. */
  uCoordinateHex: string;
  /** Expected raw 32-byte shared secret, lowercase hex. */
  outputHex: string;
}

/**
 * One case from `vectors/ed25519.json`: an Ed25519 sign/verify vector with raw
 * keys. RFC 8032.
 */
export interface Ed25519Case {
  /** Case label. */
  name: string;
  /** Provenance note (RFC citation, etc.). */
  source: string;
  /** Secret seed, lowercase hex. */
  seedHex: string;
  /** Raw 32-byte public key (derivable from the seed), lowercase hex. */
  publicKeyHex: string;
  /** Message bytes, lowercase hex (empty string = empty message). */
  messageHex: string;
  /** Expected 64-byte signature, lowercase hex. */
  signatureHex: string;
}

/**
 * One case from `vectors/payload-aead.json`: an AES-256-GCM payload vector with
 * the AVP AAD (SPEC section 4).
 */
export interface PayloadAeadCase {
  /** Case label. */
  name: string;
  /** Provenance note. */
  source: string;
  /** 32-byte AES data key, base64. */
  keyB64: string;
  /** 12-byte IV, base64. */
  ivB64: string;
  /** Repository id whose UTF-8 bytes form the AAD prefix. */
  repoId: string;
  /** Payload version bound into the AAD. */
  payloadVersion: number;
  /** Key epoch bound into the AAD. */
  keyEpoch: number;
  /** Expected AAD, lowercase hex (cross-reference with aad.json). */
  aadHex: string;
  /** Plaintext as a UTF-8 string. */
  plaintextUtf8: string;
  /** `ciphertext || tag` (16-byte GCM tag appended), base64. */
  ciphertextB64: string;
  /** A differing epoch; decrypting under this epoch's AAD MUST fail. */
  tamperEpoch: number;
}

/**
 * The wire `WrappedKey` shape (SPEC section 4): base64 fields only.
 */
export interface WrappedKeyBlob {
  /** The wrap scheme id. */
  schemeId: string;
  /** Ephemeral X25519 public key, base64 raw 32 bytes. */
  ephemeralPublicKey: string;
  /** AES-GCM IV, base64 12 bytes. */
  iv: string;
  /** Wrapped data key with its GCM tag appended, base64. */
  ciphertext: string;
}

/**
 * One case from `vectors/key-wrap.json`: a full
 * `X25519-HKDF-SHA256-AESGCM-v1` wrap of a data key plus the recipient private
 * key needed to unwrap (SPEC section 4).
 */
export interface KeyWrapCase {
  /** Case label. */
  name: string;
  /** Provenance note. */
  source: string;
  /** Recipient X25519 private scalar, base64 (NOT part of the wire format). */
  recipientPrivateKeyB64: string;
  /** Recipient X25519 public key, base64 raw 32 bytes. */
  recipientPublicKeyB64: string;
  /** The wrapped 32-byte data key, base64 (the unwrap target). */
  dataKeyB64: string;
  /** The raw X25519 shared secret, lowercase hex (cross-reference). */
  sharedSecretHex: string;
  /** The derived 32-byte KEK, lowercase hex (cross-reference). */
  kekHex: string;
  /** The HKDF info / wrap-GCM AAD label. */
  info: string;
  /** The `WrappedKey` blob as stored on the wire. */
  wrappedKey: WrappedKeyBlob;
}

/**
 * Loads the HKDF-SHA256 vectors (RFC 5869) from `vectors/hkdf.json`.
 *
 * @returns The parsed vector file of {@link HkdfCase} entries.
 */
export function loadHkdfVectors(): VectorFile<HkdfCase> {
  return loadVector<HkdfCase>("hkdf.json");
}

/**
 * Loads the X25519 vectors (RFC 7748) from `vectors/x25519.json`.
 *
 * @returns The parsed vector file of {@link X25519Case} entries.
 */
export function loadX25519Vectors(): VectorFile<X25519Case> {
  return loadVector<X25519Case>("x25519.json");
}

/**
 * Loads the Ed25519 vectors (RFC 8032) from `vectors/ed25519.json`.
 *
 * @returns The parsed vector file of {@link Ed25519Case} entries.
 */
export function loadEd25519Vectors(): VectorFile<Ed25519Case> {
  return loadVector<Ed25519Case>("ed25519.json");
}

/**
 * Loads the payload AEAD vectors (SPEC section 4) from
 * `vectors/payload-aead.json`.
 *
 * @returns The parsed vector file of {@link PayloadAeadCase} entries.
 */
export function loadPayloadAeadVectors(): VectorFile<PayloadAeadCase> {
  return loadVector<PayloadAeadCase>("payload-aead.json");
}

/**
 * Loads the key-wrap vectors (SPEC section 4) from `vectors/key-wrap.json`.
 *
 * @returns The parsed vector file of {@link KeyWrapCase} entries.
 */
export function loadKeyWrapVectors(): VectorFile<KeyWrapCase> {
  return loadVector<KeyWrapCase>("key-wrap.json");
}
