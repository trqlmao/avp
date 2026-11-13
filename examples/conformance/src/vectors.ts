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

import type { Acceptance, Commit, LeaveRequest, ManifestState, SignedManifest, WireAcceptance } from "./constructions.ts";

const here = dirname(fileURLToPath(import.meta.url));
// examples/conformance/src -> repo root (three levels up: src -> conformance -> examples -> root).
const vectorsDir = join(here, "..", "..", "..", "vectors");

/**
 * Shape shared by every vector file under `vectors/`: a human-readable
 * `description` plus an array of `cases`.
 *
 * @typeParam C - The per-case type (e.g. {@link HkdfCase}).
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
 * @param name - The vector file name relative to `vectors/` (e.g. `"hkdf.json"`).
 * @returns The parsed {@link VectorFile}.
 * @throws If the file cannot be read or its contents are not valid JSON.
 */
function loadVector<C>(name: string): VectorFile<C> {
  const raw = readFileSync(join(vectorsDir, name), "utf8");
  return JSON.parse(raw) as VectorFile<C>;
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
 * Loads the key-wrap vectors (SPEC section 4) from `vectors/key-wrap.json`.
 *
 * @returns The parsed vector file of {@link KeyWrapCase} entries.
 */
export function loadKeyWrapVectors(): VectorFile<KeyWrapCase> {
  return loadVector<KeyWrapCase>("key-wrap.json");
}

// ─── AVP 0.5 wire shapes (HTTP/JSON profile: base64 binary, camelCase proto names) ───

/** Wire `HostRef`. */
export interface WireHostRef {
  hostKey: string;
  locator: string;
}

/** Wire `MemberEntry`. */
export interface WireMemberEntry {
  ed25519PublicKey: string;
  x25519PublicKey: string;
  wrappedDataKey: WrappedKeyBlob;
  keyEpoch: number;
  homeHostKey: string;
}

/** Wire `Removal`. */
export interface WireRemoval {
  memberKey: string;
  removedAtSeq: number;
  frontier: string[];
}

/** Wire `ManifestState`. */
export interface WireManifestState {
  repoId: string;
  manifestSeq: number;
  prevManifestHash: string;
  ownerKey: string;
  genesisNonce: string;
  schemeId: string;
  keyEpoch: number;
  shareRefreshTokens: boolean;
  hosts: WireHostRef[];
  members: WireMemberEntry[];
  removals: WireRemoval[];
}

/** Wire `SignedManifest`. */
export interface WireSignedManifest {
  state: WireManifestState;
  ownerSignature: string;
}

/** Wire `Commit`. */
export interface WireCommit {
  repoId: string;
  commitId: string;
  parents: string[];
  manifestSeq: number;
  manifestHash: string;
  keyEpoch: number;
  author: string;
  iv: string;
  ciphertext: string;
  authorSignature: string;
}

const b64d = (s: string) => Buffer.from(s, "base64");
const b64e = (b: Buffer) => b.toString("base64");

/**
 * Decodes a wire `SignedManifest` into raw bytes, keeping list order as given.
 *
 * @param w - The wire object.
 * @returns The decoded signed manifest.
 */
export function signedManifestFromWire(w: WireSignedManifest): SignedManifest {
  const s = w.state;
  const state: ManifestState = {
    repoId: s.repoId,
    manifestSeq: s.manifestSeq,
    prevManifestHash: b64d(s.prevManifestHash),
    ownerKey: b64d(s.ownerKey),
    genesisNonce: b64d(s.genesisNonce),
    schemeId: s.schemeId,
    keyEpoch: s.keyEpoch,
    shareRefreshTokens: s.shareRefreshTokens,
    hosts: s.hosts.map((h) => ({ hostKey: b64d(h.hostKey), locator: h.locator })),
    members: s.members.map((m) => ({
      ed25519PublicKey: b64d(m.ed25519PublicKey),
      x25519PublicKey: b64d(m.x25519PublicKey),
      wrappedDataKey: {
        schemeId: m.wrappedDataKey.schemeId,
        ephemeralPublicKey: b64d(m.wrappedDataKey.ephemeralPublicKey),
        iv: b64d(m.wrappedDataKey.iv),
        ciphertext: b64d(m.wrappedDataKey.ciphertext),
      },
      keyEpoch: m.keyEpoch,
      homeHostKey: b64d(m.homeHostKey),
    })),
    removals: s.removals.map((r) => ({
      memberKey: b64d(r.memberKey),
      removedAtSeq: r.removedAtSeq,
      frontier: r.frontier.map(b64d),
    })),
  };
  return { state, ownerSignature: b64d(w.ownerSignature) };
}

/**
 * Encodes a signed manifest as its wire JSON, keeping list order as given.
 *
 * @param m - The signed manifest.
 * @returns The wire object.
 */
export function signedManifestToWire(m: SignedManifest): WireSignedManifest {
  const s = m.state;
  return {
    state: {
      repoId: s.repoId,
      manifestSeq: s.manifestSeq,
      prevManifestHash: b64e(s.prevManifestHash),
      ownerKey: b64e(s.ownerKey),
      genesisNonce: b64e(s.genesisNonce),
      schemeId: s.schemeId,
      keyEpoch: s.keyEpoch,
      shareRefreshTokens: s.shareRefreshTokens,
      hosts: s.hosts.map((h) => ({ hostKey: b64e(h.hostKey), locator: h.locator })),
      members: s.members.map((x) => ({
        ed25519PublicKey: b64e(x.ed25519PublicKey),
        x25519PublicKey: b64e(x.x25519PublicKey),
        wrappedDataKey: {
          schemeId: x.wrappedDataKey.schemeId,
          ephemeralPublicKey: b64e(x.wrappedDataKey.ephemeralPublicKey),
          iv: b64e(x.wrappedDataKey.iv),
          ciphertext: b64e(x.wrappedDataKey.ciphertext),
        },
        keyEpoch: x.keyEpoch,
        homeHostKey: b64e(x.homeHostKey),
      })),
      removals: s.removals.map((r) => ({
        memberKey: b64e(r.memberKey),
        removedAtSeq: r.removedAtSeq,
        frontier: r.frontier.map(b64e),
      })),
    },
    ownerSignature: b64e(m.ownerSignature),
  };
}

/**
 * Decodes a wire `Commit` into raw bytes, keeping parent order as given.
 *
 * @param w - The wire object.
 * @returns The decoded commit.
 */
export function commitFromWire(w: WireCommit): Commit {
  return {
    repoId: w.repoId,
    commitId: b64d(w.commitId),
    parents: w.parents.map(b64d),
    manifestSeq: w.manifestSeq,
    manifestHash: b64d(w.manifestHash),
    keyEpoch: w.keyEpoch,
    author: b64d(w.author),
    iv: b64d(w.iv),
    ciphertext: b64d(w.ciphertext),
    authorSignature: b64d(w.authorSignature),
  };
}

/**
 * Encodes a commit as its wire JSON, keeping parent order as given.
 *
 * @param c - The commit.
 * @returns The wire object.
 */
export function commitToWire(c: Commit): WireCommit {
  return {
    repoId: c.repoId,
    commitId: b64e(c.commitId),
    parents: c.parents.map(b64e),
    manifestSeq: c.manifestSeq,
    manifestHash: b64e(c.manifestHash),
    keyEpoch: c.keyEpoch,
    author: b64e(c.author),
    iv: b64e(c.iv),
    ciphertext: b64e(c.ciphertext),
    authorSignature: b64e(c.authorSignature),
  };
}

/** Wire `LeaveRequest`. */
export interface WireLeaveRequest {
  repoId: string;
  memberKey: string;
  at: number;
  signature: string;
}

/** Decodes a wire `LeaveRequest`. */
export function leaveFromWire(w: WireLeaveRequest): LeaveRequest {
  return { repoId: w.repoId, memberKey: b64d(w.memberKey), at: w.at, signature: b64d(w.signature) };
}

/** Encodes a leave request as its wire JSON. */
export function leaveToWire(l: LeaveRequest): WireLeaveRequest {
  return { repoId: l.repoId, memberKey: b64e(l.memberKey), at: l.at, signature: b64e(l.signature) };
}

/** Decodes a wire `Acceptance`. */
export function acceptanceFromWire(w: WireAcceptance): Acceptance {
  return { repoId: w.repoId, memberKey: b64d(w.memberKey), hostKey: b64d(w.hostKey), expiresAt: w.expiresAt, signature: b64d(w.signature) };
}

/** Encodes an acceptance as its wire JSON, fields in the SPEC 11.3 order. */
export function acceptanceToWire(a: Acceptance): WireAcceptance {
  return { repoId: a.repoId, memberKey: b64e(a.memberKey), hostKey: b64e(a.hostKey), expiresAt: a.expiresAt, signature: b64e(a.signature) };
}

// ─── AVP 0.5 vector files ───────────────────────────────────────────────────────────

/** One AVP owner case of `vectors/bip39-owner.json` (SPEC 3.1), passphrase empty. */
export interface Bip39OwnerCase {
  name: string;
  entropyHex: string;
  mnemonic: string;
  passphrase: string;
  seedHex: string;
  ed25519SeedHex: string;
  ed25519PublicKeyHex: string;
  x25519PrivateHex: string;
  x25519PublicKeyHex: string;
}

/** One external BIP39 anchor (Trezor reference vectors). */
export interface Bip39AnchorCase {
  entropyHex: string;
  mnemonic: string;
  seedHex: string;
}

/** `vectors/bip39-owner.json`. */
export interface Bip39OwnerFile {
  description: string;
  wordlist: { file: string; sha256: string; words: number };
  anchors: { source: string; passphrase: string; cases: Bip39AnchorCase[] };
  cases: Bip39OwnerCase[];
}

/** A keyed party in the manifest and commit seeds. */
export interface VectorParty {
  label: string;
  ed25519SeedHex: string;
  ed25519PublicKey: string;
  x25519PrivateHex?: string;
  x25519PublicKey?: string;
}

/** One case of `vectors/manifest.json` (SPEC 4.2). */
export interface ManifestCase {
  name: string;
  note: string;
  signedManifest: WireSignedManifest;
  expected: { stateHex: string; manifestHashHex: string; repoId?: string };
}

/** `vectors/manifest.json`. */
export interface ManifestFile {
  description: string;
  seeds: {
    owner: { entropyHex: string; ed25519SeedHex: string; ownerKey: string; x25519PrivateHex: string; x25519PublicKey: string };
    hosts: Array<{ label: string; ed25519SeedHex: string; hostKey: string; locator: string }>;
    members: VectorParty[];
    genesisNonceHex: string;
    dataKeys: Array<{ keyEpoch: number; dataKeyHex: string }>;
    wrapDerivation: string;
  };
  cases: ManifestCase[];
}

/** One case of `vectors/commit.json` (SPEC 4.3). */
export interface CommitCase {
  name: string;
  note: string;
  authorLabel: string;
  plaintextUtf8: string;
  commit: WireCommit;
  expected: { headerHex: string; commitIdHex: string; aadHex: string };
}

/** `vectors/commit.json`. */
export interface CommitFile {
  description: string;
  seeds: { dataKeyHex: string; ivHex: string; authors: VectorParty[] };
  cases: CommitCase[];
}

/** @returns The parsed `vectors/bip39-owner.json`. */
export function loadBip39OwnerVectors(): Bip39OwnerFile {
  return JSON.parse(readFileSync(join(vectorsDir, "bip39-owner.json"), "utf8")) as Bip39OwnerFile;
}

/** @returns The parsed `vectors/manifest.json`. */
export function loadManifestVectors(): ManifestFile {
  return JSON.parse(readFileSync(join(vectorsDir, "manifest.json"), "utf8")) as ManifestFile;
}

/** @returns The parsed `vectors/commit.json`. */
export function loadCommitVectors(): CommitFile {
  return JSON.parse(readFileSync(join(vectorsDir, "commit.json"), "utf8")) as CommitFile;
}
