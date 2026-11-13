/**
 * Deterministic byte constructions of AVP 0.5 (SPEC section 4):
 *
 *   - the canonical encoding (CE) writer (SPEC 4.1),
 *   - the manifest state bytes, owner signature, manifestHash, and repoId (SPEC 4.2),
 *   - the commit header, commitId, author signature message, and AAD v2 (SPEC 4.3),
 *   - the challenge transcript (SPEC 3.3),
 *   - the acceptance and leave signature messages, fingerprints, the link confirmation code, and the
 *     out-of-band token encoding (SPEC 3.2, 11).
 *
 * They are checked byte-for-byte against `vectors/manifest.json`, `vectors/commit.json`, and
 * `vectors/federation.json`. Binary
 * fields are raw bytes (`Buffer`); the wire base64 is decoded before it reaches these functions.
 *
 * Illustrative reference code, not production. SPDX-License-Identifier: MIT
 */

import {
  aesGcmDecrypt,
  ed25519PublicRaw,
  ed25519Sign,
  ed25519Verify,
  hkdfSha256,
  importEd25519Private,
  importEd25519Public,
  importX25519Private,
  importX25519Public,
  sha256,
  WRAP_INFO,
  x25519,
} from "./crypto.ts";

const U32_MAX = 0xffffffff;
const I64_MIN = -(1n << 63n);
const I64_MAX = (1n << 63n) - 1n;

/**
 * Writer for the canonical encoding (SPEC 4.1). Each method appends one item and returns the writer;
 * {@link CeWriter.finish} returns the concatenation.
 */
export class CeWriter {
  private readonly parts: Buffer[] = [];

  /**
   * Appends `tag(label)`: the UTF-8 bytes of `label`, then one `0x00` byte.
   *
   * @param label - The domain label; it MUST NOT contain `0x00`.
   * @throws If the label contains `0x00`.
   */
  tag(label: string): this {
    const b = Buffer.from(label, "utf8");
    if (b.includes(0)) {
      throw new Error("CE tag label must not contain 0x00");
    }
    this.parts.push(b, Buffer.from([0]));
    return this;
  }

  /**
   * Appends `bytes(b)`: `u32BE(len(b)) || b`.
   *
   * @param b - The raw bytes.
   * @throws RangeError if `b` is longer than `2^32 - 1` bytes.
   */
  bytes(b: Uint8Array): this {
    this.count(b.length);
    this.parts.push(Buffer.from(b));
    return this;
  }

  /**
   * Appends `str(s)`: `bytes(UTF8(s))`.
   *
   * @param s - The string.
   */
  str(s: string): this {
    return this.bytes(Buffer.from(s, "utf8"));
  }

  /**
   * Appends `i64(n)`: the 8-byte big-endian two's-complement encoding of `n`.
   *
   * @param n - The integer. A `number` must be a safe integer, so that it is exact.
   * @throws RangeError if `n` is not an exact integer in the signed 64-bit range.
   */
  i64(n: bigint | number): this {
    if (typeof n === "number" && !Number.isSafeInteger(n)) {
      throw new RangeError(`CE i64 needs a safe integer, got ${n}`);
    }
    const v = BigInt(n);
    if (v < I64_MIN || v > I64_MAX) {
      throw new RangeError(`CE i64 out of range: ${v}`);
    }
    const b = Buffer.alloc(8);
    b.writeBigInt64BE(v, 0);
    this.parts.push(b);
    return this;
  }

  /**
   * Appends `bool(b)`: one byte, `0x00` for false and `0x01` for true.
   *
   * @param b - The boolean.
   */
  bool(b: boolean): this {
    this.parts.push(Buffer.from([b ? 1 : 0]));
    return this;
  }

  /**
   * Appends `count(n)`: `u32BE(n)`.
   *
   * @param n - The count.
   * @throws RangeError if `n` is not an integer in `[0, 2^32 - 1]`.
   */
  count(n: number): this {
    if (!Number.isInteger(n) || n < 0 || n > U32_MAX) {
      throw new RangeError(`CE count out of range: ${n}`);
    }
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n, 0);
    this.parts.push(b);
    return this;
  }

  /** @returns The concatenated CE byte string. */
  finish(): Buffer {
    return Buffer.concat(this.parts);
  }
}

/**
 * Returns `items` sorted by `key` compared as unsigned bytes (SPEC 2), throwing if two items share a
 * key (a duplicate makes the wire form malformed, SPEC 4.2 and 4.3).
 */
function sortedUnique<T>(items: readonly T[], key: (t: T) => Buffer, what: string): T[] {
  const out = [...items].sort((a, b) => Buffer.compare(key(a), key(b)));
  for (let i = 1; i < out.length; i++) {
    if (key(out[i - 1]).equals(key(out[i]))) {
      throw new Error(`duplicate ${what}`);
    }
  }
  return out;
}

// ─── Manifest state (SPEC 4.2) ──────────────────────────────────────────────────────

/** A data key wrapped to one member (SPEC 4.4), with raw binary fields. */
export interface WrappedKey {
  schemeId: string;
  ephemeralPublicKey: Buffer;
  iv: Buffer;
  ciphertext: Buffer;
}

/** A host that replicates the repository (SPEC 4.2). */
export interface HostRef {
  hostKey: Buffer;
  locator: string;
}

/** A member entry as the owner signed it (SPEC 4.2). */
export interface MemberEntry {
  ed25519PublicKey: Buffer;
  x25519PublicKey: Buffer;
  wrappedDataKey: WrappedKey;
  keyEpoch: number;
  homeHostKey: Buffer;
}

/** A removed member and its signed removal cutoff (SPEC 4.2, 7.3). */
export interface Removal {
  memberKey: Buffer;
  removedAtSeq: number;
  frontier: Buffer[];
}

/** One manifest state (SPEC 4.2), field names as in the proto, in camelCase. */
export interface ManifestState {
  repoId: string;
  manifestSeq: number;
  prevManifestHash: Buffer;
  ownerKey: Buffer;
  genesisNonce: Buffer;
  schemeId: string;
  keyEpoch: number;
  shareRefreshTokens: boolean;
  hosts: HostRef[];
  members: MemberEntry[];
  removals: Removal[];
}

/** A manifest state with its owner signature (SPEC 4.2). */
export interface SignedManifest {
  state: ManifestState;
  ownerSignature: Buffer;
}

/**
 * The canonical bytes `S` of a manifest state (SPEC 4.2). Hosts are sorted by `hostKey`, members by
 * `ed25519PublicKey`, removals by `memberKey`, and each frontier by commit id, so the input order of
 * every list does not matter.
 *
 * @param s - The state.
 * @returns `S`.
 * @throws If any list holds the same key twice.
 */
export function encodeManifestState(s: ManifestState): Buffer {
  const w = new CeWriter()
    .tag("avp/manifest/v1")
    .str(s.repoId)
    .i64(s.manifestSeq)
    .bytes(s.prevManifestHash)
    .bytes(s.ownerKey)
    .bytes(s.genesisNonce)
    .str(s.schemeId)
    .i64(s.keyEpoch)
    .bool(s.shareRefreshTokens);

  const hosts = sortedUnique(s.hosts, (h) => h.hostKey, "hostKey");
  w.count(hosts.length);
  for (const h of hosts) w.bytes(h.hostKey).str(h.locator);

  const members = sortedUnique(s.members, (m) => m.ed25519PublicKey, "member ed25519PublicKey");
  w.count(members.length);
  for (const m of members) {
    w.bytes(m.ed25519PublicKey)
      .bytes(m.x25519PublicKey)
      .str(m.wrappedDataKey.schemeId)
      .bytes(m.wrappedDataKey.ephemeralPublicKey)
      .bytes(m.wrappedDataKey.iv)
      .bytes(m.wrappedDataKey.ciphertext)
      .i64(m.keyEpoch)
      .bytes(m.homeHostKey);
  }

  const removals = sortedUnique(s.removals, (r) => r.memberKey, "removal memberKey");
  w.count(removals.length);
  for (const r of removals) {
    w.bytes(r.memberKey).i64(r.removedAtSeq);
    const frontier = sortedUnique(r.frontier, (id) => id, "frontier commit id");
    w.count(frontier.length);
    for (const id of frontier) w.bytes(id);
  }
  return w.finish();
}

/**
 * Signs a manifest state with the owner key (SPEC 4.2): `ownerSignature = Ed25519-Sign(ownerKey, S)`.
 *
 * @param s - The state.
 * @param ownerSeed - The owner's 32-byte Ed25519 seed (`ed25519Seed` of SPEC 3.1).
 * @returns The signed manifest.
 */
export function signManifest(s: ManifestState, ownerSeed: Buffer): SignedManifest {
  return { state: s, ownerSignature: ed25519Sign(importEd25519Private(ownerSeed), encodeManifestState(s)) };
}

/**
 * `manifestHash = SHA-256(S || ownerSignature)` (SPEC 4.2), the raw 64-byte signature appended with no
 * length prefix.
 *
 * @param m - The signed manifest.
 * @returns The 32-byte manifest hash.
 * @throws If the signature is not 64 bytes.
 */
export function manifestHash(m: SignedManifest): Buffer {
  if (m.ownerSignature.length !== 64) {
    throw new Error(`ownerSignature must be 64 bytes, got ${m.ownerSignature.length}`);
  }
  return sha256(encodeManifestState(m.state), m.ownerSignature);
}

/**
 * The repository id (SPEC 4.2):
 * `base64url-nopad(SHA-256(CE(tag "avp/repo-id/v1", bytes(ownerKey), bytes(genesisNonce)))[0..16])`.
 *
 * @param ownerKey - The 32-byte owner Ed25519 public key.
 * @param nonce - The 16-byte genesis nonce.
 * @returns The 22-character repoId.
 * @throws If an input has the wrong length.
 */
export function deriveRepoId(ownerKey: Buffer, nonce: Buffer): string {
  if (ownerKey.length !== 32) throw new Error(`ownerKey must be 32 bytes, got ${ownerKey.length}`);
  if (nonce.length !== 16) throw new Error(`genesisNonce must be 16 bytes, got ${nonce.length}`);
  const ce = new CeWriter().tag("avp/repo-id/v1").bytes(ownerKey).bytes(nonce).finish();
  return sha256(ce).subarray(0, 16).toString("base64url");
}

// ─── Commit and AAD v2 (SPEC 4.3) ───────────────────────────────────────────────────

/** The fields of a commit that its header covers (SPEC 4.3). */
export interface CommitHeader {
  repoId: string;
  parents: Buffer[];
  manifestSeq: number;
  manifestHash: Buffer;
  keyEpoch: number;
  author: Buffer;
  iv: Buffer;
  ciphertext: Buffer;
}

/** A full commit (SPEC 4.3), field names as in the proto, in camelCase. */
export interface Commit extends CommitHeader {
  commitId: Buffer;
  authorSignature: Buffer;
}

/**
 * The commit header bytes `H` (SPEC 4.3), parents sorted.
 *
 * @param c - The header fields.
 * @returns `H`.
 * @throws If a parent id appears twice.
 */
export function encodeCommitHeader(c: CommitHeader): Buffer {
  const parents = sortedUnique(c.parents, (p) => p, "parent id");
  const w = new CeWriter().tag("avp/commit/v1").str(c.repoId).count(parents.length);
  for (const p of parents) w.bytes(p);
  return w
    .i64(c.manifestSeq)
    .bytes(c.manifestHash)
    .i64(c.keyEpoch)
    .bytes(c.author)
    .bytes(c.iv)
    .bytes(c.ciphertext)
    .finish();
}

/**
 * `commitId = SHA-256(H)` (SPEC 4.3).
 *
 * @param c - The header fields.
 * @returns The 32-byte commit id.
 */
export function commitId(c: CommitHeader): Buffer {
  return sha256(encodeCommitHeader(c));
}

/**
 * The message the author signs (SPEC 4.3): `CE(tag "avp/commit-sig/v1", bytes(commitId))`.
 *
 * @param id - The 32-byte commit id.
 * @returns The signature message.
 * @throws If `id` is not 32 bytes.
 */
export function commitSigMessage(id: Buffer): Buffer {
  if (id.length !== 32) throw new Error(`commitId must be 32 bytes, got ${id.length}`);
  return new CeWriter().tag("avp/commit-sig/v1").bytes(id).finish();
}

/**
 * Builds a full commit from its header: computes `commitId` and the author signature (SPEC 4.3).
 *
 * @param h - The header fields.
 * @param authorSeed - The author's 32-byte Ed25519 seed.
 * @returns The commit.
 */
export function signCommit(h: CommitHeader, authorSeed: Buffer): Commit {
  const id = commitId(h);
  return { ...h, commitId: id, authorSignature: ed25519Sign(importEd25519Private(authorSeed), commitSigMessage(id)) };
}

/**
 * The payload additional authenticated data, AAD v2 (SPEC 4.3), parents sorted.
 *
 * @param repoId - The repository id.
 * @param keyEpoch - The data key epoch.
 * @param author - The author's 32-byte Ed25519 public key.
 * @param parents - The parent commit ids, in any order.
 * @returns The AAD bytes.
 * @throws If a parent id appears twice.
 */
export function buildAadV2(repoId: string, keyEpoch: number, author: Buffer, parents: Buffer[]): Buffer {
  const sorted = sortedUnique(parents, (p) => p, "parent id");
  const w = new CeWriter().tag("avp/aad/v2").str(repoId).i64(keyEpoch).bytes(author).count(sorted.length);
  for (const p of sorted) w.bytes(p);
  return w.finish();
}

// ─── Signed messages: acceptance and leave (SPEC 11.3, 11.4) ────────────────────────

/** Verifies an Ed25519 signature, mapping every malformed key or signature to `false`. */
function safeVerify(publicKey: Buffer, message: Buffer, signature: Buffer): boolean {
  try {
    if (!Buffer.isBuffer(publicKey) || publicKey.length !== 32) return false;
    if (!Buffer.isBuffer(signature) || signature.length !== 64) return false;
    return ed25519Verify(importEd25519Public(publicKey), message, signature);
  } catch {
    return false;
  }
}

/** A host's signed agreement to carry a repository for one joining member (SPEC 8.2, 11.3). */
export interface Acceptance {
  repoId: string;
  memberKey: Buffer;
  hostKey: Buffer;
  expiresAt: number;
  signature: Buffer;
}

/**
 * The message a host signs for an acceptance (SPEC 11.3):
 * `CE(tag "avp/accept/v1", str(repoId), bytes(memberKey), bytes(hostKey), i64(expiresAt))`.
 */
export function acceptanceSignMessage(a: Omit<Acceptance, "signature">): Buffer {
  return new CeWriter().tag("avp/accept/v1").str(a.repoId).bytes(a.memberKey).bytes(a.hostKey).i64(a.expiresAt).finish();
}

/**
 * Signs an acceptance with the host key.
 *
 * @param a - The acceptance fields; `a.hostKey` MUST be the public key of `hostSeed`.
 * @param hostSeed - The host's 32-byte Ed25519 seed.
 */
export function signAcceptance(a: Omit<Acceptance, "signature">, hostSeed: Buffer): Acceptance {
  return { ...a, signature: ed25519Sign(importEd25519Private(hostSeed), acceptanceSignMessage(a)) };
}

/**
 * Whether `a.signature` verifies under `hostKey` over {@link acceptanceSignMessage}. Never throws.
 *
 * @param a - The acceptance.
 * @param hostKey - The key to verify under (the owner client passes the acceptance's own hostKey,
 *   after matching it to the invite token's homeHostKey).
 */
export function verifyAcceptance(a: Acceptance, hostKey: Buffer): boolean {
  try {
    return safeVerify(hostKey, acceptanceSignMessage(a), a.signature);
  } catch {
    return false;
  }
}

/** A member's signed request to leave a repository (SPEC 8.4, 11.4). */
export interface LeaveRequest {
  repoId: string;
  memberKey: Buffer;
  at: number;
  signature: Buffer;
}

/** The message a leaving member signs (SPEC 11.4): `CE(tag "avp/leave/v1", str(repoId), bytes(memberKey), i64(at))`. */
export function leaveSignMessage(l: Omit<LeaveRequest, "signature">): Buffer {
  return new CeWriter().tag("avp/leave/v1").str(l.repoId).bytes(l.memberKey).i64(l.at).finish();
}

/**
 * Signs a leave request with the member key.
 *
 * @param l - The leave fields; `l.memberKey` MUST be the public key of `memberSeed`.
 * @param memberSeed - The member's 32-byte Ed25519 seed.
 */
export function signLeave(l: Omit<LeaveRequest, "signature">, memberSeed: Buffer): LeaveRequest {
  return { ...l, signature: ed25519Sign(importEd25519Private(memberSeed), leaveSignMessage(l)) };
}

/** Whether `l.signature` verifies under `l.memberKey` (SPEC 8.4). Never throws. */
export function verifyLeave(l: LeaveRequest): boolean {
  try {
    return safeVerify(l.memberKey, leaveSignMessage(l), l.signature);
  } catch {
    return false;
  }
}

// ─── Challenge transcript (SPEC 3.3) ─────────────────────────────────────────────────

/**
 * The message a client signs to redeem a challenge (SPEC 3.3):
 * `CE(tag "avp/challenge/v1", bytes(hostKey), bytes(ed25519PublicKey), bytes(nonce))`.
 *
 * The tag keeps a host-chosen nonce from ever making this equal another signed construction
 * (SPEC 4.1), and `hostKey` binds the signature to the host being authenticated to.
 *
 * @param hostKey - The 32-byte host key of the host the client authenticates to.
 * @param ed25519PublicKey - The 32-byte key requesting the token.
 * @param nonce - The raw (base64-decoded) nonce bytes.
 * @returns The signature message.
 * @throws If either key is not 32 bytes.
 */
export function challengeMessage(hostKey: Buffer, ed25519PublicKey: Buffer, nonce: Buffer): Buffer {
  if (hostKey.length !== 32) throw new Error(`hostKey must be 32 bytes, got ${hostKey.length}`);
  if (ed25519PublicKey.length !== 32) throw new Error(`ed25519PublicKey must be 32 bytes, got ${ed25519PublicKey.length}`);
  return new CeWriter().tag("avp/challenge/v1").bytes(hostKey).bytes(ed25519PublicKey).bytes(nonce).finish();
}

/**
 * Signs the challenge transcript of SPEC 3.3 for the key of `seed`.
 *
 * @param hostKey - The 32-byte host key of the host the client authenticates to.
 * @param seed - The 32-byte Ed25519 seed of the key requesting the token.
 * @param nonce - The raw nonce bytes.
 * @returns The 64-byte signature.
 */
export function signChallenge(hostKey: Buffer, seed: Buffer, nonce: Buffer): Buffer {
  const priv = importEd25519Private(seed);
  return ed25519Sign(priv, challengeMessage(hostKey, ed25519PublicRaw(priv), nonce));
}

/**
 * Whether `signature` verifies under `ed25519PublicKey` over {@link challengeMessage} built with
 * `hostKey` (the verifying host's own key, SPEC 3.3). Never throws.
 */
export function verifyChallenge(hostKey: Buffer, ed25519PublicKey: Buffer, nonce: Buffer, signature: Buffer): boolean {
  try {
    return safeVerify(ed25519PublicKey, challengeMessage(hostKey, ed25519PublicKey, nonce), signature);
  } catch {
    return false;
  }
}

// ─── Fingerprints and device linking (SPEC 3.2, 11.2, 11.6) ─────────────────────────

/** The HKDF info and GCM AAD label of a link grant (SPEC 11.6). */
export const OWNER_LINK_INFO = Buffer.from("avp/owner-link/v1", "utf8");

/**
 * The member key fingerprint (SPEC 3.2): `hex(SHA-256(ed25519 || x25519)[0..8])` as
 * `xxxx-xxxx-xxxx-xxxx`.
 */
export function keyFingerprint(ed25519PublicKey: Buffer, x25519PublicKey: Buffer): string {
  const h = sha256(ed25519PublicKey, x25519PublicKey).subarray(0, 8).toString("hex");
  return [0, 4, 8, 12].map((i) => h.slice(i, i + 4)).join("-");
}

/** The owner fingerprint of a repo locator (SPEC 11.2): `hex(SHA-256(ownerKey)[0..8])`. */
export function ownerFingerprint(ownerKey: Buffer): string {
  return sha256(ownerKey).subarray(0, 8).toString("hex");
}

/**
 * The link confirmation code (SPEC 11.6): the first 4 bytes of
 * `SHA-256(CE(tag "avp/link-code/v1", bytes(ephemeralPublicKey)))` as `u32BE`, modulo 1 000 000,
 * written as 6 decimal digits with leading zeros.
 */
export function linkConfirmationCode(ephemeralPublic: Buffer): string {
  const d = sha256(new CeWriter().tag("avp/link-code/v1").bytes(ephemeralPublic).finish());
  return String(d.readUInt32BE(0) % 1_000_000).padStart(6, "0");
}

/**
 * Unwraps a secret wrapped with the default wrap scheme (SPEC 4.4) under the given label.
 *
 * @param recipientPrivRaw - The recipient's raw 32-byte X25519 private key.
 * @param w - The wrapped key.
 * @param info - The label, bound as both the HKDF info and the GCM AAD.
 * @returns The secret.
 * @throws If the wrap does not authenticate (wrong key, wrong label, or tampered bytes).
 */
export function unwrapSecret(recipientPrivRaw: Buffer, w: WrappedKey, info: Buffer = WRAP_INFO): Buffer {
  const shared = x25519(importX25519Private(recipientPrivRaw), importX25519Public(w.ephemeralPublicKey));
  const kek = hkdfSha256(shared, w.ephemeralPublicKey, info, 32);
  return aesGcmDecrypt(kek, w.iv, info, w.ciphertext);
}

// ─── Out-of-band tokens (SPEC 11.1) ─────────────────────────────────────────────────

/** Wire `Acceptance` (base64 binary). */
export interface WireAcceptance {
  repoId: string;
  memberKey: string;
  hostKey: string;
  expiresAt: number;
  signature: string;
}

/** Wire `WrappedKey` (base64 binary). */
export interface WireWrappedKey {
  schemeId: string;
  ephemeralPublicKey: string;
  iv: string;
  ciphertext: string;
}

/** `InviteToken`, joiner to owner (SPEC 11.3). */
export interface WireInviteToken {
  v: 2;
  ed25519PublicKey: string;
  x25519PublicKey: string;
  homeHostKey: string;
  homeHostLocator: string;
  acceptance: WireAcceptance;
}

/** `RepoLocator`, owner to joiner (SPEC 11.2). */
export interface WireRepoLocator {
  v: 2;
  repoId: string;
  hostKey: string;
  hostLocator: string;
  ownerFingerprint: string;
}

/** `LinkRequest`, new owner device (SPEC 11.6). */
export interface WireLinkRequest {
  v: 2;
  ephemeralPublicKey: string;
}

/** `LinkGrant`, existing owner device (SPEC 11.6). */
export interface WireLinkGrant {
  v: 2;
  wrap: WireWrappedKey;
}

/** The token kinds of SPEC 11, named as their schema `$defs`. */
export type TokenKind = "InviteToken" | "RepoLocator" | "LinkRequest" | "LinkGrant";

/** A token that failed to decode: not base64url-nopad, not a JSON object, `v` not 2, or a field missing or mistyped. */
export class TokenError extends Error {}

type FieldType = "string" | "base64" | "int" | { object: Spec };
type Spec = ReadonlyArray<readonly [string, FieldType]>;

const ACCEPTANCE_SPEC: Spec = [
  ["repoId", "string"],
  ["memberKey", "base64"],
  ["hostKey", "base64"],
  ["expiresAt", "int"],
  ["signature", "base64"],
];
const WRAP_SPEC: Spec = [
  ["schemeId", "string"],
  ["ephemeralPublicKey", "base64"],
  ["iv", "base64"],
  ["ciphertext", "base64"],
];
/** Field order of each token as SPEC 11 lists it (the `v` is checked separately). */
const TOKEN_SPECS: Record<TokenKind, Spec> = {
  InviteToken: [
    ["ed25519PublicKey", "base64"],
    ["x25519PublicKey", "base64"],
    ["homeHostKey", "base64"],
    ["homeHostLocator", "string"],
    ["acceptance", { object: ACCEPTANCE_SPEC }],
  ],
  RepoLocator: [
    ["repoId", "string"],
    ["hostKey", "base64"],
    ["hostLocator", "string"],
    ["ownerFingerprint", "string"],
  ],
  LinkRequest: [["ephemeralPublicKey", "base64"]],
  LinkGrant: [["wrap", { object: WRAP_SPEC }]],
};

const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const BASE64URL_NOPAD = /^[A-Za-z0-9_-]*$/;

/** Rebuilds `o` with exactly the fields of `spec`, in order, checking each type. */
function shape(o: unknown, spec: Spec, where: string): Record<string, unknown> {
  if (o === null || typeof o !== "object" || Array.isArray(o)) throw new TokenError(`${where} is not a JSON object`);
  const src = o as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const [name, type] of spec) {
    const v = src[name];
    if (type === "string") {
      if (typeof v !== "string") throw new TokenError(`${where}.${name} must be a string`);
      out[name] = v;
    } else if (type === "base64") {
      if (typeof v !== "string" || !BASE64.test(v)) throw new TokenError(`${where}.${name} must be base64`);
      out[name] = v;
    } else if (type === "int") {
      if (typeof v !== "number" || !Number.isSafeInteger(v)) throw new TokenError(`${where}.${name} must be an integer`);
      out[name] = v;
    } else {
      out[name] = shape(v, type.object, `${where}.${name}`);
    }
  }
  return out;
}

/** Validates a token object and returns it with its fields in the listed order, `v` first. */
function normalizeToken(kind: TokenKind, o: unknown): Record<string, unknown> {
  if (o === null || typeof o !== "object" || Array.isArray(o)) throw new TokenError(`${kind} is not a JSON object`);
  if ((o as Record<string, unknown>).v !== 2) throw new TokenError(`${kind} v must be 2`);
  return { v: 2, ...shape(o, TOKEN_SPECS[kind], kind) };
}

/**
 * Encodes a token (SPEC 11.1): base64url-nopad over compact JSON with the fields in the listed order.
 *
 * @param kind - The token kind.
 * @param token - The token object, fields in any order.
 * @throws {TokenError} If the object is not a valid token of that kind.
 */
export function encodeToken(kind: TokenKind, token: object): string {
  return Buffer.from(JSON.stringify(normalizeToken(kind, token)), "utf8").toString("base64url");
}

/**
 * Decodes a token (SPEC 11.1). Accepts any field order and insignificant whitespace, ignores unknown
 * fields, and rejects a token whose `v` is not `2`.
 *
 * @param kind - The expected token kind.
 * @param s - The base64url-nopad text.
 * @returns The token with its fields in the listed order.
 * @throws {TokenError} If the text is not a valid token of that kind.
 */
export function decodeToken(kind: TokenKind, s: string): Record<string, unknown> {
  if (typeof s !== "string" || !BASE64URL_NOPAD.test(s) || s.length % 4 === 1) throw new TokenError("not base64url-nopad");
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(s, "base64url").toString("utf8"));
  } catch {
    throw new TokenError("not JSON");
  }
  return normalizeToken(kind, parsed);
}

/** Decodes an `InviteToken` (SPEC 11.3). @throws {TokenError} */
export const decodeInviteToken = (s: string) => decodeToken("InviteToken", s) as unknown as WireInviteToken;
/** Decodes a `RepoLocator` (SPEC 11.2). @throws {TokenError} */
export const decodeRepoLocator = (s: string) => decodeToken("RepoLocator", s) as unknown as WireRepoLocator;
/** Decodes a `LinkRequest` (SPEC 11.6). @throws {TokenError} */
export const decodeLinkRequest = (s: string) => decodeToken("LinkRequest", s) as unknown as WireLinkRequest;
/** Decodes a `LinkGrant` (SPEC 11.6). @throws {TokenError} */
export const decodeLinkGrant = (s: string) => decodeToken("LinkGrant", s) as unknown as WireLinkGrant;

/**
 * The owner client's check of an invite token before it adds a member or a host (SPEC 8.2): the
 * acceptance signature verifies under its hostKey, its repoId is the repository's, its memberKey is
 * the token's ed25519PublicKey, its hostKey is the token's homeHostKey, and it has not expired.
 * Never throws.
 *
 * @param t - The decoded invite token.
 * @param repoId - The repository the owner is inviting to.
 * @param nowMs - The owner client's current time.
 */
export function verifyInvite(t: WireInviteToken, repoId: string, nowMs: number): boolean {
  try {
    const a = t.acceptance;
    const acc: Acceptance = {
      repoId: a.repoId,
      memberKey: Buffer.from(a.memberKey, "base64"),
      hostKey: Buffer.from(a.hostKey, "base64"),
      expiresAt: a.expiresAt,
      signature: Buffer.from(a.signature, "base64"),
    };
    // Keys are compared as decoded bytes, not as their base64 text (SPEC 3.3: hosts match by key).
    return (
      verifyAcceptance(acc, acc.hostKey) &&
      a.repoId === repoId &&
      acc.memberKey.equals(Buffer.from(t.ed25519PublicKey, "base64")) &&
      acc.hostKey.equals(Buffer.from(t.homeHostKey, "base64")) &&
      a.expiresAt > nowMs
    );
  } catch {
    return false;
  }
}
