/**
 * Deterministic byte constructions of AVP 0.5 (SPEC section 4):
 *
 *   - the canonical encoding (CE) writer (SPEC 4.1),
 *   - the manifest state bytes, owner signature, manifestHash, and repoId (SPEC 4.2),
 *   - the commit header, commitId, author signature message, and AAD v2 (SPEC 4.3).
 *
 * They are checked byte-for-byte against `vectors/manifest.json` and `vectors/commit.json`. Binary
 * fields are raw bytes (`Buffer`); the wire base64 is decoded before it reaches these functions.
 *
 * Illustrative reference code, not production. SPDX-License-Identifier: MIT
 */

import { ed25519Sign, importEd25519Private, sha256 } from "./crypto.ts";

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
