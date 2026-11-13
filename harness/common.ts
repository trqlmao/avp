/**
 * The client-side parties and constructions shared by the black-box harnesses (`conformance.ts`, one
 * host; `multihost.ts`, replication between hosts).
 *
 * Every body is built with the vector-tested constructions re-exported by ./crypto.ts, from real keys
 * and real signatures. Nothing here talks to a host.
 *
 * Illustrative reference code, not production. SPDX-License-Identifier: MIT
 */

import { randomBytes, randomUUID } from "node:crypto";

import {
  aesGcmEncrypt,
  buildAadV2,
  commitFromWire,
  commitId,
  commitSigMessage,
  commitToWire,
  deriveRepoId,
  ed25519PublicRaw,
  ed25519Verify,
  entropyToMnemonic,
  importEd25519Private,
  importEd25519Public,
  importX25519Private,
  manifestHash,
  mnemonicToSeed,
  ownerKeysFromSeed,
  signCommit,
  signedManifestFromWire,
  signedManifestToWire,
  WRAP_SCHEME_ID,
  wrapSecret,
  x25519PublicRaw,
  type Commit,
  type CommitHeader,
  type HostRef,
  type ManifestState,
  type MemberEntry,
  type PayloadV2,
  type SignedManifest,
  type WireCommit,
  type WireSignedManifest,
} from "./crypto.ts";

// ─── Parties ──────────────────────────────────────────────────────────────────────────

export interface Party {
  name: string;
  seed: Buffer;
  pub: Buffer;
  xPriv: Buffer;
  xPub: Buffer;
  token: string;
}

export function newParty(name: string, seed: Buffer = randomBytes(32), xPriv: Buffer = randomBytes(32)): Party {
  return {
    name,
    seed,
    pub: ed25519PublicRaw(importEd25519Private(seed)),
    xPriv,
    xPub: x25519PublicRaw(importX25519Private(xPriv)),
    token: "",
  };
}

/** The owner, whose keys derive from a fresh 24-word BIP39 phrase (SPEC 3.1). */
export function newOwner(name: string): Party {
  const keys = ownerKeysFromSeed(mnemonicToSeed(entropyToMnemonic(randomBytes(32))));
  return newParty(name, keys.ed25519Seed, keys.x25519Private);
}

export const b64 = (b: Buffer) => b.toString("base64");

export function wrapTo(p: Party, dataKey: Buffer) {
  return wrapSecret(p.xPub, randomBytes(32), randomBytes(12), dataKey);
}

export function memberOf(p: Party, dataKey: Buffer, keyEpoch: number, homeHostKey: Buffer): MemberEntry {
  return { ed25519PublicKey: p.pub, x25519PublicKey: p.xPub, wrappedDataKey: wrapTo(p, dataKey), keyEpoch, homeHostKey };
}

/** A payload v2 holding one account whose `accessToken` is the plaintext marker (SPEC 5). */
export function payloadWith(marker: string, by: Party): Buffer {
  const at = Date.now();
  const stamp = { at, n: 0, by: b64(by.pub) };
  const p: PayloadV2 = {
    v: 2,
    accounts: {
      [randomUUID()]: {
        fields: {
          username: { value: `harness-${marker}`, ...stamp },
          accessToken: { value: marker, ...stamp },
          type: { value: "OFFLINE", ...stamp },
        },
        bans: {},
      },
    },
  };
  return Buffer.from(JSON.stringify(p), "utf8");
}

// ─── Commits and manifest states ──────────────────────────────────────────────────────

export interface CommitSpec {
  repoId: string;
  author: Party;
  parents: Buffer[];
  manifest: SignedManifest;
  dataKey: Buffer;
  keyEpoch?: number;
  plaintext: Buffer;
}

/** A commit encrypted under AAD v2 and signed by its author (SPEC 4.3). */
export function makeCommit(c: CommitSpec): Commit {
  const keyEpoch = c.keyEpoch ?? c.manifest.state.keyEpoch;
  const iv = randomBytes(12);
  const aad = buildAadV2(c.repoId, keyEpoch, c.author.pub, c.parents);
  const header: CommitHeader = {
    repoId: c.repoId,
    parents: c.parents,
    manifestSeq: c.manifest.state.manifestSeq,
    manifestHash: manifestHash(c.manifest),
    keyEpoch,
    author: c.author.pub,
    iv,
    ciphertext: aesGcmEncrypt(c.dataKey, iv, aad, c.plaintext),
  };
  return signCommit(header, c.author.seed);
}

export function genesisState(owner: Party, dataKey: Buffer, hosts: HostRef[], home: Buffer, nonce = randomBytes(16)): ManifestState {
  return {
    repoId: deriveRepoId(owner.pub, nonce),
    manifestSeq: 1,
    prevManifestHash: Buffer.alloc(0),
    ownerKey: owner.pub,
    genesisNonce: nonce,
    schemeId: WRAP_SCHEME_ID,
    keyEpoch: 0,
    shareRefreshTokens: false,
    hosts,
    members: [memberOf(owner, dataKey, 0, home)],
    removals: [],
  };
}

/** The next state after `prev`, with the given changes (SPEC 4.2, 6.1). */
export function nextState(prev: SignedManifest, change: Partial<ManifestState>): ManifestState {
  return {
    ...prev.state,
    manifestSeq: prev.state.manifestSeq + 1,
    prevManifestHash: manifestHash(prev),
    genesisNonce: Buffer.alloc(0),
    ...change,
  };
}

// ─── Wire helpers ─────────────────────────────────────────────────────────────────────

export const wireM = (m: SignedManifest): WireSignedManifest => signedManifestToWire(m);
export const wireC = (c: Commit): WireCommit => commitToWire(c);
export const idsOf = (heads: unknown): string[] =>
  Array.isArray(heads) ? heads.map((h: any) => (typeof h === "string" ? h : String(h?.commitId))).sort() : [];
export const sameSet = (a: string[], b: string[]) => a.length === b.length && [...a].sort().every((x, i) => x === [...b].sort()[i]);

export function hashOfWire(w: WireSignedManifest): string {
  return b64(manifestHash(signedManifestFromWire(w)));
}

/** Whether a served commit verifies on the client's own terms (SPEC 7.5 step 1). */
export function verifiesAsCommit(w: WireCommit): boolean {
  const c = commitFromWire(w);
  if (!commitId(c).equals(c.commitId)) return false;
  return ed25519Verify(importEd25519Public(c.author), commitSigMessage(c.commitId), c.authorSignature);
}
