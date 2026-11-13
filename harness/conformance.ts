/**
 * AVP 0.5 black-box conformance harness, single host (HTTP/JSON profile).
 *
 * Point it at one running AVP host and it drives the client wire contract end to end, asserting the
 * SPEC MUSTs with the exact status and `code` of the SPEC 10.4 error table:
 *
 *   - discovery and host-issued authentication, including every challenge failure mode (expired,
 *     reused, not issued for the key, bad signature) and strict Ed25519 (SPEC 2, 3.3, 11.7);
 *   - createRepo: wrong repoId, host not listed, caller not the owner, bad genesis, duplicate
 *     (SPEC 6.1, 6.2, 8.2);
 *   - the manifest chain: publication at tip + 1 only, content rules, and pull returning the chain
 *     from `sinceManifestSeq` (SPEC 6.1, 6.3, 10.1);
 *   - the commit graph: id, signature, author, epoch, manifest binding, missing parents, concurrent
 *     pushes giving two heads with no conflict outcome, a merge collapsing heads, and the head bound
 *     (SPEC 7.1, 7.2, 7.4, 10.1);
 *   - removal: rotation atomicity, the removal cutoff dropping commits outside the frontier and
 *     their descendants (SPEC 7.3, 8.3);
 *   - leave round-trip, prepareJoin acceptances verified against the discovered host key, a host
 *     dropped from `hosts` (SPEC 8.2, 8.4, 8.6);
 *   - zero-knowledge: a plaintext marker never appears in any response (SPEC 13).
 *
 * Every body is built with the vector-tested constructions re-exported by ./crypto.ts, from real
 * keys and real signatures. The harness is server-agnostic: it knows only the wire contract.
 *
 *   bun conformance.ts --server http://127.0.0.1:19101
 *   AVP_SERVER_URL=http://127.0.0.1:19101 bun conformance.ts
 *
 * Options: `--challenge-ttl-ms N` (the host's challenge lifetime, default 120000, the SPEC 3.3
 * RECOMMENDED maximum; the expired-nonce check waits this long plus a margin), `--head-bound N` (the
 * host's head bound, default 16, the SPEC 7.4 RECOMMENDED value), `--startup-timeout-ms N` (how long
 * to wait for `/.well-known/avp`, default 30000), `--request-timeout-ms N` (how long one request may
 * take before the run fails, default 30000, so a hanging host fails instead of hanging the run).
 *
 * Exit code is 0 only if every check passes. SPDX-License-Identifier: MIT
 */

import { randomBytes, randomUUID } from "node:crypto";

import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  buildAadV2,
  commitFromWire,
  commitId,
  commitSigMessage,
  commitToWire,
  deriveRepoId,
  ed25519PublicRaw,
  ed25519Sign,
  sha512,
  ed25519Verify,
  decodeInviteToken,
  encodeToken,
  acceptanceToWire,
  entropyToMnemonic,
  importEd25519Private,
  importEd25519Public,
  importX25519Private,
  leaveFromWire,
  leaveToWire,
  manifestHash,
  mnemonicToSeed,
  ownerKeysFromSeed,
  signCommit,
  signLeave,
  signManifest,
  signedManifestFromWire,
  signedManifestToWire,
  unwrapSecret,
  verifyAcceptance,
  verifyInvite,
  verifyLeave,
  WRAP_SCHEME_ID,
  wrapSecret,
  x25519PublicRaw,
  type Acceptance,
  type Commit,
  type CommitHeader,
  type HostRef,
  type ManifestState,
  type MemberEntry,
  type PayloadV2,
  type Removal,
  type SignedManifest,
  type WireCommit,
  type WireInviteToken,
  type WireLeaveRequest,
  type WireSignedManifest,
} from "./crypto.ts";

// ─── Config ───────────────────────────────────────────────────────────────────────────

function flag(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i !== -1 ? process.argv[i + 1] : undefined;
}

function numberFlag(name: string, fallback: number): number {
  const raw = flag(name);
  if (raw === undefined) return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 0) throw new Error(`${name} must be a non-negative integer, got ${raw}`);
  return n;
}

const BASE_URL = (flag("--server") ?? process.env.AVP_SERVER_URL ?? "http://127.0.0.1:8787").replace(/\/$/, "");
const CHALLENGE_TTL_MS = numberFlag("--challenge-ttl-ms", 120_000);
const HEAD_BOUND = numberFlag("--head-bound", 16);
const STARTUP_TIMEOUT_MS = numberFlag("--startup-timeout-ms", 30_000);
const REQUEST_TIMEOUT_MS = numberFlag("--request-timeout-ms", 30_000);
/** Slack added to the challenge TTL before the expired nonce is redeemed. */
const EXPIRY_MARGIN_MS = 3_000;

// ─── Check framework ──────────────────────────────────────────────────────────────────

interface Result {
  section: string;
  name: string;
  ok: boolean;
  detail: string;
}

const results: Result[] = [];

/** Records one check; `detail` is shown when it fails. */
function check(section: string, name: string, ok: boolean, detail = ""): void {
  results.push({ section, name, ok, detail });
}

/** Records a check whose body may throw; a throw is a failure carrying the message. */
function checkDoes(section: string, name: string, fn: () => void): void {
  try {
    fn();
    check(section, name, true);
  } catch (err) {
    check(section, name, false, err instanceof Error ? err.message : String(err));
  }
}

// ─── HTTP ─────────────────────────────────────────────────────────────────────────────

interface Resp {
  status: number;
  body: any;
  text: string;
}

/** Every response text the host sent, scanned for the plaintext marker at the end (SPEC 13). */
const seen: string[] = [];

async function req(method: string, path: string, body?: unknown, token?: string): Promise<Resp> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token !== undefined) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
    // A host that never answers fails the run (the abort throws) instead of hanging it.
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  const text = await res.text();
  seen.push(text);
  let parsed: any = undefined;
  try {
    parsed = text ? JSON.parse(text) : undefined;
  } catch {
    parsed = undefined;
  }
  return { status: res.status, body: parsed, text };
}

const repoPath = (repoId: string, op: string) => `/v1/repos/${encodeURIComponent(repoId)}/${op}`;

function show(r: Resp): string {
  return `got ${r.status} ${r.text.slice(0, 200)}`;
}

/**
 * Asserts a SPEC 10.4 error: the exact status, and an error object whose `error` is a string and
 * whose `code` is the exact machine code of the error table.
 */
function expectError(section: string, name: string, r: Resp, status: number, code: string): void {
  const ok = r.status === status && typeof r.body?.error === "string" && r.body?.code === code;
  check(section, name, ok, `want ${status} ${code}, ${show(r)}`);
}

// ─── Parties and constructions ────────────────────────────────────────────────────────

interface Party {
  name: string;
  seed: Buffer;
  pub: Buffer;
  xPriv: Buffer;
  xPub: Buffer;
  token: string;
}

function newParty(name: string, seed: Buffer = randomBytes(32), xPriv: Buffer = randomBytes(32)): Party {
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
function newOwner(name: string): Party {
  const keys = ownerKeysFromSeed(mnemonicToSeed(entropyToMnemonic(randomBytes(32))));
  return newParty(name, keys.ed25519Seed, keys.x25519Private);
}

const b64 = (b: Buffer) => b.toString("base64");

function wrapTo(p: Party, dataKey: Buffer) {
  return wrapSecret(p.xPub, randomBytes(32), randomBytes(12), dataKey);
}

function memberOf(p: Party, dataKey: Buffer, keyEpoch: number, homeHostKey: Buffer): MemberEntry {
  return { ed25519PublicKey: p.pub, x25519PublicKey: p.xPub, wrappedDataKey: wrapTo(p, dataKey), keyEpoch, homeHostKey };
}

/** A payload v2 holding one account whose `accessToken` is the plaintext marker (SPEC 5). */
function payloadWith(marker: string, by: Party): Buffer {
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

interface CommitSpec {
  repoId: string;
  author: Party;
  parents: Buffer[];
  manifest: SignedManifest;
  dataKey: Buffer;
  keyEpoch?: number;
  plaintext: Buffer;
}

/** A commit encrypted under AAD v2 and signed by its author (SPEC 4.3). */
function makeCommit(c: CommitSpec): Commit {
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

/** Re-signs a header with another author seed, keeping the `author` field (a bad signature). */
function withForeignSignature(c: Commit, other: Party): Commit {
  return { ...c, authorSignature: ed25519Sign(importEd25519Private(other.seed), commitSigMessage(c.commitId)) };
}

/** The identity point encoding, a small-order key with no private key (SPEC 2). */
const IDENTITY_KEY = Buffer.from("0100000000000000000000000000000000000000000000000000000000000000", "hex");
/** `R` = identity, `S` = 0: verifies under the identity key for every message without the strict checks. */
const IDENTITY_FORGERY = Buffer.concat([IDENTITY_KEY, Buffer.alloc(32)]);
/** An order-8 point (SPEC 2, negative.json ed25519/order-8-key-forgery): `[k]A` is the identity when 8 divides k. */
const ORDER8_KEY = Buffer.from("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", "hex");
/** The order-8 point with the sign bit set (negative.json ed25519/order-8-sign-bit-key-forgery). */
const ORDER8_SIGN_BIT_KEY = Buffer.from("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", "hex");
/** `y = p + 1`, the non-canonical encoding of the identity (SPEC 2, negative.json ed25519/non-canonical-key). */
const NONCANONICAL_KEY = Buffer.from("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "hex");
/** The order of the edwards25519 base point (SPEC 2). */
const ED25519_L = (1n << 252n) + 27742317777372353535851937790883648493n;

const leToInt = (b: Buffer): bigint => {
  let x = 0n;
  for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]);
  return x;
};
const intToLe32 = (n: bigint): Buffer => {
  const out = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
};
/** The RFC 8032 challenge scalar `k = SHA-512(R || A || M) mod L`. */
const edChallenge = (r: Buffer, a: Buffer, m: Buffer) => leToInt(sha512(r, a, m)) % ED25519_L;

/**
 * A signature by an honest key with `R` = identity and `S = k * a mod L` (negative.json ed25519/identity-r):
 * it passes the cofactorless equation `[S]B = R + [k]A`, and strict verification rejects it because `R`
 * is small order (SPEC 2).
 */
/** The RFC 8032 secret scalar of a seed: the clamped first half of `SHA-512(seed)`. */
function secretScalar(seed: Buffer): bigint {
  const h = Buffer.from(sha512(seed).subarray(0, 32));
  h[0] &= 248;
  h[31] &= 127;
  h[31] |= 64;
  return leToInt(h);
}

function identityRSignature(p: Party, message: Buffer): Buffer {
  const s = (edChallenge(IDENTITY_KEY, p.pub, message) * secretScalar(p.seed)) % ED25519_L;
  return Buffer.concat([IDENTITY_KEY, intToLe32(s)]);
}

/** A valid signature with `L` added to `S` (negative.json ed25519/s-plus-l): `S >= L` is non-canonical (SPEC 2). */
function sPlusLSignature(p: Party, message: Buffer): Buffer {
  const sig = ed25519Sign(importEd25519Private(p.seed), message);
  return Buffer.concat([sig.subarray(0, 32), intToLe32(leToInt(sig.subarray(32)) + ED25519_L)]);
}

function genesisState(owner: Party, dataKey: Buffer, hosts: HostRef[], home: Buffer, nonce = randomBytes(16)): ManifestState {
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
function nextState(prev: SignedManifest, change: Partial<ManifestState>): ManifestState {
  return {
    ...prev.state,
    manifestSeq: prev.state.manifestSeq + 1,
    prevManifestHash: manifestHash(prev),
    genesisNonce: Buffer.alloc(0),
    ...change,
  };
}

const wireM = (m: SignedManifest): WireSignedManifest => signedManifestToWire(m);
const wireC = (c: Commit): WireCommit => commitToWire(c);
const idsOf = (heads: unknown): string[] =>
  Array.isArray(heads) ? heads.map((h: any) => (typeof h === "string" ? h : String(h?.commitId))).sort() : [];
const sameSet = (a: string[], b: string[]) => a.length === b.length && [...a].sort().every((x, i) => x === [...b].sort()[i]);

function hashOfWire(w: WireSignedManifest): string {
  return b64(manifestHash(signedManifestFromWire(w)));
}

/** Whether a served commit verifies on the client's own terms (SPEC 7.5 step 1). */
function verifiesAsCommit(w: WireCommit): boolean {
  const c = commitFromWire(w);
  if (!commitId(c).equals(c.commitId)) return false;
  return ed25519Verify(importEd25519Public(c.author), commitSigMessage(c.commitId), c.authorSignature);
}

// ─── Auth (SPEC 3.3) ──────────────────────────────────────────────────────────────────

async function challenge(key: Buffer): Promise<Resp> {
  return req("POST", "/api/auth/keypair/challenge", { ed25519PublicKey: b64(key) });
}

async function redeem(key: Buffer, nonceB64: string, signature: Buffer): Promise<Resp> {
  return req("POST", "/api/auth/keypair/token", { ed25519PublicKey: b64(key), nonce: nonceB64, signature: b64(signature) });
}

const signNonce = (p: Party, nonceB64: string) => ed25519Sign(importEd25519Private(p.seed), Buffer.from(nonceB64, "base64"));

async function login(p: Party): Promise<void> {
  const c = await challenge(p.pub);
  if (c.status !== 200 || typeof c.body?.nonce !== "string") throw new Error(`challenge for ${p.name}: ${show(c)}`);
  const t = await redeem(p.pub, c.body.nonce, signNonce(p, c.body.nonce));
  if (t.status !== 200 || typeof t.body?.token !== "string") throw new Error(`token for ${p.name}: ${show(t)}`);
  p.token = t.body.token;
}

// ─── Startup ──────────────────────────────────────────────────────────────────────────

async function waitForHost(): Promise<Resp> {
  const deadline = Date.now() + STARTUP_TIMEOUT_MS;
  let last = "";
  while (Date.now() < deadline) {
    try {
      const r = await req("GET", "/.well-known/avp");
      if (r.status === 200) return r;
      last = show(r);
    } catch (err) {
      last = err instanceof Error ? err.message : String(err);
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`no host answered GET /.well-known/avp within ${STARTUP_TIMEOUT_MS} ms (${last})`);
}

// ─── The suite ────────────────────────────────────────────────────────────────────────

const MARKER = `avp-harness-zk-${randomBytes(12).toString("hex")}`;
const LOCATOR = "vault.example";

async function run(): Promise<void> {
  // §11.7 Discovery: the host key every acceptance and every `hosts` entry is matched against.
  const disc = await waitForHost();
  check("§11.7", "discovery answers version 0.5", disc.body?.version === "0.5", show(disc));
  check("§11.7", "discovery lists the http-json profile",
    Array.isArray(disc.body?.profiles) && disc.body.profiles.includes("http-json"), show(disc));
  const hostKey = Buffer.from(String(disc.body?.hostKey ?? ""), "base64");
  check("§11.7", "discovery hostKey is a 32-byte base64 key", hostKey.length === 32, show(disc));
  if (hostKey.length !== 32) throw new Error("cannot continue without the host key");
  const hosts: HostRef[] = [{ hostKey, locator: LOCATOR }];

  const alice = newOwner("alice");
  const bob = newParty("bob");
  const carol = newParty("carol");
  const dave = newParty("dave"); // never a member

  // ─── §3.3 Authentication ─────────────────────────────────────────────────────────────

  // The expired-nonce check: issued now, redeemed at the end after the challenge TTL.
  const expiring = await challenge(alice.pub);
  const expiringIssuedAt = Date.now();

  const c1 = await challenge(alice.pub);
  const nonce1 = String(c1.body?.nonce ?? "");
  check("§3.3", "challenge returns a single nonce of at least 32 bytes",
    c1.status === 200 && Buffer.from(nonce1, "base64").length >= 32, show(c1));
  const t1 = await redeem(alice.pub, nonce1, signNonce(alice, nonce1));
  check("§3.3", "a signature over the raw nonce bytes yields a token and expiresAt",
    t1.status === 200 && typeof t1.body?.token === "string" && Number.isInteger(t1.body?.expiresAt), show(t1));
  alice.token = String(t1.body?.token ?? "");

  const reused = await redeem(alice.pub, nonce1, signNonce(alice, nonce1));
  expectError("§3.3", "a reused nonce is 401 unauthorized", reused, 401, "unauthorized");

  const c2 = await challenge(alice.pub);
  const nonce2 = String(c2.body?.nonce ?? "");
  const overText = ed25519Sign(importEd25519Private(alice.seed), Buffer.from(nonce2, "utf8"));
  expectError("§3.3", "a signature over the base64 text, not the raw nonce, is 401",
    await redeem(alice.pub, nonce2, overText), 401, "unauthorized");

  const c3 = await challenge(alice.pub);
  const nonce3 = String(c3.body?.nonce ?? "");
  expectError("§3.3", "a signature by another key is 401 unauthorized",
    await redeem(alice.pub, nonce3, signNonce(dave, nonce3)), 401, "unauthorized");

  const c4 = await challenge(alice.pub);
  const nonce4 = String(c4.body?.nonce ?? "");
  expectError("§3.3", "a nonce issued for another key is 401 unauthorized",
    await redeem(dave.pub, nonce4, signNonce(dave, nonce4)), 401, "unauthorized");

  const never = b64(randomBytes(32));
  expectError("§3.3", "a nonce the host never issued is 401 unauthorized",
    await redeem(alice.pub, never, signNonce(alice, never)), 401, "unauthorized");

  // SPEC 2: strict verification rejects the identity-key forgery (negative.json ed25519/identity-key-forgery).
  const weak = await challenge(IDENTITY_KEY);
  if (weak.status === 200 && typeof weak.body?.nonce === "string") {
    expectError("§2", "no token for a small-order key's forged challenge signature (strict Ed25519)",
      await redeem(IDENTITY_KEY, weak.body.nonce, IDENTITY_FORGERY), 401, "unauthorized");
  } else {
    check("§2", "no token for a small-order key's forged challenge signature (strict Ed25519)",
      weak.status >= 400 && weak.status < 500 && typeof weak.body?.error === "string", show(weak));
  }
  {
    // SPEC 2, 3.3: the other strict rejections on the challenge signature, each 401 unauthorized.
    const c = await challenge(dave.pub);
    const n = String(c.body?.nonce ?? "");
    expectError("§2", "no token for an honest key's signature with R = identity (strict Ed25519)",
      await redeem(dave.pub, n, identityRSignature(dave, Buffer.from(n, "base64"))), 401, "unauthorized");
    const c2 = await challenge(dave.pub);
    const n2 = String(c2.body?.nonce ?? "");
    expectError("§2", "no token for a valid signature with L added to S (strict Ed25519)",
      await redeem(dave.pub, n2, sPlusLSignature(dave, Buffer.from(n2, "base64"))), 401, "unauthorized");
    const nc = await challenge(NONCANONICAL_KEY);
    if (nc.status === 200 && typeof nc.body?.nonce === "string") {
      expectError("§2", "no token for a non-canonical key's forged signature (strict Ed25519)",
        await redeem(NONCANONICAL_KEY, nc.body.nonce, IDENTITY_FORGERY), 401, "unauthorized");
    } else {
      check("§2", "no token for a non-canonical key's forged signature (strict Ed25519)",
        nc.status >= 400 && nc.status < 500 && typeof nc.body?.error === "string", show(nc));
    }
  }

  await login(bob);
  await login(carol);
  await login(dave);

  // ─── §8.2 createRepo ─────────────────────────────────────────────────────────────────

  const k0 = randomBytes(32);
  const g1State = genesisState(alice, k0, hosts, hostKey);
  const g1 = signManifest(g1State, alice.seed);
  const repoId = g1State.repoId;
  check("§4.2", "the genesis repoId is 22 characters of base64url", /^[A-Za-z0-9_-]{22}$/.test(repoId), repoId);
  const c0 = makeCommit({ repoId, author: alice, parents: [], manifest: g1, dataKey: k0, plaintext: payloadWith(MARKER, alice) });
  const createBody = { manifest: wireM(g1), commit: wireC(c0) };

  expectError("§3.3", "createRepo without a token is 401", await req("POST", "/v1/repos", createBody), 401, "unauthorized");
  expectError("§3.3", "createRepo with a token this host never minted is 401",
    await req("POST", "/v1/repos", createBody, "not-a-token-this-host-minted"), 401, "unauthorized");
  expectError("§8.2", "createRepo by a caller that is not the genesis ownerKey is 403 forbidden",
    await req("POST", "/v1/repos", createBody, bob.token), 403, "forbidden");

  {
    // A correctly signed genesis whose repoId is derived from another nonce (SPEC 4.2, 6.2, 12.4).
    const s = { ...genesisState(alice, k0, hosts, hostKey), repoId: deriveRepoId(alice.pub, randomBytes(16)) };
    const m = signManifest(s, alice.seed);
    const c = makeCommit({ repoId: s.repoId, author: alice, parents: [], manifest: m, dataKey: k0, plaintext: payloadWith(MARKER, alice) });
    expectError("§6.2", "createRepo with a repoId that does not recompute is 400 bad_request",
      await req("POST", "/v1/repos", { manifest: wireM(m), commit: wireC(c) }, alice.token), 400, "bad_request");
  }
  {
    const other = randomBytes(32);
    const s = genesisState(alice, k0, [{ hostKey: other, locator: "b.vault.example" }], other);
    const m = signManifest(s, alice.seed);
    const c = makeCommit({ repoId: s.repoId, author: alice, parents: [], manifest: m, dataKey: k0, plaintext: payloadWith(MARKER, alice) });
    expectError("§6.1", "createRepo whose hosts do not list this host is 403 not_hosted",
      await req("POST", "/v1/repos", { manifest: wireM(m), commit: wireC(c) }, alice.token), 403, "not_hosted");
  }
  {
    const s = genesisState(alice, k0, hosts, hostKey);
    const m = signManifest(s, alice.seed);
    const bad = { ...m, ownerSignature: ed25519Sign(importEd25519Private(dave.seed), Buffer.from("not the state")) };
    const c = makeCommit({ repoId: s.repoId, author: alice, parents: [], manifest: m, dataKey: k0, plaintext: payloadWith(MARKER, alice) });
    expectError("§6.1", "createRepo with a bad owner signature is 400 bad_request",
      await req("POST", "/v1/repos", { manifest: wireM(bad), commit: wireC(c) }, alice.token), 400, "bad_request");
  }
  {
    const s = genesisState(alice, k0, hosts, hostKey);
    s.members = [...s.members, memberOf(bob, k0, 0, hostKey)];
    const m = signManifest(s, alice.seed);
    const c = makeCommit({ repoId: s.repoId, author: alice, parents: [], manifest: m, dataKey: k0, plaintext: payloadWith(MARKER, alice) });
    expectError("§6.2", "a genesis with a member besides the owner is 400 bad_request",
      await req("POST", "/v1/repos", { manifest: wireM(m), commit: wireC(c) }, alice.token), 400, "bad_request");
  }
  {
    const s = { ...genesisState(alice, k0, hosts, hostKey), keyEpoch: 1 };
    s.members = [memberOf(alice, k0, 1, hostKey)];
    const m = signManifest(s, alice.seed);
    const c = makeCommit({ repoId: s.repoId, author: alice, parents: [], manifest: m, dataKey: k0, plaintext: payloadWith(MARKER, alice) });
    expectError("§6.2", "a genesis with keyEpoch 1 is 400 bad_request",
      await req("POST", "/v1/repos", { manifest: wireM(m), commit: wireC(c) }, alice.token), 400, "bad_request");
  }
  {
    // Same genesis as the real one, with a first commit whose id does not recompute. Nothing may be
    // stored, so the valid createRepo below must still succeed (SPEC 8.2: together or not at all).
    const fakeId = randomBytes(32);
    const bad: Commit = {
      ...c0,
      commitId: fakeId,
      authorSignature: ed25519Sign(importEd25519Private(alice.seed), commitSigMessage(fakeId)),
    };
    expectError("§7.1", "createRepo whose first commit id does not recompute is 400 bad_request",
      await req("POST", "/v1/repos", { manifest: wireM(g1), commit: wireC(bad) }, alice.token), 400, "bad_request");
  }

  const created = await req("POST", "/v1/repos", createBody, alice.token);
  check("§8.2", "a valid createRepo is 200 and returns the genesis it was sent",
    created.status === 200 && created.body?.state !== undefined && hashOfWire(created.body) === b64(manifestHash(g1)),
    show(created));
  expectError("§8.2", "a second createRepo with the same repoId is 409 duplicate_repo",
    await req("POST", "/v1/repos", createBody, alice.token), 409, "duplicate_repo");

  // ─── §10.1 Unknown repositories and malformed requests ──────────────────────────────

  {
    const ghost = deriveRepoId(alice.pub, randomBytes(16));
    expectError("§10.1", "pull of a repository the host does not hold is 404 not_found",
      await req("POST", repoPath(ghost, "pull"), { sinceManifestSeq: 0, knownHeads: [] }, alice.token), 404, "not_found");
    const c = makeCommit({ repoId: ghost, author: alice, parents: [], manifest: g1, dataKey: k0, plaintext: payloadWith(MARKER, alice) });
    expectError("§10.1", "push to a repository the host does not hold is 404 not_found",
      await req("POST", repoPath(ghost, "push"), { commit: wireC(c) }, alice.token), 404, "not_found");
  }
  {
    // SPEC 10.4 exception: an unparseable request target may get a bare 400; only the status is checked.
    const r = await req("POST", "/v1/repos/%zz/pull", { sinceManifestSeq: 0, knownHeads: [] }, alice.token);
    check("§10.4", "a request target with a bad percent escape is 400", r.status === 400, show(r));
  }
  expectError("§10.4", "a pull whose body is not JSON is 400 bad_request",
    await req("POST", repoPath(repoId, "pull"), "{not json", alice.token), 400, "bad_request");

  // ─── §10.1 pull after genesis ────────────────────────────────────────────────────────

  {
    const r = await req("POST", repoPath(repoId, "pull"), { sinceManifestSeq: 0, knownHeads: [] }, alice.token);
    const ms: WireSignedManifest[] = r.body?.manifests ?? [];
    const hs: WireCommit[] = r.body?.heads ?? [];
    check("§10.1", "pull from 0 returns the genesis, the first commit as the one head, and no leaves",
      r.status === 200 && ms.length === 1 && hashOfWire(ms[0]) === b64(manifestHash(g1))
        && sameSet(idsOf(hs), [b64(c0.commitId)]) && Array.isArray(r.body?.leaves) && r.body.leaves.length === 0,
      show(r));
    checkDoes("§4.3", "the served head is byte-identical and decrypts under AAD v2 from its own header", () => {
      const served = commitFromWire(hs[0]);
      if (!verifiesAsCommit(hs[0])) throw new Error("served commit id or signature does not verify");
      if (!served.ciphertext.equals(c0.ciphertext) || !served.iv.equals(c0.iv)) throw new Error("ciphertext changed");
      const aad = buildAadV2(served.repoId, served.keyEpoch, served.author, served.parents);
      const pt = aesGcmDecrypt(k0, served.iv, aad, served.ciphertext).toString("utf8");
      if (!pt.includes(MARKER)) throw new Error("decrypted payload is not the one sent");
    });
  }
  expectError("§10.1", "pull by a caller that is not a member is 403 forbidden",
    await req("POST", repoPath(repoId, "pull"), { sinceManifestSeq: 0, knownHeads: [] }, dave.token), 403, "forbidden");

  // ─── §8.2 prepareJoin ────────────────────────────────────────────────────────────────

  for (const joiner of [bob, carol]) {
    const r = await req("POST", "/v1/prepare-join", { repoId, memberKey: b64(joiner.pub) }, joiner.token);
    const a = r.body;
    check("§8.2", `prepareJoin for ${joiner.name} returns an acceptance for that repo, key, and this host`,
      r.status === 200 && a?.repoId === repoId && a?.memberKey === b64(joiner.pub) && a?.hostKey === b64(hostKey)
        && Number.isInteger(a?.expiresAt) && a.expiresAt > Date.now(),
      show(r));
    checkDoes("§8.2", `${joiner.name}'s acceptance signature verifies under the discovered hostKey`, () => {
      const acc: Acceptance = {
        repoId: a.repoId,
        memberKey: Buffer.from(a.memberKey, "base64"),
        hostKey: Buffer.from(a.hostKey, "base64"),
        expiresAt: a.expiresAt,
        signature: Buffer.from(a.signature, "base64"),
      };
      if (!verifyAcceptance(acc, hostKey)) throw new Error("acceptance does not verify under the discovery hostKey");
      // The joiner's invite token travels encoded (SPEC 11.1, 11.3); the owner decodes and checks it.
      const token: WireInviteToken = {
        v: 2,
        ed25519PublicKey: b64(joiner.pub),
        x25519PublicKey: b64(joiner.xPub),
        homeHostKey: a.hostKey,
        homeHostLocator: LOCATOR,
        acceptance: acceptanceToWire(acc),
      };
      const invite = decodeInviteToken(encodeToken("InviteToken", token));
      if (!verifyInvite(invite, repoId, Date.now())) throw new Error("the owner's invite check (SPEC 8.2) rejects it");
    });
  }
  expectError("§8.2", "prepareJoin whose memberKey is not the caller is 403 forbidden",
    await req("POST", "/v1/prepare-join", { repoId, memberKey: b64(bob.pub) }, dave.token), 403, "forbidden");

  // ─── §6 publishManifest: seq 2 adds bob and carol ───────────────────────────────────

  const m2State = nextState(g1, {
    members: [memberOf(alice, k0, 0, hostKey), memberOf(bob, k0, 0, hostKey), memberOf(carol, k0, 0, hostKey)],
  });
  const m2 = signManifest(m2State, alice.seed);
  const publish = (m: SignedManifest, token: string, commit?: Commit) =>
    req("POST", repoPath(repoId, "manifest"), commit ? { manifest: wireM(m), commit: wireC(commit) } : { manifest: wireM(m) }, token);

  expectError("§10.1", "publishManifest by a caller that is not ownerKey is 403 forbidden", await publish(m2, bob.token), 403, "forbidden");
  expectError("§6.3", "publishing seq tip + 2 is 409 manifest_conflict",
    await publish(signManifest({ ...m2State, manifestSeq: 3 }, alice.seed), alice.token), 409, "manifest_conflict");
  expectError("§6.3", "publishing with a wrong prevManifestHash is 409 manifest_conflict",
    await publish(signManifest({ ...m2State, prevManifestHash: randomBytes(32) }, alice.seed), alice.token), 409, "manifest_conflict");
  expectError("§6.1", "a state with a bad owner signature is 400 bad_request",
    await publish({ ...m2, ownerSignature: ed25519Sign(importEd25519Private(bob.seed), Buffer.from("x")) }, alice.token),
    400, "bad_request");
  expectError("§6.1", "a member whose keyEpoch differs from the state's is 400 bad_request",
    await publish(signManifest({ ...m2State, members: [memberOf(alice, k0, 0, hostKey), memberOf(bob, k0, 1, hostKey)] }, alice.seed),
      alice.token), 400, "bad_request");
  expectError("§6.1", "a member whose homeHostKey is not in hosts is 400 bad_request",
    await publish(signManifest({ ...m2State, members: [memberOf(alice, k0, 0, hostKey), memberOf(bob, k0, 0, randomBytes(32))] },
      alice.seed), alice.token), 400, "bad_request");

  const pub2 = await publish(m2, alice.token);
  check("§6.3", "publishing seq tip + 1 is 200 and returns the published state",
    pub2.status === 200 && pub2.body?.state !== undefined && hashOfWire(pub2.body) === b64(manifestHash(m2)), show(pub2));
  expectError("§12.3", "republishing the same seq is 409 manifest_conflict", await publish(m2, alice.token), 409, "manifest_conflict");

  // ─── §10.1 pull returns the manifest chain from sinceManifestSeq ────────────────────

  {
    const pull = (since: number) => req("POST", repoPath(repoId, "pull"), { sinceManifestSeq: since, knownHeads: [] }, bob.token);
    const r0 = await pull(0);
    const ms: WireSignedManifest[] = r0.body?.manifests ?? [];
    check("§10.1", "pull from 0 returns seq 1 and 2 in ascending order, as published",
      r0.status === 200 && ms.length === 2 && ms[0].state.manifestSeq === 1 && ms[1].state.manifestSeq === 2
        && hashOfWire(ms[0]) === b64(manifestHash(g1)) && hashOfWire(ms[1]) === b64(manifestHash(m2)),
      show(r0));
    check("§6.3", "the pulled chain links by prevManifestHash",
      ms.length === 2 && ms[1].state.prevManifestHash === hashOfWire(ms[0]), show(r0));
    const r1 = await pull(1);
    check("§10.1", "pull from 1 returns only seq 2",
      r1.status === 200 && r1.body?.manifests?.length === 1 && hashOfWire(r1.body.manifests[0]) === b64(manifestHash(m2)), show(r1));
    const r2 = await pull(2);
    check("§10.1", "pull from the tip returns no states and still the heads",
      r2.status === 200 && r2.body?.manifests?.length === 0 && sameSet(idsOf(r2.body?.heads), [b64(c0.commitId)]), show(r2));
    checkDoes("§4.4", "bob unwraps the data key from the served state and reads the first commit", () => {
      const served = signedManifestFromWire(ms[1]);
      const entry = served.state.members.find((m) => m.ed25519PublicKey.equals(bob.pub));
      if (!entry) throw new Error("bob is not in the served state");
      const key = unwrapSecret(bob.xPriv, entry.wrappedDataKey);
      const aad = buildAadV2(repoId, 0, alice.pub, []);
      if (!aesGcmDecrypt(key, c0.iv, aad, c0.ciphertext).toString("utf8").includes(MARKER)) throw new Error("wrong plaintext");
    });
  }

  // ─── §7 push: forks, merges, and every reject path ───────────────────────────────────

  const push = (c: Commit, token: string, repo = repoId) => req("POST", repoPath(repo, "push"), { commit: wireC(c) }, token);
  const write = (author: Party, parents: Buffer[], manifest = m2, dataKey = k0, keyEpoch?: number) =>
    makeCommit({ repoId, author, parents, manifest, dataKey, keyEpoch, plaintext: payloadWith(MARKER, author) });

  const b1 = write(bob, [c0.commitId]);
  const pb1 = await push(b1, bob.token);
  check("§10.1", "a push on the current head is 200 accepted with that commit as the one head",
    pb1.status === 200 && pb1.body?.accepted === true && sameSet(idsOf(pb1.body?.heads), [b64(b1.commitId)]), show(pb1));

  const cc1 = write(carol, [c0.commitId]);
  const pc1 = await push(cc1, carol.token);
  check("§7.4", "a concurrent push on the same parent is 200 accepted and leaves two heads (no conflict outcome)",
    pc1.status === 200 && pc1.body?.accepted === true && sameSet(idsOf(pc1.body?.heads), [b64(b1.commitId), b64(cc1.commitId)]),
    show(pc1));

  const again = await push(b1, bob.token);
  check("§7", "re-pushing a commit the host already holds is 200 accepted with no change",
    again.status === 200 && again.body?.accepted === true && sameSet(idsOf(again.body?.heads), [b64(b1.commitId), b64(cc1.commitId)]),
    show(again));
  {
    const all = await req("POST", repoPath(repoId, "pull"), { sinceManifestSeq: 2, knownHeads: [] }, alice.token);
    check("§10.1", "pull returns both heads",
      all.status === 200 && sameSet(idsOf(all.body?.heads), [b64(b1.commitId), b64(cc1.commitId)]), show(all));
    check("§10.1", "pull returns the heads as full commits that verify",
      Array.isArray(all.body?.heads) && all.body.heads.length === 2 && all.body.heads.every((h: WireCommit) => verifiesAsCommit(h)),
      show(all));
    const known = await req("POST", repoPath(repoId, "pull"), { sinceManifestSeq: 2, knownHeads: [b64(b1.commitId)] }, alice.token);
    check("§10.1", "pull leaves out the heads named in knownHeads",
      known.status === 200 && sameSet(idsOf(known.body?.heads), [b64(cc1.commitId)]), show(known));
  }

  expectError("§7.1", "a push whose author is not the caller is 403 forbidden",
    await push(write(carol, [b1.commitId]), bob.token), 403, "forbidden");
  {
    const c = write(bob, [b1.commitId]);
    const fakeId = randomBytes(32);
    const bad = { ...c, commitId: fakeId, authorSignature: ed25519Sign(importEd25519Private(bob.seed), commitSigMessage(fakeId)) };
    expectError("§7.1", "a commit whose id does not recompute is 400 bad_request", await push(bad, bob.token), 400, "bad_request");
  }
  expectError("§7.1", "a commit whose author signature does not verify is 400 bad_request",
    await push(withForeignSignature(write(bob, [b1.commitId]), dave), bob.token), 400, "bad_request");
  {
    const other = makeCommit({ repoId: deriveRepoId(alice.pub, randomBytes(16)), author: bob, parents: [b1.commitId], manifest: m2,
      dataKey: k0, plaintext: payloadWith(MARKER, bob) });
    expectError("§7.1", "a commit whose repoId is another repository is 400 bad_request", await push(other, bob.token), 400, "bad_request");
  }
  {
    // negative.json ed25519/identity-key-forgery on a commit: a strict host fails the signature (400)
    // before the caller check (403) of SPEC 7.1.
    const h: CommitHeader = { ...write(alice, [b1.commitId]), author: IDENTITY_KEY };
    const forged: Commit = { ...h, commitId: commitId(h), authorSignature: IDENTITY_FORGERY };
    expectError("§2", "a commit by a small-order author key with a forged signature is 400 bad_request (strict Ed25519)",
      await push(forged, alice.token), 400, "bad_request");
  }
  {
    // The rest of the strict rules of SPEC 2 on the author signature, each 400 bad_request (SPEC 7.1).
    // Signed by alice's own key, a host without them would accept these as alice's writes.
    const c = write(alice, [b1.commitId]);
    expectError("§2", "a commit signed with R = identity is 400 bad_request (strict Ed25519)",
      await push({ ...c, authorSignature: identityRSignature(alice, commitSigMessage(c.commitId)) }, alice.token),
      400, "bad_request");
    const d = write(alice, [b1.commitId]);
    expectError("§2", "a commit whose signature has L added to S is 400 bad_request (strict Ed25519)",
      await push({ ...d, authorSignature: sPlusLSignature(alice, commitSigMessage(d.commitId)) }, alice.token),
      400, "bad_request");
    // Order-8 author key: re-draw the IV until 8 divides k, so R = identity, S = 0 passes the cofactorless
    // equation for this commit id (as negative.json ed25519/order-8-key-forgery does for its message).
    const base = write(alice, [b1.commitId]);
    let o8: Commit | undefined;
    for (let i = 0; i < 1000 && o8 === undefined; i++) {
      const h: CommitHeader = { ...base, author: ORDER8_KEY, iv: randomBytes(12) };
      const id = commitId(h);
      if (edChallenge(IDENTITY_KEY, ORDER8_KEY, commitSigMessage(id)) % 8n === 0n) {
        o8 = { ...h, commitId: id, authorSignature: IDENTITY_FORGERY };
      }
    }
    if (o8 === undefined) throw new Error("could not build the order-8 forgery");
    expectError("§2", "a commit by an order-8 author key with a forged signature is 400 bad_request (strict Ed25519)",
      await push(o8, alice.token), 400, "bad_request");
    // The sign-bit variant uses an honest R (the public key of seed 08 00..00) and S its scalar, so only
    // the small-order check on the key itself rejects it.
    const seed8 = Buffer.alloc(32);
    seed8[0] = 8;
    const sig8 = Buffer.concat([ed25519PublicRaw(importEd25519Private(seed8)), intToLe32(secretScalar(seed8) % ED25519_L)]);
    let o8s: Commit | undefined;
    for (let i = 0; i < 1000 && o8s === undefined; i++) {
      const h: CommitHeader = { ...base, author: ORDER8_SIGN_BIT_KEY, iv: randomBytes(12) };
      const id = commitId(h);
      if (edChallenge(sig8.subarray(0, 32), ORDER8_SIGN_BIT_KEY, commitSigMessage(id)) % 8n === 0n) {
        o8s = { ...h, commitId: id, authorSignature: sig8 };
      }
    }
    if (o8s === undefined) throw new Error("could not build the order-8 sign-bit forgery");
    expectError("§2", "a commit by the sign-bit order-8 key with an honest-R forgery is 400 bad_request (strict Ed25519)",
      await push(o8s, alice.token), 400, "bad_request");
    const hn: CommitHeader = { ...write(alice, [b1.commitId]), author: NONCANONICAL_KEY };
    expectError("§2", "a commit by a non-canonical author key with a forged signature is 400 bad_request (strict Ed25519)",
      await push({ ...hn, commitId: commitId(hn), authorSignature: IDENTITY_FORGERY }, alice.token), 400, "bad_request");
  }
  expectError("§7.2", "a commit whose keyEpoch differs from the cited state's is 403 forbidden",
    await push(write(bob, [b1.commitId], m2, k0, 1), bob.token), 403, "forbidden");
  expectError("§7.2", "a commit citing a state where its author is not a member is 403 forbidden",
    await push(write(bob, [b1.commitId], g1), bob.token), 403, "forbidden");
  {
    const unknownHash = randomBytes(32);
    const h: CommitHeader = { ...write(bob, [b1.commitId]), manifestHash: unknownHash };
    const c = signCommit(h, bob.seed);
    const r = await push(c, bob.token);
    expectError("§7.2", "a commit citing an unknown manifest hash is 422 missing_parents", r, 422, "missing_parents");
    check("§7.2", "the 422 detail names the unknown manifest hash",
      typeof r.body?.detail === "string" && r.body.detail.split(",").includes(b64(unknownHash)), show(r));
  }
  {
    const ghostParent = randomBytes(32);
    const r = await push(write(bob, [ghostParent]), bob.token);
    expectError("§7.4", "a commit with an unknown parent is 422 missing_parents", r, 422, "missing_parents");
    check("§7.4", "the 422 detail lists the missing parent id",
      typeof r.body?.detail === "string" && r.body.detail.split(",").includes(b64(ghostParent)), show(r));
  }
  {
    const d = makeCommit({ repoId, author: dave, parents: [b1.commitId], manifest: m2, dataKey: k0, plaintext: payloadWith(MARKER, dave) });
    expectError("§7.1", "a push by a caller that is not a member is 403 forbidden", await push(d, dave.token), 403, "forbidden");
  }

  const merge1 = write(alice, [b1.commitId, cc1.commitId]);
  const pm = await push(merge1, alice.token);
  check("§7.4", "a merge commit naming both heads collapses them into one head",
    pm.status === 200 && pm.body?.accepted === true && sameSet(idsOf(pm.body?.heads), [b64(merge1.commitId)]), show(pm));

  // ─── §7.3, §8.3 Removal with rotation and the cutoff ────────────────────────────────

  const cc2 = write(carol, [merge1.commitId]);
  await push(cc2, carol.token);
  const cc3 = write(carol, [cc2.commitId]); // carol writes on; the owner never sees it before the removal
  await push(cc3, carol.token);
  const b2 = write(bob, [cc3.commitId]); // a descendant of a commit outside the frontier
  const pb2 = await push(b2, bob.token);
  check("§7.4", "a chain of pushes on the single head leaves only the newest as head",
    pb2.status === 200 && sameSet(idsOf(pb2.body?.heads), [b64(b2.commitId)]), show(pb2));

  const k1 = randomBytes(32);
  const carolRemoval: Removal = { memberKey: carol.pub, removedAtSeq: 3, frontier: [cc2.commitId] };
  const m3State = nextState(m2, {
    keyEpoch: 1,
    members: [memberOf(alice, k1, 1, hostKey), memberOf(bob, k1, 1, hostKey)],
    removals: [carolRemoval],
  });
  const m3 = signManifest(m3State, alice.seed);
  const rotation = makeCommit({ repoId, author: alice, parents: [cc2.commitId], manifest: m3, dataKey: k1, plaintext: payloadWith(MARKER, alice) });

  expectError("§8.3", "an epoch-raising state without its rotation commit is 400 bad_request", await publish(m3, alice.token), 400, "bad_request");
  expectError("§8.3", "a rotation commit not authored by ownerKey is 400 bad_request",
    await publish(m3, alice.token,
      makeCommit({ repoId, author: bob, parents: [cc2.commitId], manifest: m3, dataKey: k1, plaintext: payloadWith(MARKER, bob) })),
    400, "bad_request");
  expectError("§8.3", "a rotation commit under the old epoch is 400 bad_request",
    await publish(m3, alice.token,
      makeCommit({ repoId, author: alice, parents: [cc2.commitId], manifest: m3, dataKey: k0, keyEpoch: 0, plaintext: payloadWith(MARKER, alice) })),
    400, "bad_request");
  {
    const s = nextState(m2, { keyEpoch: 1, members: [memberOf(alice, k1, 1, hostKey), memberOf(bob, k1, 1, hostKey)] });
    const m = signManifest(s, alice.seed);
    const rc = makeCommit({ repoId, author: alice, parents: [cc2.commitId], manifest: m, dataKey: k1, plaintext: payloadWith(MARKER, alice) });
    expectError("§6.1", "a state that drops a member without a removal is 400 bad_request", await publish(m, alice.token, rc), 400, "bad_request");
  }
  {
    const s = nextState(m2, { members: [memberOf(alice, k0, 0, hostKey), memberOf(bob, k0, 0, hostKey)], removals: [carolRemoval] });
    expectError("§6.1", "a removal that does not raise keyEpoch is 400 bad_request",
      await publish(signManifest(s, alice.seed), alice.token), 400, "bad_request");
  }

  const pub3 = await publish(m3, alice.token, rotation);
  check("§8.3", "the removal state with its rotation commit is 200 and returns the state",
    pub3.status === 200 && hashOfWire(pub3.body ?? { state: {} }) === b64(manifestHash(m3)), show(pub3));
  {
    const r = await req("POST", repoPath(repoId, "pull"), { sinceManifestSeq: 0, knownHeads: [] }, alice.token);
    check("§7.3", "after the removal the heads are exactly the rotation commit: the removed member's commit outside the "
      + "frontier and its descendant are dropped",
      r.status === 200 && sameSet(idsOf(r.body?.heads), [b64(rotation.commitId)]), show(r));
    check("§10.1", "pull from 0 returns all three states in order",
      r.status === 200 && (r.body?.manifests ?? []).map((m: WireSignedManifest) => m.state.manifestSeq).join(",") === "1,2,3", show(r));
  }
  // SPEC 7.3, 7.4: a dropped commit stays rejected, so a child of it is 403 forbidden, from a member in good standing.
  expectError("§7.4", "a child of the descendant the cutoff dropped is 403 forbidden",
    await push(write(bob, [b2.commitId]), bob.token), 403, "forbidden");
  expectError("§7.4", "a child of the removed member's commit the cutoff dropped is 403 forbidden",
    await push(write(bob, [cc3.commitId]), bob.token), 403, "forbidden");
  expectError("§10.1", "the removed member's pull is 403 forbidden",
    await req("POST", repoPath(repoId, "pull"), { sinceManifestSeq: 0, knownHeads: [] }, carol.token), 403, "forbidden");
  expectError("§7.1", "the removed member's push is 403 forbidden", await push(write(carol, [rotation.commitId]), carol.token), 403, "forbidden");

  // SPEC 7.2: a member's write citing an older state than the tip is valid (not lost).
  const b3 = write(bob, [cc2.commitId]);
  const pb3 = await push(b3, bob.token);
  check("§7.2", "a member's commit citing the previous state and epoch is still accepted",
    pb3.status === 200 && sameSet(idsOf(pb3.body?.heads), [b64(rotation.commitId), b64(b3.commitId)]), show(pb3));

  // ─── §8.4 Leave ──────────────────────────────────────────────────────────────────────

  const leaveOf = (p: Party, repo = repoId, at = Date.now()): WireLeaveRequest =>
    leaveToWire(signLeave({ repoId: repo, memberKey: p.pub, at }, p.seed));
  const postLeave = (l: WireLeaveRequest, token: string) => req("POST", repoPath(repoId, "leave"), l, token);

  {
    const l = leaveOf(bob);
    const bad = { ...l, signature: b64(ed25519Sign(importEd25519Private(dave.seed), Buffer.from("x"))) };
    expectError("§8.4", "a leave request with a bad signature is 400 bad_request", await postLeave(bad, bob.token), 400, "bad_request");
    expectError("§8.4", "a leave request signed for another repository is 400 bad_request",
      await postLeave(leaveOf(bob, deriveRepoId(alice.pub, randomBytes(16))), bob.token), 400, "bad_request");
    expectError("§8.4", "a leave request whose memberKey is not the caller is 403 forbidden", await postLeave(l, alice.token), 403, "forbidden");
    expectError("§8.4", "the owner's leave request is 403 forbidden", await postLeave(leaveOf(alice), alice.token), 403, "forbidden");
    expectError("§8.4", "a non-member's leave request is 403 forbidden", await postLeave(leaveOf(dave), dave.token), 403, "forbidden");
    expectError("§8.4", "a removed member's leave request is 403 forbidden", await postLeave(leaveOf(carol), carol.token), 403, "forbidden");
  }
  const leave1 = leaveOf(bob, repoId, Date.now() - 1000);
  const pl1 = await postLeave(leave1, bob.token);
  check("§8.4", "a member's valid leave request is 200 {}", pl1.status === 200 && pl1.text.trim() === "{}", show(pl1));
  {
    const r = await req("POST", repoPath(repoId, "pull"), { sinceManifestSeq: 3, knownHeads: [] }, alice.token);
    const ls: WireLeaveRequest[] = r.body?.leaves ?? [];
    check("§8.4", "pull serves the pending leave request unchanged, and it verifies",
      r.status === 200 && ls.length === 1 && ls[0].memberKey === leave1.memberKey && ls[0].at === leave1.at
        && ls[0].signature === leave1.signature && verifyLeave(leaveFromWire(ls[0])),
      show(r));
  }
  const leave2 = leaveOf(bob, repoId, Date.now());
  await postLeave(leave2, bob.token);
  {
    const r = await req("POST", repoPath(repoId, "pull"), { sinceManifestSeq: 3, knownHeads: [] }, alice.token);
    const ls: WireLeaveRequest[] = r.body?.leaves ?? [];
    check("§8.4", "the host keeps only the latest leave request per member",
      r.status === 200 && ls.length === 1 && ls[0].at === leave2.at, show(r));
  }
  {
    // The owner processes the leave by removal (SPEC 8.3, 8.4): epoch 2, rotation commit merging both heads.
    const k2 = randomBytes(32);
    const m4State = nextState(m3, {
      keyEpoch: 2,
      members: [memberOf(alice, k2, 2, hostKey)],
      removals: [carolRemoval, { memberKey: bob.pub, removedAtSeq: 4, frontier: [rotation.commitId, b3.commitId] }],
    });
    const m4 = signManifest(m4State, alice.seed);
    const r4 = makeCommit({ repoId, author: alice, parents: [rotation.commitId, b3.commitId], manifest: m4, dataKey: k2,
      plaintext: payloadWith(MARKER, alice) });
    const p4 = await publish(m4, alice.token, r4);
    check("§8.3", "removing the leaver with a merging rotation commit is 200",
      p4.status === 200 && hashOfWire(p4.body ?? { state: {} }) === b64(manifestHash(m4)), show(p4));
    const r = await req("POST", repoPath(repoId, "pull"), { sinceManifestSeq: 4, knownHeads: [] }, alice.token);
    check("§8.4", "the leave request is dropped once a state removes its member",
      r.status === 200 && Array.isArray(r.body?.leaves) && r.body.leaves.length === 0, show(r));
    check("§7.3", "the merging rotation commit is the one head, and the leaver's frontier commit survives as its parent",
      r.status === 200 && sameSet(idsOf(r.body?.heads), [b64(r4.commitId)]), show(r));
    expectError("§10.1", "the leaver's pull after removal is 403 forbidden",
      await req("POST", repoPath(repoId, "pull"), { sinceManifestSeq: 0, knownHeads: [] }, bob.token), 403, "forbidden");
  }

  // ─── §7.4 Head bound, on a second repository ────────────────────────────────────────

  {
    const kh = randomBytes(32);
    const gh = signManifest(genesisState(alice, kh, hosts, hostKey), alice.seed);
    const hr = gh.state.repoId;
    const first = makeCommit({ repoId: hr, author: alice, parents: [], manifest: gh, dataKey: kh, plaintext: payloadWith(MARKER, alice) });
    const cr = await req("POST", "/v1/repos", { manifest: wireM(gh), commit: wireC(first) }, alice.token);
    if (cr.status !== 200) throw new Error(`head-bound repository: ${show(cr)}`);
    const child = (parents: Buffer[]) =>
      makeCommit({ repoId: hr, author: alice, parents, manifest: gh, dataKey: kh, plaintext: payloadWith(MARKER, alice) });
    const forks: Commit[] = [];
    let lastHeads = 0;
    let allOk = true;
    let failure = "";
    for (let i = 0; i < HEAD_BOUND; i++) {
      const c = child([first.commitId]);
      const r = await push(c, alice.token, hr);
      forks.push(c);
      if (r.status !== 200) {
        allOk = false;
        failure = `fork ${i + 1}: ${show(r)}`;
        break;
      }
      lastHeads = idsOf(r.body?.heads).length;
    }
    check("§7.4", `forks up to the head bound (${HEAD_BOUND}) are accepted`, allOk && lastHeads === HEAD_BOUND,
      failure || `heads ${lastHeads}`);
    expectError("§7.4", "a push that would leave more than the bound is 409 too_many_heads",
      await push(child([first.commitId]), alice.token, hr), 409, "too_many_heads");
    const merge = child([forks[0].commitId, forks[1].commitId]);
    const rm = await push(merge, alice.token, hr);
    check("§7.4", "a merge commit at the bound that reduces the heads is accepted",
      rm.status === 200 && idsOf(rm.body?.heads).length === HEAD_BOUND - 1, show(rm));
    const refill = await push(child([first.commitId]), alice.token, hr);
    check("§7.4", "a push that leaves exactly the bound is accepted",
      refill.status === 200 && idsOf(refill.body?.heads).length === HEAD_BOUND, show(refill));
    expectError("§7.4", "the next push past the bound is again 409 too_many_heads",
      await push(child([first.commitId]), alice.token, hr), 409, "too_many_heads");
  }

  // ─── §8.6 A host dropped from hosts, on a third repository ──────────────────────────

  {
    const kd = randomBytes(32);
    const gd = signManifest(genesisState(alice, kd, hosts, hostKey), alice.seed);
    const dr = gd.state.repoId;
    const first = makeCommit({ repoId: dr, author: alice, parents: [], manifest: gd, dataKey: kd, plaintext: payloadWith(MARKER, alice) });
    const cr = await req("POST", "/v1/repos", { manifest: wireM(gd), commit: wireC(first) }, alice.token);
    if (cr.status !== 200) throw new Error(`dropped-host repository: ${show(cr)}`);
    const elsewhere = randomBytes(32);
    const s = nextState(gd, {
      hosts: [{ hostKey: elsewhere, locator: "b.vault.example" }],
      members: [memberOf(alice, kd, 0, elsewhere)],
    });
    const r = await req("POST", repoPath(dr, "manifest"), { manifest: wireM(signManifest(s, alice.seed)) }, alice.token);
    expectError("§6.1", "a state that drops this host from hosts is 403 not_hosted", r, 403, "not_hosted");
    expectError("§10.1", "the repository is then not served: pull is 403 not_hosted",
      await req("POST", repoPath(dr, "pull"), { sinceManifestSeq: 0, knownHeads: [] }, alice.token), 403, "not_hosted");
    expectError("§8.6", "and takes no client writes: push is 403 not_hosted",
      await push(makeCommit({ repoId: dr, author: alice, parents: [first.commitId], manifest: gd, dataKey: kd,
        plaintext: payloadWith(MARKER, alice) }), alice.token, dr), 403, "not_hosted");
  }

  // ─── §3.3 Expired nonce ──────────────────────────────────────────────────────────────

  {
    const wait = expiringIssuedAt + CHALLENGE_TTL_MS + EXPIRY_MARGIN_MS - Date.now();
    if (wait > 0) {
      console.log(`  (waiting ${Math.ceil(wait / 1000)} s for the challenge issued at start to expire)`);
      await new Promise((resolve) => setTimeout(resolve, wait));
    }
    const nonce = String(expiring.body?.nonce ?? "");
    expectError("§3.3", `a nonce redeemed after the challenge TTL (${CHALLENGE_TTL_MS} ms) is 401 unauthorized`,
      await redeem(alice.pub, nonce, signNonce(alice, nonce)), 401, "unauthorized");
  }

  // ─── §13 Zero-knowledge ──────────────────────────────────────────────────────────────

  {
    const markerBytes = Buffer.from(MARKER, "utf8");
    let inText = 0;
    let inBinary = 0;
    const scan = (v: unknown): void => {
      if (typeof v === "string") {
        if (/^[A-Za-z0-9+/]+={0,2}$/.test(v) && v.length % 4 === 0 && Buffer.from(v, "base64").includes(markerBytes)) inBinary += 1;
      } else if (Array.isArray(v)) {
        v.forEach(scan);
      } else if (v !== null && typeof v === "object") {
        Object.values(v).forEach(scan);
      }
    };
    for (const text of seen) {
      if (text.includes(MARKER)) inText += 1;
      try {
        scan(JSON.parse(text));
      } catch {
        // not JSON: the text scan above covers it
      }
    }
    check("§13", `the plaintext marker appears in none of the ${seen.length} responses`, inText === 0, `${inText} responses carry it`);
    check("§13", "no base64 value in any response decodes to bytes holding the marker", inBinary === 0, `${inBinary} values carry it`);
  }
}

// ─── Report ───────────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log(`AVP 0.5 single-host conformance harness → ${BASE_URL}\n`);
  try {
    await run();
  } catch (err) {
    console.error(`\nHarness aborted (could not complete the flow): ${err instanceof Error ? err.message : err}`);
    process.exitCode = 1;
  }
  let passed = 0;
  for (const r of results) {
    console.log(`  [${r.ok ? "PASS" : "FAIL"}] ${r.section.padEnd(6)} ${r.name}${r.ok ? "" : `  (${r.detail})`}`);
    if (r.ok) passed += 1;
  }
  const failed = results.length - passed;
  console.log(`\n${passed}/${results.length} checks passed${failed ? `, ${failed} FAILED` : ""}.`);
  if (failed > 0) process.exitCode = 1;
}

void main();
