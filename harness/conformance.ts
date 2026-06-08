/**
 * AVP black-box conformance harness (HTTP/JSON profile).
 *
 * Point it at any running AVP server and it exercises the full wire contract end to end, asserting the
 * normative MUSTs from SPEC §3/§6/§10 rather than just printing a transcript: the challenge→token flow
 * and its failure modes, optimistic concurrency (a stale push is a 200 conflict, never a 4xx), membership
 * authorization, key rotation on member removal, and (the whole point) zero-knowledge: the plaintext we
 * encrypt never appears in anything the server stores or echoes back.
 *
 * It is server-agnostic: the only AVP-specific code is the client-side crypto, reused from the
 * vector-tested reference at ../examples/typescript/client/src/crypto.ts. A pass means the target server
 * is conformant to the surface this harness covers; it is a strong supplement to the static vectors in
 * vectors/, not a replacement for them.
 *
 *   bun conformance.ts --server http://localhost:8787
 *   AVP_SERVER_URL=http://localhost:8787 bun conformance.ts
 *
 * Exit code is 0 only if every check passes. SPDX-License-Identifier: MIT
 */

import { generateKeyPairSync, randomBytes, randomUUID, sign as edSign, type KeyObject } from "node:crypto";

import {
  decryptPayload,
  encryptPayload,
  generateX25519,
  unwrapDataKey,
  wrapDataKey,
  WRAP_SCHEME_ID,
  type EncryptedEnvelopeFields,
  type WrappedKeyFields,
} from "../examples/typescript/client/src/crypto.ts";

// ─── Config ───────────────────────────────────────────────────────────────────

function parseBaseUrl(): string {
  const flag = process.argv.indexOf("--server");
  const fromFlag = flag !== -1 ? process.argv[flag + 1] : undefined;
  const url = fromFlag ?? process.env.AVP_SERVER_URL ?? "http://localhost:8787";
  return url.replace(/\/$/, "");
}

const BASE_URL = parseBaseUrl();

// ─── Tiny check framework ───────────────────────────────────────────────────────

interface Result {
  name: string;
  section: string;
  ok: boolean;
  detail: string;
}

const results: Result[] = [];

/** Record a single conformance check. `cond` true = pass; `detail` shows on failure (or info on pass). */
function check(section: string, name: string, cond: boolean, detail = ""): void {
  results.push({ section, name, ok: cond, detail });
}

/** Run a check whose body may throw; a throw is a failure carrying the message. */
async function checkThrows(
  section: string,
  name: string,
  fn: () => Promise<void> | void,
  { expectThrow = false } = {},
): Promise<void> {
  try {
    await fn();
    check(section, name, !expectThrow, expectThrow ? "expected an error but none was thrown" : "");
  } catch (err) {
    check(section, name, expectThrow, expectThrow ? "" : String(err instanceof Error ? err.message : err));
  }
}

// ─── HTTP (does not throw on non-2xx; the checks assert the status) ──────────────

interface Resp {
  status: number;
  body: any;
  text: string;
}

async function req(method: string, path: string, body?: unknown, token?: string): Promise<Resp> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let parsed: any = undefined;
  try {
    parsed = text ? JSON.parse(text) : undefined;
  } catch {
    parsed = undefined;
  }
  return { status: res.status, body: parsed, text };
}

const repoPath = (repoId: string, op: string) => `/v1/repos/${encodeURIComponent(repoId)}/${op}`;

// ─── Identity (Ed25519 id + X25519 wrap key), SPEC §2/§3 ─────────────────────────

interface Identity {
  ed25519PublicKey: string;
  x25519PublicKey: string;
  edPrivateKey: KeyObject;
  xPrivateKey: KeyObject;
}

function generateIdentity(): Identity {
  const { publicKey: edPub, privateKey: edPriv } = generateKeyPairSync("ed25519");
  const spki = edPub.export({ format: "der", type: "spki" }) as Buffer;
  const edPubRaw = spki.subarray(spki.length - 32); // SPKI = 12-byte header + raw 32-byte key
  const { privateKey: xPriv, publicKeyRaw: xPubRaw } = generateX25519();
  return {
    ed25519PublicKey: edPubRaw.toString("base64"),
    x25519PublicKey: xPubRaw.toString("base64"),
    edPrivateKey: edPriv,
    xPrivateKey: xPriv,
  };
}

function memberEntry(id: Identity, dataKey: Buffer, keyEpoch: number) {
  return {
    ed25519PublicKey: id.ed25519PublicKey,
    x25519PublicKey: id.x25519PublicKey,
    wrappedDataKey: wrapDataKey(id.x25519PublicKey, dataKey) as WrappedKeyFields,
    keyEpoch,
    keyBindingSig: null,
  };
}

interface Alt {
  uuid: string;
  username: string;
  accessToken: string;
  type: string;
  lastUsed: number;
}

function envelope(dataKey: Buffer, repoId: string, version: number, epoch: number, alts: Alt[]) {
  const body = Buffer.from(JSON.stringify({ alts, payloadVersion: version }), "utf8");
  return encryptPayload(dataKey, repoId, version, epoch, body) as EncryptedEnvelopeFields;
}

// ─── Auth (challenge → sign raw nonce → token), SPEC §3 ──────────────────────────

async function challenge(id: Identity): Promise<string> {
  const res = await req("POST", "/api/auth/keypair/challenge", { ed25519PublicKey: id.ed25519PublicKey });
  if (res.status !== 200 || typeof res.body?.nonce !== "string") {
    throw new Error(`challenge failed: ${res.status} ${res.text}`);
  }
  return res.body.nonce;
}

function signRawNonce(id: Identity, nonceB64: string): string {
  return edSign(null, Buffer.from(nonceB64, "base64"), id.edPrivateKey).toString("base64");
}

async function authenticate(id: Identity): Promise<string> {
  const nonce = await challenge(id);
  const res = await req("POST", "/api/auth/keypair/token", {
    ed25519PublicKey: id.ed25519PublicKey,
    nonce,
    signature: signRawNonce(id, nonce),
  });
  if (res.status !== 200 || typeof res.body?.token !== "string") {
    throw new Error(`token failed: ${res.status} ${res.text}`);
  }
  return res.body.token;
}

const SECRET = "ZK-PROBE-SECRET-do-not-leak"; // a marker we encrypt; must never surface server-side

// ─── The suite ──────────────────────────────────────────────────────────────────

async function run(): Promise<void> {
  const alice = generateIdentity();
  const bob = generateIdentity();
  const carol = generateIdentity(); // never a member

  // §3 Authentication
  const aliceNonce = await challenge(alice);
  check("§3", "challenge returns a base64 nonce >= 32 bytes", Buffer.from(aliceNonce, "base64").length >= 32);

  // Correct signature → token.
  const goodTok = await req("POST", "/api/auth/keypair/token", {
    ed25519PublicKey: alice.ed25519PublicKey,
    nonce: aliceNonce,
    signature: signRawNonce(alice, aliceNonce),
  });
  check("§3", "valid signed nonce yields a 200 token", goodTok.status === 200 && typeof goodTok.body?.token === "string");
  const aliceToken: string = goodTok.body?.token;

  // Reused nonce → rejected (single-use, MUST).
  const reuse = await req("POST", "/api/auth/keypair/token", {
    ed25519PublicKey: alice.ed25519PublicKey,
    nonce: aliceNonce,
    signature: signRawNonce(alice, aliceNonce),
  });
  check("§3", "a reused nonce is rejected (single-use)", reuse.status >= 400, `got ${reuse.status}`);

  // Signing the base64 string instead of the raw nonce bytes → rejected.
  const badNonce = await challenge(alice);
  const wrongSig = edSign(null, Buffer.from(badNonce, "utf8"), alice.edPrivateKey).toString("base64");
  const badSig = await req("POST", "/api/auth/keypair/token", {
    ed25519PublicKey: alice.ed25519PublicKey,
    nonce: badNonce,
    signature: wrongSig,
  });
  check("§3", "signing the base64 string (not raw bytes) is rejected", badSig.status >= 400, `got ${badSig.status}`);

  // Unauthenticated vault call → 401.
  const noAuth = await req("POST", "/v1/repos", { manifest: {}, initialEnvelope: {} });
  check("§3", "vault route without a token is 401", noAuth.status === 401, `got ${noAuth.status}`);

  // §6 createRepo
  const dataKey = randomBytes(32);
  const repoId = randomUUID();
  const altsV1: Alt[] = [{ uuid: randomUUID(), username: "main", accessToken: SECRET, type: "MICROSOFT", lastUsed: 1 }];
  const manifestV1 = {
    repoId,
    schemeId: WRAP_SCHEME_ID,
    keyEpoch: 0,
    payloadVersion: 1,
    members: [memberEntry(alice, dataKey, 0)],
  };
  const created = await req("POST", "/v1/repos", {
    manifest: manifestV1,
    initialEnvelope: envelope(dataKey, repoId, 1, 0, altsV1),
  }, aliceToken);
  check("§6", "createRepo returns 200 with a 1-member manifest",
    created.status === 200 && created.body?.members?.length === 1, `got ${created.status}`);

  // createRepo where the sole member is not the caller → 403.
  const notSelf = await req("POST", "/v1/repos", {
    manifest: { ...manifestV1, repoId: randomUUID(), members: [memberEntry(bob, dataKey, 0)] },
    initialEnvelope: envelope(dataKey, repoId, 1, 0, altsV1),
  }, aliceToken);
  check("§6", "createRepo whose sole member != caller is 403", notSelf.status === 403, `got ${notSelf.status}`);

  // Duplicate repoId → 409.
  const dup = await req("POST", "/v1/repos", {
    manifest: manifestV1,
    initialEnvelope: envelope(dataKey, repoId, 1, 0, altsV1),
  }, aliceToken);
  check("§6", "duplicate repoId on create is 409", dup.status === 409, `got ${dup.status}`);

  // pull at current version → unchanged, no envelope.
  const pullKnown = await req("POST", repoPath(repoId, "pull"), { repoId, knownPayloadVersion: 1 }, aliceToken);
  check("§6", "pull at the current version is unchanged with no envelope",
    pullKnown.status === 200 && pullKnown.body?.unchanged === true && pullKnown.body?.envelope == null);

  // pull from 0 → envelope present and decrypts to what we stored.
  const pullFresh = await req("POST", repoPath(repoId, "pull"), { repoId, knownPayloadVersion: 0 }, aliceToken);
  check("§6", "pull from an older version returns the current envelope",
    pullFresh.status === 200 && pullFresh.body?.unchanged === false && pullFresh.body?.envelope != null);
  await checkThrows("§4", "the returned envelope round-trips back to our plaintext", () => {
    const pt = decryptPayload(dataKey, pullFresh.body.envelope as EncryptedEnvelopeFields);
    const got = JSON.parse(pt.toString("utf8")) as { alts: Alt[] };
    if (got.alts[0]?.accessToken !== SECRET) {
      throw new Error("decrypted payload did not match what we encrypted");
    }
  });

  // §10 Zero-knowledge: the secret we encrypted must not surface anywhere the server returns.
  const serverView = JSON.stringify(pullFresh.body);
  let secretInCiphertext = false;
  for (const field of [pullFresh.body.envelope.ciphertext, pullFresh.body.envelope.iv]) {
    if (typeof field === "string" && Buffer.from(field, "base64").includes(Buffer.from(SECRET, "utf8"))) {
      secretInCiphertext = true;
    }
  }
  check("§10", "plaintext does not appear in the server's manifest/envelope JSON", !serverView.includes(SECRET));
  check("§10", "plaintext bytes do not appear inside the stored ciphertext/iv", !secretInCiphertext);

  // §6 push with optimistic concurrency
  const altsV2: Alt[] = [...altsV1, { uuid: randomUUID(), username: "alt", accessToken: SECRET, type: "MICROSOFT", lastUsed: 2 }];
  const okPush = await req("POST", repoPath(repoId, "push"), {
    repoId,
    envelope: envelope(dataKey, repoId, 2, 0, altsV2),
    expectedPayloadVersion: 1,
  }, aliceToken);
  check("§6", "push at the expected version is accepted and bumps the version",
    okPush.status === 200 && okPush.body?.accepted === true && okPush.body?.payloadVersion === 2);

  // Stale push → 200 conflict, NOT a 4xx.
  const stalePush = await req("POST", repoPath(repoId, "push"), {
    repoId,
    envelope: envelope(dataKey, repoId, 2, 0, altsV2),
    expectedPayloadVersion: 1, // stale
  }, aliceToken);
  check("§6", "a stale push is a 200 with conflict=true (not a 4xx)",
    stalePush.status === 200 && stalePush.body?.accepted === false && stalePush.body?.conflict === true,
    `got status ${stalePush.status} accepted=${stalePush.body?.accepted} conflict=${stalePush.body?.conflict}`);

  // §6 Authorization: a non-member cannot read the repo.
  const carolToken = await authenticate(carol);
  const carolPull = await req("POST", repoPath(repoId, "pull"), { repoId, knownPayloadVersion: 0 }, carolToken);
  check("§6", "a non-member's pull is 403", carolPull.status === 403, `got ${carolPull.status}`);

  // §6 addMember + fetchMemberKey
  const added = await req("POST", repoPath(repoId, "add-member"), { repoId, member: memberEntry(bob, dataKey, 0) }, aliceToken);
  check("§6", "addMember returns a manifest now listing both members",
    added.status === 200 && added.body?.members?.length === 2);

  const fetched = await req("GET", `/v1/repos/${encodeURIComponent(repoId)}/member/${encodeURIComponent(bob.ed25519PublicKey)}`,
    undefined, aliceToken);
  check("§6", "fetchMemberKey returns bob's entry (percent-encoded member id)",
    fetched.status === 200 && fetched.body?.x25519PublicKey === bob.x25519PublicKey, `got ${fetched.status}`);

  // bob (a real member) pulls, unwraps, decrypts → recovers the same plaintext.
  const bobToken = await authenticate(bob);
  const bobPull = await req("POST", repoPath(repoId, "pull"), { repoId, knownPayloadVersion: 0 }, bobToken);
  const bobOldEntry = bobPull.body?.manifest?.members?.find((m: any) => m.ed25519PublicKey === bob.ed25519PublicKey);
  await checkThrows("§4", "a second member unwraps the data key and decrypts the payload", () => {
    const bobKey = unwrapDataKey(bob.xPrivateKey, bobOldEntry.wrappedDataKey as WrappedKeyFields);
    const pt = decryptPayload(bobKey, bobPull.body.envelope as EncryptedEnvelopeFields);
    if (!pt.toString("utf8").includes(SECRET)) {
      throw new Error("bob could not recover the payload");
    }
  });

  // §10 Rotation on removeMember: remove bob, rotate to a new epoch + data key.
  const newKey = randomBytes(32);
  const newEpoch = 1;
  const newVersion = (bobPull.body?.manifest?.payloadVersion ?? 2) + 1;
  const rotatedEnvelope = envelope(newKey, repoId, newVersion, newEpoch, altsV2);
  const removed = await req("POST", repoPath(repoId, "remove-member"), {
    repoId,
    removedMemberId: bob.ed25519PublicKey,
    rotatedEnvelope,
    rewrappedMembers: [memberEntry(alice, newKey, newEpoch)],
    newKeyEpoch: newEpoch,
  }, aliceToken);
  check("§10", "removeMember bumps the epoch and drops the removed member",
    removed.status === 200 && removed.body?.keyEpoch === newEpoch
      && !removed.body?.members?.some((m: any) => m.ed25519PublicKey === bob.ed25519PublicKey));

  // The removed member can no longer read the repo.
  const bobAfter = await req("POST", repoPath(repoId, "pull"), { repoId, knownPayloadVersion: 0 }, bobToken);
  check("§6", "the removed member's pull is now 403", bobAfter.status === 403, `got ${bobAfter.status}`);

  // bob's OLD wrapped key recovers the OLD data key, which CANNOT decrypt the new-epoch envelope.
  const bobOldKey = unwrapDataKey(bob.xPrivateKey, bobOldEntry.wrappedDataKey as WrappedKeyFields);
  check("§10", "the departed member's old key differs from the rotated key", !bobOldKey.equals(newKey));
  await checkThrows("§10", "a stale-epoch key cannot decrypt the rotated envelope", () => {
    decryptPayload(bobOldKey, rotatedEnvelope);
  }, { expectThrow: true });

  // alice (still a member) decrypts the rotated envelope with her freshly wrapped key.
  const alicePull = await req("POST", repoPath(repoId, "pull"), { repoId, knownPayloadVersion: 0 }, aliceToken);
  const aliceNewEntry = alicePull.body?.manifest?.members?.find((m: any) => m.ed25519PublicKey === alice.ed25519PublicKey);
  await checkThrows("§10", "a remaining member decrypts the rotated envelope", () => {
    const k = unwrapDataKey(alice.xPrivateKey, aliceNewEntry.wrappedDataKey as WrappedKeyFields);
    const pt = decryptPayload(k, alicePull.body.envelope as EncryptedEnvelopeFields);
    if (!pt.toString("utf8").includes(SECRET)) {
      throw new Error("alice could not recover the rotated payload");
    }
  });
}

// ─── Report ─────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log(`AVP conformance harness → ${BASE_URL}\n`);
  try {
    await run();
  } catch (err) {
    console.error(`\nHarness aborted (could not complete the flow): ${err instanceof Error ? err.message : err}`);
    console.error("Is a conformant server running at the target URL?");
    process.exitCode = 1;
    return;
  }

  let passed = 0;
  for (const r of results) {
    const mark = r.ok ? "PASS" : "FAIL";
    const tail = r.ok ? "" : `  (${r.detail})`;
    console.log(`  [${mark}] ${r.section.padEnd(4)} ${r.name}${tail}`);
    if (r.ok) {
      passed += 1;
    }
  }
  const failed = results.length - passed;
  console.log(`\n${passed}/${results.length} checks passed${failed ? `, ${failed} FAILED` : ""}.`);
  process.exitCode = failed === 0 ? 0 : 1;
}

void main();
