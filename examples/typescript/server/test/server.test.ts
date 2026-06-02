import { after, before, beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, KeyObject, sign as cryptoSign } from "node:crypto";
import type { AddressInfo } from "node:net";
import { resetState, server } from "../src/server.ts";

let base = "";

before(async () => {
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const port = (server.address() as AddressInfo).port;
  base = `http://localhost:${port}`;
});

after(() => server.close());
beforeEach(() => resetState());

// ─── helpers ──────────────────────────────────────────────────────────────

interface KeyPair {
  pub: string;
  priv: KeyObject;
}

function keypair(): KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  return { pub: spki.subarray(spki.length - 32).toString("base64"), priv: privateKey };
}

async function post(path: string, body: unknown, token?: string): Promise<{ status: number; json: any }> {
  const res = await fetch(base + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(body),
  });
  return { status: res.status, json: await res.json() };
}

async function get(path: string, token: string): Promise<{ status: number; json: any }> {
  const res = await fetch(base + path, { headers: { Authorization: `Bearer ${token}` } });
  return { status: res.status, json: await res.json() };
}

/** Runs the keypair challenge -> token flow and returns a bearer token. */
async function authenticate(kp: KeyPair): Promise<string> {
  const challenge = await post("/api/auth/keypair/challenge", { ed25519PublicKey: kp.pub });
  const signature = cryptoSign(null, Buffer.from(challenge.json.nonce, "base64"), kp.priv).toString("base64");
  const token = await post("/api/auth/keypair/token", {
    ed25519PublicKey: kp.pub,
    nonce: challenge.json.nonce,
    signature,
  });
  return token.json.token;
}

function entry(pub: string, epoch = 0) {
  return {
    ed25519PublicKey: pub,
    x25519PublicKey: `x-${pub.slice(0, 6)}`,
    wrappedDataKey: { schemeId: "X25519-HKDF-SHA256-AESGCM-v1", ephemeralPublicKey: "eph", iv: "iv", ciphertext: "wk" },
    keyEpoch: epoch,
  };
}

function envelope(repoId: string, version: number, epoch = 0) {
  return { repoId, payloadVersion: version, keyEpoch: epoch, iv: "iv", ciphertext: `ct-${version}` };
}

// ─── tests ──────────────────────────────────────────────────────────────

test("rejects an unauthenticated vault call", async () => {
  const res = await post("/v1/repos", {});
  assert.equal(res.status, 401);
});

test("rejects a bad challenge signature", async () => {
  const kp = keypair();
  const challenge = await post("/api/auth/keypair/challenge", { ed25519PublicKey: kp.pub });
  const wrong = cryptoSign(null, Buffer.from("not the nonce"), keypair().priv).toString("base64");
  const token = await post("/api/auth/keypair/token", {
    ed25519PublicKey: kp.pub,
    nonce: challenge.json.nonce,
    signature: wrong,
  });
  assert.equal(token.status, 401);
});

test("full lifecycle: create, pull, push, add, fetch, remove", async () => {
  const alice = keypair();
  const aliceToken = await authenticate(alice);
  const repoId = "repo-lifecycle";

  const created = await post(
    "/v1/repos",
    {
      manifest: { repoId, schemeId: "scheme-v1", keyEpoch: 0, payloadVersion: 1, members: [entry(alice.pub)] },
      initialEnvelope: envelope(repoId, 1),
    },
    aliceToken,
  );
  assert.equal(created.status, 200);
  assert.equal(created.json.members.length, 1);

  // pull at the current version => unchanged; at an older version => the envelope, byte-for-byte.
  const fresh = await post(`/v1/repos/${repoId}/pull`, { repoId, knownPayloadVersion: 1 }, aliceToken);
  assert.equal(fresh.json.unchanged, true);
  const behind = await post(`/v1/repos/${repoId}/pull`, { repoId, knownPayloadVersion: 0 }, aliceToken);
  assert.equal(behind.json.unchanged, false);
  assert.equal(behind.json.envelope.ciphertext, "ct-1");

  // push with the right base version succeeds; a stale base version conflicts.
  const pushed = await post(
    `/v1/repos/${repoId}/push`,
    { repoId, envelope: envelope(repoId, 2), expectedPayloadVersion: 1 },
    aliceToken,
  );
  assert.equal(pushed.json.accepted, true);
  assert.equal(pushed.json.payloadVersion, 2);
  const stale = await post(
    `/v1/repos/${repoId}/push`,
    { repoId, envelope: envelope(repoId, 2), expectedPayloadVersion: 1 },
    aliceToken,
  );
  assert.equal(stale.json.conflict, true);
  assert.equal(stale.json.accepted, false);

  // add a member, then fetch their key back.
  const bob = keypair();
  const added = await post(`/v1/repos/${repoId}/add-member`, { repoId, member: entry(bob.pub) }, aliceToken);
  assert.equal(added.json.members.length, 2);
  const fetched = await get(`/v1/repos/${repoId}/member/${encodeURIComponent(bob.pub)}`, aliceToken);
  assert.equal(fetched.json.ed25519PublicKey, bob.pub);

  // remove bob: rotate to {alice} at a new epoch and a bumped version.
  const removed = await post(
    `/v1/repos/${repoId}/remove-member`,
    {
      repoId,
      removedMemberId: bob.pub,
      rotatedEnvelope: envelope(repoId, 3, 1),
      rewrappedMembers: [entry(alice.pub, 1)],
      newKeyEpoch: 1,
    },
    aliceToken,
  );
  assert.equal(removed.json.members.length, 1);
  assert.equal(removed.json.keyEpoch, 1);
  assert.equal(removed.json.payloadVersion, 3);
});

test("a non-member cannot read a repo", async () => {
  const alice = keypair();
  const aliceToken = await authenticate(alice);
  const repoId = "repo-private";
  await post(
    "/v1/repos",
    {
      manifest: { repoId, schemeId: "s", keyEpoch: 0, payloadVersion: 1, members: [entry(alice.pub)] },
      initialEnvelope: envelope(repoId, 1),
    },
    aliceToken,
  );

  const mallory = keypair();
  const malloryToken = await authenticate(mallory);
  const res = await post(`/v1/repos/${repoId}/pull`, { repoId, knownPayloadVersion: 0 }, malloryToken);
  assert.equal(res.status, 403);
});
