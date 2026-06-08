/**
 * gRPC reference client for the Alt Vault Protocol.
 *
 * Drives the whole wire contract over a single gRPC channel against the sibling `../server` (or any
 * conformant gRPC server): generate an Ed25519 + X25519 identity, run the challenge -> sign -> token auth
 * flow (the example `Auth` service), then create a repo, pull, push, add a second member, fetch that
 * member's key, have the second member decrypt, and finally rotate them out with removeMember. Every one
 * of the canonical `Vault` RPCs is exercised.
 *
 * The envelope and wrapped-key cryptography is REAL and reused from the vector-tested
 * ../../typescript/client/src/crypto.ts, so this client and the HTTP/JSON client are byte-compatible at
 * the message level; only the transport differs. The token rides in `authorization` gRPC metadata.
 *
 * Run: `npm install && npm run client` (uses tsx). Point it with AVP_GRPC_TARGET (default localhost:50051).
 *
 * SPDX-License-Identifier: MIT
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
} from "../../typescript/client/src/crypto.ts";
import { avp, grpc } from "../proto.ts";

const TARGET = process.env.AVP_GRPC_TARGET ?? "localhost:50051";

const vault = new avp.Vault(TARGET, grpc.credentials.createInsecure());
const authClient = new avp.Auth(TARGET, grpc.credentials.createInsecure());

/** Promisify a unary gRPC call; a conflict push resolves normally (it is not an error). */
function unary<T = any>(client: any, method: string, request: unknown, metadata?: any): Promise<T> {
  return new Promise((resolve, reject) => {
    const cb = (err: unknown, res: T) => (err ? reject(err) : resolve(res));
    if (metadata) {
      client[method](request, metadata, cb);
    } else {
      client[method](request, cb);
    }
  });
}

function bearer(token: string): any {
  const m = new grpc.Metadata();
  m.set("authorization", `Bearer ${token}`);
  return m;
}

// ─── Identity (SPEC sections 2, 3) ───────────────────────────────────────────────

interface Identity {
  ed25519PublicKey: string;
  x25519PublicKey: string;
  edPrivateKey: KeyObject;
  xPrivateKey: KeyObject;
}

function generateIdentity(): Identity {
  const { publicKey: edPub, privateKey: edPriv } = generateKeyPairSync("ed25519");
  const spki = edPub.export({ format: "der", type: "spki" }) as Buffer;
  const edPubRaw = spki.subarray(spki.length - 32);
  const { privateKey: xPriv, publicKeyRaw: xPubRaw } = generateX25519();
  return { ed25519PublicKey: edPubRaw.toString("base64"), x25519PublicKey: xPubRaw.toString("base64"), edPrivateKey: edPriv, xPrivateKey: xPriv };
}

async function authenticate(id: Identity): Promise<string> {
  const challenge = await unary(authClient, "Challenge", { ed25519PublicKey: id.ed25519PublicKey });
  const signature = edSign(null, Buffer.from(challenge.nonce, "base64"), id.edPrivateKey).toString("base64");
  const token = await unary(authClient, "Token", { ed25519PublicKey: id.ed25519PublicKey, nonce: challenge.nonce, signature });
  return token.token;
}

interface Alt {
  uuid: string;
  username: string;
  accessToken: string;
  type: string;
  lastUsed: number;
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

function envelope(dataKey: Buffer, repoId: string, version: number, epoch: number, alts: Alt[]) {
  return encryptPayload(dataKey, repoId, version, epoch, Buffer.from(JSON.stringify({ alts, payloadVersion: version }), "utf8")) as EncryptedEnvelopeFields;
}

const step = (label: string, detail: string) => console.log(`  ${label.padEnd(16)} ${detail}`);

async function main(): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    vault.waitForReady(Date.now() + 5000, (err: unknown) => (err ? reject(err) : resolve()));
  });

  console.log(`AVP reference gRPC client -> ${TARGET}`);
  console.log("(Real envelope/wrap crypto; the token rides in gRPC metadata; the server stays zero-knowledge.)\n");

  const alice = generateIdentity();
  const bob = generateIdentity();
  const aliceToken = await authenticate(alice);
  step("auth", `alice token=${aliceToken.slice(0, 12)}…`);

  const dataKey = randomBytes(32);
  const repoId = randomUUID();
  const altsV1: Alt[] = [{ uuid: randomUUID(), username: "alice_main", accessToken: "secret-v1", type: "MICROSOFT", lastUsed: 1 }];

  const manifest = await unary(vault, "CreateRepo", {
    manifest: { repoId, schemeId: WRAP_SCHEME_ID, keyEpoch: 0, payloadVersion: 1, members: [memberEntry(alice, dataKey, 0)] },
    initialEnvelope: envelope(dataKey, repoId, 1, 0, altsV1),
  }, bearer(aliceToken));
  step("createRepo", `repoId=${manifest.repoId} members=${manifest.members.length} v=${manifest.payloadVersion}`);

  const pullSame = await unary(vault, "Pull", { repoId, knownPayloadVersion: manifest.payloadVersion }, bearer(aliceToken));
  step("pull (known)", `unchanged=${pullSame.unchanged} envelope=${pullSame.envelope ? "present" : "null"}`);

  const altsV2: Alt[] = [...altsV1, { uuid: randomUUID(), username: "alice_alt", accessToken: "secret-v2", type: "MICROSOFT", lastUsed: 2 }];
  const push = await unary(vault, "Push", { repoId, envelope: envelope(dataKey, repoId, 2, 0, altsV2), expectedPayloadVersion: 1 }, bearer(aliceToken));
  step("push", `accepted=${push.accepted} conflict=${push.conflict} v=${push.payloadVersion}`);

  const conflict = await unary(vault, "Push", { repoId, envelope: envelope(dataKey, repoId, 2, 0, altsV2), expectedPayloadVersion: 1 }, bearer(aliceToken));
  step("push (stale)", `accepted=${conflict.accepted} conflict=${conflict.conflict} serverV=${conflict.payloadVersion}`);

  const withBob = await unary(vault, "AddMember", { repoId, member: memberEntry(bob, dataKey, 0) }, bearer(aliceToken));
  step("addMember", `members=${withBob.members.length} (added bob)`);

  const bobEntry = await unary(vault, "FetchMemberKey", { repoId, memberId: bob.ed25519PublicKey }, bearer(aliceToken));
  step("fetchMemberKey", `bob x25519=${bobEntry.x25519PublicKey.slice(0, 12)}…`);

  // bob authenticates, pulls, unwraps, decrypts.
  const bobToken = await authenticate(bob);
  const bobPull = await unary(vault, "Pull", { repoId, knownPayloadVersion: 0 }, bearer(bobToken));
  const bobMember = bobPull.manifest.members.find((m: any) => m.ed25519PublicKey === bob.ed25519PublicKey);
  const bobDataKey = unwrapDataKey(bob.xPrivateKey, bobMember.wrappedDataKey as WrappedKeyFields);
  const payload = JSON.parse(decryptPayload(bobDataKey, bobPull.envelope as EncryptedEnvelopeFields).toString("utf8"));
  step("bob pull", `v=${bobPull.manifest.payloadVersion} alts=${payload.alts.length} (decrypted)`);
  if (payload.alts.at(-1)?.accessToken !== "secret-v2") {
    throw new Error("bob did not recover alice's payload");
  }

  // Rotate bob out: new data key + epoch, re-wrap to alice only.
  const newKey = randomBytes(32);
  const rotated = await unary(vault, "RemoveMember", {
    repoId,
    removedMemberId: bob.ed25519PublicKey,
    rotatedEnvelope: envelope(newKey, repoId, bobPull.manifest.payloadVersion + 1, 1, altsV2),
    rewrappedMembers: [memberEntry(alice, newKey, 1)],
    newKeyEpoch: 1,
  }, bearer(aliceToken));
  step("removeMember", `members=${rotated.members.length} epoch=${rotated.keyEpoch} (bob rotated out)`);
  if (rotated.keyEpoch !== 1 || rotated.members.some((m: any) => m.ed25519PublicKey === bob.ed25519PublicKey)) {
    throw new Error("rotation did not drop bob / bump the epoch");
  }

  console.log("\nDone. Full lifecycle exercised over gRPC against a zero-knowledge server.");
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error("\nClient failed:", err instanceof Error ? err.message : err);
    console.error("Is a server running? Start one with `npm run server` in ../, or set AVP_GRPC_TARGET.");
    process.exit(1);
  });
