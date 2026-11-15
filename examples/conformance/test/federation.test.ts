/**
 * Tokens, signatures, fingerprints, device linking, and avp:// locators (SPEC section 11) against
 * vectors/federation.json.
 *
 * Token cases are a decode oracle and a canonical-encode check. Every signature in the file (the
 * host acceptance inside the invite token, the leave requests, the challenge transcripts) is verified
 * here with node:crypto over a message assembled by hand from the SPEC 11.3, 11.4, and 3.3 layouts,
 * independently of the helper that signed it. The link confirmation code and the fingerprints are recomputed by hand, and the
 * link grant is unwrapped by hand to recover the owner entropy.
 *
 * SPDX-License-Identifier: MIT
 */

import test from "node:test";
import assert from "node:assert/strict";
import {
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  hkdfSync,
  verify,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";

import { entropyToMnemonic, mnemonicToSeed, ownerKeysFromSeed } from "../src/bip39.ts";
import {
  challengeMessage,
  decodeInviteToken,
  decodeLinkGrant,
  decodeLinkRequest,
  decodeRepoLocator,
  encodeToken,
  keyFingerprint,
  linkConfirmationCode,
  ownerFingerprint,
  signChallenge,
  verifyChallenge,
  verifyInvite,
  type WireInviteToken,
} from "../src/constructions.ts";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..", "..");

const schema = JSON.parse(readFileSync(join(root, "schema", "avp.schema.json"), "utf8"));
const fed = JSON.parse(readFileSync(join(root, "vectors", "federation.json"), "utf8"));
const manifest = JSON.parse(readFileSync(join(root, "vectors", "manifest.json"), "utf8"));

const ajv = new Ajv2020({ strict: false, allErrors: true });
ajv.addSchema(schema, "avp");

const fromB64 = (s: string) => Buffer.from(s, "base64");
const sha256 = (...p: Buffer[]) => {
  const h = createHash("sha256");
  for (const x of p) h.update(x);
  return h.digest();
};

// ---- hand-assembled CE pieces (SPEC 4.1), independent of CeWriter ----
const be32 = (n: number) => Buffer.from([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
function be64(n: number): Buffer {
  const out = Buffer.alloc(8);
  let u = BigInt.asUintN(64, BigInt(n));
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(u & 0xffn);
    u >>= 8n;
  }
  return out;
}
const lp = (b: Buffer) => Buffer.concat([be32(b.length), b]);
const label = (l: string) => Buffer.concat([Buffer.from(l, "utf8"), Buffer.from([0])]);

function acceptanceMessage(a: any): Buffer {
  return Buffer.concat([
    label("avp/accept/v1"),
    lp(Buffer.from(a.repoId, "utf8")),
    lp(fromB64(a.memberKey)),
    lp(fromB64(a.hostKey)),
    be64(a.expiresAt),
  ]);
}

function leaveMessage(l: any): Buffer {
  return Buffer.concat([label("avp/leave/v1"), lp(Buffer.from(l.repoId, "utf8")), lp(fromB64(l.memberKey)), be64(l.at)]);
}

function edVerify(pubB64: string, msg: Buffer, sigB64: string): boolean {
  const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), fromB64(pubB64)]);
  return verify(null, msg, createPublicKey({ key: spki, format: "der", type: "spki" }), fromB64(sigB64));
}

const DECODERS: Record<string, (s: string) => unknown> = {
  InviteToken: decodeInviteToken,
  RepoLocator: decodeRepoLocator,
  LinkRequest: decodeLinkRequest,
  LinkGrant: decodeLinkGrant,
};

test("federation.json carries one token of every SPEC 11 kind", () => {
  const schemas = new Set((fed.tokens as any[]).map((t) => t.schema));
  for (const k of Object.keys(DECODERS)) assert.ok(schemas.has(k), `missing a ${k} token`);
  assert.ok((fed.leaves as any[]).length > 0);
});

for (const tc of fed.tokens as Array<any>) {
  test(`federation token ${tc.name}: decoding base64url yields the object`, () => {
    const obj = JSON.parse(Buffer.from(tc.base64url, "base64url").toString("utf8"));
    assert.deepEqual(obj, tc.decoded);
    assert.equal(obj.v, 2);
    assert.deepEqual(DECODERS[tc.schema](tc.base64url), tc.decoded);
  });

  test(`federation token ${tc.name}: canonical minified encoding round-trips`, () => {
    const json = JSON.stringify(tc.decoded);
    assert.equal(json, tc.canonicalJson, "canonical JSON mismatch (field order or whitespace)");
    assert.equal(Buffer.from(json, "utf8").toString("base64url"), tc.base64url, "base64url mismatch");
    assert.equal(encodeToken(tc.schema, tc.decoded), tc.base64url);
    assert.doesNotMatch(tc.base64url, /[=+/]/, "base64url-nopad has no padding and no +/");
  });

  test(`federation token ${tc.name}: decoded object validates against ${tc.schema}`, () => {
    const validate = ajv.getSchema(`avp#/$defs/${tc.schema}`);
    assert.ok(validate, `schema is missing $def ${tc.schema}`);
    assert.ok(validate(tc.decoded), JSON.stringify(validate.errors, null, 2));
  });

  test(`federation token ${tc.name}: a decoder accepts any field order and whitespace`, () => {
    const reversed = Object.fromEntries(Object.entries(tc.decoded).reverse());
    const loose = Buffer.from(JSON.stringify(reversed, null, 2), "utf8").toString("base64url");
    assert.deepEqual(DECODERS[tc.schema](loose), tc.decoded);
    assert.equal(encodeToken(tc.schema, reversed as any), tc.base64url, "the encoder restores the listed order");
  });

  test(`federation token ${tc.name}: a decoder rejects v != 2, a missing field, and bad base64url`, () => {
    const dec = DECODERS[tc.schema];
    const enc = (o: unknown) => Buffer.from(JSON.stringify(o), "utf8").toString("base64url");
    assert.throws(() => dec(enc({ ...tc.decoded, v: 1 })));
    assert.throws(() => dec(enc({ ...tc.decoded, v: "2" })));
    const keys = Object.keys(tc.decoded);
    const missing = { ...tc.decoded };
    delete missing[keys[keys.length - 1]];
    assert.throws(() => dec(enc(missing)));
    assert.throws(() => dec(tc.base64url + "!"));
    assert.throws(() => dec(Buffer.from("not json", "utf8").toString("base64url")));
    assert.throws(() => dec(enc([tc.decoded])));
  });
}

// ---- signatures, verified with node:crypto over hand-assembled messages ----

test("invite token: the host acceptance signature verifies under hostKey over SPEC 11.3", () => {
  const tc = (fed.tokens as any[]).find((t) => t.schema === "InviteToken");
  const a = tc.decoded.acceptance;
  const msg = acceptanceMessage(a);
  assert.equal(msg.toString("hex"), tc.acceptanceMessageHex);
  assert.ok(edVerify(a.hostKey, msg, a.signature));
  assert.equal(a.memberKey, tc.decoded.ed25519PublicKey);
  assert.equal(a.hostKey, tc.decoded.homeHostKey);
  assert.equal(a.repoId, manifest.cases[0].expected.repoId);
});

test("invite token: owner verification accepts it and rejects each SPEC 8.2 failure", () => {
  const tc = (fed.tokens as any[]).find((t) => t.schema === "InviteToken");
  const t: WireInviteToken = tc.decoded;
  const repoId = t.acceptance.repoId;
  const before = t.acceptance.expiresAt - 1;
  assert.equal(verifyInvite(t, repoId, before), true);
  // expiresAt must be later than now
  assert.equal(verifyInvite(t, repoId, t.acceptance.expiresAt), false);
  // acceptance repoId must equal the repository's
  assert.equal(verifyInvite(t, "A".repeat(22), before), false);
  // memberKey must equal the token's ed25519PublicKey
  assert.equal(verifyInvite({ ...t, ed25519PublicKey: t.x25519PublicKey }, repoId, before), false);
  // hostKey must equal the token's homeHostKey
  assert.equal(verifyInvite({ ...t, homeHostKey: t.ed25519PublicKey }, repoId, before), false);
  // signature must verify under the acceptance's hostKey
  const sig = fromB64(t.acceptance.signature);
  sig[0] ^= 1;
  assert.equal(verifyInvite({ ...t, acceptance: { ...t.acceptance, signature: sig.toString("base64") } }, repoId, before), false);
  assert.equal(verifyInvite({ ...t, acceptance: { ...t.acceptance, expiresAt: t.acceptance.expiresAt + 1 } }, repoId, before), false);
  assert.equal(verifyInvite({ ...t, acceptance: { ...t.acceptance, hostKey: "AAAA" } }, repoId, before), false);
});

for (const lc of fed.leaves as Array<any>) {
  test(`leave request ${lc.name}: signature verifies under memberKey over SPEC 11.4 and the body validates`, () => {
    const msg = leaveMessage(lc.decoded);
    assert.equal(msg.toString("hex"), lc.signatureMessageHex);
    assert.ok(edVerify(lc.decoded.memberKey, msg, lc.decoded.signature));
    const validate = ajv.getSchema("avp#/$defs/LeaveRequest");
    assert.ok(validate && validate(lc.decoded), JSON.stringify(validate?.errors));
  });
}

// ---- challenge transcript (SPEC 3.3), verified with node:crypto over a hand-assembled message ----

function challengeMsg(hostKey: Buffer, key: Buffer, nonce: Buffer): Buffer {
  return Buffer.concat([label("avp/challenge/v1"), lp(hostKey), lp(key), lp(nonce)]);
}

/** The Ed25519 seed of a manifest.json party (the owner or a member) by its public key. */
function seedOf(pubB64: string): Buffer {
  if (manifest.seeds.owner.ownerKey === pubB64) return Buffer.from(manifest.seeds.owner.ed25519SeedHex, "hex");
  const m = (manifest.seeds.members as any[]).find((x) => x.ed25519PublicKey === pubB64);
  assert.ok(m, `no manifest.json seed for ${pubB64}`);
  return Buffer.from(m.ed25519SeedHex, "hex");
}

test("federation.json carries challenge transcripts, one with a nonce above the 32-byte minimum", () => {
  const cs = fed.challenges as any[];
  assert.ok(cs.length >= 2);
  assert.ok(cs.every((c) => fromB64(c.nonce).length >= 32));
  assert.ok(cs.some((c) => fromB64(c.nonce).length > 32));
  const hostKeys = new Set((manifest.seeds.hosts as any[]).map((h) => h.hostKey));
  for (const c of cs) assert.ok(hostKeys.has(c.hostKey), `${c.name}: hostKey is a manifest.json host`);
});

for (const cc of fed.challenges as Array<any>) {
  test(`challenge ${cc.name}: messageHex is the SPEC 3.3 transcript and the signature verifies over it`, () => {
    const hostKey = fromB64(cc.hostKey);
    const key = fromB64(cc.ed25519PublicKey);
    const nonce = fromB64(cc.nonce);
    const msg = challengeMsg(hostKey, key, nonce);
    assert.equal(msg.toString("hex"), cc.messageHex);
    assert.equal(challengeMessage(hostKey, key, nonce).toString("hex"), cc.messageHex);
    assert.ok(edVerify(cc.ed25519PublicKey, msg, cc.signature));
    assert.equal(signChallenge(hostKey, seedOf(cc.ed25519PublicKey), nonce).toString("base64"), cc.signature, "the signature reproduces");
    assert.equal(verifyChallenge(hostKey, key, nonce, fromB64(cc.signature)), true);
  });

  test(`challenge ${cc.name}: the signature does not verify for another host key, as a raw nonce, or as a commit signature`, () => {
    const hostKey = fromB64(cc.hostKey);
    const key = fromB64(cc.ed25519PublicKey);
    const nonce = fromB64(cc.nonce);
    const sig = fromB64(cc.signature);
    const other = (manifest.seeds.hosts as any[]).find((h) => h.hostKey !== cc.hostKey);
    assert.equal(verifyChallenge(fromB64(other.hostKey), key, nonce, sig), false, "bound to the host key");
    assert.equal(edVerify(cc.ed25519PublicKey, nonce, cc.signature), false, "not a signature over the raw nonce");
    assert.equal(verifyChallenge(hostKey, key, nonce, Buffer.from(sig.map((b, i) => (i === 0 ? b ^ 1 : b)))), false);
    // The transcript of a 32-byte nonce is never the commit-sig message of that value (SPEC 4.1).
    const asCommitSig = Buffer.concat([label("avp/commit-sig/v1"), lp(nonce.subarray(0, 32))]);
    assert.equal(edVerify(cc.ed25519PublicKey, asCommitSig, cc.signature), false, "not a commit author signature");
  });
}

test("challenge transcript: the construction rejects keys that are not 32 bytes", () => {
  const k = Buffer.alloc(32, 1);
  assert.throws(() => challengeMessage(Buffer.alloc(31), k, k));
  assert.throws(() => challengeMessage(k, Buffer.alloc(33), k));
  assert.equal(verifyChallenge(Buffer.alloc(31), k, k, Buffer.alloc(64)), false, "verify never throws");
});

// ---- link confirmation code, fingerprints, link grant (hand computations) ----

for (const lc of fed.linkCodes as Array<any>) {
  test(`link confirmation code ${lc.name}: first 4 bytes of the SPEC 11.6 hash, u32BE mod 10^6, 6 digits`, () => {
    const eph = fromB64(lc.ephemeralPublicKey);
    const digest = sha256(label("avp/link-code/v1"), lp(eph));
    const n = ((digest[0] << 24) >>> 0) + (digest[1] << 16) + (digest[2] << 8) + digest[3];
    const code = String(n % 1_000_000).padStart(6, "0");
    assert.equal(code, lc.code);
    assert.match(lc.code, /^\d{6}$/);
    assert.equal(linkConfirmationCode(eph), lc.code);
  });
}

test("link codes include one with a leading zero, so zero padding is pinned", () => {
  assert.ok((fed.linkCodes as any[]).some((c) => c.code.startsWith("0")));
});

for (const fp of fed.fingerprints.members as Array<any>) {
  test(`member key fingerprint ${fp.label}: hex(SHA-256(ed25519 || x25519)[0..8]) grouped by four (SPEC 3.2)`, () => {
    const h = sha256(fromB64(fp.ed25519PublicKey), fromB64(fp.x25519PublicKey)).subarray(0, 8).toString("hex");
    assert.equal(fp.fingerprint, h.match(/.{4}/g)!.join("-"));
    assert.equal(keyFingerprint(fromB64(fp.ed25519PublicKey), fromB64(fp.x25519PublicKey)), fp.fingerprint);
  });
}

test("owner fingerprint: hex(SHA-256(ownerKey)[0..8]) and the repo locator carries it (SPEC 11.2)", () => {
  const o = fed.fingerprints.owner;
  assert.equal(o.ownerKey, manifest.seeds.owner.ownerKey);
  assert.equal(o.ownerFingerprint, sha256(fromB64(o.ownerKey)).subarray(0, 8).toString("hex"));
  assert.equal(ownerFingerprint(fromB64(o.ownerKey)), o.ownerFingerprint);
  for (const t of (fed.tokens as any[]).filter((x) => x.schema === "RepoLocator")) {
    assert.equal(t.decoded.ownerFingerprint, o.ownerFingerprint);
    assert.equal(t.decoded.repoId, manifest.cases[0].expected.repoId);
  }
});

test("link grant: unwrapping under avp/owner-link/v1 recovers the owner entropy, which derives the ownerKey", () => {
  const tc = (fed.tokens as any[]).find((t) => t.schema === "LinkGrant");
  const req = (fed.tokens as any[]).find((t) => t.schema === "LinkRequest");
  const w = tc.decoded.wrap;
  const ephPriv = createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b656e04220420", "hex"), Buffer.from(tc.checker.linkEphemeralPrivateHex, "hex")]),
    format: "der",
    type: "pkcs8",
  });
  const jwk = createPublicKey(ephPriv).export({ format: "jwk" }) as { x: string };
  assert.equal(Buffer.from(jwk.x, "base64url").toString("base64"), req.decoded.ephemeralPublicKey, "the grant answers the link request");
  const wrapPub = createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b656e032100", "hex"), fromB64(w.ephemeralPublicKey)]),
    format: "der",
    type: "spki",
  });
  const shared = diffieHellman({ privateKey: ephPriv, publicKey: wrapPub });
  const unwrap = (info: string) => {
    const kek = Buffer.from(hkdfSync("sha256", shared, fromB64(w.ephemeralPublicKey), Buffer.from(info, "utf8"), 32));
    const ct = fromB64(w.ciphertext);
    const d = createDecipheriv("aes-256-gcm", kek, fromB64(w.iv));
    d.setAAD(Buffer.from(info, "utf8"));
    d.setAuthTag(ct.subarray(ct.length - 16));
    return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
  };
  const entropy = unwrap("avp/owner-link/v1");
  assert.equal(entropy.toString("hex"), tc.checker.entropyHex);
  assert.equal(entropy.length, 32);
  assert.throws(() => unwrap("avp/rdk-wrap/v1"), "the data key wrap label MUST NOT unwrap a link grant");
  const keys = ownerKeysFromSeed(mnemonicToSeed(entropyToMnemonic(entropy)));
  assert.equal(keys.ed25519Public.toString("base64"), manifest.seeds.owner.ownerKey);
});

// ---- avp://<hostLocator>/<repoId> (SPEC 11.2) ----

const AVP_URI = /^avp:\/\/([^/]+)\/(.+)$/;

function parseAvpUri(uri: string): { host: string; repoId: string } {
  const m = AVP_URI.exec(uri);
  if (!m) {
    throw new Error(`not an avp:// uri: ${uri}`);
  }
  return { host: m[1], repoId: m[2] };
}

function formatAvpUri(host: string, repoId: string): string {
  return `avp://${host}/${repoId}`;
}

for (const tc of fed.uris as Array<any>) {
  test(`avp uri ${tc.name}: parses into host and repoId`, () => {
    assert.deepEqual(parseAvpUri(tc.uri), { host: tc.host, repoId: tc.repoId });
  });

  test(`avp uri ${tc.name}: formats back to the same string`, () => {
    assert.equal(formatAvpUri(tc.host, tc.repoId), tc.uri);
  });

  test(`avp uri ${tc.name}: the repoId is a 22-character base64url id (SPEC 4.2)`, () => {
    assert.match(tc.repoId, /^[A-Za-z0-9_-]{22}$/);
  });
}
