/**
 * Manifest state (SPEC sections 4.1 and 4.2) against vectors/manifest.json: the CE bytes of each state,
 * the owner signature, manifestHash, and the repoId derivation at seq 1.
 *
 * The CE construction has no external anchor, so every case is also re-derived here by a second,
 * differently written computation: the bytes are hand-assembled from the SPEC 4.2 layout with raw
 * Buffer concatenation, a hand-written unsigned byte comparator, and BigInt shifts for i64, without
 * calling CeWriter or the encoder under test. Input order of hosts, members, removals, and frontier
 * ids is shuffled and the encoding MUST NOT change.
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
  type KeyObject,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";

import {
  deriveRepoId,
  encodeManifestState,
  manifestHash,
  signManifest,
  type ManifestState,
} from "../src/constructions.ts";
import { loadManifestVectors, signedManifestFromWire } from "../src/vectors.ts";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..", "..");

const hex = (b: Buffer) => b.toString("hex");
const fromHex = (s: string) => Buffer.from(s, "hex");
const fromB64 = (s: string) => Buffer.from(s, "base64");

// ---- independent SPEC 4.1 primitives (raw Buffer concatenation, not CeWriter) ----

function be32(n: number): Buffer {
  return Buffer.from([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}
function be64(n: number): Buffer {
  let u = BigInt.asUintN(64, BigInt(n));
  const out = Buffer.alloc(8);
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(u & 0xffn);
    u >>= 8n;
  }
  return out;
}
const lenPrefixed = (b: Buffer) => Buffer.concat([be32(b.length), b]);
const utf8 = (s: string) => lenPrefixed(Buffer.from(s, "utf8"));
const label = (l: string) => Buffer.concat([Buffer.from(l, "utf8"), Buffer.from([0])]);

/** Unsigned bytewise order, shorter prefix first (SPEC 2), written without Buffer.compare. */
function byteOrder(a: Buffer, b: Buffer): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

/** Hand-assembles S (SPEC 4.2) straight from the wire JSON of a ManifestState. */
function handAssembleState(w: any): Buffer {
  const parts: Buffer[] = [
    label("avp/manifest/v1"),
    utf8(w.repoId),
    be64(w.manifestSeq),
    lenPrefixed(fromB64(w.prevManifestHash)),
    lenPrefixed(fromB64(w.ownerKey)),
    lenPrefixed(fromB64(w.genesisNonce)),
    utf8(w.schemeId),
    be64(w.keyEpoch),
    Buffer.from([w.shareRefreshTokens ? 1 : 0]),
  ];
  const hosts = [...w.hosts].sort((a: any, b: any) => byteOrder(fromB64(a.hostKey), fromB64(b.hostKey)));
  parts.push(be32(hosts.length));
  for (const h of hosts) parts.push(lenPrefixed(fromB64(h.hostKey)), utf8(h.locator));
  const members = [...w.members].sort((a: any, b: any) => byteOrder(fromB64(a.ed25519PublicKey), fromB64(b.ed25519PublicKey)));
  parts.push(be32(members.length));
  for (const m of members) {
    parts.push(
      lenPrefixed(fromB64(m.ed25519PublicKey)),
      lenPrefixed(fromB64(m.x25519PublicKey)),
      utf8(m.wrappedDataKey.schemeId),
      lenPrefixed(fromB64(m.wrappedDataKey.ephemeralPublicKey)),
      lenPrefixed(fromB64(m.wrappedDataKey.iv)),
      lenPrefixed(fromB64(m.wrappedDataKey.ciphertext)),
      be64(m.keyEpoch),
      lenPrefixed(fromB64(m.homeHostKey)),
    );
  }
  const removals = [...w.removals].sort((a: any, b: any) => byteOrder(fromB64(a.memberKey), fromB64(b.memberKey)));
  parts.push(be32(removals.length));
  for (const r of removals) {
    parts.push(lenPrefixed(fromB64(r.memberKey)), be64(r.removedAtSeq));
    const frontier = (r.frontier as string[]).map(fromB64).sort(byteOrder);
    parts.push(be32(frontier.length));
    for (const id of frontier) parts.push(lenPrefixed(id));
  }
  return Buffer.concat(parts);
}

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
function verifyEd25519(pub: Buffer, msg: Buffer, sig: Buffer): boolean {
  const key = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, pub]), format: "der", type: "spki" });
  return verify(null, msg, key, sig);
}

// ---- independent node:crypto key handling (RFC 8410 DER prefixes), not src/crypto.ts ----

const X25519_PKCS8 = Buffer.from("302e020100300506032b656e04220420", "hex");
const X25519_SPKI = Buffer.from("302a300506032b656e032100", "hex");
const ED25519_PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex");
const x25519Priv = (raw: Buffer) => createPrivateKey({ key: Buffer.concat([X25519_PKCS8, raw]), format: "der", type: "pkcs8" });
const x25519Pub = (raw: Buffer) => createPublicKey({ key: Buffer.concat([X25519_SPKI, raw]), format: "der", type: "spki" });
const rawPub = (k: KeyObject) => Buffer.from((createPublicKey(k).export({ format: "jwk" }) as { x: string }).x, "base64url");
const edPubFromSeed = (seed: Buffer) =>
  rawPub(createPrivateKey({ key: Buffer.concat([ED25519_PKCS8, seed]), format: "der", type: "pkcs8" }));
const xPubFromPriv = (priv: Buffer) => rawPub(x25519Priv(priv));

/** SPEC 4.4 unwrap with node:crypto directly: X25519, HKDF(salt = ephemeral pub, info), GCM(aad = info). */
function unwrapDirect(recipientPriv: Buffer, w: { ephemeralPublicKey: string; iv: string; ciphertext: string }): Buffer {
  const info = Buffer.from("avp/rdk-wrap/v1", "utf8");
  const eph = fromB64(w.ephemeralPublicKey);
  const shared = diffieHellman({ privateKey: x25519Priv(recipientPriv), publicKey: x25519Pub(eph) });
  const kek = Buffer.from(hkdfSync("sha256", shared, eph, info, 32));
  const ct = fromB64(w.ciphertext);
  const d = createDecipheriv("aes-256-gcm", kek, fromB64(w.iv));
  d.setAAD(info);
  d.setAuthTag(ct.subarray(ct.length - 16));
  return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
}

// ---- shuffles ----

function rotations<T>(xs: T[]): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < Math.max(1, xs.length); i++) out.push([...xs.slice(i), ...xs.slice(0, i)]);
  out.push([...xs].reverse());
  return out;
}

function shuffledVariants(s: ManifestState): ManifestState[] {
  const out: ManifestState[] = [];
  const hostsV = rotations(s.hosts);
  const membersV = rotations(s.members);
  const removalsV = rotations(s.removals.map((r) => ({ ...r, frontier: [...r.frontier].reverse() })));
  const n = Math.max(hostsV.length, membersV.length, removalsV.length);
  for (let i = 0; i < n; i++) {
    out.push({
      ...s,
      hosts: hostsV[i % hostsV.length],
      members: membersV[(i + 1) % membersV.length],
      removals: removalsV[i % removalsV.length],
    });
  }
  return out;
}

// ---- the vector file ----

const file = loadManifestVectors();
const raw = JSON.parse(readFileSync(join(root, "vectors", "manifest.json"), "utf8"));

test("manifest.json has the four documented cases in chain order", () => {
  assert.deepEqual(
    file.cases.map((c) => c.name),
    ["genesis", "add-members", "remove-member", "policy-flip"],
  );
  assert.deepEqual(
    file.cases.map((c) => c.signedManifest.state.manifestSeq),
    [1, 2, 3, 4],
  );
});

test("manifest.json wire objects validate against schema $defs/SignedManifest", () => {
  const schema = JSON.parse(readFileSync(join(root, "schema", "avp.schema.json"), "utf8"));
  const ajv = new Ajv2020({ strict: false, allErrors: true });
  ajv.addSchema(schema, "avp");
  const validate = ajv.getSchema("avp#/$defs/SignedManifest");
  assert.ok(validate);
  for (const c of raw.cases) assert.ok(validate(c.signedManifest), `${c.name}: ${JSON.stringify(validate.errors)}`);
});

for (const c of file.cases) {
  const wire = raw.cases.find((x: any) => x.name === c.name);

  test(`manifest ${c.name}: encodeManifestState matches the vector`, () => {
    const m = signedManifestFromWire(c.signedManifest);
    assert.equal(hex(encodeManifestState(m.state)), c.expected.stateHex);
  });

  test(`manifest ${c.name}: hand-assembled SPEC 4.2 bytes equal the vector`, () => {
    assert.equal(hex(handAssembleState(wire.signedManifest.state)), c.expected.stateHex);
  });

  test(`manifest ${c.name}: owner signature reproduces and verifies, manifestHash matches`, () => {
    const m = signedManifestFromWire(c.signedManifest);
    const seed = fromHex(file.seeds.owner.ed25519SeedHex);
    const signed = signManifest(m.state, seed);
    assert.equal(signed.ownerSignature.toString("base64"), c.signedManifest.ownerSignature);
    const s = fromHex(c.expected.stateHex);
    assert.ok(verifyEd25519(m.state.ownerKey, s, m.ownerSignature), "owner signature verifies over S");
    assert.equal(hex(manifestHash(m)), c.expected.manifestHashHex);
    // independent: SHA-256(S || raw 64-byte signature), no length prefix on the signature
    const independent = createHash("sha256").update(s).update(fromB64(c.signedManifest.ownerSignature)).digest("hex");
    assert.equal(independent, c.expected.manifestHashHex);
    assert.equal(m.ownerSignature.length, 64);
  });

  test(`manifest ${c.name}: shuffled list input order gives identical bytes`, () => {
    const m = signedManifestFromWire(c.signedManifest);
    for (const v of shuffledVariants(m.state)) assert.equal(hex(encodeManifestState(v)), c.expected.stateHex);
  });
}

test("manifest genesis: seq 1 edge rules and repoId derivation", () => {
  const g = signedManifestFromWire(file.cases[0].signedManifest).state;
  assert.equal(g.manifestSeq, 1);
  assert.equal(g.prevManifestHash.length, 0, "prevManifestHash empty at seq 1");
  assert.equal(g.genesisNonce.length, 16, "genesisNonce 16 bytes at seq 1");
  assert.equal(hex(g.genesisNonce), "01".repeat(16));
  assert.equal(g.keyEpoch, 0);
  assert.equal(g.removals.length, 0);
  assert.equal(g.members.length, 1);
  assert.equal(hex(g.members[0].ed25519PublicKey), hex(g.ownerKey));

  const id = deriveRepoId(g.ownerKey, g.genesisNonce);
  assert.equal(id, file.cases[0].expected.repoId);
  assert.equal(id, g.repoId);
  assert.equal(id.length, 22);
  assert.match(id, /^[A-Za-z0-9_-]{22}$/, "base64url without padding");
  // independent: base64url-nopad(SHA-256(tag || bytes(ownerKey) || bytes(genesisNonce))[0..16])
  const digest = createHash("sha256")
    .update(Buffer.concat([label("avp/repo-id/v1"), lenPrefixed(g.ownerKey), lenPrefixed(g.genesisNonce)]))
    .digest();
  assert.equal(digest.subarray(0, 16).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_"), id);
});

test("manifest chain: prevManifestHash links, genesisNonce empty after seq 1, repoId fixed", () => {
  for (let i = 1; i < file.cases.length; i++) {
    const s = signedManifestFromWire(file.cases[i].signedManifest).state;
    assert.equal(hex(s.prevManifestHash), file.cases[i - 1].expected.manifestHashHex, `${file.cases[i].name} links`);
    assert.equal(s.prevManifestHash.length, 32);
    assert.equal(s.genesisNonce.length, 0, "genesisNonce empty after seq 1");
    assert.equal(s.repoId, file.cases[0].signedManifest.state.repoId);
    assert.equal(file.cases[i].expected.repoId, undefined, "repoId is derived only at seq 1");
  }
  // SPEC 6.1 content rules every state satisfies: the owner is exactly one member, every member's
  // homeHostKey is a listed host, and every member's keyEpoch equals the state's.
  for (const c of file.cases) {
    const s = signedManifestFromWire(c.signedManifest).state;
    assert.ok(s.hosts.length > 0, `${c.name}: hosts not empty`);
    assert.equal(s.members.filter((m) => m.ed25519PublicKey.equals(s.ownerKey)).length, 1, `${c.name}: owner is a member`);
    for (const m of s.members) {
      assert.ok(s.hosts.some((h) => h.hostKey.equals(m.homeHostKey)), `${c.name}: homeHostKey is in hosts`);
      assert.equal(m.keyEpoch, s.keyEpoch, `${c.name}: member keyEpoch equals state keyEpoch`);
    }
  }
});

test("manifest seeds: every party's public keys derive from its seed hex; owner equals bip39-owner.json case 0", () => {
  const s = file.seeds;
  const bip = JSON.parse(readFileSync(join(root, "vectors", "bip39-owner.json"), "utf8")).cases[0];
  assert.equal(s.owner.entropyHex, bip.entropyHex);
  assert.equal(s.owner.ed25519SeedHex, bip.ed25519SeedHex);
  assert.equal(hex(fromB64(s.owner.ownerKey)), bip.ed25519PublicKeyHex);
  assert.equal(s.owner.x25519PrivateHex, bip.x25519PrivateHex);
  assert.equal(hex(fromB64(s.owner.x25519PublicKey)), bip.x25519PublicKeyHex);
  assert.equal(hex(edPubFromSeed(fromHex(s.owner.ed25519SeedHex))), hex(fromB64(s.owner.ownerKey)));
  assert.equal(hex(xPubFromPriv(fromHex(s.owner.x25519PrivateHex))), hex(fromB64(s.owner.x25519PublicKey)));
  const memberBytes: Record<string, string> = { alice: "11", bob: "22", carol: "33" };
  for (const m of s.members) {
    assert.equal(m.ed25519SeedHex, memberBytes[m.label].repeat(32), `${m.label} Ed25519 seed`);
    assert.equal(m.x25519PrivateHex, memberBytes[m.label].repeat(32), `${m.label} X25519 private`);
    assert.equal(edPubFromSeed(fromHex(m.ed25519SeedHex)).toString("base64"), m.ed25519PublicKey, `${m.label} Ed25519 public`);
    assert.equal(xPubFromPriv(fromHex(m.x25519PrivateHex!)).toString("base64"), m.x25519PublicKey, `${m.label} X25519 public`);
  }
  const hostBytes: Record<string, string> = { a: "a0", b: "b0" };
  for (const h of s.hosts) {
    assert.equal(h.ed25519SeedHex, hostBytes[h.label].repeat(32));
    assert.equal(edPubFromSeed(fromHex(h.ed25519SeedHex)).toString("base64"), h.hostKey, `host ${h.label} key`);
    assert.equal(h.locator, `${h.label}.vault.example`);
  }
  assert.deepEqual(
    s.dataKeys.map((k) => [k.keyEpoch, k.dataKeyHex]),
    [
      [0, "42".repeat(32)],
      [1, "43".repeat(32)],
    ],
  );
});

test("manifest member wraps open to the epoch's data key (SPEC 4.4, node:crypto directly) and follow wrapDerivation", () => {
  const s = file.seeds;
  const parties = [
    { label: "owner", ed25519PublicKey: s.owner.ownerKey, x25519PublicKey: s.owner.x25519PublicKey, x25519PrivateHex: s.owner.x25519PrivateHex },
    ...s.members.map((m) => ({ label: m.label, ed25519PublicKey: m.ed25519PublicKey, x25519PublicKey: m.x25519PublicKey!, x25519PrivateHex: m.x25519PrivateHex! })),
  ];
  const text = (p: string) => Buffer.from(p, "utf8");
  let checked = 0;
  for (const c of raw.cases) {
    for (const m of c.signedManifest.state.members) {
      const p = parties.find((x) => x.ed25519PublicKey === m.ed25519PublicKey);
      assert.ok(p, `${c.name}: member ${m.ed25519PublicKey} is a seeded party`);
      assert.equal(m.x25519PublicKey, p.x25519PublicKey, `${c.name}/${p.label} X25519 key`);
      const w = m.wrappedDataKey;
      assert.equal(w.schemeId, "X25519-HKDF-SHA256-AESGCM-v1");
      assert.deepEqual(
        [fromB64(w.ephemeralPublicKey).length, fromB64(w.iv).length, fromB64(w.ciphertext).length],
        [32, 12, 48],
        `${c.name}/${p.label} wrap field lengths (SPEC 6.1)`,
      );
      const dataKey = s.dataKeys.find((k) => k.keyEpoch === m.keyEpoch);
      assert.ok(dataKey, `${c.name}/${p.label} epoch ${m.keyEpoch} has a seeded data key`);
      const opened = unwrapDirect(fromHex(p.x25519PrivateHex), w);
      assert.equal(hex(opened), dataKey.dataKeyHex, `${c.name}/${p.label} unwraps to the epoch data key`);
      // wrapDerivation: eph = SHA-256("avp/vectors/wrap-ephemeral/<epoch>/<label>"), iv = SHA-256("avp/vectors/wrap-iv/<epoch>/<label>")[0..12]
      const ephPriv = createHash("sha256").update(text(`avp/vectors/wrap-ephemeral/${m.keyEpoch}/${p.label}`)).digest();
      assert.equal(xPubFromPriv(ephPriv).toString("base64"), w.ephemeralPublicKey, `${c.name}/${p.label} ephemeral key`);
      const iv = createHash("sha256").update(text(`avp/vectors/wrap-iv/${m.keyEpoch}/${p.label}`)).digest().subarray(0, 12);
      assert.equal(iv.toString("base64"), w.iv, `${c.name}/${p.label} wrap IV`);
      checked++;
    }
  }
  assert.equal(checked, 1 + 4 + 3 + 3, "every member of every state was checked");
});

test("manifest remove-member: two-id frontier, epoch bump, removals cumulative into policy-flip", () => {
  const before = signedManifestFromWire(file.cases[1].signedManifest).state;
  const rm = signedManifestFromWire(file.cases[2].signedManifest).state;
  const flip = signedManifestFromWire(file.cases[3].signedManifest).state;
  assert.equal(rm.removals.length, 1);
  assert.equal(rm.removals[0].removedAtSeq, 3);
  assert.equal(rm.removals[0].frontier.length, 2);
  assert.equal(rm.keyEpoch, before.keyEpoch + 1);
  assert.ok(!rm.members.some((m) => m.ed25519PublicKey.equals(rm.removals[0].memberKey)));
  assert.ok(before.members.some((m) => m.ed25519PublicKey.equals(rm.removals[0].memberKey)));
  for (const m of rm.members) assert.equal(m.keyEpoch, rm.keyEpoch);
  // cumulative: the later state repeats every earlier removal unchanged
  assert.deepEqual(flip.removals, rm.removals);
  assert.equal(rm.shareRefreshTokens, false);
  assert.equal(flip.shareRefreshTokens, true);
});

test("manifest wire lists in the vector file are not already sorted (the encoder must sort)", () => {
  const add = raw.cases[1].signedManifest.state;
  const keys = add.members.map((m: any) => fromB64(m.ed25519PublicKey));
  const sorted = [...keys].sort(byteOrder);
  assert.notDeepEqual(keys.map(hex), sorted.map(hex));
});

test("encodeManifestState rejects duplicate list keys (SPEC 4.2 wire form)", () => {
  const s = signedManifestFromWire(file.cases[2].signedManifest).state;
  assert.throws(() => encodeManifestState({ ...s, hosts: [...s.hosts, s.hosts[0]] }), /duplicate/);
  assert.throws(() => encodeManifestState({ ...s, members: [...s.members, s.members[0]] }), /duplicate/);
  assert.throws(() => encodeManifestState({ ...s, removals: [...s.removals, s.removals[0]] }), /duplicate/);
  const r = s.removals[0];
  assert.throws(
    () => encodeManifestState({ ...s, removals: [{ ...r, frontier: [r.frontier[0], r.frontier[0]] }] }),
    /duplicate/,
  );
});

test("deriveRepoId rejects inputs of the wrong length", () => {
  assert.throws(() => deriveRepoId(Buffer.alloc(31), Buffer.alloc(16)), /32 bytes/);
  assert.throws(() => deriveRepoId(Buffer.alloc(32), Buffer.alloc(15)), /16 bytes/);
});
