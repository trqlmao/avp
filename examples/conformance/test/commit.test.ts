/**
 * Commit header, commitId, author signature, AAD v2, and payload AES-256-GCM (SPEC section 4.3) against
 * vectors/commit.json.
 *
 * The header and AAD v2 have no external anchor, so every case is re-derived here by a second,
 * differently written computation: the bytes are hand-assembled from the SPEC 4.3 layout with raw
 * Buffer concatenation, a hand-written unsigned byte comparator, and BigInt shifts for i64, without
 * calling CeWriter or the encoder under test. AES-256-GCM and Ed25519 come from node:crypto directly
 * (already RFC-anchored by the hkdf/x25519/ed25519 vectors). Parent order is shuffled and the id MUST
 * NOT change.
 *
 * SPDX-License-Identifier: MIT
 */

import test from "node:test";
import assert from "node:assert/strict";
import { createCipheriv, createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";

import { aesGcmDecrypt, aesGcmEncrypt, ed25519Sign, importEd25519Private } from "../src/crypto.ts";
import {
  buildAadV2,
  commitId,
  commitSigMessage,
  encodeCommitHeader,
  type CommitHeader,
} from "../src/constructions.ts";
import { commitFromWire, loadCommitVectors, loadManifestVectors } from "../src/vectors.ts";

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
function byteOrder(a: Buffer, b: Buffer): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}
const sortedParents = (w: any) => (w.parents as string[]).map(fromB64).sort(byteOrder);

function handHeader(w: any): Buffer {
  const parents = sortedParents(w);
  return Buffer.concat([
    label("avp/commit/v1"),
    utf8(w.repoId),
    be32(parents.length),
    ...parents.map(lenPrefixed),
    be64(w.manifestSeq),
    lenPrefixed(fromB64(w.manifestHash)),
    be64(w.keyEpoch),
    lenPrefixed(fromB64(w.author)),
    lenPrefixed(fromB64(w.iv)),
    lenPrefixed(fromB64(w.ciphertext)),
  ]);
}

function handAad(w: any): Buffer {
  const parents = sortedParents(w);
  return Buffer.concat([
    label("avp/aad/v2"),
    utf8(w.repoId),
    be64(w.keyEpoch),
    lenPrefixed(fromB64(w.author)),
    be32(parents.length),
    ...parents.map(lenPrefixed),
  ]);
}

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
function verifyEd25519(pub: Buffer, msg: Buffer, sig: Buffer): boolean {
  const key = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, pub]), format: "der", type: "spki" });
  return verify(null, msg, key, sig);
}

function permutations<T>(xs: T[]): T[][] {
  if (xs.length <= 1) return [xs];
  return xs.flatMap((x, i) => permutations([...xs.slice(0, i), ...xs.slice(i + 1)]).map((p) => [x, ...p]));
}

// ---- the vector file ----

const file = loadCommitVectors();
const raw = JSON.parse(readFileSync(join(root, "vectors", "commit.json"), "utf8"));
const manifests = loadManifestVectors();

test("commit.json has the three documented cases and the fixed key and IV", () => {
  assert.deepEqual(
    file.cases.map((c) => [c.name, c.commit.parents.length]),
    [
      ["root", 0],
      ["single-parent", 1],
      ["three-parent-merge", 3],
    ],
  );
  assert.equal(file.seeds.dataKeyHex, "42".repeat(32));
  assert.equal(file.seeds.ivHex, "0c".repeat(12));
  for (const c of file.cases) assert.equal(c.commit.iv, fromHex("0c".repeat(12)).toString("base64"));
});

test("commit.json wire objects validate against schema $defs/Commit", () => {
  const schema = JSON.parse(readFileSync(join(root, "schema", "avp.schema.json"), "utf8"));
  const ajv = new Ajv2020({ strict: false, allErrors: true });
  ajv.addSchema(schema, "avp");
  const validate = ajv.getSchema("avp#/$defs/Commit");
  assert.ok(validate);
  for (const c of raw.cases) assert.ok(validate(c.commit), `${c.name}: ${JSON.stringify(validate.errors)}`);
});

test("commits cite manifest.json states by seq and manifestHash", () => {
  for (const c of file.cases) {
    const m = manifests.cases.find((x) => x.signedManifest.state.manifestSeq === c.commit.manifestSeq);
    assert.ok(m, `${c.name} cites a state in manifest.json`);
    assert.equal(hex(fromB64(c.commit.manifestHash)), m.expected.manifestHashHex);
    assert.equal(c.commit.repoId, m.signedManifest.state.repoId);
  }
});

test("single-parent commit's parent is the root commit", () => {
  assert.deepEqual(file.cases[1].commit.parents, [file.cases[0].commit.commitId]);
});

for (const c of file.cases) {
  const wire = raw.cases.find((x: any) => x.name === c.name).commit;

  test(`commit ${c.name}: header hex and commitId`, () => {
    const commit = commitFromWire(c.commit);
    assert.equal(hex(encodeCommitHeader(commit)), c.expected.headerHex);
    assert.equal(hex(commitId(commit)), c.expected.commitIdHex);
    assert.equal(hex(commit.commitId), c.expected.commitIdHex, "wire commitId equals the recomputed id");
  });

  test(`commit ${c.name}: hand-assembled SPEC 4.3 header, id, and AAD v2 equal the vector`, () => {
    const h = handHeader(wire);
    assert.equal(hex(h), c.expected.headerHex);
    assert.equal(createHash("sha256").update(h).digest("hex"), c.expected.commitIdHex);
    assert.equal(hex(handAad(wire)), c.expected.aadHex);
  });

  test(`commit ${c.name}: AAD v2 hex`, () => {
    const commit = commitFromWire(c.commit);
    assert.equal(hex(buildAadV2(commit.repoId, commit.keyEpoch, commit.author, commit.parents)), c.expected.aadHex);
  });

  test(`commit ${c.name}: AES-256-GCM ciphertext under the fixed key and IV`, () => {
    const key = fromHex(file.seeds.dataKeyHex);
    const iv = fromHex(file.seeds.ivHex);
    const aad = fromHex(c.expected.aadHex);
    const pt = Buffer.from(c.plaintextUtf8, "utf8");
    assert.equal(aesGcmEncrypt(key, iv, aad, pt).toString("base64"), c.commit.ciphertext);
    // independent: node:crypto directly, tag appended
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(aad);
    const direct = Buffer.concat([cipher.update(pt), cipher.final(), cipher.getAuthTag()]);
    assert.equal(direct.toString("base64"), c.commit.ciphertext);
    assert.equal(aesGcmDecrypt(key, iv, aad, fromB64(c.commit.ciphertext)).toString("utf8"), c.plaintextUtf8);
    assert.equal(JSON.parse(c.plaintextUtf8).v, 2, "payload v2");
  });

  test(`commit ${c.name}: author signature reproduces and verifies over CE(avp/commit-sig/v1, id)`, () => {
    const commit = commitFromWire(c.commit);
    const msg = commitSigMessage(commit.commitId);
    // independent: tag || u32BE(32) || id
    assert.equal(hex(msg), hex(Buffer.concat([label("avp/commit-sig/v1"), lenPrefixed(fromHex(c.expected.commitIdHex))])));
    const author = file.seeds.authors.find((a) => a.label === c.authorLabel);
    assert.ok(author);
    assert.equal(c.commit.author, author.ed25519PublicKey);
    const sig = ed25519Sign(importEd25519Private(fromHex(author.ed25519SeedHex)), msg);
    assert.equal(sig.toString("base64"), c.commit.authorSignature);
    assert.ok(verifyEd25519(commit.author, msg, commit.authorSignature));
    // the signature is over the CE message, not the bare id
    assert.ok(!verifyEd25519(commit.author, commit.commitId, commit.authorSignature));
  });

  test(`commit ${c.name}: every parent order gives the same header, id, and AAD`, () => {
    const commit = commitFromWire(c.commit);
    for (const p of permutations(commit.parents)) {
      const shuffled: CommitHeader = { ...commit, parents: p };
      assert.equal(hex(encodeCommitHeader(shuffled)), c.expected.headerHex);
      assert.equal(hex(commitId(shuffled)), c.expected.commitIdHex);
      assert.equal(hex(buildAadV2(commit.repoId, commit.keyEpoch, commit.author, p)), c.expected.aadHex);
    }
  });
}

test("three-parent merge: wire parents are not already sorted", () => {
  const ps = raw.cases[2].commit.parents.map(fromB64);
  assert.notDeepEqual(ps.map(hex), [...ps].sort(byteOrder).map(hex));
});

test("AAD v2 binds the parent set: swapping a parent fails decryption", () => {
  const c = file.cases[2];
  const commit = commitFromWire(c.commit);
  const swapped = [...commit.parents];
  swapped[0] = Buffer.alloc(32, 0x5a);
  const aad = buildAadV2(commit.repoId, commit.keyEpoch, commit.author, swapped);
  assert.throws(() => aesGcmDecrypt(fromHex(file.seeds.dataKeyHex), commit.iv, aad, commit.ciphertext));
});

test("encodeCommitHeader and buildAadV2 reject a duplicate parent (SPEC 4.3)", () => {
  const commit = commitFromWire(file.cases[1].commit);
  const dup = [commit.parents[0], commit.parents[0]];
  assert.throws(() => encodeCommitHeader({ ...commit, parents: dup }), /duplicate/);
  assert.throws(() => buildAadV2(commit.repoId, commit.keyEpoch, commit.author, dup), /duplicate/);
});

test("commitSigMessage rejects an id that is not 32 bytes", () => {
  assert.throws(() => commitSigMessage(Buffer.alloc(31)), /32 bytes/);
});
