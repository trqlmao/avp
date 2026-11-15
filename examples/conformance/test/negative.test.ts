/**
 * Negative ("MUST reject") vectors (vectors/negative.json). Each case is a valid construction with one
 * mutation that a conformant implementation MUST reject: key-unwrap and wrap-unwrap MUST fail
 * authentication, ed25519-verify, manifest-verify, commit-verify, acceptance-verify, leave-verify, and
 * challenge-verify MUST return false, manifest-link MUST find the previous hash wrong, and payload-decrypt under the
 * stated AAD v2 inputs MUST fail authentication. This guards against an implementation that
 * "succeeds" on tampered, truncated, wrong-key, or wrong-AAD inputs.
 *
 * SPDX-License-Identifier: MIT
 */

import test from "node:test";
import assert from "node:assert/strict";
import { createHash, createPublicKey, verify as rawVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  aesGcmDecrypt,
  ed25519Verify,
  importEd25519Public,
  importX25519Private,
  importX25519Public,
  WRAP_INFO,
  wrapKek,
  x25519,
} from "../src/crypto.ts";
import {
  buildAadV2,
  commitId,
  commitSigMessage,
  encodeManifestState,
  manifestHash,
  unwrapSecret,
  verifyAcceptance,
  verifyChallenge,
  verifyLeave,
} from "../src/constructions.ts";
import { acceptanceFromWire, commitFromWire, leaveFromWire, signedManifestFromWire } from "../src/vectors.ts";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..", "..");
const negative = JSON.parse(readFileSync(join(root, "vectors", "negative.json"), "utf8"));

const fromB64 = (s: string) => Buffer.from(s, "base64");
const fromHex = (s: string) => Buffer.from(s, "hex");
/** DER prefix for an Ed25519 SubjectPublicKeyInfo (RFC 8410), for the node:crypto checks below. */
const SPKI = Buffer.from("302a300506032b6570032100", "hex");

function safeVerify(pub: Buffer, msg: Buffer, sig: Buffer): boolean {
  try {
    return ed25519Verify(importEd25519Public(pub), msg, sig);
  } catch {
    return false; // a malformed key or signature that throws is also a rejection
  }
}

/** Returns true when the case's input is accepted; every case MUST return false. */
function accepted(c: any): boolean {
  switch (c.op) {
    case "ed25519-verify":
      return safeVerify(fromHex(c.publicKeyHex), fromHex(c.messageHex), fromHex(c.signatureHex));
    case "key-unwrap": {
      const ephPub = fromB64(c.ephemeralPublicKeyB64);
      const shared = x25519(importX25519Private(fromB64(c.recipientPrivateKeyB64)), importX25519Public(ephPub));
      aesGcmDecrypt(wrapKek(shared, ephPub), fromB64(c.ivB64), WRAP_INFO, fromB64(c.ciphertextB64));
      return true;
    }
    case "wrap-unwrap": {
      const w = c.wrap;
      unwrapSecret(
        fromHex(c.recipientPrivateKeyHex),
        { schemeId: w.schemeId, ephemeralPublicKey: fromB64(w.ephemeralPublicKey), iv: fromB64(w.iv), ciphertext: fromB64(w.ciphertext) },
        Buffer.from(c.info, "utf8"),
      );
      return true;
    }
    case "manifest-verify": {
      const m = signedManifestFromWire(c.signedManifest);
      return safeVerify(m.state.ownerKey, encodeManifestState(m.state), m.ownerSignature);
    }
    case "manifest-link": {
      const prev = signedManifestFromWire(c.prev);
      const next = signedManifestFromWire(c.next);
      // The mutation keeps the owner signature valid, so only the chain link can reject it.
      assert.ok(safeVerify(next.state.ownerKey, encodeManifestState(next.state), next.ownerSignature), "next must be validly signed");
      return next.state.manifestSeq === prev.state.manifestSeq + 1 && next.state.prevManifestHash.equals(manifestHash(prev));
    }
    case "commit-verify": {
      const cm = commitFromWire(c.commit);
      return commitId(cm).equals(cm.commitId) && safeVerify(cm.author, commitSigMessage(cm.commitId), cm.authorSignature);
    }
    case "payload-decrypt": {
      const a = c.aad;
      const aad = buildAadV2(a.repoId, a.keyEpoch, fromB64(a.author), a.parents.map(fromB64));
      aesGcmDecrypt(fromHex(c.dataKeyHex), fromB64(c.ivB64), aad, fromB64(c.ciphertextB64));
      return true;
    }
    case "acceptance-verify":
      return verifyAcceptance(acceptanceFromWire(c.acceptance), fromB64(c.verifyHostKey));
    case "leave-verify":
      return verifyLeave(leaveFromWire(c.leave));
    case "challenge-verify":
      return verifyChallenge(fromB64(c.hostKey), fromB64(c.ed25519PublicKey), fromB64(c.nonce), fromB64(c.signature));
    default:
      throw new Error(`unknown op ${c.op}`);
  }
}

function rejects(c: any): boolean {
  try {
    return !accepted(c);
  } catch (e) {
    if (e instanceof assert.AssertionError) throw e;
    return true; // authentication failure (AEAD throws) is a rejection
  }
}

for (const c of negative.cases as Array<any>) {
  test(`negative ${c.name} (${c.mutation}) is rejected`, () => {
    assert.equal(c.expect, "reject");
    assert.ok(rejects(c), `op ${c.op} must reject this case`);
  });
}

/** The 0.5 MUST-reject cases SPEC 14 names, plus the AAD v2 and header bindings. */
const REQUIRED = [
  "manifest/bad-owner-signature",
  "manifest/wrong-prev-hash",
  "commit/id-mismatch-tampered-ciphertext",
  "commit/id-mismatch-tampered-header",
  "commit/author-signed-other-id",
  "payload/aad-v2-swapped-parent",
  "payload/aad-v2-wrong-epoch",
  "payload/aad-v2-wrong-author",
  "payload/aad-v2-wrong-repo-id",
  "link-grant/unwrapped-with-rdk-wrap-label",
  "acceptance/verified-with-other-host-key",
  "challenge/signature-presented-as-commit-signature",
  "challenge/commit-sig-message-as-nonce",
  "challenge/commit-signature-presented-as-challenge",
  "challenge/made-for-other-host-key",
  "challenge/signature-over-raw-nonce",
];

/**
 * The challenge cases (SPEC 3.3, 4.1) are appended after every earlier case, so the bank's earlier
 * positions stay fixed for runners that index them.
 */
test("the challenge negatives come last, after the strict ed25519 rejects", () => {
  const names = (negative.cases as any[]).map((c) => c.name);
  const firstChallenge = names.findIndex((n) => n.startsWith("challenge/"));
  assert.equal(names.length - firstChallenge, 5);
  assert.ok(names.slice(firstChallenge).every((n) => n.startsWith("challenge/")));
  assert.equal(names[firstChallenge - 1], "ed25519/order-8-sign-bit-key-forgery");
});

/**
 * Each challenge case's valid signature verifies with node:crypto over the SPEC 3.3 transcript
 * assembled here by hand, with the label written out, so a generator that signed under any other
 * label (or without a field) fails this bank even after its output is regenerated.
 */
test("the challenge negatives carry signatures over a hand-built avp/challenge/v1 transcript", () => {
  const u32 = (n: number) => Buffer.from([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
  const lp = (b: Buffer) => Buffer.concat([u32(b.length), b]);
  const transcript = (hostKey: Buffer, key: Buffer, nonce: Buffer) =>
    Buffer.concat([Buffer.from("avp/challenge/v1", "utf8"), Buffer.from([0]), lp(hostKey), lp(key), lp(nonce)]);
  const edVerify = (pub: Buffer, msg: Buffer, sig: Buffer) =>
    rawVerify(null, msg, createPublicKey({ key: Buffer.concat([SPKI, pub]), format: "der", type: "spki" }), sig);
  const byName = new Map((negative.cases as any[]).map((c) => [c.name, c]));
  const challenges = (negative.cases as any[]).filter((c) => c.op === "challenge-verify");
  assert.equal(challenges.length, 3);
  for (const c of challenges) {
    const restored = { ...c, ...c.base };
    assert.ok(
      edVerify(fromB64(restored.ed25519PublicKey), transcript(fromB64(restored.hostKey), fromB64(restored.ed25519PublicKey), fromB64(restored.nonce)), fromB64(restored.signature)),
      `${c.name}: the base is a signature over the hand-built transcript`,
    );
  }
  const other = byName.get("challenge/made-for-other-host-key");
  assert.ok(edVerify(fromB64(other.ed25519PublicKey), transcript(fromB64(other.base.hostKey), fromB64(other.ed25519PublicKey), fromB64(other.nonce)), fromB64(other.signature)));
  // The commit-verify cases carry alice's transcript signature for a.vault.example, whose nonce is the
  // commit id or the whole commit-sig message, as their author signature.
  const hostA = fromB64(other.hostKey);
  for (const [name, nonceOf] of [
    ["challenge/signature-presented-as-commit-signature", (id: Buffer) => id],
    ["challenge/commit-sig-message-as-nonce", (id: Buffer) => commitSigMessage(id)],
  ] as const) {
    const cm = commitFromWire(byName.get(name).commit);
    assert.ok(edVerify(cm.author, transcript(hostA, cm.author, nonceOf(cm.commitId)), cm.authorSignature), `${name}: a transcript signature`);
  }
});

/**
 * Without domain separation each cross case is accepted: the raw-nonce signature verifies over the
 * nonce, and a commit author signature verifies over the commit-sig message a host could pass off as
 * a nonce. This shows the transcript, not some other mutation, is what rejects them.
 */
test("the challenge negatives verify under the old raw-nonce construction", () => {
  const byName = new Map((negative.cases as any[]).map((c) => [c.name, c]));
  const raw = byName.get("challenge/signature-over-raw-nonce");
  assert.equal(safeVerify(fromB64(raw.ed25519PublicKey), fromB64(raw.nonce), fromB64(raw.signature)), true);
  const asChallenge = byName.get("challenge/commit-signature-presented-as-challenge");
  assert.equal(
    safeVerify(fromB64(asChallenge.ed25519PublicKey), commitSigMessage(fromB64(asChallenge.nonce)), fromB64(asChallenge.signature)),
    true,
    "the signature is alice's valid author signature over that commit id",
  );
  const other = byName.get("challenge/made-for-other-host-key");
  assert.equal(verifyChallenge(fromB64(other.base.hostKey), fromB64(other.ed25519PublicKey), fromB64(other.nonce), fromB64(other.signature)), true);
});

test("negative.json carries every 0.5 MUST-reject case", () => {
  const names = (negative.cases as any[]).map((c) => c.name);
  for (const n of REQUIRED) assert.ok(names.includes(n), `missing negative ${n}`);
});

test("each 0.5 negative differs from a valid base by its one mutation (the base is accepted)", () => {
  const legacy = new Set(["key-unwrap", "ed25519-verify"]);
  for (const c of negative.cases as any[]) {
    if (legacy.has(c.op)) continue; // the 0.4-era cases predate `base`
    assert.ok(c.base, `${c.name}: every 0.5 negative carries a base`);
    assert.equal(accepted({ ...c, ...c.base }), true, `${c.name}: the unmutated base must be accepted`);
  }
});

/**
 * A deliberately lenient Ed25519 verifier (RFC 8032 section 5.1.7 without its encoding checks):
 * it decodes a point without requiring y < p or rejecting a set sign bit on x = 0, accepts
 * small-order points, and checks the cofactorless equation [S]B = R + [k]A. It is written out here
 * so the test does not depend on which checks the platform's OpenSSL happens to apply; newer
 * OpenSSL builds reject some of these encodings themselves.
 */
const P = 2n ** 255n - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const md = (a: bigint) => ((a % P) + P) % P;
const pw = (b: bigint, e: bigint) => {
  let r = 1n;
  for (b = md(b); e > 0n; e >>= 1n, b = md(b * b)) if (e & 1n) r = md(r * b);
  return r;
};
const D = md(-121665n * pw(121666n, P - 2n));
const SQRT_M1 = pw(2n, (P - 1n) / 4n);
type Pt = [bigint, bigint, bigint, bigint];
const le = (b: Uint8Array) => {
  let n = 0n;
  for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]);
  return n;
};
const decodeLenient = (b: Uint8Array): Pt | null => {
  const sign = BigInt(b[31] >> 7);
  const y = md(le(b) & ((1n << 255n) - 1n));
  const x2 = md((y * y - 1n) * pw(D * y * y + 1n, P - 2n));
  let x = pw(x2, (P + 3n) / 8n);
  if (md(x * x - x2) !== 0n) x = md(x * SQRT_M1);
  if (md(x * x - x2) !== 0n) return null;
  if ((x & 1n) !== sign) x = md(-x);
  return [x, y, 1n, md(x * y)];
};
const add = ([x1, y1, z1, t1]: Pt, [x2, y2, z2, t2]: Pt): Pt => {
  const a = md((y1 - x1) * (y2 - x2));
  const b = md((y1 + x1) * (y2 + x2));
  const c = md(2n * D * t1 * t2);
  const d = md(2n * z1 * z2);
  const e = b - a, f = d - c, g = d + c, h = b + a;
  return [md(e * f), md(g * h), md(f * g), md(e * h)];
};
const mul = (k: bigint, p: Pt): Pt => {
  let r: Pt = [0n, 1n, 1n, 0n];
  for (; k > 0n; k >>= 1n, p = add(p, p)) if (k & 1n) r = add(r, p);
  return r;
};
const same = ([x1, y1, z1]: Pt, [x2, y2, z2]: Pt) => md(x1 * z2 - x2 * z1) === 0n && md(y1 * z2 - y2 * z1) === 0n;
const BASE = decodeLenient(Buffer.from("5866666666666666666666666666666666666666666666666666666666666666", "hex"))!;
const cofactorlessVerify = (pub: Uint8Array, msg: Uint8Array, sig: Uint8Array) => {
  const a = decodeLenient(pub);
  const r = decodeLenient(sig.subarray(0, 32));
  if (!a || !r) return false;
  const k = le(createHash("sha512").update(sig.subarray(0, 32)).update(pub).update(msg).digest()) % L;
  return same(mul(le(sig.subarray(32, 64)), BASE), add(r, mul(k, a)));
};

test("the lenient verifier accepts a valid RFC 8032 signature and rejects a tampered one", () => {
  const cases = JSON.parse(readFileSync(join(root, "vectors", "ed25519.json"), "utf8")).cases as any[];
  assert.ok(cases.length > 0);
  for (const v of cases) {
    const pub = fromHex(v.publicKeyHex);
    const msg = fromHex(v.messageHex);
    const sig = fromHex(v.signatureHex);
    assert.equal(cofactorlessVerify(pub, msg, sig), true, `${v.name}: valid signature`);
    const bad = Buffer.from(sig);
    bad[40] ^= 1;
    assert.equal(cofactorlessVerify(pub, msg, bad), false, `${v.name}: tampered S`);
    const badMsg = Buffer.concat([msg, Buffer.from([0])]);
    assert.equal(cofactorlessVerify(pub, badMsg, sig), false, `${v.name}: different message`);
  }
});

/**
 * The strict Ed25519 cases (SPEC 2) are only meaningful if a verifier without the strict checks
 * accepts them: the lenient verifier above accepts the small-order forgeries (including the order-8
 * key with its sign bit set, whose R is not the identity) and the non-canonical key, and the S + L
 * signature verifies once S is reduced modulo L.
 */
test("the strict ed25519 negatives are accepted by a cofactorless verifier", () => {
  const lenient = (c: any) => cofactorlessVerify(fromHex(c.publicKeyHex), fromHex(c.messageHex), fromHex(c.signatureHex));
  const byName = new Map((negative.cases as any[]).map((c) => [c.name, c]));
  const forgeries = [
    "ed25519/identity-key-forgery",
    "ed25519/order-8-key-forgery",
    "ed25519/identity-r",
    "ed25519/non-canonical-key",
    "ed25519/order-8-sign-bit-key-forgery",
  ];
  for (const n of forgeries) {
    const c = byName.get(n);
    assert.ok(c, `missing negative ${n}`);
    assert.equal(lenient(c), true, `${n}: a cofactorless verifier accepts it, so the strict check is what rejects it`);
  }
  const c = byName.get("ed25519/s-plus-l");
  assert.ok(c, "missing negative ed25519/s-plus-l");
  const sig = fromHex(c.signatureHex);
  let s = 0n;
  for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(sig[i]);
  assert.ok(s >= L, "S is not reduced");
  const reduced = Buffer.from(sig);
  let r = s - L;
  for (let i = 32; i < 64; i++) {
    reduced[i] = Number(r & 0xffn);
    r >>= 8n;
  }
  assert.equal(lenient({ ...c, signatureHex: reduced.toString("hex") }), true, "the reduced signature is valid");
});
