/**
 * Negative ("MUST reject") vectors (vectors/negative.json). Each case is a valid construction with one
 * mutation that a conformant implementation MUST reject: key-unwrap and wrap-unwrap MUST fail
 * authentication, ed25519-verify, manifest-verify, commit-verify, acceptance-verify, and leave-verify
 * MUST return false, manifest-link MUST find the previous hash wrong, and payload-decrypt under the
 * stated AAD v2 inputs MUST fail authentication. This guards against an implementation that
 * "succeeds" on tampered, truncated, wrong-key, or wrong-AAD inputs.
 *
 * SPDX-License-Identifier: MIT
 */

import test from "node:test";
import assert from "node:assert/strict";
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
  verifyLeave,
} from "../src/constructions.ts";
import { acceptanceFromWire, commitFromWire, leaveFromWire, signedManifestFromWire } from "../src/vectors.ts";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..", "..");
const negative = JSON.parse(readFileSync(join(root, "vectors", "negative.json"), "utf8"));

const fromB64 = (s: string) => Buffer.from(s, "base64");
const fromHex = (s: string) => Buffer.from(s, "hex");

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
];

test("negative.json carries every 0.5 MUST-reject case", () => {
  const names = (negative.cases as any[]).map((c) => c.name);
  for (const n of REQUIRED) assert.ok(names.includes(n), `missing negative ${n}`);
});

test("each 0.5 negative differs from a valid base by its one mutation (the base is accepted)", () => {
  for (const c of negative.cases as any[]) {
    if (!c.base) continue;
    assert.equal(accepted({ ...c, ...c.base }), true, `${c.name}: the unmutated base must be accepted`);
  }
});
