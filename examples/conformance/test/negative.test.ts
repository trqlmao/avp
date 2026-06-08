/**
 * Negative ("MUST reject") vectors (vectors/negative.json). Each case is a valid construction with one
 * mutation that a conformant implementation MUST reject: payload-decrypt and key-unwrap MUST fail
 * authentication (the AEAD throws), and ed25519-verify MUST return false. This guards against an
 * implementation that "succeeds" on tampered, truncated, replayed, or wrong-key inputs.
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
import { buildAad } from "../src/constructions.ts";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..", "..");
const negative = JSON.parse(readFileSync(join(root, "vectors", "negative.json"), "utf8"));

const fromB64 = (s: string) => Buffer.from(s, "base64");
const fromHex = (s: string) => Buffer.from(s, "hex");

for (const c of negative.cases as Array<any>) {
  test(`negative ${c.name} (${c.mutation}) is rejected`, () => {
    if (c.op === "ed25519-verify") {
      let verified = false;
      try {
        verified = ed25519Verify(importEd25519Public(fromHex(c.publicKeyHex)), fromHex(c.messageHex), fromHex(c.signatureHex));
      } catch {
        verified = false; // a malformed key/signature that throws is also a rejection
      }
      assert.equal(verified, false, "tampered signature must not verify");
      return;
    }

    assert.throws(() => {
      if (c.op === "payload-decrypt") {
        const aad = buildAad(c.repoId, c.payloadVersion, c.keyEpoch);
        aesGcmDecrypt(fromB64(c.keyB64), fromB64(c.ivB64), aad, fromB64(c.ciphertextB64));
      } else if (c.op === "key-unwrap") {
        const ephPub = fromB64(c.ephemeralPublicKeyB64);
        const shared = x25519(importX25519Private(fromB64(c.recipientPrivateKeyB64)), importX25519Public(ephPub));
        const kek = wrapKek(shared, ephPub);
        aesGcmDecrypt(kek, fromB64(c.ivB64), WRAP_INFO, fromB64(c.ciphertextB64));
      } else {
        throw new Error(`unknown op ${c.op}`);
      }
    }, `op ${c.op} must reject this case`);
  });
}
