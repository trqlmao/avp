/**
 * Conformance test: reproduces the AVP cryptographic vectors with Node's
 * `crypto` and round-trips the AEAD/key-wrap compositions.
 *
 *   - RFC 5869 HKDF-SHA256  -> vectors/hkdf.json
 *   - RFC 7748 X25519       -> vectors/x25519.json
 *   - RFC 8032 Ed25519      -> vectors/ed25519.json
 *   - SPEC section 4 AEAD   -> vectors/payload-aead.json
 *   - SPEC section 4 wrap   -> vectors/key-wrap.json
 *
 * The RFC cases (hkdf/x25519/ed25519) reproduce published outputs byte-for-byte.
 * The composition cases additionally round-trip (decrypt/unwrap and assert
 * recovery) and the AEAD case asserts that a tampered AAD epoch is rejected.
 * The same vectors are independently cross-checked against the Java reference
 * implementation; see vectors/README.md.
 *
 * Run with: node --import tsx --test test/crypto.test.ts
 *
 * Illustrative reference code, not production. SPDX-License-Identifier: MIT
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";

import { buildAad } from "../src/constructions.ts";
import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  ed25519PublicRaw,
  ed25519Sign,
  ed25519Verify,
  hkdfSha256,
  importEd25519Private,
  importEd25519Public,
  importX25519Private,
  importX25519Public,
  wrapKek,
  WRAP_INFO,
  WRAP_SCHEME_ID,
  x25519,
  x25519PublicRaw,
} from "../src/crypto.ts";
import {
  loadEd25519Vectors,
  loadHkdfVectors,
  loadKeyWrapVectors,
  loadPayloadAeadVectors,
  loadX25519Vectors,
} from "../src/vectors.ts";

const hex = (b: Buffer): string => b.toString("hex");
const fromHex = (h: string): Buffer => Buffer.from(h, "hex");
const b64 = (b: Buffer): string => b.toString("base64");
const fromB64 = (s: string): Buffer => Buffer.from(s, "base64");

// ---- HKDF-SHA256 (RFC 5869) ----
test("HKDF-SHA256 (RFC 5869) reproduces vectors/hkdf.json", async (t) => {
  const vector = loadHkdfVectors();
  assert.ok(vector.cases.length > 0, "expected at least one HKDF case");

  for (const c of vector.cases) {
    await t.test(c.name, () => {
      const ikm = fromHex(c.ikmHex);
      const salt = fromHex(c.saltHex);
      const info = fromHex(c.infoHex);
      const okm = hkdfSha256(ikm, salt, info, c.length);
      assert.equal(hex(okm), c.okmHex, "OKM");
    });
  }
});

// ---- X25519 ECDH (RFC 7748) ----
test("X25519 (RFC 7748) reproduces vectors/x25519.json", async (t) => {
  const vector = loadX25519Vectors();
  assert.ok(vector.cases.length > 0, "expected at least one X25519 case");

  for (const c of vector.cases) {
    await t.test(c.name, () => {
      const priv = importX25519Private(fromHex(c.scalarHex));
      const pub = importX25519Public(fromHex(c.uCoordinateHex));
      const out = x25519(priv, pub);
      assert.equal(hex(out), c.outputHex, "shared secret");
    });
  }
});

// ---- Ed25519 (RFC 8032) ----
test("Ed25519 (RFC 8032) reproduces vectors/ed25519.json", async (t) => {
  const vector = loadEd25519Vectors();
  assert.ok(vector.cases.length > 0, "expected at least one Ed25519 case");

  for (const c of vector.cases) {
    await t.test(c.name, () => {
      const priv = importEd25519Private(fromHex(c.seedHex));
      const pub = importEd25519Public(fromHex(c.publicKeyHex));
      const msg = fromHex(c.messageHex);
      // public key derives from the seed
      assert.equal(hex(ed25519PublicRaw(priv)), c.publicKeyHex, "public key derived from seed");
      // signature reproduces byte-for-byte (Ed25519 is deterministic)
      assert.equal(hex(ed25519Sign(priv, msg)), c.signatureHex, "signature");
      // and verifies under the public key
      assert.ok(ed25519Verify(pub, msg, fromHex(c.signatureHex)), "verify");
    });
  }
});

// ---- AES-256-GCM payload AEAD (SPEC section 4) ----
test("payload AEAD (SPEC section 4) reproduces and round-trips vectors/payload-aead.json", async (t) => {
  const vector = loadPayloadAeadVectors();
  assert.ok(vector.cases.length > 0, "expected at least one payload-aead case");

  for (const c of vector.cases) {
    await t.test(c.name, () => {
      const key = fromB64(c.keyB64);
      const iv = fromB64(c.ivB64);
      const aad = buildAad(c.repoId, c.payloadVersion, c.keyEpoch);
      const plaintext = Buffer.from(c.plaintextUtf8, "utf8");

      // AAD matches the committed hex (and the aad.json layout).
      assert.equal(hex(aad), c.aadHex, "AAD layout");

      // re-encrypt is deterministic given key+iv+aad and matches the committed ciphertext.
      const ct = aesGcmEncrypt(key, iv, aad, plaintext);
      assert.equal(b64(ct), c.ciphertextB64, "ciphertext||tag");

      // decrypt recovers the plaintext.
      const recovered = aesGcmDecrypt(key, iv, aad, fromB64(c.ciphertextB64));
      assert.equal(recovered.toString("utf8"), c.plaintextUtf8, "decrypt round-trip");

      // a tampered AAD epoch is rejected (replay/rollback protection).
      const tampered = buildAad(c.repoId, c.payloadVersion, c.tamperEpoch);
      assert.throws(() => aesGcmDecrypt(key, iv, tampered, fromB64(c.ciphertextB64)), "tampered-epoch must fail");
    });
  }
});

// ---- Default wrap scheme X25519-HKDF-SHA256-AESGCM-v1 (SPEC section 4) ----
test("key wrap (SPEC section 4) reproduces and round-trips vectors/key-wrap.json", async (t) => {
  const vector = loadKeyWrapVectors();
  assert.ok(vector.cases.length > 0, "expected at least one key-wrap case");

  for (const c of vector.cases) {
    await t.test(c.name, () => {
      assert.equal(c.wrappedKey.schemeId, WRAP_SCHEME_ID, "schemeId");

      const recipPriv = importX25519Private(fromB64(c.recipientPrivateKeyB64));
      const recipPubRaw = x25519PublicRaw(recipPriv);
      assert.equal(b64(recipPubRaw), c.recipientPublicKeyB64, "recipient public key matches private key");

      const ephPubRaw = fromB64(c.wrappedKey.ephemeralPublicKey);
      const iv = fromB64(c.wrappedKey.iv);
      const wrappedCt = fromB64(c.wrappedKey.ciphertext);
      const dataKey = fromB64(c.dataKeyB64);

      // recompute shared secret = X25519(recipientPriv, ephemeralPub) and the KEK.
      const shared = x25519(recipPriv, importX25519Public(ephPubRaw));
      assert.equal(hex(shared), c.sharedSecretHex, "shared secret");
      const kek = wrapKek(shared, ephPubRaw);
      assert.equal(hex(kek), c.kekHex, "KEK");

      // re-wrap is deterministic given KEK+iv+aad and matches the committed ciphertext.
      const rewrapped = aesGcmEncrypt(kek, iv, WRAP_INFO, dataKey);
      assert.equal(b64(rewrapped), c.wrappedKey.ciphertext, "wrapped ciphertext||tag");

      // unwrap recovers the data key.
      const recovered = aesGcmDecrypt(kek, iv, WRAP_INFO, wrappedCt);
      assert.equal(b64(recovered), c.dataKeyB64, "unwrapped data key");
    });
  }
});
