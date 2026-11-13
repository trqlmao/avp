/**
 * Conformance test: reproduces the AVP cryptographic vectors with Node's
 * `crypto` and round-trips the AEAD/key-wrap compositions.
 *
 *   - RFC 5869 HKDF-SHA256  -> vectors/hkdf.json
 *   - RFC 7748 X25519       -> vectors/x25519.json
 *   - RFC 8032 Ed25519      -> vectors/ed25519.json
 *   - SPEC section 4.4 wrap -> vectors/key-wrap.json
 *
 * The RFC cases (hkdf/x25519/ed25519) reproduce published outputs byte-for-byte.
 * The key-wrap composition additionally round-trips (unwrap and assert
 * recovery). The payload AEAD under AAD v2 is covered by test/commit.test.ts.
 * The same vectors are independently cross-checked against the Java reference
 * implementation; see vectors/README.md.
 *
 * Run with: node --import tsx --test test/crypto.test.ts
 *
 * Illustrative reference code, not production. SPDX-License-Identifier: MIT
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";

import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  ed25519PublicRaw,
  ed25519Sign,
  ed25519StrictInputsOk,
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

// ---- Strict Ed25519 pre-checks (SPEC section 2) ----

/** The seven small-order encodings SPEC 2 lists (sign bit cleared), little-endian hex. */
const SPEC_SMALL_ORDER = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
];
/** The group order L of SPEC 2. */
const SPEC_L = (1n << 252n) + 27742317777372353535851937790883648493n;
/** Writes x as 32 little-endian bytes. */
const le32 = (x: bigint): Buffer => Buffer.from(Array.from({ length: 32 }, (_, i) => Number((x >> BigInt(8 * i)) & 0xffn)));
/** The encoding with the sign bit (top bit of the last byte) set. */
const withSignBit = (b: Buffer): Buffer => {
  const out = Buffer.from(b);
  out[31] |= 0x80;
  return out;
};

test("ed25519StrictInputsOk applies the SPEC 2 pre-checks", async (t) => {
  const c = loadEd25519Vectors().cases[0];
  const pub = fromHex(c.publicKeyHex);
  const sig = fromHex(c.signatureHex);
  const honestR = sig.subarray(0, 32);
  const honestS = sig.subarray(32, 64);

  await t.test("an RFC 8032 signature passes", () => {
    assert.equal(ed25519StrictInputsOk(pub, sig), true);
  });

  for (const h of SPEC_SMALL_ORDER) {
    for (const [label, enc] of [["sign bit clear", fromHex(h)], ["sign bit set", withSignBit(fromHex(h))]] as const) {
      await t.test(`small-order ${h.slice(0, 8)}..${hex(enc.subarray(31))} (${label}) is rejected as A and as R`, () => {
        assert.equal(ed25519StrictInputsOk(enc, sig), false, "as the public key A");
        assert.equal(ed25519StrictInputsOk(pub, Buffer.concat([enc, honestS])), false, "as R");
      });
    }
  }

  await t.test("y = p + 2 (non-canonical, not on the blocklist) is rejected as A and as R", () => {
    const pPlus2 = fromHex("ef" + "ff".repeat(30) + "7f");
    for (const enc of [pPlus2, withSignBit(pPlus2)]) {
      assert.equal(ed25519StrictInputsOk(enc, sig), false, "as the public key A");
      assert.equal(ed25519StrictInputsOk(pub, Buffer.concat([enc, honestS])), false, "as R");
    }
  });

  await t.test("S = L is rejected and S = L - 1 passes", () => {
    assert.equal(ed25519StrictInputsOk(pub, Buffer.concat([honestR, le32(SPEC_L)])), false, "S = L");
    assert.equal(ed25519StrictInputsOk(pub, Buffer.concat([honestR, le32(SPEC_L - 1n)])), true, "S = L - 1");
  });
});
