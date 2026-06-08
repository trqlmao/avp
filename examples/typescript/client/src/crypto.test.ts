/**
 * Tests for the high-level AVP crypto functions in `crypto.ts`.
 *
 * Two layers:
 *   1. Round-trip tests: `encryptPayload -> decryptPayload` and
 *      `wrapDataKey -> unwrapDataKey` using freshly generated keys.
 *   2. Vector cross-checks: deterministic reproductions against
 *      `vectors/payload-aead.json`, `vectors/key-wrap.json`, and
 *      `vectors/aad.json` to confirm the compositions are byte-for-byte
 *      correct.
 *
 * SPDX-License-Identifier: MIT
 */

import { test, expect } from "bun:test";
import { createCipheriv, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
  buildAad,
  decryptPayload,
  encryptPayload,
  generateX25519,
  importX25519Private,
  unwrapDataKey,
  wrapDataKey,
} from "./crypto.ts";

// ─── Vector helpers ───────────────────────────────────────────────────────────

const HERE = dirname(fileURLToPath(import.meta.url));

function loadVector(name: string): unknown {
  const p = join(HERE, "../../../../vectors", name);
  return JSON.parse(readFileSync(p, "utf8"));
}

// ─── Round-trip tests ─────────────────────────────────────────────────────────

test("encryptPayload -> decryptPayload round-trip", () => {
  const dataKey = randomBytes(32);
  const repoId = "vault.example/test-repo";
  const version = 3;
  const epoch = 1;
  const plaintext = Buffer.from(JSON.stringify({ alts: [], payloadVersion: version }), "utf8");

  const envelope = encryptPayload(dataKey, repoId, version, epoch, plaintext);

  expect(envelope.repoId).toBe(repoId);
  expect(envelope.payloadVersion).toBe(version);
  expect(envelope.keyEpoch).toBe(epoch);
  // IV is 12 bytes -> 16 base64 chars.
  expect(Buffer.from(envelope.iv, "base64").length).toBe(12);

  const recovered = decryptPayload(dataKey, envelope);
  expect(recovered).toEqual(plaintext);
});

test("decryptPayload fails on tampered epoch", () => {
  const dataKey = randomBytes(32);
  const envelope = encryptPayload(dataKey, "vault.example/repo", 1, 0, Buffer.from("hello"));
  const tampered = { ...envelope, keyEpoch: 99 };
  expect(() => decryptPayload(dataKey, tampered)).toThrow();
});

test("decryptPayload fails on wrong key", () => {
  const dataKey = randomBytes(32);
  const envelope = encryptPayload(dataKey, "vault.example/repo", 1, 0, Buffer.from("hello"));
  const wrongKey = randomBytes(32);
  expect(() => decryptPayload(wrongKey, envelope)).toThrow();
});

test("wrapDataKey -> unwrapDataKey round-trip", () => {
  const dataKey = randomBytes(32);
  const { privateKey, publicKeyRaw } = generateX25519();
  const pubB64 = publicKeyRaw.toString("base64");

  const wrapped = wrapDataKey(pubB64, dataKey);
  expect(wrapped.schemeId).toBe("X25519-HKDF-SHA256-AESGCM-v1");

  const recovered = unwrapDataKey(privateKey, wrapped);
  expect(recovered).toEqual(dataKey);
});

test("unwrapDataKey fails on wrong private key", () => {
  const dataKey = randomBytes(32);
  const { publicKeyRaw } = generateX25519();
  const wrapped = wrapDataKey(publicKeyRaw.toString("base64"), dataKey);

  const { privateKey: wrongPriv } = generateX25519();
  expect(() => unwrapDataKey(wrongPriv, wrapped)).toThrow();
});

// ─── Vector cross-checks ──────────────────────────────────────────────────────

test("buildAad matches vectors/aad.json", () => {
  const { cases } = loadVector("aad.json") as {
    cases: Array<{ repoId: string; payloadVersion: number; keyEpoch: number; expectedAadHex: string }>;
  };
  for (const c of cases) {
    const got = buildAad(c.repoId, c.payloadVersion, c.keyEpoch).toString("hex");
    expect(got).toBe(c.expectedAadHex);
  }
});

test("encryptPayload matches vectors/payload-aead.json", () => {
  const { cases } = loadVector("payload-aead.json") as {
    cases: Array<{
      keyB64: string;
      ivB64: string;
      repoId: string;
      payloadVersion: number;
      keyEpoch: number;
      aadHex: string;
      plaintextUtf8: string;
      ciphertextB64: string;
      tamperEpoch: number;
    }>;
  };

  for (const c of cases) {
    const dataKey = Buffer.from(c.keyB64, "base64");
    const iv = Buffer.from(c.ivB64, "base64");
    const plaintext = Buffer.from(c.plaintextUtf8, "utf8");

    // Confirm AAD is consistent with aad.json.
    const aad = buildAad(c.repoId, c.payloadVersion, c.keyEpoch);
    expect(aad.toString("hex")).toBe(c.aadHex);

    // Re-encrypt with the committed key+iv: must reproduce the same ciphertext.
    const cipher = createCipheriv("aes-256-gcm", dataKey, iv);
    cipher.setAAD(aad);
    const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const ct = Buffer.concat([body, cipher.getAuthTag()]);
    expect(ct.toString("base64")).toBe(c.ciphertextB64);

    // Decrypting the known ciphertext must recover the plaintext.
    const knownEnvelope = {
      repoId: c.repoId,
      payloadVersion: c.payloadVersion,
      keyEpoch: c.keyEpoch,
      iv: c.ivB64,
      ciphertext: c.ciphertextB64,
    };
    const recovered = decryptPayload(dataKey, knownEnvelope);
    expect(recovered.toString("utf8")).toBe(c.plaintextUtf8);

    // Tampered epoch must fail decryption.
    const tampered = { ...knownEnvelope, keyEpoch: c.tamperEpoch };
    expect(() => decryptPayload(dataKey, tampered)).toThrow();
  }
});

test("unwrapDataKey recovers dataKey from vectors/key-wrap.json", () => {
  const { cases } = loadVector("key-wrap.json") as {
    cases: Array<{
      recipientPrivateKeyB64: string;
      dataKeyB64: string;
      wrappedKey: {
        schemeId: string;
        ephemeralPublicKey: string;
        iv: string;
        ciphertext: string;
      };
    }>;
  };

  for (const c of cases) {
    const recipientPriv = importX25519Private(Buffer.from(c.recipientPrivateKeyB64, "base64"));
    const recovered = unwrapDataKey(recipientPriv, c.wrappedKey);
    expect(recovered.toString("base64")).toBe(c.dataKeyB64);
  }
});
