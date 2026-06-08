/**
 * Reproducible derivation of the AVP conformance vectors.
 *
 * Two jobs:
 *   --check (default): re-derive every committed vector's value fields from its documented seeds and
 *     assert the committed file matches. This is the provenance and drift gate: the vectors are not
 *     arbitrary bytes, they are exactly what this script computes. Read-only.
 *   --write: (re)generate vectors/negative.json, the MUST-reject bank, which is derived from the same
 *     seeds as the positive composition vectors.
 *
 * The positive vectors (aad, key-binding-message, hkdf, x25519, ed25519, payload-aead, key-wrap,
 * federation) are RFC-anchored and cross-verified; this script re-derives and checks them but does not
 * rewrite them, so their reviewed prose and formatting are preserved. The negative vectors are owned by
 * this script. The crypto is reused from the vector-tested reference at
 * ../examples/conformance/src so the generator cannot drift from the runner.
 *
 *   bun vectors/generate.ts --check
 *   bun vectors/generate.ts --write
 *
 * SPDX-License-Identifier: MIT
 */

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  aesGcmEncrypt,
  ed25519PublicRaw,
  ed25519Sign,
  hkdfSha256,
  importEd25519Private,
  importX25519Private,
  importX25519Public,
  WRAP_INFO,
  wrapKek,
  x25519,
} from "../examples/conformance/src/crypto.ts";
import { buildAad, buildAadHex, buildKeyBindingMessage } from "../examples/conformance/src/constructions.ts";

const dir = dirname(fileURLToPath(import.meta.url));
const read = (f: string) => JSON.parse(readFileSync(join(dir, f), "utf8"));

const hex = (b: Buffer) => b.toString("hex");
const b64 = (b: Buffer) => b.toString("base64");
const fromB64 = (s: string) => Buffer.from(s, "base64");
const fromHex = (s: string) => Buffer.from(s, "hex");

// ─── Provenance checks: re-derive committed positive vectors from their seeds ─────

interface Check {
  name: string;
  ok: boolean;
  detail: string;
}

function eq(name: string, got: string, want: string, results: Check[]): void {
  results.push({ name, ok: got === want, detail: got === want ? "" : `got ${got} want ${want}` });
}

function checkPositives(): Check[] {
  const r: Check[] = [];

  // aad.json: AAD = UTF8(repoId) || 0x1F || int64BE(version) || int64BE(epoch)
  for (const c of read("aad.json").cases) {
    eq(`aad ${c.repoId}/${c.payloadVersion}/${c.keyEpoch}`, buildAadHex(c.repoId, c.payloadVersion, c.keyEpoch), c.expectedAadHex, r);
  }

  // key-binding-message.json: utf8(ed + "|" + x)
  for (const c of read("key-binding-message.json").cases) {
    eq(`key-binding ${c.name ?? c.ed25519PublicKey.slice(0, 8)}`, buildKeyBindingMessage(c.ed25519PublicKey, c.x25519PublicKey), c.expectedMessageUtf8, r);
  }

  // hkdf.json: HKDF-SHA256 expand output
  for (const c of read("hkdf.json").cases) {
    const okm = hkdfSha256(fromHex(c.ikmHex), fromHex(c.saltHex), fromHex(c.infoHex), c.length);
    eq(`hkdf ${c.name}`, hex(okm), c.okmHex, r);
  }

  // x25519.json: raw ECDH output (unhashed)
  for (const c of read("x25519.json").cases) {
    const out = x25519(importX25519Private(fromHex(c.scalarHex)), importX25519Public(fromHex(c.uCoordinateHex)));
    eq(`x25519 ${c.name}`, hex(out), c.outputHex, r);
  }

  // ed25519.json: derive public key from seed and reproduce the signature
  for (const c of read("ed25519.json").cases) {
    const priv = importEd25519Private(fromHex(c.seedHex));
    eq(`ed25519 ${c.name} pubkey`, hex(ed25519PublicRaw(priv)), c.publicKeyHex, r);
    eq(`ed25519 ${c.name} sig`, hex(ed25519Sign(priv, fromHex(c.messageHex))), c.signatureHex, r);
  }

  // payload-aead.json: AES-256-GCM with the AVP AAD
  for (const c of read("payload-aead.json").cases) {
    const aad = buildAad(c.repoId, c.payloadVersion, c.keyEpoch);
    eq(`payload-aead ${c.name} aad`, hex(aad), c.aadHex, r);
    const ct = aesGcmEncrypt(fromB64(c.keyB64), fromB64(c.ivB64), aad, Buffer.from(c.plaintextUtf8, "utf8"));
    eq(`payload-aead ${c.name} ciphertext`, b64(ct), c.ciphertextB64, r);
  }

  // key-wrap.json: shared secret (ECDH symmetry), KEK, and the wrap ciphertext
  for (const c of read("key-wrap.json").cases) {
    const shared = x25519(importX25519Private(fromB64(c.recipientPrivateKeyB64)), importX25519Public(fromB64(c.wrappedKey.ephemeralPublicKey)));
    eq(`key-wrap ${c.name} shared`, hex(shared), c.sharedSecretHex, r);
    const kek = wrapKek(shared, fromB64(c.wrappedKey.ephemeralPublicKey));
    eq(`key-wrap ${c.name} kek`, hex(kek), c.kekHex, r);
    const ct = aesGcmEncrypt(kek, fromB64(c.wrappedKey.iv), WRAP_INFO, fromB64(c.dataKeyB64));
    eq(`key-wrap ${c.name} ciphertext`, b64(ct), c.wrappedKey.ciphertext, r);
  }

  // federation.json: base64url(canonical minified JSON) round-trips
  for (const t of read("federation.json").tokens) {
    eq(`federation ${t.name} encode`, Buffer.from(t.canonicalJson, "utf8").toString("base64url"), t.base64url, r);
    eq(`federation ${t.name} decode`, JSON.stringify(JSON.parse(Buffer.from(t.base64url, "base64url").toString("utf8"))), JSON.stringify(t.decoded), r);
  }

  return r;
}

// ─── Negative ("MUST reject") bank, derived from the positive seeds ──────────────

const flipFirst = (b: Buffer) => Buffer.concat([Buffer.from([b[0] ^ 0x01]), b.subarray(1)]);
const flipLast = (b: Buffer) => Buffer.concat([b.subarray(0, b.length - 1), Buffer.from([b[b.length - 1] ^ 0x01])]);
const dropLast = (b: Buffer) => b.subarray(0, b.length - 1);

function buildNegatives(): any {
  const pa = read("payload-aead.json").cases[0];
  const kw = read("key-wrap.json").cases[0];
  const ed = read("ed25519.json").cases.find((c: any) => c.name === "rfc8032-test2");
  const edOther = read("ed25519.json").cases.find((c: any) => c.name === "rfc8032-test3");

  // Recompute the valid base ciphertexts so the mutations below are self-derived.
  const paKey = fromB64(pa.keyB64);
  const paIv = fromB64(pa.ivB64);
  const paAad = buildAad(pa.repoId, pa.payloadVersion, pa.keyEpoch);
  const paCt = aesGcmEncrypt(paKey, paIv, paAad, Buffer.from(pa.plaintextUtf8, "utf8"));
  const altKeyB64 = b64(Buffer.alloc(32, 0xff)); // a wrong 32-byte data key

  const ephPub = fromB64(kw.wrappedKey.ephemeralPublicKey);
  const recipPriv = fromB64(kw.recipientPrivateKeyB64);
  const kwIv = fromB64(kw.wrappedKey.iv);
  const kek = wrapKek(x25519(importX25519Private(recipPriv), importX25519Public(ephPub)), ephPub);
  const kwCt = aesGcmEncrypt(kek, kwIv, WRAP_INFO, fromB64(kw.dataKeyB64));
  // RFC 7748 §6.1 Bob private scalar, used as a *wrong* recipient key (valid scalar, wrong KEK).
  const wrongRecipientB64 = b64(fromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));

  const sig = fromHex(ed.signatureHex);

  const payload = (name: string, mutation: string, over: Record<string, unknown>) => ({
    name: `payload/${name}`,
    op: "payload-decrypt",
    mutation,
    expect: "reject",
    keyB64: pa.keyB64,
    ivB64: pa.ivB64,
    repoId: pa.repoId,
    payloadVersion: pa.payloadVersion,
    keyEpoch: pa.keyEpoch,
    ciphertextB64: b64(paCt),
    ...over,
  });

  const wrap = (name: string, mutation: string, over: Record<string, unknown>) => ({
    name: `key-wrap/${name}`,
    op: "key-unwrap",
    mutation,
    expect: "reject",
    recipientPrivateKeyB64: kw.recipientPrivateKeyB64,
    ephemeralPublicKeyB64: kw.wrappedKey.ephemeralPublicKey,
    ivB64: kw.wrappedKey.iv,
    ciphertextB64: b64(kwCt),
    ...over,
  });

  const verify = (name: string, mutation: string, over: Record<string, unknown>) => ({
    name: `ed25519/${name}`,
    op: "ed25519-verify",
    mutation,
    expect: "reject",
    publicKeyHex: ed.publicKeyHex,
    messageHex: ed.messageHex,
    signatureHex: ed.signatureHex,
    ...over,
  });

  return {
    description:
      "MUST-reject vectors. Each case starts from a valid construction (the seeds of payload-aead.json, key-wrap.json, and ed25519.json) and applies exactly one mutation; a conformant implementation MUST reject it. 'op' is the operation: 'payload-decrypt' (AES-256-GCM with the AVP AAD) and 'key-unwrap' (X25519-HKDF-SHA256-AESGCM-v1) MUST fail authentication; 'ed25519-verify' MUST return false. Wire base64 strictness is implementation-specific and intentionally not tested here. Generated by vectors/generate.ts from the same seeds as the positive vectors.",
    cases: [
      payload("flipped-tag", "flip the last byte of the ciphertext (inside the GCM tag)", { ciphertextB64: b64(flipLast(paCt)) }),
      payload("bit-flipped-body", "flip a bit in the first ciphertext byte", { ciphertextB64: b64(flipFirst(paCt)) }),
      payload("truncated-1-byte", "drop the last ciphertext byte", { ciphertextB64: b64(dropLast(paCt)) }),
      payload("missing-tag", "drop the whole 16-byte tag, leaving only the ciphertext body", { ciphertextB64: b64(paCt.subarray(0, paCt.length - 16)) }),
      payload("wrong-aad-repoId", "decrypt the valid ciphertext under an AAD with a different repoId", { repoId: "repo-aead-2" }),
      payload("wrong-aad-version", "decrypt the valid ciphertext under an AAD with a different payloadVersion", { payloadVersion: pa.payloadVersion + 1 }),
      payload("wrong-aad-epoch", "decrypt the valid ciphertext under an AAD with a different keyEpoch (rollback)", { keyEpoch: pa.keyEpoch + 1 }),
      payload("wrong-key", "decrypt the valid ciphertext under a different data key", { keyB64: altKeyB64 }),

      wrap("flipped-tag", "flip the last byte of the wrap ciphertext (inside the GCM tag)", { ciphertextB64: b64(flipLast(kwCt)) }),
      wrap("tampered-body", "flip a bit in the first wrap-ciphertext byte", { ciphertextB64: b64(flipFirst(kwCt)) }),
      wrap("truncated-1-byte", "drop the last wrap-ciphertext byte", { ciphertextB64: b64(dropLast(kwCt)) }),
      wrap("wrong-recipient-key", "unwrap with a different recipient private key (wrong KEK)", { recipientPrivateKeyB64: wrongRecipientB64 }),
      wrap("wrong-ephemeral-key", "unwrap against a different ephemeral public key (wrong shared secret)", { ephemeralPublicKeyB64: kw.recipientPublicKeyB64 }),

      verify("flipped-signature", "flip the first signature byte", { signatureHex: hex(flipFirst(sig)) }),
      verify("wrong-message", "verify the valid signature against a different message", { messageHex: "ff" }),
      verify("wrong-public-key", "verify the valid signature under a different public key", { publicKeyHex: edOther.publicKeyHex }),
    ],
  };
}

// ─── Entry point ────────────────────────────────────────────────────────────────

const write = process.argv.includes("--write");

const positives = checkPositives();
const negatives = buildNegatives();

let failed = positives.filter((c) => !c.ok);

if (write) {
  writeFileSync(join(dir, "negative.json"), JSON.stringify(negatives, null, 2) + "\n");
  console.log(`Wrote negative.json (${negatives.cases.length} cases).`);
} else {
  const committed = JSON.stringify(read("negative.json"));
  const regenerated = JSON.stringify(negatives);
  if (committed !== regenerated) {
    failed = failed.concat([{ name: "negative.json matches generator output", ok: false, detail: "run `bun vectors/generate.ts --write`" }]);
  }
}

for (const c of positives) {
  console.log(`  [${c.ok ? "OK" : "DRIFT"}] ${c.name}${c.ok ? "" : `  (${c.detail})`}`);
}
if (!write) {
  const negOk = failed.every((f) => f.name !== "negative.json matches generator output");
  console.log(`  [${negOk ? "OK" : "DRIFT"}] negative.json matches generator output`);
}

if (failed.length > 0) {
  console.error(`\n${failed.length} vector(s) drifted from their derivation. ${write ? "" : "Re-run with --write if the change is intended."}`);
  process.exitCode = 1;
} else {
  console.log(`\nAll ${positives.length} positive vectors reproduce from their seeds; negative bank is ${write ? "written" : "in sync"}.`);
}
