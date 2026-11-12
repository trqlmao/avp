/**
 * BIP39 owner identity (SPEC section 3.1): entropy to mnemonic, mnemonic to entropy (with every reject
 * path), mnemonic to seed, and seed to the owner Ed25519 and X25519 keys.
 *
 * External anchor: three 256-bit-entropy cases of the Trezor reference vectors
 * (https://raw.githubusercontent.com/trezor/python-mnemonic/master/vectors.json, english entries 8, 11
 * and 14, passphrase "TREZOR"), copied below as literal data. The AVP owner cases in
 * vectors/bip39-owner.json (passphrase empty) are then checked against the library functions and,
 * independently, against a direct node:crypto computation of the SPEC formulas.
 *
 * SPDX-License-Identifier: MIT
 */

import test from "node:test";
import assert from "node:assert/strict";
import { createHash, hkdfSync, pbkdf2Sync } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { entropyToMnemonic, mnemonicToEntropy, mnemonicToSeed, ownerKeysFromSeed } from "../src/bip39.ts";
import { loadBip39OwnerVectors } from "../src/vectors.ts";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..", "..");

const hex = (b: Buffer) => b.toString("hex");
const fromHex = (s: string) => Buffer.from(s, "hex");

// Literal copies of trezor/python-mnemonic vectors.json, english[8], english[11], english[14].
const TREZOR = [
  {
    entropyHex: "0000000000000000000000000000000000000000000000000000000000000000",
    mnemonic:
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
    seedHex:
      "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
  },
  {
    entropyHex: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    mnemonic: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
    seedHex:
      "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
  },
  {
    entropyHex: "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
    mnemonic:
      "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
    seedHex:
      "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
  },
];

test("bip39 wordlist is the pinned upstream file", () => {
  const raw = readFileSync(join(root, "vectors", "bip39-english.txt"));
  assert.equal(
    createHash("sha256").update(raw).digest("hex"),
    "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
  );
  const text = raw.toString("utf8");
  assert.ok(!text.includes("\r"), "LF line endings only");
  assert.ok(text.endsWith("\n"), "trailing newline");
  assert.equal(text.split("\n").length - 1, 2048);
});

for (const v of TREZOR) {
  test(`bip39 trezor anchor ${v.entropyHex.slice(0, 8)}: entropy, mnemonic, seed (passphrase TREZOR)`, () => {
    assert.equal(entropyToMnemonic(fromHex(v.entropyHex)), v.mnemonic);
    assert.equal(hex(mnemonicToEntropy(v.mnemonic)), v.entropyHex);
    assert.equal(hex(mnemonicToSeed(v.mnemonic, "TREZOR")), v.seedHex);
  });
}

test("bip39-owner.json carries the same trezor anchors", () => {
  const anchors = loadBip39OwnerVectors().anchors.cases;
  assert.deepEqual(
    anchors.map((a) => [a.entropyHex, a.mnemonic, a.seedHex]),
    TREZOR.map((a) => [a.entropyHex, a.mnemonic, a.seedHex]),
  );
});

// ---- reject paths (SPEC 3.1: not exactly 24 words, unknown word, bad checksum) ----

const VALID = TREZOR[2].mnemonic;

test("mnemonicToEntropy rejects a 23-word phrase", () => {
  const words = VALID.split(" ").slice(0, 23).join(" ");
  assert.throws(() => mnemonicToEntropy(words), /24 words/);
});

test("mnemonicToEntropy rejects a 25-word phrase", () => {
  assert.throws(() => mnemonicToEntropy(VALID + " abandon"), /24 words/);
});

test("mnemonicToEntropy rejects a 12-word phrase (valid BIP39 at 128 bits, not AVP)", () => {
  // trezor english[0]: a valid 12-word BIP39 mnemonic.
  assert.throws(
    () => mnemonicToEntropy("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
    /24 words/,
  );
});

test("mnemonicToEntropy rejects an unknown word", () => {
  const words = VALID.split(" ");
  words[5] = "notaword";
  assert.throws(() => mnemonicToEntropy(words.join(" ")), /unknown word/);
});

test("mnemonicToEntropy rejects a double space as an unknown (empty) word", () => {
  const words = VALID.split(" ");
  assert.throws(() => mnemonicToEntropy(words.slice(0, 23).join(" ") + "  " + words[23]), /24 words|unknown word/);
});

test("mnemonicToEntropy rejects a bad checksum word", () => {
  // "abandon" x24 is all-zero bits, but the checksum of 32 zero bytes is 0x66 ("art"), so this fails.
  const bad = Array(24).fill("abandon").join(" ");
  assert.throws(() => mnemonicToEntropy(bad), /checksum/);
  // Swapping only the last word of a valid phrase (which holds the checksum bits) also fails.
  const words = VALID.split(" ");
  words[23] = words[23] === "zoo" ? "zone" : "zoo";
  assert.throws(() => mnemonicToEntropy(words.join(" ")), /checksum/);
});

test("entropyToMnemonic rejects entropy that is not 32 bytes", () => {
  assert.throws(() => entropyToMnemonic(Buffer.alloc(16)), /32 bytes/);
});

test("ownerKeysFromSeed rejects a seed that is not 64 bytes", () => {
  assert.throws(() => ownerKeysFromSeed(Buffer.alloc(32)), /64 bytes/);
});

// ---- AVP owner cases (passphrase empty) ----

const owner = loadBip39OwnerVectors();

test("bip39-owner.json has the three documented cases", () => {
  assert.equal(owner.cases.length, 3);
  assert.deepEqual(
    owner.cases.map((c) => c.entropyHex),
    [
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
      "0000000000000000000000000000000000000000000000000000000000000000",
    ],
  );
  // The all-zero case reuses the trezor anchor mnemonic, so its words are externally anchored.
  assert.equal(owner.cases[2].mnemonic, TREZOR[0].mnemonic);
  for (const c of owner.cases) assert.equal(c.passphrase, "");
});

for (const c of owner.cases) {
  test(`bip39-owner ${c.name}: mnemonic, seed, and owner keys`, () => {
    assert.equal(entropyToMnemonic(fromHex(c.entropyHex)), c.mnemonic);
    assert.equal(c.mnemonic.split(" ").length, 24);
    assert.equal(hex(mnemonicToEntropy(c.mnemonic)), c.entropyHex);
    const seed = mnemonicToSeed(c.mnemonic);
    assert.equal(hex(seed), c.seedHex);
    const keys = ownerKeysFromSeed(seed);
    assert.equal(hex(keys.ed25519Seed), c.ed25519SeedHex);
    assert.equal(hex(keys.ed25519Public), c.ed25519PublicKeyHex);
    assert.equal(hex(keys.x25519Private), c.x25519PrivateHex);
    assert.equal(hex(keys.x25519Public), c.x25519PublicKeyHex);
  });

  test(`bip39-owner ${c.name}: independent node:crypto derivation of the SPEC 3.1 formulas`, () => {
    // seed = PBKDF2-HMAC-SHA512(NFKD(mnemonic), "mnemonic" || NFKD(""), 2048, 64)
    const seed = pbkdf2Sync(Buffer.from(c.mnemonic.normalize("NFKD"), "utf8"), Buffer.from("mnemonic", "utf8"), 2048, 64, "sha512");
    assert.equal(hex(seed), c.seedHex);
    const ed = Buffer.from(hkdfSync("sha256", seed, Buffer.alloc(0), Buffer.from("avp/owner/ed25519/v1"), 32));
    const xp = Buffer.from(hkdfSync("sha256", seed, Buffer.alloc(0), Buffer.from("avp/owner/x25519/v1"), 32));
    assert.equal(hex(ed), c.ed25519SeedHex);
    assert.equal(hex(xp), c.x25519PrivateHex);
  });
}

test("owner keys differ between the two labels and between owners", () => {
  const a = owner.cases[0];
  const b = owner.cases[1];
  assert.notEqual(a.ed25519SeedHex, a.x25519PrivateHex);
  assert.notEqual(a.ed25519PublicKeyHex, b.ed25519PublicKeyHex);
});
