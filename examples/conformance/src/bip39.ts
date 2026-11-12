/**
 * BIP39 owner identity (SPEC section 3.1): 256-bit entropy to a 24-word English mnemonic and back, the
 * PBKDF2 seed, and the owner Ed25519 and X25519 keys derived from it with HKDF-SHA256.
 *
 * The wordlist is the pinned upstream file `vectors/bip39-english.txt` (2048 words, LF, SHA-256 checked
 * by `vectors/generate.ts --check` and the tests).
 *
 * Illustrative reference code, not production. SPDX-License-Identifier: MIT
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ed25519PublicRaw,
  hkdfSha256,
  importEd25519Private,
  importX25519Private,
  pbkdf2Sha512,
  sha256,
  x25519PublicRaw,
} from "./crypto.ts";

const here = dirname(fileURLToPath(import.meta.url));
// examples/conformance/src -> repo root -> vectors/bip39-english.txt
const WORDLIST_PATH = join(here, "..", "..", "..", "vectors", "bip39-english.txt");

/** AVP mnemonics are always 24 words over 256 bits of entropy (SPEC 3.1). */
const ENTROPY_BYTES = 32;
const WORD_COUNT = 24;

let wordlist: string[] | undefined;
let wordIndex: Map<string, number> | undefined;

function words(): { list: string[]; index: Map<string, number> } {
  if (!wordlist || !wordIndex) {
    const text = readFileSync(WORDLIST_PATH, "utf8");
    if (!text.endsWith("\n") || text.includes("\r")) {
      throw new Error("bip39 wordlist must use LF line endings with a trailing newline");
    }
    const list = text.slice(0, -1).split("\n");
    if (list.length !== 2048) {
      throw new Error(`bip39 wordlist must have 2048 words, got ${list.length}`);
    }
    const index = new Map<string, number>();
    list.forEach((w, i) => index.set(w, i));
    if (index.size !== 2048) {
      throw new Error("bip39 wordlist has duplicate words");
    }
    wordlist = list;
    wordIndex = index;
  }
  return { list: wordlist, index: wordIndex };
}

/**
 * Encodes 32 bytes of entropy as a 24-word BIP39 mnemonic (SPEC 3.1): the first 8 bits of
 * `SHA-256(entropy)` are appended as a checksum, the 264 bits are split into 24 groups of 11 bits
 * (most significant first), and each group indexes the English wordlist. Words are joined by one space.
 *
 * @param entropy - Exactly 32 bytes of entropy.
 * @returns The 24-word mnemonic.
 * @throws If `entropy` is not 32 bytes.
 */
export function entropyToMnemonic(entropy: Buffer): string {
  if (entropy.length !== ENTROPY_BYTES) {
    throw new Error(`bip39 entropy must be ${ENTROPY_BYTES} bytes, got ${entropy.length}`);
  }
  const { list } = words();
  const bits = Buffer.concat([entropy, sha256(entropy).subarray(0, 1)]); // 33 bytes = 264 bits
  const out: string[] = [];
  for (let w = 0; w < WORD_COUNT; w++) {
    let idx = 0;
    for (let b = 0; b < 11; b++) {
      const bit = w * 11 + b;
      idx = (idx << 1) | ((bits[bit >> 3] >> (7 - (bit & 7))) & 1);
    }
    out.push(list[idx]);
  }
  return out.join(" ");
}

/**
 * Decodes a 24-word BIP39 mnemonic back to its 32 bytes of entropy (SPEC 3.1). The phrase is
 * NFKD-normalized and split on single spaces.
 *
 * @param mnemonic - The mnemonic.
 * @returns The 32-byte entropy.
 * @throws If the phrase is not exactly 24 words, contains a word that is not in the list (an empty
 *   word from a doubled space included), or fails the checksum.
 */
export function mnemonicToEntropy(mnemonic: string): Buffer {
  const { index } = words();
  const parts = mnemonic.normalize("NFKD").split(" ");
  if (parts.length !== WORD_COUNT) {
    throw new Error(`bip39 mnemonic must be exactly ${WORD_COUNT} words, got ${parts.length}`);
  }
  const bits = Buffer.alloc(33);
  parts.forEach((word, w) => {
    const idx = index.get(word);
    if (idx === undefined) {
      throw new Error(`bip39 mnemonic has an unknown word at position ${w + 1}`);
    }
    for (let b = 0; b < 11; b++) {
      if ((idx >> (10 - b)) & 1) {
        const bit = w * 11 + b;
        bits[bit >> 3] |= 0x80 >> (bit & 7);
      }
    }
  });
  const entropy = bits.subarray(0, ENTROPY_BYTES);
  // Compare the checksum byte without an early exit on the value.
  const diff = sha256(entropy)[0] ^ bits[ENTROPY_BYTES];
  if (diff !== 0) {
    throw new Error("bip39 mnemonic checksum does not match");
  }
  return Buffer.from(entropy);
}

/**
 * The BIP39 seed (SPEC 3.1): `PBKDF2-HMAC-SHA512(NFKD(mnemonic), UTF8("mnemonic") || NFKD(passphrase),
 * 2048, 64)`. AVP uses an empty passphrase; the parameter exists for the reference vectors.
 *
 * @param mnemonic - The mnemonic text.
 * @param passphrase - The BIP39 passphrase, empty for AVP.
 * @returns The 64-byte seed.
 */
export function mnemonicToSeed(mnemonic: string, passphrase = ""): Buffer {
  const password = Buffer.from(mnemonic.normalize("NFKD"), "utf8");
  const salt = Buffer.from("mnemonic" + passphrase.normalize("NFKD"), "utf8");
  return pbkdf2Sha512(password, salt, 2048, 64);
}

/** HKDF info label of the owner Ed25519 signing seed (SPEC 3.1). */
export const OWNER_ED25519_INFO = Buffer.from("avp/owner/ed25519/v1", "utf8");
/** HKDF info label of the owner X25519 private key (SPEC 3.1). */
export const OWNER_X25519_INFO = Buffer.from("avp/owner/x25519/v1", "utf8");

/**
 * Derives the owner keys from a BIP39 seed (SPEC 3.1), each as `HKDF-SHA256(ikm = seed, salt = empty,
 * info = label, L = 32)`. The X25519 private key is used as is; the X25519 function clamps it.
 *
 * @param seed - The 64-byte BIP39 seed.
 * @returns The Ed25519 seed and public key (the `ownerKey`) and the X25519 private and public keys.
 * @throws If `seed` is not 64 bytes.
 */
export function ownerKeysFromSeed(seed: Buffer): {
  ed25519Seed: Buffer;
  ed25519Public: Buffer;
  x25519Private: Buffer;
  x25519Public: Buffer;
} {
  if (seed.length !== 64) {
    throw new Error(`bip39 seed must be 64 bytes, got ${seed.length}`);
  }
  const ed25519Seed = hkdfSha256(seed, Buffer.alloc(0), OWNER_ED25519_INFO, 32);
  const x25519Private = hkdfSha256(seed, Buffer.alloc(0), OWNER_X25519_INFO, 32);
  return {
    ed25519Seed,
    ed25519Public: ed25519PublicRaw(importEd25519Private(ed25519Seed)),
    x25519Private,
    x25519Public: x25519PublicRaw(importX25519Private(x25519Private)),
  };
}
