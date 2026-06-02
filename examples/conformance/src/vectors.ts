/**
 * Loads the AVP deterministic test vectors from the repository's `vectors/`
 * directory. The path is resolved relative to this file so the runner works
 * regardless of the current working directory.
 *
 * Illustrative reference code, not production. SPDX-License-Identifier: MIT
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
// examples/conformance/src -> repo root (three levels up: src -> conformance -> examples -> root).
const vectorsDir = join(here, "..", "..", "..", "vectors");

/**
 * One case from `vectors/aad.json`: the inputs to the AAD construction (SPEC
 * section 4) paired with the expected lowercase-hex output.
 */
export interface AadCase {
  /** Repository id whose UTF-8 bytes form the AAD prefix. */
  repoId: string;
  /** Payload version counter encoded as the first `int64BE` field. */
  payloadVersion: number;
  /** Key-rotation epoch counter encoded as the second `int64BE` field. */
  keyEpoch: number;
  /** Expected AAD bytes, lowercase-hex encoded. */
  expectedAadHex: string;
}

/**
 * One case from `vectors/key-binding-message.json`: the two member public keys
 * paired with the expected canonical binding message (SPEC section 9).
 */
export interface KeyBindingMessageCase {
  /** Member's base64-encoded Ed25519 public key (its member id). */
  ed25519PublicKey: string;
  /** Member's base64-encoded X25519 public key. */
  x25519PublicKey: string;
  /** Expected binding message: `ed25519PublicKey + "|" + x25519PublicKey`. */
  expectedMessageUtf8: string;
}

/**
 * Shape shared by every vector file under `vectors/`: a human-readable
 * `description` plus an array of `cases`.
 *
 * @typeParam C - The per-case type (e.g. {@link AadCase}).
 */
interface VectorFile<C> {
  /** Human-readable description of what the file's cases cover. */
  description: string;
  /** The vector cases to check. */
  cases: C[];
}

/**
 * Reads and parses a vector file from the repository's `vectors/` directory.
 *
 * @typeParam C - The per-case type the file's `cases` array is parsed into.
 * @param name - The vector file name relative to `vectors/` (e.g. `"aad.json"`).
 * @returns The parsed {@link VectorFile}.
 * @throws If the file cannot be read or its contents are not valid JSON.
 */
function loadVector<C>(name: string): VectorFile<C> {
  const raw = readFileSync(join(vectorsDir, name), "utf8");
  return JSON.parse(raw) as VectorFile<C>;
}

/**
 * Loads the AAD-layout vectors (SPEC section 4) from `vectors/aad.json`.
 *
 * @returns The parsed vector file of {@link AadCase} entries.
 * @throws If `vectors/aad.json` is missing or not valid JSON.
 */
export function loadAadVectors(): VectorFile<AadCase> {
  return loadVector<AadCase>("aad.json");
}

/**
 * Loads the key-binding-message vectors (SPEC section 9) from
 * `vectors/key-binding-message.json`.
 *
 * @returns The parsed vector file of {@link KeyBindingMessageCase} entries.
 * @throws If `vectors/key-binding-message.json` is missing or not valid JSON.
 */
export function loadKeyBindingMessageVectors(): VectorFile<KeyBindingMessageCase> {
  return loadVector<KeyBindingMessageCase>("key-binding-message.json");
}
