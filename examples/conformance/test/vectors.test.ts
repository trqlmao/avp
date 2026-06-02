/**
 * Conformance test: re-derives the AVP deterministic constructions and asserts
 * they reproduce the repository's vectors exactly.
 *
 *   - SPEC section 4: the AAD layout      -> vectors/aad.json
 *   - SPEC section 9: the binding message -> vectors/key-binding-message.json
 *
 * Run with: node --import tsx --test test/vectors.test.ts
 *
 * Illustrative reference code, not production. SPDX-License-Identifier: MIT
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";

import { buildAadHex, buildKeyBindingMessage } from "../src/constructions.ts";
import { loadAadVectors, loadKeyBindingMessageVectors } from "../src/vectors.ts";

// Each committed case becomes its own named sub-test, so a failure pinpoints
// the exact (repoId, payloadVersion, keyEpoch) input that diverged.
test("AAD construction (SPEC section 4) reproduces vectors/aad.json", async (t) => {
  const vector = loadAadVectors();
  assert.ok(vector.cases.length > 0, "expected at least one AAD case");

  for (const c of vector.cases) {
    await t.test(`repoId=${JSON.stringify(c.repoId)} v=${c.payloadVersion} epoch=${c.keyEpoch}`, () => {
      const actual = buildAadHex(c.repoId, c.payloadVersion, c.keyEpoch);
      assert.equal(actual, c.expectedAadHex);
    });
  }
});

// Same per-case pattern; sub-test names are truncated to the first 8 base64
// characters of each key to stay readable while remaining distinguishable.
test("key-binding message (SPEC section 9) reproduces vectors/key-binding-message.json", async (t) => {
  const vector = loadKeyBindingMessageVectors();
  assert.ok(vector.cases.length > 0, "expected at least one key-binding case");

  for (const c of vector.cases) {
    await t.test(`ed=${c.ed25519PublicKey.slice(0, 8)}… x=${c.x25519PublicKey.slice(0, 8)}…`, () => {
      const actual = buildKeyBindingMessage(c.ed25519PublicKey, c.x25519PublicKey);
      assert.equal(actual, c.expectedMessageUtf8);
    });
  }
});
