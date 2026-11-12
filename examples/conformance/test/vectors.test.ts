/**
 * Conformance test: the canonical encoding (CE) writer of SPEC section 4.1, item by item. Every
 * expected value is the literal byte string the SPEC 4.1 table gives for that input, written out by
 * hand; none is computed by the writer under test.
 *
 * The whole constructions built on the writer are pinned by the vector files: manifest.json
 * (test/manifest.test.ts), commit.json (test/commit.test.ts), and bip39-owner.json
 * (test/bip39.test.ts).
 *
 * Run with: node --import tsx --test test/vectors.test.ts
 *
 * Illustrative reference code, not production. SPDX-License-Identifier: MIT
 */

import { strict as assert } from "node:assert";
import { test } from "node:test";

import { CeWriter } from "../src/constructions.ts";

const hexOf = (w: CeWriter) => w.finish().toString("hex");

test("CE tag(label) is the UTF-8 label then 0x00", () => {
  // "avp/x" = 61 76 70 2f 78
  assert.equal(hexOf(new CeWriter().tag("avp/x")), "6176702f7800");
});

test("CE bytes(b) is u32BE(len) || b, including the empty string", () => {
  assert.equal(hexOf(new CeWriter().bytes(Buffer.alloc(0))), "00000000");
  assert.equal(hexOf(new CeWriter().bytes(Buffer.from([0xde, 0xad, 0xbe]))), "00000003deadbe");
  assert.equal(hexOf(new CeWriter().bytes(Buffer.alloc(300, 0x01))), "0000012c" + "01".repeat(300));
});

test("CE str(s) is bytes(UTF-8 s)", () => {
  assert.equal(hexOf(new CeWriter().str("")), "00000000");
  // U+00E9 is c3 a9 in UTF-8: two bytes, so the length is 3 for "aé".
  assert.equal(hexOf(new CeWriter().str("aé")), "0000000361c3a9");
});

test("CE i64(n) is 8-byte big-endian two's complement", () => {
  assert.equal(hexOf(new CeWriter().i64(0)), "0000000000000000");
  assert.equal(hexOf(new CeWriter().i64(1)), "0000000000000001");
  assert.equal(hexOf(new CeWriter().i64(-1)), "ffffffffffffffff");
  // above 2^32: a 32-bit truncation would give 00000000_00000002
  assert.equal(hexOf(new CeWriter().i64(4294967298)), "0000000100000002");
  // epoch milliseconds (2026-01-01T00:00:00Z = 1767225600000 = 0x19b76daa800)
  assert.equal(hexOf(new CeWriter().i64(1767225600000)), "0000019b76daa800");
  assert.equal(hexOf(new CeWriter().i64(9223372036854775807n)), "7fffffffffffffff");
  assert.equal(hexOf(new CeWriter().i64(-9223372036854775808n)), "8000000000000000");
});

test("CE i64 rejects values it cannot encode exactly", () => {
  assert.throws(() => new CeWriter().i64(9223372036854775808n), RangeError);
  assert.throws(() => new CeWriter().i64(1.5), RangeError);
  assert.throws(() => new CeWriter().i64(2 ** 53), RangeError, "a number above 2^53 - 1 is not exact");
});

test("CE bool(b) is one byte 0x00 or 0x01", () => {
  assert.equal(hexOf(new CeWriter().bool(false)), "00");
  assert.equal(hexOf(new CeWriter().bool(true)), "01");
});

test("CE count(n) is u32BE(n)", () => {
  assert.equal(hexOf(new CeWriter().count(0)), "00000000");
  assert.equal(hexOf(new CeWriter().count(16)), "00000010");
  assert.equal(hexOf(new CeWriter().count(0xffffffff)), "ffffffff");
  assert.throws(() => new CeWriter().count(-1), RangeError);
  assert.throws(() => new CeWriter().count(2 ** 32), RangeError);
});

test("CE items concatenate in call order", () => {
  const got = new CeWriter().tag("t").str("ab").i64(2).bool(true).count(1).bytes(Buffer.from([0xff])).finish();
  assert.equal(got.toString("hex"), "7400" + "000000026162" + "0000000000000002" + "01" + "00000001" + "00000001ff");
});

test("CE tag rejects a label containing 0x00", () => {
  assert.throws(() => new CeWriter().tag("a\u0000b"), /0x00/);
});
