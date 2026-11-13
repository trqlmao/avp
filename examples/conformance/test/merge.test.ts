/**
 * Payload v2 merge, deletion, refresh-token stripping, and the hybrid logical clock (SPEC section 5
 * and 5.1) against vectors/merge.json.
 *
 * Every `expected` in merge.json is hand-written from the SPEC 5 merge rule, not produced by the
 * merge under test. Each case is checked for every permutation of its inputs (commutativity), for
 * idempotence (merging the result with any input, or with itself, changes nothing), and for
 * associativity over every ordered triple of inputs. `expectedDeleted` pins the SPEC 5 deletion
 * rule per account.
 *
 * SPDX-License-Identifier: MIT
 */

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";

import { Hlc, isDeleted, mergePayloads, stripRefresh, type PayloadV2 } from "../src/merge.ts";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..", "..");
const vectors = JSON.parse(readFileSync(join(root, "vectors", "merge.json"), "utf8"));
const schema = JSON.parse(readFileSync(join(root, "schema", "avp.schema.json"), "utf8"));

const ajv = new Ajv2020({ strict: false, allErrors: true });
ajv.addSchema(schema, "avp");

interface MergeCase {
  name: string;
  note: string;
  stripRefresh?: boolean;
  inputs: PayloadV2[];
  expected: PayloadV2;
  expectedDeleted: Record<string, boolean>;
}

function permutations<T>(xs: T[]): T[][] {
  if (xs.length <= 1) return [xs];
  const out: T[][] = [];
  xs.forEach((x, i) => {
    for (const rest of permutations([...xs.slice(0, i), ...xs.slice(i + 1)])) out.push([x, ...rest]);
  });
  return out;
}

const BRIEF_CASES = [
  "field-conflict-newest-wins",
  "tie-broken-by-member-id",
  "different-fields-both-kept",
  "delete-then-edit-revives",
  "edit-then-delete-removes",
  "three-way",
  "bans-per-server",
  "strip-after-policy-off",
];

test("merge.json has every named case", () => {
  const names = (vectors.cases as MergeCase[]).map((c) => c.name);
  for (const n of BRIEF_CASES) assert.ok(names.includes(n), `missing merge case ${n}`);
});

for (const c of vectors.cases as MergeCase[]) {
  const finish = (p: PayloadV2) => (c.stripRefresh ? stripRefresh(p) : p);

  test(`merge ${c.name}: inputs and expected are valid payloads`, () => {
    const validate = ajv.getSchema("avp#/$defs/VaultPayload");
    assert.ok(validate);
    for (const p of [...c.inputs, c.expected]) assert.ok(validate(p), JSON.stringify(validate.errors));
    assert.ok(c.inputs.length >= 2, "a merge case needs at least two inputs");
  });

  test(`merge ${c.name}: every permutation of the inputs merges to expected`, () => {
    for (const perm of permutations(c.inputs)) {
      assert.deepStrictEqual(finish(mergePayloads(perm)), c.expected);
    }
  });

  test(`merge ${c.name}: merging the result with any input or itself is unchanged (idempotent)`, () => {
    for (const input of [...c.inputs, c.expected]) {
      assert.deepStrictEqual(finish(mergePayloads([c.expected, input])), c.expected);
      assert.deepStrictEqual(finish(mergePayloads([input, c.expected])), c.expected);
    }
    for (const input of c.inputs) assert.deepStrictEqual(mergePayloads([input, input]), mergePayloads([input]));
  });

  test(`merge ${c.name}: merge is associative over every ordered triple of inputs`, () => {
    for (const a of c.inputs) {
      for (const b of c.inputs) {
        for (const d of c.inputs) {
          const left = mergePayloads([mergePayloads([a, b]), d]);
          const right = mergePayloads([a, mergePayloads([b, d])]);
          assert.deepStrictEqual(left, right);
          assert.deepStrictEqual(left, mergePayloads([a, b, d]));
        }
      }
    }
  });

  test(`merge ${c.name}: deletion state of each account follows SPEC 5`, () => {
    const merged = finish(mergePayloads(c.inputs));
    assert.deepEqual(Object.keys(c.expectedDeleted).sort(), Object.keys(c.expected.accounts).sort());
    for (const [uuid, deleted] of Object.entries(c.expectedDeleted)) {
      assert.equal(isDeleted(merged.accounts[uuid]), deleted, `account ${uuid}`);
    }
  });

  test(`merge ${c.name}: merging does not mutate its inputs`, () => {
    const before = JSON.stringify(c.inputs);
    mergePayloads(c.inputs);
    stripRefresh(mergePayloads(c.inputs));
    assert.equal(JSON.stringify(c.inputs), before);
  });
}

test("merge strip-after-policy-off: inputs carry refreshToken and expiresAt, the result carries neither", () => {
  const c = (vectors.cases as MergeCase[]).find((x) => x.name === "strip-after-policy-off");
  assert.ok(c && c.stripRefresh === true);
  const has = (p: PayloadV2, f: string) => Object.values(p.accounts).some((a) => f in a.fields);
  for (const f of ["refreshToken", "expiresAt"]) {
    assert.ok(c.inputs.some((p) => has(p, f)), `an input must carry ${f}`);
    assert.ok(!has(c.expected, f), `expected must not carry ${f}`);
    assert.ok(!has(stripRefresh(mergePayloads(c.inputs)), f));
    assert.ok(has(mergePayloads(c.inputs), f), "the unstripped merge still carries the field");
  }
});

test("isDeleted: a deletion stamp equal to a field stamp does not delete (strictly greater, SPEC 5)", () => {
  const s = { at: 10, n: 0, by: "x" };
  assert.equal(isDeleted({ deleted: s, fields: { username: { value: "u", ...s } }, bans: {} }), false);
  assert.equal(isDeleted({ deleted: { ...s, n: 1 }, fields: { username: { value: "u", ...s } }, bans: {} }), true);
  assert.equal(isDeleted({ deleted: s, fields: {}, bans: { srv: { value: null, ...s, at: 11 } } }), false);
  assert.equal(isDeleted({ fields: {}, bans: {} }), false);
});

test("mergePayloads rejects a payload whose v is not 2 and an empty list (SPEC 5)", () => {
  assert.throws(() => mergePayloads([{ v: 1, accounts: {} } as unknown as PayloadV2]));
  assert.throws(() => mergePayloads([]));
});

test("stamps compare `by` by UTF-8 bytes, not by locale (SPEC 5)", () => {
  // "Z" (0x5a) sorts before "a" (0x61) by bytes; a case-insensitive locale compare would invert it.
  const p = (by: string, value: string): PayloadV2 => ({
    v: 2,
    accounts: { u: { fields: { username: { value, at: 1, n: 0, by } }, bans: {} } },
  });
  const merged = mergePayloads([p("a", "lower"), p("Z", "upper")]);
  assert.equal(merged.accounts.u.fields.username.value, "lower");
});

// ─── HLC (SPEC 5) ──────────────────────────────────────────────────────────────────

interface HlcCase {
  name: string;
  note: string;
  start: { at: number; n: number };
  steps: Array<
    | { op: "tick"; now: number; expect: { at: number; n: number } }
    | { op: "observe"; stamp: { at: number; n: number; by: string }; expect: { at: number; n: number } }
  >;
}

for (const h of vectors.hlc as HlcCase[]) {
  test(`hlc ${h.name}`, () => {
    const clock = new Hlc(h.start.at, h.start.n);
    h.steps.forEach((s, i) => {
      if (s.op === "tick") {
        assert.deepEqual(clock.tick(s.now), s.expect, `step ${i} tick(${s.now})`);
      } else {
        clock.observe(s.stamp);
        assert.deepEqual(clock.state(), s.expect, `step ${i} observe`);
      }
    });
  });
}
