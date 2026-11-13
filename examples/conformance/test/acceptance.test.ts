/**
 * Host acceptance rules (SPEC sections 6, 7, 8.3, 8.4) against vectors/acceptance.json, run through
 * the RepoView rules engine. The Rust and Java rule engines run the same file unchanged.
 *
 * Every step's `expect`, and every scenario's `finalHeads`, `finalHeld`, and `finalTip`, is literal
 * data written in vectors/generate.ts from the SPEC rule the scenario names in its description; it
 * is not captured from RepoView. This file only replays the steps and compares.
 *
 * SPDX-License-Identifier: MIT
 */

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { manifestHash, type Commit, type LeaveRequest, type SignedManifest } from "../src/constructions.ts";
import { RepoView, type Verdict } from "../src/rules.ts";
import { commitFromWire, leaveFromWire, signedManifestFromWire } from "../src/vectors.ts";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..", "..");
const acceptance = JSON.parse(readFileSync(join(root, "vectors", "acceptance.json"), "utf8"));

const CODES = ["ok", "bad_request", "forbidden", "not_hosted", "too_many_heads", "manifest_conflict", "missing_parents"];

/** The scenarios the plan names (Task 8 brief) and SPEC 14 requires; each MUST be present. */
const BRIEF_SCENARIOS: Record<string, string[]> = {
  "genesis-ok": ["ok"],
  "genesis-wrong-repo-id": ["bad_request"],
  "genesis-host-not-listed": ["not_hosted"],
  "manifest-seq-skip": ["manifest_conflict"],
  "manifest-bad-owner-sig": ["bad_request"],
  "manifest-rollback": ["manifest_conflict"],
  "commit-non-member": ["forbidden"],
  "commit-epoch-mismatch": ["forbidden"],
  "commit-unknown-parent": ["missing_parents"],
  "concurrent-commits-two-heads": [],
  "merge-collapses-heads": [],
  "merge-at-head-bound": [],
  "seventeenth-head-rejected": ["too_many_heads"],
  "removed-member-frontier-ok": [],
  "removed-member-after-cutoff": ["forbidden"],
  "removed-member-backdated-child-of-frontier": ["forbidden"],
  "diverged-owner-lower-hash-wins": [],
  "diverged-owner-commit-rechecked-ok": [],
  "diverged-owner-commit-held": ["forbidden"],
  "leave-bad-signature": ["bad_request"],
};

const verdictCode = (v: Verdict) => (v.ok ? "ok" : v.code);
const b64 = (b: Buffer) => b.toString("base64");

interface Step {
  op: "manifest" | "commit" | "leave";
  via: "push" | "offer";
  label: string;
  item: any;
  expect: string;
}

function apply(view: RepoView, step: Step): Verdict {
  if (step.op === "manifest") {
    const m: SignedManifest = signedManifestFromWire(step.item.manifest);
    const c: Commit | undefined = step.item.commit ? commitFromWire(step.item.commit) : undefined;
    return view.applyManifest(m, c, step.via);
  }
  if (step.op === "commit") return view.applyCommit(commitFromWire(step.item), step.via);
  const l: LeaveRequest = leaveFromWire(step.item);
  return view.applyLeave(l, step.via);
}

test("acceptance.json has every scenario the plan and SPEC 14 name, with the named codes", () => {
  const byName = new Map((acceptance.scenarios as any[]).map((s) => [s.name, s]));
  for (const [name, codes] of Object.entries(BRIEF_SCENARIOS)) {
    const s = byName.get(name);
    assert.ok(s, `missing scenario ${name}`);
    const expects = (s.steps as Step[]).map((x) => x.expect);
    for (const code of codes) assert.ok(expects.includes(code), `${name} must expect ${code}`);
  }
});

test("acceptance.json scenarios are well formed", () => {
  const names = new Set<string>();
  for (const s of acceptance.scenarios as any[]) {
    assert.ok(!names.has(s.name), `duplicate scenario ${s.name}`);
    names.add(s.name);
    assert.match(s.name, /^[a-z0-9]+(-[a-z0-9]+)*$/);
    assert.match(s.description, /SPEC \d/, `${s.name} must cite a SPEC section`);
    assert.equal(Buffer.from(s.hostKey, "base64").length, 32);
    assert.equal(s.headBound, 16);
    for (const st of s.steps as Step[]) {
      assert.ok(["manifest", "commit", "leave"].includes(st.op));
      assert.ok(["push", "offer"].includes(st.via));
      assert.ok(CODES.includes(st.expect), `${s.name}: unknown code ${st.expect}`);
    }
    assert.ok(Array.isArray(s.finalHeads) && Array.isArray(s.finalHeld));
    assert.ok(s.finalTip === null || Buffer.from(s.finalTip, "base64").length === 32);
  }
});

for (const s of acceptance.scenarios as any[]) {
  test(`acceptance ${s.name}`, () => {
    const view = new RepoView(Buffer.from(s.hostKey, "base64"), s.headBound);
    (s.steps as Step[]).forEach((step, i) => {
      assert.equal(verdictCode(apply(view, step)), step.expect, `step ${i} (${step.op} ${step.label} via ${step.via})`);
    });
    assert.deepEqual([...view.heads()].sort(), [...s.finalHeads].sort(), "final heads");
    assert.deepEqual([...view.held()].sort(), [...s.finalHeld].sort(), "final held commits");
    const tip = view.tip();
    assert.equal(tip ? b64(manifestHash(tip)) : null, s.finalTip, "final manifest tip");
  });
}

test("an accepted leave request is pending for its member (SPEC 8.4)", () => {
  const s = (acceptance.scenarios as any[]).find((x) => x.name === "leave-ok");
  const view = new RepoView(Buffer.from(s.hostKey, "base64"), s.headBound);
  for (const step of s.steps as Step[]) apply(view, step);
  const leave = (s.steps as Step[]).find((x) => x.op === "leave");
  assert.deepEqual(view.pendingLeaves(), [leave?.item.memberKey]);
});

// ─── Robustness: attacker-controlled input never throws past the API ──────────────

function genesisOf(name: string): Step {
  const s = (acceptance.scenarios as any[]).find((x) => x.name === name);
  return s.steps[0];
}

test("RepoView maps malformed manifests to bad_request instead of throwing", () => {
  const g = genesisOf("genesis-ok");
  const host = Buffer.from((acceptance.scenarios as any[])[0].hostKey, "base64");
  const base = signedManifestFromWire(g.item.manifest);
  const bad: any[] = [
    { ...base, ownerSignature: Buffer.alloc(3) },
    { ...base, state: { ...base.state, ownerKey: Buffer.alloc(5) } },
    { ...base, state: { ...base.state, manifestSeq: 1.5 } },
    { ...base, state: { ...base.state, manifestSeq: Number.NaN } },
    { ...base, state: { ...base.state, hosts: [base.state.hosts[0], base.state.hosts[0]] } },
    { ...base, state: { ...base.state, members: null } },
    { ...base, state: null },
    null,
    {},
  ];
  for (const m of bad) {
    const view = new RepoView(host);
    let v: Verdict | undefined;
    assert.doesNotThrow(() => {
      v = view.applyManifest(m);
    });
    assert.deepEqual(v, { ok: false, code: "bad_request" });
  }
});

test("RepoView maps malformed commits and leaves to bad_request instead of throwing", () => {
  const g = genesisOf("genesis-ok");
  const host = Buffer.from((acceptance.scenarios as any[])[0].hostKey, "base64");
  const view = new RepoView(host);
  assert.equal(verdictCode(view.applyManifest(signedManifestFromWire(g.item.manifest), commitFromWire(g.item.commit))), "ok");
  const root = commitFromWire(g.item.commit);
  const bad: any[] = [
    { ...root, commitId: Buffer.alloc(31) },
    { ...root, parents: [Buffer.alloc(32, 1), Buffer.alloc(32, 1)] },
    { ...root, parents: "x" },
    { ...root, iv: Buffer.alloc(11) },
    { ...root, ciphertext: Buffer.alloc(4) },
    { ...root, keyEpoch: -1 },
    { ...root, authorSignature: Buffer.alloc(64) },
    null,
  ];
  for (const c of bad) {
    let v: Verdict | undefined;
    assert.doesNotThrow(() => {
      v = view.applyCommit(c);
    });
    assert.deepEqual(v, { ok: false, code: "bad_request" });
  }
  for (const l of [null, { repoId: root.repoId, memberKey: Buffer.alloc(2), at: 0, signature: Buffer.alloc(64) }] as any[]) {
    let v: Verdict | undefined;
    assert.doesNotThrow(() => {
      v = view.applyLeave(l);
    });
    assert.deepEqual(v, { ok: false, code: "bad_request" });
  }
  assert.deepEqual(view.heads(), [b64(root.commitId)], "malformed input changed no state");
});
