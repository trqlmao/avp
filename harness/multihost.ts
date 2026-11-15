/**
 * AVP 0.5 black-box multi-host harness: replication between hosts (SPEC 6.5, 7, 8, 9).
 *
 * Point it at two running AVP hosts, A and B, that are peered with each other (SPEC 9.3 `AVP_PEERS`),
 * have distinct host keys, and run with the test control on (`AVP_TEST_CONTROL=1`). Optionally a third
 * host C, peered with A and B but never listed in any repository's `hosts`. Every scenario works on a
 * fresh repository, drives only the client routes and the test control, and asserts what the SPEC
 * says both hosts must converge on:
 *
 *   - write-while-b-paused-converges: a write on A while B is paused reaches B after it heals, and a
 *     write on B reaches A; a leave request on B is offered to A, and a newer one made on A while B
 *     is paused reaches B by catch-up `fetch` (SPEC 8.4, 9.1, 9.2, 9.3);
 *   - concurrent-writes-two-heads-then-merge: concurrent writes on A and B give the same two heads on
 *     both hosts, and a merge on A collapses them on both (SPEC 7.4, 9.2);
 *   - removed-member-rejected-on-both: a commit the removed member wrote on B while B was paused is
 *     dropped by B and never accepted by A, and the removed member is refused on both (SPEC 7.1, 7.3);
 *   - unlisted-host-refused: C never holds or serves the repository, and A and B are unaffected
 *     (SPEC 6.1 rule 6, 9.2, 9.3); skipped with a note when `--c` is absent;
 *   - old-epoch-head: a head written on B under epoch E while A rotates to E + 1 is kept on both, and
 *     the owner, holding E's key, merges it forward (SPEC 7.2, 7.5, 8.3);
 *   - diverged-owner: the owner publishes a seq N + 1 on A and a different seq N + 1 on B while they
 *     are apart; after the heal both tips equal the bytewise-lower manifestHash, and a member commit
 *     citing the losing state is accepted after re-check (SPEC 6.5). It runs twice, once with the
 *     lower hash on A and once on B, so each host both keeps its chain and switches to the other.
 *
 *   bun multihost.ts --a http://127.0.0.1:19201 --b http://127.0.0.1:19202 --c http://127.0.0.1:19203
 *
 * Options: `--converge-ms N` (how long a convergence wait polls, default 15000), `--quiet-ms N` (how
 * long a "nothing arrives" check waits, default 6000: one SPEC 9.3 sweep interval of 5 s plus a
 * margin), `--startup-timeout-ms N` (default 30000), `--request-timeout-ms N` (default 30000).
 *
 * Exit code is 0 only if every check passes. SPDX-License-Identifier: MIT
 */

import { randomBytes } from "node:crypto";

import {
  aesGcmDecrypt,
  buildAadV2,
  commitFromWire,
  leaveFromWire,
  leaveToWire,
  manifestHash,
  signLeave,
  signManifest,
  verifyAcceptance,
  verifyLeave,
  type Commit,
  type HostRef,
  type SignedManifest,
  type WireCommit,
  type WireLeaveRequest,
  type WireSignedManifest,
} from "./crypto.ts";
import {
  b64,
  challengeSignature,
  genesisState,
  hashOfWire,
  idsOf,
  makeCommit,
  memberOf,
  newOwner,
  newParty,
  nextState,
  payloadWith,
  sameSet,
  verifiesAsCommit,
  wireC,
  wireM,
  type Party,
} from "./common.ts";

// ─── Config ───────────────────────────────────────────────────────────────────────────

function flag(name: string): string | undefined {
  const i = process.argv.indexOf(name);
  return i !== -1 ? process.argv[i + 1] : undefined;
}

function numberFlag(name: string, fallback: number): number {
  const raw = flag(name);
  if (raw === undefined) return fallback;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 0) throw new Error(`${name} must be a non-negative integer, got ${raw}`);
  return n;
}

const trim = (u: string | undefined) => (u === undefined ? undefined : u.replace(/\/$/, ""));
const URL_A = trim(flag("--a"));
const URL_B = trim(flag("--b"));
const URL_C = trim(flag("--c"));
/** The brief: convergence waits poll up to 15 s. */
const CONVERGE_MS = numberFlag("--converge-ms", 15_000);
/** One SPEC 9.3 sweep interval (5 s) plus a margin: long enough for a host that would send, to send. */
const QUIET_MS = numberFlag("--quiet-ms", 6_000);
const STARTUP_TIMEOUT_MS = numberFlag("--startup-timeout-ms", 30_000);
const REQUEST_TIMEOUT_MS = numberFlag("--request-timeout-ms", 30_000);
const POLL_MS = 250;

// ─── Check framework ──────────────────────────────────────────────────────────────────

interface Result {
  scenario: string;
  section: string;
  name: string;
  ok: boolean;
  detail: string;
}

const results: Result[] = [];
let current = "setup";

/** Records one check of the current scenario; `detail` is shown when it fails. */
function check(section: string, name: string, ok: boolean, detail = ""): void {
  results.push({ scenario: current, section, name, ok, detail });
  console.log(`  [${ok ? "PASS" : "FAIL"}] ${section.padEnd(6)} ${name}${ok ? "" : `  (${detail})`}`);
}

/** Records a check whose body may throw; a throw is a failure carrying the message. */
function checkDoes(section: string, name: string, fn: () => void): void {
  try {
    fn();
    check(section, name, true);
  } catch (err) {
    check(section, name, false, err instanceof Error ? err.message : String(err));
  }
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

// ─── HTTP ─────────────────────────────────────────────────────────────────────────────

interface Host {
  name: string;
  url: string;
  key: Buffer;
}

interface Resp {
  status: number;
  body: any;
  text: string;
}

/** Every response text a host sent, scanned for the plaintext marker at the end (SPEC 13). */
const seen: string[] = [];

async function req(h: Host | string, method: string, path: string, body?: unknown, token?: string): Promise<Resp> {
  const base = typeof h === "string" ? h : h.url;
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token !== undefined) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(`${base}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  const text = await res.text();
  seen.push(text);
  let parsed: any = undefined;
  try {
    parsed = text ? JSON.parse(text) : undefined;
  } catch {
    parsed = undefined;
  }
  return { status: res.status, body: parsed, text };
}

const repoPath = (repoId: string, op: string) => `/v1/repos/${encodeURIComponent(repoId)}/${op}`;
const show = (r: Resp) => `got ${r.status} ${r.text.slice(0, 200)}`;

/** Asserts a SPEC 10.4 error: the exact status and machine `code`. */
function expectError(section: string, name: string, r: Resp, status: number, code: string): void {
  const ok = r.status === status && typeof r.body?.error === "string" && r.body?.code === code;
  check(section, name, ok, `want ${status} ${code}, ${show(r)}`);
}

async function waitForHost(url: string): Promise<Resp> {
  const deadline = Date.now() + STARTUP_TIMEOUT_MS;
  let last = "";
  while (Date.now() < deadline) {
    try {
      const r = await req(url, "GET", "/.well-known/avp");
      if (r.status === 200) return r;
      last = show(r);
    } catch (err) {
      last = err instanceof Error ? err.message : String(err);
    }
    await sleep(POLL_MS);
  }
  throw new Error(`no host answered GET ${url}/.well-known/avp within ${STARTUP_TIMEOUT_MS} ms (${last})`);
}

async function discover(name: string, url: string): Promise<Host> {
  const d = await waitForHost(url);
  const key = Buffer.from(String(d.body?.hostKey ?? ""), "base64");
  if (d.body?.version !== "0.5" || key.length !== 32) throw new Error(`${name} (${url}) is not an AVP 0.5 host: ${show(d)}`);
  return { name, url, key };
}

/** The test control of SPEC 9.3: pause or resume all host traffic of `h`. */
async function setPaused(h: Host, paused: boolean): Promise<void> {
  const r = await req(h, "POST", "/v1/test/replication", { paused });
  if (r.status !== 200) {
    throw new Error(`host ${h.name}: POST /v1/test/replication { paused: ${paused} } ${show(r)} (start it with AVP_TEST_CONTROL=1)`);
  }
}

// ─── Parties, sessions, and client operations ─────────────────────────────────────────

const tokens = new Map<string, string>();
const tok = (p: Party, h: Host): string => tokens.get(`${p.name}@${h.url}`) ?? "";

async function login(p: Party, h: Host): Promise<void> {
  const c = await req(h, "POST", "/api/auth/keypair/challenge", { ed25519PublicKey: b64(p.pub) });
  if (c.status !== 200 || typeof c.body?.nonce !== "string") throw new Error(`challenge for ${p.name} on ${h.name}: ${show(c)}`);
  const sig = challengeSignature(p, h.key, c.body.nonce);
  const t = await req(h, "POST", "/api/auth/keypair/token", { ed25519PublicKey: b64(p.pub), nonce: c.body.nonce, signature: b64(sig) });
  if (t.status !== 200 || typeof t.body?.token !== "string") throw new Error(`token for ${p.name} on ${h.name}: ${show(t)}`);
  tokens.set(`${p.name}@${h.url}`, t.body.token);
}

const pull = (h: Host, p: Party, repoId: string, since = 0) =>
  req(h, "POST", repoPath(repoId, "pull"), { sinceManifestSeq: since, knownHeads: [] }, tok(p, h));
const push = (h: Host, p: Party, repoId: string, c: Commit) => req(h, "POST", repoPath(repoId, "push"), { commit: wireC(c) }, tok(p, h));
const publish = (h: Host, p: Party, repoId: string, m: SignedManifest, commit?: Commit) =>
  req(h, "POST", repoPath(repoId, "manifest"), commit ? { manifest: wireM(m), commit: wireC(commit) } : { manifest: wireM(m) }, tok(p, h));

/** What one host serves a member for a repository: the chain's hashes in order and the head ids. */
interface View {
  status: number;
  chain: string[];
  seqs: number[];
  heads: string[];
  raw: Resp;
}

async function viewOn(h: Host, p: Party, repoId: string): Promise<View> {
  const r = await pull(h, p, repoId);
  const ms: WireSignedManifest[] = Array.isArray(r.body?.manifests) ? r.body.manifests : [];
  return {
    status: r.status,
    chain: r.status === 200 ? ms.map(hashOfWire) : [],
    seqs: r.status === 200 ? ms.map((m) => m.state.manifestSeq) : [],
    heads: r.status === 200 ? idsOf(r.body?.heads) : [],
    raw: r,
  };
}

const describe = (v: View) => `status ${v.status}, seqs [${v.seqs.join(",")}], tip ${v.chain.at(-1) ?? "-"}, heads [${v.heads.join(", ")}]`;

/** Polls `probe` every 250 ms until `ok` holds or `ms` passes; returns the last value and whether it held. */
async function until<T>(probe: () => Promise<T>, ok: (t: T) => boolean, ms = CONVERGE_MS): Promise<{ ok: boolean; value: T }> {
  const deadline = Date.now() + ms;
  let value = await probe();
  while (!ok(value) && Date.now() < deadline) {
    await sleep(POLL_MS);
    value = await probe();
  }
  return { ok: ok(value), value };
}

/** Waits until `h` serves exactly `heads` (and, if given, the tip `tip`), and records the check. */
async function expectConverged(section: string, name: string, h: Host, p: Party, repoId: string, heads: Buffer[], tip?: SignedManifest) {
  const want = heads.map(b64);
  const r = await until(() => viewOn(h, p, repoId), (v) =>
    v.status === 200 && sameSet(v.heads, want) && (tip === undefined || v.chain.at(-1) === b64(manifestHash(tip))));
  check(section, name, r.ok, `want heads [${want.join(", ")}]${tip ? ` tip ${b64(manifestHash(tip))}` : ""} within ${CONVERGE_MS} ms, ${describe(r.value)}`);
  return r.value;
}

// ─── Repositories ─────────────────────────────────────────────────────────────────────

const MARKER = `avp-multihost-zk-${randomBytes(12).toString("hex")}`;

interface World {
  a: Host;
  b: Host;
  c?: Host;
  alice: Party;
  bob: Party;
  carol: Party;
}

interface Repo {
  repoId: string;
  g1: SignedManifest;
  m2: SignedManifest;
  k0: Buffer;
  c0: Commit;
  hosts: HostRef[];
}

/**
 * A repository created on A, then listed on B the way SPEC 8.1 and 8.2 add a host: bob calls
 * prepareJoin on his home host B, and the owner publishes seq 2 adding B to `hosts` and bob (home B),
 * plus carol (home A) when asked. B gets its first copy by replication only (SPEC 8.1: no import call).
 */
async function newRepo(w: World, withCarol = false): Promise<Repo> {
  const { a, b, alice, bob, carol } = w;
  const k0 = randomBytes(32);
  const g1 = signManifest(genesisState(alice, k0, [{ hostKey: a.key, locator: "a.vault.example" }], a.key), alice.seed);
  const repoId = g1.state.repoId;
  const c0 = makeCommit({ repoId, author: alice, parents: [], manifest: g1, dataKey: k0, plaintext: payloadWith(MARKER, alice) });
  const cr = await req(a, "POST", "/v1/repos", { manifest: wireM(g1), commit: wireC(c0) }, tok(alice, a));
  if (cr.status !== 200) throw new Error(`createRepo on A: ${show(cr)}`);

  const pj = await req(b, "POST", "/v1/prepare-join", { repoId, memberKey: b64(bob.pub) }, tok(bob, b));
  const acc = pj.body;
  const accepted = pj.status === 200 && acc?.repoId === repoId && acc?.hostKey === b64(b.key)
    && verifyAcceptance({ repoId: acc.repoId, memberKey: Buffer.from(acc.memberKey, "base64"), hostKey: Buffer.from(acc.hostKey, "base64"),
      expiresAt: acc.expiresAt, signature: Buffer.from(acc.signature, "base64") }, b.key);
  if (!accepted) throw new Error(`prepareJoin for bob on B: ${show(pj)}`);

  const hosts: HostRef[] = [{ hostKey: a.key, locator: "a.vault.example" }, { hostKey: b.key, locator: "b.vault.example" }];
  const members = [memberOf(alice, k0, 0, a.key), memberOf(bob, k0, 0, b.key)];
  if (withCarol) members.push(memberOf(carol, k0, 0, a.key));
  const m2 = signManifest(nextState(g1, { hosts, members }), alice.seed);
  const p2 = await publish(a, alice, repoId, m2);
  if (p2.status !== 200) throw new Error(`publish seq 2 on A: ${show(p2)}`);

  const r = await until(() => viewOn(b, bob, repoId), (v) =>
    v.status === 200 && v.chain.join() === [g1, m2].map((m) => b64(manifestHash(m))).join() && sameSet(v.heads, [b64(c0.commitId)]));
  check("§9.2", "B, newly listed at seq 2, gets its first copy from A by replication (chain [1,2], head the first commit)",
    r.ok, `within ${CONVERGE_MS} ms, ${describe(r.value)}`);
  if (!r.ok) throw new Error("B never received the repository; the scenario cannot continue");
  return { repoId, g1, m2, k0, c0, hosts };
}

const write = (repo: Repo, author: Party, parents: Buffer[], manifest = repo.m2, dataKey = repo.k0) =>
  makeCommit({ repoId: repo.repoId, author, parents, manifest, dataKey, plaintext: payloadWith(MARKER, author) });

const leaveOf = (repo: Repo, p: Party, at: number): WireLeaveRequest =>
  leaveToWire(signLeave({ repoId: repo.repoId, memberKey: p.pub, at }, p.seed));

/** Waits until `h` serves exactly the one pending leave request `want`, unchanged, and records the check. */
async function expectLeave(section: string, name: string, h: Host, p: Party, repo: Repo, want: WireLeaveRequest): Promise<void> {
  const same = (r: Resp) => {
    const ls: WireLeaveRequest[] = Array.isArray(r.body?.leaves) ? r.body.leaves : [];
    return r.status === 200 && ls.length === 1 && ls[0].repoId === want.repoId && ls[0].memberKey === want.memberKey
      && ls[0].at === want.at && ls[0].signature === want.signature && verifyLeave(leaveFromWire(ls[0]));
  };
  const r = await until(() => pull(h, p, repo.repoId), same);
  check(section, name, r.ok, `want the one leave at ${want.at} by ${want.memberKey} within ${CONVERGE_MS} ms, ${show(r.value)}`);
}

async function expectPushed(name: string, h: Host, p: Party, repo: Repo, c: Commit, heads: Buffer[]): Promise<void> {
  const r = await push(h, p, repo.repoId, c);
  check("§10.1", name, r.status === 200 && r.body?.accepted === true && sameSet(idsOf(r.body?.heads), heads.map(b64)), show(r));
}

// ─── Scenarios ────────────────────────────────────────────────────────────────────────

async function writeWhileBPausedConverges(w: World): Promise<void> {
  const { a, b, alice, bob } = w;
  const repo = await newRepo(w);
  await setPaused(b, true);
  {
    const r = await req(b, "POST", `/v1/host/repos/${encodeURIComponent(repo.repoId)}/heads`, {});
    check("§9.3", "a paused host answers an inbound host route with 503", r.status === 503, show(r));
  }
  const a1 = write(repo, alice, [repo.c0.commitId]);
  await expectPushed("alice's write on A is accepted while B is paused", a, alice, repo, a1, [a1.commitId]);
  await sleep(QUIET_MS);
  {
    const v = await viewOn(b, bob, repo.repoId);
    check("§9.3", `while paused, B receives no host traffic: after ${QUIET_MS} ms its head is still the first commit`,
      v.status === 200 && sameSet(v.heads, [b64(repo.c0.commitId)]), describe(v));
  }
  await setPaused(b, false);
  const v = await expectConverged("§9.2", "after B heals, catch-up brings A's write: B's heads become exactly [a1]", b, bob, repo.repoId, [a1.commitId]);
  checkDoes("§9.1", "the commit B serves is A's commit unchanged: same ciphertext, id and signature verify", () => {
    const served = (v.raw.body?.heads ?? []).find((h: WireCommit) => h.commitId === b64(a1.commitId));
    if (!served) throw new Error("B does not serve a1");
    if (!verifiesAsCommit(served)) throw new Error("served commit id or signature does not verify");
    if (!commitFromWire(served).ciphertext.equals(a1.ciphertext)) throw new Error("ciphertext changed in transit");
  });
  const b2 = write(repo, bob, [a1.commitId]);
  await expectPushed("bob's write on B on top of a1 is accepted", b, bob, repo, b2, [b2.commitId]);
  await expectConverged("§9.2", "a write accepted on B is offered to A: A's heads become exactly [b2]", a, alice, repo.repoId, [b2.commitId]);

  // SPEC 8.4, 9.1, 9.2: leave requests replicate like any accepted write, by offer and by catch-up.
  const l1 = leaveOf(repo, bob, Date.now() - 1000);
  {
    const r = await req(b, "POST", repoPath(repo.repoId, "leave"), l1, tok(bob, b));
    check("§8.4", "bob's leave request on B is 200 {}", r.status === 200 && r.text.trim() === "{}", show(r));
  }
  await expectLeave("§9.2", "the leave accepted on B is offered to A: A's pull serves it unchanged, and it verifies", a, alice, repo, l1);
  await setPaused(b, true);
  const l2 = leaveOf(repo, bob, Date.now());
  {
    const r = await req(a, "POST", repoPath(repo.repoId, "leave"), l2, tok(bob, a));
    check("§8.4", "bob's newer leave request on A, while B is paused, is 200 {}", r.status === 200 && r.text.trim() === "{}", show(r));
  }
  // Wait out A's one offer of l2 (refused with 503) and a sweep, so after the heal l2 can reach B
  // only by B's catch-up fetch.
  await sleep(QUIET_MS);
  {
    const r = await pull(b, alice, repo.repoId);
    const ls: WireLeaveRequest[] = Array.isArray(r.body?.leaves) ? r.body.leaves : [];
    check("§9.3", `while paused, B receives no host traffic: after ${QUIET_MS} ms it still serves exactly the older leave`,
      r.status === 200 && ls.length === 1 && ls[0].at === l1.at && ls[0].signature === l1.signature, show(r));
  }
  await setPaused(b, false);
  await expectLeave("§9.1", "after the heal B's catch-up fetch brings the newer leave: B serves exactly it, unchanged", b, alice, repo, l2);
}

async function concurrentWritesTwoHeadsThenMerge(w: World): Promise<void> {
  const { a, b, alice, bob } = w;
  const repo = await newRepo(w);
  await setPaused(b, true);
  const a1 = write(repo, alice, [repo.c0.commitId]);
  const b1 = write(repo, bob, [repo.c0.commitId]);
  await expectPushed("alice's write on A, on the first commit, is accepted", a, alice, repo, a1, [a1.commitId]);
  await expectPushed("bob's concurrent write on B, on the same parent, is accepted", b, bob, repo, b1, [b1.commitId]);
  await setPaused(b, false);
  const both = [a1.commitId, b1.commitId];
  await expectConverged("§7.4", "A ends with both concurrent writes as two heads (no conflict outcome)", a, alice, repo.repoId, both);
  await expectConverged("§7.4", "B ends with the same two heads", b, bob, repo.repoId, both);
  const merge = write(repo, alice, both);
  await expectPushed("alice's merge on A naming both heads collapses them on A", a, alice, repo, merge, [merge.commitId]);
  await expectConverged("§9.2", "the merge reaches B and collapses its heads to exactly [merge]", b, bob, repo.repoId, [merge.commitId]);
}

async function removedMemberRejectedOnBoth(w: World): Promise<void> {
  const { a, b, alice, bob, carol } = w;
  const repo = await newRepo(w, true);
  const cc1 = write(repo, carol, [repo.c0.commitId]);
  await expectPushed("carol's write on A is accepted while she is a member", a, carol, repo, cc1, [cc1.commitId]);
  await expectConverged("§9.2", "carol's write reaches B", b, bob, repo.repoId, [cc1.commitId]);

  await setPaused(b, true);
  const cx = write(repo, carol, [cc1.commitId]); // never reaches the owner before the removal
  await expectPushed("carol's write on paused B is accepted there (B's tip still lists her)", b, carol, repo, cx, [cx.commitId]);

  const k1 = randomBytes(32);
  const m3 = signManifest(nextState(repo.m2, {
    keyEpoch: 1,
    members: [memberOf(alice, k1, 1, a.key), memberOf(bob, k1, 1, b.key)],
    removals: [{ memberKey: carol.pub, removedAtSeq: 3, frontier: [cc1.commitId] }],
  }), alice.seed);
  const rot = write(repo, alice, [cc1.commitId], m3, k1);
  {
    const r = await publish(a, alice, repo.repoId, m3, rot);
    check("§8.3", "the owner removes carol on A with a rotation commit whose frontier is [cc1]", r.status === 200 && hashOfWire(r.body) === b64(manifestHash(m3)), show(r));
  }
  expectError("§7.1", "the removed member's push on A is 403 forbidden", await push(a, carol, repo.repoId, write(repo, carol, [cc1.commitId])), 403, "forbidden");
  await setPaused(b, false);

  await expectConverged("§7.3", "B adopts the removal and drops carol's commit outside the frontier: tip seq 3, heads exactly [rotation]",
    b, bob, repo.repoId, [rot.commitId], m3);
  await sleep(QUIET_MS);
  {
    const v = await viewOn(a, alice, repo.repoId);
    check("§7.3", `A never accepts the commit B held for the removed member: after ${QUIET_MS} ms A's heads are still exactly [rotation]`,
      v.status === 200 && sameSet(v.heads, [b64(rot.commitId)]), describe(v));
    const vb = await viewOn(b, bob, repo.repoId);
    check("§7.3", "nor does B serve it again: B's heads are still exactly [rotation]",
      vb.status === 200 && sameSet(vb.heads, [b64(rot.commitId)]), describe(vb));
  }
  expectError("§7.1", "the removed member's pull on B is 403 forbidden", await pull(b, carol, repo.repoId), 403, "forbidden");
  expectError("§7.1", "the removed member's push on B is 403 forbidden", await push(b, carol, repo.repoId, write(repo, carol, [rot.commitId])), 403, "forbidden");
  expectError("§7.1", "the removed member's pull on A is 403 forbidden", await pull(a, carol, repo.repoId), 403, "forbidden");
  expectError("§7.4", "on B, a member's child of the dropped commit is 403 forbidden",
    await push(b, bob, repo.repoId, write(repo, bob, [cx.commitId])), 403, "forbidden");
  {
    const r = await push(a, bob, repo.repoId, write(repo, bob, [cx.commitId]));
    const ok = (r.status === 403 && r.body?.code === "forbidden") || (r.status === 422 && r.body?.code === "missing_parents");
    check("§7.4", "on A, a member's child of that commit is refused (403 forbidden, or 422 missing_parents: A never accepted it)", ok, show(r));
  }
}

async function unlistedHostRefused(w: World): Promise<void> {
  const { a, b, alice, bob } = w;
  const c = w.c as Host;
  const repo = await newRepo(w);
  expectError("§9.3", "C, peered with A and B but not listed, holds no copy: pull is 404 not_found",
    await pull(c, alice, repo.repoId), 404, "not_found");
  const a1 = write(repo, alice, [repo.c0.commitId]);
  await expectPushed("alice's write on A is accepted", a, alice, repo, a1, [a1.commitId]);
  await expectConverged("§9.2", "the listed host B receives it", b, bob, repo.repoId, [a1.commitId]);
  await sleep(QUIET_MS);
  expectError("§9.3", `after ${QUIET_MS} ms of offers and sweeps, C still holds no copy: pull is 404 not_found`,
    await pull(c, alice, repo.repoId), 404, "not_found");
  expectError("§6.1", "C takes no client write for it: push is 404 not_found",
    await push(c, alice, repo.repoId, write(repo, alice, [a1.commitId])), 404, "not_found");
  for (const [h, p] of [[a, alice], [b, bob]] as const) {
    const v = await viewOn(h, p, repo.repoId);
    check("§9.2", `${h.name}'s client view is unaffected by C: chain [1,2] and heads exactly [a1]`,
      v.status === 200 && v.chain.join() === [repo.g1, repo.m2].map((m) => b64(manifestHash(m))).join() && sameSet(v.heads, [b64(a1.commitId)]),
      describe(v));
  }
}

async function oldEpochHead(w: World): Promise<void> {
  const { a, b, alice, bob } = w;
  const repo = await newRepo(w);
  await setPaused(b, true);
  const be = write(repo, bob, [repo.c0.commitId]); // epoch 0, citing seq 2
  await expectPushed("bob's write under epoch 0 on paused B is accepted", b, bob, repo, be, [be.commitId]);
  const k1 = randomBytes(32);
  const m3 = signManifest(nextState(repo.m2, { keyEpoch: 1, members: [memberOf(alice, k1, 1, a.key), memberOf(bob, k1, 1, b.key)] }), alice.seed);
  const rot = write(repo, alice, [repo.c0.commitId], m3, k1);
  {
    const r = await publish(a, alice, repo.repoId, m3, rot);
    check("§8.3", "the owner rotates to epoch 1 on A with a rotation commit", r.status === 200 && hashOfWire(r.body) === b64(manifestHash(m3)), show(r));
  }
  await setPaused(b, false);
  const both = [rot.commitId, be.commitId];
  const va = await expectConverged("§7.2", "A keeps the epoch-0 head that arrives after the rotation: heads exactly [rotation, bob's]", a, alice, repo.repoId, both, m3);
  await expectConverged("§7.2", "B adopts the rotation and keeps its epoch-0 head: tip seq 3, heads exactly [rotation, bob's]", b, bob, repo.repoId, both, m3);
  checkDoes("§7.5", "the owner, holding epoch 0's key, reads the old-epoch head under AAD v2 from its own header", () => {
    const served = (va.raw.body?.heads ?? []).find((h: WireCommit) => h.commitId === b64(be.commitId));
    if (!served) throw new Error("A does not serve bob's head");
    const c = commitFromWire(served);
    if (c.keyEpoch !== 0) throw new Error(`keyEpoch ${c.keyEpoch}, want 0`);
    const pt = aesGcmDecrypt(repo.k0, c.iv, buildAadV2(c.repoId, c.keyEpoch, c.author, c.parents), c.ciphertext).toString("utf8");
    if (!pt.includes(MARKER)) throw new Error("decrypted payload is not bob's");
  });
  const merge = write(repo, alice, both, m3, k1);
  await expectPushed("the owner's merge under epoch 1 naming both heads is accepted on A", a, alice, repo, merge, [merge.commitId]);
  await expectConverged("§7.5", "the merge forward reaches B: heads exactly [merge]", b, bob, repo.repoId, [merge.commitId], m3);
}

async function divergedOwner(w: World): Promise<void> {
  // Both orientations, so each host once switches chains and once keeps its own.
  await divergeOnce(w, true);
  await divergeOnce(w, false);
}

async function divergeOnce(w: World, winnerOnA: boolean): Promise<void> {
  const { a, b, alice, bob, carol } = w;
  const repo = await newRepo(w);
  await setPaused(b, true);
  // Two owner devices, apart: seq 3 on A turns the refresh-token policy on; seq 3 on B adds carol.
  // carol's wrapped key is fresh randomness each time, so re-drawing it picks which hash is lower.
  const x = signManifest(nextState(repo.m2, { shareRefreshTokens: true }), alice.seed);
  let y: SignedManifest;
  do {
    y = signManifest(nextState(repo.m2, { members: [...repo.m2.state.members, memberOf(carol, repo.k0, 0, a.key)] }), alice.seed);
  } while ((Buffer.compare(manifestHash(x), manifestHash(y)) < 0) !== winnerOnA);
  const px = await publish(a, alice, repo.repoId, x);
  check("§6.3", "the owner's seq 3 (policy on) is accepted on A", px.status === 200, show(px));
  const py = await publish(b, alice, repo.repoId, y);
  check("§6.3", "a different seq 3 (adds carol) is accepted on paused B", py.status === 200, show(py));
  const xLower = Buffer.compare(manifestHash(x), manifestHash(y)) < 0;
  const [win, lose] = xLower ? [x, y] : [y, x];
  const [winHost, loseHost] = xLower ? [a, b] : [b, a];
  console.log(`  (the lower manifestHash is the seq 3 on ${winHost.name}; ${loseHost.name} holds the losing state)`);
  // Bob is a member at epoch 0 in both states, so his commit citing the losing state stays valid.
  const cl = write(repo, bob, [repo.c0.commitId], lose);
  await expectPushed(`bob's write citing the state ${loseHost.name} holds is accepted there`, loseHost, bob, repo, cl, [cl.commitId]);
  const cw = write(repo, alice, [repo.c0.commitId], win);
  await expectPushed(`alice's write citing the state ${winHost.name} holds is accepted there`, winHost, alice, repo, cw, [cw.commitId]);
  await setPaused(b, false);

  const heads = [cl.commitId, cw.commitId];
  for (const [h, p] of [[a, alice], [b, bob]] as const) {
    const r = await until(() => viewOn(h, p, repo.repoId), (v) =>
      v.status === 200 && v.chain.join() === [repo.g1, repo.m2, win].map((m) => b64(manifestHash(m))).join());
    check("§6.5", `${h.name}'s chain is [1, 2, the lower-hash seq 3]: its tip equals the lower manifestHash`, r.ok,
      `want tip ${b64(manifestHash(win))} within ${CONVERGE_MS} ms, ${describe(r.value)}`);
    await expectConverged("§6.5", `${h.name} accepts bob's commit citing the losing state after re-check: heads exactly [bob's, alice's]`,
      h, p, repo.repoId, heads, win);
  }
  for (const h of [a, b]) {
    expectError("§6.5", `${h.name}, on the winning chain, answers the losing state with 409 manifest_conflict`,
      await publish(h, alice, repo.repoId, lose), 409, "manifest_conflict");
  }
  const next = signManifest(nextState(win, { shareRefreshTokens: !win.state.shareRefreshTokens }), alice.seed);
  const pn = await publish(a, alice, repo.repoId, next);
  check("§6.3", "the owner publishes seq 4 on the winning chain on A", pn.status === 200 && hashOfWire(pn.body) === b64(manifestHash(next)), show(pn));
  await expectConverged("§9.2", "seq 4 reaches B on the same chain", b, bob, repo.repoId, heads, next);
}

// ─── Runner ───────────────────────────────────────────────────────────────────────────

const SCENARIOS: { name: string; needsC?: boolean; run: (w: World) => Promise<void> }[] = [
  { name: "write-while-b-paused-converges", run: writeWhileBPausedConverges },
  { name: "concurrent-writes-two-heads-then-merge", run: concurrentWritesTwoHeadsThenMerge },
  { name: "removed-member-rejected-on-both", run: removedMemberRejectedOnBoth },
  { name: "unlisted-host-refused", needsC: true, run: unlistedHostRefused },
  { name: "old-epoch-head", run: oldEpochHead },
  { name: "diverged-owner", run: divergedOwner },
];

async function main(): Promise<void> {
  if (URL_A === undefined || URL_B === undefined) {
    console.error("usage: bun multihost.ts --a URL --b URL [--c URL]");
    process.exitCode = 2;
    return;
  }
  console.log(`AVP 0.5 multi-host harness → A ${URL_A}, B ${URL_B}${URL_C ? `, C ${URL_C}` : ""}\n`);
  let world: World;
  try {
    const a = await discover("A", URL_A);
    const b = await discover("B", URL_B);
    const c = URL_C === undefined ? undefined : await discover("C", URL_C);
    const keys = [a, b, c].filter((h): h is Host => h !== undefined).map((h) => b64(h.key));
    if (new Set(keys).size !== keys.length) throw new Error("the hosts must have distinct host keys (distinct AVP_HOST_SEED)");
    world = { a, b, c, alice: newOwner("alice"), bob: newParty("bob"), carol: newParty("carol") };
    for (const h of [a, b]) await setPaused(h, false);
    for (const h of [a, b, c]) {
      if (h === undefined) continue;
      for (const p of [world.alice, world.bob, world.carol]) await login(p, h);
    }
  } catch (err) {
    console.error(`Harness aborted during setup: ${err instanceof Error ? err.message : err}`);
    process.exitCode = 1;
    return;
  }

  const skipped: string[] = [];
  for (const s of SCENARIOS) {
    if (s.needsC && world.c === undefined) {
      console.log(`== ${s.name}\n  [SKIP] needs --c URL: a third host peered with A and B but not listed in the repository's hosts\n`);
      skipped.push(s.name);
      continue;
    }
    current = s.name;
    console.log(`== ${s.name}`);
    try {
      await s.run(world);
    } catch (err) {
      check("-", "scenario aborted", false, err instanceof Error ? err.message : String(err));
    } finally {
      for (const h of [world.a, world.b]) {
        try {
          await setPaused(h, false);
        } catch (err) {
          check("-", `could not unpause ${h.name}`, false, err instanceof Error ? err.message : String(err));
        }
      }
    }
    console.log("");
  }

  current = "zero-knowledge";
  console.log(`== ${current}`);
  check("§13", `the plaintext marker appears in none of the ${seen.length} responses`, !seen.some((t) => t.includes(MARKER)));

  const passed = results.filter((r) => r.ok).length;
  const failedScenarios = [...new Set(results.filter((r) => !r.ok).map((r) => r.scenario))];
  console.log(`\n${passed}/${results.length} checks passed${skipped.length ? `, skipped: ${skipped.join(", ")}` : ""}.`);
  if (failedScenarios.length > 0) {
    console.log(`FAILED scenarios: ${failedScenarios.join(", ")}`);
    process.exitCode = 1;
  }
}

void main();
