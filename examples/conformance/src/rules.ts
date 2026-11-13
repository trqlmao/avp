/**
 * Host acceptance rules (SPEC sections 6, 7, 8.3, 8.4): one host's view of one repository, applying
 * manifest states, commits, and leave requests and answering each with a verdict.
 *
 * `RepoView` models the decisions, not the transport: it holds the winning manifest chain, every
 * verified losing state (SPEC 6.5), every commit with its status (accepted, held, rejected), every
 * verified commit header (for the removal cutoff ancestry of SPEC 7.3), and the pending leave
 * requests. Each operation names its path: `"push"` is a client write (`push`, `publishManifest`,
 * `createRepo`, `leave`), where the authenticated caller is the author (or the owner for a manifest)
 * and the head bound applies; `"offer"` is a replicated item (SPEC 9.1), with no caller check, no
 * head bound, and no per-state hosted check: rule 6 applies to the tip of the chain being received,
 * which the host checks before it applies the offer (SPEC 6.1, 9.2), and `tipListsHost()` tells the
 * host whether it may serve the repository. It is checked against `vectors/acceptance.json`.
 *
 * Every input is attacker-controlled. No method throws on any input: every failure maps to a
 * `Verdict` code.
 *
 * Illustrative reference code, not production. SPDX-License-Identifier: MIT
 */

import { ed25519Verify, importEd25519Public } from "./crypto.ts";
import {
  commitId,
  commitSigMessage,
  deriveRepoId,
  encodeManifestState,
  leaveSignMessage,
  manifestHash,
  type Commit,
  type LeaveRequest,
  type ManifestState,
  type SignedManifest,
} from "./constructions.ts";

/** The reject codes a host answers with on these paths (SPEC 10.4). */
export type VerdictCode = "bad_request" | "forbidden" | "not_hosted" | "too_many_heads" | "manifest_conflict" | "missing_parents";

/** The outcome of one operation. */
export type Verdict = { ok: true } | { ok: false; code: VerdictCode };

/** The path an item arrived on: a client write, or a replication offer from a peer host. */
export type Via = "push" | "offer";

const OK: Verdict = { ok: true };
const fail = (code: VerdictCode): Verdict => ({ ok: false, code });

const key = (b: Buffer) => b.toString("base64");

/**
 * `pending` is a stored commit whose removal cutoff became undecidable (a frontier commit's header is
 * unknown, SPEC 7.3): it is not accepted (not a head), not held, and not dropped. The cutoff is run
 * again whenever a new verified header arrives.
 */
type Status = "accepted" | "held" | "rejected" | "pending";

interface StateRec {
  m: SignedManifest;
  hash: Buffer;
  key: string;
  seq: number;
}

interface CommitRec {
  c: Commit;
  status: Status;
}

/** Everything a view holds; copied shallowly to make an operation atomic. */
interface Store {
  /** The winning chain; `chain[i]` has `manifestSeq` `i + 1`. */
  chain: StateRec[];
  /** Every verified state, winning or losing, by manifest hash. */
  states: Map<string, StateRec>;
  /** Manifest hash of each epoch-raising state to its rotation commit id. */
  rotation: Map<string, string>;
  /** Every commit with a status, by commit id. Records are replaced, never mutated. */
  commits: Map<string, CommitRec>;
  /** Every commit whose id recomputes and whose signature verifies, accepted or not (SPEC 7.3). */
  headers: Map<string, Commit>;
  /** The latest leave request per member key. */
  leaves: Map<string, LeaveRequest>;
}

/** The classification of one commit by the membership, cutoff, and parent rules. */
type Classification = { kind: "accepted" } | { kind: "held" } | { kind: "rejected" } | { kind: "error"; code: VerdictCode };

const isBuf = (b: unknown, len?: number): b is Buffer => Buffer.isBuffer(b) && (len === undefined || b.length === len);
const isInt = (n: unknown, min: number): n is number => typeof n === "number" && Number.isSafeInteger(n) && n >= min;
const isStr = (s: unknown): s is string => typeof s === "string";

function safeVerify(publicKey: Buffer, message: Buffer, signature: Buffer): boolean {
  try {
    return ed25519Verify(importEd25519Public(publicKey), message, signature);
  } catch {
    return false;
  }
}

/** True when `xs` holds no two equal buffers. */
function distinct(xs: Buffer[]): boolean {
  return new Set(xs.map(key)).size === xs.length;
}

/** SPEC 6.1 rule 1: the state decodes, has no duplicate, and its binary fields have their lengths. */
function manifestShapeOk(m: SignedManifest): boolean {
  if (m === null || typeof m !== "object" || !isBuf(m.ownerSignature, 64)) return false;
  const s = m.state as ManifestState;
  if (s === null || typeof s !== "object") return false;
  if (!isStr(s.repoId) || !isStr(s.schemeId) || typeof s.shareRefreshTokens !== "boolean") return false;
  if (!isInt(s.manifestSeq, 1) || !isInt(s.keyEpoch, 0) || !isBuf(s.ownerKey, 32)) return false;
  const genesis = s.manifestSeq === 1;
  if (!isBuf(s.prevManifestHash, genesis ? 0 : 32) || !isBuf(s.genesisNonce, genesis ? 16 : 0)) return false;
  if (!Array.isArray(s.hosts) || !Array.isArray(s.members) || !Array.isArray(s.removals)) return false;
  for (const h of s.hosts) {
    if (h === null || typeof h !== "object" || !isBuf(h.hostKey, 32) || !isStr(h.locator)) return false;
  }
  for (const x of s.members) {
    if (x === null || typeof x !== "object") return false;
    if (!isBuf(x.ed25519PublicKey, 32) || !isBuf(x.x25519PublicKey, 32) || !isBuf(x.homeHostKey, 32) || !isInt(x.keyEpoch, 0)) return false;
    const w = x.wrappedDataKey;
    if (w === null || typeof w !== "object" || !isStr(w.schemeId)) return false;
    if (!isBuf(w.ephemeralPublicKey, 32) || !isBuf(w.iv, 12) || !isBuf(w.ciphertext, 48)) return false;
  }
  for (const r of s.removals) {
    if (r === null || typeof r !== "object" || !isBuf(r.memberKey, 32) || !isInt(r.removedAtSeq, 0)) return false;
    if (!Array.isArray(r.frontier) || !r.frontier.every((id) => isBuf(id, 32)) || !distinct(r.frontier)) return false;
  }
  return (
    distinct(s.hosts.map((h) => h.hostKey)) &&
    distinct(s.members.map((x) => x.ed25519PublicKey)) &&
    distinct(s.removals.map((r) => r.memberKey))
  );
}

/** SPEC 7.1: the commit decodes and its binary fields have their lengths; no parent appears twice. */
function commitShapeOk(c: Commit): boolean {
  if (c === null || typeof c !== "object" || !isStr(c.repoId)) return false;
  if (!isBuf(c.commitId, 32) || !isBuf(c.manifestHash, 32) || !isBuf(c.author, 32) || !isBuf(c.iv, 12)) return false;
  if (!isBuf(c.ciphertext) || c.ciphertext.length < 16 || !isBuf(c.authorSignature, 64)) return false;
  if (!isInt(c.manifestSeq, 1) || !isInt(c.keyEpoch, 0)) return false;
  return Array.isArray(c.parents) && c.parents.every((p) => isBuf(p, 32)) && distinct(c.parents);
}

const hasMember = (s: ManifestState, k: Buffer) => s.members.some((x) => x.ed25519PublicKey.equals(k));
const hasHost = (s: ManifestState, k: Buffer) => s.hosts.some((h) => h.hostKey.equals(k));

/** SPEC 6.2: the genesis state. */
function genesisOk(s: ManifestState): boolean {
  if (s.prevManifestHash.length !== 0 || s.genesisNonce.length !== 16 || s.keyEpoch !== 0 || s.removals.length !== 0) return false;
  if (s.members.length !== 1 || !s.members[0].ed25519PublicKey.equals(s.ownerKey)) return false;
  return s.repoId === deriveRepoId(s.ownerKey, s.genesisNonce);
}

const sameFrontier = (a: Buffer[], b: Buffer[]) => a.length === b.length && a.map(key).sort().join() === b.map(key).sort().join();

/** SPEC 6.1 rule 5: the content rules, against the previous state when `prev` is given. */
function contentOk(s: ManifestState, prev: ManifestState | undefined): boolean {
  if (s.hosts.length === 0) return false;
  if (s.members.filter((x) => x.ed25519PublicKey.equals(s.ownerKey)).length !== 1) return false;
  if (!s.members.every((x) => x.keyEpoch === s.keyEpoch && hasHost(s, x.homeHostKey))) return false;
  if (s.members.some((x) => s.removals.some((r) => r.memberKey.equals(x.ed25519PublicKey)))) return false;
  if (!s.removals.every((r) => r.removedAtSeq >= 2 && r.removedAtSeq <= s.manifestSeq)) return false;
  if (prev === undefined) return true;

  if (s.repoId !== prev.repoId || !s.ownerKey.equals(prev.ownerKey) || s.schemeId !== prev.schemeId || s.genesisNonce.length !== 0) {
    return false;
  }
  if (s.keyEpoch !== prev.keyEpoch && s.keyEpoch !== prev.keyEpoch + 1) return false;
  for (const r of prev.removals) {
    const same = s.removals.find((x) => x.memberKey.equals(r.memberKey));
    if (!same || same.removedAtSeq !== r.removedAtSeq || !sameFrontier(same.frontier, r.frontier)) return false;
  }
  const added = s.removals.filter((r) => !prev.removals.some((x) => x.memberKey.equals(r.memberKey)));
  for (const r of added) {
    if (r.removedAtSeq !== s.manifestSeq || !hasMember(prev, r.memberKey)) return false;
  }
  for (const x of prev.members) {
    if (hasMember(s, x.ed25519PublicKey)) continue;
    if (x.ed25519PublicKey.equals(s.ownerKey) || !added.some((r) => r.memberKey.equals(x.ed25519PublicKey))) return false;
  }
  if (added.length > 0 && s.keyEpoch !== prev.keyEpoch + 1) return false;
  return true;
}

/**
 * One host's view of one repository.
 *
 * Construct it with the host's own Ed25519 key; apply items in arrival order; read `heads()`,
 * `held()`, and `tip()`.
 *
 * Host implementers: on the `"offer"` path this engine applies no per-state hosted check, so it will
 * adopt a whole repository whose states never list this host. The host MUST therefore apply an offer
 * (with its catch-up) to a trial copy of the view, check the validated resulting tip with
 * `tipListsHost()` (the received tip of SPEC 9.2), and then either commit the trial copy atomically or
 * discard it and answer `403 not_hosted`; a first copy is all or nothing. The not-hosted marker of
 * SPEC 8.6 (set when a validated state that would become the winning tip drops this host, on publish
 * or on offer) is host state; this engine does not keep it.
 */
export class RepoView {
  private readonly hostKey: Buffer;
  private readonly headBound: number;
  private st: Store = {
    chain: [],
    states: new Map(),
    rotation: new Map(),
    commits: new Map(),
    headers: new Map(),
    leaves: new Map(),
  };

  /**
   * @param hostKey - This host's 32-byte Ed25519 host key.
   * @param headBound - The head bound for client writes (SPEC 7.4, RECOMMENDED 16).
   */
  constructor(hostKey: Buffer, headBound = 16) {
    this.hostKey = Buffer.from(hostKey);
    this.headBound = headBound;
  }

  // ─── Public API ─────────────────────────────────────────────────────────────

  /**
   * Applies a signed manifest state (SPEC 6), with the commit published together with it: the first
   * commit at genesis (SPEC 8.2), the rotation commit of an epoch-raising state (SPEC 8.3), or an
   * optional commit with any other state. The state and its commit are applied together or not at all.
   *
   * @param m - The signed manifest.
   * @param commit - The commit carried with it, if any.
   * @param via - `"push"` for `createRepo`/`publishManifest`, `"offer"` for replication.
   */
  applyManifest(m: SignedManifest, commit?: Commit, via: Via = "push"): Verdict {
    const snap = this.snapshot();
    try {
      // A failed adoption restores itself; a conflict that retains a losing state keeps it (SPEC 6.5).
      return this.manifest(m, commit, via);
    } catch {
      this.restore(snap);
      return fail("bad_request");
    }
  }

  /**
   * Applies one commit (SPEC 7): a client `push`, or a commit from a peer's `offer`.
   *
   * @param c - The commit.
   * @param via - The path it arrived on.
   */
  applyCommit(c: Commit, via: Via = "push"): Verdict {
    const snap = this.snapshot();
    try {
      return this.commit(c, via, false);
    } catch {
      this.restore(snap);
      return fail("bad_request");
    }
  }

  /**
   * Applies a signed leave request (SPEC 8.4). On `"push"` the authenticated caller is `memberKey`.
   *
   * @param l - The leave request.
   * @param via - The path it arrived on; replication skips only the caller check, which a push meets.
   */
  applyLeave(l: LeaveRequest, via: Via = "push"): Verdict {
    void via;
    try {
      if (l === null || typeof l !== "object" || !isStr(l.repoId) || !isBuf(l.memberKey, 32) || !isBuf(l.signature, 64)) {
        return fail("bad_request");
      }
      if (!isInt(l.at, Number.MIN_SAFE_INTEGER)) return fail("bad_request");
      if (!safeVerify(l.memberKey, leaveSignMessage(l), l.signature)) return fail("bad_request");
      const tip = this.tipRec();
      if (tip === undefined || l.repoId !== tip.m.state.repoId) return fail("bad_request");
      const s = tip.m.state;
      if (!hasMember(s, l.memberKey) || l.memberKey.equals(s.ownerKey)) return fail("forbidden");
      const cur = this.st.leaves.get(key(l.memberKey));
      if (cur === undefined || l.at > cur.at) this.st.leaves.set(key(l.memberKey), l);
      return OK;
    } catch {
      return fail("bad_request");
    }
  }

  /** @returns The ids (base64) of the accepted commits with no accepted child. */
  heads(): string[] {
    return this.headKeys().sort();
  }

  /** @returns The ids (base64) of the held commits (SPEC 6.5). */
  held(): string[] {
    return [...this.st.commits].filter(([, r]) => r.status === "held").map(([k]) => k).sort();
  }

  /** @returns The tip of the winning chain, or `undefined` before genesis. */
  tip(): SignedManifest | undefined {
    return this.tipRec()?.m;
  }

  /**
   * Whether the tip of the winning chain lists this host. A host does not serve a repository whose tip
   * does not list it (SPEC 8.6, 10.1); states before the tip may not list it when the host got its
   * first copy by replication (SPEC 6.1 rule 6, 9.2).
   *
   * @returns `true` if the tip's `hosts` contains this host's key, `false` otherwise or before genesis.
   */
  tipListsHost(): boolean {
    const tip = this.tipRec();
    return tip !== undefined && hasHost(tip.m.state, this.hostKey);
  }

  /** @returns The pending leave requests (SPEC 8.4), one per member: its key (base64) and `at`, sorted by key. */
  pendingLeaves(): Array<{ memberKey: string; at: number }> {
    return [...this.st.leaves]
      .map(([k, l]) => ({ memberKey: k, at: l.at }))
      .sort((x, y) => (x.memberKey < y.memberKey ? -1 : 1));
  }

  // ─── Store ──────────────────────────────────────────────────────────────────

  private snapshot(): Store {
    const s = this.st;
    return {
      chain: [...s.chain],
      states: new Map(s.states),
      rotation: new Map(s.rotation),
      commits: new Map(s.commits),
      headers: new Map(s.headers),
      leaves: new Map(s.leaves),
    };
  }

  private restore(snap: Store): void {
    // Verified headers stay known: ancestry uses them whether or not the commit was accepted (SPEC 7.3).
    // The re-check that ran inside the failed operation was reverted with it, so run it again here
    // over the restored state for any header the operation learned.
    const headers = this.st.headers;
    this.st = snap;
    let learned = false;
    for (const [k, c] of headers) {
      if (this.st.headers.has(k)) continue;
      this.st.headers.set(k, c);
      learned = true;
    }
    if (learned) {
      this.recheckCutoffs();
      this.propagate();
    }
  }

  private tipRec(): StateRec | undefined {
    return this.st.chain[this.st.chain.length - 1];
  }

  private isWinning(r: StateRec): boolean {
    return this.st.chain[r.seq - 1]?.key === r.key;
  }

  private setStatus(id: string, status: Status): void {
    const r = this.st.commits.get(id);
    if (r !== undefined && r.status !== status) this.st.commits.set(id, { c: r.c, status });
  }

  private headKeys(): string[] {
    const accepted = [...this.st.commits].filter(([, r]) => r.status === "accepted");
    const parents = new Set<string>();
    for (const [, r] of accepted) for (const p of r.c.parents) parents.add(key(p));
    return accepted.map(([k]) => k).filter((k) => !parents.has(k));
  }

  // ─── Manifest states (SPEC 6, 8.3) ──────────────────────────────────────────

  private manifest(m: SignedManifest, commit: Commit | undefined, via: Via): Verdict {
    // Rule 1, structure; rule 2, owner signature.
    if (!manifestShapeOk(m)) return fail("bad_request");
    const s = m.state;
    if (!safeVerify(s.ownerKey, encodeManifestState(s), m.ownerSignature)) return fail("bad_request");
    const hash = manifestHash(m);
    const rec: StateRec = { m, hash, key: key(hash), seq: s.manifestSeq };

    if (s.manifestSeq === 1) {
      // createRepo carries the genesis and its first commit together (SPEC 8.2); without the commit
      // the client request is malformed.
      if (via === "push" && commit === undefined) return fail("bad_request");
      // Rule 3, genesis.
      if (!genesisOk(s)) return fail("bad_request");
      if (this.st.chain.length > 0) {
        // Host level, not an engine verdict: a host answers createRepo for a repoId it already holds
        // with 409 duplicate_repo (SPEC 8.2, 12.3) before consulting the engine. The answer below is a
        // placeholder that no acceptance.json scenario pins.
        const same = this.st.chain[0].key === rec.key;
        return same && via === "offer" && commit === undefined ? OK : fail("manifest_conflict");
      }
      if (!contentOk(s, undefined)) return fail("bad_request");
      // Rule 6, hosted, on a client write. By replication it applies to the tip of the chain being
      // received, which the host checks before it applies any item (SPEC 6.1, 9.2).
      if (via === "push" && !hasHost(s, this.hostKey)) return fail("not_hosted");
      return this.adopt(rec, undefined, commit, via);
    }

    // Rule 4, chain link.
    if (this.st.chain.length === 0) return fail("manifest_conflict");
    const prev = this.st.states.get(key(s.prevManifestHash));
    if (prev === undefined || prev.seq !== s.manifestSeq - 1) return fail("manifest_conflict");
    const known = this.st.states.get(rec.key);
    if (known !== undefined && (this.isWinning(known) || via === "push")) {
      // A retry of a state already on the chain: idempotent by replication, a conflict on publish
      // (SPEC 12.3). A retained losing state offered again is evaluated again below.
      return this.isWinning(known) && via === "offer" && commit === undefined ? OK : fail("manifest_conflict");
    }
    const content = contentOk(s, prev.m.state);
    if (via === "push" && prev !== this.tipRec()) {
      // Still rule 4: a client publish is accepted only at tip + 1 linked to the tip (SPEC 6.3), and it
      // fails here before the content rule; the tie rule is for states that arrive by replication. A
      // state that also passes rule 5 is kept as a verified losing state (SPEC 6.5).
      if (content) this.retainLosing(rec, prev, commit);
      return fail("manifest_conflict");
    }
    // Rule 5, content.
    if (!content) return fail("bad_request");

    if (!this.isWinning(prev)) {
      // Extends a losing chain: verified and retained, never adopted (SPEC 6.5).
      this.retainLosing(rec, prev, commit);
      return fail("manifest_conflict");
    }
    const atSeq = this.st.chain[s.manifestSeq - 1];
    if (atSeq !== undefined && Buffer.compare(hash, atSeq.hash) > 0) {
      // Diverged and loses the tie rule: retained as a verified losing state (SPEC 6.5).
      this.retainLosing(rec, prev, commit);
      return fail("manifest_conflict");
    }
    // Appends to the tip, or wins the tie rule at its seq (lower manifestHash). Rule 6 as above.
    if (via === "push" && !hasHost(s, this.hostKey)) return fail("not_hosted");
    return this.adopt(rec, prev, commit, via);
  }

  private retainLosing(rec: StateRec, prev: StateRec, commit: Commit | undefined): void {
    this.st.states.set(rec.key, rec);
    const raising = rec.m.state.keyEpoch === prev.m.state.keyEpoch + 1;
    if (!raising || commit === undefined || !this.rotationShapeOk(rec, commit) || !this.headerOk(commit)) return;
    // The rotation commit of a losing epoch-raising state is kept with it, held (SPEC 8.3).
    const id = key(commit.commitId);
    if (!this.st.commits.has(id)) this.st.commits.set(id, { c: commit, status: "held" });
    this.st.rotation.set(rec.key, id);
    this.recordHeader(commit);
  }

  /**
   * Records a verified commit header. A new one can complete the ancestry an undecided cutoff was
   * waiting for (SPEC 7.3), so every path that learns a header re-runs the cutoff re-check.
   */
  private recordHeader(c: Commit): void {
    const id = key(c.commitId);
    if (this.st.headers.has(id)) return;
    this.st.headers.set(id, c);
    this.recheckCutoffs();
    this.propagate();
  }

  /** SPEC 8.2 and 8.3: the commit published with a genesis or epoch-raising state. */
  private rotationShapeOk(rec: StateRec, c: Commit): boolean {
    const s = rec.m.state;
    return (
      commitShapeOk(c) &&
      c.manifestSeq === s.manifestSeq &&
      c.manifestHash.equals(rec.hash) &&
      c.keyEpoch === s.keyEpoch &&
      c.author.equals(s.ownerKey) &&
      (s.manifestSeq !== 1 || c.parents.length === 0)
    );
  }

  private citesState(rec: StateRec, c: Commit): boolean {
    return commitShapeOk(c) && c.manifestSeq === rec.seq && c.manifestHash.equals(rec.hash);
  }

  /** Adopts a state onto the winning chain together with its commit, or changes nothing (SPEC 8.2, 8.3). */
  private adopt(rec: StateRec, prev: StateRec | undefined, commit: Commit | undefined, via: Via): Verdict {
    const snap = this.snapshot();
    const v = this.adoptUnchecked(rec, prev, commit, via);
    if (!v.ok) this.restore(snap);
    return v;
  }

  private adoptUnchecked(rec: StateRec, prev: StateRec | undefined, commit: Commit | undefined, via: Via): Verdict {
    const s = rec.m.state;
    const raising = prev !== undefined && s.keyEpoch === prev.m.state.keyEpoch + 1;
    if (raising && commit === undefined) return fail("bad_request");
    if (commit !== undefined) {
      // The genesis commit and a rotation commit have a fixed shape (SPEC 8.2, 8.3); any other commit
      // published with a state is validated as a push that cites the new state.
      const shaped = raising || prev === undefined ? this.rotationShapeOk(rec, commit) : this.citesState(rec, commit);
      if (!shaped) return fail("bad_request");
    }

    const switching = this.st.chain.length >= s.manifestSeq;
    this.st.states.set(rec.key, rec);
    this.st.chain = [...this.st.chain.slice(0, s.manifestSeq - 1), rec];

    if (switching) this.recheckAccepted(s.manifestSeq);
    this.recheckCutoffs();
    for (const r of s.removals) this.st.leaves.delete(key(r.memberKey));
    this.recheckHeld();
    this.propagate();

    if (commit !== undefined) {
      const v = this.commit(commit, via, true);
      if (!v.ok) return v;
      if (raising) this.st.rotation.set(rec.key, key(commit.commitId));
    }
    return OK;
  }

  // ─── Commits (SPEC 7, 6.5) ──────────────────────────────────────────────────

  /** SPEC 7.1: id recomputes and the author signature verifies. */
  private headerOk(c: Commit): boolean {
    return commitId(c).equals(c.commitId) && safeVerify(c.author, commitSigMessage(c.commitId), c.authorSignature);
  }

  private commit(c: Commit, via: Via, carried: boolean): Verdict {
    if (!commitShapeOk(c)) return fail("bad_request");
    const tip = this.tipRec();
    // Host level, not an engine verdict: a host answers 404 not_found for a repository it does not
    // hold (SPEC 10.1) before consulting the engine. The answer below is a placeholder that no
    // acceptance.json scenario pins.
    if (tip === undefined) return fail("missing_parents");
    if (c.repoId !== tip.m.state.repoId || !this.headerOk(c)) return fail("bad_request");
    const id = key(c.commitId);
    this.recordHeader(c);

    // Caller check on the client routes: the caller is the author (the owner for a carried commit)
    // and is a member of the tip.
    if (via === "push") {
      if (carried && !c.author.equals(tip.m.state.ownerKey)) return fail("forbidden");
      if (!hasMember(tip.m.state, c.author)) return fail("forbidden");
    }

    const existing = this.st.commits.get(id);
    if (existing !== undefined) {
      if (existing.status === "accepted") return OK;
      // Undecided cutoff: retryable once the missing frontier commit arrives (SPEC 7.3).
      return existing.status === "pending" ? fail("missing_parents") : fail("forbidden");
    }

    const cls = this.classify(c, via === "push");
    switch (cls.kind) {
      case "error":
        return fail(cls.code);
      case "rejected":
        this.st.commits.set(id, { c, status: "rejected" });
        return fail("forbidden");
      case "held":
        this.st.commits.set(id, { c, status: "held" });
        return fail("forbidden");
      case "accepted":
        this.st.commits.set(id, { c, status: "accepted" });
        return OK;
    }
  }

  /** SPEC 7.2 to 7.4 (and 6.5 for a commit citing a losing state). */
  private classify(c: Commit, applyBound: boolean): Classification {
    const tip = this.tipRec() as StateRec;
    // 7.2 manifest binding: the (seq, hash) pair must name a verified state this host holds.
    const bound = this.st.states.get(key(c.manifestHash));
    if (bound === undefined || bound.seq !== c.manifestSeq) return { kind: "error", code: "missing_parents" };

    let status: "accepted" | "held" = "accepted";
    if (this.isWinning(bound)) {
      if (!hasMember(bound.m.state, c.author) || c.keyEpoch !== bound.m.state.keyEpoch) return { kind: "rejected" };
      const cut = this.cutoff(c, tip);
      if (cut === "fail") return { kind: "rejected" };
      if (cut === "undecided") return { kind: "error", code: "missing_parents" };
    } else {
      const v = this.losingVerdict(c, tip);
      if (v === "undecided") return { kind: "error", code: "missing_parents" };
      if (v === "rejected") return { kind: "rejected" };
      status = v;
    }

    // 7.4 parents.
    const parents = c.parents.map((p) => this.st.commits.get(key(p)));
    if (parents.some((r) => r?.status === "rejected")) return { kind: "rejected" };
    // A pending parent is not accepted and is waiting on a missing frontier commit: retryable.
    if (parents.some((r) => r === undefined || r.status === "pending")) return { kind: "error", code: "missing_parents" };
    if (parents.some((r) => r?.status === "held")) status = "held";

    if (status === "accepted" && applyBound) {
      const heads = new Set(this.headKeys());
      const named = c.parents.filter((p) => heads.has(key(p))).length;
      if (heads.size - named + 1 > this.headBound) return { kind: "error", code: "too_many_heads" };
    }
    return { kind: status };
  }

  /**
   * SPEC 6.5: a commit citing a verified losing state, re-checked against the winning chain. The
   * removal cutoff takes precedence; then accept if the winning state at that seq lists the author at
   * the commit's epoch; then the drop test; otherwise held.
   */
  private losingVerdict(c: Commit, tip: StateRec): "accepted" | "held" | "rejected" | "undecided" {
    const cut = this.cutoff(c, tip);
    if (cut === "fail") return "rejected";
    if (cut === "undecided") return "undecided";
    const w = this.st.chain[c.manifestSeq - 1];
    if (w !== undefined && hasMember(w.m.state, c.author) && w.m.state.keyEpoch === c.keyEpoch) return "accepted";
    if (this.dropTest(c, tip)) return "rejected";
    return "held";
  }

  /**
   * SPEC 6.5 drop test: the tip's epoch passed the commit's, or the author was removed and the commit
   * is not covered by the frontier. A cutoff that cannot be decided yet is not a drop (SPEC 7.3 says
   * only that the host MUST NOT accept such a commit).
   */
  private dropTest(c: Commit, tip: StateRec): boolean {
    if (tip.m.state.keyEpoch > c.keyEpoch) return true;
    return this.cutoff(c, tip) === "fail";
  }

  /**
   * SPEC 7.3 removal cutoff against the tip's removals: a commit by a removed author is valid only if
   * its id is in the frontier or it is an ancestor of a frontier commit, ancestry following the
   * parents of every verified header. `"undecided"` when a header on the way is unknown.
   */
  private cutoff(c: Commit, tip: StateRec): "ok" | "fail" | "undecided" {
    const r = tip.m.state.removals.find((x) => x.memberKey.equals(c.author));
    if (r === undefined) return "ok";
    const target = key(c.commitId);
    const stack = r.frontier.map(key);
    if (stack.includes(target)) return "ok";
    const seen = new Set(stack);
    let undecided = false;
    while (stack.length > 0) {
      const h = this.st.headers.get(stack.pop() as string);
      if (h === undefined) {
        undecided = true;
        continue;
      }
      for (const p of h.parents) {
        const pk = key(p);
        if (pk === target) return "ok";
        if (!seen.has(pk)) {
          seen.add(pk);
          stack.push(pk);
        }
      }
    }
    return undecided ? "undecided" : "fail";
  }

  private cutoffOk(c: Commit): boolean {
    const tip = this.tipRec();
    return tip !== undefined && this.cutoff(c, tip) === "ok";
  }

  // ─── Re-checks after a new winning state ────────────────────────────────────

  /** SPEC 6.5: after a switch, every accepted commit citing a state from the fork point on. */
  private recheckAccepted(forkSeq: number): void {
    const tip = this.tipRec() as StateRec;
    for (const [id, r] of [...this.st.commits]) {
      if (r.status !== "accepted" || r.c.manifestSeq < forkSeq) continue;
      const bound = this.st.states.get(key(r.c.manifestHash));
      if (bound === undefined || this.isWinning(bound)) continue;
      const v = this.losingVerdict(r.c, tip);
      if (v === "rejected" || v === "held") this.setStatus(id, v);
      else if (v === "undecided") this.setStatus(id, "pending");
    }
  }

  /**
   * SPEC 7.3, run on each new winning state and each new verified header: every stored commit by a
   * removed member is checked against the tip's cutoff. One that fails is dropped; an accepted one
   * that cannot be decided leaves the heads as pending; a pending one that is now covered is accepted
   * again. A held commit stays held unless it fails.
   */
  private recheckCutoffs(): void {
    const tip = this.tipRec();
    if (tip === undefined) return;
    for (const [id, r] of [...this.st.commits]) {
      if (r.status === "rejected") continue;
      const cut = this.cutoff(r.c, tip);
      if (cut === "fail") this.setStatus(id, "rejected");
      else if (cut === "undecided" && r.status === "accepted") this.setStatus(id, "pending");
      else if (cut === "ok" && r.status === "pending") this.setStatus(id, this.decidePending(r.c));
    }
  }

  /**
   * The status of a pending commit whose own cutoff is now decided as covered. A commit citing a
   * verified losing state goes through the rest of the SPEC 6.5 re-check (winning state at its seq,
   * drop test, hold), as at its first classification; then its parents decide as in SPEC 7.4.
   */
  private decidePending(c: Commit): Status {
    const tip = this.tipRec() as StateRec;
    let status: Status = "accepted";
    const bound = this.st.states.get(key(c.manifestHash));
    if (bound !== undefined && !this.isWinning(bound)) {
      const v = this.losingVerdict(c, tip);
      if (v === "undecided") return "pending";
      if (v === "rejected") return "rejected";
      status = v;
    }
    const parents = c.parents.map((p) => this.st.commits.get(key(p))?.status);
    if (parents.includes("rejected")) return "rejected";
    if (parents.includes("pending") || parents.includes(undefined)) return "pending";
    if (parents.includes("held")) return "held";
    return status;
  }

  /**
   * SPEC 6.5 deciding a held commit, against the new tip: dropped if it meets the drop test, accepted
   * if the tip lists its author at its epoch, held otherwise. A held descendant waits for its held
   * ancestors and is then re-checked in turn.
   */
  private recheckHeld(): void {
    const tip = this.tipRec() as StateRec;
    for (let changed = true; changed; ) {
      changed = false;
      this.propagate();
      for (const [id, r] of [...this.st.commits]) {
        if (r.status !== "held") continue;
        const parents = r.c.parents.map((p) => this.st.commits.get(key(p))?.status);
        if (parents.some((p) => p !== "accepted")) continue;
        if (this.dropTest(r.c, tip)) {
          this.setStatus(id, "rejected");
          changed = true;
        } else if (this.cutoff(r.c, tip) === "ok" && hasMember(tip.m.state, r.c.author) && tip.m.state.keyEpoch === r.c.keyEpoch) {
          this.setStatus(id, "accepted");
          changed = true;
        }
      }
    }
  }

  /**
   * A commit with a rejected parent is rejected; an accepted commit with a held parent is held, and
   * one with a pending parent is pending.
   */
  private propagate(): void {
    for (let changed = true; changed; ) {
      changed = false;
      for (const [id, r] of [...this.st.commits]) {
        if (r.status === "rejected") continue;
        const parents = r.c.parents.map((p) => this.st.commits.get(key(p))?.status);
        if (parents.includes("rejected")) {
          this.setStatus(id, "rejected");
          changed = true;
        } else if (r.status === "accepted" && parents.includes("held")) {
          this.setStatus(id, "held");
          changed = true;
        } else if (r.status === "accepted" && parents.includes("pending")) {
          this.setStatus(id, "pending");
          changed = true;
        } else if (r.status === "pending" && !parents.includes("pending") && this.cutoffOk(r.c)) {
          // Waiting only on its parent: decided again, with the full re-check, once the parent is.
          const next = this.decidePending(r.c);
          if (next !== "pending") {
            this.setStatus(id, next);
            changed = true;
          }
        }
      }
    }
  }
}
