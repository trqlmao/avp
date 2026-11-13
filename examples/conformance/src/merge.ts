/**
 * Payload v2 (SPEC section 5): the per-account, per-field merge, the deletion rule, refresh-token
 * stripping (SPEC 5.1), and the hybrid logical clock that stamps every write.
 *
 * Checked against `vectors/merge.json`, whose expected results are hand-written from the SPEC rule.
 *
 * Illustrative reference code, not production. SPDX-License-Identifier: MIT
 */

/** A write stamp `(at, n, by)` (SPEC 5). */
export interface Stamp {
  at: number;
  n: number;
  by: string;
}

/** One last-writer-wins register: a value and its stamp (SPEC 5). */
export interface Field extends Stamp {
  value: unknown;
}

/** One account: its optional deletion marker, its fields, and its bans keyed by server id (SPEC 5). */
export interface Account {
  deleted?: Stamp;
  fields: Record<string, Field>;
  bans: Record<string, Field>;
}

/** The plaintext inside a commit's ciphertext (SPEC 5). */
export interface PayloadV2 {
  v: 2;
  accounts: Record<string, Account>;
}

/** The fields SPEC 5.1 strips when the refresh-token policy is not `true`. */
export const REFRESH_FIELDS = ["refreshToken", "expiresAt"] as const;

/**
 * Orders two stamps by `at`, then `n`, then `by` compared by its UTF-8 bytes (SPEC 5).
 *
 * @returns A negative number, zero, or a positive number as `a` is less than, equal to, or greater
 *   than `b`.
 */
export function compareStamps(a: Stamp, b: Stamp): number {
  if (a.at !== b.at) return a.at < b.at ? -1 : 1;
  if (a.n !== b.n) return a.n < b.n ? -1 : 1;
  return Buffer.compare(Buffer.from(a.by, "utf8"), Buffer.from(b.by, "utf8"));
}

const stampOf = (s: Stamp): Stamp => ({ at: s.at, n: s.n, by: s.by });
const fieldOf = (f: Field): Field => ({ value: structuredClone(f.value), at: f.at, n: f.n, by: f.by });

/** Merges one map of registers into `into`, keeping the greatest stamp per key. */
function mergeRegisters(into: Map<string, Field>, from: Record<string, Field>): void {
  for (const [k, f] of Object.entries(from)) {
    const cur = into.get(k);
    if (cur === undefined || compareStamps(f, cur) > 0) into.set(k, f);
  }
}

/** Builds a plain object from a map with its keys in sorted (UTF-16 code unit) order. */
function sortedRecord<V, W>(m: Map<string, V>, f: (v: V) => W): Record<string, W> {
  const out: Record<string, W> = {};
  for (const k of [...m.keys()].sort()) out[k] = f(m.get(k) as V);
  return out;
}

/**
 * Merges two or more payloads (SPEC 5): the union of the accounts; per account, each field name and
 * each ban server id takes the `Field` with the greatest stamp among the inputs; `deleted` is the
 * greatest `deleted` stamp and is absent if no input has one. The inputs are not modified.
 *
 * @param ps - The payloads, at least one.
 * @returns The merged payload, a fresh object with its map keys sorted.
 * @throws If `ps` is empty or a payload's `v` is not `2` (such a payload is unreadable).
 */
export function mergePayloads(ps: PayloadV2[]): PayloadV2 {
  if (ps.length === 0) throw new Error("mergePayloads needs at least one payload");
  const acc = new Map<string, { deleted?: Stamp; fields: Map<string, Field>; bans: Map<string, Field> }>();
  for (const p of ps) {
    if (p === null || typeof p !== "object" || p.v !== 2 || p.accounts === null || typeof p.accounts !== "object") {
      throw new Error("payload is not v 2");
    }
    for (const [uuid, a] of Object.entries(p.accounts)) {
      let cur = acc.get(uuid);
      if (cur === undefined) {
        cur = { fields: new Map(), bans: new Map() };
        acc.set(uuid, cur);
      }
      if (a.deleted !== undefined && (cur.deleted === undefined || compareStamps(a.deleted, cur.deleted) > 0)) {
        cur.deleted = a.deleted;
      }
      mergeRegisters(cur.fields, a.fields ?? {});
      mergeRegisters(cur.bans, a.bans ?? {});
    }
  }
  return {
    v: 2,
    accounts: sortedRecord(acc, (a) => {
      const out: Account = { fields: sortedRecord(a.fields, fieldOf), bans: sortedRecord(a.bans, fieldOf) };
      return a.deleted === undefined ? out : { deleted: stampOf(a.deleted), ...out };
    }),
  };
}

/**
 * Removes the `refreshToken` and `expiresAt` fields, stamps included, from every account (SPEC 5.1).
 * A client applies it to every payload it encrypts, decrypts, or merges while the policy is not
 * `true`. The input is not modified.
 *
 * @param p - The payload.
 * @returns A copy without the two fields.
 */
export function stripRefresh(p: PayloadV2): PayloadV2 {
  const accounts: Record<string, Account> = {};
  for (const [uuid, a] of Object.entries(p.accounts)) {
    const fields: Record<string, Field> = {};
    for (const [k, f] of Object.entries(a.fields)) {
      if (!(REFRESH_FIELDS as readonly string[]).includes(k)) fields[k] = fieldOf(f);
    }
    const bans: Record<string, Field> = {};
    for (const [k, f] of Object.entries(a.bans)) bans[k] = fieldOf(f);
    accounts[uuid] = a.deleted === undefined ? { fields, bans } : { deleted: stampOf(a.deleted), fields, bans };
  }
  return { v: 2, accounts };
}

/**
 * Whether an account is deleted (SPEC 5): `deleted` exists and is greater than every field stamp and
 * every ban stamp in the account.
 */
export function isDeleted(a: Account): boolean {
  if (a.deleted === undefined) return false;
  const d = a.deleted;
  return [...Object.values(a.fields), ...Object.values(a.bans)].every((f) => compareStamps(d, f) > 0);
}

/**
 * A hybrid logical clock with state `(at, n)` (SPEC 5). A client observes every stamp of every
 * payload it merges before its next tick, so each stamp it writes exceeds every stamp it has seen.
 */
export class Hlc {
  private at: number;
  private n: number;

  constructor(at = 0, n = 0) {
    this.at = at;
    this.n = n;
  }

  /**
   * Advances the clock for a write: `(now, 0)` if `now > at`, otherwise `(at, n + 1)`.
   *
   * @param nowMs - The wall clock in epoch milliseconds.
   * @returns The new state; with the client's member id as `by`, it is the write's stamp.
   */
  tick(nowMs: number): { at: number; n: number } {
    if (nowMs > this.at) {
      this.at = nowMs;
      this.n = 0;
    } else {
      this.n += 1;
    }
    return this.state();
  }

  /**
   * Folds in a stamp seen in a merged payload: a later `at` is taken with its `n`; an equal `at`
   * takes the larger `n`; an earlier one changes nothing.
   */
  observe(s: Stamp): void {
    if (s.at > this.at) {
      this.at = s.at;
      this.n = s.n;
    } else if (s.at === this.at) {
      this.n = Math.max(this.n, s.n);
    }
  }

  /** @returns The current state. */
  state(): { at: number; n: number } {
    return { at: this.at, n: this.n };
  }
}
