# AVP conformance harness

A black-box conformance suite for the AVP 0.5 HTTP/JSON profile. Point it at one running AVP host and it
drives the client wire contract end to end, asserting the normative MUSTs with the exact status and
`code` of the SPEC 10.4 error table instead of just printing a transcript. It is the executable companion
to the static [`../vectors/`](../vectors/): the vectors prove your crypto reproduces known-good bytes; this
proves your *host* behaves.

```sh
# against any host (use 127.0.0.1 rather than localhost on Windows)
bun conformance.ts --server http://127.0.0.1:19101
# or
AVP_SERVER_URL=http://127.0.0.1:19101 bun conformance.ts
```

Exit code is `0` only if every check passes; each check prints `PASS`/`FAIL` with its SPEC section. The
harness polls `GET /.well-known/avp` until the host answers, so it can be started together with the host.

| Option | Default | Meaning |
|---|---|---|
| `--challenge-ttl-ms N` | `120000` | The host's challenge nonce lifetime (SPEC 3.3 RECOMMENDED maximum). The expired-nonce check redeems a nonce issued at start once this much time (plus 3 s) has passed, so a run takes about two minutes. |
| `--head-bound N` | `16` | The host's head bound (SPEC 7.4 RECOMMENDED value). |
| `--startup-timeout-ms N` | `30000` | How long to wait for discovery. |

## What it checks

| SPEC | Checks |
|---|---|
| §11.7 Discovery | `version` is `0.5`, `profiles` lists `http-json`, `hostKey` is a 32-byte key; every later host match uses that key. |
| §2, §3.3 Auth | a challenge returns a nonce of at least 32 bytes; a signature over the raw nonce yields a token; `401 unauthorized` for a reused nonce, an expired nonce, a nonce issued for another key, a nonce never issued, a signature by another key, and a signature over the base64 text; no token for the small-order identity key's forged signature (strict Ed25519); `401` for a missing or unknown bearer token. |
| §6.1, §6.2, §8.2 createRepo | `403 forbidden` when the caller is not the genesis `ownerKey`; `400 bad_request` for a `repoId` that does not recompute, a bad owner signature, a genesis with a second member, and a genesis at `keyEpoch` 1; `403 not_hosted` when `hosts` does not list the host; `400` for a first commit whose id does not recompute, after which the valid create still succeeds (nothing stored); the valid create returns the genesis it was sent; a repeat is `409 duplicate_repo`. |
| §10.1, §10.4 Routing | `404 not_found` for pull and push on a repository the host does not hold; a bad percent escape in the path is `400` (status only); a body that is not JSON is `400 bad_request`. |
| §6.3, §6.1 publishManifest | `403 forbidden` for a caller that is not `ownerKey`; `409 manifest_conflict` for seq tip + 2, a wrong `prevManifestHash`, and a republished seq; `400 bad_request` for a bad owner signature, a member epoch mismatch, a `homeHostKey` not in `hosts`, a member dropped without a removal, and a removal that does not raise `keyEpoch`. |
| §10.1 pull | the chain from `sinceManifestSeq` in ascending order (0, 1, and the tip), as published and linked by hash; the heads not in `knownHeads` as full commits that verify; pending leave requests; `403 forbidden` for a non-member and for a removed member. |
| §4.3, §4.4 Payload | the served commit is byte-identical and decrypts under AAD v2 rebuilt from its own header; a joined member unwraps the data key from the served state. |
| §7.1, §7.2 push | `400 bad_request` for an id that does not recompute, a bad author signature, another repository's `repoId`, and a small-order author key with a forged signature (strict Ed25519, before the caller check); `403 forbidden` for a caller that is not the author, a non-member, an epoch mismatch, and a cited state that does not list the author; `422 missing_parents` naming an unknown manifest hash in `detail`; a commit citing the previous state is still accepted. |
| §7.4 Heads | a concurrent push on the same parent is `200` and leaves two heads (no conflict outcome); a re-push is accepted with no change; an unknown parent is `422 missing_parents` with the id in `detail`; a merge collapses the heads; forks up to the bound are accepted, the next is `409 too_many_heads`, a merge at the bound is accepted, and the bound is exact. |
| §7.3, §8.3 Removal | an epoch-raising state without its rotation commit, with a rotation commit not by the owner, or under the old epoch is `400 bad_request`; after the removal the heads are exactly the rotation commit, so the removed member's commit outside the frontier and a descendant of it by another member are dropped; the removed member can no longer pull or push. |
| §8.2 prepareJoin | the acceptance names the repo, the caller, and the discovered host key, has a future `expiresAt`, verifies under the discovered `hostKey`, and passes the owner's invite check; `403 forbidden` when `memberKey` is not the caller. |
| §8.4 Leave | `400 bad_request` for a bad signature or another repository; `403 forbidden` for a caller that is not `memberKey`, the owner, a non-member, and a removed member; a valid request is `200 {}` and is served unchanged by pull; only the latest per member is kept; it is dropped once a state removes the member. |
| §6.1, §8.6 Not hosted | a state that drops the host is `403 not_hosted`, after which pull and push are `403 not_hosted`. |
| §13 Zero-knowledge | a random plaintext marker, written into every payload the harness encrypts, appears in no response text and in no base64 value of any response. |

Multi-host behavior (SPEC §9: replication, convergence, diverged owner states) is out of scope for this
single-host suite.

## How it works

The only AVP-specific code is the client-side construction, re-exported by [`crypto.ts`](crypto.ts) from
the vector-tested conformance runner in [`../examples/conformance/src`](../examples/conformance/src/):
the CE writer, manifest and commit constructions, AAD v2, the wrap scheme, BIP39 owner keys, and strict
Ed25519. Every body is built from real keys and real signatures, so the harness itself stays a thin wire
driver. It runs under [Bun](https://bun.sh) with no install step (only Node's built-in `crypto` and
global `fetch`). `bun install && bun run typecheck` runs `tsc` over it.

A pass certifies the surface this harness covers; it supplements, and does not replace, reproducing the
[`../vectors/`](../vectors/) in your implementation language. CI runs it against the Rust and Java
reference hosts (`.github/workflows/conformance.yml`).
