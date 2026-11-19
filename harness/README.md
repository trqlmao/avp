# AVP conformance harness

A black-box conformance suite for the AVP 0.5 HTTP/JSON and gRPC client profiles. Point it at one running AVP host and it
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

## Profiles

`--profile http-json` (the default) drives the HTTP/JSON profile (SPEC §10.2). `--profile grpc` drives
the same suite over the gRPC client profile (SPEC §10.3): `--server` is then `grpc://host:port`
(plaintext) or `grpcs://host:port` (TLS), with `AVP_GRPC_URL` as the fallback. [`transport.ts`](transport.ts)
maps each client route to its `avp.Vault` RPC (a pull gains `repoId` from the path), loads
[`../proto/avp.proto`](../proto/avp.proto) at runtime, and turns a refused call back into the SPEC 10.4
error object (the status message is the `code`, `detail` the `avp-error-detail` trailer); every
expected error then also asserts the gRPC status of the §10.3 table. Discovery runs on `GetHostInfo`
and must list `grpc`. The checks of HTTP framing have no gRPC form, because the repository is the
body's, and print `SKIP (http-json only)`: the bad percent escape, the non-JSON body, and a push or
leave naming another repository than the path. The gRPC profile needs `bun install` here
(`@grpc/grpc-js`, `@grpc/proto-loader`); the HTTP/JSON profile still runs without an install.

```sh
bash harness/run-hosts.sh rust -- bun harness/conformance.ts --profile grpc --server grpc://127.0.0.1:19211
```

| Option | Default | Meaning |
|---|---|---|
| `--challenge-ttl-ms N` | `120000` | The host's challenge nonce lifetime (SPEC 3.3 RECOMMENDED maximum). The expired-nonce check redeems a nonce issued at start once this much time (plus 3 s) has passed, so a run takes about two minutes. |
| `--head-bound N` | `16` | The host's head bound (SPEC 7.4 RECOMMENDED value). |
| `--startup-timeout-ms N` | `30000` | How long to wait for discovery. |
| `--request-timeout-ms N` | `30000` | How long one request may take; a host that does not answer in time fails the run instead of hanging it. |

## What it checks

| SPEC | Checks |
|---|---|
| §11.7 Discovery | `version` is `0.5`, `profiles` lists `http-json` (`grpc` under `--profile grpc`, on `GetHostInfo`), `hostKey` is a 32-byte key; every later host match uses that key. |
| §2, §3.3 Auth | a challenge returns a nonce of at least 32 bytes; a signature over the `avp/challenge/v1` transcript of the host key, the key, and the raw nonce yields a token; `401 unauthorized` for a reused nonce, an expired nonce, a nonce issued for another key, a nonce never issued, a signature by another key, a transcript over the base64 text, a signature over the raw nonce alone (the old construction), and a transcript built with another host key; strict Ed25519: no token for a forged signature under the small-order identity key or the non-canonical key `y = p + 1`, for an honest key's signature with `R` = identity, or for a valid signature with `L` added to `S`; `401` for a missing or unknown bearer token. |
| §6.1, §6.2, §8.2 createRepo | `403 forbidden` when the caller is not the genesis `ownerKey`; `400 bad_request` for a `repoId` that does not recompute, a bad owner signature, a genesis with a second member, and a genesis at `keyEpoch` 1; `403 not_hosted` when `hosts` does not list the host; `400` for a first commit whose id does not recompute, after which the valid create still succeeds (nothing stored); the valid create returns the genesis it was sent; a repeat is `409 duplicate_repo`. |
| §10.1, §10.4 Routing | `404 not_found` for pull and push on a repository the host does not hold; a bad percent escape in the path is `400` (status only); a body that is not JSON is `400 bad_request`. |
| §6.3, §6.1 publishManifest | `403 forbidden` for a caller that is not `ownerKey`; `409 manifest_conflict` for seq tip + 2, a wrong `prevManifestHash`, and a republished seq; `400 bad_request` for a bad owner signature, a member epoch mismatch, a `homeHostKey` not in `hosts`, a member dropped without a removal, and a removal that does not raise `keyEpoch`. |
| §10.1 pull | the chain from `sinceManifestSeq` in ascending order (0, 1, and the tip), as published and linked by hash; the heads not in `knownHeads` as full commits that verify; pending leave requests; `403 forbidden` for a non-member and for a removed member. |
| §4.3, §4.4 Payload | the served commit is byte-identical and decrypts under AAD v2 rebuilt from its own header; a joined member unwraps the data key from the served state. |
| §7.1, §7.2 push | `400 bad_request` for an id that does not recompute, a bad author signature, a challenge signature (SPEC §4.1) whose nonce is the commit id or the whole commit-sig message presented as the author signature, another repository's `repoId`, and, by strict Ed25519 before the caller check, a commit signed by alice with `R` = identity or with `S + L`, and forged commits under the identity key, an order-8 key (and its sign-bit variant with an honest `R`), and the non-canonical key; `403 forbidden` for a caller that is not the author, a non-member, an epoch mismatch, and a cited state that does not list the author; `422 missing_parents` naming an unknown manifest hash in `detail`; a commit citing the previous state is still accepted. |
| §7.4 Heads | a concurrent push on the same parent is `200` and leaves two heads (no conflict outcome); a re-push is accepted with no change; an unknown parent is `422 missing_parents` with the id in `detail`; a merge collapses the heads; forks up to the bound are accepted, the next is `409 too_many_heads`, a merge at the bound is accepted, and the bound is exact. |
| §7.3, §8.3 Removal | an epoch-raising state without its rotation commit, with a rotation commit not by the owner, or under the old epoch is `400 bad_request`; after the removal the heads are exactly the rotation commit, so the removed member's commit outside the frontier and a descendant of it by another member are dropped, and a member's child of either is `403 forbidden`; the removed member can no longer pull or push. |
| §8.2 prepareJoin | the acceptance names the repo, the caller, and the discovered host key, has a future `expiresAt`, verifies under the discovered `hostKey`, and passes the owner's invite check; `403 forbidden` when `memberKey` is not the caller. |
| §8.4 Leave | `400 bad_request` for a bad signature or another repository; `403 forbidden` for a caller that is not `memberKey`, the owner, a non-member, and a removed member; a valid request is `200 {}` and is served unchanged by pull; only the latest per member is kept; it is dropped once a state removes the member. |
| §6.1, §8.6 Not hosted | a state that drops the host is `403 not_hosted`, after which pull and push are `403 not_hosted`. |
| §13 Zero-knowledge | a random plaintext marker, written into every payload the harness encrypts, appears in no response text and in no base64 value of any response. |

Multi-host behavior (SPEC §9: replication, convergence, diverged owner states) is out of scope for this
single-host suite; [`multihost.ts`](#multi-host-scenarios) covers it.

## Multi-host scenarios

`multihost.ts` drives two hosts, A and B, that replicate with each other (SPEC §9), plus an optional
third host C, and asserts what both hosts must converge on. It uses only the client routes and the
reference test control (SPEC §9.3), so it runs against any pair of hosts that ship that profile, in any
language pairing.

```sh
bun multihost.ts --a http://127.0.0.1:19201 --b http://127.0.0.1:19202 --c http://127.0.0.1:19203
```

Start each host with `AVP_TEST_CONTROL=1`, `AVP_BIND=127.0.0.1` (the test control must not face a
network), a distinct `AVP_HOST_SEED`, and `AVP_PEERS` naming the others
(`<base64 hostKey>@http://127.0.0.1:<port>`; the host key is the one each host's `/.well-known/avp`
serves). A and B peer with each other; C peers with A and B (and they with C) but is never listed in a
repository's `hosts`. Without `--c` the `unlisted-host-refused` scenario is skipped with a printed note.
Exit code is `0` only if every check passes; a failure names its scenario.

[`run-hosts.sh`](run-hosts.sh) does that setup for the reference hosts. It builds and starts one to three
of them (`rust` or `java`) on `http://127.0.0.1:19201`, `:19202` and `:19203` with fixed distinct seeds,
every host peered with the others, waits for each to serve `/.well-known/avp`, runs a command from the
repository root, and stops the hosts. Every `rust` host also serves the gRPC client profile on
`grpc://127.0.0.1:19211`, `:19212` and `:19213` (`AVP_GRPC_PORT`); the script waits for its
`grpc on 127.0.0.1:<port>` startup line and exports `AVP_GRPC_URL`, `AVP_GRPC_URL_B`, and
`AVP_GRPC_URL_C` for the rust hosts only (the java host is HTTP/JSON only). CI and the Taskfile use it:

```sh
bash harness/run-hosts.sh rust java java -- bun harness/multihost.ts \
  --a http://127.0.0.1:19201 --b http://127.0.0.1:19202 --c http://127.0.0.1:19203
bash harness/run-hosts.sh java -- bun harness/conformance.ts --server http://127.0.0.1:19201
bash harness/run-hosts.sh rust rust rust -- bun harness/multihost.ts --profile grpc \
  --a http://127.0.0.1:19201 --b http://127.0.0.1:19202 --c http://127.0.0.1:19203 \
  --a-grpc grpc://127.0.0.1:19211 --b-grpc grpc://127.0.0.1:19212 --c-grpc grpc://127.0.0.1:19213
```

The command also gets `AVP_SERVER_URL` (host A) and, when started, `AVP_SERVER_URL_B` and
`AVP_SERVER_URL_C`, the variables the reference clients read. `JAVA_HOME` picks the JDK; host logs go
to `AVP_HOSTS_LOG_DIR` (default a new temporary directory) and are printed when a run fails.

| Option | Default | Meaning |
|---|---|---|
| `--profile P` | `http-json` | `grpc` sends every client operation to `--a-grpc`, `--b-grpc`, `--c-grpc` (`grpc://host:port`; env `AVP_GRPC_URL`, `AVP_GRPC_URL_B`, `AVP_GRPC_URL_C`); `--a`, `--b`, `--c` stay HTTP for the test control and the host routes, which are not client operations. Each host must list `grpc` and answer the same host key on both fronts. |
| `--converge-ms N` | `15000` | How long a convergence wait polls (every 250 ms). |
| `--quiet-ms N` | `6000` | How long a "nothing arrives" check waits: one 5 s sweep (SPEC §9.3) plus a margin. |
| `--startup-timeout-ms N` | `30000` | How long to wait for each host's discovery. |
| `--request-timeout-ms N` | `30000` | How long one request may take. |

Every scenario works on a fresh repository that the owner creates on A and then lists on B the way
SPEC §8.1 and §8.2 add a host (bob's `prepareJoin` on B, then a seq 2 adding B and bob), so B's first
copy always arrives by replication. "Paused" means the test control `POST /v1/test/replication
{ paused: true }` on B, which stops all host traffic to and from B.

| Scenario | SPEC | Checks |
|---|---|---|
| `write-while-b-paused-converges` | §8.4, §9.1, §9.2, §9.3 | B gets its first copy from A; a paused B answers a host route with `503` and receives nothing for one sweep; after the heal B's heads are exactly A's write, served unchanged; a write on B then reaches A. Leave requests replicate both ways: bob's leave on B is offered to A, which serves it unchanged; a newer leave on A while B is paused has not reached B one sweep later (A's single offer was refused), then reaches B by catch-up `fetch` after the heal and replaces the older one there. |
| `concurrent-writes-two-heads-then-merge` | §7.4, §9.2 | concurrent writes on A and on paused B on the same parent leave the same two heads on both hosts (no conflict outcome); the owner's merge on A collapses them on both. |
| `removed-member-rejected-on-both` | §7.1, §7.3, §7.4, §8.3 | carol writes on paused B while the owner removes her on A with frontier `[cc1]`; after the heal B adopts the removal and drops her commit outside the frontier (heads exactly the rotation commit), A never accepts it, her pull and push are `403 forbidden` on both, and a child of the dropped commit is `403 forbidden` on B and refused on A. |
| `unlisted-host-refused` | §6.1, §9.2, §9.3 | C, peered but not listed, answers `404 not_found` for the repository's pull and push, before and after a sweep interval of writes on A; A and B serve the same chain and heads. (A direct signed host request from C is out of scope: the harness holds no host key of C's.) |
| `old-epoch-head` | §7.2, §7.5, §8.3 | bob writes under epoch 0 on paused B while the owner rotates to epoch 1 on A; after the heal both hosts keep the old-epoch head next to the rotation commit, the owner decrypts it with epoch 0's key, and its merge forward under epoch 1 collapses the heads on both. |
| `diverged-owner` | §6.3, §6.5 | the owner publishes one seq 3 on A and a different seq 3 on paused B; after the heal both chains end in the bytewise-lower `manifestHash`, bob's commit citing the losing state is accepted after re-check on both, each host answers the losing state with `409 manifest_conflict`, and seq 4 on the winning chain replicates. It runs once with the lower hash on A and once on B. |

Every payload carries a random marker, which must appear in no response (SPEC §13).

## How it works

The only AVP-specific code is the client-side construction, re-exported by [`crypto.ts`](crypto.ts) from
the vector-tested conformance runner in [`../examples/conformance/src`](https://github.com/trqlmao/avp/tree/main/examples/conformance/src):
the CE writer, manifest and commit constructions, AAD v2, the wrap scheme, BIP39 owner keys, and strict
Ed25519. Every body is built from real keys and real signatures, so the harness itself stays a thin wire
driver; [`common.ts`](common.ts) holds the parties and constructions both harnesses share. It runs
under [Bun](https://bun.sh) with no install step for the HTTP/JSON profile (only Node's built-in
`crypto` and global `fetch`); the gRPC profile imports its libraries on first use. `bun install && bun
run typecheck` runs `tsc` over it.

A pass certifies the surface this harness covers; it supplements, and does not replace, reproducing the
[`../vectors/`](../vectors/) in your implementation language. CI runs it against the Rust and Java
reference hosts, and over the gRPC profile against the Rust host (`.github/workflows/conformance.yml`).
