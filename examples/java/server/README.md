# AVP reference host (Java)

An in-memory reference host for [AVP 0.5](../../../SPEC.md), HTTP/JSON profile. It serves the
client-facing API of SPEC section 10 (host-issued authentication, `createRepo`, `pull`, `push`,
`publishManifest`, `leave`, `prepareJoin`, and discovery) and replicates repositories with its peer
hosts over the reference host-to-host profile of SPEC section 9.3 (signed HTTP/JSON). It behaves like
the [Rust reference host](../../rust/server/), and the two replicate with each other.

The host is a thin HTTP/JSON layer over the shared Java sources in [`../avp`](../avp/). Their
`AvpRules.RepoView` runs every manifest chain and commit rule (SPEC sections 6 and 7); the host only
authenticates the caller, decodes the body, checks the caller identity each operation requires, maps
the engine's reject codes to the status table of SPEC 10.4, and serializes the answer. Items received
from a peer go through the same engine: the host never trusts a peer's verdict.

> **Illustrative, not for production.** State lives in process memory and is lost on restart, and
> there is no TLS. What it does honour is the part that matters: it is **zero-knowledge**. It stores
> only owner-signed manifest states (public keys, wrapped keys, counters, signatures), commits
> (ciphertext, ids, signatures), and signed leave requests. It never holds a data key, decrypts
> nothing, and never logs a request body.

## Build and run

JDK 21 or later, nothing else: no build tool, no dependencies (`com.sun.net.httpserver` serves,
`java.net.http.HttpClient` calls peers, JCA does Ed25519). From this directory:

```sh
javac -d build ../avp/*.java *.java
java -cp build Server                                   # listens on http://0.0.0.0:8787
PORT=9000 java -cp build Server                         # another port
AVP_HOST_SEED=<64 hex digits> java -cp build Server     # a fixed host key
AVP_PEERS="<base64 key>@http://b.vault.example:8787" java -cp build Server   # peer with another host
java -cp build SmokeTest                                # the API and replication suite
```

| Variable | Meaning |
|---|---|
| `PORT` | Listen port on `0.0.0.0`. Default `8787`. |
| `AVP_HOST_SEED` | The 32-byte Ed25519 seed of the host key, as 64 hex digits. Without it the host key is random for each start. |
| `AVP_PEERS` | The static peer list, `<base64 hostKey>@<http base url>,...` (SPEC 9.3). Only these keys may call the host routes. Unset or empty means no peers. Plain `http://` only. |
| `AVP_TEST_CONTROL` | `1` enables `POST /v1/test/replication` (below). Never set it in production; without it the route does not exist (`404`). |

A bad `PORT`, `AVP_HOST_SEED`, or `AVP_PEERS` value exits with code 1 and a message naming it.

The binary prints the port and the host key (base64) at start. A client checks that key against
`GET /.well-known/avp` and against the manifest's `hosts` (SPEC 3.3, 11.7).

`SmokeTest` starts hosts in-process (`Server.start(port, config)`, port `0` for a free one) and talks
to them over real HTTP, with every body built by the shared sources from real keys and signatures. It
has one check per test of the Rust host's `tests/api.rs` and `tests/replication.rs`, under the same
name, and prints `ok <name>` for each; the exit code is 0 only when every check passed.

## Files

| File | What it holds |
|---|---|
| [`Server.java`](Server.java) | The binary, the HTTP layer, host-issued authentication, the client routes, and the host routes. |
| [`Replication.java`](Replication.java) | The peer list, host request signatures, applying received items, and the peer workers. |
| [`SmokeTest.java`](SmokeTest.java) | The integration suite. |

## Routes

Bodies are JSON with the proto field names in `camelCase` and binary values as base64 with padding
(see [`schema/avp.schema.json`](../../../schema/avp.schema.json) and
[`openapi.yaml`](../../../openapi.yaml)). Every route except discovery and the two auth routes needs
`Authorization: Bearer <token>`, where the token was minted by this host.

| Route | Body and response | Caller must be |
|---|---|---|
| `GET /.well-known/avp` | `{ version: "0.5", profiles: ["http-json"], hostKey }` | anyone |
| `POST /api/auth/keypair/challenge` | `{ ed25519PublicKey }` to `{ nonce }` | anyone |
| `POST /api/auth/keypair/token` | `{ ed25519PublicKey, nonce, signature }` to `{ token, expiresAt }` | anyone |
| `POST /v1/repos` | `{ manifest, commit }` to `SignedManifest` | the genesis `ownerKey` |
| `POST /v1/repos/{repoId}/pull` | `{ sinceManifestSeq, knownHeads }` to `{ manifests, heads, leaves }` | a member of the tip |
| `POST /v1/repos/{repoId}/push` | `{ commit }` to `{ accepted: true, heads }` | the commit's `author`, a member of the tip |
| `POST /v1/repos/{repoId}/manifest` | `{ manifest, commit? }` to `SignedManifest` | the `ownerKey` |
| `POST /v1/repos/{repoId}/leave` | `LeaveRequest` to `{}` | the leaving `memberKey` |
| `POST /v1/prepare-join` | `{ repoId, memberKey }` to `Acceptance` | `memberKey` |

`repoId` in a path is percent-decoded as a path segment. A request line that is not a valid URI (for
example a `%` not followed by two hex digits) is refused by the JDK HTTP server before the host sees
it: the status is `400`, but the body is the JDK's, not a SPEC 10.4 error object. A valid escape that
decodes to bad UTF-8 reaches the host and is `400 bad_request`. `prepareJoin` answers an acceptance
signed by the host key with `expiresAt` 15 minutes ahead, and the host records it.

Request bodies are decoded strictly: a field the schema does not list is `400` (the schema's
`additionalProperties: false`), except inside a `SignedManifest`, `Commit`, or `LeaveRequest`, whose
unknown fields are ignored, as the Rust host does.

A repository whose winning tip at this host does not list this host is **not hosted** (SPEC 8.6):
every client route and every host route answers `403 not_hosted` for it and it takes no writes, until
a state received by replication lists the host again. A `publishManifest` of a validated state that
drops this host answers `403 not_hosted`; the host still records the state (with its rotation commit
when it raises the epoch, never with another carried commit) and does not offer it to peers. A
`createRepo` genesis that does not list this host stores nothing.

## Replication (SPEC 9)

### Host routes

Signed host requests from a peer in `AVP_PEERS`; no bearer token. Bodies follow the schema's
`HeadsRequest`, `FetchRequest`, and `OfferRequest`. The body `repoId` is optional (SPEC 9.3 gives the
heads body as `{}`), the path is authoritative, and a body `repoId` that differs from the path is
`400`. The host sends `repoId` in every body.

| Route | Body and response |
|---|---|
| `POST /v1/host/repos/{repoId}/heads` | `{ repoId? }` to `{ manifestTip: { manifestSeq, manifestHash }, heads }` |
| `POST /v1/host/repos/{repoId}/fetch` | `{ repoId?, ids }` to `{ manifests, commits, leaves }` |
| `POST /v1/host/repos/{repoId}/offer` | `{ repoId?, manifests, commits, leaves }` to `{ accepted, rejected: [{ id, code }] }` |

Checks, in order:

1. `503` (no `code`) while replication is paused by the test control.
2. `401 unauthorized` if a host header is missing or malformed, the key is not in `AVP_PEERS`, the
   signature does not verify, or `|now - AVP-Host-Time|` is over 60 seconds.
3. `400 bad_request` for a malformed body, a body `repoId` that differs from the path, or more than
   4096 ids or items in one list.
4. `heads` and `fetch`: `404 not_found` if the host does not hold the repository, `403 not_hosted` if
   its winning tip does not list this host, `403 forbidden` if that tip does not list the calling
   peer (SPEC 9.2).
5. `offer`: `403 forbidden` if the host holds the repository and its tip does not list the sender.
   The items are then validated by the engine on a trial copy in dependency order, whatever order
   the sender used: states by ascending seq, each epoch-raising state with its rotation commit as
   one atomic pair, commits parents first, leave requests last. An item that cannot apply yet waits
   on the ids it misses and is tried again only when one of them settles, so the engine work is
   linear in the items, capped at three engine applications per item plus 64; a commit that cannot
   apply in the offer at all is not tried. An epoch-raising state tries each verified commit shaped
   like its rotation commit (those with accepted parents first, at most 8) until one pairs with it,
   so a decoy does not block it. The **received tip** then decides (SPEC 9.2):
   - it does not list this host: `403 not_hosted`. A first copy stores nothing; a held repository
     keeps the validated states (with their rotation commits, not the other items) and is then not
     hosted.
   - a first copy whose tip does not list the sender: `403 forbidden`, nothing stored.
   - a first copy over the repository caps (per owner key, or for the whole host): `429
     quota_exceeded`, nothing stored.
   - otherwise `200`, with each manifest hash and commit id in `accepted` or in `rejected` with the
     code a client would get. Both items of a rejected pair carry the same code. A leave request that
     fails validation is dropped.

   A peer cannot grow a repository with items the engine refuses: a commit that ends neither
   accepted, held, nor pending is not stored, nor is its header, and the answer reports what is
   stored. An offer with missing items, or for a repository the host does not hold yet, also makes
   the host catch up from the sender. A first copy whose received tip is not known yet (a gap in the
   chain) answers `200` with per-item rejections and stores nothing; the catch-up decides.

`fetch` returns, for a manifest hash (winning or verified losing), that state and every state before
it in ascending seq, with the rotation commit of each epoch-raising state among them even while held;
for a commit id, that commit if accepted or a rotation commit; and every pending leave request. Held
and pending commits are not heads and are not served.

### Request signature

Each request carries `AVP-Host-Key` (base64), `AVP-Host-Time` (epoch milliseconds, decimal digits
with an optional leading `-` and nothing else), and `AVP-Host-Signature`, base64 of Ed25519 over
`CE(tag "avp/host-req/v1", str("POST"), str(path), bytes(SHA-256(body)), i64(time))`, where `path` is
the request path as sent, without the query, and `body` the exact body bytes. The receiver verifies
over the path and the bytes it received.

This simple profile has no nonce: a captured request can be replayed to the same host within the 60
second window. A replay only repeats a read or re-offers items the receiver validates again, but it
does let an eavesdropper on the plain HTTP link read the repository's ciphertext by replaying a
`fetch`. A deployment that needs replay protection or link confidentiality should use another profile
(for example mutual TLS).

### Cadence

One worker thread per peer, so a dead or slow peer delays only its own worker:

- **On startup** each worker sweeps its peer at once.
- **After every accepted client write** (`createRepo`, `push`, `publishManifest`, `leave`) the write is
  offered to each peer whose key is in the repository's tip `hosts`, while that tip lists this host.
- **Every 5 seconds** each worker sweeps every held repository whose winning tip lists its peer:
  `heads`, then `fetch`
  for the tip state and the heads this host lacks (and always once, for the leave requests), then
  `fetch` for what the items not applied yet still miss, at most 64 rounds and 4096 ids per catch-up.
  What is not applied yet is carried into the next round with the ids it waits on and is tried again
  only when one of those arrives or becomes known. Carried and fetched items together are at most
  4096 per round (those carried longest are dropped first), and one catch-up makes at most 24704
  engine applications in all its rounds. These bound a peer that keeps a catch-up going, not the
  length of an honest history.
- **Only listed hosts** get host requests for a repository (SPEC 9.3): a peer in `AVP_PEERS` that
  is not in the repository's winning tip `hosts` gets no `heads`, `fetch`, or `offer` for it, so it
  never learns the repoId. A catch-up after an incomplete offer goes to the peer that sent the offer.

The state lock is never held across an outbound call. A held repository is updated under it; a first
copy is validated outside the lock and admitted under it, after re-checking that the repository is
still not held and the repository caps. Outbound calls time out after 10 seconds (the whole exchange,
body included) and read at most 16 MiB of response; a peer answer that is too large, malformed, or
not `200` is dropped. Peer answers are decoded tolerantly (an unknown field is ignored), while every
item in them still goes through the engine.

A newly listed host gets its first copy by replication (SPEC 8.1): the received tip must list it and
the sender, and the earlier states of the chain need not list it. The host does not apply the SPEC
8.2 SHOULD that a host store a replicated repository only after issuing an acceptance for it, as the
Rust host does not: a genesis that lists several hosts has only the owner as member, so the other
hosts could then never carry it.

### Test control

Only with `AVP_TEST_CONTROL=1`: `POST /v1/test/replication { paused: bool }` answers `{ paused }`.
While paused the host sends no host traffic and answers every host route with `503`; client routes
keep working. Unpausing starts a sweep of every peer at once.

## Errors

Every non-2xx body the host writes is `{ error, code?, detail? }` (SPEC 10.4).

| Status | `code` | When |
|---|---|---|
| `400` | `bad_request` | malformed body or path, bad base64, wrong binary length, bad signature, an id or `repoId` that does not recompute, an epoch-raising state without its rotation commit |
| `401` | `unauthorized` | missing, unknown, or expired token; a challenge nonce that is unknown, reused, expired, issued for another key, or signed wrongly; a bad host request signature |
| `403` | `forbidden` | the caller is not the key the operation requires, not a member, after the removal cutoff, an epoch mismatch, a held commit; a peer not in the repository's `hosts` |
| `403` | `not_hosted` | this host is not in the manifest's `hosts`, or the repository's winning tip here does not list it |
| `404` | `not_found` | unknown repository or route |
| `409` | `duplicate_repo` | `createRepo` for a `repoId` this host already holds |
| `409` | `too_many_heads` | the push would leave more than 16 heads; merge first |
| `409` | `manifest_conflict` | the published state is not tip + 1 or does not link to the tip |
| `413` | `too_large` | the body is over the size limit |
| `422` | `missing_parents` | an unknown parent, cited manifest state, or frontier commit; `detail` lists the ids, base64, separated by `,` |
| `429` | `quota_exceeded` | a deployment limit below was hit |
| `500` | none | an internal failure (never a caller's input) |
| `503` | none | a host route while replication is paused by the test control |

## Limits

| Limit | Value | Answer |
|---|---|---|
| Request body | 4 MiB | `413 too_large` |
| Heads per repository (client writes) | 16 | `409 too_many_heads` |
| Members in a manifest state | 500 | `429 quota_exceeded` |
| Repositories per owner key (`createRepo` and first copies by replication) | 1000 | `429 quota_exceeded` |
| Repositories on this host (`createRepo` and first copies by replication) | 10000 | `429 quota_exceeded` |
| Outstanding challenges per key | 16 | `429 quota_exceeded` with `Retry-After` |
| Live tokens per key | 32 | `429 quota_exceeded` |
| Recorded unexpired acceptances per member key | 64 | `429 quota_exceeded` |
| Outstanding challenges, live tokens, recorded acceptances in all | 10000, 100000, 10000 | the oldest entry is evicted, so one caller cannot lock others out |
| Challenge lifetime | 2 minutes | `401 unauthorized` after |
| Token lifetime | 15 minutes | `401 unauthorized` after |

Challenges and tokens are stored under the SHA-256 digest of the secret, so a lookup compares digests
and says nothing about the secret; the key a challenge was issued for is compared in constant time.

## Try it

The auth flow (SPEC 3.3): `challenge` returns a base64 nonce, the client signs the **raw nonce
bytes** (base64-decode it first) with its Ed25519 key, and `token` returns a bearer token valid only
at this host. Real request bodies (owner-signed manifests, signed commits) come from a client; the
checks in [`SmokeTest.java`](SmokeTest.java) build every one of them with the shared sources.

```sh
curl -s localhost:8787/.well-known/avp
```

---

SPDX-License-Identifier: MIT
