# Implementing AVP

A language-agnostic guide to building a conformant Alt Vault Protocol 0.5 client and host. Start here;
read [`SPEC.md`](SPEC.md) for the normative detail. Where this guide and the SPEC differ, the SPEC wins.

## 1. Overview

You are building two things:

- **A client** that holds the keys and does all the cryptography: it derives the owner keys from a BIP39
  phrase, signs manifest states (as owner) and commits (as member), encrypts the payload, wraps data keys,
  and merges concurrent heads.
- **A zero-knowledge host** that authenticates callers, validates every signed item it receives, stores
  ciphertext, wrapped keys, public keys, counters, ids, and signatures, and replicates each repository with
  the other hosts that repository lists. It never receives a phrase, a seed, a data key, a private key, or
  a plaintext alt. It verifies signatures and recomputes hashes; it decrypts nothing.

A repository is three structures (SPEC §1):

- the **manifest chain**: owner-signed states holding the members, their wrapped data keys, the key epoch,
  the refresh-token policy, and the hosts (SPEC §4.2, §6);
- the **commit graph**: member-signed commits, each carrying the full encrypted payload and naming its
  parents; concurrent writes fork it and leave several **heads** (SPEC §4.3, §7);
- the **payload**: accounts whose every field carries its own stamp, so heads merge per field without
  losing a write (SPEC §5).

The **HTTP/JSON profile** (one `POST` per operation, proto field names in `camelCase`,
`Authorization: Bearer <token>`) is the most portable starting point. The gRPC profile in
[`proto/avp.proto`](proto/avp.proto) carries the same messages; pick one.

Over gRPC (SPEC §10.3) every client operation is an RPC on `avp.Vault`, discovery included
(`GetHostInfo`), and the token rides the `authorization` metadata as `Bearer <token>`. There is no path:
the repository is the one the body names (`PullRequest.repoId` exists for that and is gRPC only). A refused
call's status message is the §10.4 `code`, with `detail` in the `avp-error-detail` trailer. Leave no
required sub-message unset: a request without one is `bad_request`. A token you mint over one profile works
over the other at the same host, and an item you write over one pulls over the other with the same values.

Conformance means three things (SPEC §14, [§6 below](#6-conformance-checklist)):

1. Reproduce the vectors in [`vectors/`](vectors/) byte for byte, and reject every case in
   [`vectors/negative.json`](vectors/negative.json).
2. For a host, pass the black-box harness in [`harness/`](harness/), single-host and multi-host.
3. Interoperate: your client against another implementation's host, and your host replicating with
   another implementation's host.

## 2. Identities and authentication (SPEC §2, §3)

### Strict Ed25519

Every Ed25519 signature AVP verifies (owner, author, acceptance, leave, host request, challenge) is
verified **strictly** (SPEC §2). Before the curve check, reject a public key `A` or signature half `R` that
is a small-order point or a non-canonical encoding, and an `S` at or above the group order `L`. Then verify
with the cofactorless equation `[S]B = R + [k]A`, comparing `R` by its encoding. libsodium's
`crypto_sign_verify_detached` and dalek's `verify_strict` do this; the JDK and OpenSSL verifiers do the
equation but need the pre-checks added. The last six `ed25519-verify` cases of `negative.json` are the
forgeries a non-strict verifier accepts.

### Owner phrase and owner keys (SPEC §3.1)

The owner is the member who creates the repository. Its authority is a 24-word BIP39 phrase:

1. 32 bytes of entropy from a secure RNG; checksum = first 8 bits of `SHA-256(entropy)`; 264 bits split
   into 24 groups of 11 bits, each mapped into [`vectors/bip39-english.txt`](vectors/bip39-english.txt).
2. `seed = PBKDF2-HMAC-SHA512(NFKD(mnemonic), "mnemonic", 2048, 64)` (the passphrase is empty).
3. `ed25519Seed = HKDF-SHA256(seed, empty salt, "avp/owner/ed25519/v1", 32)` and
   `x25519Private = HKDF-SHA256(seed, empty salt, "avp/owner/x25519/v1", 32)`. The Ed25519 public key is
   the **`ownerKey`**. An empty HKDF salt means 32 zero bytes (RFC 5869).

Reject a phrase that is not 24 words, uses a word not in the list, or fails the checksum. Show the phrase
once and never send it, its entropy, or the seed to a host. Vectors:
[`vectors/bip39-owner.json`](vectors/bip39-owner.json).

### Members (SPEC §3.2)

A member is a per-device Ed25519 + X25519 keypair. Its **member id** is the standard base64 (with padding)
of the raw 32-byte Ed25519 public key. The owner is a member too, with the two owner keys. The fingerprint
a client shows is `hex(SHA-256(ed25519 || x25519)[0..8])` as `xxxx-xxxx-xxxx-xxxx`. A removed key never
becomes a member again.

### Host keys and host-issued tokens (SPEC §3.3)

Every host has an Ed25519 **host key**, and every host match (`hosts`, `homeHostKey`, acceptances,
host-to-host requests) compares host keys, never locators. Discovery (`GET /.well-known/avp`) returns
`{ version: "0.5", profiles, hostKey }`; check the key against the one you expect (SPEC §11.7).

The host is the token issuer; there is no external identity service:

```
POST /api/auth/keypair/challenge
  body: { "ed25519PublicKey": "<base64>" }
  response: { "nonce": "<base64>" }

POST /api/auth/keypair/token
  body: { "ed25519PublicKey": "<base64>", "nonce": "<base64>", "signature": "<base64>" }
  response: { "token": "<bearer>", "expiresAt": <ms> }
```

Sign the **challenge transcript**, never the nonce alone:

```
challengeMessage = CE(tag "avp/challenge/v1", bytes(hostKey), bytes(ed25519PublicKey), bytes(nonce))
signature        = Ed25519-Sign(ed25519PublicKey, challengeMessage)
```

`hostKey` is the 32-byte key of the host you are authenticating to (the key you match it by, checked
against discovery), `ed25519PublicKey` your 32-byte key, and `nonce` the **decoded nonce bytes**, not the
base64 text. The host builds the same transcript with its own host key and verifies it. A signature over
the raw nonce (the old construction) or over a transcript built with another host key is
`401 unauthorized`, as is a reused, expired, foreign, or never-issued nonce. The tag is what stops a
malicious host from choosing a "nonce" that is really another construction's message, such as a commit
signature message (SPEC §3.3); every signed message has its own tag (the table in SPEC §4.1). Tokens are **host-local**: cache them keyed by host key and
never present one host's token to another.

## 3. Constructions (SPEC §4)

### 3a. Canonical encoding (CE, SPEC §4.1)

Every signed or hashed structure is a CE byte string; there is no JSON canonicalization anywhere:

| Item | Bytes |
|---|---|
| `tag(label)` | UTF-8 of `label`, then `0x00` |
| `bytes(b)` | `u32BE(len(b)) \|\| b` |
| `str(s)` | `bytes(UTF8(s))` |
| `i64(n)` | 8-byte big-endian two's complement |
| `bool(b)` | `0x00` or `0x01` |
| `count(n)` | `u32BE(n)` |

Every key, hash, nonce, IV, signature, and ciphertext goes through `bytes(...)` as **raw decoded bytes**,
never as base64 text. Lists are sorted by the stated key as unsigned bytes before encoding.

### 3b. Manifest state (SPEC §4.2)

`S = CE(tag "avp/manifest/v1", ...)` over `repoId`, `manifestSeq`, `prevManifestHash`, `ownerKey`,
`genesisNonce`, `schemeId`, `keyEpoch`, `shareRefreshTokens`, then the hosts sorted by `hostKey`, the
members sorted by `ed25519PublicKey`, and the cumulative removals sorted by `memberKey` (each with its
sorted `frontier`). The exact layout is in SPEC §4.2.

```
ownerSignature = Ed25519-Sign(ownerKey, S)
manifestHash   = SHA-256(S || ownerSignature)      raw 64-byte signature, no length prefix
repoId         = base64url-nopad(SHA-256(CE(tag "avp/repo-id/v1", bytes(ownerKey), bytes(genesisNonce)))[0..16])
```

`manifestHash` is never sent; every party recomputes it. Vectors:
[`vectors/manifest.json`](vectors/manifest.json) (its wire lists are deliberately unsorted).

### 3c. Commit and AAD v2 (SPEC §4.3)

```
H               = CE(tag "avp/commit/v1", str(repoId), count + sorted bytes(parentId), i64(manifestSeq),
                     bytes(manifestHash), i64(keyEpoch), bytes(author), bytes(iv), bytes(ciphertext))
commitId        = SHA-256(H)
authorSignature = Ed25519-Sign(author, CE(tag "avp/commit-sig/v1", bytes(commitId)))
AAD             = CE(tag "avp/aad/v2", str(repoId), i64(keyEpoch), bytes(author), count + sorted bytes(parentId))
```

The payload is AES-256-GCM under the data key of `keyEpoch`, a fresh 12-byte IV, the 16-byte tag
appended. Build the AAD from the header fields you received. Vectors:
[`vectors/commit.json`](vectors/commit.json).

### 3d. Wrap scheme `X25519-HKDF-SHA256-AESGCM-v1` (SPEC §4.4)

To wrap a secret to `recipientPub` under a label `info`:

1. Fresh ephemeral X25519 pair; `sharedSecret = X25519(ephemeralPriv, recipientPub)`, raw and unhashed.
2. `KEK = HKDF-SHA256(sharedSecret, salt = ephemeralPubRaw, info, 32)`.
3. `ciphertext = AES-256-GCM(KEK, fresh 12-byte iv, aad = UTF8(info), secret)`, tag appended.
4. `WrappedKey = { schemeId, ephemeralPublicKey, iv, ciphertext }`.

Data keys use `info = "avp/rdk-wrap/v1"`; device linking uses `"avp/owner-link/v1"`. A wrap made under one
label MUST fail to unwrap under the other. Vectors: [`vectors/x25519.json`](vectors/x25519.json),
[`vectors/hkdf.json`](vectors/hkdf.json), [`vectors/key-wrap.json`](vectors/key-wrap.json).

### Encoding rule

Binary values in JSON are **standard base64 with padding** (RFC 4648 §4). `repoId` and the outer encoding
of the out-of-band tokens (SPEC §11) are **base64url without padding** (RFC 4648 §5). A `repoId` in a URL
path is percent-encoded as a path segment, and a host routes on the escaped path.

## 4. Payload v2 and merge (SPEC §5)

```
{ "v": 2, "accounts": { "<uuid>": { "deleted"?: Stamp, "fields": { "<name>": Field }, "bans": { "<serverId>": Field } } } }
Field = { "value": <json>, "at": <ms>, "n": <counter>, "by": "<member id>" }
```

- Stamps order by `(at, n, by)`, `by` by its UTF-8 bytes; the greatest wins.
- Keep a hybrid logical clock: `tick(now)` gives `(now, 0)` if `now > at`, else `(at, n + 1)`;
  `observe(stamp)` raises the clock to the stamp. Observe every stamp of every payload you merge before
  your next tick.
- Merge: union of accounts; per field and per ban server id, the greatest stamp; `deleted` is the greatest
  marker. An account is deleted iff its marker beats every field and ban stamp, so a later edit revives it.
- Policy (SPEC §5.1): unless the latest verified state has `shareRefreshTokens: true`, strip `refreshToken`
  and `expiresAt` **with their stamps** from every payload you write, decrypt, or merge.

Vectors: [`vectors/merge.json`](vectors/merge.json) (every input order, idempotence, associativity, the
HLC, and stripping after the policy is turned off).

## 5. Flows and the wire contract

### Routes (HTTP/JSON profile, SPEC §10.2)

All bodies are JSON with proto field names in `camelCase`. Every route except discovery and the two auth
routes needs `Authorization: Bearer <token>`; the `/v1/host/` routes are host-signed instead (§5j below).
The machine-readable surface, with every status code, is [`openapi.yaml`](openapi.yaml).

| Route | Body -> Response |
|---|---|
| `POST /api/auth/keypair/challenge` | `{ ed25519PublicKey }` -> `{ nonce }` |
| `POST /api/auth/keypair/token` | `{ ed25519PublicKey, nonce, signature }` -> `{ token, expiresAt }` |
| `POST /v1/repos` | `{ manifest, commit }` -> `SignedManifest` |
| `POST /v1/repos/{repoId}/pull` | `{ sinceManifestSeq, knownHeads }` -> `{ manifests, heads, leaves }` |
| `POST /v1/repos/{repoId}/push` | `{ commit }` -> `{ accepted: true, heads }` |
| `POST /v1/repos/{repoId}/manifest` | `{ manifest, commit? }` -> `SignedManifest` |
| `POST /v1/repos/{repoId}/leave` | `LeaveRequest` -> `{}` |
| `POST /v1/prepare-join` | `{ repoId, memberKey }` -> `Acceptance` |
| `POST /v1/host/repos/{repoId}/heads` | host-signed `{}` -> `{ manifestTip, heads }` |
| `POST /v1/host/repos/{repoId}/fetch` | host-signed `{ ids }` -> `{ manifests, commits, leaves }` |
| `POST /v1/host/repos/{repoId}/offer` | host-signed `{ manifests, commits, leaves }` -> `{ accepted, rejected }` |
| `GET /.well-known/avp` | -> `{ version, profiles, hostKey }` |

### 5a. Create (SPEC §6.2, §8.2)

The owner client derives the owner keys, generates a 16-byte genesis nonce and the epoch 0 data key, wraps
the data key to its own X25519 key, and signs the genesis state: seq 1, empty `prevManifestHash`,
`keyEpoch` 0, one member (the owner, with `homeHostKey` = its host), no removals, `hosts` listing its home
host. It seals the first commit (no parents, citing seq 1 and the genesis hash, authored by `ownerKey`) and
calls `createRepo`. The host recomputes `repoId`, runs SPEC §6 and §7, and stores both or neither; a
repeat is `409 duplicate_repo`.

### 5b. Pull, verify, merge, push (SPEC §6.4, §7.5, §10.1)

1. `pull { sinceManifestSeq, knownHeads }` returns the states after your pinned seq, the heads you do not
   know, and the pending leave requests. There is no "unchanged" and no "conflict" outcome.
2. Verify every state (SPEC §6.1): structure, owner signature, genesis or chain link, content rules. Pin
   the highest verified `(manifestSeq, manifestHash)`. If the first returned state does not link to your
   pin, pull again from 0 and apply the tie rule (§5i). Never accept a chain without your pin unless it
   wins at a fork at or below it. An empty answer does not prove your pin is current: a pin on a state
   that lost the tie rule at its own seq has nothing above it. So on `409 manifest_conflict`, or a `403`
   that a stale pin may cause (a push citing a losing state), pull again from 0, verify that chain like
   any pull, adopt it only if it wins at a fork at or below your pin, rebuild on the new tip, and retry
   once (SPEC §6.3, §6.4). One re-pull and one retry per operation, never a loop; a `403` that leaves
   your pin unchanged is terminal.
3. Verify every head (SPEC §7.5): id and signature, the removal cutoff, and membership at the commit's
   epoch. Discard one that fails.
4. Decrypt each readable head (AAD v2 from its header, the data key of its epoch), observe its stamps,
   and merge. A head you cannot read (no key for its epoch, bad tag, `v` not 2) is left alone: do not fail
   the pull and do not name it as a parent.
5. If you merged more than one head, push the merge commit, whose `parents` are exactly the heads you
   merged.

To write, tick the clock, set fields with the new stamp, and push a commit citing your tip state and
epoch with your current heads as parents. A push on stale heads is accepted as a fork; the next pull shows
you the heads to merge. `409 too_many_heads` (RECOMMENDED bound 16, counted as the heads the push would
leave) means merge first; a merge that reduces the heads is always accepted at the bound.

### 5c. Commit acceptance on the host (SPEC §7)

In order: decode and recompute the id and author signature (`400`); on client routes the caller is a
member of the tip and the author (`403`); the cited `(manifestSeq, manifestHash)` resolves to a verified
state (`422 missing_parents` naming the hash if unknown); the author is a member of it and `keyEpoch`
matches (`403`); the removal cutoff (`403`); every parent known (`422 missing_parents` with the ids in
`detail`). A commit whose parent was rejected, or dropped by a removal cutoff, is `403 forbidden`. A
commit the host already holds is accepted again with no change.

### 5d. Invite with prepareJoin (SPEC §8.1, §8.2, §11.2, §11.3)

1. The owner sends the joiner a `RepoLocator { v, repoId, hostKey, hostLocator, ownerFingerprint }`.
2. The joiner calls `prepareJoin { repoId, memberKey }` on its own home host and receives a host-signed
   `Acceptance { repoId, memberKey, hostKey, expiresAt, signature }`. A host that will not carry the
   repository answers with an error instead.
3. The joiner sends the owner an `InviteToken { v, ed25519PublicKey, x25519PublicKey, homeHostKey,
   homeHostLocator, acceptance }`.
4. The owner client verifies the acceptance (signature under its `hostKey` over
   `CE(tag "avp/accept/v1", ...)`, same `repoId`, `memberKey` = the token's key, `hostKey` = the token's
   `homeHostKey`, not expired), wraps the current data key to **the token's** X25519 key (never a key a
   host serves), and publishes the next state adding the member and, if needed, its home host.
5. The newly listed host receives its first copy by replication; the joiner pulls from it and checks the
   genesis `ownerKey` against `ownerFingerprint`.

Tokens are base64url-nopad over compact JSON with `"v": 2`; decoders accept any field order. Vectors:
[`vectors/federation.json`](vectors/federation.json).

### 5e. Remove with a cutoff (SPEC §7.3, §8.3)

In one `publishManifest { manifest, commit }`:

1. pull the tip and the heads, and merge every head you can read;
2. generate the data key for `keyEpoch + 1` and wrap it to every remaining member;
3. build the next state without the member, with a new removal `{ memberKey, removedAtSeq, frontier }`
   and `keyEpoch + 1`; `frontier` is every head merged into the rotation commit plus every verified commit
   by the removed member that is not an ancestor of one of them;
4. build the **rotation commit**: the merged payload under the new epoch, parents = the merged heads,
   citing the new state, authored by `ownerKey`.

A host adopts an epoch-raising state only together with its rotation commit, atomically, on every path
(`400 bad_request` if it arrives without one). After the removal, a commit by the removed member is
accepted only if its id is in the frontier or an ancestor of one; anything else is `403 forbidden`,
whatever state it cites, and the host drops already-accepted commits that fail the cutoff together with
their descendants.

### 5f. Leave (SPEC §8.4, §11.4)

A member signs `LeaveRequest { repoId, memberKey, at, signature }` over
`CE(tag "avp/leave/v1", str(repoId), bytes(memberKey), i64(at))` and sends it with `leave`. The host keeps
the latest per member, serves it in `pull`, replicates it, and drops it once a state removes the member.
The owner client SHOULD process pending leaves by removal (§5e) the next time it is online.

### 5g. Policy and host-set changes (SPEC §8.5, §8.6)

Each is a new owner-signed state with no commit. Drop a host only when no member has it as
`homeHostKey`, and publish that state through a host that stays listed: the dropped host answers
`403 not_hosted`, keeps the state, and stops serving the repository while its winning tip does not list
it.

### 5h. Owner device linking (SPEC §11.6)

The new device shows `LinkRequest { v, ephemeralPublicKey }` and a 6-digit confirmation code (the first 4
bytes of `SHA-256(CE(tag "avp/link-code/v1", bytes(ephemeralPublicKey)))` as `u32BE`, modulo 1 000 000,
zero-padded). The existing device shows the code it computes, requires the owner to confirm the match,
and returns `LinkGrant { v, wrap }`: the 32-byte mnemonic **entropy** wrapped to the ephemeral key under
`"avp/owner-link/v1"`. The new device unwraps it and derives the phrase and keys.

### 5i. Diverged owner states (SPEC §6.5)

Two valid states at the same seq mean two owner devices published offline. The state with the
bytewise-lower `manifestHash` wins with every state after it. Hosts keep the losing states (verified) so
they can resolve commits that cite them. A commit citing a losing state is re-checked against the winning
state at that seq: rejected if it fails the cutoff, accepted if the author is a member there at the same
epoch, rejected if the winning tip moved past its epoch or removed its author outside the frontier,
otherwise **held** (stored, not a head, not served) until a later winning state decides.

### 5j. Replication between hosts (SPEC §9)

Hosts listed in a repository replicate it with `heads`, `fetch`, and `offer`. A host validates every
received item by the same rules as a client write (without the head bound or the caller check); §6.1
rule 6 (`not_hosted`) applies to the **received tip** of an offer, so a newly listed host can take the
earlier states that do not list it. A first copy is all or nothing. Each epoch-raising state travels with
its rotation commit.

The reference hosts use signed HTTP/JSON (SPEC §9.3): each request carries `AVP-Host-Key`,
`AVP-Host-Time`, and `AVP-Host-Signature` = Ed25519 over
`CE(tag "avp/host-req/v1", str(method), str(path), bytes(SHA-256(body)), i64(time))`; the receiver rejects
an unknown key, a bad signature, or more than 60 s of skew with `401`. A host on this profile MUST send
host requests for a repository only to the peers its winning tip lists (or, for a first copy, to the peer
that offered it). It offers every accepted write to the listed peers and sweeps them every 5 s (`heads`,
then `fetch`). The proto's `Replication` service carries the same messages for a gRPC profile.

Reference host environment: `PORT`, `AVP_BIND` (listen address, default `0.0.0.0`; use `127.0.0.1` for
local runs), `AVP_HOST_SEED` (hex, 32 bytes; random if unset), `AVP_PEERS`
(`<base64 hostKey>@<http base url>,...`), and `AVP_TEST_CONTROL=1` (enables
`POST /v1/test/replication { paused }`; never in production).

### Errors (SPEC §10.4)

A non-`2xx` response body is an error object `{ "error": "<message>", "code": "<machine code>",
"detail": "<optional>" }`. `error` is for humans (do not parse it); `code` is an optional stable token you
may switch on, falling back to the status when absent.

One exception: a request whose target cannot be parsed as a path (for example `/v1/repos/%zz/pull`) MAY
be answered with a bare `400` without the error object, because an HTTP server can refuse such a request
line before any route runs. Clients and harnesses check only the status there.

| Status | `code` | Meaning |
|---|---|---|
| `400` | `bad_request` | Malformed, bad signature, an id or `repoId` that does not recompute, an epoch-raising state without its rotation commit |
| `401` | `unauthorized` | Missing or invalid token, bad challenge nonce, bad host request signature |
| `403` | `forbidden` | Not a member, after the removal cutoff, epoch mismatch, held commit, wrong caller, or `policy_denied` |
| `403` | `not_hosted` | This host is not in the manifest's `hosts` |
| `404` | `not_found` | The host does not hold the repository |
| `409` | `duplicate_repo` | `createRepo` for an existing `repoId` |
| `409` | `too_many_heads` | The push would leave more heads than the bound; merge first |
| `409` | `manifest_conflict` | Not tip + 1, wrong previous hash, or the state loses the tie rule; pull from seq 0, rebuild, retry once |
| `413` | `too_large` | Body over a host limit (SPEC §12.1) |
| `422` | `missing_parents` | Unknown parent, cited state, or frontier commit; `detail` lists the ids; retry later |
| `429` | `quota_exceeded` | A deployment limit; honor `Retry-After` (SPEC §12.2) |

Every error except `422 missing_parents` is terminal for that request: do not retry it unchanged.
Retries and idempotency are in SPEC §12.3 (a re-push of a commit the host already accepted changes
nothing; a repeat `createRepo` is `409 duplicate_repo`, a repeat `publishManifest` is
`409 manifest_conflict`, after which the client pulls and checks).

### Zero-knowledge and passthrough

A host stores and returns each signed manifest and commit with every field intact: dropping or rewriting
a field (including `shareRefreshTokens`) breaks the owner or author signature and every client rejects
it. A host never decrypts and never logs a request body.

## 6. Conformance checklist

This mirrors SPEC §14.

1. **RFC-anchored primitives.** HKDF-SHA256 (`hkdf.json`, RFC 5869), X25519 (`x25519.json`, RFC 7748),
   and Ed25519 sign and verify (`ed25519.json`, RFC 8032; it anchors every signature).
2. **Wrap scheme.** Wrap and unwrap of a data key (`key-wrap.json`).
3. **Owner identity.** Entropy to mnemonic, mnemonic to seed, seed to the owner keys
   (`bip39-owner.json`, over `bip39-english.txt`).
4. **Manifest.** CE bytes, owner signature, `manifestHash`, and the seq 1 `repoId` (`manifest.json`),
   independent of list input order.
5. **Commit.** Header bytes, `commitId`, author signature, AAD v2, and ciphertext (`commit.json`),
   independent of parent order.
6. **Merge.** Every permutation, idempotence, the HLC, deletion and revival, per-server bans, and
   stripping after the policy is off (`merge.json`).
7. **Acceptance rules.** Replay every scenario of `acceptance.json` through your host's rules: each step's
   verdict and the final heads, held commits, tip, and leaves.
8. **Tokens and addresses.** Every token, the acceptance and leave signatures, link confirmation codes,
   fingerprints, `avp://` locators, and the challenge transcript and its signature (`federation.json`).
9. **Negative cases.** Reject every case of `negative.json`, including the strict Ed25519 rejects and the
   cross-construction challenge cases, and accept each case's `base`. Reproducing the positive vectors is necessary but not sufficient.
10. **Black-box your host.** `bun harness/conformance.ts --server http://127.0.0.1:PORT` drives the
    client wire contract (auth failure modes, `createRepo`, the pulled chain, forks and merges, the head
    bound, `manifest_conflict`, the removal cutoff, leave, `prepareJoin`, not hosted, zero-knowledge).
    `bun harness/multihost.ts --a URL --b URL [--c URL]` drives replication between hosts started with
    `AVP_TEST_CONTROL=1`; [`harness/run-hosts.sh`](harness/run-hosts.sh) builds and starts the reference
    hosts for it. See [`harness/README.md`](harness/README.md).
11. **Interop.** Run your client against another implementation's host and replicate your host with
    another implementation's host. [`.github/workflows/examples-interop.yml`](.github/workflows/examples-interop.yml)
    and the `multihost` job of [`conformance.yml`](.github/workflows/conformance.yml) do this for the
    reference implementations.

`bun vectors/generate.ts --check` re-derives every committed vector from its documented seeds; see
[`vectors/README.md`](vectors/README.md).

## 7. Reference implementations

Rust and Java are the 0.5 references. Each language has one shared library that both its client and its
host use, and each is verified against every vector and the harness. The Go, Python, TypeScript, and gRPC
examples stopped at 0.4; see the `v0.4` tag.

| Language | Shared library | Host | Client |
|---|---|---|---|
| Rust | [`examples/rust/avp/`](examples/rust/avp/) | [`examples/rust/server/`](examples/rust/server/) | [`examples/rust/client/`](examples/rust/client/) |
| Java | [`examples/java/avp/`](examples/java/avp/) | [`examples/java/server/`](examples/java/server/) | [`examples/java/client/`](examples/java/client/) |

Where to look when you are stuck on a subtlety:

- CE writer: Rust `encoding.rs` (`Ce`), Java `AvpEncoding.java`.
- Owner phrase and keys: `owner.rs`, `AvpOwner.java`. Manifest and `repoId`: `manifest.rs`,
  `AvpManifest.java`. Commit and AAD v2: `commit.rs`, `AvpCommit.java`. Wrap and strict Ed25519:
  `crypto.rs`, `AvpCrypto.java`. Tokens: `tokens.rs`, `AvpTokens.java`. Payload, merge, HLC:
  `payload.rs`, `AvpPayload.java`.
- Host rules (SPEC §6, §7, §8.3, §8.4): `rules.rs` (`RepoView`) and `AvpRules.java`; both replay
  `acceptance.json` unchanged.

The Node conformance runner in [`examples/conformance/`](examples/conformance/) independently checks every
vector with Node's `crypto` and is a useful second reference for the byte-level expectations.
