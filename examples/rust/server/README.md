# AVP reference host (Rust)

An in-memory reference host for [AVP 0.5](../../../SPEC.md), HTTP/JSON profile. It serves the
client-facing API of SPEC section 10: host-issued authentication, `createRepo`, `pull`, `push`,
`publishManifest`, `leave`, `prepareJoin`, and discovery. Host-to-host replication (SPEC section 9)
is not part of this crate yet.

The host is a thin HTTP/JSON layer over the shared [`avp`](../avp/) crate. The crate's
`rules::RepoView` runs every manifest chain and commit rule (SPEC sections 6 and 7); the host only
authenticates the caller, decodes the body, checks the caller identity each operation requires, maps
the engine's reject codes to the status table of SPEC 10.4, and serializes the answer.

> **Illustrative, not for production.** State lives in process memory and is lost on restart, and
> there is no TLS. What it does honour is the part that matters: it is **zero-knowledge**. It stores
> only owner-signed manifest states (public keys, wrapped keys, counters, signatures), commits
> (ciphertext, ids, signatures), and signed leave requests. It never holds a data key, decrypts
> nothing, and never logs a request body.

## Build and run

Requires a Rust toolchain with `cargo`, edition 2024, Rust 1.85 or later.

```sh
cargo run                                   # listens on http://0.0.0.0:8787
PORT=9000 cargo run                         # another port
AVP_HOST_SEED=<64 hex digits> cargo run     # a fixed host key
```

```sh
cargo build --release   # optimized binary at target/release/avp-reference-server
cargo test              # the API test suite (tests/api.rs)
```

| Variable | Meaning |
|---|---|
| `PORT` | Listen port on `0.0.0.0`. Default `8787`. |
| `AVP_HOST_SEED` | The 32-byte Ed25519 seed of the host key, as 64 hex digits. Without it the host key is random for each start. |

The binary prints the bound address and the host key (base64) at start. A client checks that key
against `GET /.well-known/avp` and against the manifest's `hosts` (SPEC 3.3, 11.7).

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

`repoId` in a path is percent-decoded as a path segment. `prepareJoin` answers an acceptance signed
by the host key with `expiresAt` 15 minutes ahead, and the host records it.

## Errors

Every non-2xx body is `{ error, code?, detail? }` (SPEC 10.4).

| Status | `code` | When |
|---|---|---|
| `400` | `bad_request` | malformed body or path, bad base64, wrong binary length, bad signature, an id or `repoId` that does not recompute, an epoch-raising state without its rotation commit |
| `401` | `unauthorized` | missing, unknown, or expired token; a challenge nonce that is unknown, reused, expired, issued for another key, or signed wrongly |
| `403` | `forbidden` | the caller is not the key the operation requires, not a member, after the removal cutoff, an epoch mismatch, a held commit |
| `403` | `not_hosted` | this host is not in the manifest's `hosts` |
| `404` | `not_found` | unknown repository or route |
| `409` | `duplicate_repo` | `createRepo` for a `repoId` this host already holds |
| `409` | `too_many_heads` | the push would leave more than 16 heads; merge first |
| `409` | `manifest_conflict` | the published state is not tip + 1 or does not link to the tip |
| `413` | `too_large` | the body is over the size limit |
| `422` | `missing_parents` | an unknown parent, cited manifest state, or frontier commit; `detail` lists the ids, base64, separated by `,` |
| `429` | `quota_exceeded` | a deployment limit below was hit |

## Limits

| Limit | Value | Answer |
|---|---|---|
| Request body | 4 MiB | `413 too_large` |
| Heads per repository (client writes) | 16 | `409 too_many_heads` |
| Members in a manifest state | 500 | `429 quota_exceeded` |
| Repositories per owner key | 1000 | `429 quota_exceeded` |
| Outstanding challenges | 10000 | `429 quota_exceeded` with `Retry-After` |
| Live tokens | 100000 | `429 quota_exceeded` |
| Recorded unexpired acceptances | 10000 | `429 quota_exceeded` |
| Challenge lifetime | 2 minutes | `401 unauthorized` after |
| Token lifetime | 15 minutes | `401 unauthorized` after |

## Try it

The auth flow (SPEC 3.3): `challenge` returns a base64 nonce, the client signs the **raw nonce
bytes** (base64-decode it first) with its Ed25519 key, and `token` returns a bearer token valid only
at this host. Real request bodies (owner-signed manifests, signed commits) come from a client such as
the [Rust reference client](../client/); the integration tests in [`tests/api.rs`](tests/api.rs)
build every one of them with the `avp` crate.

```sh
curl -s localhost:8787/.well-known/avp
```

## Dependencies

Pinned exactly in [`Cargo.toml`](Cargo.toml):

| Crate | Why |
|---|---|
| `avp` (path `../avp`) | wire types, crypto, and the rules engine |
| `tiny_http` | a small blocking HTTP/1.1 server, no async runtime |
| `serde`, `serde_json` | request and response bodies |
| `ed25519-dalek` | the host key type |

## License

MIT (`SPDX-License-Identifier: MIT`).
