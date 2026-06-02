# AVP reference server (Rust)

An in-memory reference server for the [Alt Vault Protocol](../../../SPEC.md), HTTP/JSON profile. It
implements the whole wire contract so an implementer can point a client at something real. It is a
sibling of the [TypeScript reference server](../../typescript/server/) and behaves identically.

> **Illustrative, not for production.** State lives in process memory and is lost on restart, there is
> no TLS, and the bearer token is an opaque random string mapped to a member id in this same process. A
> real deployment mints a JWT verifiable via JWKS (SPEC section 3) and serves over HTTPS. What this
> server *does* honour is the part that matters: it is **zero-knowledge**. It stores only the manifest,
> the encrypted envelope, the per-member wrapped keys, public keys, and the version/epoch counters that
> clients send, and it decrypts nothing. The only cryptography it performs is verifying the Ed25519
> challenge signature.

## Build and run

Requires a Rust toolchain (`cargo`, edition 2021, Rust 1.74+).

```sh
cargo run            # listens on http://localhost:8787
PORT=9000 cargo run  # override the port
```

```sh
cargo build --release   # optimized binary at target/release/avp-reference-server
cargo test              # run the test suite
```

## Dependencies

Minimal and version-pinned (see [`Cargo.toml`](Cargo.toml)):

| Crate | Why |
|---|---|
| `tiny_http` | a tiny blocking HTTP/1.1 server, no async runtime |
| `serde_json` | parse/emit JSON and store message shapes opaquely as `Value` |
| `ed25519-dalek` | verify the Ed25519 challenge signature (the only crypto here) |
| `base64` | decode public keys / nonces / signatures, encode nonces and tokens |
| `rand` | random nonces and opaque bearer tokens |

Message shapes are kept as `serde_json::Value` rather than rigid structs on purpose: the server stores
and echoes back exactly what the client sends (wrapped keys, ciphertext, counters) without interpreting
the encrypted parts, which keeps it faithful to the zero-knowledge guarantee.

## Endpoints

All bodies are JSON using the proto field names in `camelCase` (see
[`../../../schema/avp.schema.json`](../../../schema/avp.schema.json)). Every route except the two auth
routes requires `Authorization: Bearer <token>`.

| Method + path | Request → Response |
|---|---|
| `POST /api/auth/keypair/challenge` | `{ ed25519PublicKey }` → `{ nonce }` (single-use, ~2 min TTL) |
| `POST /api/auth/keypair/token` | `{ ed25519PublicKey, nonce, signature }` → `{ token, expiresAt }` |
| `POST /v1/repos` | `{ manifest, initialEnvelope }` → `VaultManifest` |
| `POST /v1/repos/{repoId}/pull` | `{ repoId, knownPayloadVersion }` → `{ manifest, envelope?, unchanged }` |
| `POST /v1/repos/{repoId}/push` | `{ repoId, envelope, expectedPayloadVersion, rotatedMembers? }` → `{ accepted, conflict, payloadVersion, keyEpoch }` |
| `POST /v1/repos/{repoId}/add-member` | `{ repoId, member }` → `VaultManifest` |
| `POST /v1/repos/{repoId}/remove-member` | `{ repoId, removedMemberId, rotatedEnvelope, rewrappedMembers, newKeyEpoch }` → `VaultManifest` |
| `GET /v1/repos/{repoId}/member/{memberId}` | → `MemberEntry` (URL-decode `memberId`; base64 ids contain `+ / =`) |

Status codes: `401` (missing/unknown token, or a bad/expired challenge), `403` (authenticated caller is
not a member of the repo), `404` (unknown repo or member), `409` (duplicate `repoId`), `200` otherwise.

## Try it

The [auth flow](../../../SPEC.md#3-identity-and-authentication): `challenge` returns a base64 nonce, the
client signs the **base64-decoded** nonce bytes with its Ed25519 private key, and `token` returns a
bearer token. Then create a repo and pull it back. The values below (members `alice` and `bob`, host
`vault.example`) are placeholders, exactly as in the [shared examples](../../README.md); real keys and
ciphertext come from a client.

```sh
# A repo whose sole member's ed25519PublicKey equals the token subject.
curl -s -X POST localhost:8787/v1/repos \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --data @../../create-repo-request.json
```

See [`../../create-repo-request.json`](../../create-repo-request.json),
[`../../pull-response.json`](../../pull-response.json), and
[`../../push-request.json`](../../push-request.json) for representative bodies.

## License

MIT (`SPDX-License-Identifier: MIT`).
