# AVP reference server, Go (in-memory)

An in-memory reference server for the [Alt Vault Protocol](../../../SPEC.md),
HTTP/JSON profile. It implements the whole wire contract so an implementer can point
a client at something real. It is a sibling of the
[Rust reference server](../../rust/server/) and behaves identically.

> **Illustrative, not for production.** State lives in process memory and is lost on
> restart, there is no TLS, and the bearer token is an opaque random string mapped to
> a member id in this same process. A real deployment mints a JWT verifiable via JWKS
> (SPEC section 3) and serves over HTTPS. What this server *does* honour is the part
> that matters: it is **zero-knowledge**. It stores only the manifest, the encrypted
> envelope, the per-member wrapped keys, public keys, and the version/epoch counters
> that clients send, and it decrypts nothing. The only cryptography it performs is
> verifying the Ed25519 challenge signature.

## Build and run

Requires Go 1.22+. No dependencies (standard library only).

```sh
go run .             # listens on http://localhost:8787
PORT=9000 go run .   # override the port
```

```sh
go build             # build the ./server binary
go test ./...        # run the smoke test
```

## Endpoints

All bodies are JSON using the proto field names in `camelCase` (see
[`../../../schema/avp.schema.json`](../../../schema/avp.schema.json)). Every route
except the two auth routes requires `Authorization: Bearer <token>`.

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

Status codes: `401` (missing/unknown token, or a bad/expired challenge), `403`
(authenticated caller is not a member of the repo), `404` (unknown repo or member),
`409` (duplicate `repoId`), `200` otherwise.

## Notes for implementers

Message shapes are typed structs ([`../avp/wire.go`](../avp/wire.go)), but the
cryptographic fields (wrapped keys, IVs, ciphertext) are plain base64 strings the
server stores and echoes back verbatim without interpreting, which keeps it faithful
to the zero-knowledge guarantee. Routing uses the request's *escaped* path so a
percent-encoded slash inside a base64 member id is not mistaken for a path separator.

## License

MIT (`SPDX-License-Identifier: MIT`).
