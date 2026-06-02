# AVP reference server (in-memory)

A tiny, runnable reference server for the [HTTP/JSON profile](../../SPEC.md), so you can point a client
at something real while you build it. One file, [`server.ts`](server.ts), Node built-ins only.

```sh
npm install
npm start          # listens on http://localhost:8787 (set PORT to change)
npm run typecheck  # optional: tsc --noEmit
```

## What it implements

The full wire contract: the keypair `challenge` / `token` auth flow and the six vault operations
(`createRepo`, `pull`, `push`, `addMember`, `removeMember`, `fetchMemberKey`). Routes:

| Method & path | Operation |
|---|---|
| `POST /api/auth/keypair/challenge` | request a nonce |
| `POST /api/auth/keypair/token` | redeem a signed nonce for a bearer token |
| `POST /v1/repos` | createRepo |
| `POST /v1/repos/{repoId}/pull` | pull |
| `POST /v1/repos/{repoId}/push` | push (optimistic concurrency) |
| `POST /v1/repos/{repoId}/add-member` | addMember |
| `POST /v1/repos/{repoId}/remove-member` | removeMember |
| `GET  /v1/repos/{repoId}/member/{memberId}` | fetchMemberKey |

Request and response bodies are the ones in [`../`](../) and [`../../schema/avp.schema.json`](../../schema/avp.schema.json).

## It is zero-knowledge

The server stores only the manifest, the encrypted envelope, the per-member wrapped keys, the public
keys, and the version and epoch counters that clients send. It never sees a data key or a plaintext alt,
and it decrypts nothing. It verifies the Ed25519 challenge signature over the raw nonce bytes exactly as
the spec requires.

## What is simplified (do not ship this)

- **In memory.** All state is lost on restart; there is no database.
- **No TLS.** Put it behind TLS in any real deployment.
- **Opaque token, not a JWT.** It mints a random bearer token and maps it to the member id in this same
  process. A real deployment mints a JWT whose subject is the member id, verifiable by the vault server
  via the identity provider's JWKS (see SPEC section 3).
- **v1 membership policy.** Any member may invite (add a member). Tighten as your deployment needs.
