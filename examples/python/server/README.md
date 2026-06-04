# AVP reference server, Python (in-memory)

A tiny, runnable reference server for the [HTTP/JSON profile](../../../SPEC.md), so you can point a
client at something real while you build it. The standard library plus one dependency
([`cryptography`](https://pypi.org/project/cryptography/), only for Ed25519 verification); the
source is one file, [`server.py`](server.py).

```sh
python -m venv .venv && . .venv/bin/activate   # optional; Windows: .venv\Scripts\activate
pip install -r requirements.txt
python server.py                                # listens on http://localhost:8787 (set PORT to change)
python -m unittest test_server.py               # integration suite (real Ed25519 auth, full lifecycle)
python -m py_compile server.py                  # syntax check
```

Requires Python 3.9+.

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

Request and response bodies are the ones in [`../../`](../../) and
[`../../../schema/avp.schema.json`](../../../schema/avp.schema.json). The behaviour is matched to
the [TypeScript reference server](../../typescript/server/) operation for operation: same routes,
status codes (`401` unauthenticated, `403` non-member, `404` unknown repo/member, `409` duplicate
repo), and in-memory model.

## It is zero-knowledge

The server stores only the manifest, the encrypted envelope, the per-member wrapped keys, the public
keys, and the version and epoch counters that clients send. It never sees a data key or a plaintext
alt, and it decrypts nothing. The **only** cryptography it performs is verifying the Ed25519
challenge signature over the raw nonce bytes exactly as the spec requires (the test suite drives
this with a real keypair).

## What is simplified (do not ship this)

- **In memory.** All state is lost on restart; there is no database. State lives in plain dicts
  guarded by a single lock (the server is threaded).
- **No TLS.** Put it behind TLS in any real deployment.
- **Opaque token, not a JWT.** It mints a random bearer token and maps it to the member id in this
  same process. A real deployment mints a JWT whose subject is the member id, verifiable by the
  vault server via the identity provider's JWKS (see SPEC section 3).
- **v1 membership policy.** Any member may invite (add a member). Tighten as your deployment needs.

## Quick smoke test

With the server running, the auth flow needs a real Ed25519 signature, so the simplest end-to-end
check is the test suite (`python -m unittest test_server.py`). To poke the surface by hand, an
unauthenticated vault call returns `401`:

```sh
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8787/v1/repos   # -> 401
```
