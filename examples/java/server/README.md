# AVP reference server, Java (in-memory)

A tiny, runnable reference server for the [HTTP/JSON profile](../../../SPEC.md), so you can point a
client at something real while you build it. JDK built-ins only, no dependencies, no build tool. The
source is one file, [`Server.java`](Server.java), runnable straight from source.

```sh
java Server.java          # listens on http://localhost:8787 (set PORT to change)
java SmokeTest.java       # integration suite (real Ed25519 auth, full lifecycle)
```

`java Server.java` uses the [single-file source-code launcher](https://openjdk.org/jeps/330)
(`java <file>.java`), available on **JDK 17+**. No `javac`, classpath, or jar is needed. To compile
explicitly instead:

```sh
javac Server.java
java Server
```

The smoke test depends on `Server.java`; the launcher compiles both together when you run
`java SmokeTest.java` from this directory (or `javac Server.java SmokeTest.java && java SmokeTest`).

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
[`../../../schema/avp.schema.json`](../../../schema/avp.schema.json). `{memberId}` is a base64 Ed25519
key, so it contains `+` `/` `=` and MUST be URL-encoded by the client; the server decodes the raw path
segment itself (`decodeURIComponent` semantics, not form decoding).

## It is zero-knowledge

The server stores only the manifest, the encrypted envelope, the per-member wrapped keys, the public
keys, and the version and epoch counters that clients send. It never sees a data key or a plaintext alt,
and it decrypts nothing. The only cryptography it performs is verifying the Ed25519 challenge signature
over the raw nonce bytes (the base64-decoded nonce), exactly as the spec requires, using the JDK's
built-in `Ed25519` provider, the smoke test drives this with a real keypair.

## What is simplified (do not ship this)

- **In memory.** All state is lost on restart; there is no database.
- **No TLS.** Put it behind TLS in any real deployment.
- **Opaque token, not a JWT.** It mints a random bearer token and maps it to the member id in this same
  process. A real deployment mints a JWT whose subject is the member id, verifiable by the vault server
  via the identity provider's JWKS (see SPEC section 3).
- **Hand-rolled JSON.** A minimal parser/serializer lives inside `Server.java` so the example stays
  dependency-free. It is just enough to move the contract's message shapes; it is not a JSON library.
- **v1 membership policy.** Any member may invite (add a member). Tighten as your deployment needs.

The cast in any worked example is illustrative: a host like `vault.example`, members `alice` and `bob`,
and a client name like `democlient`. The base64 key and ciphertext values are placeholders, not real
cryptographic output.

---

SPDX-License-Identifier: MIT
