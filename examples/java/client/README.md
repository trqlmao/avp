# AVP reference client — Java

A tiny, runnable reference client for the [HTTP/JSON profile](../../../SPEC.md). It drives the full
lifecycle against a running server so you can watch every operation happen end to end. JDK built-ins
only — no dependencies, no build tool. The source is one file, [`Client.java`](Client.java), runnable
straight from source.

```sh
java Client.java          # drives the flow against http://localhost:8787
```

`java Client.java` uses the [single-file source-code launcher](https://openjdk.org/jeps/330)
(`java <file>.java`), available on **JDK 17+**. No `javac`, classpath, or jar is needed. To compile
explicitly instead:

```sh
javac Client.java
java Client
```

Point it at a different server with the `AVP_SERVER_URL` environment variable:

```sh
AVP_SERVER_URL=http://vault.example:8787 java Client.java
```

You need a server running first. The sibling [`../server`](../server) is the obvious one — start it in
another terminal:

```sh
cd ../server && java Server.java          # listens on http://localhost:8787
```

## What it does

In one run, with two locally generated members (`alice` and `bob`):

1. **Generate keypairs** — each member is a fresh Ed25519 keypair (`java.security`). The base64 raw
   32-byte Ed25519 public key (the last 32 bytes of the JDK's SPKI export) is the member id (SPEC
   section 2).
2. **Authenticate** — the `challenge` -> sign nonce -> `token` flow. The client signs the **raw nonce
   bytes** (base64-decoded), which is exactly what a conformant server verifies.
3. **createRepo** — alice creates a repo as its sole member.
4. **pull** — once at the known version (server reports `unchanged`, omits the envelope) and once from
   version 0 (server returns the current envelope).
5. **push** — writes a new payload version with optimistic concurrency, then deliberately re-pushes at a
   stale expected version to show the `conflict` response.
6. **addMember** — alice records bob's member entry.
7. **fetchMemberKey** — looks bob's entry back up by member id (URL-encoded, because base64 ids contain
   `+ / =`).
8. **bob pulls** — bob authenticates with his own keypair and syncs the shared repo.

Each step prints a one-line transcript entry. The client is dependency-free: it uses
`java.net.http.HttpClient` for HTTP, the JDK's built-in `Ed25519` provider for the keypair and the
challenge signature, and a small hand-rolled JSON parser/serializer (mirroring the one in
[`../server/Server.java`](../server/Server.java)).

## What is a placeholder (read this)

**The envelope and wrapped-key cryptography is out of scope for this example.** This client does **not**
encrypt anything. It carries the alt payload as an **opaque placeholder ciphertext** and fills each
member's wrapped data key with a labelled placeholder blob. That is fine for exercising the wire
contract, because the server is zero-knowledge and never decrypts what it stores — so a placeholder
ciphertext round-trips identically to a real one.

A production client does the real work the server cannot:

- derive a per-repo symmetric **data key**,
- **AES-256-GCM** encrypt the alt payload, binding `(repoId, payloadVersion, keyEpoch)` into the AAD
  (SPEC section 4),
- **wrap** the data key to each member's X25519 public key via X25519 + HKDF-SHA256, and
- rotate the key epoch on member removal.

See SPEC sections 4–5 and the `lol.trq.alts` reference implementation for that part. The **only** real
cryptography in this example is the Ed25519 challenge signature, which is genuinely part of the wire
contract.

## What is simplified (do not ship this)

- **Placeholder crypto.** As above — no real encryption or key wrapping happens here.
- **No TLS.** It talks plain HTTP to `localhost` by default. A real client uses HTTPS; bearer tokens are
  credentials and the transport MUST be TLS (SPEC section 12).
- **Single process, no persistence.** It generates fresh keypairs each run and keeps no state.
- **Hand-rolled JSON.** A minimal parser/serializer lives inside `Client.java` so the example stays
  dependency-free. It is just enough to move the contract's message shapes; it is not a JSON library.
- **No anti-MITM key-binding verification.** A production client SHOULD (and, off a host it does not
  operate, MUST) verify `MemberEntry.keyBindingSig` before wrapping a data key to a served member entry
  (SPEC section 9). This example skips that step.

The cast is illustrative: a host like `vault.example`, members `alice` and `bob`, and a client name like
`democlient`. The base64 key and ciphertext values printed in the transcript are real Ed25519 keys for
the auth signature and placeholders for everything else.

---

SPDX-License-Identifier: MIT
