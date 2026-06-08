# AVP reference client, Java

A tiny, runnable reference client for the [HTTP/JSON profile](../../../SPEC.md). It drives the full
lifecycle against a running server so you can watch every operation happen end to end. JDK built-ins
only, no dependencies, no build tool. Two files: [`Crypto.java`](Crypto.java) for the cryptographic
core and [`Client.java`](Client.java) for the HTTP lifecycle. A conformance test harness lives in
[`CryptoVectors.java`](CryptoVectors.java).

```sh
javac Crypto.java CryptoVectors.java Client.java
java CryptoVectors     # verify all crypto vectors (23 assertions, exits 0 on pass)
java Client            # drives the flow against http://localhost:8787
```

Point it at a different server with the `AVP_SERVER_URL` environment variable:

```sh
AVP_SERVER_URL=http://vault.example:8787 java Client
```

You need a server running first. The sibling [`../server`](../server) is the obvious one, start it in
another terminal:

```sh
cd ../server && java Server.java          # listens on http://localhost:8787
```

## What it does

In one run, with two locally generated members (`alice` and `bob`):

1. **Generate keypairs**, each member gets a fresh Ed25519 signing keypair (`java.security`) and a fresh
   X25519 keypair for data-key wrapping. The base64 raw 32-byte Ed25519 public key (the last 32 bytes of
   the JDK's SPKI export) is the member id (SPEC section 2).
2. **Authenticate**, the `challenge` -> sign nonce -> `token` flow. The client signs the **raw nonce
   bytes** (base64-decoded), which is exactly what a conformant server verifies.
3. **createRepo**, alice mints a 32-byte per-repo data key, AES-256-GCM-encrypts the initial alt
   payload, wraps the data key to her own X25519 key, and creates a repo as its sole member.
4. **pull**, once at the known version (server reports `unchanged`, omits the envelope) and once from
   version 0 (server returns the current envelope).
5. **push**, encrypts a new v2 payload (alice adds a second alt account) with optimistic concurrency,
   then deliberately re-pushes at a stale expected version to show the `conflict` response.
6. **addMember**, alice wraps the data key to bob's X25519 key and records his entry.
7. **fetchMemberKey**, looks bob's entry back up by member id (URL-encoded, because base64 ids contain
   `+ / =`).
8. **bob pulls and decrypts**, bob authenticates with his own keypair, pulls the shared repo, unwraps
   the data key from his member entry with his X25519 private key, and decrypts the payload, recovering
   exactly what alice stored.

Each step prints a one-line transcript entry.

## The crypto is real

Unlike the placeholder clients, this one does the real envelope work (SPEC sections 4-5) using the
sibling [`Crypto.java`](Crypto.java):

- derives a per-repo symmetric **data key** (`SecureRandom`),
- **AES-256-GCM** encrypts the alt payload, binding `(repoId, payloadVersion, keyEpoch)` into the AAD
  (SPEC section 4),
- **HKDF-SHA256** (RFC 5869), hand-rolled from `Mac.getInstance("HmacSHA256")` because JDK 21 has no
  JCE HKDF,
- **wraps** the data key to each member's X25519 public key via X25519 key agreement and the above
  HKDF-SHA256 (scheme `X25519-HKDF-SHA256-AESGCM-v1`), and unwraps it again on the receiving side.

Those constructions are checked byte-for-byte against the [conformance vectors](../../../vectors/) by
`CryptoVectors.java` (23 assertions covering all 7 vector files), so this client genuinely
interoperates rather than only round-tripping its own placeholders.

## What is simplified (do not ship this)

This example is **illustrative, not production**. Specifically:

- **No TLS.** It talks plain HTTP to `localhost` by default. A real client uses HTTPS; bearer tokens
  are credentials and the transport MUST be TLS (SPEC section 12).
- **Single process, no persistence.** It generates fresh keypairs each run and keeps no state.
- **No key rotation on removal.** The lifecycle here does not exercise `removeMember`; a real client
  rotates the key epoch and re-wraps the data key to the remaining members when someone leaves.
- **No anti-MITM key-binding verification.** A production client SHOULD (and, off a host it does not
  operate, MUST) verify `MemberEntry.keyBindingSig` against the issuer before wrapping a data key to a
  served member entry (SPEC section 9). `Crypto.keyBindingMessage` provides the canonical message; the
  lifecycle here skips the check.
- **Hand-rolled JSON.** A minimal parser/serializer lives inside `Client.java` so the example stays
  dependency-free. It is just enough to move the contract's message shapes; it is not a JSON library.

---

SPDX-License-Identifier: MIT
