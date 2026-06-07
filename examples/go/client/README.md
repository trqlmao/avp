# AVP reference client, Go

A tiny, runnable reference client for the [HTTP/JSON profile](../../../SPEC.md). It
drives the full lifecycle against a running server so you can watch every operation
happen end to end. It is a sibling of the [Rust reference client](../../rust/client/)
and is wire-compatible with every reference server in this repository.

```sh
go run .              # drives the flow against http://localhost:8787
go build              # build the ./client binary
```

Point it at a different server with the `AVP_SERVER_URL` environment variable:

```sh
AVP_SERVER_URL=http://vault.example:8787 go run .
```

You need a server running first. The sibling [`../server`](../server) is the obvious
one:

```sh
cd ../server && go run .   # listens on http://localhost:8787
```

## What it does

In one run, with two locally generated members (`alice` and `bob`):

1. **Generate keypairs**, each member is a fresh Ed25519 keypair (the member id) plus
   an X25519 keypair for data-key wrapping.
2. **Authenticate**, the `challenge` -> sign nonce -> `token` flow. The client signs
   the **raw nonce bytes** (base64-decoded), which is exactly what a conformant server
   verifies.
3. **createRepo**, alice mints a per-repo data key, encrypts the initial alt payload,
   wraps the data key to her own X25519 key, and creates a repo as its sole member.
4. **pull**, once at the known version (server reports `unchanged`, omits the
   envelope) and once from version 0 (server returns the current envelope).
5. **push**, encrypts and writes a new payload version with optimistic concurrency,
   then deliberately re-pushes at a stale expected version to show the `conflict`
   response.
6. **addMember**, alice wraps the data key to bob's X25519 key and records his entry.
7. **fetchMemberKey**, looks bob's entry back up by member id (URL-encoded, because
   base64 ids contain `+ / =`).
8. **bob pulls and decrypts**, bob authenticates with his own keypair, pulls the
   shared repo, unwraps the data key from his member entry, and decrypts the payload,
   recovering exactly what alice stored.

Each step prints a one-line transcript entry.

## The crypto is real

Unlike the placeholder clients, this one does the real envelope work (SPEC sections
4–5) using the sibling [`../avp`](../avp) package:

- derives a per-repo symmetric **data key**,
- **AES-256-GCM** encrypts the alt payload, binding `(repoId, payloadVersion,
  keyEpoch)` into the AAD (SPEC section 4),
- **wraps** the data key to each member's X25519 public key via X25519 +
  HKDF-SHA256, and unwraps it again on the receiving side.

Those constructions are checked byte-for-byte against the
[conformance vectors](../../../vectors/) by the `avp` package's tests, so this client
genuinely interoperates rather than only round-tripping its own placeholders.

## What is simplified (do not ship this)

This example is **illustrative, not production**. Specifically:

- **No TLS.** It talks plain HTTP to `localhost` by default. A real client uses
  HTTPS; bearer tokens are credentials and the transport MUST be TLS (SPEC section 12).
- **Single process, no persistence.** It generates fresh keypairs each run and keeps
  no state.
- **No key rotation on removal.** The lifecycle here does not exercise `removeMember`;
  a real client rotates the key epoch and re-wraps the data key to the remaining
  members when someone leaves.
- **No anti-MITM key-binding verification.** A production client SHOULD (and, off a
  host it does not operate, MUST) verify `MemberEntry.keyBindingSig` against the
  issuer before wrapping a data key to a served member entry (SPEC section 9). The
  `avp` package provides `KeyBindingMessage` for this; the lifecycle here skips the
  check.

## License

MIT (`SPDX-License-Identifier: MIT`).
