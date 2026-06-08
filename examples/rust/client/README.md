# AVP reference client, Rust

A tiny, runnable reference client for the [HTTP/JSON profile](../../../SPEC.md). It drives the full
lifecycle against a running server so you can watch every operation happen end to end, including
real envelope encryption and key wrapping. The source is [`src/main.rs`](src/main.rs) and
[`src/crypto.rs`](src/crypto.rs). It is a sibling of the
[Go reference client](../../go/client/) and is wire-compatible with every reference server in
this repository.

```sh
cargo build           # compile
cargo run             # drives the flow against http://localhost:8787
cargo test            # run the conformance vector tests
cargo build --release # optimized binary at target/release/avp-reference-client
```

Point it at a different server with the `AVP_SERVER_URL` environment variable:

```sh
AVP_SERVER_URL=http://vault.example:8787 cargo run
```

You need a server running first. The sibling [`../server`](../server) is the obvious one:

```sh
cd ../server && cargo run   # listens on http://localhost:8787
```

The [Go server](../../go/server/) is wire-compatible and works just as well.

## What it does

In one run, with two locally generated members (`alice` and `bob`):

1. **Generate keypairs**, each member is a fresh Ed25519 keypair (the member id, SPEC section 2)
   plus a real X25519 keypair for data-key wrapping.
2. **Authenticate**, the `challenge` -> sign nonce -> `token` flow. The client signs the **raw
   nonce bytes** (base64-decoded), which is exactly what a conformant server verifies.
3. **createRepo**, alice mints a 32-byte per-repo data key, AES-256-GCM-encrypts the initial alt
   payload, wraps the data key to her own X25519 key, and creates a repo as its sole member.
4. **pull**, once at the known version (server reports `unchanged`, omits the envelope) and once
   from version 0 (server returns the current envelope).
5. **push**, encrypts and writes a new payload version with optimistic concurrency, then
   deliberately re-pushes at a stale expected version to show the `conflict` response.
6. **addMember**, alice wraps the data key to bob's X25519 key and records his entry.
7. **fetchMemberKey**, looks bob's entry back up by member id (URL-encoded, because base64 ids
   contain `+ / =`).
8. **bob pulls and decrypts**, bob authenticates with his own keypair, pulls the shared repo,
   finds his member entry in the manifest, unwraps the data key with his X25519 private key,
   and decrypts the payload -- recovering exactly what alice stored.

Each step prints a one-line transcript entry.

## The crypto is real

Unlike placeholder reference clients, this one does the full envelope work (SPEC sections 4-5)
in [`src/crypto.rs`](src/crypto.rs):

- derives a per-repo symmetric **data key** (32 random bytes),
- **AES-256-GCM** encrypts the alt payload, binding `(repoId, payloadVersion, keyEpoch)` into
  the AAD (SPEC section 4),
- **wraps** the data key to each member's X25519 public key via
  `X25519-HKDF-SHA256-AESGCM-v1`: ephemeral X25519 ECDH (shared secret used raw, unhashed),
  HKDF-SHA256 for the key-encryption key, AES-256-GCM to seal the data key,
- **unwraps** the data key on the receiving side using the recipient's X25519 private key.

Those constructions are checked byte-for-byte against the shared
[conformance vectors](../../../vectors/) by `cargo test`, so this client genuinely interoperates
rather than only round-tripping its own values.

## Dependencies

Minimal and version-pinned (see [`Cargo.toml`](Cargo.toml)):

| Crate | Why |
|---|---|
| `ureq` | tiny blocking HTTP/1.1 client, no async runtime |
| `serde_json` | build and parse JSON message shapes (`Value`) |
| `ed25519-dalek` | generate the Ed25519 keypair and sign the challenge nonce |
| `base64` | standard-base64 encode/decode for all wire byte fields |
| `rand` | random keypair seeds, data key, IVs, and the opaque repoId |
| `aes-gcm` | AES-256-GCM payload AEAD and data-key wrap seal/open |
| `hkdf` | HKDF-SHA256 key derivation for the KEK in X25519-HKDF-SHA256-AESGCM-v1 |
| `sha2` | SHA-256 hash function, pulled in by `hkdf` |
| `x25519-dalek` | X25519 Diffie-Hellman for ephemeral key agreement in the wrap scheme |

## What is simplified (do not ship this)

- **No TLS.** It talks plain HTTP to `localhost` by default. A real client uses HTTPS; bearer
  tokens are credentials and the transport MUST be TLS (SPEC section 12).
- **Single process, no persistence.** It generates fresh keypairs each run and keeps no state.
- **No key rotation on removal.** The lifecycle here does not exercise `removeMember`; a real
  client rotates the key epoch and re-wraps the data key to the remaining members when someone
  leaves.
- **No anti-MITM key-binding verification.** A production client SHOULD (and, off a host it does
  not operate, MUST) verify `MemberEntry.keyBindingSig` before wrapping a data key to a served
  member entry (SPEC section 9). This example skips that check.

## License

MIT (`SPDX-License-Identifier: MIT`).
