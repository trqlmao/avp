# AVP — Alt Vault Protocol

An open, vendor-neutral protocol for **sharing Minecraft alt accounts across clients** through a
zero-knowledge sync server. Any client or mod can implement either side and interoperate: members of a
shared *alt repository* are identified by a keypair, the alt payload is end-to-end encrypted on the
client, and the server stores only ciphertext, wrapped keys, public keys, and version counters — it can
decrypt nothing.

AVP is **federated**: a repository is addressed `avp://host/repoId`, and one portable identity reaches
repositories on any conformant server, so different clients (and different communities running their own
servers) can share alts without a central authority.

> This repository is the **specification**, not an implementation. It defines the wire contract; anyone
> may build a conformant client or server from it. A conformant client and server exist as separate
> reference implementations.

## What's here

| Path | Contents |
|---|---|
| [`SPEC.md`](SPEC.md) | The normative protocol specification. |
| [`proto/avp.proto`](proto/avp.proto) | Canonical Protocol Buffers schema for the gRPC profile. |
| [`schema/avp.schema.json`](schema/avp.schema.json) | JSON Schema for the HTTP/JSON profile. |
| [`vectors/`](vectors/) | Conformance test vectors. |

## Design in one paragraph

A repository has one symmetric **data key** that encrypts the alt payload (AES-256-GCM, with the
repository id, payload version, and key epoch bound in as additional authenticated data). That data key
is **wrapped** to each member's X25519 public key, so only members can decrypt it; the server never
sees it unwrapped. A member's stable identity is an **Ed25519 public key**. Removing a member rotates
the data key to a new epoch so the departed member's old wrapped copy is useless. Writes use optimistic
concurrency on a monotonic payload version. None of the plaintext — passphrases, identity seeds, the
data key, or the alts themselves — ever reaches the server.

## Two transport profiles

The same messages are defined for two interchangeable encodings:

- **gRPC profile** — [`proto/avp.proto`](proto/avp.proto) is canonical; field numbers and names are
  stable.
- **HTTP/JSON profile** — one HTTP path per operation, JSON bodies whose field names are exactly the
  proto field names in `camelCase`, a Bearer token in `Authorization`. See
  [`schema/avp.schema.json`](schema/avp.schema.json).

An implementer may support either or both. A JS/web client can implement the protocol with no gRPC
toolchain at all.

## License

- The specification prose (`SPEC.md`, this README) is licensed **CC-BY-4.0**.
- The machine-readable artifacts (`proto/`, `schema/`, `vectors/`) are licensed **MIT**.

See [`LICENSE`](LICENSE).

## Status

Draft **v0.2** of the protocol. The wire contract is stable; open items (algorithm-negotiation
choreography, cross-identity-provider trust in full federation) are tracked in `SPEC.md` §Security
considerations.
