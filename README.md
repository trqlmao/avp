# AVP, the Alt Vault Protocol

An open, vendor-neutral protocol for sharing Minecraft alt accounts across clients through a
zero-knowledge sync server.

[![License](https://img.shields.io/badge/license-CC--BY--4.0%20%2F%20MIT-blue.svg)](LICENSE)
[![no-leak](https://github.com/trqlmao/avp-spec/actions/workflows/no-leak.yml/badge.svg)](https://github.com/trqlmao/avp-spec/actions/workflows/no-leak.yml)
[![spec](https://img.shields.io/badge/spec-v0.2%20draft-orange.svg)](SPEC.md)

Members of a shared *alt repository* are identified by a keypair. The alt payload is encrypted on the
client before it ever leaves the machine, so the server stores only ciphertext, wrapped keys, public
keys, and version counters. It can decrypt nothing. Any client or mod can implement either side and
interoperate, the same way any mail client talks to any IMAP server.

AVP is federated. A repository is addressed `avp://host/repoId`, and one portable identity reaches
repositories on any conformant server. Different clients, and different communities running their own
servers, can share alts without a central authority.

> This repository is the **specification**, not an implementation. It defines the wire contract so
> anyone can build a conformant client or server. A conformant client and server exist as separate
> reference implementations.

## How it works in one paragraph

A repository has one symmetric data key that encrypts the alt payload (AES-256-GCM, with the repository
id, payload version, and key epoch bound in as additional authenticated data). That data key is wrapped
to each member's X25519 public key, so only members can decrypt it, and the server never sees it
unwrapped. A member's stable identity is an Ed25519 public key. Removing a member rotates the data key to
a new epoch, so the departed member's old wrapped copy becomes useless. Writes use optimistic concurrency
on a monotonic payload version. No plaintext (passphrases, identity seeds, the data key, or the alts
themselves) ever reaches the server.

## Two transport profiles

The same messages are defined for two interchangeable encodings, so you can pick whichever fits your
stack:

- **gRPC profile.** [`proto/avp.proto`](proto/avp.proto) is canonical. Field numbers and names are
  stable.
- **HTTP/JSON profile.** One HTTP path per operation, JSON bodies whose field names are the proto field
  names in `camelCase`, and a Bearer token in `Authorization`. See [`schema/avp.schema.json`](schema/avp.schema.json).

A browser or Node client can implement AVP with no gRPC toolchain at all.

## Repository layout

| Path | Contents |
|------|----------|
| [`SPEC.md`](SPEC.md) | The normative protocol specification. |
| [`proto/avp.proto`](proto/avp.proto) | Canonical Protocol Buffers schema (gRPC profile). |
| [`schema/avp.schema.json`](schema/avp.schema.json) | JSON Schema (HTTP/JSON profile). |
| [`vectors/`](vectors/) | Conformance test vectors. |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to help. |
| [`SECURITY.md`](SECURITY.md) | How to report a vulnerability. |

## Implement it in your client

If you build a Minecraft client, mod, or launcher, you can add cross-client alt sharing by implementing
the side you need:

1. Read [`SPEC.md`](SPEC.md). It is short and self-contained.
2. Generate types from [`proto/avp.proto`](proto/avp.proto), or work straight from
   [`schema/avp.schema.json`](schema/avp.schema.json) if you prefer JSON.
3. Check your build against [`vectors/`](vectors/), then cross-test against another implementation: if
   it decrypts what you encrypt and verifies what you sign, you interoperate.

Your client and ours can then share the same repositories. The protocol does not care which client a
member runs.

## Want to help?

Contributions from other client developers are very welcome. Good ways to lock in:

- **Implement a client or server** in a new language and report back on anything ambiguous in the spec.
- **Add conformance vectors**, especially for key wrap/unwrap, rotation, and the auth challenge.
- **Write a reference HTTP/JSON server skeleton** so newcomers can stand one up quickly.
- **Review the cryptography** and the federation and anti-MITM design, and open issues for weaknesses.
- **Help design the open items** in `SPEC.md` §12 (algorithm negotiation, cross-identity-provider trust).

Start by opening an issue to discuss, then send a pull request. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Disclaimer

AVP is an independent, community specification. It is not affiliated with, endorsed by, or associated
with Mojang or Microsoft. "Minecraft" and related marks belong to their respective owners and are used
here only to describe interoperability. The specification is provided as is, without warranty of any
kind. How an implementation obtains and uses accounts, and whether that complies with any service's terms
or with applicable law, is the implementer's responsibility.

## License

- Specification prose (`SPEC.md`, this README) is licensed **CC-BY-4.0**.
- Machine-readable artifacts (`proto/`, `schema/`, `vectors/`) are licensed **MIT**.

See [`LICENSE`](LICENSE).

## Status

Draft v0.2 of the protocol. The wire contract is stable. Open items are tracked in `SPEC.md` §Security
considerations.

## Activity

![Repobeats analytics image](https://repobeats.axiom.co/api/embed/8fbbf889a0dea0c16bb24d8a5dca479a4dd1bee1.svg "Repobeats analytics image")
