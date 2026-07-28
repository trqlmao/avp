# AVP, the Alt Vault Protocol

An open, vendor-neutral protocol for sharing Minecraft alt accounts across clients through a
zero-knowledge sync server.

[![License](https://img.shields.io/badge/license-CC--BY--4.0%20%2F%20MIT-blue.svg)](LICENSE)
[![no-leak](https://github.com/trqlmao/avp/actions/workflows/no-leak.yml/badge.svg)](https://github.com/trqlmao/avp/actions/workflows/no-leak.yml)
[![spec](https://img.shields.io/badge/spec-v0.4%20draft-orange.svg)](SPEC.md)

Read it online at **[avp.trq.lol](https://avp.trq.lol)**, or jump straight to the
[specification](SPEC.md), the [proto schema](proto/avp.proto), or the [worked examples](examples/).

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
  stable. A runnable client and server live in [`examples/grpc/`](examples/grpc/).
- **HTTP/JSON profile.** One HTTP path per operation, JSON bodies whose field names are the proto field
  names in `camelCase`, and a Bearer token in `Authorization`. Message shapes are
  [`schema/avp.schema.json`](schema/avp.schema.json); the full route surface (paths, status codes, error
  bodies) is [`openapi.yaml`](openapi.yaml).

A browser or Node client can implement AVP with no gRPC toolchain at all.

## Repository layout

| Path | Contents |
|------|----------|
| [`SPEC.md`](SPEC.md) | The normative protocol specification. |
| [`proto/avp.proto`](proto/avp.proto) | Canonical Protocol Buffers schema (gRPC profile). |
| [`schema/avp.schema.json`](schema/avp.schema.json) | JSON Schema message shapes (HTTP/JSON profile). |
| [`openapi.yaml`](openapi.yaml) | OpenAPI 3.1 route description for the HTTP/JSON profile. |
| [`vectors/`](vectors/) | Conformance test vectors (indexed by [`vectors/index.json`](vectors/index.json)). |
| [`examples/`](examples/) | A worked end-to-end flow, representative message bodies, and runnable reference implementations. |
| [`harness/`](harness/) | Black-box conformance suite: run it against any server to assert the wire-contract MUSTs. |
| [`Taskfile.yml`](Taskfile.yml) | One-command local runner: `task test` runs the conformance suite and every example. |
| [`THREATMODEL.md`](THREATMODEL.md) | What AVP defends against, what it does not, and the residual risks. |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to help. |
| [`SECURITY.md`](SECURITY.md) | How to report a vulnerability. |
| [`llms.txt`](llms.txt) | Structured entry point for LLMs and AI agents. |

## Implement it in your client

If you build a Minecraft client, mod, or launcher, you can add cross-client alt sharing by implementing
the side you need:

1. Read [`SPEC.md`](SPEC.md). It is short and self-contained.
2. Generate types from [`proto/avp.proto`](proto/avp.proto), or work straight from
   [`schema/avp.schema.json`](schema/avp.schema.json) if you prefer JSON.
3. Check your build against [`vectors/`](vectors/), then cross-test against another implementation: if
   it decrypts what you encrypt and verifies what you sign, you interoperate.

The [`examples/`](examples/) directory walks the full flow (create, invite, join, pull, push, rotate)
with representative message bodies, which is the fastest way to see how the pieces fit together.

Your client and ours can then share the same repositories. The protocol does not care which client a
member runs.

### Check yourself against the vectors

The reference conformance runner reproduces every vector in [`vectors/`](vectors/) with Node's `crypto`:

```sh
cd examples/conformance
bun install
bun run test
```

It reproduces the deterministic and RFC-anchored vectors exactly and round-trips the composition vectors
(decrypting and unwrapping what a peer produced). Reproduce the same in your language and you are
conformant.

### Check your server

The vectors prove your crypto; the black-box harness in [`harness/`](harness/) proves your *server*.
Point it at any running AVP server and it drives the full wire contract, asserting the normative MUSTs:
the auth failure modes, optimistic-concurrency `conflict`, membership authorization, key rotation, and
zero-knowledge:

```sh
bun harness/conformance.ts --server http://localhost:8787
```

It prints `PASS`/`FAIL` per check and exits non-zero on any failure. CI
([`.github/workflows/conformance.yml`](.github/workflows/conformance.yml)) runs it against the Go and
TypeScript reference servers, lints [`openapi.yaml`](openapi.yaml), and checks that the schema, example
bodies, and vector index stay consistent.

## For AI agents

If you are an AI coding agent asked to implement, review, or extend AVP, start from
[`llms.txt`](llms.txt). It is a structured index of every document here with direct links to the raw
files, in the [llmstxt.org](https://llmstxt.org) format.

Before generating an implementation, load [`SPEC.md`](SPEC.md) in full. The points most often gotten
wrong:

1. **Field names are normative.** Use the exact names in [`proto/avp.proto`](proto/avp.proto) (and their
   `camelCase` form for JSON). Do not rename or renumber fields.
2. **Two fixed byte constructions.** The additional-authenticated-data layout (SPEC section 4) and the
   canonical key-binding message (SPEC section 9) are exact. Reproduce the deterministic
   [`vectors/`](vectors/) before trusting your encoder.
3. **Zero-knowledge is the whole point.** Never send the server a plaintext alt, a passphrase, an
   identity seed, or the data key. The server sees only ciphertext, wrapped keys, public keys, counters,
   and opaque signatures.
4. **Provenance values are runtime data.** `sourceClient` and `sourceUser` are filled in by the
   implementer at runtime. Never hardcode a real client, user, or server name into spec text or examples;
   a CI gate rejects vendor-internal names (see [`CONTRIBUTING.md`](CONTRIBUTING.md)).
5. **Pick a profile.** gRPC from the proto, or HTTP/JSON from the schema. Both carry the same messages.

Verify against another conformant implementation: if it decrypts what you encrypt and verifies what you
sign, you interoperate.

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

This repository is dual-licensed:

- **Machine-readable artifacts** (`proto/`, `schema/`, `vectors/`) and the example code under
  `examples/` are licensed **MIT**, see [`LICENSE`](LICENSE).
- **Specification prose** (`SPEC.md` and this README) is licensed **CC-BY-4.0**, see
  [`LICENSE-docs`](LICENSE-docs).

## Status

Draft v0.4 of the protocol. The wire contract is stable. Open items are tracked in `SPEC.md` §Security
considerations.

## Activity

![Repobeats analytics image](https://repobeats.axiom.co/api/embed/8fbbf889a0dea0c16bb24d8a5dca479a4dd1bee1.svg "Repobeats analytics image")
