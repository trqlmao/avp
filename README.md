# AVP, the Alt Vault Protocol

An open, vendor-neutral protocol for sharing Minecraft alt accounts across clients through
zero-knowledge hosts that replicate each repository between them.

[![License](https://img.shields.io/badge/license-CC--BY--4.0%20%2F%20MIT-blue.svg)](LICENSE)
[![no-leak](https://github.com/trqlmao/avp/actions/workflows/no-leak.yml/badge.svg)](https://github.com/trqlmao/avp/actions/workflows/no-leak.yml)
[![spec](https://img.shields.io/badge/spec-v0.5%20stable-brightgreen.svg)](SPEC.md)

Read it online at **[avp.trq.lol](https://avp.trq.lol)**, or jump straight to the
[specification](SPEC.md), the [proto schema](proto/avp.proto), or the [worked examples](examples/).

Members of a shared *alt repository* are identified by a keypair. The alt payload is encrypted on the
client before it ever leaves the machine, so a host stores only ciphertext, wrapped keys, public keys,
counters, ids, and signatures. It can decrypt nothing. Any client or mod can implement either side and
interoperate, the same way any mail client talks to any IMAP server.

AVP is federated. A repository lives on several hosts at once: each member talks to its own home host,
and the hosts replicate with each other, so a member keeps working while another member's host is down.
Different clients, and different communities running their own hosts, can share alts without a central
authority.

> This repository is the **specification**, not an implementation. It defines the wire contract so
> anyone can build a conformant client or host. Illustrative Rust and Java reference clients and hosts
> live in [`examples/`](examples/).

## How it works in one paragraph

The repository owner holds a 24-word recovery phrase that derives the owner signing key. Only the owner
signs **manifest states**: a hash-linked chain holding the members, the data key wrapped to each member's
X25519 key, the key epoch, the refresh-token policy, and the hosts. Every write is a **commit** signed by
its member author, carrying the full payload encrypted with AES-256-GCM under the epoch's data key, with
the repository, epoch, author, and parent commits bound in as additional authenticated data. Concurrent
writes on different hosts fork the commit graph; every field carries its own timestamp, so clients merge
the heads per field without losing a write. Removing a member rotates the data key to a new epoch and
signs a cutoff that rejects anything the removed member backdates. Hosts verify every signature and
validate every item, but no phrase, seed, data key, or plaintext alt ever reaches one.

## Two transport profiles

The same messages are defined for two interchangeable encodings, so you can pick whichever fits your
stack:

- **gRPC profile.** [`proto/avp.proto`](proto/avp.proto) is canonical. Field numbers and names are
  stable. It also defines the `Replication` service for host-to-host sync over gRPC. The gRPC example
  stopped at 0.4; see the `v0.4` tag.
- **HTTP/JSON profile.** One HTTP path per operation, JSON bodies whose field names are the proto field
  names in `camelCase`, and a Bearer token in `Authorization`. Message shapes are
  [`schema/avp.schema.json`](schema/avp.schema.json); the full route surface (paths, status codes, error
  bodies) is [`openapi.yaml`](openapi.yaml). The reference hosts replicate with each other over signed
  HTTP/JSON (SPEC section 9.3).

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
| [`harness/`](harness/) | Black-box conformance suite: run it against any host, or several replicating hosts, to assert the wire-contract MUSTs. |
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

The [`examples/`](examples/) directory walks the full flow (create, invite, join, write, merge, remove,
replicate) with representative message bodies and holds the Rust and Java reference clients and hosts.
[`IMPLEMENTING.md`](IMPLEMENTING.md) is the implementer's guide.

Your client and ours can then share the same repositories. The protocol does not care which client a
member runs.

### Check yourself against the vectors

The reference conformance runner reproduces every vector in [`vectors/`](vectors/) with Node's `crypto`:

```sh
cd examples/conformance
bun install
bun run test
```

It reproduces the RFC-anchored and construction vectors exactly, round-trips the composition vectors
(decrypting and unwrapping what a peer produced), replays the host acceptance scenarios, and rejects every
negative case. Reproduce the same in your language and your crypto and rules are conformant.

### Check your host

The vectors prove your crypto; the black-box harness in [`harness/`](harness/) proves your *host*.
Point it at any running AVP host and it drives the full wire contract, asserting the normative MUSTs:
the auth failure modes, the manifest chain, forks and merges, the head bound, the removal cutoff, leave,
`prepareJoin`, and zero-knowledge. A second suite drives replication between two or three hosts:

```sh
bun harness/conformance.ts --server http://127.0.0.1:8787
bun harness/multihost.ts --a http://127.0.0.1:19201 --b http://127.0.0.1:19202 --c http://127.0.0.1:19203
```

Each prints `PASS`/`FAIL` per check and exits non-zero on any failure. CI
([`.github/workflows/conformance.yml`](.github/workflows/conformance.yml)) runs both against the Rust and
Java reference hosts, the multi-host suite in every language pairing, lints [`openapi.yaml`](openapi.yaml),
and checks that the schema, example bodies, and vector index stay consistent.

## For AI agents

If you are an AI coding agent asked to implement, review, or extend AVP, start from
[`llms.txt`](llms.txt). It is a structured index of every document here with direct links to the raw
files, in the [llmstxt.org](https://llmstxt.org) format.

Before generating an implementation, load [`SPEC.md`](SPEC.md) in full. The points most often gotten
wrong:

1. **Field names are normative.** Use the exact names in [`proto/avp.proto`](proto/avp.proto) (and their
   `camelCase` form for JSON). Do not rename or renumber fields.
2. **Fixed byte constructions.** Every signed or hashed structure (manifest state, commit header, AAD,
   acceptance, leave request) is built by the canonical encoding of SPEC section 4 and is exact.
   Reproduce the [`vectors/`](vectors/) before trusting your encoder.
3. **Zero-knowledge is the whole point.** Never send a host a plaintext alt, the owner phrase or seed, a
   private key, or a data key. A host sees only ciphertext, wrapped keys, public keys, counters, ids, and
   signatures.
4. **Provenance values are runtime data.** `sourceClient` and `sourceUser` are filled in by the
   implementer at runtime. Never hardcode a real client, user, or server name into spec text or examples;
   a CI gate rejects vendor-internal names (see [`CONTRIBUTING.md`](CONTRIBUTING.md)).
5. **Pick a profile.** gRPC from the proto, or HTTP/JSON from the schema. Both carry the same messages.

Verify against another conformant implementation: if it decrypts what you encrypt and verifies what you
sign, you interoperate.

## Want to help?

Contributions from other client developers are very welcome. Good ways to lock in:

- **Implement a client or host** in a new language and report back on anything ambiguous in the spec.
- **Add conformance vectors**, especially host acceptance scenarios and negative cases.
- **Write a reference HTTP/JSON host skeleton** so newcomers can stand one up quickly.
- **Review the cryptography** and the manifest chain, removal cutoff, and replication design, and open
  issues for weaknesses.
- **Help design the open items** in `SPEC.md` §15 (algorithm negotiation, ownership transfer,
  deletion-marker GC and retention, host freshness).

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

Stable v0.5 of the protocol: multi-host repositories with an owner-signed manifest chain, a signed commit
graph, per-field merge, host-issued authentication, and a BIP39 owner identity. 0.5 is a breaking version,
not wire compatible with 0.4. Open items are tracked in `SPEC.md` §15.

## Activity

![Repobeats analytics image](https://repobeats.axiom.co/api/embed/8fbbf889a0dea0c16bb24d8a5dca479a4dd1bee1.svg "Repobeats analytics image")
