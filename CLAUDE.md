# CLAUDE.md

Guidance for AI coding agents working in this repository.

## What this repo is

This is the **specification** for AVP (the Alt Vault Protocol), an open,
vendor-neutral, zero-knowledge, federated protocol for sharing Minecraft alt
accounts across clients. It is the wire contract, not a product. There is no
application to run here. The deliverables are documents, a proto schema, a JSON
schema, conformance vectors, a black-box host harness, and small illustrative
examples.

AVP 0.5 (draft) in one breath: a repository lives on several hosts that
replicate it; an owner holding a BIP39 phrase signs a hash-linked manifest
chain (members, wrapped data keys, key epoch, refresh-token policy, hosts);
members sign commits carrying the full encrypted payload; concurrent heads
merge per field; removal rotates the key and signs a cutoff; each host issues
its own tokens. Every signed or hashed structure uses the canonical encoding
(CE) of SPEC §4.

The live site (GitHub Pages, custom domain `avp.trq.lol`) is rendered from this
repo with Jekyll. The README is the home page.

## Source of truth and how the pieces relate

- `SPEC.md` is the **normative contract**. Anything an implementation MUST do is
  stated there in RFC 2119 language. Do not soften MUST/SHALL/SHOULD/MAY.
- `proto/avp.proto` is the **canonical** message definition. Field numbers and
  names are stable; add fields, never renumber or rename them.
- `schema/avp.schema.json` mirrors the proto for the HTTP/JSON profile: the same
  field names in `camelCase`. Keep it in sync with the proto and SPEC. It also
  holds the HTTP error body (`$defs/Error` = `{ error, code?, detail? }`).
- `openapi.yaml` is the OpenAPI 3.1 description of the HTTP/JSON profile (paths,
  methods, status codes, error responses). It does not redefine message shapes:
  it `$ref`s them from `schema/avp.schema.json`, which stays the single source of
  truth. Keep its routes and status set aligned with SPEC §10 (client and
  host-to-host routes, the §10.4 error table).
- `vectors/` are conformance test vectors, indexed by `vectors/index.json`
  (kind, spec section, anchors; keep it in sync when adding or removing a
  vector). See `vectors/README.md`. **Never edit a vector value without
  re-verifying it three ways** (RFC or published anchor, a reference
  implementation, and the Node runner agree byte for byte).
  - RFC-anchored primitives: `hkdf.json`, `x25519.json`, `ed25519.json`, and
    the wrap composition `key-wrap.json`.
  - 0.5 constructions, generated from documented seeds: `bip39-owner.json`
    (over the pinned wordlist `bip39-english.txt`), `manifest.json`,
    `commit.json`, and `federation.json` (out-of-band tokens, leave
    signatures, link codes, fingerprints, `avp://` locators; it uses
    `tokens`/`leaves`/`linkCodes`/`fingerprints`/`uris`, not `cases`).
  - Hand-written expectations: `merge.json` (payload merge and HLC) and
    `acceptance.json` (host rule scenarios with a top-level `scenarios`
    array; the Rust and Java rules engines replay it unchanged).
  - `negative.json`, the MUST-reject bank, including the strict Ed25519
    rejects of SPEC §2.
  `vectors/generate.ts` is the generator. `bun vectors/generate.ts --check`
  is the provenance and drift gate (CI runs it); `--write` regenerates only
  the files the generator owns (`negative.json`, `bip39-owner.json`,
  `manifest.json`, `commit.json`, `federation.json`, `merge.json`,
  `acceptance.json`) and never rewrites the RFC-anchored files.
- `examples/` holds the illustrative Rust and Java references for the
  HTTP/JSON profile. Each language has one shared library that both its host
  and its client use: the `avp` crate (`examples/rust/avp`) and
  `examples/java/avp` (JDK only, default package). Hosts are in
  `examples/<lang>/server`, clients in `examples/<lang>/client`. Hosts read
  `PORT`, `AVP_BIND` (default `0.0.0.0`; use `127.0.0.1` locally),
  `AVP_HOST_SEED`, `AVP_PEERS`, and `AVP_TEST_CONTROL`, and replicate over
  signed HTTP/JSON (SPEC §9.3); the proto still defines the `Replication`
  service for a gRPC profile. `examples/conformance` is the Node/Bun runner
  that reproduces every vector and checks schema/example/index/openapi
  consistency. None of it is production code. The Go, Python, TypeScript
  and gRPC examples stopped at 0.4 (see the `v0.4` tag).
- `harness/` is the black-box host suite. `harness/conformance.ts` drives one
  host's client wire contract (`bun harness/conformance.ts --server URL`):
  auth failure modes, `createRepo`, the pulled chain, forks and merges, the
  head bound, `manifest_conflict`, the removal cutoff, leave, `prepareJoin`,
  not hosted, zero-knowledge. `harness/multihost.ts` drives replication
  between two or three hosts (convergence, concurrent writes, removal on
  every host, unlisted hosts, old-epoch heads, leave replication, diverged
  owner states). `harness/run-hosts.sh` builds and starts the reference hosts
  on `127.0.0.1` and runs a command against them; `harness/common.ts` holds
  the shared helpers and `harness/crypto.ts` the vector-tested crypto. The
  harness is the executable check for a *host*; the vectors are the check for
  the *constructions*.
- `THREATMODEL.md` is the adversary model (what AVP defends, what it does not, the
  residual risks). Keep it consistent with SPEC §13 invariants and §15 open items
  when the security posture changes.

When you change one of `SPEC.md` / `proto/avp.proto` / `schema/avp.schema.json` /
`openapi.yaml`, check whether the others need the matching change. They describe
one protocol.

## Hard rules

1. **Vendor neutrality is enforced.** AVP names no specific client, product,
   sponsor, server deployment, or anti-cheat. This is what makes it a standard
   rather than one vendor's API. `.github/workflows/no-leak.yml` scans every
   change against a denylist (sourced from a private secret) and fails the build
   on an internal name. Use generic placeholders: `vault.example` for a host, a
   neutral client/user name for provenance values. Provenance fields
   (`sourceClient`, `sourceUser`) carry such names only at runtime, set by each
   implementer, never baked into spec text, examples, or tests.
2. **Zero-knowledge is the whole point.** Never let a host see a plaintext
   alt, the owner phrase, its entropy or seed, a private key, or a data key. A
   host stores only ciphertext, wrapped keys, public keys, counters, ids, and
   signatures.
3. **Fixed byte constructions are exact.** The canonical encoding (SPEC §4.1)
   and every layout built on it (manifest state, commit header, AAD v2,
   acceptance, leave, link code, host request) are byte-for-byte. Reproduce
   the vectors before trusting any encoder you write.
4. **No em dashes** in prose (house style). Use commas, colons, semicolons,
   periods, or parentheses.

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/):
`type(scope): summary`, for example `docs(spec): clarify AAD layout` or
`feat(proto): add field for X`. Breaking changes to the wire contract use `!`
and a `BREAKING CHANGE:` footer, and bump the version in `SPEC.md` and
`README.md`. **Never add an AI-attribution trailer** (no `Co-Authored-By` for an
AI). The committer is the responsible author.

## Build and test

- Conformance runner (vectors + schema/example/index/openapi consistency):
  `cd examples/conformance && bun install && bun run test`.
- Vector drift gate: `bun vectors/generate.ts --check`.
- Black-box a host: start one with `AVP_BIND=127.0.0.1`, then
  `bun harness/conformance.ts --server http://127.0.0.1:PORT`; or let
  `bash harness/run-hosts.sh rust -- bun harness/conformance.ts --server http://127.0.0.1:19201`
  build and start it.
- One-command local run: `Taskfile.yml` (go-task). `task test` runs the
  conformance runner, the vector drift gate, and the Rust and Java tests;
  `task harness`, `task multihost`, `task interop`, and `task openapi-lint` run
  the host harness, the multi-host harness, cross-language interop, and the
  Spectral lint. Each target mirrors a CI job.
- `llms-full.txt` is generated from `IMPLEMENTING.md`, `SPEC.md`, and
  `THREATMODEL.md`: after editing any of them run
  `node scripts/build-llms-full.mjs --write` (`docs.yml` runs `--check`).
- CI workflows in `.github/workflows/`: per-language `examples-{node,rust,java}.yml`,
  the cross-language `examples-interop.yml`, `conformance.yml` (vector runner +
  Spectral lint of `openapi.yaml` + schema-consistency + the black-box harness against
  the Rust and Java reference hosts + the multi-host harness per language pairing),
  and `docs.yml` (llms-full sync). `no-leak.yml` is the vendor-neutrality gate.
- The Pages site builds on push (no local step required). If you want to preview
  it locally and have Ruby, `bundle exec jekyll serve` renders `_layouts/default.html`
  with `assets/css/style.css`.

## Site (GitHub Pages)

`_config.yml` uses a hand-written layout (`_layouts/default.html` +
`assets/css/style.css`), not a gem theme. The look is minimal, light, text-first,
monospace headings, no accent color (neutrality). `CNAME` pins `avp.trq.lol`; do
not change it. Keep the layout dependency-free (no JS frameworks).
