# Changelog

Notable changes to the Alt Vault Protocol (AVP) and this repository. The format follows
[Keep a Changelog](https://keepachangelog.com/). The protocol version is independent of any
implementation's version.

## [Unreleased]

### Specification

- Clarified that an issuer MAY require out-of-band authentication and embed deployment-specific claims
  on the `token` grant, and that a server MAY return implementation-defined resource or policy errors
  such as quota limits; both non-normative (SPEC sections 3 and 6).
- Defined the HTTP/JSON error body `{ error, code?, detail? }` and a status→code table, and stated that
  every non-2xx is terminal while a stale-version `push` is a `200` with `conflict: true` (SPEC section
  6); added `$defs/Error` to the JSON Schema.
- Reworded the conformance section (SPEC section 11) to map each requirement to the vector that actually
  exists: the Ed25519 primitive anchors the challenge signature and the payload-AEAD epoch-tamper case
  anchors rotation correctness; dedicated challenge/token and rotation vectors are noted as welcome
  additions rather than implied to already exist.

### Repository

- Added a black-box conformance harness in `harness/`: point it at any running server and it drives the
  full wire contract, asserting the normative MUSTs (auth failure modes, optimistic-concurrency
  conflict, membership authorization, key rotation, and zero-knowledge — the plaintext never surfaces in
  what the server stores). Reuses the vector-tested reference crypto.
- Added a `conformance` CI workflow: reproduces the vectors, lints `openapi.yaml` with Spectral, checks
  that the schema / example bodies / vector index / OpenAPI `$refs` stay consistent, and runs the
  black-box harness against the Go and TypeScript reference servers. The vector runner now also runs in
  CI for the first time.
- Added `openapi.yaml`, an OpenAPI 3.1 description of the HTTP/JSON profile (paths, status codes, error
  responses) that references the JSON Schema shapes, so the route surface is machine-readable and
  stub-generatable.
- Added `vectors/index.json`, a machine-readable index of the conformance vectors (file, kind, spec
  section, RFC anchors) so a harness can enumerate them without hardcoding filenames.
- Added a root `Taskfile.yml` (go-task): `task test` runs the conformance suite and every language's
  example tests in one command, mirroring the CI jobs.
- Added a Go reference client and server, and upgraded the TypeScript, Python, Java, and Rust reference
  clients to implement the real envelope and key-wrap crypto (previously opaque placeholders). Every
  example is verified byte-for-byte against the conformance vectors.
- Added a cross-language interop CI workflow: each language's client runs against the Go reference
  server, and the Go reference client runs against each language's server.
- Added `IMPLEMENTING.md`, a language-agnostic guide for building a conformant client or server that
  links each construction to its spec section, its conformance vector, and the reference code; pointed
  `llms.txt` at it.

## [0.2] - 2026-06-01

Initial public draft of the protocol.

### Specification

- Keypair identity with a challenge/token authentication flow (SPEC section 3).
- Zero-knowledge cryptographic envelope: `WrappedKey`, `MemberEntry`, `EncryptedEnvelope`,
  `VaultManifest`; AES-256-GCM with a fixed AAD byte layout (section 4).
- Payload and provenance fields, carried inside the encrypted payload only (section 5).
- Six vault operations across two interchangeable transport profiles, gRPC and HTTP/JSON (section 6).
- Federation by portable identity plus `avp://host/repoId` addressing, with an invite/locator join
  handshake (section 8).
- Optional issuer-signed key binding for anti-MITM when joining a repository on a host you do not
  operate (section 9).

### Repository

- Canonical `proto/avp.proto`, an HTTP/JSON JSON Schema, and deterministic conformance vectors.
- A worked end-to-end example flow with representative message bodies.
- Reference server and client implementations under `examples/<language>/`.
- `llms.txt`, contributing and security guides, and a CI gate enforcing vendor neutrality.
