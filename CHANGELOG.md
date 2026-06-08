# Changelog

Notable changes to the Alt Vault Protocol (AVP) and this repository. The format follows
[Keep a Changelog](https://keepachangelog.com/). The protocol version is independent of any
implementation's version.

## [Unreleased]

### Specification

- Clarified that an issuer MAY require out-of-band authentication and embed deployment-specific claims
  on the `token` grant, and that a server MAY return implementation-defined resource or policy errors
  such as quota limits; both non-normative (SPEC sections 3 and 6).

### Repository

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
