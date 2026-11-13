# Changelog

Notable changes to the Alt Vault Protocol (AVP) and this repository. The format follows
[Keep a Changelog](https://keepachangelog.com/). The protocol version is independent of any
implementation's version.

## [0.5] - 2026-11-13

Multi-host repositories. A repository now lives on several hosts that replicate it with each other, an
owner holding a BIP39 recovery phrase signs every membership, policy, and host change, every write is a
member-signed commit, and concurrent writes merge per field instead of conflicting. 0.5 is a **breaking**
version: it is not wire compatible with 0.4 servers, payloads, or vectors, and no migration path is
specified. `SPEC.md` was rewritten; the section numbers below are 0.5's.

### Specification

- **Strict Ed25519** (section 2): every verified signature rejects small-order and non-canonical `A` and
  `R` and `S >= L` before any other check, then uses the cofactorless equation `[S]B = R + [k]A` with `R`
  compared by encoding, so every conformant implementation accepts exactly the same signatures.
- **Owner identity** (section 3.1): a 24-word BIP39 phrase (256-bit entropy, English wordlist, empty
  passphrase) derives the owner Ed25519 and X25519 keys by HKDF-SHA256 with the labels
  `avp/owner/ed25519/v1` and `avp/owner/x25519/v1`. The phrase is the identity; it never reaches a host.
- **Host keys and host-issued authentication** (section 3.3): each host has an Ed25519 host key, every
  host match compares keys, and each host mints its own host-local bearer tokens for any key that signs
  its challenge. There is no external identity provider. The client signs the transcript
  `CE(tag "avp/challenge/v1", bytes(hostKey), bytes(ed25519PublicKey), bytes(nonce))`, not the raw nonce
  as in 0.4, so a host cannot pick a nonce that is another construction's message, and every signed
  construction has its own tag (section 4.1).
- **Canonical encoding** (section 4.1): one deterministic byte writer (`tag`, `bytes`, `str`, `i64`,
  `bool`, `count`, sorted lists) for every signed or hashed structure; no JSON canonicalization anywhere.
- **Manifest chain** (sections 4.2, 6): owner-signed, hash-linked states carrying the members, wrapped
  data keys, key epoch, `shareRefreshTokens` (now covered by the owner signature, closing 0.4's manifest
  authentication open item), the hosts, and cumulative removals. `repoId` is derived from the owner key
  and a genesis nonce and never encodes a host. Clients pin the highest verified state (rollback
  protection); diverged owner states resolve by the bytewise-lower `manifestHash`, with commits citing a
  losing state re-checked, accepted, or held until the owner decides.
- **Commit graph and AAD v2** (sections 4.3, 7): commits name their parents, cite their manifest state by
  seq and hash, and are signed by their author over a `commitId` that covers the ciphertext. AAD v2 binds
  `repoId`, `keyEpoch`, `author`, and the sorted parents. Hosts keep every head, bound them (RECOMMENDED
  16, new code `too_many_heads`), and answer unknown parents with `422 missing_parents`.
- **Removal cutoff** (sections 7.3, 8.3): removing a member rotates the data key and signs a frontier;
  afterwards a commit by the removed member is accepted only if it is in the frontier or an ancestor of
  it, which closes backdating. A commit the cutoff dropped counts as rejected, so its children are
  rejected too. An epoch-raising state and its rotation commit are adopted atomically.
- **Payload v2 and merge** (section 5): every account field and ban carries an `(at, n, by)` stamp from a
  hybrid logical clock; heads merge per field and per ban server id, deletion is a stamped marker that a
  later edit revives, and refresh-token stripping removes the fields with their stamps.
- **Membership operations** (section 8): invites go through `prepareJoin` and a host-signed acceptance in
  the invite token, so an owner adds a host only with that host's consent; members can leave with a
  signed leave request; policy and host-set changes are owner-signed states; a dropped host stops serving
  the repository.
- **Replication between hosts** (section 9): `heads`, `fetch`, and `offer`, with every received item
  validated by the client-write rules and the hosted check applied to the received tip. The reference
  profile is signed HTTP/JSON (`AVP-Host-Key`, `AVP-Host-Time`, `AVP-Host-Signature`, 60 s skew), and a
  host on it MUST send host requests for a repository only to the peers its tip lists. The proto adds a
  `Replication` service for a gRPC profile.
- **Transport and errors** (section 10): new routes `POST /v1/repos/{repoId}/manifest`, `.../leave`,
  `POST /v1/prepare-join`, and the three `/v1/host/repos/{repoId}/...` routes; `pull` and `push` take and
  return commits and heads; discovery adds `hostKey`. New error codes `not_hosted`, `too_many_heads`,
  `manifest_conflict`, and `missing_parents`. A request target that cannot be parsed as a path MAY get a
  bare `400` without the error body.
- **Tokens and device linking** (section 11): `RepoLocator`, `InviteToken` with `Acceptance`,
  `LeaveRequest`, and owner device linking (`LinkRequest`, a 6-digit confirmation code, and a `LinkGrant`
  wrapping the phrase entropy under `avp/owner-link/v1`), all `"v": 2`. Member and owner fingerprints.
- **Invariants, conformance, open items** (sections 13 to 15): owner authority, chain and commit
  integrity, rotation atomicity, no lost writes, and hosts matched by key are invariants. Open items are
  algorithm negotiation, ownership transfer, deletion-marker GC and commit pruning, and host freshness
  against a withholding host. `THREATMODEL.md` was rewritten to match (stolen owner phrase, diverged owner
  devices, replication).
- `proto/avp.proto`, `schema/avp.schema.json`, and `openapi.yaml` describe the 0.5 messages and routes;
  `openapi.yaml` `info.version` is `0.5`.

### Vectors

- Added `bip39-english.txt` (the pinned BIP39 English wordlist) and `bip39-owner.json` (entropy to
  mnemonic, seed, and owner keys, anchored to the Trezor BIP39 reference vectors).
- Added `manifest.json` (CE bytes, owner signature, `manifestHash`, `repoId`) and `commit.json` (header
  bytes, `commitId`, author signature, AAD v2, ciphertext), both independent of list input order.
- Added `merge.json` (every input order, idempotence, associativity, the HLC, deletion and revival,
  per-server bans, stripping after the policy is turned off) and `acceptance.json` (replayable host
  rule scenarios with each step's verdict and the final heads, held commits, tip, and leaves).
- Rewrote `federation.json` for the 0.5 tokens, leave signatures, link codes, fingerprints, and locators,
  and `negative.json` with 0.5 manifest, commit, AAD v2, link grant, acceptance, and leave cases plus the
  strict Ed25519 rejects.
- `vectors/generate.ts` derives every 0.5 file from documented seeds; `--check` is the drift gate.
  `hkdf.json`, `x25519.json`, `ed25519.json`, and `key-wrap.json` are unchanged.

### Examples

- Rebuilt the Rust and Java references around one shared library per language (`examples/rust/avp`,
  `examples/java/avp`) used by both the host and the client, each reproducing every vector and replaying
  `acceptance.json`.
- The reference hosts replicate with each other over signed HTTP/JSON and read `PORT`, `AVP_BIND`,
  `AVP_HOST_SEED`, `AVP_PEERS`, and `AVP_TEST_CONTROL`. The reference clients run the whole flow (owner
  phrase, create, invite with `prepareJoin`, merge, remove with a cutoff, leave, device linking) against
  one or two hosts.
- Rewrote the worked flow and example bodies (`create-repo-request.json`, `publish-manifest-request.json`,
  `push-request.json`, `pull-response.json`, `offer-request.json`), `IMPLEMENTING.md`, and the README for
  0.5.
- The black-box harness checks the 0.5 single-host contract (`harness/conformance.ts`) and adds
  multi-host scenarios (`harness/multihost.ts`) plus a launcher (`harness/run-hosts.sh`). CI runs both
  against the Rust and Java hosts, the multi-host suite in every language pairing, and each client
  against the other language's host.

### Removed

- The Go, Python, TypeScript, and TypeScript gRPC reference examples. They stopped at 0.4; see the
  `v0.4` tag.
- The 0.4 vectors `aad.json`, `key-binding-message.json`, and `payload-aead.json`, replaced by
  `commit.json`.
- From the protocol: optimistic concurrency on a payload version (`conflict`), the `addMember`,
  `removeMember`, and member-key routes, the identity-provider key binding (`keyBindingSig`,
  `issuerJwksUrl`), and the 0.4 AAD layout.

## [0.4] - 2026-07-28

Refresh-token sharing, gated by a per-repository opt-in, plus a per-server ban map. The transport
surface, the cryptographic envelope, and every conformance vector are unchanged from 0.3, so a 0.3
server needs no cryptographic work to serve 0.4 clients. Two things do not carry over silently. The
payload's single `ban` object became the `bans` map keyed by server id, a client-to-client payload change
the server never sees. And because the JSON Schema sets `additionalProperties: false` on both
`VaultManifest` and `AltAccount`, a peer validating against the 0.3 schema **rejects** the new fields
rather than ignoring them, so interoperating with a 0.4 peer means adopting the 0.4 schema. Servers
additionally MUST persist and return `shareRefreshTokens` (SPEC section 5.1): one that drops it disables
refresh-token sharing for every member of every repository it hosts, and does so without an error.

### Specification

- Changed the payload `AltAccount.ban` (a single ban object or `null`) to `bans`, a map from a server id
  to that server's most recent ban observation, or `null` (SPEC section 5, schema `$defs/AltAccount`).
  This lets a cross-client repository track that an alt is banned on one server but usable on another.
  The change is to the encrypted payload schema (server-invisible); it affects only client-to-client
  payload compatibility.
- Added optional `VaultManifest.shareRefreshTokens` (boolean, default `false`), a per-repository opt-in
  to sharing refresh tokens (SPEC section 5.1, `proto` field 6, schema `$defs/VaultManifest`). It is
  non-secret repository metadata that the server stores and serves alongside `schemeId`, `keyEpoch`, and
  `payloadVersion`. **A server MUST persist and return it.** A server that deserializes the manifest into
  a fixed record and drops unknown keys answers `200` while discarding the policy; the next `pull` then
  reports the field absent, every client reads that absence as `false`, and refresh tokens are stripped
  from that point on, leaving the owner with a successful write and a repository that silently withholds.
- Added optional `AltAccount.refreshToken` (string or `null`) and `AltAccount.expiresAt` (int64 epoch
  millis; absent or `0` means unknown) to the encrypted payload (SPEC section 5, schema
  `$defs/AltAccount`). A refresh token buys durable access to the underlying account rather than one
  bounded session, so it is carried only where the repository policy allows it. The server never sees
  either field.
- Specified the client duties around the policy (SPEC section 5.1): clients MUST tolerate the absence of
  all three fields and MUST read an absent, `null`, or unreadable `shareRefreshTokens` as `false` (fail
  closed, never open), and MUST strip `refreshToken`/`expiresAt` from payloads for a repository whose
  policy is not `true` on **read** as well as on write, so the policy holds even when a peer runs a
  modified build. Sharing is irrevocable: key rotation and `removeMember` protect future payloads only,
  and revocation is upstream at the issuing provider exclusively.
- Stated the limitation honestly rather than implying the policy is enforced: `shareRefreshTokens` is
  served by the sync server bound by neither a signature nor the payload AAD, so a compromised or
  malicious host can flip it and induce clients to upload refresh tokens on their next push with no
  signal to the owner who left it off. The policy binds members, not the host. Recorded as a new
  **Manifest authentication** open item (SPEC section 12) and in `THREATMODEL.md` (assets, A4, A5, A6,
  and the residual-risk list); closing it needs an owner-signed manifest plus local policy pinning and is
  deferred to a future version.

### Repository

- Fixed the Go reference implementation, which declared `VaultManifest` as a fixed struct and so silently
  dropped `shareRefreshTokens`: exactly the defect the specification now forbids. Added the field with
  its `json` tag (no `omitempty`, so the server always states the policy) plus two regression tests, one
  asserting the policy survives create, pull, push, and `addMember` in the raw response JSON, and one
  asserting a manifest sent without the key reads back as `false`. The Go server itself needed no change:
  it stores the manifest whole and mutates only counters and roster.
- Added `shareRefreshTokens` to the worked `create-repo-request.json` and `pull-response.json` bodies, so
  the example flow shows the policy being sent and returned. Documented the field on the TypeScript
  reference server's `VaultManifest` interface, and added a **Manifest passthrough rule** to
  `IMPLEMENTING.md` section 5 next to the zero-knowledge rule. The Java, Python, and Rust reference
  servers hold the manifest as an untyped map/dict/`Value` and the gRPC example loads the canonical proto
  dynamically, so all four carry the new field with no code change.

## [0.3] - 2026-06-08

Conformance tooling, a threat model, operational limits, and a runnable gRPC reference. The wire contract
is unchanged from 0.2, so existing 0.2 clients and servers stay conformant; the bump reflects the new
normative operational-limits section and error contract plus the matured repository surface.

### Specification

- Filled the reserved SPEC section 7 with **Operational limits and retries**: resource limits (with a
  `413`/`too_large` and `429`/`quota_exceeded` error contract), rate limiting (`Retry-After` and
  `RateLimit-*` headers), per-operation idempotency and safe-retry rules, and `repoId` charset/length
  guidance. Added `too_large` to the `$defs/Error` code enum and the `413`/`429` responses (with
  `Retry-After`/`RateLimit-*` headers) to `openapi.yaml`.
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
- Specified that the federation tokens (SPEC section 8.1) use minified JSON in the member order shown as
  the RECOMMENDED encoding, while a decoder MUST accept any valid JSON object with the required members.
- Added `THREATMODEL.md`, the adversary model (network, honest-but-curious and malicious server, insider,
  removed member, compromised IdP, stolen token/key), cryptographic assumptions, non-goals, and residual
  risks; linked from SPEC section 12 and `SECURITY.md`.

### Repository

- Added `llms-full.txt`, a single-file full-text bundle of the implementer guide, the specification, and
  the threat model for AI ingestion (the llmstxt.org "full" variant). It is generated by
  `scripts/build-llms-full.mjs` and gated by the `docs` workflow so it cannot drift from its sources;
  linked from `llms.txt`.
- Surfaced the implementer guide and the threat model in the site navigation (avp.trq.lol), with an
  active-page indicator.
- Added `examples/grpc/`, a runnable gRPC reference client and server that load the canonical
  `proto/avp.proto` dynamically (no codegen) and exercise all six `Vault` RPCs plus a challenge/token
  `Auth` service over one gRPC channel, with the real envelope crypto reused from the TypeScript example.
  The `examples-grpc` workflow runs it end to end. The canonical proto previously had no running code.
- Added `vectors/negative.json`, a MUST-reject bank, and a conformance test for it: valid payload-aead,
  key-wrap, and ed25519 constructions with one mutation each (flipped tag, bit flip, truncation, missing
  tag, wrong AAD repoId/version/epoch, wrong key, wrong recipient/ephemeral wrap key, wrong message/public
  key). Each MUST be rejected; reproducing the positive vectors is necessary but not sufficient.
- Added `vectors/generate.ts`, a reproducible derivation of every vector from documented seeds.
  `--check` re-derives the committed positive vectors and asserts they match (the provenance and drift
  gate, run in CI and by `task test`), and owns `negative.json` via `--write`. It reuses the vector-tested
  reference crypto so it cannot drift from the runner.
- Added `vectors/federation.json` and a conformance test for it: the base64url join-handshake tokens
  (invite request, repo locator) as a decode oracle plus canonical-encode round-trip, and `avp://`
  repository URI parse/format (SPEC section 8). Indexed in `vectors/index.json`.
- Added a black-box conformance harness in `harness/`: point it at any running server and it drives the
  full wire contract, asserting the normative MUSTs (auth failure modes, optimistic-concurrency
  conflict, membership authorization, key rotation, and zero-knowledge: the plaintext never surfaces in
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
