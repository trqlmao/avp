# Implementing AVP

A language-agnostic guide to building a conformant Alt Vault Protocol client and server.
Start here; read SPEC.md for normative detail.

## 1. Overview

You are building two things:

- **A client** that generates keypairs, authenticates, and performs all cryptography: encrypting
  the alt payload, wrapping the data key per recipient, and deriving the AAD that ties ciphertext
  to a specific repo, version, and epoch.
- **A zero-knowledge server** that stores and returns what the client sends and nothing else. The
  server never receives a plaintext alt, a passphrase, or the data key. The only cryptography
  it performs is verifying the Ed25519 challenge signature.

The **HTTP/JSON transport profile** (one `POST` per operation, proto field names in `camelCase`,
`Authorization: Bearer <token>`) is the most portable starting point. A gRPC profile exists (see
[`proto/avp.proto`](proto/avp.proto)) and is interchangeable at the message level; pick one.

Conformance means two things:

1. Reproduce the deterministic and RFC-anchored vectors in [`vectors/`](vectors/) byte-for-byte.
2. Pass cross-language wire interop: your client runs against another implementation's server and
   vice versa (see [§6 Conformance checklist](#6-conformance-checklist)).

## 2. Identity and authentication (SPEC §3)

Every member is an **Ed25519 keypair**. The raw 32-byte public key, standard base64-encoded, is
the member id and is used everywhere on the wire.

### Keypair generation

Generate a fresh Ed25519 keypair per member. The member id is `base64(raw_ed25519_pub)` using
standard base64 with padding. Store the private key locally; never send it.

Each member also needs an **X25519 keypair** for data-key wrapping (§4). Generate it separately;
the two public keys together form the member's published identity.

### Authentication flow

```
POST /api/auth/keypair/challenge
  body: { "ed25519PublicKey": "<base64>" }
  response: { "nonce": "<base64>" }

POST /api/auth/keypair/token
  body: { "ed25519PublicKey": "<base64>", "nonce": "<base64>", "signature": "<base64>" }
  response: { "token": "<bearer>", "expiresAt": <ms> }
```

The signature step: base64-**decode** the `nonce` string to raw bytes, then Ed25519-sign those
raw bytes with the member's private key. Pass the base64-encoded signature. A common mistake is
signing the base64 string instead of the decoded bytes; the server rejects it.

Tokens are **server-local**: do not present a token from one host to another. Cache tokens keyed
by host and refresh when they expire.

## 3. The cryptographic envelope (SPEC §4)

### 3a. Additional authenticated data (AAD)

Every payload ciphertext binds (repoId, payloadVersion, keyEpoch) in a fixed byte layout:

```
AAD = UTF8(repoId) || 0x1F || int64BE(payloadVersion) || int64BE(keyEpoch)
```

That is: the UTF-8 bytes of `repoId`, then a single byte `0x1F` (ASCII unit separator), then
`payloadVersion` as a big-endian 8-byte two's-complement integer, then `keyEpoch` the same way.

Vectors: [`vectors/aad.json`](vectors/aad.json).
Reference: `BuildAAD` in [`examples/go/avp/crypto.go`](examples/go/avp/crypto.go).

### 3b. Payload AEAD

The alt payload is AES-256-GCM with a **12-byte IV** and the **16-byte authentication tag
appended** to the ciphertext (not separate). Use the AAD from §3a. A fresh random IV is
generated per write.

The `EncryptedEnvelope` wire type is `{ repoId, payloadVersion, keyEpoch, iv, ciphertext }`,
all base64.

Vectors: [`vectors/payload-aead.json`](vectors/payload-aead.json).
Reference: `EncryptPayload` / `DecryptPayload` in [`examples/go/avp/crypto.go`](examples/go/avp/crypto.go).

### 3c. HKDF-SHA256 (RFC 5869)

HKDF is used to derive the key-encryption key (KEK) in the wrap scheme. When the salt is empty,
it is replaced by 32 zero bytes (RFC 5869 §2.2). In the wrap scheme (§3d) the salt is never
empty (it is the ephemeral public key).

Vectors: [`vectors/hkdf.json`](vectors/hkdf.json) - includes RFC 5869 Appendix A.1 and A.3
(the zero-salt case).
Reference: `HKDFSHA256` in [`examples/go/avp/crypto.go`](examples/go/avp/crypto.go).

### 3d. Data-key wrap: X25519-HKDF-SHA256-AESGCM-v1

To wrap the 32-byte data key to a recipient whose X25519 public key is `recipientPub`:

1. Generate a fresh ephemeral X25519 keypair `(ephemeralPriv, ephemeralPub)`.
2. `sharedSecret = X25519(ephemeralPriv, recipientPub)` - the raw 32-byte ECDH output,
   **not hashed**.
3. `KEK = HKDF-SHA256(ikm=sharedSecret, salt=ephemeralPubRaw, info=UTF8("avp/rdk-wrap/v1"), L=32)`.
   `ephemeralPubRaw` is the raw 32-byte little-endian X25519 public key.
4. Pick a fresh 12-byte `iv`.
   `ciphertext = AES-256-GCM(key=KEK, iv=iv, aad=UTF8("avp/rdk-wrap/v1"), plaintext=dataKey)`
   with the 16-byte tag appended.
5. `WrappedKey = { schemeId, ephemeralPublicKey: base64(ephemeralPubRaw), iv: base64(iv), ciphertext: base64(ciphertext) }`.

To **unwrap**: recompute `sharedSecret = X25519(recipientPriv, ephemeralPub)` and the same KEK,
then AES-256-GCM-decrypt with the same `aad`.

The `info` string `"avp/rdk-wrap/v1"` is the scheme label and is used as both the HKDF `info`
and the GCM AAD - it must be identical in every implementation.

Vectors: [`vectors/x25519.json`](vectors/x25519.json) (the shared secret) and
[`vectors/key-wrap.json`](vectors/key-wrap.json) (the full composition).
Reference: `WrapDataKey` / `UnwrapDataKey` in [`examples/go/avp/crypto.go`](examples/go/avp/crypto.go).

### Encoding rule

All key, IV, ciphertext, signature, and nonce bytes on the wire are **standard base64 with
padding** (RFC 4648 §4). The only exception is the federation tokens in SPEC §8 (the invite
request and repo locator), which use **base64url without padding** (RFC 4648 §5). Do not
mix them: standard base64 uses `+` and `/`; base64url uses `-` and `_`. A base64 member id
contains `+`, `/`, and `=` characters and must be URL-percent-encoded when it appears in a path
segment.

## 4. Key binding (SPEC §9)

An identity provider (IdP) MAY sign each member's two public keys to let a joiner verify that
the server is serving the right keys. The canonical signed message is:

```
bindingMessage = UTF8(ed25519PublicKey + "|" + x25519PublicKey)
```

where both keys are their standard base64 wire forms. The `|` is a literal U+007C.

Vectors: [`vectors/key-binding-message.json`](vectors/key-binding-message.json).
Reference: `KeyBindingMessage` in [`examples/go/avp/crypto.go`](examples/go/avp/crypto.go).

When joining a repository on a server you do not operate, verify `MemberEntry.keyBindingSig`
against the IdP's public key (from the repo locator's `issuerJwksUrl`) before wrapping the
data key to that member entry.

## 5. Wire contract

### Routes (HTTP/JSON profile)

All bodies are JSON with proto field names in `camelCase`. Routes other than the two auth routes
require `Authorization: Bearer <token>`. The machine-readable route description, with every status code
and the error body, is [`openapi.yaml`](openapi.yaml) (OpenAPI 3.1); generate a client or server stub
from it if your stack supports it.

| Method + path | Request -> Response |
|---|---|
| `POST /api/auth/keypair/challenge` | `{ ed25519PublicKey }` -> `{ nonce }` |
| `POST /api/auth/keypair/token` | `{ ed25519PublicKey, nonce, signature }` -> `{ token, expiresAt }` |
| `POST /v1/repos` | `{ manifest, initialEnvelope }` -> `VaultManifest` |
| `POST /v1/repos/{repoId}/pull` | `{ repoId, knownPayloadVersion }` -> `{ manifest, envelope?, unchanged }` |
| `POST /v1/repos/{repoId}/push` | `{ repoId, envelope, expectedPayloadVersion, rotatedMembers? }` -> `{ accepted, conflict, payloadVersion, keyEpoch }` |
| `POST /v1/repos/{repoId}/add-member` | `{ repoId, member }` -> `VaultManifest` |
| `POST /v1/repos/{repoId}/remove-member` | `{ repoId, removedMemberId, rotatedEnvelope, rewrappedMembers, newKeyEpoch }` -> `VaultManifest` |
| `GET /v1/repos/{repoId}/member/{memberId}` | -> `MemberEntry` |

Note: `memberId` in the path is the base64 Ed25519 public key. Because it contains `+`, `/`, and
`=`, it must be percent-encoded in the URL and the server must use the *escaped* path when routing
(do not let the router unescape before matching the path separator).

### Status codes

| Code | Meaning |
|---|---|
| `200` | Success |
| `401` | Missing or invalid token, or an expired/bad challenge nonce |
| `403` | Token is valid but the caller is not a member of the repo |
| `404` | Repo or member not found |
| `409` | Duplicate `repoId` on create |

Every non-2xx response body is an error object: `{ "error": "<message>", "code": "<machine code>",
"detail": "<optional>" }`. `error` is human-readable (do not parse it); `code` is an optional stable
token (`unauthorized`, `forbidden`, `not_found`, `duplicate_repo`, `quota_exceeded`, `policy_denied`,
`bad_request`) you may switch on. Treat all of them as **terminal** — see the concurrency note below for
the one outcome that is *not* an error.

Optimistic concurrency: `push` returns `{ "accepted": false, "conflict": true }` with the
current version when `expectedPayloadVersion` does not match. A client must pull, re-apply, and
retry; this is not a `4xx` status code.

### Zero-knowledge rule

The server stores and echoes back `iv`, `ciphertext`, `ephemeralPublicKey`, and `wrappedKey`
fields verbatim, as opaque base64 strings. It never decrypts them. The only cryptographic
operation the server performs is verifying the Ed25519 challenge signature in the
`token` step.

## 6. Conformance checklist

1. **Reproduce the deterministic vectors byte-for-byte.** The AAD layout
   (`vectors/aad.json`) and the key-binding message (`vectors/key-binding-message.json`) are
   pure string/byte constructions with no key material. They must match exactly.

2. **Reproduce the RFC-anchored primitive vectors.** `vectors/hkdf.json` pins HKDF to RFC 5869
   test cases; `vectors/x25519.json` pins X25519 to RFC 7748 vectors; `vectors/ed25519.json` pins
   Ed25519 to RFC 8032 vectors. Every conformant implementation must reproduce these published
   outputs.

3. **Round-trip the composition vectors.** `vectors/payload-aead.json` and `vectors/key-wrap.json`
   contain fixed-key ciphertexts generated from the RFC-anchored primitives. Decrypt the
   `payload-aead` case and recover the plaintext; unwrap the `key-wrap` case and recover the data
   key. Also verify that decryption fails when the `keyEpoch` in the AAD is changed (rollback
   protection).

4. **Cross-language wire interop.** Run your client against another implementation's server, and
   another implementation's client against your server. The
   [`.github/workflows/examples-interop.yml`](.github/workflows/examples-interop.yml) workflow
   does this for all five reference examples and is a useful model.

5. **Black-box your server.** Point the conformance harness in [`harness/`](harness/) at your running
   server (`bun harness/conformance.ts --server http://localhost:PORT`). It drives the whole flow and
   asserts the normative MUSTs — the auth failure modes, optimistic-concurrency `conflict`, membership
   authorization, key rotation, and zero-knowledge (the plaintext never surfaces in what the server
   stores). CI runs it against the Go and TypeScript reference servers.

## 7. Reference implementations

All five examples implement the real envelope and key-wrap crypto, each verified byte-for-byte
against `vectors/`. Go and TypeScript are the fullest worked references for the cryptographic
core and the full server-client flow.

| Language | Server | Client |
|---|---|---|
| Go | [`examples/go/server/`](examples/go/server/) | [`examples/go/client/`](examples/go/client/) |
| TypeScript | [`examples/typescript/server/`](examples/typescript/server/) | [`examples/typescript/client/`](examples/typescript/client/) |
| Rust | [`examples/rust/server/`](examples/rust/server/) | [`examples/rust/client/`](examples/rust/client/) |
| Python | [`examples/python/server/`](examples/python/server/) | [`examples/python/client/`](examples/python/client/) |
| Java | [`examples/java/server/`](examples/java/server/) | [`examples/java/client/`](examples/java/client/) |

The Go crypto package ([`examples/go/avp/crypto.go`](examples/go/avp/crypto.go)) is a
self-contained, pure-standard-library implementation of every construction in §3 and §4; read it
alongside the vectors if you are stuck on a subtlety. The conformance runner
([`examples/conformance/`](examples/conformance/)) independently checks every vector with
Node's `crypto` and is a useful second reference for the byte-level expectations.
