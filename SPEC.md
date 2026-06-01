# Alt Vault Protocol (AVP) — Specification

**Version:** 0.2 (draft)
**Status:** stable wire contract; see §12 for open items.

AVP lets independent Minecraft clients share alt accounts through a zero-knowledge server. This document
is the normative contract. An implementation is *conformant* if it satisfies every MUST here and passes
the vectors in [`vectors/`](vectors/).

## 1. Overview

A **repository** ("repo") is a shared, end-to-end-encrypted collection of alt accounts with a set of
**members**. A member is an Ed25519 keypair. The repo has a single symmetric **data key** that encrypts
the alt payload; the data key is wrapped to each member's X25519 public key. A **server** stores the
encrypted payload, the per-member wrapped keys, the members' public keys, and version/epoch counters —
and nothing it can decrypt. All cryptography happens on the client.

Repositories are **federated**: each is addressed `avp://host/repoId`, and a member's keypair
authenticates against any conformant server, so a member can join and sync a repository hosted anywhere.

## 2. Conventions

- The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as in RFC 2119.
- All binary values on the wire are **base64** (standard alphabet, with padding) unless stated otherwise.
- "Ed25519 public key" / "X25519 public key" mean the **raw 32-byte** encodings (RFC 8032 / RFC 7748),
  base64-encoded. A member's **id** is its base64 Ed25519 public key.
- JSON field names in the HTTP/JSON profile are exactly the proto field names rendered in `camelCase`.
- Times are epoch milliseconds (`int64`) unless noted.

## 3. Identity and authentication

Members are identified by an **Ed25519 keypair, not an account**. Authentication is a challenge→token
flow that yields a bearer token scoping the caller to the repositories it is a member of. The token is
minted by an **identity provider (IdP)** and verified by the vault server.

1. `challenge { ed25519PublicKey } → { nonce }` — the server returns a single-use random **nonce** (at
   least 32 bytes, base64) with a short TTL (RECOMMENDED ≤ 2 minutes).
2. `token { ed25519PublicKey, nonce, signature } → { token, expiresAt }` — the client signs the **raw
   nonce bytes** (the bytes obtained by base64-decoding `nonce`) with its Ed25519 private key. The IdP
   MUST verify the signature against `ed25519PublicKey`, MUST reject a reused or expired nonce, and then
   mints a token whose subject is the member id.

The reference token is a JWT with claims `{ "sub": "key:" + ed25519PublicKey, "kind": "keypair" }` and no
account/email/role claims, verifiable via the IdP's published key set (e.g. JWKS). A vault server
authorizes each operation by matching the token subject (with the `key:` prefix stripped) against repo
membership; it MUST NOT require any account lookup.

A token is **server-local**: it is minted by, and valid only at, the server that issued it. A client
MUST cache tokens keyed by host and MUST NOT present a token issued by one host to another (see §8).

## 4. Cryptographic envelope

Field names are part of the contract. All values are base64 strings unless typed otherwise.

- **`WrappedKey`** = `{ schemeId, ephemeralPublicKey, iv, ciphertext }` — the repo data key encrypted to
  one member under the named wrap scheme.
- **`MemberEntry`** = `{ ed25519PublicKey, x25519PublicKey, wrappedDataKey: WrappedKey, keyEpoch: int64,
  keyBindingSig? }` — a member as the server stores it. `keyBindingSig` is OPTIONAL (§9); `null`/absent
  when no binding is published.
- **`EncryptedEnvelope`** = `{ repoId, payloadVersion: int64, keyEpoch: int64, iv, ciphertext }` — the
  encrypted alt payload at a given version and epoch.
- **`VaultManifest`** = `{ repoId, schemeId, keyEpoch: int64, payloadVersion: int64,
  members: MemberEntry[] }` — the non-secret repository metadata.

The data key is per-repo and symmetric. The payload AEAD is AES-256-GCM (12-byte IV, 128-bit tag) or an
equivalent AEAD named by `schemeId`. The **additional authenticated data (AAD)** bound into every
payload ciphertext is the tuple `(repoId, payloadVersion, keyEpoch)`. Because the AAD is part of
interoperable ciphertext, its byte layout is fixed:

```
AAD = UTF8(repoId) || 0x1F || int64BE(payloadVersion) || int64BE(keyEpoch)
```

that is, the UTF-8 bytes of `repoId`, a single `0x1F` separator byte, then the big-endian 8-byte
two's-complement encodings of `payloadVersion` and `keyEpoch`. A conformant encoder MUST bind all three
this way, so that an envelope replayed under a different repo, version, or epoch fails authentication.
See [`vectors/aad.json`](vectors/aad.json).

The default wrap scheme has `schemeId` **`X25519-HKDF-SHA256-AESGCM-v1`**: generate an ephemeral X25519
keypair, ECDH with the recipient's X25519 key, derive an AES-256 key with HKDF-SHA256, and AES-256-GCM
encrypt the 32-byte data key. `WrappedKey.ephemeralPublicKey` is the ephemeral X25519 public key.

## 5. Payload and provenance

The plaintext inside `EncryptedEnvelope.ciphertext` is a JSON object:

```json
{ "alts": [ <AltAccount>, ... ], "payloadVersion": <int64> }
```

`payloadVersion` here is a redundant stamp; the authoritative version is the envelope header (bound into
the AAD). An **`AltAccount`** is:

```json
{
  "uuid": "<player uuid>",
  "username": "<last known name>",
  "accessToken": "<credential>",
  "type": "MICROSOFT | COOKIE | SESSION | OFFLINE",
  "lastUsed": <int64>,
  "lastUsedBy": "<member id or null>",
  "ban": { "banned": <bool>, "observedAt": <int64>, "source": "...", "detail": "...", "observedBy": "<member id or null>" } | null,
  "sourceClient": "<client name or null>",
  "sourceUser": "<user within that client or null>"
}
```

**Provenance.** `sourceClient` / `sourceUser` identify which client an alt was added from and the user
within that client (for example a client id and a user handle). They are plain, opaque,
implementer-defined strings; this specification defines only the field names, never their values. They
let a cross-client repository attribute each alt. Because they live **inside the encrypted payload**, the
server never sees them — cross-client attribution does not weaken the zero-knowledge guarantee.
Implementations SHOULD set them when adding an alt and MUST tolerate their absence (older payloads, or
clients that do not attribute).

`lastUsedBy` / `ban.observedBy` are member ids (base64 Ed25519 keys) or `null`; they let members
coordinate (who used an alt last, who observed it banned) so a teammate is not handed a banned account.

## 6. Transport surface

The vault operations below carry a bearer token (§3). Authentication (`challenge`/`token`) is typically
HTTP/JSON to the IdP but MAY be offered over gRPC; the data operations are the vault service.

| Operation | Request → Response | Authorization |
|---|---|---|
| `createRepo` | `CreateRepoRequest { manifest, initialEnvelope }` → `VaultManifest` | `manifest.members` MUST contain exactly one member whose key equals the caller |
| `pull` | `PullRequest { repoId, knownPayloadVersion }` → `PullResponse { manifest, envelope?, unchanged }` | caller is a member |
| `push` | `PushRequest { repoId, envelope, expectedPayloadVersion, rotatedMembers? }` → `PushResponse { accepted, payloadVersion, keyEpoch, conflict }` | caller is a member |
| `addMember` | `MemberAddRequest { repoId, member }` → `VaultManifest` | caller is a member (v1 policy: any member may invite) |
| `removeMember` | `MemberRemoveRequest { repoId, removedMemberId, rotatedEnvelope, rewrappedMembers, newKeyEpoch }` → `VaultManifest` | caller is a member |
| `fetchMemberKey` | `{ repoId, memberId }` → `MemberEntry` | caller is a member |

Semantics:

- **createRepo** — create from a client-built manifest + initial payload. The server MUST reject a
  manifest whose sole member is not the caller, and MUST reject a duplicate `repoId`.
- **pull** — if `knownPayloadVersion` equals the current version, the server returns
  `{ manifest, unchanged: true }` and SHOULD omit `envelope`; otherwise it returns the manifest and the
  current envelope.
- **push** — optimistic concurrency: the write applies only if `expectedPayloadVersion` equals the
  current version; otherwise the server returns `{ accepted: false, conflict: true }` with the current
  version and the client MUST pull, re-apply, and retry. `payloadVersion` is monotonic per repo. If
  `rotatedMembers` is present, the server replaces the member roster atomically with the write (the
  rotation path).
- **addMember** — record a member whose wrapped key the *client* computed (the server cannot wrap).
- **removeMember** — in one atomic step: drop `removedMemberId`, replace the roster with
  `rewrappedMembers`, store `rotatedEnvelope`, and set the epoch to `newKeyEpoch`.
- **fetchMemberKey** — return a member's `MemberEntry` (its public keys and any `keyBindingSig`).

### Profiles

- **gRPC** — [`proto/avp.proto`](proto/avp.proto) is canonical. Field numbers and names are stable.
- **HTTP/JSON** — one path per operation (e.g. `POST /v1/repos`, `POST /v1/repos/{repoId}/pull`, …), JSON
  bodies using the proto field names in `camelCase`, the token in `Authorization: Bearer <token>`. The
  conformance schema is [`schema/avp.schema.json`](schema/avp.schema.json). Implementations MAY support
  either or both profiles; the message semantics are identical.

## 7. (reserved)

## 8. Federation

AVP federates by **portable identity + addressing**, not server-to-server replication.

- **Address.** A repository is globally identified by `(host, repoId)` and rendered as the URI
  `avp://<host>/<repoId>`, where `<host>` is an authority (`host` or `host:port`) and `<repoId>` is the
  exact opaque id the server minted. The id MUST NOT encode the host (so manifests and AAD are
  host-independent).
- **Portable identity.** A member's Ed25519 keypair authenticates against any conformant server (§3).
  Tokens are per-host (§3); a client MUST scope them by host.
- **Reaching a repo.** To use a repository, a client connects to its `host` (resolving how to dial it —
  see discovery below) and authenticates with its own keypair.

### 8.1 Join handshake

Because adding a member is member-initiated (an existing member wraps the data key to the joiner's
X25519 key), the joiner publishes its keys first. Two base64url-encoded JSON tokens:

1. **Invite request** (joiner → inviter): `{ "v": 1, "ed25519PublicKey", "x25519PublicKey" }` — the
   joiner's public keys. The inviter calls `addMember` with them.
2. **Repo locator** (inviter → joiner): `{ "v": 1, "host", "repoId", "schemeId", "keyEpoch",
   "issuerJwksUrl"? }` — where the repository lives, plus the IdP whose key bindings to trust (§9).
   `schemeId`/`keyEpoch` are hints; the authoritative values come from the pulled manifest.
   `issuerJwksUrl` MAY be absent when the deployment publishes no key binding.

Tokens are base64url (RFC 4648 §5, no padding) over the compact JSON above. They carry only public data
and are safe to relay over any channel.

### 8.2 Discovery (optional)

A server MAY expose an unauthenticated `GET /.well-known/avp` returning at least
`{ "profiles": ["grpc"|"http-json", ...], "issuerJwksUrl": "..." }` so that a client resolving an
`avp://` address knows which transport profile(s) to use and which IdP to trust. Absent discovery, a
client SHOULD default to the HTTP/JSON profile over HTTPS and to the issuer named out of band (e.g. in a
repo locator).

### 8.3 Server-to-server

Reaching a repository through a server that does not host it (replication/relay) is **out of scope** for
this version and is a possible future extension.

## 9. Anti-MITM key binding

A hostile or compromised server could serve a wrong X25519 public key for a member id on
`fetchMemberKey`, tricking another member into wrapping the data key to an attacker. To defend against
this when joining a repository on a server one does not operate:

- An IdP MAY publish a **key binding**: an Ed25519 signature, made with the IdP's key, over the member's
  two public keys. The canonical signed message is the member's base64 Ed25519 key, a single `|`
  (U+007C), then its base64 X25519 key, UTF-8 encoded:
  `bindingMessage = utf8( ed25519PublicKey + "|" + x25519PublicKey )`.
- The signature is carried as `MemberEntry.keyBindingSig` (base64), stored and served opaquely by the
  server.
- A client SHOULD verify `keyBindingSig` against the IdP's public key (from `issuerJwksUrl`, §8.1) before
  wrapping a data key to a served `MemberEntry`. This SHOULD becomes a **MUST** when the repository's
  host is one the client does not itself operate.

This is additive and zero-knowledge-safe: a public-key signature, never a secret.

## 10. Invariants

A conformant server MUST uphold:

- **Zero-knowledge.** The server MUST NOT receive, store, or log a passphrase, identity seed, data key,
  or plaintext alt. It stores only ciphertext, base64 wrapped-key blobs, raw public keys, counters, and
  opaque signatures. After a full create+push, no stored value decodes to a plaintext alt field.
- **Optimistic concurrency.** Every `push` is gated on `expectedPayloadVersion`; a stale writer receives
  `conflict`. `payloadVersion` is strictly monotonic per repo.
- **Rotation correctness.** `removeMember` increments `keyEpoch`; a removed member's old wrapped key
  cannot derive the new epoch's data key, and the AAD makes a stale-epoch ciphertext fail
  authentication.

## 11. Conformance

An implementation is conformant if it satisfies every MUST above and reproduces the vectors in
[`vectors/`](vectors/) (canonical AAD/binding-message construction, challenge/sign/token, key wrap/unwrap,
and rotation). See [`vectors/README.md`](vectors/README.md).

## 12. Security considerations and open items

- **Algorithm negotiation.** `schemeId` names the AEAD/KDF/wrap scheme; the choreography for upgrading a
  repository's scheme over its lifetime is not yet specified.
- **Cross-IdP trust (federation).** §9 lets a client verify member key bindings against a single IdP
  named out of band (the repo locator's `issuerJwksUrl`). In full federation the signing IdP is itself
  per-server; trusting bindings across multiple IdPs (pinned-issuer sets, web-of-trust) is deferred.
- **Token theft.** Tokens are bearer credentials; transport MUST be TLS. Tokens are per-host (§3), short
  lived, and scoped to membership.
- **Nonce handling.** Challenge nonces MUST be single-use with a short TTL to prevent replay of the
  signed-challenge step.
