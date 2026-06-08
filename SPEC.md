# Alt Vault Protocol (AVP): Specification

**Version:** 0.2 (draft)
**Status:** stable wire contract; see §12 for open items.

AVP lets independent Minecraft clients share alt accounts through a zero-knowledge server. This document
is the normative contract. An implementation is *conformant* if it satisfies every MUST here and passes
the vectors in [`vectors/`](vectors/).

## 1. Overview

A **repository** ("repo") is a shared, end-to-end-encrypted collection of alt accounts with a set of
**members**. A member is an Ed25519 keypair. The repo has a single symmetric **data key** that encrypts
the alt payload; the data key is wrapped to each member's X25519 public key. A **server** stores the
encrypted payload, the per-member wrapped keys, the members' public keys, and version/epoch counters, and nothing it can decrypt. All cryptography happens on the client.

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

1. `challenge { ed25519PublicKey } → { nonce }`, the server returns a single-use random **nonce** (at
   least 32 bytes, base64) with a short TTL (RECOMMENDED ≤ 2 minutes).
2. `token { ed25519PublicKey, nonce, signature } → { token, expiresAt }`, the client signs the **raw
   nonce bytes** (the bytes obtained by base64-decoding `nonce`) with its Ed25519 private key. The IdP
   MUST verify the signature against `ed25519PublicKey`, MUST reject a reused or expired nonce, and then
   mints a token whose subject is the member id.

The reference token is a JWT with claims `{ "sub": "key:" + ed25519PublicKey, "kind": "keypair" }` and no
account/email/role claims, verifiable via the IdP's published key set (e.g. JWKS). A vault server
authorizes each operation by matching the token subject (with the `key:` prefix stripped) against repo
membership; it MUST NOT require any account lookup.

A token is **server-local**: it is minted by, and valid only at, the server that issued it. A client
MUST cache tokens keyed by host and MUST NOT present a token issued by one host to another (see §8).

**Issuer authentication policy (non-normative).** The `challenge`/`token` flow proves control of the
Ed25519 identity; it does not prescribe *who* may obtain a token. An issuer MAY require additional,
out-of-band authentication on the `token` request (for example, an existing account session presented
as a bearer credential) before minting a keypair token, and MAY embed additional deployment-specific
claims in the resulting JWT. Such requirements and claims are deployment policy: they do not alter the
`challenge`/`token` request or response shapes, and a conformant client that lacks the required
out-of-band credential simply receives an authentication failure. Conformant clients MUST ignore JWT
claims they do not recognize.

## 4. Cryptographic envelope

Field names are part of the contract. All values are base64 strings unless typed otherwise.

- **`WrappedKey`** = `{ schemeId, ephemeralPublicKey, iv, ciphertext }`, the repo data key encrypted to
  one member under the named wrap scheme.
- **`MemberEntry`** = `{ ed25519PublicKey, x25519PublicKey, wrappedDataKey: WrappedKey, keyEpoch: int64,
  keyBindingSig? }`, a member as the server stores it. `keyBindingSig` is OPTIONAL (§9); `null`/absent
  when no binding is published.
- **`EncryptedEnvelope`** = `{ repoId, payloadVersion: int64, keyEpoch: int64, iv, ciphertext }`, the
  encrypted alt payload at a given version and epoch.
- **`VaultManifest`** = `{ repoId, schemeId, keyEpoch: int64, payloadVersion: int64,
  members: MemberEntry[] }`, the non-secret repository metadata.

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

### Default wrap scheme: `X25519-HKDF-SHA256-AESGCM-v1`

This is the default `schemeId`. Keys are raw encodings: X25519 keys are the raw 32-byte little-endian
form (RFC 7748), and the 32-byte data key is the AES-256 key. To **wrap** a data key to a recipient
whose X25519 public key is `recipientPub`:

1. Generate a fresh ephemeral X25519 key pair `(ephemeralPriv, ephemeralPub)`.
2. `sharedSecret = X25519(ephemeralPriv, recipientPub)`, the raw 32-byte ECDH output (not hashed).
3. `KEK = HKDF-SHA256(ikm = sharedSecret, salt = ephemeralPubRaw, info = UTF8("avp/rdk-wrap/v1"), L = 32)`
   where `ephemeralPubRaw` is the raw 32-byte ephemeral public key and `KEK` is a 32-byte key. (HKDF is
   RFC 5869; the extract step uses 32 zero bytes when the salt is empty, but here the salt is never
   empty.)
4. Pick a fresh 12-byte `iv`. `ciphertext = AES-256-GCM(key = KEK, iv = iv, aad = UTF8("avp/rdk-wrap/v1"),
   plaintext = dataKey)`, with the 128-bit tag appended to the ciphertext.
5. `WrappedKey = { schemeId, ephemeralPublicKey: base64(ephemeralPubRaw), iv: base64(iv),
   ciphertext: base64(ciphertext) }`.

To **unwrap**, recompute `sharedSecret = X25519(recipientPriv, ephemeralPub)` and the same `KEK`, then
AES-256-GCM-decrypt with the same `aad`. The `info` string (`avp/rdk-wrap/v1`) is bound as both the HKDF
`info` and the GCM AAD; it is the vendor-neutral scheme label, identical for every implementation.

The conformance vectors in [`vectors/`](vectors/) pin each primitive and this composition byte-for-byte.

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
server never sees them, so cross-client attribution does not weaken the zero-knowledge guarantee.
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

- **createRepo**, create from a client-built manifest + initial payload. The server MUST reject a
  manifest whose sole member is not the caller, and MUST reject a duplicate `repoId`.
- **pull**, if `knownPayloadVersion` equals the current version, the server returns
  `{ manifest, unchanged: true }` and SHOULD omit `envelope`; otherwise it returns the manifest and the
  current envelope.
- **push**, optimistic concurrency: the write applies only if `expectedPayloadVersion` equals the
  current version; otherwise the server returns `{ accepted: false, conflict: true }` with the current
  version and the client MUST pull, re-apply, and retry. `payloadVersion` is monotonic per repo. If
  `rotatedMembers` is present, the server replaces the member roster atomically with the write (the
  rotation path).
- **addMember**, record a member whose wrapped key the *client* computed (the server cannot wrap).
- **removeMember**, in one atomic step: drop `removedMemberId`, replace the roster with
  `rewrappedMembers`, store `rotatedEnvelope`, and set the epoch to `newKeyEpoch`.
- **fetchMemberKey**, return a member's `MemberEntry` (its public keys and any `keyBindingSig`).

**Implementation-defined errors (non-normative).** Beyond the protocol-defined outcomes
(optimistic-concurrency `conflict`, *not found*, and membership *permission denied*), a server MAY
reject any operation with an implementation-defined resource or policy error, for example a quota
limit (repositories per tenant, members per repository) or an operation disallowed by deployment
policy. These are distinct from a concurrency `conflict`: a client MUST surface them as terminal
failures and MUST NOT retry them as if they were a stale-version conflict. Recommended encodings:
HTTP `429 Too Many Requests` / `403 Forbidden` for the JSON profile; gRPC `RESOURCE_EXHAUSTED` /
`PERMISSION_DENIED` for the gRPC profile.

### Errors

In the HTTP/JSON profile, any non-`2xx` response body is an **error object**:

```json
{ "error": "<human-readable message>", "code": "<machine code>", "detail": "<optional context>" }
```

`error` is a human-readable message and is always present; clients MUST NOT parse it. `code` is an
OPTIONAL stable machine-readable token (see the table) a client MAY switch on; when absent, the client
falls back to the HTTP status. `detail` is OPTIONAL extra context. The schema is
[`schema/avp.schema.json`](schema/avp.schema.json) `#/$defs/Error`; the full route surface, including
which status each operation can return, is [`openapi.yaml`](openapi.yaml).

| Status | `code` | Meaning |
|---|---|---|
| `400` | `bad_request` | Malformed body or parameters |
| `401` | `unauthorized` | Missing/invalid token, or an expired/reused challenge nonce |
| `403` | `forbidden` | Authenticated but not a member, or an operation disallowed by policy (`policy_denied`) |
| `404` | `not_found` | Repo or member does not exist |
| `409` | `duplicate_repo` | `createRepo` with an id that already exists |
| `429` | `quota_exceeded` | A deployment resource limit was hit |

A client MUST treat every error here as **terminal** and MUST NOT retry it as if it were a
stale-version conflict. The one retryable outcome (optimistic-concurrency conflict) is **not** an
error: `push` returns HTTP `200` with `PushResponse { accepted: false, conflict: true }` and the
current version (§10). The gRPC profile carries the same outcomes as status codes
(`INVALID_ARGUMENT`, `UNAUTHENTICATED`, `PERMISSION_DENIED`, `NOT_FOUND`, `ALREADY_EXISTS`,
`RESOURCE_EXHAUSTED`).

### Profiles

- **gRPC**, [`proto/avp.proto`](proto/avp.proto) is canonical. Field numbers and names are stable.
- **HTTP/JSON**, one path per operation (e.g. `POST /v1/repos`, `POST /v1/repos/{repoId}/pull`, …), JSON
  bodies using the proto field names in `camelCase`, the token in `Authorization: Bearer <token>`. The
  conformance schema is [`schema/avp.schema.json`](schema/avp.schema.json). Implementations MAY support
  either or both profiles; the message semantics are identical.

## 7. Operational limits and retries

Operational guidance for a deployment. Except where a MUST is stated, these are RECOMMENDED practice
rather than new wire contract; a server states its actual limits out of band (its documentation or its
discovery document, §8.2).

### 7.1 Resource limits

A server SHOULD bound, per its deployment policy, at least the size of an `EncryptedEnvelope`, the number
of members in a repository, and the number of repositories per tenant. When an operation would exceed a
limit, the server MUST reject it with a terminal resource error, not an optimistic-concurrency `conflict`
(§6 Errors): HTTP `413` (`too_large`) for an oversize body, or `429` (`quota_exceeded`) or `403`
(`policy_denied`) for a count or policy limit; gRPC `RESOURCE_EXHAUSTED` or `PERMISSION_DENIED`. A client
MUST surface these as failures and MUST NOT retry them as a stale-version conflict.

As non-normative starting points, a payload on the order of a few megabytes, a few hundred members, and a
per-tenant repository count in the low thousands are generous for the alt-sharing use case; deployments
tune these to their needs.

### 7.2 Rate limiting

A server MAY rate-limit any operation. When it does, it SHOULD return `429` with a `Retry-After` header
(delay-seconds or an HTTP-date) and MAY include the `RateLimit-Limit`, `RateLimit-Remaining`, and
`RateLimit-Reset` headers. A client SHOULD honor `Retry-After` before retrying, and SHOULD apply its own
backoff with jitter when it is absent. A rate-limit rejection is terminal for that attempt, not a
conflict.

### 7.3 Idempotency and retries

A client MAY retry an operation whose response it did not receive (for example after a dropped
connection). The protocol is designed so that this is safe:

- `pull` and `fetchMemberKey` are reads and are idempotent.
- `push` is guarded by `expectedPayloadVersion` (§6). A retry either applies once (if the first attempt
  did not) or returns `conflict` with the current version (if it did), so a push never double-applies; the
  client reconciles by pulling.
- `createRepo` is idempotent on `repoId`: a retry after a successful create returns `409`
  (`duplicate_repo`), and a client SHOULD treat a duplicate on its own create as success.
- `addMember` SHOULD be idempotent on the member id: re-adding a member already present, with the same
  keys, is a no-op that returns the current manifest.
- `removeMember` carries the post-rotation state (the new roster, envelope, and epoch). Re-sending the
  identical request before any intervening write sets the repository to the same target state and is
  therefore idempotent. A client that cannot confirm the outcome SHOULD `pull` and compare the epoch
  rather than blindly re-sending, because a removal that races another member's write must be recomputed
  against the newer version.

### 7.4 Repository identifiers

A `repoId` is an opaque, server-minted, non-empty string that MUST NOT encode the host (§8). A server
SHOULD mint it from the URL-unreserved characters (RFC 3986: `A-Z a-z 0-9 - . _ ~`, for example a UUID or
a base64url token) and SHOULD keep it at most 255 characters, so it needs no special handling in a path.
Regardless of how it is minted, because a `repoId` (and a base64 member id) can contain characters that
are reserved in a URI, a client MUST percent-encode it in a path segment and a server MUST route on the
escaped path (§6).

## 8. Federation

AVP federates by **portable identity + addressing**, not server-to-server replication.

- **Address.** A repository is globally identified by `(host, repoId)` and rendered as the URI
  `avp://<host>/<repoId>`, where `<host>` is an authority (`host` or `host:port`) and `<repoId>` is the
  exact opaque id the server minted. The id MUST NOT encode the host (so manifests and AAD are
  host-independent).
- **Portable identity.** A member's Ed25519 keypair authenticates against any conformant server (§3).
  Tokens are per-host (§3); a client MUST scope them by host.
- **Reaching a repo.** To use a repository, a client connects to its `host` (resolving how to dial it, see discovery below) and authenticates with its own keypair.

### 8.1 Join handshake

Because adding a member is member-initiated (an existing member wraps the data key to the joiner's
X25519 key), the joiner publishes its keys first. Two base64url-encoded JSON tokens:

1. **Invite request** (joiner → inviter): `{ "v": 1, "ed25519PublicKey", "x25519PublicKey" }`, the
   joiner's public keys. The inviter calls `addMember` with them.
2. **Repo locator** (inviter → joiner): `{ "v": 1, "host", "repoId", "schemeId", "keyEpoch",
   "issuerJwksUrl"? }`, where the repository lives, plus the IdP whose key bindings to trust (§9).
   `schemeId`/`keyEpoch` are hints; the authoritative values come from the pulled manifest.
   `issuerJwksUrl` MAY be absent when the deployment publishes no key binding.

Tokens are base64url (RFC 4648 §5, no padding) over the compact JSON above. They carry only public data
and are safe to relay over any channel. The RECOMMENDED encoding is minified JSON with members in the
order shown; a decoder MUST accept any valid JSON object that carries the required members, regardless of
member order or insignificant whitespace. See [`vectors/federation.json`](vectors/federation.json) for
byte-exact token and `avp://` URI vectors.

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
[`vectors/`](vectors/), indexed by [`vectors/index.json`](vectors/index.json):

- the **deterministic constructions**: the AAD layout (`aad.json`) and the canonical key-binding
  message (`key-binding-message.json`);
- the **RFC-anchored primitives**: HKDF-SHA256 (`hkdf.json`), X25519 (`x25519.json`), and Ed25519
  sign/verify (`ed25519.json`). The Ed25519 vector anchors the signature used by the challenge→token
  flow (§3): signing the raw nonce bytes is exactly this primitive;
- the **envelope compositions**: payload AEAD (`payload-aead.json`) and the key wrap/unwrap
  (`key-wrap.json`). The payload-AEAD case includes the epoch-tamper assertion (decryption fails when
  the AAD's `keyEpoch` changes), which is the cryptographic core of rotation correctness (§10): a
  stale-epoch envelope cannot authenticate;
- the **federation encodings**: the join-handshake tokens (§8.1) and `avp://` URIs (§8) in
  `federation.json`, base64url and JSON constructions with no key material;
- the **negative cases**: `negative.json`, valid constructions with one mutation each that a conformant
  implementation MUST reject (payload-decrypt and key-unwrap fail authentication, ed25519-verify returns
  false). Reproducing the positive vectors is necessary but not sufficient.

Every committed vector is reproducible from documented seeds by [`vectors/generate.ts`](vectors/generate.ts)
(`--check` re-derives and asserts them; it also owns `negative.json`).

See [`vectors/README.md`](vectors/README.md). A **server** additionally proves conformance by passing the
black-box harness in [`harness/`](harness/), which drives the full wire contract and asserts the MUSTs of
§3, §6, and §10 (the auth failure modes, optimistic-concurrency `conflict`, membership authorization, key
rotation, and zero-knowledge). Dedicated end-to-end vectors for the challenge→token exchange and the
multi-step `removeMember` rotation are a welcome addition (see [`CONTRIBUTING.md`](CONTRIBUTING.md));
today those paths are covered by the primitives above, the harness, and the cross-language wire interop
in [`examples/`](examples/).

## 12. Security considerations and open items

[`THREATMODEL.md`](THREATMODEL.md) gives the full adversary model (what AVP defends, what it does not, and
the residual risks). The open items below are the unresolved pieces of it.

- **Algorithm negotiation.** `schemeId` names the AEAD/KDF/wrap scheme; the choreography for upgrading a
  repository's scheme over its lifetime is not yet specified.
- **Cross-IdP trust (federation).** §9 lets a client verify member key bindings against a single IdP
  named out of band (the repo locator's `issuerJwksUrl`). In full federation the signing IdP is itself
  per-server; trusting bindings across multiple IdPs (pinned-issuer sets, web-of-trust) is deferred.
- **Token theft.** Tokens are bearer credentials; transport MUST be TLS. Tokens are per-host (§3), short
  lived, and scoped to membership.
- **Nonce handling.** Challenge nonces MUST be single-use with a short TTL to prevent replay of the
  signed-challenge step.
