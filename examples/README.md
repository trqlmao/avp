# Examples

A worked end-to-end flow, representative message bodies, and runnable reference implementations, to make
the spec concrete. The prose below is **illustrative**: hosts are `vault.example`, members are `alice`
and `bob`, and the base64 key and ciphertext values shown in the worked flow are fixtures, not real
cryptographic output. The runnable implementations, by contrast, do the real crypto (see Implementations
below). See [`../SPEC.md`](../SPEC.md) for the normative rules and [`../vectors/`](../vectors/) for
byte-exact construction vectors.

Field names below are the HTTP/JSON profile (proto field names in `camelCase`); the gRPC profile carries
the same fields.

## Implementations

Reference clients and servers, organized as `examples/<language>/<client|server>/`. Each implements the
HTTP/JSON profile against in-memory state and is illustrative, not production.

| Language | Server | Client |
|---|---|---|
| TypeScript | [`typescript/server/`](typescript/server/) | [`typescript/client/`](typescript/client/) |
| Rust | [`rust/server/`](rust/server/) | [`rust/client/`](rust/client/) |
| Python | [`python/server/`](python/server/) | [`python/client/`](python/client/) |
| Java | [`java/server/`](java/server/) | [`java/client/`](java/client/) |
| Go | [`go/server/`](go/server/) | [`go/client/`](go/client/) |

All five examples implement the real envelope and key-wrap crypto (payload AEAD and
X25519-HKDF-SHA256-AESGCM-v1), each verified byte-for-byte against
[`../vectors/`](../vectors/). Cross-language wire compatibility is checked continuously
by the `examples-interop` workflow: each language's client runs against the Go reference
server, and the Go reference client runs against each language's server. Go and TypeScript
are the fullest worked references for the cryptographic core.

For the **gRPC profile**, [`grpc/`](grpc/) is a runnable client and server that load the canonical
[`../proto/avp.proto`](../proto/avp.proto) directly and exercise all six `Vault` RPCs over a gRPC channel
(the `examples-grpc` workflow runs it end to end). The message objects and crypto are identical to the
HTTP/JSON examples; only the transport differs.

Conformance tooling lives in [`conformance/`](conformance/) (it checks the repo's
[`../vectors/`](../vectors/)). From the repo root, [`task test`](../Taskfile.yml) (go-task) runs the
conformance suite and every language's example tests in one command; per-language targets
(`task go`, `task rust`, …) run just one toolchain. More languages are welcome; see
[`../CONTRIBUTING.md`](../CONTRIBUTING.md).

## The cast

- **alice** and **bob**: two members, each an Ed25519 keypair (plus an X25519 key for wrapping). Their
  Ed25519 public key is their member id.
- **`vault.example`**: the server that hosts the repository. Either member could be pointed at a
  different server by default; they reach this repository by its address.

## 1. alice creates a repository

alice generates a per-repo data key, wraps it to her own X25519 key, encrypts the initial alt payload,
and calls `createRepo`. See [`create-repo-request.json`](create-repo-request.json). The server stores it
and returns the manifest. The repository's address is now:

```
avp://vault.example/3b1f9c64-0b2a-4f1e-9c3d-1a2b3c4d5e6f
```

## 2. bob asks to join

bob sends alice an **invite request** out of band: a base64url JSON of his public keys (SPEC section 8.1).

```json
{ "v": 1, "ed25519PublicKey": "Ym9iLWVkMjU1MTktcHVibGljLWtleQ", "x25519PublicKey": "Ym9iLXgyNTUxOS1wdWJsaWMta2V5" }
```

base64url-encoded, that is one opaque token bob pastes to alice.

## 3. alice adds bob

alice wraps the repo data key to bob's X25519 key (client-side) and calls `addMember` with the resulting
`MemberEntry`. She then replies to bob with a **repo locator**:

```json
{ "v": 1, "host": "vault.example", "repoId": "3b1f9c64-0b2a-4f1e-9c3d-1a2b3c4d5e6f", "schemeId": "X25519-HKDF-SHA256-AESGCM-v1", "keyEpoch": 0, "issuerJwksUrl": "https://idp.example/.well-known/jwks.json" }
```

base64url-encoded, this tells bob where the repository lives and which identity provider to trust for key
bindings.

## 4. bob authenticates and pulls

bob decodes the locator, resolves a transport for `vault.example`, and authenticates with his own
keypair (SPEC section 3): `challenge` returns a nonce, bob signs the raw nonce bytes, `token` returns a
bearer token scoped to `vault.example`. bob then calls `pull` with `knownPayloadVersion: 0` and gets the
manifest and current envelope. See [`pull-response.json`](pull-response.json). bob unwraps the data key
from his `MemberEntry` and decrypts the payload.

## 5. someone pushes a change

A member adds an alt, re-encrypts the payload at the next version, and calls `push` with
`expectedPayloadVersion` set to the version they pulled. See [`push-request.json`](push-request.json). If
another member wrote first, the server returns `{ "accepted": false, "conflict": true }` with the current
version, and the client pulls, re-applies, and retries.

## 6. removing a member rotates the key

To remove a member, a remaining member rotates the data key to a new epoch, re-wraps it to everyone who
stays, re-encrypts the payload, and calls `removeMember` with the removed id, the rotated envelope, the
re-wrapped roster, and the new epoch, all applied atomically. The removed member's old wrapped key cannot
derive the new epoch's data key, and the AAD makes a stale-epoch envelope fail authentication.

## Anti-MITM in one line

When bob joins on a server he does not operate, he verifies each served `MemberEntry.keyBindingSig`
against the issuer from the locator before wrapping a data key to it (SPEC section 9). The signed message
is `utf8(ed25519PublicKey + "|" + x25519PublicKey)`; see
[`../vectors/key-binding-message.json`](../vectors/key-binding-message.json).
