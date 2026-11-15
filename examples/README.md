# Examples

A worked end-to-end flow, representative message bodies, and runnable reference implementations, to make
the spec concrete. The prose below is **illustrative**: hosts are `a.vault.example` and `b.vault.example`,
members are `alice` (the owner), `bob`, and `carol`, and the base64 key, signature, and ciphertext values in
the example bodies are fixtures, not real cryptographic output. The runnable implementations, by contrast,
do the real crypto (see Implementations below). See [`../SPEC.md`](../SPEC.md) for the normative rules,
[`../IMPLEMENTING.md`](../IMPLEMENTING.md) for the implementer's guide, and [`../vectors/`](../vectors/) for
byte-exact construction vectors.

Field names below are the HTTP/JSON profile (proto field names in `camelCase`); the gRPC profile carries
the same fields.

## Implementations

Reference clients and hosts for AVP 0.5, organized as `examples/<language>/<avp|server|client>/`. Each
language has one shared library (`avp`) holding the constructions, the payload merge, and the host rules
engine, which both its host and its client use. Each host implements the HTTP/JSON profile against
in-memory state and replicates with its peers over signed HTTP/JSON (SPEC section 9.3). They are
illustrative, not production.

| Language | Shared library | Host | Client |
|---|---|---|---|
| Rust | [`rust/avp/`](rust/avp/) | [`rust/server/`](rust/server/) | [`rust/client/`](rust/client/) |
| Java | [`java/avp/`](java/avp/) | [`java/server/`](java/server/) | [`java/client/`](java/client/) |

Both libraries reproduce every vector in [`../vectors/`](../vectors/) and replay
[`acceptance.json`](../vectors/acceptance.json) unchanged. Cross-language compatibility is checked
continuously: the `examples-interop` workflow runs each client against the other language's host, alone
and as bob's home host, and the multi-host harness ([`../harness/multihost.ts`](../harness/multihost.ts))
replicates Rust and Java hosts with each other. The Go, Python, TypeScript, and gRPC examples stopped at
0.4; see the `v0.4` tag.

Each host reads `PORT`, `AVP_BIND` (listen address, default `0.0.0.0`; use `127.0.0.1` for local runs),
`AVP_HOST_SEED` (hex host key seed), `AVP_PEERS` (`<base64 hostKey>@<http base url>,...`), and
`AVP_TEST_CONTROL` (`1` enables the replication pause route the multi-host harness uses). See each
host's README.

Conformance tooling lives in [`conformance/`](conformance/) (it checks the repo's
[`../vectors/`](../vectors/), the schema, these example bodies, and `openapi.yaml`). From the repo root,
[`task test`](../Taskfile.yml) (go-task) runs the conformance suite, the vector drift check, and each
language's tests in one command; per-language targets (`task rust`, `task java`) run one toolchain, and
`task harness`, `task multihost`, and `task interop` start the reference hosts with
[`../harness/run-hosts.sh`](../harness/run-hosts.sh). More languages are welcome; see
[`../CONTRIBUTING.md`](../CONTRIBUTING.md).

## The cast

- **alice**: the owner. Her 24-word recovery phrase derives the owner Ed25519 key (`ownerKey`) and X25519
  key (SPEC section 3.1). Only she signs manifest states.
- **bob** and **carol**: members, each a per-device Ed25519 + X25519 keypair. A member's id is the base64
  of its Ed25519 public key.
- **`a.vault.example`**: alice's home host. **`b.vault.example`**: bob's home host. Each has an Ed25519 host
  key, and each holds a full copy of the repository once the manifest lists it.

## 1. alice creates a repository

alice's client generates a 16-byte genesis nonce and the epoch 0 data key, wraps the data key to her own
X25519 key, and signs the genesis state: seq 1, one member (alice, home host `a.vault.example`), `hosts`
listing `a.vault.example`, no removals. The `repoId` is derived from her owner key and the nonce, so it
never names a host. She seals the first commit (no parents, citing seq 1) and calls `createRepo` on her
home host. See [`create-repo-request.json`](create-repo-request.json). The host recomputes the `repoId`,
verifies her signatures, and stores the state and the commit together.

## 2. bob asks to join

alice sends bob a **repo locator** out of band (SPEC section 11.2): the `repoId`, her home host's key and
locator, and her owner key fingerprint. bob's client calls `prepareJoin { repoId, memberKey }` on his own
home host `b.vault.example`, which answers with a signed **acceptance** if it agrees to carry the
repository. bob sends alice an **invite token** (SPEC section 11.3) with his two public keys, his home
host's key and locator, and that acceptance. Both tokens are base64url JSON; see
[`../vectors/federation.json`](../vectors/federation.json).

## 3. alice adds bob

alice's client verifies the acceptance (signed by the host key the token names, for this `repoId` and bob's
key, not expired), wraps the current data key to the X25519 key **from the token**, and publishes the next
state adding bob as a member with home host `b.vault.example` and adding that host to `hosts`. She adds
carol the same way.

## 4. the new host gets its copy, and bob pulls

`a.vault.example` offers the new states and commits to `b.vault.example`, the one peer the new tip lists.
See [`offer-request.json`](offer-request.json) for the shape of an `offer` (host-signed with the
`AVP-Host-*` headers, SPEC section 9.3). `b.vault.example` validates every item by the same rules as a
client write and, because the received tip lists it, keeps the copy.

bob authenticates to his home host (SPEC section 3.3: `challenge`, sign the `avp/challenge/v1` transcript of the host key, his key, and the nonce, `token`) and
calls `pull`. He gets the manifest states after his pinned seq, the heads he does not know, and the
pending leave requests. See [`pull-response.json`](pull-response.json). He verifies every owner signature
and chain link, checks the genesis owner key against the locator's fingerprint, unwraps the data key from
his member entry, and decrypts each head.

## 5. bob writes, and concurrent writes merge

bob ticks his hybrid logical clock, stamps the fields he sets, encrypts the full payload under AAD v2, and
pushes a commit whose parent is the head he read. See [`push-request.json`](push-request.json). If carol
pushes on `a.vault.example` at the same time, the hosts replicate both commits and each now has two heads.
There is no conflict outcome: the next client that pulls merges the heads per field (the greatest stamp
wins) and pushes a merge commit naming both heads as parents.

## 6. removing a member rotates the key and signs a cutoff

To remove carol, alice's client pulls and merges every head, generates the epoch 1 data key, wraps it to
the remaining members, and publishes, in one `publishManifest`, the next state (carol removed, a removal
whose `frontier` lists the heads alice merged, `keyEpoch` 1) together with the **rotation commit** that
re-encrypts the merged payload under epoch 1. See
[`publish-manifest-request.json`](publish-manifest-request.json). Every host adopts the state and the
rotation commit together or not at all. carol's old wrapped key cannot derive the epoch 1 key, and any
commit she writes later, even one citing the old state and epoch, is rejected unless it is in the frontier
or an ancestor of it.

## 7. bob leaves

bob signs a leave request and sends it with `leave`. His client stops syncing; the hosts keep and replicate
the request (it appears in `pull`, as in [`pull-response.json`](pull-response.json)) until alice's client
processes it by removal.
