# AVP threat model

This document states what the Alt Vault Protocol defends against, what it deliberately does not, and the
residual risks an operator or implementer should understand. It is informative; the normative contract is
[`SPEC.md`](SPEC.md). To report a vulnerability, follow [`SECURITY.md`](SECURITY.md).

AVP shares alt accounts across clients through a zero-knowledge, federated server. All cryptography
happens on the client; the server stores only ciphertext, per-member wrapped keys, public keys, version
and epoch counters, and opaque signatures. The threat model follows from that single design choice.

## Assets

In rough order of sensitivity:

1. **The alt plaintext.** The account credentials inside the encrypted payload (`accessToken`, the
   OPTIONAL `refreshToken` where a repository shares one, and the `username`, `uuid`, `bans`, and
   provenance fields around it). This is what AVP exists to protect. A `refreshToken` is the most
   sensitive value AVP ever carries: it grants durable access to the underlying account rather than one
   bounded session, which is why sharing it is a per-repository opt-in that defaults to off (SPEC §5.1).
2. **The repository data key.** The per-repo symmetric AES-256 key that encrypts the payload. Anyone who
   holds it can read every alt in the repo.
3. **Member private keys.** Each member's Ed25519 identity key (authenticates, and is the member id) and
   X25519 key (unwraps the data key).
4. **Bearer tokens.** Short-lived, per-host credentials that authorize vault operations.
5. **Metadata.** The membership roster (public keys), repository sizes, and access patterns. Lower value,
   and partly exposed to the server by design (see Non-goals).

## Actors and trust boundaries

- **Client.** Trusted. It generates keys, performs all cryptography, and is the only place plaintext, the
  data key, and private keys exist.
- **Vault server.** Untrusted for confidentiality and integrity of content; relied on only for storage
  and availability. It is zero-knowledge by construction.
- **Identity provider (IdP).** A trust anchor. It issues bearer tokens (§3) and MAY sign member key
  bindings (§9). A deployment may run the IdP and vault server together or separately.
- **Members.** Authorized insiders. Every member holds the data key and can read the whole repo.
- **Network.** Untrusted. Transport security is provided by TLS, not by the protocol messages.

## Adversaries

### A1. Passive network observer

*Capability:* reads traffic between client and server.

*Defended:* payloads and wrapped keys are encrypted (AES-256-GCM, X25519 + HKDF wrap); the data key and
plaintext never appear on the wire. Transport MUST be TLS, so even the ciphertext envelope and bearer
tokens are not exposed in transit.

*Residual:* without TLS, an observer sees ciphertext, public keys, counters, and bearer tokens. TLS is
mandatory for exactly this reason.

### A2. Active network attacker (MITM)

*Capability:* intercepts, modifies, replays, or reorders messages.

*Defended:* authentication is an Ed25519 challenge over a single-use, short-TTL nonce, so a captured auth
exchange cannot be replayed. Every payload binds `(repoId, payloadVersion, keyEpoch)` into the AES-GCM
AAD, so an envelope cannot be replayed under a different repository, version, or epoch without failing
authentication. Tampering with ciphertext fails the GCM tag.

*Residual:* an attacker who also controls or impersonates the server is covered by A4. Bearer tokens are
themselves bearer credentials, so TLS plus short token lifetimes are required to limit a capture-and-reuse
window (see A8).

### A3. Honest-but-curious server

*Capability:* sees and stores everything the protocol sends it, and tries to learn the alts.

*Defended:* zero-knowledge is an invariant (SPEC §10). After a create and push, no stored value decodes to
a plaintext alt field. The server holds ciphertext, base64 wrapped-key blobs, raw public keys, counters,
and opaque signatures, and can decrypt none of it. Provenance (`sourceClient`, `sourceUser`) lives inside
the encrypted payload, so cross-client attribution does not weaken this.

*Residual:* the server learns **metadata**: the membership roster (a set of public keys), repository and
payload sizes, and the timing and frequency of operations. AVP does not hide this from the server it talks
to. See Non-goals.

### A4. Malicious server

*Capability:* in addition to A3, returns wrong, stale, or withheld data, and serves chosen key material.

*Defended:* it still cannot read or forge plaintext (it has no data key). Against the specific attack of
serving a **wrong X25519 key** for a member (to trick an inviter into wrapping the data key to an
attacker), §9 key binding defends: the IdP signs each member's two public keys, and a joiner verifies the
binding before wrapping. This verification SHOULD be done always and MUST be done when the repository's
host is one the client does not itself operate.

*Residual:* a malicious server can still attack **availability and freshness**. It can withhold updates,
serve a stale but validly-encrypted manifest and envelope, or refuse service. The monotonic
`payloadVersion` and the epoch-bound AAD let a client detect a rollback of content it can compare against,
but a client with no independent reference cannot, on its own, distinguish "no newer version exists" from
"the server is hiding it." Detecting equivocation or stale-state attacks requires out-of-band comparison
or version pinning, which AVP does not currently specify.

A malicious server can also **rewrite the manifest's non-secret metadata**, which is served unsigned and
is bound by neither a signature nor the payload AAD. The consequential case is the refresh-token sharing
policy (SPEC §5.1): a host that flips `shareRefreshTokens` from `false` to `true` induces conformant
clients opening the repository afterwards to stop stripping and to upload refresh tokens on their next
push, and the owner who deliberately left the policy off gets no signal that it changed. The policy binds
**members, not the host**: it constrains what conformant members do with a policy they are served. Closing
this needs an authenticated manifest (an owner signature over at least `repoId`, `keyEpoch`, and the
policy) plus local pinning, so that a `false` to `true` transition requires explicit confirmation rather
than taking effect silently. That is deferred (SPEC §12). Until it lands, enabling refresh-token sharing
extends trust to the host as well as to the members, and the credentials it exposes are durable ones.

### A5. Malicious or careless member (insider)

*Capability:* a current member with the data key.

*Defended:* nothing, by design, with respect to the contents of their own repository. Membership is the
trust boundary: every member can decrypt every alt. Integrity of writes is bounded by optimistic
concurrency (a member cannot silently clobber a concurrent write).

*Residual:* a member can exfiltrate every alt they can see, and under the v1 policy any member may invite
another (the `addMember` authorization is "any member"). Treat repository membership as a full grant of
read access to everything in that repository, present and future, until the member is removed. Where
`shareRefreshTokens` is on (SPEC §5.1), that grant is also durable: a refresh token a member copies keeps
working until it is revoked upstream, long after their access to the repository ends.

### A6. Removed member

*Capability:* a former member who retains keys and anything they previously pulled.

*Defended:* `removeMember` rotates the data key to a new epoch and re-wraps it only to the remaining
members. The removed member's old wrapped key cannot derive the new epoch's data key, and the epoch in the
AAD makes a stale-epoch envelope fail authentication. They lose access to all **future** writes.

*Residual:* there is **no backward secrecy**. A removed member keeps every alt they already decrypted
while a member. Rotation protects new data, not old. Rotate credentials (the alts themselves) out of band
if a departure requires revoking access to data already shared. A shared `refreshToken` (SPEC §5.1) is the
worst case: an `accessToken` a departed member kept expires on its own, while a refresh token keeps
minting new ones until it is revoked at the provider that issued it. Neither key rotation nor turning
`shareRefreshTokens` back off reaches a credential already on someone's disk; only upstream revocation
does.

### A7. Compromised IdP

*Capability:* controls token issuance and key-binding signatures.

*Defended:* the IdP is an explicit trust anchor, not an attacker AVP defends against. It is the smallest
sensible anchor: tokens carry only `sub` and `kind`, with no account or role claims, and a vault server
authorizes purely on membership.

*Residual:* a compromised IdP can mint a token for any identity (authenticating as anyone at the transport
layer) and can forge key bindings, defeating the A4 defense. In the current single-issuer model a
repository trusts one IdP, named out of band in the repo locator. Cross-issuer trust (pinned-issuer sets,
web-of-trust) is deferred (SPEC §12). Run the IdP with the same care as any signing authority, and rotate
its key set if it is suspected compromised.

### A8. Stolen bearer token

*Capability:* possesses a valid, unexpired token.

*Defended:* tokens are scoped to a single host and to the bearer's repository memberships, and are
short-lived. They never leave TLS.

*Residual:* until it expires, a stolen token impersonates its subject at that host. Keep token TTLs short
and transport encrypted; a longer TTL is a longer theft window.

### A9. Stolen member private key

*Capability:* possesses a member's Ed25519 and/or X25519 private key.

*Defended:* out of scope for the protocol (see Non-goals); how a client stores keys at rest is a client
concern.

*Residual:* whoever holds the Ed25519 key can authenticate as that member; whoever holds the X25519 key
can unwrap every data key wrapped to that member. A stolen private key is a full member compromise and is
handled the same as A5 plus removal (A6) once detected.

## Cryptographic assumptions

AVP assumes the standard security of its primitives and their correct, side-channel-aware implementation:

- **Ed25519** (RFC 8032) for identity and signatures; **X25519** (RFC 7748) for key agreement;
  **HKDF-SHA256** (RFC 5869) for key derivation; **AES-256-GCM** (RFC 5116) for the payload and wrap AEAD.
- **TLS** for all transport. Bearer tokens and the ciphertext envelope rely on it.
- A **cryptographically secure RNG** for the data key, ephemeral wrap keys, IVs, and challenge nonces.
- **GCM IV uniqueness per key.** A fresh random 12-byte (96-bit) IV is generated per write under a given
  data key. Reusing an IV under the same key is catastrophic for GCM (it leaks the XOR of plaintexts and
  enables forgery). With random 96-bit IVs the birthday bound keeps collision probability negligible for
  the small write volumes a vault sees; implementations SHOULD nonetheless treat key-epoch rotation as the
  mechanism that resets the IV space and SHOULD rotate well before approaching 2^32 writes under a single
  data key.

## Non-goals

AVP deliberately does **not** provide:

- **Client endpoint security.** Malware on a member's machine, or insecure key storage at rest, defeats
  the protocol. Protecting the client device and its key store is the implementer's responsibility.
- **Metadata privacy from the server.** The server it talks to learns the membership roster, repository
  and payload sizes, and access timing. AVP hides content, not the shape of the traffic.
- **Availability or anti-censorship guarantees.** A server can refuse or degrade service (A4). AVP has no
  built-in replication or quorum.
- **Backward secrecy on removal.** Removal protects future writes only (A6).
- **Server-to-server replication or relay.** Out of scope for this version (SPEC §8.3).
- **Anything about the accounts themselves.** Whether obtaining or using a given account complies with a
  service's terms or with applicable law is the implementer's responsibility, not the protocol's.

## Residual risks and open items

These are tracked as open items in [`SPEC.md`](SPEC.md) §12 and are the most useful places to contribute a
security review:

- **Freshness and equivocation against a malicious server** (A4): no in-protocol mechanism proves a
  client is seeing the latest, non-forked state.
- **Unauthenticated manifest metadata** (A4): the manifest is served unsigned and unbound to the payload
  AAD, so the refresh-token sharing policy (SPEC §5.1) binds members rather than the host. An
  authenticated manifest plus policy pinning is deferred (SPEC §12).
- **Single-issuer trust** (A7): cross-IdP trust is unspecified.
- **No backward secrecy** (A6): removal does not revoke already-seen data.
- **Metadata exposure to the server** (A3).
- **Bearer-token theft window** (A8): mitigated by TLS and short TTLs, not eliminated.
- **Algorithm agility:** `schemeId` names the AEAD/KDF/wrap scheme, but the choreography for upgrading a
  repository's scheme over its lifetime is not yet specified.

Found something exploitable? Please follow [`SECURITY.md`](SECURITY.md) rather than opening a public issue.
