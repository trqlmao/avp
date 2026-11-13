# AVP threat model

This document states what the Alt Vault Protocol defends against, what it deliberately does not, and the
residual risks an operator or implementer should understand. It is informative; the normative contract is
[`SPEC.md`](SPEC.md). To report a vulnerability, follow [`SECURITY.md`](SECURITY.md).

AVP shares alt accounts across clients through zero-knowledge hosts. A repository lives on several hosts at
once, each with a full copy. All cryptography happens on the client; a host stores only ciphertext,
per-member wrapped keys, public keys, counters, ids, and signatures. Membership, wrapped keys, the key epoch,
the refresh-token policy, and the host set are fixed by an owner-signed manifest chain that every client and
host verifies (SPEC §6), and every write is a member-signed commit (SPEC §7). The threat model follows from
those choices.

## Assets

In rough order of sensitivity:

1. **The alt plaintext.** The account credentials inside the encrypted payload (`accessToken`, the
   OPTIONAL `refreshToken` where a repository shares one, and the `username`, `bans`, and provenance fields
   around them). A `refreshToken` is the most sensitive value AVP ever carries: it grants durable access to
   the underlying account rather than one bounded session, which is why sharing it is a per-repository
   opt-in that defaults to off (SPEC §5.1).
2. **The owner recovery phrase and owner keys.** The 24-word BIP39 phrase derives the owner Ed25519 signing
   key and X25519 key (SPEC §3.1). Whoever holds it controls membership and can read everything.
3. **The repository data keys.** The per-epoch symmetric AES-256 keys that encrypt the payload.
4. **Member private keys.** Each member's Ed25519 identity key (authenticates, signs commits, and is the
   member id) and X25519 key (unwraps the data key).
5. **Host keys.** Each host's Ed25519 key. It signs acceptances and host-to-host requests. It grants no read
   capability.
6. **Bearer tokens.** Short-lived, host-local credentials that authorize client operations.
7. **Metadata.** The membership roster (public keys), the host set, repository sizes, the commit graph
   shape, and access patterns. Lower value, and exposed to hosts by design (see Non-goals).

## Actors and trust boundaries

- **Client.** Trusted. It generates keys, performs all cryptography, and is the only place plaintext, data
  keys, the owner phrase, and private keys exist.
- **Owner.** The member who created the repository and holds the phrase. The only party that can sign a
  manifest state, so the only party that can invite, remove, change the policy, or change the hosts.
- **Members.** Authorized insiders. Every member holds the data key and can read the whole repository.
  Members cannot invite.
- **Hosts.** Every host listed in a repository's `hosts`, including the member's own home host. Untrusted for
  confidentiality and integrity; they store, sync, and authenticate, and are zero-knowledge by construction.
- **Host operators.** Host operators, including the operator of a member's own home host, are **untrusted
  for confidentiality and integrity. They are trusted only for availability.** No operator can read vault
  contents, forge a manifest state or a commit, or cause a data key to be wrapped to a key it controls.
- **Network.** Untrusted. Client-to-host transport security is TLS; host-to-host transport security comes
  from the deployment profile (SPEC §9).

There is no identity service in 0.5. Each host mints its own tokens for any key that signs its challenge
(SPEC §3.3); a token proves control of a key at one host and nothing more.

## Adversaries

### A1. Passive network observer

*Capability:* reads traffic between client and host, or between hosts.

*Defended:* payloads and wrapped keys are encrypted (AES-256-GCM, X25519 + HKDF wrap); data keys and
plaintext never appear on the wire. Client-to-host transport MUST be TLS, so ciphertext, manifests, and
bearer tokens are not exposed in transit.

*Residual:* without TLS, an observer sees ciphertext, public keys, counters, the commit graph, and bearer
tokens. Host-to-host links are protected only as well as the deployment profile protects them; even in the
clear they carry nothing a host could not already see (A3).

### A2. Active network attacker (MITM)

*Capability:* intercepts, modifies, replays, or reorders messages.

*Defended:* authentication is an Ed25519 challenge over a single-use, short-TTL nonce, so a captured auth
exchange cannot be replayed. Manifest states are owner-signed and hash-chained, and commits are
author-signed with ids that cover the ciphertext, so a modified state or commit fails verification. The
payload AAD binds `repoId`, `keyEpoch`, `author`, and the sorted parent ids (SPEC §4.3), so a ciphertext
cannot be replayed under a different repository, epoch, author, or parent set. Tampering with ciphertext
fails the GCM tag. Signed host-to-host requests in the reference profile bind method, path, body hash, and
time, with a 60-second skew window (SPEC §9.3).

*Residual:* an attacker can drop or delay traffic (availability). Bearer tokens are bearer credentials, so
TLS plus short token lifetimes are required to limit a capture-and-reuse window (see A8). A replay of a
signed host request within the skew window re-sends an idempotent message.

### A3. Honest-but-curious host

*Capability:* sees and stores everything the protocol sends it, and tries to learn the alts.

*Defended:* zero-knowledge is an invariant (SPEC §13). The host holds ciphertext, wrapped keys, public keys,
counters, ids, and signatures, and can decrypt none of it. Provenance (`sourceClient`, `sourceUser`) lives
inside the encrypted payload.

*Residual:* the host learns **metadata**: the membership roster, the host set, payload sizes, the shape of
the commit graph (who wrote when, which writes forked), and the timing of operations. See Non-goals.

### A4. Malicious host

*Capability:* in addition to A3, returns wrong, stale, or withheld data, refuses service, and can run a
modified host on any key it controls.

*Defended:* it cannot forge manifest states (they need the owner signature, SPEC §6.1), forge commits (they
need an author signature over an id that covers the ciphertext, SPEC §7.1), roll a client back past its
pinned `manifestSeq` (SPEC §6.4), flip the refresh-token policy (it is inside the signed state, SPEC §5.1),
or get a data key wrapped to itself (the owner wraps only to keys from an invite token, never to keys a host
serves, SPEC §8.1). It cannot add itself to a repository: the owner adds a host only with that host's signed
acceptance in an invite token (SPEC §8.2), and other hosts refuse to serve a host that is not listed (SPEC
§9.2).

*Residual:* a malicious host can still attack **availability and freshness**. It can withhold new heads or
manifest states, delay them, or refuse service. A member whose only host withholds cannot, on its own,
distinguish "nothing new" from "hidden". A member on another host gets the writes anyway through
replication, which is a practical improvement over a single-host design. Freshness against a withholding
host is an open item (SPEC §15).

### A5. Malicious or careless member (insider)

*Capability:* a current member with the data key.

*Defended:* nothing, by design, with respect to the contents of their own repository. Membership is the
trust boundary: every member can decrypt every alt. Members **cannot invite**: only the owner can add a
member (SPEC §8). A member cannot erase another member's write, because a stale write is a fork, never an
overwrite, and merge is per field (SPEC §5, §7.4).

*Residual:* a member can exfiltrate every alt they can see, and can write newer stamps that win per-field
merges (a later edit legitimately overrides an earlier one). Treat membership as a full grant of read
access to everything in that repository, present and future, until the member is removed. Where
`shareRefreshTokens` is on (SPEC §5.1), that grant is durable: a refresh token a member copies keeps working
until it is revoked upstream.

### A6. Removed member

*Capability:* a former member who retains keys, an old `manifestSeq`, the old epoch key, and anything they
previously pulled.

*Defended:* removal rotates the data key to a new epoch wrapped only to the remaining members, so the
removed member cannot read later commits. The removing state carries a signed **removal cutoff**: the
frontier of commits the owner had seen (SPEC §7.3). After removal, a commit by that member is accepted only
if its id is in the frontier or is an ancestor of a frontier commit, whatever `manifestSeq` it cites. That
closes backdating: a commit that cites the old state and old epoch, even one whose parent is in the
frontier, is rejected. A removed key is never a member again (SPEC §6.1).

*Residual:* there is **no backward secrecy**. A removed member keeps every alt they already decrypted while a
member. Rotation protects new data, not old. Writes the removed member made that never reached the owner
before removal are dropped. A host that has not yet received the removing state may briefly accept a
backdated commit; it is dropped, with its descendants, once the state arrives, but its content survives in
the local state of any client that already merged it. A shared `refreshToken` (SPEC §5.1) is the worst case:
it keeps minting new access tokens until it is revoked at the provider that issued it; only upstream
revocation reaches it.

### A7. Stolen owner phrase

*Capability:* possesses the owner's 24-word recovery phrase, its entropy, or a linked owner device.

*Defended:* out of scope for the protocol, like a stolen member key (A9). The phrase never leaves owner
devices and never passes through a host (SPEC §3.1); device linking moves the entropy only after the owner
compares a confirmation code on both devices (SPEC §11.6).

*Residual:* the holder is the owner. They can sign manifest states: add a member they control, receive a
wrapped data key, and read everything; remove members; change the policy and the hosts. This is a full
ownership compromise. Ownership transfer is not specified (SPEC §15), so a repository whose phrase is stolen
cannot be moved to a new owner key; its members should create a new repository under a new phrase and
rotate the alts' credentials out of band. Store the phrase offline and link devices only when needed. (0.4's
"compromised identity provider" adversary is removed: 0.5 has no identity provider.)

### A8. Stolen bearer token

*Capability:* possesses a valid, unexpired token.

*Defended:* tokens are host-local, scoped to the bearer's memberships at that host, and short-lived. They
never leave TLS. A token cannot sign a commit, a manifest state, or a leave request, so it cannot write as
the member or change membership.

*Residual:* until it expires, a stolen token lets its holder pull as that member at that host (ciphertext
only) and call `prepareJoin` as that key. Keep token TTLs short.

### A9. Stolen member private key

*Capability:* possesses a member's Ed25519 and/or X25519 private key.

*Defended:* out of scope for the protocol (see Non-goals); how a client stores keys at rest is a client
concern.

*Residual:* whoever holds the Ed25519 key can authenticate and sign commits as that member; whoever holds the
X25519 key can unwrap every data key wrapped to that member. A stolen private key is a full member compromise
and is handled as A5 plus removal (A6) once detected.

### A10. Diverged owner devices

*Capability:* not an attacker. Two owner devices, offline from each other, each publish a different state at
the same `manifestSeq`.

*Defended:* the divergence is resolved deterministically and surfaced, not silent. Of the two states at the
fork point, the one with the bytewise-lower `manifestHash` wins, with every state after it; every host and
client converges on it (SPEC §6.5). Commits citing a losing state are re-checked against the winning state at
the same seq: accepted if the author is a member there at the same epoch, otherwise held (stored, not a head,
not served) until an owner device decides, by re-inviting the author at that epoch or by moving on (a later
epoch or a removal drops it). A commit must cite a state the host has verified as owner-signed, so a made-up
manifest hash is never accepted. Hosts and clients SHOULD tell the owner.

*Residual:* the losing branch's changes are discarded: members invited only there must be invited again, and
removals made only there must be made again. Until they are redone, a member the owner meant to remove on
the losing device is still a member. An owner client MUST pull the tip before publishing (SPEC §6.3), which
keeps divergence to the offline case.

### A11. Replication amplification

*Capability:* a compromised host that is listed in a repository's `hosts`.

*Defended:* it receives ciphertext, manifest states, commits, and leave requests by replication. That is
equivalent to A3 for that host and adds no read capability: every host validates every replicated item by
the same rules as a client write (SPEC §9), so a compromised peer cannot inject a forged state or commit,
and a host not listed in `hosts` is refused by the others (SPEC §9.2). The reference hosts also send their
host requests for a repository only to its listed hosts (SPEC §9.3), so a peer that is not listed does not
learn which repository ids they hold.

*Residual:* listing more hosts exposes the same ciphertext and metadata to more operators, and each listed
host can withhold (A4) from its own members. A listed host can relay valid commits it receives from members
on other hosts in any order; validation, not ordering, is what protects the repository.

## Cryptographic assumptions

AVP assumes the standard security of its primitives and their correct, side-channel-aware implementation:

- **Ed25519** (RFC 8032) for identity, manifest, commit, acceptance, leave, and host request signatures;
  **X25519** (RFC 7748) for key agreement; **HKDF-SHA256** (RFC 5869) for key derivation;
  **PBKDF2-HMAC-SHA512** (RFC 8018) for the BIP39 seed; **SHA-256** for ids and hashes; **AES-256-GCM**
  (RFC 5116) for the payload and wrap AEAD.
- **TLS** for client-to-host transport. Bearer tokens rely on it.
- A **cryptographically secure RNG** for the owner entropy, genesis nonces, data keys, ephemeral wrap keys,
  IVs, and challenge nonces.
- **GCM IV uniqueness per key.** A fresh random 12-byte IV is generated per commit under a given data key.
  Reusing an IV under the same key is catastrophic for GCM. With random 96-bit IVs the birthday bound keeps
  collision probability negligible for the small write volumes a vault sees; implementations SHOULD
  nonetheless rotate well before approaching 2^32 commits under a single data key.

## Non-goals

AVP deliberately does **not** provide:

- **Client endpoint security.** Malware on a member's machine, or insecure key or phrase storage, defeats the
  protocol. Protecting the client device is the implementer's responsibility.
- **Confidentiality against members.** A member can read everything in the repository (A5).
- **Metadata privacy from hosts.** Hosts learn the roster, the host set, sizes, the commit graph shape, and
  timing. AVP hides content, not the shape of the traffic.
- **Availability guarantees.** A host can refuse or degrade service (A4). Replication across several hosts
  improves availability in practice but guarantees nothing.
- **Backward secrecy on removal.** Removal protects future commits only (A6).
- **Host-to-host transport security** beyond what a deployment profile provides (SPEC §9).
- **Anything about the accounts themselves.** Whether obtaining or using a given account complies with a
  service's terms or with applicable law is the implementer's responsibility, not the protocol's.

## Residual risks and open items

These match the open items in [`SPEC.md`](SPEC.md) §15 and are the most useful places to contribute a
security review:

- **Host freshness against a withholding host** (A4): a member whose only host withholds new heads or states
  cannot detect it on its own.
- **Ownership transfer** (A7): `ownerKey` is fixed for a repository's life, so a lost or stolen phrase cannot
  be recovered from inside the repository.
- **Deletion-marker GC, commit pruning, and retention**: markers are kept forever; hosts MAY prune commit
  bodies, but 0.5 does not define how a pruned commit is served to or verified by a peer that lacks it, so a
  host that pruned a body cannot bootstrap a new peer for that commit (the reference hosts do not prune); a safe
  collection rule is not specified.
- **Algorithm negotiation**: `schemeId` names the wrap scheme, but the choreography for upgrading a
  repository's scheme over its lifetime is not specified.

Accepted residuals, by design rather than open: no backward secrecy (A6), metadata exposure to hosts (A3),
diverged owner branches discarded (A10), and the bearer-token theft window (A8), mitigated by TLS and short
TTLs.

Found something exploitable? Please follow [`SECURITY.md`](SECURITY.md) rather than opening a public issue.
