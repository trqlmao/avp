# Alt Vault Protocol (AVP): Specification

**Version:** 0.5 (draft)
**Status:** draft wire contract; see §15 for open items.

AVP lets independent Minecraft clients share alt accounts through zero-knowledge hosts. This document is
the normative contract. An implementation is *conformant* if it satisfies every MUST here and reproduces
the vectors in [`vectors/`](vectors/) (§14).

0.5 is a breaking version. It is not wire compatible with 0.4 servers or payloads, and no migration path
is specified.

## 1. Overview

A **repository** ("repo") is a shared, end-to-end-encrypted collection of alt accounts with a set of
**members**. A member is an Ed25519 + X25519 keypair. The repo has a symmetric **data key** per key epoch
that encrypts the alt payload; the data key is wrapped to each member's X25519 public key. All
cryptography happens on the client.

A repository lives on **several hosts at once**. Each host listed in the repository holds a full copy and
replicates it with the other listed hosts (§9). A member's client talks only to its own **home host**. If
another member's host is down, the member still has the latest copy its host synced and can read and write
it; hosts catch each other up when they reconnect.

Three structures carry a repository:

- The **manifest chain** (§4.2, §6): an append-only chain of states signed by the repository **owner**,
  holding the membership roster, wrapped data keys, key epoch, refresh-token policy, and the set of hosts.
  Only the owner can produce a state, so only the owner can invite, remove, change the policy, or change
  the hosts.
- The **commit graph** (§4.3, §7): member-signed commits, each carrying the full encrypted payload state
  and naming its parent commits. Concurrent writes on different hosts fork the graph; **heads** are commits
  with no children.
- The **payload** (§5): a map of accounts whose every field carries its own timestamp, so a client that
  sees several heads merges them per account and per field without losing a write.

A host stores ciphertext, wrapped keys, public keys, counters, and signatures, and nothing it can decrypt.
No host and no operator, including the operator of a member's own home host, can read vault contents,
forge a manifest state or a commit, or cause a data key to be wrapped to a key it controls. Hosts decide
who may store and sync; only keys held by people decide who can read.

## 2. Conventions

- The key words MUST, MUST NOT, SHOULD, SHOULD NOT, RECOMMENDED, and MAY are to be interpreted as in
  RFC 2119.
- **Raw keys.** "Ed25519 public key" and "X25519 public key" mean the raw 32-byte encodings (RFC 8032,
  RFC 7748). An Ed25519 signature is the raw 64-byte encoding.
- **Strict Ed25519 verification.** Every Ed25519 signature AVP verifies (owner signatures on manifest
  states, author signatures on commits, host acceptances, leave requests, host requests, and the
  challenge signature of §3.3; the full list is the table of §4.1) MUST be verified strictly, so that every conformant implementation accepts
  exactly the same signatures. A verifier MUST reject the signature, before any other check, if the public
  key `A` or the signature's first half `R` (the encoding of a point) is the encoding of a point of small
  order, if `A` or `R` is a non-canonical encoding (its 255-bit `y` field, the 32 bytes read little-endian
  with the top bit cleared, is at least `p = 2^255 - 19`), or if the signature's second half `S`, read
  little-endian, is at least the group order `L = 2^252 + 27742317777372353535851937790883648493`. A
  32-byte encoding is of small order if, with the top bit of its last byte cleared, it equals one of the
  seven encodings `0x00..00` (order 4), `0x01 00..00` (the identity), the two order-8 encodings
  `26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05` and
  `c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a`, `p - 1` (order 2), `p`, and `p + 1`
  (the last two are the non-canonical encodings of `0` and `1`), written as little-endian hex. A signature
  that passes these checks MUST then verify by the **cofactorless** equation of RFC 8032 §5.1.7: with
  `k = SHA-512(R || A || M)` read little-endian and reduced modulo `L`, and `B` the base point, the verifier
  computes the point `[S]B - [k]A` and accepts only if its 32-byte encoding equals `R` byte for byte, that
  is, `[S]B = R + [k]A` with `R` compared by its encoding. A verifier MUST NOT use the cofactored check
  `[8][S]B = [8]R + [8][k]A` that RFC 8032 also permits, because the two checks accept different
  signatures. The rule follows the strict verification of libsodium (`crypto_sign_verify_detached`). Without it, a cofactorless verifier accepts
  forgeries under a small-order key that has no private key, and implementations disagree on which
  commits and states are valid. `negative.json` pins these rejections (§14).
- **Wire encoding of binary.** In JSON (the HTTP/JSON profile and the token payloads of §11) every binary
  value is **base64** (RFC 4648 §4, standard alphabet, with padding) unless stated otherwise. In the
  canonical encoding (§4) every binary value is the **raw decoded bytes**, never its base64 text.
- **base64url-nopad** means RFC 4648 §5 without `=` padding. It is used for `repoId` (§4.2) and for the
  outer encoding of tokens (§11).
- **hex** means lowercase hexadecimal.
- A member's **id** (member id) is the base64 text of its Ed25519 public key. Where a member id appears as a
  string (`by`, `lastUsedBy`, `observedBy`), it is that text.
- A **commit id** and a **manifest hash** are 32-byte SHA-256 outputs (§4.2, §4.3). On the wire they are
  base64. The word **id** used for an item in replication (§9) means a commit id or a manifest hash.
- **Sorting.** Wherever a list is sorted, it is sorted by the stated key compared as **unsigned bytes**
  (lexicographic over the raw bytes, a shorter prefix sorting first), over raw decoded bytes for binary
  keys and over UTF-8 bytes for strings.
- JSON field names in the HTTP/JSON profile are exactly the proto field names rendered in `camelCase`.
- Times are epoch milliseconds (`int64`) unless noted.
- SHA-256 and SHA-512 are FIPS 180-4. HKDF-SHA256 is RFC 5869. PBKDF2 is RFC 8018. AES-256-GCM is
  RFC 5116 with a 12-byte IV and the 16-byte tag appended to the ciphertext.
- `x[0..n]` means the first `n` bytes of `x`. `||` is byte concatenation.

## 3. Identities

### 3.1 Owner identity: BIP39 phrase and key derivation

The **owner** is the member who creates a repository. The owner's authority is a key derived from a BIP39
recovery phrase. The phrase *is* the identity: it derives the keys rather than unlocking a stored copy, so
there is no ciphertext to lose and no operator ever holds it.

**Mnemonic.** An owner client MUST generate 32 bytes (256 bits) of entropy from a cryptographically secure
RNG and encode it as a 24-word BIP39 mnemonic over the BIP39 English wordlist
([`vectors/bip39-english.txt`](vectors/bip39-english.txt), 2048 words): append the first 8 bits of
`SHA-256(entropy)` as a checksum, split the resulting 264 bits into 24 groups of 11 bits (most significant
first), and map each group to the word at that index. Words are joined by a single space (U+0020). When
decoding a mnemonic, a client MUST reject a phrase that is not exactly 24 words, contains a word that is not
in the list, or fails the checksum.

**Seed.** `seed = PBKDF2-HMAC-SHA512(password = NFKD(mnemonic), salt = UTF8("mnemonic") || NFKD(passphrase),
iterations = 2048, length = 64)`. The passphrase is **empty** for AVP, so the salt is the 8 bytes
`mnemonic`.

**Owner keys.** With `salt = empty` (RFC 5869 then uses 32 zero bytes in the extract step):

```
ed25519Seed   = HKDF-SHA256(ikm = seed, salt = empty, info = UTF8("avp/owner/ed25519/v1"), L = 32)
x25519Private = HKDF-SHA256(ikm = seed, salt = empty, info = UTF8("avp/owner/x25519/v1"),  L = 32)
```

`ed25519Seed` is the RFC 8032 private key seed of the owner signing key; its public key is the
**`ownerKey`**. `x25519Private` is the owner's X25519 private key (clamped by the X25519 function as
RFC 7748 specifies); its public key is the owner's X25519 public key. The owner is one member entry
(§4.2) with these two public keys, whichever of its devices is in use.

**Owner devices.** Every owner device holds the same owner keys, either from the phrase or from device
linking (§11.6). A client MAY use one phrase for several repositories or one phrase per repository; the
reference clients use one phrase per owner identity, reused across that owner's repositories. Each
repository still gets a distinct `repoId` because its genesis nonce is random (§4.2).

**Showing the phrase.** A client SHOULD show the phrase once at creation, require confirmation that it was
saved, and warn that without it (and without another owner device) ownership is unrecoverable: the
repository keeps working for its members, but its membership, policy, and hosts are frozen. A client MUST
NOT send the phrase, the entropy, the seed, or any owner private key to a host.

### 3.2 Members

A **member identity** is a per-device Ed25519 + X25519 keypair, as in 0.4. How a client stores it at rest is
a client concern. A person using two devices as a non-owner is two members. Members get no recovery
phrase: a member who loses a device generates a new keypair and is invited again (§8.1).

A member key that appears in a repository's removals (§4.2) is never a member of that repository again
(§6.1); a removed person rejoins with a new keypair.

The **key fingerprint** a client shows for a member is `hex(SHA-256(ed25519PublicKey || x25519PublicKey)[0..8])`
over the raw keys, rendered as four groups of four hex digits separated by `-` (`xxxx-xxxx-xxxx-xxxx`).

### 3.3 Host identity and host-issued authentication

**Host key.** Every host has an Ed25519 **host key**. It identifies the host in a repository's `hosts` set,
in a member's `homeHostKey`, in acceptances (§8.2), in tokens (§11), and in host-to-host requests (§9.3).
A host is matched by its host key and only by its host key. A **locator** (`host` or `host:port`) is a
dialing hint that travels beside the key; no rule in this specification depends on DNS or TLS hostname
binding. A host SHOULD keep its host key for its whole life, because changing it detaches it from every
repository that lists the old key.

**Authentication.** The host is the token issuer. There is no external identity service in the protocol.
A host mints its own bearer tokens for any Ed25519 key that signs its challenge:

1. `challenge { ed25519PublicKey } → { nonce }`. The host returns a single-use random nonce of at least
   32 bytes (base64) with a short TTL (RECOMMENDED at most 2 minutes).
2. `token { ed25519PublicKey, nonce, signature } → { token, expiresAt }`. The client signs the
   **challenge transcript** with its Ed25519 private key:

   ```
   challengeMessage = CE(tag "avp/challenge/v1", bytes(hostKey), bytes(ed25519PublicKey), bytes(nonce))
   signature        = Ed25519-Sign(ed25519PublicKey, challengeMessage)
   ```

   where `hostKey` is the 32-byte host key of the host the client is authenticating to (the key the client
   matches that host by: from the repository's `hosts`, a `homeHostKey`, a token of §11, or discovery,
   §11.7), `ed25519PublicKey` is the 32-byte key requesting the token, and `nonce` is the raw nonce bytes
   (the base64-decoded `nonce`). A client MUST NOT sign the raw nonce, or any other bytes a host supplies,
   outside this transcript. The host MUST build `challengeMessage` with its own host key and verify the
   signature over it against `ed25519PublicKey`. It MUST reject (`401 unauthorized`) a signature that does
   not verify over that transcript, which includes a signature over the raw nonce bytes and a transcript
   built with another host key, and a nonce that was already used, has expired, or was not issued for that
   key. It then mints a token whose subject is that key.

   The host chooses the nonce, so the transcript is what keeps the challenge from being a signing oracle.
   Its `avp/challenge/v1` tag separates it from every other signed construction (§4.1): no nonce a host
   picks makes `challengeMessage` equal to a commit, leave, manifest, or other signed message. Its
   `hostKey` binds the signature to one host: a host that relays another host's nonce to a client gets a
   signature that the other host rejects.

The token format is host-defined and opaque to clients. A token is **host-local**: it is valid only at the
host that issued it, and a client MUST cache tokens keyed by host key and MUST NOT present a token issued by
one host to another. Tokens SHOULD be short-lived. Every client operation of §10 except discovery carries
the token in `Authorization: Bearer <token>` and is authorized by matching the token subject against the
manifest state; a host MUST NOT require any account lookup to authorize a member.

**Deployment access control.** A host MAY require an out-of-band credential (for example its own user
session) before it mints a token, before it agrees to store a new repository (`createRepo`, `prepareJoin`),
or before it serves a member, and MAY apply quotas. This decides who may use the host. It never grants
membership, ownership, or any cryptographic capability, and it does not change any request or response
shape: a client that lacks the credential receives `401 unauthorized`, `403 forbidden`, or
`429 quota_exceeded`.

## 4. Canonical encoding

Every signed or hashed structure in AVP is a byte string built by the **canonical encoding (CE)** writer.
It is deterministic and language-neutral; there is no JSON canonicalization anywhere in a signed or hashed
input. The byte layouts below are exact, and the vectors pin them (§14).

### 4.1 CE writer

A CE byte string is the concatenation of these items, in the order a construction lists them:

| Item | Bytes |
|---|---|
| `tag(label)` | the UTF-8 bytes of `label`, then one `0x00` byte |
| `bytes(b)` | `u32BE(len(b)) \|\| b` |
| `str(s)` | `bytes(UTF8(s))` |
| `i64(n)` | the 8-byte big-endian two's-complement encoding of `n` |
| `bool(b)` | one byte, `0x00` for false, `0x01` for true |
| `count(n)` | `u32BE(n)` |

`u32BE(n)` is the 4-byte big-endian unsigned encoding. Every CE string begins with exactly one `tag`. Inside
a CE string, every key, hash, nonce, IV, signature, and ciphertext goes through `bytes(...)`, never raw. The
one raw append in AVP is outside any CE string: `manifestHash` (§4.2) hashes a finished CE string followed
by the raw 64-byte owner signature. A list is written as
`count(n)` followed by its `n` elements, sorted by the stated key (§2) before encoding. `CE(tag "L", x, y)`
is shorthand for the string `tag(L) || x || y`.

**Domain separation.** Every message an AVP key signs is a CE string whose first item is a `tag`, and each
signed construction has its own label. The labels in the table below are distinct and none contains a
`0x00` byte, so the terminating `0x00` makes the tags prefix-free: two messages with different labels
differ within the shorter label or at its `0x00`, and no message of one construction can equal a message
of another, whatever the fields after the tag hold. An implementation MUST NOT sign, and MUST NOT verify an
AVP signature over, bytes that are not one of these constructions; in particular it MUST NOT sign bytes
another party supplies except as a field inside one of them. A new signed construction MUST take a new
label.

| Construction | Signing key | Signed message | Section |
|---|---|---|---|
| manifest state | owner key | `S = CE(tag "avp/manifest/v1", ...)` | §4.2 |
| commit author signature | member key (`author`) | `CE(tag "avp/commit-sig/v1", bytes(commitId))` | §4.3, §7.1 |
| leave request | member key | `CE(tag "avp/leave/v1", str(repoId), bytes(memberKey), i64(at))` | §8.4, §11.4 |
| challenge | the key requesting a token | `CE(tag "avp/challenge/v1", bytes(hostKey), bytes(ed25519PublicKey), bytes(nonce))` | §3.3 |
| acceptance | host key | `CE(tag "avp/accept/v1", str(repoId), bytes(memberKey), bytes(hostKey), i64(expiresAt))` | §8.2, §11.3 |
| host request | host key | `CE(tag "avp/host-req/v1", str(method), str(path), bytes(SHA-256(body)), i64(time))` | §9.3 |

The owner key is also a member key, so it signs every construction a member key signs. The other CE labels
(`avp/repo-id/v1`, `avp/commit/v1`, `avp/aad/v2`, `avp/link-code/v1`) are hashed or used as AEAD additional
data, never signed, and are distinct from the labels above.

### 4.2 Manifest state

A **manifest state** carries:

| Field | Type | Meaning |
|---|---|---|
| `repoId` | string | the repository id (below) |
| `manifestSeq` | int64 | `1` at genesis, `+1` per state |
| `prevManifestHash` | bytes | `manifestHash` of the previous state; empty at seq 1 |
| `ownerKey` | bytes (32) | the owner Ed25519 public key, fixed for the repository's life |
| `genesisNonce` | bytes | 16 random bytes at seq 1; empty in every later state |
| `schemeId` | string | the wrap scheme id (§4.4) |
| `keyEpoch` | int64 | the current data key epoch |
| `shareRefreshTokens` | bool | the refresh-token policy (§5.1), default `false` |
| `hosts` | `HostRef[]` | the hosts that replicate this repository |
| `members` | `MemberEntry[]` | the members, including the owner |
| `removals` | `Removal[]` | every member ever removed, cumulative |

- **`HostRef`** = `{ hostKey, locator }`: the host's Ed25519 host key and a locator string (§3.3).
- **`WrappedKey`** = `{ schemeId, ephemeralPublicKey, iv, ciphertext }`: the data key wrapped to one member
  (§4.4).
- **`MemberEntry`** = `{ ed25519PublicKey, x25519PublicKey, wrappedDataKey: WrappedKey, keyEpoch: int64,
  homeHostKey }`: a member, the data key of `keyEpoch` wrapped to its X25519 key, and the host key of its
  home host.
- **`Removal`** = `{ memberKey, removedAtSeq: int64, frontier: [commitId] }`: a removed member's Ed25519 key,
  the `manifestSeq` of the state that removed it, and its signed removal cutoff (§7.3).

**Encoding.** The state's canonical bytes `S` are:

```
S = tag("avp/manifest/v1")
    str(repoId)
    i64(manifestSeq)
    bytes(prevManifestHash)                  empty at seq 1
    bytes(ownerKey)
    bytes(genesisNonce)                      16 bytes at seq 1, empty after
    str(schemeId)
    i64(keyEpoch)
    bool(shareRefreshTokens)
    count(hosts)       then for each host, sorted by hostKey:
        bytes(hostKey)
        str(locator)
    count(members)     then for each member, sorted by ed25519PublicKey:
        bytes(ed25519PublicKey)
        bytes(x25519PublicKey)
        str(wrappedDataKey.schemeId)
        bytes(wrappedDataKey.ephemeralPublicKey)
        bytes(wrappedDataKey.iv)
        bytes(wrappedDataKey.ciphertext)
        i64(member.keyEpoch)
        bytes(homeHostKey)
    count(removals)    then for each removal, sorted by memberKey:
        bytes(memberKey)
        i64(removedAtSeq)
        count(frontier)    then each commit id, sorted:
            bytes(commitId)
```

**Signature and hash.**

```
ownerSignature = Ed25519-Sign(ownerKey, S)
manifestHash   = SHA-256(S || ownerSignature)
```

where `ownerSignature` is appended as its raw 64 bytes with no length prefix. A **signed manifest** is the
pair `SignedManifest = { state: ManifestState, ownerSignature }`. `manifestHash` is never sent; every party
recomputes it.

**Repository id.** `repoId` is client-minted and globally unique. It is derived from the owner key and the
genesis nonce and MUST NOT encode a host:

```
repoId = base64url-nopad( SHA-256( CE(tag "avp/repo-id/v1", bytes(ownerKey), bytes(genesisNonce)) )[0..16] )
```

which is 22 characters. The owner client generates `genesisNonce` as 16 bytes from a cryptographically
secure RNG. Hosts and clients MUST recompute `repoId` from the seq 1 state and reject a mismatch (§6.2).

**Wire form.** On the wire the lists MAY appear in any order (the encoding sorts them). A state that lists
the same `hostKey`, the same member `ed25519PublicKey`, the same removal `memberKey`, or the same frontier
commit id twice is malformed (`400 bad_request`). A host MUST store and serve each signed manifest so that
every field survives unchanged: a host that drops or rewrites any field breaks the owner signature, and
every client then rejects the state.

### 4.3 Commit and AAD v2

A **commit** carries:

| Field | Type | Meaning |
|---|---|---|
| `repoId` | string | the repository |
| `commitId` | bytes (32) | the commit id (below) |
| `parents` | `[commitId]` | zero for the first commit, one normally, two or more for a merge |
| `manifestSeq` | int64 | the manifest state the author wrote under |
| `manifestHash` | bytes (32) | the `manifestHash` of that state |
| `keyEpoch` | int64 | the epoch of the data key that encrypts the payload |
| `author` | bytes (32) | the author's member Ed25519 public key |
| `iv` | bytes (12) | the payload AES-GCM IV |
| `ciphertext` | bytes | the payload ciphertext with the 16-byte tag appended |
| `authorSignature` | bytes (64) | the author's signature over `commitId` |

**Header and id.**

```
H = tag("avp/commit/v1")
    str(repoId)
    count(parents)     then each parent id, sorted:
        bytes(parentId)
    i64(manifestSeq)
    bytes(manifestHash)
    i64(keyEpoch)
    bytes(author)
    bytes(iv)
    bytes(ciphertext)

commitId        = SHA-256(H)
authorSignature = Ed25519-Sign(author, CE(tag "avp/commit-sig/v1", bytes(commitId)))
```

`commitId` covers the ciphertext, so a commit id names exactly one payload. A commit that lists the same
parent id twice is malformed (`400 bad_request`).

**AAD v2.** The payload is encrypted with AES-256-GCM under the data key of `keyEpoch`, with a fresh random
12-byte `iv`, and with this additional authenticated data:

```
AAD = tag("avp/aad/v2")
      str(repoId)
      i64(keyEpoch)
      bytes(author)
      count(parents)     then each parent id, sorted:
          bytes(parentId)
```

A conformant encoder MUST bind all four this way, so a ciphertext replayed under a different repository,
epoch, author, or parent set fails authentication. A client MUST build the AAD from the commit header
fields it received, and MUST treat a commit whose payload fails to decrypt as unreadable (§7.5).

Each commit carries the **full payload state** (§5), not a delta.

### 4.4 Wrap scheme (unchanged): `X25519-HKDF-SHA256-AESGCM-v1`

This is the default and, in 0.5, the only `schemeId`. Keys are raw encodings: X25519 keys are the raw
32-byte little-endian form (RFC 7748), and a data key is a 32-byte AES-256 key generated from a
cryptographically secure RNG for each key epoch. The scheme takes an `info` label; the data key wrap uses
`info = "avp/rdk-wrap/v1"`, and device linking uses `info = "avp/owner-link/v1"` (§11.6). To **wrap** a
secret to a recipient whose X25519 public key is `recipientPub`:

1. Generate a fresh ephemeral X25519 key pair `(ephemeralPriv, ephemeralPub)`.
2. `sharedSecret = X25519(ephemeralPriv, recipientPub)`, the raw 32-byte ECDH output (not hashed).
3. `KEK = HKDF-SHA256(ikm = sharedSecret, salt = ephemeralPubRaw, info = UTF8(info), L = 32)`, where
   `ephemeralPubRaw` is the raw 32-byte ephemeral public key. The salt is never empty.
4. Pick a fresh 12-byte `iv`. `ciphertext = AES-256-GCM(key = KEK, iv = iv, aad = UTF8(info),
   plaintext = secret)`, with the 16-byte tag appended.
5. `WrappedKey = { schemeId, ephemeralPublicKey: ephemeralPubRaw, iv, ciphertext }`.

To **unwrap**, recompute `sharedSecret = X25519(recipientPriv, ephemeralPub)` and the same `KEK`, then
AES-256-GCM-decrypt with the same `aad`. The `info` label is bound as both the HKDF `info` and the GCM AAD,
so a wrap made under one label MUST fail to unwrap under the other.

## 5. Payload v2 and merge

The plaintext inside a commit's `ciphertext` is a UTF-8 JSON object:

```json
{ "v": 2, "accounts": { "<uuid>": <Account>, ... } }
```

```
Account = { "deleted"?: Stamp, "fields": { "<name>": Field, ... }, "bans": { "<serverId>": Field, ... } }
Field   = { "value": <json>, "at": <int64 ms>, "n": <int counter>, "by": "<member id>" }
Stamp   = { "at": <int64 ms>, "n": <int counter>, "by": "<member id>" }
```

A client MUST treat a payload whose `v` is not `2` as unreadable. The map key of `accounts` is the
account's player UUID.

**Fields.** The field names are exactly `username`, `accessToken`, `refreshToken`, `expiresAt`, `type`,
`lastUsed`, `lastUsedBy`, `sourceClient`, and `sourceUser`. Their values keep their 0.4 meanings:

| Field | Value |
|---|---|
| `username` | the last known name (string) |
| `accessToken` | the credential an implementation replays to use the account (string) |
| `refreshToken` | an OPTIONAL longer-lived credential that can mint a fresh `accessToken` (string or `null`) |
| `expiresAt` | the epoch-millisecond expiry of `accessToken`; absent or `0` means unknown (int64) |
| `type` | `"MICROSOFT"`, `"COOKIE"`, `"SESSION"`, or `"OFFLINE"` |
| `lastUsed` | epoch milliseconds (int64) |
| `lastUsedBy` | member id, or `null` |
| `sourceClient` | the client the alt was added from (string or `null`) |
| `sourceUser` | the user within that client (string or `null`) |

`accessToken`, `refreshToken`, and `expiresAt` are plain, opaque, implementer-defined values: this
specification defines only the field names, never their format or how they are obtained. Whether a
`refreshToken` may be present at all is governed by the signed policy (§5.1). `sourceClient` and
`sourceUser` are provenance: plain, opaque, implementer-defined strings that let a cross-client repository
attribute each alt. Implementations SHOULD set them when adding an alt and MUST tolerate their absence.
Like every field, they live inside the encrypted payload, so no host ever sees them.

**Bans.** `bans` maps a **server id** (a plain, opaque, implementer-defined string) to a `Field` whose
`value` is the most recent ban observed for the alt on that server,
`{ "banned": <bool>, "observedAt": <int64>, "source": "...", "detail": "...", "observedBy": "<member id or null>" }`,
or `null`. Keying by server lets a repository track that an alt is banned on one server but usable on
another.

Implementations MUST tolerate the absence of any field, of `bans` entries, and of `deleted`.

**Stamps and the hybrid logical clock.** Every `Field` and the `deleted` marker carry a stamp
`(at, n, by)`. Stamps are ordered by `at`, then `n`, then `by` compared as a string by its UTF-8 bytes; the
greatest stamp wins. A client keeps a hybrid logical clock (HLC) with state `(at, n)`:

- `tick(now)`: if `now > at`, the state becomes `(now, 0)`; otherwise it becomes `(at, n + 1)`. The new
  state, with `by` set to the client's member id, is the stamp of the write.
- `observe(stamp)`: if `stamp.at > at`, the state becomes `(stamp.at, stamp.n)`; if `stamp.at == at`, `n`
  becomes `max(n, stamp.n)`; otherwise the state is unchanged.

`now` is the client's wall clock in milliseconds. A client MUST observe every stamp of every payload it
merges before its next tick, so every stamp it writes is greater than every stamp it has seen. A client
MUST NOT issue two stamps with the same `(at, n, by)`. One edit takes one tick and MAY apply that stamp to
every field it sets.

**Writes.** To set a field, a client stores `{ value, at, n, by }` with a fresh stamp. To delete an
account, a client sets its `deleted` marker to a fresh stamp and leaves its fields and bans in place.

**Merge.** The merge of two or more payloads is computed per account:

1. The result's accounts are the union of the inputs' accounts.
2. For each account, each field name and each ban server id present in any input takes the `Field` with the
   greatest stamp among the inputs.
3. `deleted` is the greatest `deleted` stamp among the inputs, and is absent if no input has one.

An account is **deleted** if and only if `deleted` exists and is greater than every field stamp and every
ban stamp in that account. An edit after the deletion therefore brings the account back (with its fields),
and a deletion after the edit removes it. A deleted account stays in the payload with its marker; clients
hide it from use. Merge is commutative, associative, and idempotent; the merge vectors prove it on fixed
inputs (§14). (Two different `Field` values under an equal stamp cannot arise from conformant writers; if
they do, the result is implementation-defined.)

**Deletion markers** are never garbage-collected in 0.5 (§15).

**Client flow.** A client that pulls more than one head (§7.5) MUST merge every head it can read with its
local state and push the merge commit, whose `parents` are exactly the heads it merged, unless it is
read-only for that pull.

### 5.1 Refresh-token sharing policy

An `accessToken` buys a bounded session; a `refreshToken` buys durable access to the underlying account
until it is revoked at the provider that issued it. Sharing the second is a materially larger decision than
sharing the first, so a repository opts in to it explicitly.

`shareRefreshTokens` in the manifest state is that opt-in: boolean, **`false` by default**. It is
non-secret metadata. It says whether a class of field may be present inside the ciphertext, never what that
field contains. It is covered by the owner signature (§4.2), so only the owner can change it (§8.5); a host
that rewrites it breaks the signature and every client rejects the state.

**Fail closed.** A client MUST treat the policy as enabled **only** when the latest verified manifest state
has `shareRefreshTokens` equal to `true`. In the HTTP/JSON profile an absent `shareRefreshTokens` means
`false`. A client that cannot determine the policy withholds and MUST NOT infer permission from silence.

**Strip on write and on read.** For a repository whose policy is not `true`, a client MUST NOT include a
`refreshToken` or `expiresAt` field in any account of a payload it encrypts, and MUST remove both from every
account of every payload it decrypts or merges before the result reaches the rest of the client. Stripping
removes the `refreshToken` and `expiresAt` `Field` entries **entirely, including their stamps**. It applies
to merged-in heads written while the policy was `true`: the merged result carries neither field. Stripping
on read as well as on write is what makes the policy hold: a member running a modified or older build can
put a refresh token into a payload the policy forbids, and read-side stripping means every conformant member
discards it instead of storing it and re-sharing it on its own next write.

**Policy change.** A client SHOULD show a `false` to `true` change to the member the first time it sees it.

**Sharing is irrevocable.** Once a refresh token has reached a member's disk it cannot be recalled. Key
rotation and removal (§8.3) protect future commits only; they do not reach a credential a member has already
decrypted and stored. Setting `shareRefreshTokens` back to `false` stops future sharing and undoes none of
the sharing already done. The only effective revocation is upstream, at the provider that issued the token.

## 6. Manifest chain rules

Clients and hosts MUST verify every manifest state before they use it, store it, or serve it. A host
evaluates the checks below in the order given and answers with the first failure. A client applies the same
checks and discards a state that fails.

### 6.1 Validating a state

1. **Structure.** The state decodes, has no duplicate (§4.2), and its binary fields have these lengths:
   `ownerKey`, every `hostKey`, `ed25519PublicKey`, `x25519PublicKey`, `homeHostKey`, and removal
   `memberKey` 32 bytes; `prevManifestHash` empty at seq 1 and 32 bytes after; `genesisNonce` 16 bytes at
   seq 1 and empty after; every frontier commit id 32 bytes; every `wrappedDataKey` with a 32-byte
   `ephemeralPublicKey`, a 12-byte `iv`, and a 48-byte `ciphertext` (the 32-byte data key plus the 16-byte
   tag); `ownerSignature` 64 bytes. Otherwise `400 bad_request`.
2. **Owner signature.** `ownerSignature` verifies under `ownerKey` over `S` (§4.2). Otherwise
   `400 bad_request`. A host MUST reject a manifest state not signed by `ownerKey`.
3. **Genesis** (seq 1 only): §6.2. Otherwise `400 bad_request`.
4. **Chain link** (seq greater than 1): §6.3. Otherwise `409 manifest_conflict`, unless §6.5 applies.
5. **Content rules.** Every state MUST satisfy:
   - `hosts` is not empty.
   - `members` contains exactly one entry whose `ed25519PublicKey` equals `ownerKey`.
   - every member's `keyEpoch` equals the state's `keyEpoch`.
   - every member's `homeHostKey` equals the `hostKey` of an entry in `hosts`.
   - no member's `ed25519PublicKey` equals the `memberKey` of any removal.
   - every removal's `removedAtSeq` is at least 2 and at most the state's `manifestSeq`.

   A state with `manifestSeq` greater than 1 MUST also satisfy, against the previous state:
   - `repoId`, `ownerKey`, and `schemeId` are unchanged, and `genesisNonce` is empty.
   - `keyEpoch` equals the previous `keyEpoch` or the previous `keyEpoch + 1`.
   - every removal of the previous state appears unchanged (`memberKey`, `removedAtSeq`, and `frontier`).
   - every new removal (one not in the previous state) has `removedAtSeq` equal to this state's
     `manifestSeq`, and names a key that was a member of the previous state.
   - every member of the previous state that is not a member of this state has a new removal, and
     `ownerKey` is never removed.
   - if the state adds a removal, `keyEpoch` equals the previous `keyEpoch + 1`.

   Otherwise `400 bad_request`.
6. **Hosted.** A host MUST reject a state whose `hosts` does not contain its own host key, with
   `403 not_hosted`. A host MUST NOT accept a repository whose signed manifest does not list it. For
   states received by replication, this rule applies to the received tip (§9.2), the validated tip of the
   winning chain the receiver would hold after the offer, not to each state before it, so that a newly
   listed host can receive the earlier states of the chain, which do not list it (§8.1). A host that
   already holds the repository still keeps a validated state that this rule answers with
   `403 not_hosted`, as §8.6 describes, and does not serve the repository while its winning tip does not
   list it; keeping owner-signed states in this way is not accepting the repository.

### 6.2 Genesis

The seq 1 state is the **genesis** state. It MUST have an empty `prevManifestHash`, a 16-byte
`genesisNonce`, `keyEpoch` equal to `0`, no removals, and exactly one member, the owner. Its `repoId` MUST
equal the derivation of §4.2 recomputed from `ownerKey` and `genesisNonce`; hosts and clients MUST recompute
it and reject a mismatch (`400 bad_request`). The `ownerKey` of the genesis state is the repository's owner
key for its whole life.

### 6.3 Chain link and publication

A state with `manifestSeq = k > 1` links to the state at `k - 1`: its `prevManifestHash` MUST equal that
state's `manifestHash`. A host accepts a new state from a client (§10) only if `manifestSeq` equals its tip's
`manifestSeq + 1` and `prevManifestHash` equals its tip's `manifestHash`; otherwise it answers
`409 manifest_conflict`. An owner client MUST pull the manifest tip before publishing a state. On
`manifest_conflict` it MUST pull again with `sinceManifestSeq = 0`, re-verify the chain from genesis
(§6.4), rebuild its change on the verified tip, and retry once. The retry is bounded: one re-pull and one
retry per operation, never a loop; if the retry fails too, the client returns that error.

### 6.4 Rollback protection

A client MUST pin, per repository, the `manifestSeq` and `manifestHash` of the highest verified state it has
accepted. It MUST reject any chain that does not contain its pinned state, with one exception: a chain that
diverges from the client's own verified chain at a fork point at or below the pinned seq and wins there under
§6.5. Such a winning chain MAY have a lower tip `manifestSeq` than the pin; the client then re-pins to its
tip. A host can therefore not roll a client back, because every state needs the owner signature and a
winning diverged chain needs an owner-signed state at the fork point.

`pull` returns the states with `manifestSeq` greater than the client's `sinceManifestSeq` (§10). A client
whose first returned state does not link to its pinned state MUST pull again with `sinceManifestSeq = 0` and
apply §6.5 to the full chain.

A pin can also be stale with nothing above it: a device pinned on a state that lost the §6.5 tie rule at
its own `manifestSeq` gets no state from `pull`, so the check above never fires. A client that gets
`409 manifest_conflict`, or a `403` whose cause may be a stale pin (for example a `push` answered
`403 forbidden` because it cites a losing state whose epoch the winning chain raised), MUST therefore pull
again with `sinceManifestSeq = 0` and re-verify the full chain by §6.1 and §7.5, as for any pull, before it
retries once. If that chain does not contain its pin, the client adopts it only under the exception above
(it wins at a fork point at or below the pin, §6.5), re-pins to its tip, unwraps the data keys it gives
the client, and rebuilds the request on the new tip; any other chain is rejected as a rollback, and a
chain with a different genesis state is never adopted. If the re-pull leaves the pin unchanged, the `403`
is terminal (§10.4) and is not retried. The retry is bounded: one re-pull and one retry per operation,
never a loop; if the retry fails too, the client returns that error.

### 6.5 Diverged owner states

Only the owner can produce a state, so the chain never forks in normal operation. Two different validly
signed states with the same `manifestSeq` mean two owner devices published while offline from each other.
The rule is deterministic:

- **Tie rule.** Of two chains that agree up to `manifestSeq = k - 1` and hold different valid states at
  `manifestSeq = k` (the fork point), the chain whose state at `k` has the **bytewise-lower
  `manifestHash`** wins, together with every state after it on that chain. The other chain's states from `k`
  on are discarded from the chain. A host MUST retain them as **verified losing states** (each verified by
  §6.1 rules 1, 2, and 5 and linked by `prevManifestHash` to a verified state) so it can resolve commits that
  cite them (§7.2), and MUST serve them through replication `fetch` by manifest hash (§9.1).
- A host that holds the losing chain and receives the winning state at `k` (with every state needed to link
  it) MUST replace its states from `k` on with the winning chain. A host that holds the winning chain MUST
  NOT adopt a losing state into its chain: it answers `409 manifest_conflict` and, if the state verifies,
  retains it as a verified losing state. Both hosts therefore converge on the same tip.
- Hosts and clients SHOULD surface the event to the owner. Members invited only on the losing chain are not
  members and must be invited again; removals made only on the losing chain did not happen and must be made
  again.
- **Commits citing a losing state** (a verified losing state, §7.2) are re-checked against the winning
  chain's state at the same `manifestSeq`, in this order: (1) the removal cutoff (§7.3) takes precedence: a
  commit that fails it is rejected (`403 forbidden`), never held; (2) the commit is accepted if the winning
  chain has a state at that seq that lists the author as a member and whose `keyEpoch` equals the commit's
  `keyEpoch`; (3) the commit is rejected (`403 forbidden`) if it meets the **drop test**: the `keyEpoch` of
  the host's winning tip exceeds the commit's `keyEpoch`, or the author appears in the tip's `removals` and
  the commit is not covered by the frontier rule (§7.3); (4) otherwise it is **held** until an owner device
  decides.
- **Held commits.** A host MUST store a held commit and MUST NOT treat it as a head, serve it in `pull`,
  offer it to a peer, or count it against the head bound (§7.4). The one exception is a rotation commit
  (§8.3), which is always stored with its state and always returned by `fetch` and carried in `offer` with
  it, even while held. A host answers a client push of a held commit with `403 forbidden`. Every descendant
  of a held commit is held with it, not dropped. Hosts SHOULD surface held commits to the owner.
- **Deciding a held commit.** Each time a host accepts a new state on the winning chain, it MUST re-check
  every held commit against that state, in this order: the commit is **dropped permanently** if it meets the
  drop test (the owner moved on or removed the author), and every held descendant of it is dropped with it;
  otherwise it is **accepted**, with its held descendants re-checked in turn, if the state lists the author
  as a member and the state's `keyEpoch` equals the commit's `keyEpoch` (the owner re-invited the author);
  otherwise it stays held.
- **Losing epochs.** A commit written under an epoch raised only on a losing chain is encrypted under a data
  key the winning chain's members never received. If such a commit is later accepted, clients handle it as
  an unreadable head (§7.5).
- A host that switches to a winning chain MUST re-check, by the rules above, every accepted commit that
  cites a state from the fork point on. A commit that becomes held leaves the heads together with its
  descendants, which are held with it; a commit that fails the removal cutoff is dropped with its
  descendants (§7.3).

## 7. Commit acceptance rules

A host accepts a commit, from a client `push`, from `createRepo` or `publishManifest`, or from a peer's
`offer`, only if it passes every rule below against the host's current verified chain. A host evaluates them
in the order given and answers with the first failure. If the host already holds a commit with the same
`commitId`, the push is accepted again with no change.

### 7.1 Signature and id

The commit decodes, `repoId` matches the repository, and its binary fields have the stated lengths
(`400 bad_request`). `commitId` MUST recompute from the header (§4.3), and `authorSignature` MUST verify
under `author` over `CE(tag "avp/commit-sig/v1", bytes(commitId))`. Otherwise `400 bad_request`.

On the client routes the authenticated caller MUST be a member of the host's tip state and MUST equal
`author`; otherwise `403 forbidden`.

### 7.2 Membership, epoch, and manifest binding

- **Manifest binding.** A commit cites its manifest state by `manifestSeq` **and** `manifestHash`, so the
  citation is unambiguous even when owner states diverge (§6.5). The pair `(manifestSeq, manifestHash)` MUST
  identify a state the host holds and has verified as owner-signed for this repository: either the state on
  its winning chain at that seq, or a verified losing state (§6.5) with that seq and hash. If it is the
  winning chain's state, the rules below use it. If it is a verified losing state, §6.5 applies (re-check
  against the winning chain's state at that seq, or hold). If the host holds no such state, it tries to obtain
  it from its peers (`fetch` by manifest hash, §9.1) and otherwise answers `422 missing_parents` naming the
  manifest hash in `detail`, which is retryable like an unknown parent. A cited pair that never resolves to a
  valid owner-signed state of this repository is never accepted; the §6.5 re-check applies only to verified
  losing states.
- **Membership.** The `author` MUST be a member of the cited state. Otherwise `403 forbidden`.
- **Epoch.** `keyEpoch` MUST equal the cited state's `keyEpoch`. Otherwise `403 forbidden`.

A commit citing an older state than the tip is valid if it passes these rules: a member's write made
concurrently with a manifest change is not lost.

### 7.3 Removal cutoff

Rule 7.2 alone is not enough: a removed member keeps an old `manifestSeq` and the old epoch key, so it could
keep writing commits that cite them (backdating). The state that removes a member therefore carries a signed
**cutoff**, the removal's `frontier` (§4.2).

- Let `r` be a removal in the host's tip state. A commit whose `author` equals `r.memberKey` is valid
  **only if** its `commitId` is in `r.frontier`, or it is an ancestor of a commit whose id is in
  `r.frontier`. Every other commit by that author MUST be rejected with `403 forbidden`, whatever
  `manifestSeq` it cites and whatever its parents are.
- In particular, a commit by a removed author whose parent is in the frontier, but whose own id is neither in
  the frontier nor an ancestor of a frontier id, MUST be rejected (`403 forbidden`).
- **Ancestor** means reachable by following `parents` links one or more steps. Ancestry for this rule is
  computed from the `parents` of commit headers whose `commitId` recomputes and whose `authorSignature`
  verifies, whether or not the host has yet accepted them. A host that cannot decide because it lacks a
  frontier commit MUST NOT accept the commit; it answers `422 missing_parents` naming the frontier ids it
  lacks, and fetches them from a peer.
- When a host accepts a state that adds a removal, it MUST re-check every commit it holds by the removed
  member, and MUST drop from its heads, and stop serving and offering, every commit that fails the cutoff
  together with every descendant of it. A commit dropped this way counts as rejected for §7.4, so a commit
  that later names it as a parent is rejected with `403 forbidden`.

Consequence: a removed member's writes that never reached the owner before removal are dropped. That is the
price of making removal real. Their content survives only in the local state of a client that already
merged it.

The owner client builds the frontier (§8.3) from the heads it merges into the removal's rotation commit, so
every commit those heads descend from, by any author, stays valid on every host.

### 7.4 Parents and the head bound

- **Parents known.** Every parent MUST be a commit the host has accepted. Otherwise the host answers
  `422 missing_parents` with `detail` listing the missing ids (base64, separated by `,`), fetches them from a
  peer (§9), and the client MAY retry. A commit whose parent is held is held (§6.5); a commit whose parent
  the host rejected is rejected with `403 forbidden`. A commit that the removal cutoff dropped (§7.3) counts
  as rejected, so a child of a dropped commit is rejected with `403 forbidden`.
- **Heads.** Heads are accepted commits with no accepted children. A host MUST keep every head; a commit
  stops being a head only when a commit naming it as a parent is accepted (or when §6.5 holds or drops it,
  or §7.3 drops it).
- **Head bound.** A host SHOULD bound the number of heads per repository (RECOMMENDED 16). A client `push`,
  and the commit of `publishManifest`, is evaluated by the number of heads it **would leave**: the current
  heads, minus those named in its `parents`, plus one. Only a commit that would leave **more than** the bound
  is rejected, with `409 too_many_heads`, a terminal error asking the client to merge first. A merge commit
  that reduces the number of heads MUST be accepted at the bound. A host MUST NOT apply the head bound to
  commits it receives by replication (§9), so that hosts converge.

### 7.5 Client checks and old-epoch heads

A client checks each commit it pulls on its own terms. It never trusts the host's acceptance by itself: what
authorizes a commit is the author signature plus owner-signed membership at the commit's epoch. A client has
no notion of a held commit and never needs a losing state. A client MUST verify:

1. **Id and signature.** `commitId` recomputes from the header and `authorSignature` verifies (§7.1).
2. **Removal cutoff.** The cutoff of §7.3 against the removals of its verified chain. Since a pulled commit
   is a head, a head authored by a removed member passes only if its id is in that removal's frontier.
3. **Membership.** If `(manifestSeq, manifestHash)` is the state on the client's verified winning chain at
   that seq, the author is a member of that state and `keyEpoch` equals that state's `keyEpoch`. Otherwise
   (the pair is not on the client's chain), the author is a member of at least one state of the client's
   verified winning chain at or after the cited seq whose `keyEpoch` equals the commit's `keyEpoch`.

A client discards a commit that fails these checks: it does not merge it and never names it as a parent.

A head under an older `keyEpoch` (written concurrently with a rotation) can be read only by members who held
that epoch's key. Clients SHOULD retain prior epoch data keys locally so they can decrypt such heads and
merge them forward under the current epoch. A client that cannot read a head (no key for its epoch, or a
payload that fails to decrypt or is not `v: 2`) MUST NOT fail the pull and MUST NOT name the head as a
parent; it merges the heads it can read and leaves the unreadable one for another member.

## 8. Membership operations

Only the owner changes membership, policy, and hosts. Every change is a new manifest state signed by the
owner and published with `publishManifest` (§10). Members cannot invite.

### 8.1 Invite

The join flow has three tokens, all out of band (§11):

1. The owner gives the joiner a **repo locator** (§11.2): the `repoId`, the owner's home host, and the owner
   key fingerprint.
2. The joiner's client calls `prepareJoin` on its own home host (§8.2) and builds an **invite token**
   (§11.3) with its two public keys, its home host's key and locator, and the host's signed acceptance.
3. The owner's client verifies the invite token (§8.2), wraps the current data key to exactly the joiner's
   X25519 key, and publishes a new state adding the member (with `keyEpoch` equal to the state's,
   `homeHostKey` from the token) and, if the joiner's home host is not yet in `hosts`, that host.

The owner client MUST wrap the data key only to keys taken from an invite token, never to keys served by a
host. Clients SHOULD show the joiner's key fingerprint (§3.2) on both sides so the joiner and the owner can
compare them when the token travelled over an untrusted channel. The joiner's client then pulls from its
home host once the host has the repository; the newly listed host gets its first copy by replication from
any other listed host (§9), and no import call exists.

### 8.2 prepareJoin and host acceptance

A new host must agree before it carries a repository. Before producing an invite token, the joiner's client
calls `prepareJoin { repoId, memberKey }` on its home host, authenticated with that host's token. The
authenticated caller MUST equal `memberKey` (`403 forbidden`). This is where the host's access control and
quotas apply (§3.3). A host that agrees answers with a host-signed **acceptance**
`{ repoId, memberKey, hostKey, expiresAt, signature }` (§11.3). A host that refuses returns an error, and
the joiner's client tells the joiner that their host will not carry the vault. `expiresAt` SHOULD be short;
the reference hosts use 15 minutes.

**Owner verification.** Before it adds a member or a host, the owner's client MUST verify the invite token's
acceptance, and MUST reject the invite unless all of these hold:

- `signature` verifies under the acceptance's `hostKey` over
  `CE(tag "avp/accept/v1", str(repoId), bytes(memberKey), bytes(hostKey), i64(expiresAt))`;
- the acceptance's `repoId` equals the repository's `repoId`;
- the acceptance's `memberKey` equals the invite token's `ed25519PublicKey`;
- the acceptance's `hostKey` equals the invite token's `homeHostKey`;
- `expiresAt` is later than the owner client's current time.

The owner's client MUST NOT add a host to `hosts` without a valid acceptance from that host. A host SHOULD
record the acceptances it issues and SHOULD refuse (`403 forbidden`) to store, by replication, a repository
it does not hold unless it issued an acceptance for that `repoId` to a member whose `homeHostKey` is its own
key in the validated received tip (§9.2).

**Initial host.** At creation, `createRepo` on the owner's home host acts as the owner's own `prepareJoin`
plus genesis, so the same access control applies. The authenticated caller MUST equal the genesis
`ownerKey` (`403 forbidden`), the genesis state MUST pass §6 (including `403 not_hosted` if it does not list
the host), the first commit MUST have no parents, cite seq 1 and the genesis `manifestHash`, have `author`
equal to `ownerKey`, have `keyEpoch` `0`, and pass §7. A duplicate `repoId` is `409 duplicate_repo`.
The state and the commit are accepted together or not at all.

### 8.3 Remove

To remove a member, the owner's client MUST, in one publication:

1. pull the tip and the heads, and merge every head it can read (§5);
2. generate a new data key for `keyEpoch + 1` and wrap it to every remaining member, the owner included;
3. build the next state with the member dropped from `members`, a new removal
   `{ memberKey, removedAtSeq = this seq, frontier }`, and `keyEpoch + 1`;
4. build the **rotation commit**: the merged current state, encrypted under the new epoch, with `parents`
   equal to the heads it merged, citing the new state's `manifestSeq` and `manifestHash`, authored by the
   owner;
5. call `publishManifest { manifest, commit }`.

The owner client MUST set `frontier` to every head it merged into the rotation commit, plus every commit by
the removed member it has verified that is not an ancestor of one of those heads. Every commit by the
removed member that the owner client has seen is then in the frontier or an ancestor of it.

**Rotation commit.** The rotation commit of an epoch-raising state (one whose `keyEpoch` is the previous
`keyEpoch + 1`) is the commit published together with that state. It MUST cite that state's `manifestSeq`
and `manifestHash`, its `keyEpoch` MUST equal the new epoch, and its `author` MUST be `ownerKey`
(`400 bad_request` otherwise). A host MUST record which commit accompanied each epoch-raising state, so it
can hand the pair on by replication (§9.1).

**Atomicity governs adoption.** A host MUST adopt an epoch-raising state onto its winning chain only together
with its rotation commit, **atomically**: it validates the state (§6), then the commit against the new state
(§7), and stores both or neither. This holds on every path: `publishManifest` and replication alike (§9.1).
An epoch-raising state that would be adopted but arrives without its rotation commit is rejected with
`400 bad_request`. A rotation commit is always stored with its state and always travels with it in `fetch`
and `offer`. A host that keeps an epoch-raising state only as a verified losing state (§6.5) keeps its
rotation commit with it as a held commit. A verified losing state MAY be retained and replicated without its
rotation commit only when the sender never had it; the receiver then keeps the losing state for manifest
binding (§7.2) and cannot adopt it onto its chain until the rotation commit arrives. A state that does not change `keyEpoch` MAY carry a commit, which is then validated as a
push that cites the new state.

### 8.4 Leave

A member MAY publish a signed **leave request** `{ repoId, memberKey, at, signature }` (§11.4) with
`leave` (§10). The host MUST verify that `signature` verifies under `memberKey` (`400 bad_request`), that
`repoId` matches, that the authenticated caller equals `memberKey`, and that `memberKey` is a member of the
tip and is not `ownerKey` (`403 forbidden`). The host stores the request, keeps the latest one per member,
serves it in `pull` and replicates it (§9), and drops it once a state removes `memberKey`.

The leaving member's client stops syncing immediately. The owner's client SHOULD process pending leave
requests automatically the next time it is online, by removal (§8.3). Until then the leaver still holds the
current key, which is the same as the lack of backward secrecy on removal.

### 8.5 Refresh-token policy change

A change of `shareRefreshTokens` is a new state signed by the owner. It needs no commit. Clients apply the
new value from the first state that carries it (§5.1).

### 8.6 Host set changes

A change of `hosts` is a new state. Inviting a member whose home host is not yet listed adds it in the same
state (§8.1), with a valid acceptance (§8.2). A host MAY be dropped from `hosts` only when no member has it as
`homeHostKey` (§6.1). The owner client SHOULD publish a state that drops a host through a host that stays
listed, because the dropped host answers that publish with `403 not_hosted` (§6.1) even though it records
the state, and does not offer it to its peers.

A host that holds a repository and receives a validated state that does not list it MUST still adopt that
state as it adopts any other validated state (§6, §6.5), together with its rotation commit when it raises
the epoch (§8.3). This holds for a client publish, which the host answers with `403 not_hosted` by §6.1
rule 6 (the last rule, so the state passed every other rule), and for the validated states of an offer
whose received tip does not list the receiver, which the host answers with `403 not_hosted` (§9.2). Its
winning tip can then be a state that does not list it. A host whose winning tip does not list it treats
the repository as **not hosted**: it MUST NOT serve the repository to clients (`403 not_hosted`, §10.1) or
to peers, MUST NOT accept client writes for it, and MAY delete its copy entirely, after which it holds
nothing and a later listing is a first copy (§9.2). Keeping these owner-signed states is not accepting the
repository (§6.1). Nothing else marks the repository: the host is hosted again exactly when its winning
tip, decided by §6 and §6.5 over the states it holds and later receives by replication, lists it, whether
a later state lists it again or a diverged chain that lists it wins the tie rule at the fork point (§6.5).
Peers do not offer to or serve a host that is not in their tip's `hosts` (§9.2), so a dropped host learns
of a re-listing when a peer whose tip lists it offers the chain.

## 9. Replication between hosts

Hosts listed in a repository's signed `hosts` set replicate it with each other, each holding a full copy.
This section defines the messages and how a host validates and serves them. How hosts reach and
authenticate each other comes from a **deployment profile** (for example mutual TLS, or signed calls over an
existing node-to-node link). Whatever the transport, a host MUST validate every item it receives by the same
rules as a client write, except that §6.1 rule 6 applies to the received tip (§9.2) rather than to each
state; the transport only decides who may talk to it.

### 9.1 Messages

- **`heads(repoId)`** → `{ manifestTip: { manifestSeq, manifestHash }, heads: [id] }`: the sender's verified
  tip and its current head ids. Held commits (§6.5) are not heads.
- **`fetch(repoId, ids)`** → `{ manifests: [SignedManifest], commits: [Commit], leaves: [LeaveRequest] }`:
  for each requested id that is a manifest hash (of a winning-chain state or a verified losing state,
  §6.5), that state and every state before it on its chain, in ascending `manifestSeq`, and in `commits` the
  rotation commit (§8.3) of every epoch-raising state among them, even while that commit is held; for each
  requested id that is a commit id, that commit; and every pending leave request of the repository. Ids the
  sender does not hold are left out. Other held commits (§6.5) are not served.
- **`offer(repoId, manifests, commits, leaves)`** → `{ accepted: [id], rejected: [{ id, code }] }`: the
  sender pushes items it believes the receiver lacks. An offer that carries an epoch-raising state MUST carry
  its rotation commit in the same call (even while that commit is held), unless the state is a verified losing
  state whose rotation commit the sender never had (§8.3). The receiver applies the items in dependency
  order: a commit after the state it cites and after its parents, each epoch-raising state it adopts onto its
  winning chain together with its rotation commit as one atomic pair (§8.3, the same rules as
  `publishManifest`), a losing epoch-raising state with its rotation commit kept held, and leave requests
  last. States are validated by §6 (including §6.5, with rule 6 applied to the received tip, §9.2), commits
  by §7 without the head bound and without the caller check, and leave requests by §8.4 without the caller
  check. It reports each manifest hash and commit id as accepted or rejected with
  the error code it would have returned to a client (`missing_parents` included); both items of a rejected
  pair are rejected with the same code. An epoch-raising state that the receiver would adopt but that is
  offered without its rotation commit is rejected with `400 bad_request`. A leave request that fails
  validation is dropped.

### 9.2 Serving and catch-up

- A host MUST NOT serve `heads` or `fetch` for a repository to a host whose host key is not in that
  repository's `hosts` (in the serving host's tip), and MUST reject an `offer` from such a host, with
  `403 forbidden`.
- A host MUST NOT accept a repository whose signed manifest does not list it (§6.1): an `offer` whose
  received tip does not list the receiver is answered with `403 not_hosted`. The **received tip** of an
  offer is the tip of the winning chain the receiver would hold after validating the offer's items, with
  the catch-up below when it needs one, by §6 (including §6.5) with rule 6 left out. Losing states do not
  count, and for an offer that carries no states it is the receiver's current tip, so such an offer to a
  host whose tip does not list it is answered with `403 not_hosted`. The receiver MUST validate first and
  then check the validated received tip, before it stores anything from the offer or the catch-up. A state
  before the received tip is not rejected because it does not list the receiver (§6.1 rule 6).
- For a repository the receiver does not hold, the first copy is all or nothing: if the validated received
  tip does not list the receiver, it stores nothing from the offer or the catch-up; otherwise it ends
  holding a validated chain whose tip lists it. A first copy that would exceed the receiver's repository
  limits is rejected as §12.1 states (the reference hosts answer `429 quota_exceeded`) and stores nothing.
- A receiver that holds the repository MUST adopt the validated states it received (each epoch-raising
  state with its rotation commit, §8.3) even when the received tip does not list it, and MAY keep the
  other validated items; it then treats the repository as not hosted while its winning tip does not list
  it (§8.6).
- A host that receives an offer for a repository it does not hold, or one with missing items, gets the rest
  from the sender: `heads`; then `fetch` for the tip manifest hash, which returns the chain with the rotation
  commit of each epoch-raising state; then `fetch` for the head commits and, walking `parents` (and the
  states commits cite), for every commit and state it lacks, until every item links to items it holds. It
  then applies everything in the dependency order of `offer`, with each epoch-raising state and its rotation
  commit as one atomic pair. It validates a new repository from genesis (§6.2).
- **Catch-up after downtime** is the same sequence: `heads`, then `fetch`. Hosts run it when a peer
  reconnects and periodically.
- A host offers each write it accepts (a manifest state with its rotation commit when it raises the epoch, a
  commit, a leave request) to every other host in the repository's `hosts` that it can reach.
- **Retention.** A host MUST retain every manifest state of its winning chain and every verified losing state
  (§6.5). A host MAY prune the payload body of a commit that is no longer a head and is an ancestor of every
  head; commit headers SHOULD be kept long enough to answer ancestry questions (including the removal cutoff,
  §7.3). Because `commitId` covers the ciphertext, 0.5 does not define how a pruned commit is served to, or
  verified by, a peer that lacks it: a host that has pruned a body cannot bootstrap a new peer for that
  commit. The reference hosts do not prune. See §15.

### 9.3 Reference host-to-host profile: signed HTTP/JSON

The reference hosts ship this profile. Other deployments MAY use another; the proto's `Replication` service
carries the same messages for a gRPC profile.

**Routes.** `POST /v1/host/repos/{repoId}/heads` (body `{}`), `POST /v1/host/repos/{repoId}/fetch`
(body `{ ids }`), and `POST /v1/host/repos/{repoId}/offer` (body `{ manifests, commits, leaves }`), with the
responses of §9.1 and JSON as in §10.2.

**Request signature.** Every request carries three headers:

- `AVP-Host-Key`: the sender's host key, base64;
- `AVP-Host-Time`: the sender's current time in epoch milliseconds, decimal;
- `AVP-Host-Signature`: base64 of
  `Ed25519-Sign(hostKey, CE(tag "avp/host-req/v1", str(method), str(path), bytes(SHA-256(body)), i64(time)))`,

where `method` is the uppercase HTTP method (`POST`), `path` is the request path exactly as sent (for
example `/v1/host/repos/<repoId>/offer`, without scheme, authority, or query), `body` is the exact request
body bytes (SHA-256 of the empty string for an empty body), and `time` is the `AVP-Host-Time` value. The
receiver MUST reject the request with `401 unauthorized` if a header is missing, if the key is not in its
static peer list, if the signature does not verify, or if `|now - time|` exceeds 60 seconds. The repository
rules of §9.2 then apply.

**Configuration.**

- Peers come from the environment variable `AVP_PEERS="<base64 hostKey>@<http base url>,..."`: a
  comma-separated static list. Only these keys may call the host routes.
- The host identity seed comes from `AVP_HOST_SEED` (hex, 32 bytes, the RFC 8032 seed of the host key). When
  it is unset the host generates a random seed at start.

**Cadence.** A reference host replicates on startup, after every accepted write (an `offer` to each peer
whose key is in the repository's `hosts`), and every 5 seconds (`heads`, then `fetch` for what it lacks).
A host that uses this profile MUST send `heads`, `fetch`, and `offer` for a repository only to peers whose
key is in that repository's `hosts` in its winning tip, or, for a first copy it does not yet hold, to the
peer that offered it (§9.2). A peer that is not listed therefore cannot enumerate the repository ids the
host holds. It can still confirm an id it already knows, because the host answers its `heads` for a
repository it holds with a `403` (§8.6, §9.2) and for an id it does not hold with `404 not_found`. A newly
listed host gets its first copy from a listed host that offers it.

**Test control.** When `AVP_TEST_CONTROL=1`, a reference host serves `POST /v1/test/replication
{ paused: bool }`. While paused it sends no host traffic and answers every inbound host route with `503`. A
production host MUST NOT enable this route.

## 10. Transport surface and errors

### 10.1 Operations

| Operation | Purpose | Authorization |
|---|---|---|
| `challenge`, `token` | Host-issued authentication (§3.3) | none |
| `createRepo` | Genesis state (seq 1) plus first commit (§8.2) | caller is the genesis `ownerKey` |
| `pull` | Manifest chain since the client's pinned seq, the heads it lacks, pending leave requests | caller is a member of the tip |
| `push` | One commit, a normal write or a merge (§7) | caller is a member of the tip and the `author` |
| `publishManifest` | New owner-signed state, with its rotation commit when it rotates the key (§8) | caller is `ownerKey` |
| `leave` | Signed leave request (§8.4) | caller is the leaving member |
| `prepareJoin` | Joiner asks its home host to carry a repository; returns an acceptance (§8.2) | caller is `memberKey` |

Every repository operation except `prepareJoin` and `createRepo` answers `404 not_found` for a repository the
host does not hold, and `403 not_hosted` for one whose winning tip does not list the host (§8.6).

**pull** `{ sinceManifestSeq, knownHeads: [id] }` → `{ manifests, heads, leaves }`: `manifests` is every
state with `manifestSeq` greater than `sinceManifestSeq`, in ascending order; `heads` is every head commit
whose id is not in `knownHeads`; `leaves` is every pending leave request. There is no "unchanged" or
"conflict" outcome.

**push** `{ commit }` → `{ accepted: true, heads: [id] }`: the host's heads after the commit. A push based on
stale heads is simply a new fork; the next pull shows the client the heads to merge.

### 10.2 HTTP/JSON profile

JSON bodies use the proto field names in `camelCase`, binary fields as base64 with padding (§2), and the token
in `Authorization: Bearer <token>`. The conformance schema is
[`schema/avp.schema.json`](schema/avp.schema.json) and the route surface is [`openapi.yaml`](openapi.yaml).
`repoId` in a path is percent-encoded as a path segment.

| Route | Body → Response |
|---|---|
| `POST /api/auth/keypair/challenge` | `{ ed25519PublicKey }` → `{ nonce }` |
| `POST /api/auth/keypair/token` | `{ ed25519PublicKey, nonce, signature }` → `{ token, expiresAt }`; the host mints the token |
| `POST /v1/repos` | `{ manifest: SignedManifest, commit: Commit }` → `SignedManifest` |
| `POST /v1/repos/{repoId}/pull` | `{ sinceManifestSeq, knownHeads: [id] }` → `{ manifests: [SignedManifest], heads: [Commit], leaves: [LeaveRequest] }` |
| `POST /v1/repos/{repoId}/push` | `{ commit }` → `{ accepted: true, heads: [id] }` |
| `POST /v1/repos/{repoId}/manifest` | `{ manifest, commit? }` → `SignedManifest` |
| `POST /v1/repos/{repoId}/leave` | `LeaveRequest` → `{}` |
| `POST /v1/prepare-join` | `{ repoId, memberKey }` → `Acceptance` |
| `POST /v1/host/repos/{repoId}/heads` | host-signed `{}` → `{ manifestTip, heads: [id] }` (§9.3) |
| `POST /v1/host/repos/{repoId}/fetch` | host-signed `{ ids: [id] }` → `{ manifests, commits, leaves }` (§9.3) |
| `POST /v1/host/repos/{repoId}/offer` | host-signed `{ manifests, commits, leaves }` → `{ accepted: [id], rejected: [{ id, code }] }` (§9.3) |
| `GET /.well-known/avp` | → `{ version, profiles, hostKey }` (§11.7) |

### 10.3 gRPC profile

[`proto/avp.proto`](proto/avp.proto) is canonical. Field numbers and names are stable. Implementations MAY
support either or both profiles. The gRPC profile is a framing change only: the operations, authorization,
error codes, limits, and every signed construction are those of the HTTP/JSON profile.

**Service.** The `avp.Vault` service carries every client operation of §10.1 and discovery (§11.7):

| RPC | Operation (§10.1) | HTTP/JSON route (§10.2) | Authorization |
|---|---|---|---|
| `GetHostInfo` | discovery (§11.7) | `GET /.well-known/avp` | none |
| `Challenge` | `challenge` | `POST /api/auth/keypair/challenge` | none |
| `Token` | `token` | `POST /api/auth/keypair/token` | none (the host mints the token) |
| `CreateRepo` | `createRepo` | `POST /v1/repos` | bearer; caller is the genesis `ownerKey` |
| `Pull` | `pull` | `POST /v1/repos/{repoId}/pull` | bearer; caller is a member of the tip |
| `Push` | `push` | `POST /v1/repos/{repoId}/push` | bearer; caller is a member of the tip and the `author` |
| `PublishManifest` | `publishManifest` | `POST /v1/repos/{repoId}/manifest` | bearer; caller is `ownerKey` |
| `Leave` | `leave` | `POST /v1/repos/{repoId}/leave` | bearer; caller is the leaving member |
| `PrepareJoin` | `prepareJoin` | `POST /v1/prepare-join` | bearer; caller is `memberKey` |

**Authentication.** The token travels in the `authorization` request metadata as `Bearer <token>`. A token is
host-local (§3.3), not profile-local: a host that serves both profiles MUST accept, over either profile, a
token it minted over either profile.

**Addressing.** There is no path. The repository is the one the request body names: `CreateRepo`
`manifest.state.repoId`, `Pull` `repoId`, `Push` `commit.repoId`, `PublishManifest` `manifest.state.repoId`,
`Leave` `repoId`, and `PrepareJoin` `repoId`. A malformed `repoId` is `bad_request`.
`PullRequest.repoId` is a gRPC-only addressing field: an HTTP/JSON pull body never carries it (the path
does), and [`schema/avp.schema.json`](schema/avp.schema.json) does not list it.

**Encoding.** Binary values are base64 strings exactly as in §2 and §10.2. Proto3 has no presence for
scalars: a scalar left at its default is read as that default, and a host MUST NOT tell it apart from an
explicit default. A message-typed field that the JSON schema requires (for example `CreateRepoRequest.commit`,
`PushRequest.commit`, `PublishManifestRequest.manifest`, `SignedManifest.state`,
`MemberEntry.wrappedDataKey`) MUST be present; a request without it is `bad_request`.

**Errors.** A refused call ends with the gRPC status below, and the status message is the §10.4 `code`
string exactly:

| `code` | gRPC status |
|---|---|
| `bad_request` | `INVALID_ARGUMENT` |
| `unauthorized` | `UNAUTHENTICATED` |
| `forbidden`, `policy_denied`, `not_hosted` | `PERMISSION_DENIED` |
| `not_found` | `NOT_FOUND` |
| `duplicate_repo` | `ALREADY_EXISTS` |
| `too_many_heads`, `manifest_conflict`, `missing_parents` | `FAILED_PRECONDITION` |
| `quota_exceeded`, `too_large` | `RESOURCE_EXHAUSTED` |

The §10.4 `detail`, when present, travels in the `avp-error-detail` trailing metadata (ASCII), and the §12.2
`Retry-After` in the `retry-after` trailing metadata as decimal seconds. A client MUST branch on the status
message when it is a §10.4 code and fall back to the gRPC status code when it is not, as an HTTP/JSON
client falls back to the HTTP status. A request that does not decode as the RPC's request message MAY be
refused with the gRPC library's own status, the counterpart of the bare `400` exception of §10.4.

**Limits.** §12 applies to the encoded request message: a request over the host's body limit is `too_large`
(`RESOURCE_EXHAUSTED`).

**Values.** A host MUST store and serve an item with the same decoded values whichever profile carried it,
so an item written over one profile pulls over the other unchanged. Signatures cover the canonical encoding
of §4.1, built from the decoded values, and never a transport encoding.

**Discovery.** `GetHostInfo` answers what `GET /.well-known/avp` answers (§11.7).

**Replication.** The `Replication` service carries `Heads`, `Fetch`, and `Offer` (§9.1) for a deployment
whose host-to-host profile is gRPC; this section does not change it or §9.3.

### 10.4 Errors

In the HTTP/JSON profile, any non-`2xx` response body is an **error object**:

```json
{ "error": "<human-readable message>", "code": "<machine code>", "detail": "<optional context>" }
```

`error` is a human-readable message and is always present; clients MUST NOT parse it. `code` is an OPTIONAL
stable machine token from the table below that a client MAY switch on; when it is absent the client falls
back to the HTTP status. `detail` is OPTIONAL extra context. The schema is
[`schema/avp.schema.json`](schema/avp.schema.json) `#/$defs/Error`.

One exception: a request whose target cannot be parsed as a path (for example `/v1/repos/%zz/pull`, a `%`
not followed by two hex digits) MAY be answered with a bare `400` without the error object, since an HTTP
server can refuse such a request line before any route runs. Clients and conformance harnesses then check
only the status.

| Status | `code` | Meaning |
|---|---|---|
| `400` | `bad_request` | Malformed body or parameters, a bad signature, an id or `repoId` that does not recompute, or an epoch-raising state without its rotation commit (§8.3) |
| `401` | `unauthorized` | Missing or invalid token, an expired or reused challenge nonce, or a bad host request signature |
| `403` | `forbidden` | Not a member, a commit after the removal cutoff, an epoch mismatch, a held commit, the caller is not the required key, or an operation disallowed by policy (`policy_denied`) |
| `403` | `not_hosted` | This host is not in the manifest's `hosts` |
| `404` | `not_found` | The repository does not exist on this host |
| `409` | `duplicate_repo` | `createRepo` with a `repoId` that already exists |
| `409` | `too_many_heads` | The push would leave more heads than the bound; merge first (§7.4) |
| `409` | `manifest_conflict` | The published seq is not tip + 1, the previous hash does not match, or the state loses the tie rule (§6.3, §6.5) |
| `422` | `missing_parents` | A parent, a cited manifest state, or a frontier commit is unknown; `detail` lists the ids. The host fetches them and the client MAY retry |
| `429` | `quota_exceeded` | A deployment resource limit was hit |

Every error except `422 missing_parents` is **terminal** for that request: a client MUST NOT retry it
unchanged. `too_many_heads` and `manifest_conflict` tell the client what to do next (merge, or pull from
seq 0 and rebuild, §6.3, §6.4); a request rebuilt on a new tip after that re-pull is not unchanged. The gRPC profile (§10.3) maps them to
`INVALID_ARGUMENT` (`bad_request`), `UNAUTHENTICATED` (`unauthorized`), `PERMISSION_DENIED` (`forbidden`,
`policy_denied`, `not_hosted`), `NOT_FOUND`, `ALREADY_EXISTS` (`duplicate_repo`), `FAILED_PRECONDITION`
(`too_many_heads`, `manifest_conflict`, `missing_parents`), and `RESOURCE_EXHAUSTED` (`quota_exceeded`,
`too_large`), and carries the same `code` string as the status message.

## 11. Tokens, addressing, device linking

### 11.1 Token encoding

A token is base64url-nopad (§2) over compact JSON with its fields in the order listed, and `"v": 2` where the
token has a `v`. Binary values inside the JSON are base64 (§2). A decoder MUST accept any valid JSON object
that carries the required fields, regardless of field order or insignificant whitespace, and MUST reject a
token whose `v` is not `2`. Tokens travel out of band (paste, QR) and never through a host. The byte-exact
tokens are in [`vectors/federation.json`](vectors/federation.json).

### 11.2 Repo locator and `avp://` addresses

`RepoLocator { v, repoId, hostKey, hostLocator, ownerFingerprint }`, sent by the owner to a joiner (§8.1):
the repository, the owner's home host (its key and locator), and
`ownerFingerprint = hex(SHA-256(ownerKey)[0..8])` (16 hex digits). A joiner's client MUST check, once it pulls
the repository, that the genesis `ownerKey` matches `ownerFingerprint`.

The URI `avp://<hostLocator>/<repoId>` is a **locator**: "you can reach this repository at this host". The
repository's identity is `repoId` alone, which never encodes a host.

### 11.3 Invite token and acceptance

`InviteToken { v, ed25519PublicKey, x25519PublicKey, homeHostKey, homeHostLocator, acceptance }`, sent by
the joiner to the owner (§8.1). `acceptance` is the `Acceptance` object from `prepareJoin`:

`Acceptance { repoId, memberKey, hostKey, expiresAt, signature }`, where `signature` is
`Ed25519-Sign(hostKey, CE(tag "avp/accept/v1", str(repoId), bytes(memberKey), bytes(hostKey), i64(expiresAt)))`.
The owner client verifies it as §8.2 states.

### 11.4 Leave request

`LeaveRequest { repoId, memberKey, at, signature }`, where `at` is the leaving client's time in epoch
milliseconds and `signature` is
`Ed25519-Sign(memberKey, CE(tag "avp/leave/v1", str(repoId), bytes(memberKey), i64(at)))`. It is sent to the
host with `leave` (§8.4) as a JSON body, not out of band and not base64url-wrapped.

### 11.5 Fingerprints

The member key fingerprint is §3.2. The owner fingerprint is §11.2.

### 11.6 Owner device linking

An owner who still has a working device can add a new one without typing the phrase. Clients SHOULD offer
it; the phrase remains the fallback.

1. The new device generates a fresh ephemeral X25519 key pair and shows a **link request**
   `LinkRequest { v, ephemeralPublicKey }` and its **confirmation code**: the first 4 bytes of
   `SHA-256(CE(tag "avp/link-code/v1", bytes(ephemeralPublicKey)))` read as `u32BE`, taken modulo 1 000 000,
   and written as 6 decimal digits with leading zeros.
2. The owner enters the request on an existing owner device. That device MUST show the confirmation code it
   computes and MUST require the owner to confirm that it matches the code on the new device before it
   continues.
3. The existing device returns a **link grant** `LinkGrant { v, wrap }`, where `wrap` is a `WrappedKey` of the
   owner's 32-byte **mnemonic entropy** (not the derived seed) under the default wrap scheme (§4.4) to
   `ephemeralPublicKey`, with `info = "avp/owner-link/v1"` as both the HKDF info and the GCM AAD. Carrying the
   entropy lets the linked device regenerate and show the phrase.
4. The new device unwraps it with its ephemeral private key, derives the mnemonic, the seed, and the owner
   keys (§3.1), and discards the ephemeral key. A grant that does not unwrap under `avp/owner-link/v1` MUST
   be rejected.

### 11.7 Discovery

A host MAY expose an unauthenticated `GET /.well-known/avp` returning at least
`{ "version": "0.5", "profiles": ["grpc" | "http-json", ...], "hostKey": "<base64 host key>" }`, so a client
resolving a locator knows which transport profiles to use and can check the host key against the one in a
token or in `hosts`. A client MUST match hosts by key (§3.3), never by locator alone. Absent discovery, a
client SHOULD default to the HTTP/JSON profile over HTTPS.

Over gRPC, discovery is the `GetHostInfo` RPC (§10.3), which answers the same document. `profiles` lists
`grpc` on a host that serves the gRPC profile and `http-json` on one that serves the HTTP/JSON profile. A
locator names where the host's HTTP/JSON profile is reached; a host that serves the gRPC profile at another
address states that address out of band.

## 12. Operational limits

Except where a MUST is stated, these are RECOMMENDED practice. A host states its actual limits out of band.

### 12.1 Resource limits

A host SHOULD bound, per its deployment policy, at least the size of a commit, the number of members in a
repository, the number of repositories per tenant, and the number of heads per repository (RECOMMENDED 16,
§7.4). When an operation exceeds a limit the host MUST reject it with a terminal error: `413` (`too_large`)
for an oversize body, `429` (`quota_exceeded`) or `403` (`policy_denied`) for a count or policy limit, and
`409 too_many_heads` for the head bound. As non-normative starting points, a payload of a few megabytes, a
few hundred members, and a per-tenant repository count in the low thousands are generous for alt sharing.

### 12.2 Rate limiting

A host MAY rate-limit any operation. When it does, it SHOULD return `429` with a `Retry-After` header and MAY
include `RateLimit-Limit`, `RateLimit-Remaining`, and `RateLimit-Reset`. A client SHOULD honor `Retry-After`
and SHOULD otherwise back off with jitter.

### 12.3 Idempotency and retries

A client MAY retry an operation whose response it did not receive. The protocol makes this safe:

- `pull`, `heads`, and `fetch` are reads.
- `push` of a commit the host already holds is accepted with no change (§7), so a push never double-applies.
- `createRepo` answers a retry after success with `409 duplicate_repo`; a client SHOULD then pull and treat
  the repository as created if its genesis state is the one it sent.
- `publishManifest` answers a retry after success with `409 manifest_conflict`; a client SHOULD then pull and
  treat the publication as done if the tip is the state it sent.
- `leave` and `offer` are idempotent: the host keeps one copy of each item.
- `prepareJoin` returns a fresh acceptance each time.

### 12.4 Repository identifiers

A `repoId` is the 22-character base64url-nopad string of §4.2. A host MUST reject a `repoId` that does not
recompute from the genesis state. Because ids are carried in paths, a client MUST percent-encode a `repoId`
as a path segment and a host MUST route on the escaped path.

### 12.5 Retention

Hosts MUST keep every manifest state of the winning chain and every verified losing state (§6.5, §9.2). A host
MAY prune the payload body of a commit that is no longer a head and is an ancestor of every head, and SHOULD
keep commit headers long enough to answer ancestry questions; 0.5 does not define how a pruned commit is
served to or verified by a peer that lacks it (§9.2). Deletion markers in payloads are never garbage-collected
in 0.5. The reference hosts prune nothing.

## 13. Invariants

A conformant implementation MUST uphold:

- **Zero-knowledge.** A host MUST NOT receive, store, or log a passphrase, recovery phrase, entropy, seed,
  data key, private key, or plaintext alt. It stores only ciphertext, wrapped keys, public keys, counters,
  ids, and signatures. After a full create and push, no stored value decodes to a plaintext alt field.
- **Owner authority.** Membership, wrapped keys, the key epoch, the refresh-token policy, and the host set
  change only by an owner-signed manifest state that every client and host verifies (§6). No path exists by
  which a host or operator can add a member, cause a data key to be wrapped to a key it controls, flip the
  policy, or derive the owner key.
- **Chain integrity.** The manifest chain is append-only per seq, links by hash, and is pinned by every
  client (§6.4); diverged owner states resolve by the tie rule to the same tip everywhere (§6.5).
- **Commit integrity.** Every accepted commit's id recomputes and its author signature verifies; the
  `(manifestSeq, manifestHash)` it cites resolves to a verified owner-signed state of the repository, and its
  author is a member at the commit's epoch of the winning chain's state at that seq (§7.1, §7.2, §6.5).
- **Rotation atomicity.** An epoch-raising state and its rotation commit are accepted together or not at all,
  on `publishManifest` and on replication alike (§8.3, §9.1).
- **No lost writes.** A host keeps every head; a write on a stale head becomes a fork, never an overwrite;
  merge is per field and loses no field (§5, §7.4). A commit citing a losing state is held, not dropped,
  until the owner decides (§6.5). The only writes dropped are those §6.5 drops permanently and those §7.3
  rejects.
- **Removal is real.** After removal, a removed member's commits are accepted only within the signed cutoff
  (§7.3), and new commits are under an epoch whose key was never wrapped to it.
- **Rotation correctness.** A removal increments `keyEpoch`; a removed member's old wrapped key cannot derive
  the new epoch's data key, and the AAD makes a ciphertext under the wrong epoch fail authentication.
- **Hosts by key.** Every host match (`hosts`, `homeHostKey`, acceptances, `not_hosted`, host-to-host
  serving) compares host keys (§3.3).
- **Domain separation.** Every AVP signature is over a CE string that begins with the distinct tag of its
  construction (§4.1). No key signs host-supplied bytes outside such a string, and a challenge signature
  covers the host key it was made for (§3.3), so no signature made for one construction, or for one host's
  challenge, verifies as another.

## 14. Conformance

An implementation is conformant if it satisfies every MUST above and reproduces the vectors in
[`vectors/`](vectors/), indexed by [`vectors/index.json`](vectors/index.json):

- **RFC-anchored primitives**: HKDF-SHA256 (`hkdf.json`), X25519 (`x25519.json`), and Ed25519 sign and
  verify (`ed25519.json`). The Ed25519 vector anchors every signature; the challenge transcript is pinned
  in `federation.json`.
- **Wrap scheme**: wrap and unwrap of a data key (`key-wrap.json`, §4.4).
- **Owner identity**: entropy to mnemonic, mnemonic to seed, and seed to the owner Ed25519 and X25519 keys
  (`bip39-owner.json`, §3.1), over the pinned English wordlist (`bip39-english.txt`).
- **Manifest**: the CE bytes of a state, its owner signature, its `manifestHash`, and the `repoId`
  derivation at seq 1 (`manifest.json`, §4.1, §4.2), independent of the input order of hosts, members,
  removals, and frontier ids.
- **Commit**: the header bytes, `commitId`, author signature, AAD v2 bytes, and AES-256-GCM ciphertext
  (`commit.json`, §4.3), independent of parent order.
- **Merge**: the merged payload for every permutation of each case's inputs, idempotence, the HLC, deletion
  and revival in both orders, per-server bans, and stripping after the policy is turned off
  (`merge.json`, §5, §5.1).
- **Acceptance rules**: fixed manifest chains and commit graphs with the expected accept or reject code of
  each step and the final heads (`acceptance.json`, §6, §7, §8.4), covering at least: genesis `repoId`
  recomputation, a genesis that does not list the host (`not_hosted` on a client write, accepted by
  replication as the start of a chain whose validated received tip lists the host, §9.2), a seq skip and a
  rollback (`manifest_conflict`), a bad owner signature, a non-member and an epoch mismatch (`forbidden`), an unknown
  parent (`missing_parents`), concurrent commits giving two heads, a merge collapsing heads, a merge accepted
  at the head bound, the push past the bound (`too_many_heads`), a removed member within the frontier, after
  the cutoff, and backdated as a child of a frontier commit (`forbidden`), diverged owner states (lower hash
  wins, a commit re-checked and accepted, a commit held), and a leave request with a bad signature.
- **Tokens and addresses**: every token of §11 (with the acceptance and leave signatures, the link
  confirmation code, and the owner and member fingerprints), `avp://` locators, and the challenge
  transcript `challengeMessage` of §3.3 with its signature (`federation.json`).
- **Negative cases**: `negative.json`, valid constructions with one mutation each that a conformant
  implementation MUST reject, including a manifest with a bad signature or a wrong previous hash, a commit
  whose id does not recompute or whose author signed another id, a payload whose AAD v2 has a swapped parent,
  a link grant unwrapped with the data key wrap label, an acceptance verified with another host key, the
  cross-construction and challenge cases of §3.3 and §4.1 (a challenge signature presented as a commit
  author signature over the same 32 bytes, a commit author signature presented as a challenge signature, a
  challenge signature made for another host key, and a signature over the raw nonce), and
  the Ed25519 signatures that strict verification (§2) rejects: a small-order public key or `R`, a
  non-canonical public key, and a non-canonical `S`. Reproducing the positive vectors is necessary but not
  sufficient.

Every committed vector is reproducible from documented seeds by [`vectors/generate.ts`](vectors/generate.ts)
(`--check` re-derives and asserts them; it also owns `negative.json`). See
[`vectors/README.md`](vectors/README.md).

A **host** additionally proves conformance by passing the black-box harness in [`harness/`](harness/), which
drives the client wire contract (the auth failure modes of §3.3, including a signature over the raw nonce
and a transcript built with another host key, `createRepo` checks, the pulled chain,
forks and merges, the head bound, `manifest_conflict`, the removal cutoff, leave, `prepareJoin`
acceptances, and zero-knowledge), and its multi-host scenarios, which drive §9 between two or more hosts
(convergence after a paused host, concurrent writes on two hosts, a removed member rejected on both, an
unlisted host refused, an old-epoch head merged forward, and diverged owner states converging). A host
that serves the gRPC profile (§10.3) additionally passes the same harness with `--profile grpc`.

## 15. Security considerations and open items

[`THREATMODEL.md`](THREATMODEL.md) gives the full adversary model. The considerations below hold for 0.5.

- **Token theft.** Tokens are bearer credentials; client-to-host transport MUST be TLS. Tokens are host-local
  (§3.3), short-lived, and scoped to membership.
- **Nonce handling.** Challenge nonces MUST be single-use with a short TTL to prevent replay of the signed
  challenge. The client signs the `avp/challenge/v1` transcript, never the host-chosen nonce alone (§3.3,
  §4.1).
- **Owner phrase.** Whoever holds the phrase, or an owner device, is the owner (THREATMODEL A7).
- **Host-to-host transport.** The protocol validates every replicated item; confidentiality and
  authentication of host-to-host links come from the deployment profile (§9).

Open items:

- **Algorithm negotiation.** `schemeId` names the wrap scheme, and 0.5 forbids changing it (§6.1); the
  choreography for upgrading a repository's scheme over its lifetime is not specified.
- **Ownership transfer.** `ownerKey` is fixed for a repository's life. Transferring ownership to another key
  is not specified.
- **Deletion-marker GC, commit pruning, and retention.** Deletion markers are kept forever (§12.5). A safe
  rule for collecting them once every head descends from the deletion and every member has synced past it is
  not specified. Hosts MAY prune commit bodies (§9.2), but because `commitId` covers the ciphertext, 0.5 does
  not define how a pruned commit is served to or verified by a peer that lacks it, so a host that has pruned
  a body cannot bootstrap a new peer for that commit. How long commit headers must be kept for ancestry
  questions is likewise not specified. The reference hosts do not prune.
- **Host freshness against a withholding host.** A host cannot forge or roll back, but it can withhold new
  heads or manifest states from its own members. A member on another host gets them anyway; a member whose
  only host withholds cannot, on its own, distinguish "nothing new" from "hidden".
