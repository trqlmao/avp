# Conformance vectors

Test vectors an implementation can check itself against. Each file is JSON with a `description` and one
or more `cases`. The conformance runner in [`../examples/conformance`](../examples/conformance) loads and
checks every file here with Node's `crypto`.

[`index.json`](index.json) is a machine-readable index of these files: each entry gives the file, its
`kind` (deterministic / rfc-primitive / composition / data / scenario / negative), the spec section, and the published
anchors, so a harness can enumerate the vectors instead of hardcoding filenames.

## AVP 0.5 construction vectors (generated)

These pin the 0.5 byte constructions. They are derived only from fixed seeds (listed in each file under
`seeds`) by [`generate.ts`](generate.ts), which owns them.

- [`bip39-english.txt`](bip39-english.txt), the BIP39 English wordlist, a byte copy of the upstream
  `bitcoin/bips` `bip-0039/english.txt` (2048 words, LF, trailing newline, SHA-256
  `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`, checked by `generate.ts --check`).
- [`bip39-owner.json`](bip39-owner.json), the owner identity of SPEC §3.1: entropy to the 24-word mnemonic,
  the PBKDF2 seed (empty passphrase), and the HKDF owner Ed25519 and X25519 keys. Its `anchors` are three
  256-bit cases of the Trezor reference vectors (`trezor/python-mnemonic` `vectors.json`, passphrase
  `TREZOR`), which pin entropy, mnemonic, and seed against an external implementation.
- [`manifest.json`](manifest.json), a four-state owner-signed chain (genesis, add members, remove a member
  with a two-id frontier, policy flip) for SPEC §4.1 and §4.2: the CE bytes `S`, the owner signature,
  `manifestHash`, and the seq 1 `repoId`. The wire lists are stored in descending order so an encoder that
  does not sort fails.
- [`commit.json`](commit.json), three commits (root, single parent, three-parent merge) for SPEC §4.3: the
  header bytes, `commitId`, author signature, AAD v2 bytes, and the AES-256-GCM ciphertext. Each commit
  cites a `manifest.json` state; the removal frontier in `manifest.json` names two of these commits.

The CE constructions have no published anchor, so the runner also re-derives every case by a second,
hand-written assembly of the SPEC layout (raw byte concatenation, independent of the encoder under test).

- [`federation.json`](federation.json), the out-of-band tokens and addressing of SPEC §11. Unlike the
  others it uses top-level `tokens`, `leaves`, `linkCodes`, `fingerprints`, and `uris` rather than
  `cases`. Each token case (`InviteToken`, `RepoLocator`, `LinkRequest`, `LinkGrant`) is a **decode
  oracle**: base64url-decoding `base64url` MUST yield `decoded`. `canonicalJson` is the compact encoding
  with the fields in the SPEC order and `"v": 2`, and `base64url` is its base64url-nopad form; a decoder
  MUST accept any field order and whitespace and MUST reject a `v` other than 2. The invite token's
  acceptance is signed by the joiner's home host over `acceptanceMessageHex`; each `leaves` case is a
  leave request body (JSON, not base64url) signed by its member over `signatureMessageHex`. The runner
  verifies both with `node:crypto` over a hand-assembled message. `linkCodes` are SPEC §11.6 confirmation
  codes (one has a leading zero), `fingerprints` are the member and owner fingerprints, and the link
  grant's `checker` holds the link private key (never on the wire) and the owner entropy it unwraps to.
  Each `avp://` URI case pins parse and format of `avp://<hostLocator>/<repoId>`.

## Merge vectors (hand-written)

- [`merge.json`](merge.json), the payload v2 merge of SPEC §5 and §5.1. Each case gives `inputs` and the
  `expected` merge, written by hand from the SPEC rule (greatest `(at, n, by)` stamp per field and per ban
  server id, `by` compared by UTF-8 bytes; greatest `deleted`), and `expectedDeleted`, the deletion state of
  each account. Merging the inputs in **every order** MUST give `expected`, merging `expected` with any
  input or with itself MUST give `expected`, and merge MUST be associative. When `stripRefresh` is true,
  the merged result is stripped of `refreshToken` and `expiresAt` (with their stamps) before comparing.
  `hlc` pins the hybrid logical clock: start at `start`, apply each `tick` or `observe`, and the state
  after each step MUST equal `expect`.

## Host acceptance scenarios (hand-written verdicts)

- [`acceptance.json`](acceptance.json), the host rules of SPEC §6, §7, §8.3, and §8.4 as replayable
  scenarios. The Rust and Java rule engines run this file unchanged. Its expectations are written by hand
  from the SPEC rule each scenario's `description` cites; the signed items are built from the
  `manifest.json` seeds, plus one extra data key for epoch 2 (32 bytes of `0x44`) that only the
  `content-epoch-jump-2` scenario uses.

  ```
  { description, scenarios: [ {
      name, description,              description cites the SPEC sections
      hostKey,                        base64 Ed25519 key of the host whose view this is (a.vault.example)
      headBound,                      16
      steps: [ { op, via, label, item, expect } ],
      finalHeads: [commitId],         base64, sorted
      finalHeld: [commitId],          base64, sorted
      finalTip: manifestHash | null,  base64 manifestHash of the winning chain's tip
      finalLeaves?: [{ memberKey, at }]  optional: the pending leave requests, sorted by memberKey
  } ] }
  ```

  Each step:

  - `op` is `"manifest"`, `"commit"`, or `"leave"`.
  - `item` for `manifest` is `{ manifest: SignedManifest, commit?: Commit }`, the `publishManifest` body.
    The commit, when present, is the genesis commit (the `createRepo` body), the rotation commit of an
    epoch-raising state, or a commit that cites the new state; the state and its commit are applied
    together or not at all (SPEC §8.2, §8.3). `item` for `commit` is a `Commit`; for `leave`, a
    `LeaveRequest`. All in the HTTP/JSON wire form (base64 binary).
  - `via` is the path the item arrived on. `"push"` is a client write (`push`, `createRepo`,
    `publishManifest`, `leave`) whose authenticated caller is the commit's author (the owner for a
    manifest and the commit carried with it, `memberKey` for a leave): the caller check of SPEC §7.1 and
    the head bound of §7.4 apply. `"offer"` is an item in a peer host's replication `offer` (SPEC §9.1):
    no caller check and no head bound.
  - `expect` is `"ok"` or one of the SPEC §10.4 codes `bad_request`, `forbidden`, `not_hosted`,
    `too_many_heads`, `manifest_conflict`, `missing_parents`. A held commit (SPEC §6.5) answers
    `forbidden` on either path.
  - `label` names the item for readers and failure messages only.

  After the last step, the host's heads (accepted commits with no accepted child) MUST equal
  `finalHeads`, its held commits `finalHeld`, and its tip `finalTip`, compared as sets for the lists.
  A stored commit whose removal cutoff cannot yet be decided (SPEC §7.3) is in neither list.

  Two answers are host level, not engine verdicts, and no scenario pins them: `createRepo` for a
  `repoId` the host already holds is `409 duplicate_repo` (SPEC §8.2, §12.3), and any operation on a
  repository the host does not hold is `404 not_found` (SPEC §10.1). A host answers both before it
  consults its rules engine, so the engine's verdict type has neither code.

  `not_hosted` is an engine verdict only for `via: "push"`: a client write of a state whose `hosts` does
  not list this host (SPEC §6.1 rule 6). For `via: "offer"` it is host level, like the two answers above:
  the host checks that the tip of the chain it is receiving lists it, and otherwise rejects the offer with
  `403 not_hosted` and stores nothing, before it applies any item of the offer or catch-up to its engine
  (SPEC §9.2). The engine therefore does not reject an offered state because it does not list this host,
  so a newly listed host can take the earlier states of the chain (SPEC §8.1); the offered steps of a
  scenario are items that passed that check. The engine reports whether its current tip lists this host,
  so that the host can refuse to serve a repository whose tip does not (SPEC §8.6, §10.1).

## Cryptographic primitive vectors (RFC-anchored)

Each primitive AVP relies on is pinned to a **published RFC test vector**, so a conformant
implementation reproduces a known-good output and cannot drift on the primitive itself:

- [`hkdf.json`](hkdf.json), HKDF-SHA256 (RFC 5869). Cases `rfc5869-tc1` (RFC 5869 Appendix A.1) and
  `rfc5869-tc3` (Appendix A.3, the zero-length-salt case that exercises the empty-salt → 32 zero bytes
  rule). Each case gives `ikmHex`/`saltHex`/`infoHex`/`length` and the expected `prkHex` (extract step)
  and `okmHex` (expand step).
- [`x25519.json`](x25519.json), X25519 ECDH (RFC 7748), raw 32-byte little-endian keys, **unhashed**
  shared secret. Cases `rfc7748-vec1` and `rfc7748-vec2` are the RFC 7748 §5.2 single-iteration vectors;
  `rfc7748-dh` is the RFC 7748 §6.1 Diffie-Hellman example. Note: RFC 7748 prints the `vec2` input
  u-coordinate with its most-significant bit set; RFC 7748 §5 requires masking that bit before decoding,
  and the committed value is already masked so every conformant decoder (whether or not it masks
  internally) agrees byte-for-byte. The `rfc7748-dh` keypairs (Alice = recipient, Bob = ephemeral) are
  reused by `key-wrap.json`, anchoring the wrap composition's shared secret to a published vector.
- [`ed25519.json`](ed25519.json), Ed25519 sign/verify (RFC 8032), raw 32-byte keys. Cases
  `rfc8032-test2` and `rfc8032-test3` are the RFC 8032 §7.1 vectors. The runner derives the public key
  from the seed, reproduces the (deterministic) signature byte-for-byte, and verifies it.

## Composition vectors (three-way cross-verified)

This exercises the default wrap scheme (SPEC §4.4). They embed fixed keys/IVs so they are
reproducible, and their correctness is established by **three independent sources agreeing byte-for-byte**
(see "Three-way verification" below):

- [`key-wrap.json`](key-wrap.json), the default wrap scheme `X25519-HKDF-SHA256-AESGCM-v1`:
  `sharedSecret = X25519(ephemeralPriv, recipientPub)`;
  `KEK = HKDF-SHA256(ikm=sharedSecret, salt=ephemeralPubRaw, info=UTF8("avp/rdk-wrap/v1"), L=32)`;
  `wrappedCiphertext = AES-256-GCM(KEK, iv, aad=UTF8("avp/rdk-wrap/v1"), plaintext=dataKey)` with the
  16-byte tag appended. The `WrappedKey` on the wire is `{schemeId, ephemeralPublicKey, iv, ciphertext}`;
  the case additionally carries `recipientPrivateKeyB64` (**not** part of the wire format, only so a
  checker can unwrap) plus the intermediate `sharedSecretHex`/`kekHex` for cross-reference. The recipient
  and ephemeral keypairs are the RFC 7748 §6.1 Alice and Bob keypairs, so the shared secret equals the
  published RFC 7748 §6.1 value. The runner recomputes the shared secret and KEK, re-wraps and asserts
  equality with the committed ciphertext, and unwraps and asserts data-key recovery.

## Three-way verification

The composition vectors are public and must not contain mistakes, so each was confirmed by **three
independent sources agreeing byte-for-byte** before being committed:

1. **Published RFC test vectors**, every primitive carries at least one published anchor: HKDF-SHA256
   from RFC 5869 (Test Cases 1 and 3), X25519 from RFC 7748 (§5.2 vectors and the §6.1 DH example), and
   Ed25519 from RFC 8032 (§7.1 TEST 2 and TEST 3). The composition vectors are anchored to RFC 7748 §6.1
   via the wrap keypairs. The Node runner reproduces every published output exactly.
2. **The reference implementation (Java)**, the `lol.trq.alts` crypto primitives independently agree
   with every vector: its HKDF and X25519 reproduce the primitive outputs, it verifies (and reproduces)
   the Ed25519 signatures, and its `X25519HkdfAesGcmKeyWrap` unwraps the
   key-wrap vector and recovers the data key. This was verified with a throwaway harness against the
   library's compiled primitives.
3. **The Node conformance runner**, reproduces every primitive output and round-trips every composition
   vector (decrypt/unwrap and assert recovery) with Node's `crypto`; see the runner's
   [`README.md`](../examples/conformance/README.md). `bun run test` must pass.

An implementation proves conformance by reproducing the deterministic and RFC-anchored vectors exactly,
and by round-tripping the composition vectors (decrypting/unwrapping what a peer encrypted/wrapped,
verifying what a peer signed).

The 0.5 construction vectors (`bip39-owner.json`, `manifest.json`, `commit.json`) are verified by the
Trezor BIP39 reference vectors and the RFC-anchored primitives, by the Node runner, and by the runner's
second, hand-written assembly of every CE layout; the rebuilt Rust and Java references reproduce them
byte-for-byte as their third source.

## Negative vectors

- [`negative.json`](negative.json), a bank of MUST-reject cases. Each case starts from a valid
  construction and applies one mutation. From the seeds of `key-wrap.json` and `ed25519.json`: a flipped
  GCM tag, a flipped body bit, truncation, a wrong recipient or ephemeral wrap key, a wrong message, or a
  wrong public key. From the 0.5 items of `manifest.json`, `commit.json`, and `federation.json`: a
  manifest with a bad or foreign owner signature, a validly signed manifest with a wrong previous hash, a
  commit whose id no longer recomputes (tampered ciphertext or header), an author signature over another
  commit id, a payload decrypted under AAD v2 with a wrong parent set, epoch, author, or repoId, a link
  grant unwrapped with the data key wrap label `avp/rdk-wrap/v1`, an acceptance verified under another
  host key or with a tampered `expiresAt`, and a leave request signed by another key. A conformant
  implementation MUST reject every case; the description lists what each `op` means. Each 0.5 case also
  carries `base`, the fields that restore the valid construction, which MUST be accepted, so the one
  mutation is shown to be the cause. Passing the positive vectors is not enough; an implementation that
  accepts a tampered input is not conformant. Wire base64 strictness is implementation-specific and is
  intentionally not tested here.

## Regenerating the vectors

[`generate.ts`](generate.ts) is the reproducible derivation of these files. It reuses the vector-tested
reference crypto so it cannot drift from the runner.

- `bun vectors/generate.ts --check` re-derives every committed positive vector's value fields from its
  documented seeds and asserts the committed file matches, checks the wordlist hash and the Trezor anchors,
  then asserts `negative.json` and the 0.5 files equal the generator's output. This is the provenance and
  drift gate; CI runs it. It does not rewrite the RFC-anchored and cross-verified positive files (their
  reviewed prose and formatting are preserved).
- `bun vectors/generate.ts --write` regenerates the files the generator owns: `negative.json`,
  `bip39-owner.json`, `manifest.json`, `commit.json`, `federation.json`, `merge.json`, and
  `acceptance.json`. The expected values of `merge.json` and `acceptance.json` are literal data in the
  generator, written from the SPEC; only their signed inputs are derived from seeds.
