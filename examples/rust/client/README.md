# AVP reference client (Rust)

A reference client for [AVP 0.5](../../../SPEC.md), HTTP/JSON profile, built on the shared
[`avp`](../avp/) crate. The library (`src/lib.rs`) holds one member device's copy of a repository;
the binary (`src/main.rs`) runs a worked flow against live hosts and prints each step. It talks to
the [Rust reference host](../server/) and to any other conformant host.

> **Illustrative, not for production.** Keys live in memory and there is no TLS. What it does
> honour is the client side of the protocol: it never trusts a host, and it never sends a host the
> recovery phrase, its entropy or seed, a private key, a data key, or a plaintext.

## Build and run

Requires a Rust toolchain with `cargo`, edition 2024, Rust 1.85 or later.

```sh
cargo build
cargo test        # tests/flow.rs, against real in-process hosts
```

Start a host, then run the flow against it:

```sh
cd ../server && PORT=19001 cargo run &
AVP_SERVER_URL=http://localhost:19001 cargo run
```

With a second host that replicates with the first, bob's home host is that second host:

```sh
AVP_SERVER_URL=http://a.vault.example:19001 AVP_SERVER_URL_B=http://b.vault.example:19002 cargo run
```

| Variable | Meaning |
|---|---|
| `AVP_SERVER_URL` | The owner's host. Default `http://localhost:8787`. |
| `AVP_SERVER_URL_B` | Optional. Bob's home host; it must list the first host in its `AVP_PEERS` and the first host must list it. |

The binary exits 0 when every step succeeds and 1 with the error otherwise.

## The worked flow

1. **create**: a new owner identity from 32 bytes of entropy; the 24-word phrase is shown once
   (SPEC 3.1). The owner creates the repository on host A: a random genesis nonce, the `repoId`
   derived from it, an epoch-0 data key wrapped to the owner, the owner-signed genesis state, and
   an empty first commit (SPEC 8.2). It prints the repo locator token (SPEC 11.2).
2. **write**: the owner adds an account to the payload (SPEC 5).
3. **invite**: bob calls `prepareJoin` on his home host and builds an invite token with the host's
   acceptance; the owner verifies the acceptance and wraps the data key to exactly the token's
   X25519 key (SPEC 8.1, 8.2). Both sides print bob's key fingerprint (SPEC 3.2). Bob joins from
   his home host and checks the owner fingerprint (SPEC 11.2).
4. **write** and **merge**: the owner and bob edit the same account concurrently; the owner pulls,
   merges both heads per field, and pushes the merge commit; bob pulls it and sees both edits
   (SPEC 5).
5. **leave**: bob sends a signed leave request and stops syncing; the owner processes it as a
   removal with key rotation (SPEC 8.3, 8.4).
6. **link**: a new owner device shows a link request and its confirmation code, the existing device
   shows the same code and the owner confirms, the grant carries the entropy, and the new device
   regenerates the same phrase and reads the vault (SPEC 11.6).

## What the client checks itself

The host's acceptance is never trusted on its own (SPEC 7.5). Everything below runs in the client,
in [`src/sync.rs`](src/sync.rs):

- **Manifest states** (SPEC 6.1 rules 1 to 5, 6.2): structure and lengths, the owner signature, the
  genesis rules with `repoId` recomputed, the chain link, and the content rules against the
  previous state. A state that fails is discarded with every state after it.
- **Rollback protection** (SPEC 6.4, 6.5): the client pins its highest verified state. A chain that
  does not contain the pin is rejected, unless it diverges at or below the pin and wins the tie rule
  (bytewise-lower `manifestHash`), in which case the client re-pins to its tip.
- **Pulled commits** (SPEC 7.5): the id recomputes and the author signature verifies; a head by a
  removed member passes only if its id is in the removal's frontier; the author is a member, at the
  commit's epoch, of the cited state when it is on the client's chain, or of a state at or after
  the cited seq otherwise. A commit that fails is never merged and never a parent.
- **Merge and unreadable heads** (SPEC 5, 7.5): every readable head is merged and the merge is
  pushed with exactly those heads as parents; the clock observes every stamp first. A head the
  client cannot read (no key for its epoch, or a payload that does not decrypt) is left alone
  without error. Every epoch's data key is retained, so old-epoch heads are merged forward.
- **Refresh-token policy** (SPEC 5.1): unless the latest verified state has `shareRefreshTokens`
  `true`, `refreshToken` and `expiresAt` are removed with their stamps on write and on read.
- **Invites** (SPEC 8.2): the acceptance must verify under its host key, name this repository, the
  token's member key and home host, and not have expired.
- **Hosts** (SPEC 3.3, 11.7): a host is matched by the key from discovery; bearer tokens are cached
  per host and presented only to the host that minted them.

The owner operations are `invite`, `remove` (rotation, rewrap, frontier, and rotation commit in one
`publishManifest`, SPEC 8.3), `set_share_refresh_tokens` (SPEC 8.5), and `process_leaves`.

## Tests

`tests/flow.rs` starts real reference hosts in-process on port 0 (two peered hosts where a test
needs replication) and builds every item with real keys. Where a test needs a misbehaving host
(a forged or rewritten manifest, a rolled-back chain, a commit a host would never serve), it puts
a malicious in-process proxy between the client and an honest host: the proxy forwards every
request, records every request body, and rewrites the `pull` answer. One test checks every
recorded body and everything the host stores for the phrase, entropy, seed, private keys, data
keys, and plaintexts.

## Dependencies

Pinned exactly in [`Cargo.toml`](Cargo.toml):

| Crate | Why |
|---|---|
| `avp` (path `../avp`) | wire types, crypto, owner identity, payload merge, tokens |
| `ureq` | a small blocking HTTP/1.1 client; default features off (no TLS, no compression) |
| `serde`, `serde_json` | request and response bodies |
| `ed25519-dalek`, `x25519-dalek` | member key pairs |
| `thiserror` | the client error type |

Dev dependencies: `avp-reference-server` (path `../server`, the in-process hosts) and `tiny_http`
(the test proxy).

## License

MIT (`SPDX-License-Identifier: MIT`).
