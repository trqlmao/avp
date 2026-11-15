# AVP reference client (Java)

A reference client for [AVP 0.5](../../../SPEC.md), HTTP/JSON profile, built on the shared Java sources
in [`../avp`](../avp/). [`Vault.java`](Vault.java) holds one member device's copy of a repository;
[`Client.java`](Client.java) runs a worked flow against live hosts and prints each step. It behaves like
the [Rust reference client](../../rust/client/) and talks to the [Java](../server/) and
[Rust](../../rust/server/) reference hosts and to any other conformant host.

> **Illustrative, not for production.** Keys live in memory, nothing is persisted, and there is no TLS.
> What it does honour is the client side of the protocol: it never trusts a host, and it never sends a
> host the recovery phrase, its entropy or seed, a private key, a data key, or a plaintext.

## Build and run

JDK 21 or later, nothing else: no build tool, no dependencies (`java.net.http.HttpClient` talks to hosts,
JCA does Ed25519, X25519, and AES-GCM through the shared sources). From this directory:

```sh
javac -d build ../avp/*.java ../server/Server.java ../server/Replication.java *.java
java -cp build ClientTest      # the client tests, against real in-process hosts
```

The tests compile the [Java reference host](../server/) in as a library; `Client` itself needs only
`../avp`. Start a host, then run the flow against it:

```sh
cd ../server && javac -d build ../avp/*.java *.java && PORT=19001 java -cp build Server &
AVP_SERVER_URL=http://localhost:19001 java -cp build Client
```

With a second host that replicates with the first, bob's home host is that second host:

```sh
AVP_SERVER_URL=http://a.vault.example:19001 AVP_SERVER_URL_B=http://b.vault.example:19002 java -cp build Client
```

| Variable | Meaning |
|---|---|
| `AVP_SERVER_URL` | The owner's host. Default `http://localhost:8787`. |
| `AVP_SERVER_URL_B` | Optional. Bob's home host; it must list the first host in its `AVP_PEERS` and the first host must list it. |

`Client` exits 0 when every step succeeds and 1 with the error otherwise.

## The worked flow

1. **create**: a new owner identity from 32 bytes of entropy; the 24-word phrase is shown once (SPEC
   3.1). The owner creates the repository on host A: a random genesis nonce, the `repoId` derived from
   it, an epoch-0 data key wrapped to the owner, the owner-signed genesis state, and an empty first
   commit (SPEC 8.2). It prints the repo locator token (SPEC 11.2).
2. **write**: the owner adds an account to the payload (SPEC 5).
3. **invite**: bob calls `prepareJoin` on his home host and builds an invite token with the host's
   acceptance; the owner verifies the acceptance and wraps the data key to exactly the token's X25519
   key (SPEC 8.1, 8.2). Both sides print bob's key fingerprint (SPEC 3.2). Bob joins from his home host
   and checks the owner fingerprint (SPEC 11.2), retrying on one connection while the host waits for
   replication.
4. **write** and **merge**: the owner and bob edit the same account concurrently; the owner pulls,
   merges both heads per field, and pushes the merge commit; bob pulls it and sees both edits (SPEC 5).
5. **leave**: bob sends a signed leave request and stops syncing; the owner processes it as a removal
   with key rotation (SPEC 8.3, 8.4).
6. **link**: a new owner device shows a link request and its confirmation code, the existing device
   shows the same code and the owner confirms, the grant carries the entropy, and the new device
   regenerates the same phrase and reads the vault (SPEC 11.6).

## The library

`Vault` is the model for a client library embedded in a larger program (a game client, for example):

- **No static mutable state.** Every host connection, token cache, and vault is an object.
- **Asynchronous public surface.** Every operation that talks to a host (`HostClient.connect`,
  `Vault.create`, `open`, `join`, `prepareJoin`, `pull`, `write`, `mergeHeads`, `invite`, `remove`,
  `setShareRefreshTokens`, `leave`, `processLeaves`, `HostClient.push`) returns a `CompletableFuture`.
  The blocking work runs on the host connection's executor: a new virtual thread per operation, or the
  `Executor` passed to `HostClient.connect(url, executor)`, whose lifecycle the caller owns. Operations on
  one vault run one at a time, in the order they start.
- **One exception type.** A failed future completes with a `CompletionException` whose cause is a
  `Vault.ClientException`, categorized by `Kind` (`HOST` with the status and the SPEC 10.4 `code`,
  `TRANSPORT`, `BAD_RESPONSE`, `STATE_REJECTED`, `COMMIT_REJECTED`, `INVITE_REFUSED`, `LEFT`, and so on).
  No unchecked exception escapes on host input.
- **Payloads are JSON trees** (`Map<String, Object>`, as the shared `AvpJson` parses them). `write`
  hands the edit a deep copy of the local payload and the clock; `Vault.setField` and
  `Vault.deleteAccount` edit it with a stamp from `AvpPayload.Hlc.tick`.

The plan's constraint for these examples (JDK only, no build tool, the default package, no third-party
dependency) takes precedence over the house conventions for SDK code where they differ: there is no
Gson, so records carry no `@SerializedName`.

## What the client checks itself

The host's acceptance is never trusted on its own (SPEC 7.5). Everything below runs in the client, in
[`Vault.java`](Vault.java):

- **Manifest states** (SPEC 6.1 rules 1 to 5, 6.2): structure and lengths, the owner signature, the
  genesis rules with `repoId` recomputed, the chain link, and the content rules against the previous
  state. A state that fails is discarded with every state after it. Every signature check is the strict
  Ed25519 verification of SPEC 2 (`AvpCrypto.ed25519Verify`).
- **Rollback protection** (SPEC 6.4, 6.5): the client pins its highest verified state. A chain that does
  not contain the pin is rejected, unless it diverges at or below the pin and wins the tie rule
  (bytewise-lower `manifestHash`), in which case the client re-pins to its tip. A chain that forks at
  genesis is never adopted: the genesis state fixes the repository.
- **Pulled commits** (SPEC 7.5): the id recomputes and the author signature verifies; a head by a
  removed member passes only if its id is in the removal's frontier; the author is a member, at the
  commit's epoch, of the cited state when it is on the client's chain, or of a state at or after the
  cited seq otherwise. A commit that fails is never merged and never a parent. Ids are de-duplicated
  only after verification, so a forgery cannot shadow a real head.
- **Merge and unreadable heads** (SPEC 5, 7.5): every readable head is merged and the merge is pushed
  with exactly those heads as parents; the clock observes every stamp first. A head the client cannot
  read (no key for its epoch, or a payload that does not decrypt) is left alone without error. Every
  epoch's data key is retained, so old-epoch heads are merged forward.
- **Refresh-token policy** (SPEC 5.1): unless the latest verified state has `shareRefreshTokens` `true`,
  `refreshToken` and `expiresAt` are removed with their stamps on write and on read.
- **Invites** (SPEC 8.2): the acceptance must verify under its host key, name this repository, the
  token's member key and home host, and not have expired.
- **Leave requests** (SPEC 8.4): only a request that verifies under its `memberKey`, names this
  repository, and comes from a current member who is not the owner is processed.
- **Hosts** (SPEC 3.3, 10.4, 11.7): a host is matched by the key from discovery; bearer tokens are
  cached per host and presented only to the host that minted them. Every host answer is read up to 16
  MiB and decoded item by item, so one malformed item is dropped without hiding the rest. An error
  answer without the JSON error body (a bare `400`, SPEC 10.4) is reported by its status alone.

Every `pull` sends `knownHeads: []`, so the host answers with every current head. That is how the
client learns which of the heads it merged are still heads (a non-empty `knownHeads` cannot tell a known
head that is still current from one that was superseded); the cost is that each pull downloads every
head body.

The owner operations are `invite`, `remove` (rotation, rewrap, frontier, and rotation commit in one
`publishManifest`, SPEC 8.3), `setShareRefreshTokens` (SPEC 8.5), and `processLeaves`.

## Tests

[`ClientTest.java`](ClientTest.java) ports every test of the Rust client's `tests/flow.rs`, under the same
names and with the same assertions, and adds two Java-only cases (a bare `400` error body, and the "at or
after the cited seq" bound of SPEC 7.5). It starts real Java reference hosts in-process on port 0 (two
peered hosts where a test needs replication) and builds every item with real keys. Where a test needs a
misbehaving host (a forged or rewritten manifest, a rolled-back chain, a commit a host would never
serve), it puts a malicious in-process proxy between the client and an honest host: the proxy forwards
every request, records every request body, and rewrites the `pull` answer. One test checks every
recorded body and everything the host stores for the phrase, entropy, seed, private keys, data keys,
and plaintexts. `java -cp build ClientTest <name> ...` runs only the named tests.

## License

MIT (`SPDX-License-Identifier: MIT`).
