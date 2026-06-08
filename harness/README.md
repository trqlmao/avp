# AVP conformance harness

A black-box conformance suite for the HTTP/JSON profile. Point it at a running AVP server and it drives
the full wire contract end to end, asserting the normative MUSTs instead of just printing a transcript.
It is the executable companion to the static [`../vectors/`](../vectors/): the vectors prove your crypto
reproduces known-good bytes; this proves your *server* behaves.

```sh
# against any conformant server
bun conformance.ts --server http://localhost:8787
# or
AVP_SERVER_URL=http://localhost:8787 bun conformance.ts
```

Exit code is `0` only if every check passes; each check prints `PASS`/`FAIL` with its SPEC section.

## What it checks

| SPEC | Checks |
|---|---|
| §3 Auth | challenge returns a ≥32-byte nonce; a valid signed nonce yields a token; a **reused** nonce is rejected (single-use); signing the base64 string instead of the raw nonce bytes is rejected; a vault call without a token is `401`. |
| §6 Vault | `createRepo` returns a 1-member manifest; a manifest whose sole member ≠ caller is `403`; a duplicate `repoId` is `409`; `pull` at the current version is `unchanged` with no envelope; `pull` from an older version returns the envelope; `push` at the expected version is accepted and bumps the version; a **stale** `push` is a `200` with `conflict=true` (never a 4xx); a non-member's `pull` is `403`; `addMember` then `fetchMemberKey` round-trips; the removed member's `pull` becomes `403`. |
| §4 Envelope | the pulled envelope round-trips back to our plaintext; a second member unwraps the data key and decrypts. |
| §10 Invariants | the plaintext never appears in the server's JSON or inside the stored ciphertext/iv (**zero-knowledge**); `removeMember` bumps the epoch and drops the member; the departed member's old key differs from the rotated key and cannot decrypt the new-epoch envelope; a remaining member decrypts the rotated envelope. |

## How it works

The only AVP-specific code is the client-side crypto, imported from the vector-tested reference at
[`../examples/typescript/client/src/crypto.ts`](../examples/typescript/client/src/crypto.ts), so the
harness itself stays a thin wire driver. It runs under [Bun](https://bun.sh) with no install step (only
Node's built-in `crypto` and global `fetch`). `bun run typecheck` runs `tsc` over it.

A pass certifies the surface this harness covers; it supplements, and does not replace, reproducing the
[`../vectors/`](../vectors/) in your implementation language. CI runs it against the Go and TypeScript
reference servers (`.github/workflows/conformance.yml`).
