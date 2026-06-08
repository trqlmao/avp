# gRPC reference example

A runnable client and server for the **gRPC transport profile**. Where the per-language examples under
`examples/<lang>/` implement the HTTP/JSON profile, this one exercises the canonical
[`proto/avp.proto`](../../proto/avp.proto) directly, so the gRPC profile is not just a schema on disk.

It loads the proto dynamically with [`@grpc/proto-loader`](https://www.npmjs.com/package/@grpc/proto-loader)
(no codegen step, no committed generated stubs) and serves it with
[`@grpc/grpc-js`](https://www.npmjs.com/package/@grpc/grpc-js). `keepCase: false` renders the snake_case
proto fields as the same camelCase the HTTP/JSON profile uses, so the message objects, and the real
envelope crypto reused from [`../typescript/client/src/crypto.ts`](../typescript/client/src/crypto.ts),
are identical to the HTTP examples; only the transport differs.

```sh
npm install        # or: bun install
npm run server     # starts the in-memory gRPC server on :50051 (PORT to override)
npm run client     # in another shell; AVP_GRPC_TARGET to point elsewhere
```

The client prints a transcript of the full lifecycle and exits non-zero on any failure.

## What it shows

- **Auth over gRPC.** The canonical proto carries the challenge/token *messages* but no auth service (a
  token rides in metadata). This example adds an `Auth` service ([`avp-auth.proto`](avp-auth.proto)) that
  offers the challenge -> sign-nonce -> token flow over the same channel, as SPEC section 3 permits. The
  returned token is sent as `authorization: Bearer <token>` gRPC metadata on every `Vault` call.
- **All six `Vault` RPCs.** `CreateRepo`, `Pull`, `Push`, `AddMember`, `FetchMemberKey`, and
  `RemoveMember` (with key rotation).
- **The same semantics as the HTTP profile.** Optimistic concurrency is a normal `PushResponse` with
  `conflict = true` (not a gRPC error); membership, sole-member create, and duplicate-repo rules map to
  `PERMISSION_DENIED` / `ALREADY_EXISTS` / `NOT_FOUND` / `UNAUTHENTICATED` (SPEC sections 6 and 7).
- **Zero-knowledge.** The server stores and echoes the manifest, envelope, wrapped keys, public keys, and
  counters, and decrypts nothing; the second member recovers the payload the first member encrypted.

Illustrative, not production: state is in memory and there is no TLS (a real deployment uses
`grpc.credentials` with TLS and an IdP that mints JWTs verifiable via JWKS).
