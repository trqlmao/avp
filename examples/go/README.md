# AVP reference example, Go

A runnable reference [client](client/) and [server](server/) for the
[Alt Vault Protocol](../../SPEC.md), HTTP/JSON profile, in Go. It is a sibling of
the [TypeScript](../typescript/), [Rust](../rust/), [Python](../python/), and
[Java](../java/) examples and is wire-compatible with all of them.

**This example implements the real cryptography end to end.** The other reference
clients deliberately carry the alt payload and wrapped keys as opaque placeholders
(only the Ed25519 auth is real); the real envelope and key-wrap constructions live
only in the [conformance vectors](../../vectors/). This Go example closes that gap:
it is a runnable, dependency-free, vector-verified reference for the parts of SPEC
§4 and §9 that are easiest to get subtly wrong — the AAD byte layout, the
HKDF-salted X25519 key wrap, the unhashed shared secret, and AES-256-GCM tag
handling. The server stays **zero-knowledge** the whole time: it stores ciphertext
and wrapped keys, and decrypts nothing.

## Layout

```
examples/go/
  avp/       shared, reusable core: the real crypto (crypto.go) + wire types (wire.go)
  client/    a runnable client that drives the full lifecycle with real crypto
  server/    an in-memory, zero-knowledge server
```

The crypto and wire types are a single, tested package (`avp/`) that both the client
and server import, so there is exactly one copy to read and reuse. Copy the whole
`examples/go/` module, not a lone file.

## Run it

In one terminal, start the server (listens on `http://localhost:8787`):

```sh
cd server && go run .
```

In another, run the client; it drives create -> pull -> push -> add-member ->
fetch -> (second member) pull + unwrap + decrypt and prints a transcript:

```sh
cd client && go run .
```

Point the client at another server with `AVP_SERVER_URL`, and change the server's
port with `PORT`:

```sh
PORT=9000 go run .                                  # server
AVP_SERVER_URL=http://localhost:9000 go run .       # client
```

## Test it

```sh
go test ./...
```

`avp/` is checked byte-for-byte against the repository's
[conformance vectors](../../vectors/) (HKDF-SHA256, X25519, Ed25519, the AAD and
key-binding constructions, the payload AEAD, and the key wrap). `server/` boots on
an ephemeral port and runs the full lifecycle with real keypairs, asserting that the
second member decrypts, through the zero-knowledge server, exactly what the first
member encrypted.

## Dependencies

None. The example is pure Go standard library, including the crypto: `crypto/ecdh`
(X25519), `crypto/ed25519`, `crypto/aes` + `crypto/cipher` (AES-256-GCM), and
`crypto/hmac` + `crypto/sha256` (a short hand-rolled HKDF-SHA256). On Go 1.24+ the
standard `crypto/hkdf` is a drop-in replacement for the hand-rolled one;
`golang.org/x/crypto/hkdf` works on older toolchains. Requires Go 1.22+.

## License

MIT (`SPDX-License-Identifier: MIT`).
