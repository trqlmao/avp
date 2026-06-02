# Reference servers

Runnable reference implementations of the AVP server, one directory per language. Each implements the
full [HTTP/JSON profile](../../SPEC.md) against in-memory state, so you can point a client at something
real. They are illustrative, not production code.

| Language | Path | Notes |
|---|---|---|
| TypeScript | [`typescript/`](typescript/) | Node built-ins only; `npm start`, `npm test`. |

More languages are welcome — see [`../../CONTRIBUTING.md`](../../CONTRIBUTING.md). A new implementation
should keep the same routes and message shapes and stay zero-knowledge (store only ciphertext, wrapped
keys, public keys, and counters).
