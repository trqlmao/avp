## Summary

<!-- What does this change, and why? -->

## Checklist

- [ ] No vendor-internal names. The `no-leak` CI gate must pass (see `CONTRIBUTING.md`); AVP is vendor-neutral.
- [ ] Ran the affected example(s): `bun install && bun run typecheck` (and `bun run test` where a test script exists) for TypeScript/conformance; `cargo build && cargo test` for Rust; the documented build for Java/Python.
- [ ] `SPEC.md`, `proto/avp.proto`, and `schema/avp.schema.json` stay in sync if the wire format changed.
- [ ] Conformance `vectors/` updated if cryptographic behavior changed.
- [ ] `CHANGELOG.md` updated for a spec or artifact change.
