# Contributing to AVP

Thanks for your interest. AVP is meant to be built by many clients, so outside contributions are the
point, not the exception. This guide covers how to help and the few rules that keep the standard usable
for everyone.

## Ways to contribute

- **Implement the protocol** in a client, server, or library, and open issues for anything in the spec
  that was ambiguous or hard to satisfy. Real implementations are the best spec review.
- **Add or improve conformance vectors** in [`vectors/`](vectors/), especially for key wrap and unwrap,
  rotation, and the challenge and token flow.
- **Improve the spec text** for clarity, or fix errors and inconsistencies.
- **Propose extensions** for the open items in [`SPEC.md`](SPEC.md) §12 (algorithm negotiation, cross
  identity-provider trust in federation).
- **Review the security design** (the envelope, federation addressing, anti-MITM key binding) and report
  weaknesses. For anything that looks exploitable, follow [`SECURITY.md`](SECURITY.md) instead of opening
  a public issue.

## How to propose a change

1. Open an issue describing the problem or idea first, so design discussion happens before code.
2. Send a pull request. Keep it focused on one logical change.
3. Make sure CI passes (see below).

For changes to the wire contract:

- Use RFC 2119 keywords (MUST, SHOULD, MAY) deliberately.
- Keep existing Protocol Buffers field numbers and names stable. Add new fields, do not renumber.
- A change that breaks interoperability is a new protocol version. Call it out clearly and update the
  version in `SPEC.md` and `README.md`.
- Keep `proto/avp.proto`, `schema/avp.schema.json`, and `SPEC.md` in sync. They describe the same
  messages.

## Vendor neutrality (enforced by CI)

AVP names no specific client, product, sponsor, or server deployment. This is what makes it a standard
rather than one vendor's API. A CI job (`.github/workflows/no-leak.yml`) scans every change and fails on
a denylist of internal names. Use generic placeholders in examples and tests, for example
`vault.example` for a host, and a neutral client and user name for provenance values. The protocol's
provenance fields carry such names at runtime, set by each implementer, never baked into the spec.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/): `type(scope): summary`, for example
`docs(spec): clarify AAD layout` or `feat(proto): add field for X`. Breaking changes use `!` and a
`BREAKING CHANGE:` footer.

## Licensing of contributions

By contributing you agree that your contribution is licensed under the same terms as this repository:
CC-BY-4.0 for prose and MIT for machine-readable artifacts (see [`LICENSE`](LICENSE)). There is no CLA.

## Conduct

Be respectful and assume good faith. Keep discussion technical and on topic. Maintainers may remove
comments or contributions that are abusive or off topic.
