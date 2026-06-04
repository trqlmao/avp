# CLAUDE.md

Guidance for AI coding agents working in this repository.

## What this repo is

This is the **specification** for AVP (the Alt Vault Protocol), an open,
vendor-neutral, zero-knowledge, federated protocol for sharing Minecraft alt
accounts across clients. It is the wire contract, not a product. There is no
application to run here. The deliverables are documents, a proto schema, a JSON
schema, conformance vectors, and small illustrative examples.

The live site (GitHub Pages, custom domain `avp.trq.lol`) is rendered from this
repo with Jekyll. The README is the home page.

## Source of truth and how the pieces relate

- `SPEC.md` is the **normative contract**. Anything an implementation MUST do is
  stated there in RFC 2119 language. Do not soften MUST/SHALL/SHOULD/MAY.
- `proto/avp.proto` is the **canonical** message definition. Field numbers and
  names are stable; add fields, never renumber or rename them.
- `schema/avp.schema.json` mirrors the proto for the HTTP/JSON profile: the same
  field names in `camelCase`. Keep it in sync with the proto and SPEC.
- `vectors/` are conformance test vectors, RFC-anchored and three-way verified
  (published RFCs + a reference implementation + the Node runner all agree
  byte-for-byte). **Never edit a vector value without re-verifying all three.**
  See `vectors/README.md`.
- `examples/` are illustrative reference clients and servers (TypeScript, Rust,
  Python, Java) plus a Node conformance runner. They are not production code.

When you change one of `SPEC.md` / `proto/avp.proto` / `schema/avp.schema.json`,
check whether the other two need the matching change. They describe one protocol.

## Hard rules

1. **Vendor neutrality is enforced.** AVP names no specific client, product,
   sponsor, server deployment, or anti-cheat. This is what makes it a standard
   rather than one vendor's API. `.github/workflows/no-leak.yml` scans every
   change against a denylist (sourced from a private secret) and fails the build
   on an internal name. Use generic placeholders: `vault.example` for a host, a
   neutral client/user name for provenance values. Provenance fields
   (`sourceClient`, `sourceUser`) carry such names only at runtime, set by each
   implementer, never baked into spec text, examples, or tests.
2. **Zero-knowledge is the whole point.** Never let the server see a plaintext
   alt, a passphrase, an identity seed, or the data key. The server stores only
   ciphertext, wrapped keys, public keys, counters, and opaque signatures.
3. **Fixed byte constructions are exact.** The AAD layout (SPEC §4) and the
   key-binding message (SPEC §9) are byte-for-byte. Reproduce the deterministic
   vectors before trusting any encoder you write.
4. **No em dashes** in prose (house style). Use commas, colons, semicolons,
   periods, or parentheses.

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/):
`type(scope): summary`, for example `docs(spec): clarify AAD layout` or
`feat(proto): add field for X`. Breaking changes to the wire contract use `!`
and a `BREAKING CHANGE:` footer, and bump the version in `SPEC.md` and
`README.md`. **Never add an AI-attribution trailer** (no `Co-Authored-By` for an
AI). The committer is the responsible author.

## Build and test

- Conformance runner (checks the vectors): `cd examples/conformance && bun install && bun run test`.
- Per-language example CIs live in `.github/workflows/examples-{node,rust,java,python}.yml`;
  each builds and tests its example client/server.
- The Pages site builds on push (no local step required). If you want to preview
  it locally and have Ruby, `bundle exec jekyll serve` renders `_layouts/default.html`
  with `assets/css/style.css`.

## Site (GitHub Pages)

`_config.yml` uses a hand-written layout (`_layouts/default.html` +
`assets/css/style.css`), not a gem theme. The look is minimal, light, text-first,
monospace headings, no accent color (neutrality). `CNAME` pins `avp.trq.lol`; do
not change it. Keep the layout dependency-free (no JS frameworks).
