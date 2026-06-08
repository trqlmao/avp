# Security policy

AVP is a protocol specification, so "security issues" here mean weaknesses in the design or in the
machine-readable artifacts that could lead implementers to build something insecure. Examples:

- A flaw in the cryptographic envelope, key wrap, rotation, or the zero-knowledge guarantee.
- A federation or anti-MITM weakness (for example a way to make a member wrap a data key to an attacker).
- An error in `proto/avp.proto`, `schema/avp.schema.json`, or `vectors/` that would cause a conformant
  implementation to be insecure or to interoperate incorrectly.

Vulnerabilities in a specific client, server, or library that implements AVP belong to that project, not
here. Please report those to the relevant project.

[`THREATMODEL.md`](THREATMODEL.md) describes what AVP defends against, what it does not, and the known
residual risks. A report that sharpens or breaks part of that model is exactly what is most useful here.

## Reporting

Please report security issues **privately**, not in a public issue or pull request.

Use GitHub's private vulnerability reporting on this repository: open the **Security** tab and choose
**Report a vulnerability**. That opens a private advisory visible only to you and the maintainers.

Include, as far as you can:

- which part of the spec or artifacts is affected (section, file, message, or field),
- a clear description of the weakness and why it matters,
- a concrete attack scenario or proof of concept, and
- any suggested fix.

## What to expect

This is a community project, so responses are best effort. We aim to acknowledge a report within a few
days, agree on impact and a fix, and coordinate disclosure with you. Please give us reasonable time to
publish a corrected version before disclosing publicly. Credit is given to reporters who want it.

## Scope notes

- Reports about the protocol intentionally do not require any account or live service. The reference
  design authenticates with a keypair and stores only ciphertext.
- Cross identity-provider trust in full federation is a known open item (see `SPEC.md` §12). Reports that
  sharpen that threat model are welcome.
