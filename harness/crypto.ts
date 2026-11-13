/**
 * The client-side AVP 0.5 constructions the black-box harness drives a host with.
 *
 * Nothing is reimplemented here: every export comes from the vector-tested conformance runner in
 * `examples/conformance/src`, whose CE writer, manifest and commit constructions, AAD v2, wrap scheme,
 * BIP39 owner keys, strict Ed25519 verification, and payload merge reproduce the committed vectors
 * byte for byte (`cd examples/conformance && bun run test`).
 *
 * Illustrative reference code, not production. SPDX-License-Identifier: MIT
 */

export * from "../examples/conformance/src/crypto.ts";
export * from "../examples/conformance/src/constructions.ts";
export * from "../examples/conformance/src/bip39.ts";
export * from "../examples/conformance/src/merge.ts";
export {
  acceptanceFromWire,
  acceptanceToWire,
  commitFromWire,
  commitToWire,
  leaveFromWire,
  leaveToWire,
  signedManifestFromWire,
  signedManifestToWire,
  type WireCommit,
  type WireLeaveRequest,
  type WireSignedManifest,
} from "../examples/conformance/src/vectors.ts";
