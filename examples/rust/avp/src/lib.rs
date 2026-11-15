// SPDX-License-Identifier: MIT

//! Shared AVP 0.5 library for the Rust reference host and client.
//!
//! It implements the byte constructions and rules of `SPEC.md` and reproduces every shared vector
//! in `vectors/` byte for byte:
//!
//! - [`encoding`]: the canonical encoding writer (SPEC 4.1) and the wire base64 forms.
//! - [`crypto`]: SHA-256, HKDF, AES-256-GCM, X25519, Ed25519, and the wrap scheme (SPEC 4.4).
//! - [`owner`]: the BIP39 owner identity (SPEC 3.1).
//! - [`auth`]: the challenge transcript of host-issued authentication (SPEC 3.3).
//! - [`manifest`]: manifest states, the owner signature, `manifestHash`, `repoId` (SPEC 4.2).
//! - [`commit`]: commits, `commitId`, the author signature, AAD v2 (SPEC 4.3).
//! - [`payload`]: payload v2, the merge, stripping, and the hybrid logical clock (SPEC 5).
//! - [`tokens`]: out-of-band tokens, leave requests, fingerprints, `avp://` URIs (SPEC 11).
//! - [`rules`]: the host rules engine [`rules::RepoView`] (SPEC 6, 7, 8.3, 8.4).
//!
//! No function panics on its input: every failure is an [`AvpError`] or a [`RejectCode`].
//!
//! Illustrative reference code, not production.

#![warn(missing_docs)]

pub mod auth;
pub mod commit;
pub mod crypto;
pub mod encoding;
pub mod error;
pub mod manifest;
pub mod owner;
pub mod payload;
pub mod rules;
pub mod tokens;

pub use error::{AvpError, RejectCode};
