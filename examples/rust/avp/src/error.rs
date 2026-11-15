// SPDX-License-Identifier: MIT

//! The crate's one error type and the host reject codes of SPEC 10.4.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Every failure of this crate.
///
/// No function in the crate panics on its input; each failure is one of these variants.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AvpError {
    /// Input that does not decode: wrong length, bad base64 or JSON, a value out of range, a
    /// duplicate list key, or a mnemonic with the wrong word count or an unknown word.
    #[error("bad encoding: {0}")]
    BadEncoding(String),
    /// A signature that does not verify, or a recomputed id that does not match.
    #[error("bad signature")]
    BadSignature,
    /// A BIP39 mnemonic whose checksum does not match (SPEC 3.1).
    #[error("bad checksum")]
    BadChecksum,
    /// An AEAD or key agreement failure: wrong key, wrong label or AAD, or tampered bytes.
    #[error("cryptographic operation failed")]
    Crypto,
    /// A host rules verdict (SPEC 10.4).
    #[error("rejected: {0}")]
    Reject(RejectCode),
}

impl From<RejectCode> for AvpError {
    fn from(code: RejectCode) -> Self {
        AvpError::Reject(code)
    }
}

/// A host's reject code on the repository paths (SPEC 10.4), serialized as its wire string.
///
/// `duplicate_repo` and `not_found` are host-level answers given before the rules engine runs, so
/// they are not engine verdicts and have no variant here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RejectCode {
    /// `400 bad_request`: malformed, a bad signature, an id that does not recompute.
    #[serde(rename = "bad_request")]
    BadRequest,
    /// `403 forbidden`: not a member, after the removal cutoff, an epoch mismatch, a held commit.
    #[serde(rename = "forbidden")]
    Forbidden,
    /// `403 not_hosted`: this host is not in the manifest's `hosts`.
    #[serde(rename = "not_hosted")]
    NotHosted,
    /// `409 too_many_heads`: the push would leave more heads than the bound.
    #[serde(rename = "too_many_heads")]
    TooManyHeads,
    /// `409 manifest_conflict`: not tip + 1, a previous hash mismatch, or a losing state.
    #[serde(rename = "manifest_conflict")]
    ManifestConflict,
    /// `422 missing_parents`: a parent, a cited manifest state, or a frontier commit is unknown.
    #[serde(rename = "missing_parents")]
    MissingParents,
}

impl RejectCode {
    /// The wire string of the code, as in the HTTP error body's `code`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RejectCode::BadRequest => "bad_request",
            RejectCode::Forbidden => "forbidden",
            RejectCode::NotHosted => "not_hosted",
            RejectCode::TooManyHeads => "too_many_heads",
            RejectCode::ManifestConflict => "manifest_conflict",
            RejectCode::MissingParents => "missing_parents",
        }
    }
}

impl fmt::Display for RejectCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
