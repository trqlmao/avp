// SPDX-License-Identifier: MIT

//! AVP 0.5 reference client, HTTP/JSON profile, over the shared `avp` crate.
//!
//! - [`sync`]: one member device's copy of one repository, [`sync::Vault`]: the verified manifest
//!   chain with rollback protection (SPEC 6), the client checks of every pulled commit (SPEC 7.5),
//!   the per-field merge (SPEC 5), refresh-token stripping (SPEC 5.1), and the owner operations
//!   invite, remove, policy, and leave processing (SPEC 8).
//! - [`link`]: the owner identity (SPEC 3.1) and owner device linking (SPEC 11.6).
//! - [`flow`]: the worked flow `main` runs against live hosts.
//!
//! The client never trusts a host: every answer is untrusted input, every state and commit is
//! checked by the client itself, and no secret (the phrase, its entropy or seed, a private key, a
//! data key, a plaintext) is ever sent to a host. No function here panics on a host answer.
//!
//! Illustrative reference code, not production: keys live in memory and there is no TLS.

#![warn(missing_docs)]

pub mod flow;
pub mod link;
pub mod sync;

use avp::AvpError;
use thiserror::Error;

/// Every failure of the client.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    /// The host could not be reached, or the connection failed.
    #[error("transport: {0}")]
    Transport(String),
    /// The host answered with a non-2xx status and the SPEC 10.4 error body.
    #[error("host answered {status} {code:?}: {message}")]
    Host {
        /// The HTTP status.
        status: u16,
        /// The machine `code`, when the body carries one.
        code: Option<String>,
        /// The human-readable `error` (never parsed, SPEC 10.4).
        message: String,
    },
    /// A host answer that does not decode as the route's response.
    #[error("malformed host answer: {0}")]
    BadResponse(String),
    /// A construction failed in the shared crate.
    #[error(transparent)]
    Avp(#[from] AvpError),
    /// A manifest state failed a SPEC 6 check and was not used.
    #[error("manifest state rejected: {0}")]
    StateRejected(&'static str),
    /// A commit failed a SPEC 7.5 check and was discarded.
    #[error("commit discarded: {0}")]
    CommitRejected(&'static str),
    /// An invite token failed the SPEC 8.2 owner verification.
    #[error("invite refused: {0}")]
    InviteRefused(&'static str),
    /// The host's discovery key is not the key the client expected (SPEC 3.3, 11.7).
    #[error("host key does not match the expected key")]
    HostKeyMismatch,
    /// The operation needs a role this device does not have (owner, member).
    #[error("not permitted: {0}")]
    NotPermitted(&'static str),
    /// No data key is held for the epoch.
    #[error("no data key for epoch {0}")]
    NoKey(i64),
    /// This member left the repository and no longer syncs (SPEC 8.4).
    #[error("this member left the repository and no longer syncs")]
    Left,
    /// The owner did not confirm the device link code (SPEC 11.6).
    #[error("the link confirmation code was not confirmed")]
    LinkNotConfirmed,
    /// The genesis owner key does not match the repo locator's fingerprint (SPEC 11.2).
    #[error("the repository's owner key does not match the locator's fingerprint")]
    OwnerMismatch,
    /// A step of the worked flow did not end as expected.
    #[error("worked flow: {0}")]
    Flow(String),
}

impl ClientError {
    /// The host's machine error code (`forbidden`, `manifest_conflict`, ...), if this is a host
    /// answer that carries one.
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        match self {
            ClientError::Host { code, .. } => code.as_deref(),
            _ => None,
        }
    }
}

/// The result type of the client.
pub type Result<T> = std::result::Result<T, ClientError>;
