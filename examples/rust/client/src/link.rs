// SPDX-License-Identifier: MIT

//! The owner identity (SPEC 3.1) and owner device linking (SPEC 11.6).
//!
//! The phrase is the identity: [`OwnerIdentity`] holds the 32-byte entropy and the owner keys
//! derived from it. Linking moves that entropy to a new device out of band, never through a host:
//! the new device shows a [`LinkSession`] request and its confirmation code, an existing owner
//! device [`approve`]s it only after the owner confirms the code, and the grant opens only under the
//! new device's ephemeral key with the `avp/owner-link/v1` label.

use avp::crypto::{random_bytes, x25519_public, x25519_random};
use avp::owner::{OwnerKeys, entropy_to_mnemonic, mnemonic_to_entropy};
use avp::tokens::{LinkGrant, LinkRequest};
use x25519_dalek::StaticSecret;

use crate::{ClientError, Result};

/// An owner identity: the BIP39 entropy and the owner keys derived from it (SPEC 3.1).
///
/// It is a secret. The client shows the phrase once at creation and never sends the phrase, the
/// entropy, the seed, or a private key to a host.
#[derive(Clone)]
pub struct OwnerIdentity {
    /// The 32 bytes of mnemonic entropy; a device link grant carries exactly these (SPEC 11.6).
    pub entropy: [u8; 32],
    /// The owner Ed25519 and X25519 keys.
    pub keys: OwnerKeys,
}

impl OwnerIdentity {
    /// A new identity from 32 bytes of CSPRNG entropy.
    ///
    /// # Errors
    ///
    /// [`ClientError::Avp`] if the key derivation fails (not reachable for 32-byte inputs).
    pub fn generate() -> Result<OwnerIdentity> {
        OwnerIdentity::from_entropy(random_bytes::<32>())
    }

    /// The identity of a 24-word phrase.
    ///
    /// # Errors
    ///
    /// [`ClientError::Avp`] if the phrase is not 24 words of the English list or fails the checksum
    /// (SPEC 3.1).
    pub fn from_mnemonic(phrase: &str) -> Result<OwnerIdentity> {
        OwnerIdentity::from_entropy(mnemonic_to_entropy(phrase)?)
    }

    /// The identity of 32 bytes of entropy: the mnemonic, its seed, then the owner keys.
    ///
    /// # Errors
    ///
    /// [`ClientError::Avp`] if the key derivation fails (not reachable for 32-byte inputs).
    pub fn from_entropy(entropy: [u8; 32]) -> Result<OwnerIdentity> {
        Ok(OwnerIdentity {
            keys: OwnerKeys::from_entropy(&entropy)?,
            entropy,
        })
    }

    /// The 24-word phrase. A client shows it once, at creation (SPEC 3.1).
    #[must_use]
    pub fn mnemonic(&self) -> String {
        entropy_to_mnemonic(&self.entropy)
    }
}

/// The new device's side of a link (SPEC 11.6 steps 1 and 4).
pub struct LinkSession {
    ephemeral: StaticSecret,
    request: LinkRequest,
}

impl LinkSession {
    /// A fresh ephemeral X25519 key pair and its link request.
    #[must_use]
    pub fn new() -> LinkSession {
        let ephemeral = x25519_random();
        let request = LinkRequest::new(x25519_public(&ephemeral));
        LinkSession { ephemeral, request }
    }

    /// The link request to show (as a token, out of band).
    #[must_use]
    pub fn request(&self) -> &LinkRequest {
        &self.request
    }

    /// The 6-digit confirmation code this device shows.
    ///
    /// # Errors
    ///
    /// [`ClientError::Avp`] if the code cannot be computed (not reachable for a 32-byte key).
    pub fn confirmation_code(&self) -> Result<String> {
        Ok(self.request.confirmation_code()?)
    }

    /// Opens a grant with the ephemeral key, which is then discarded, and derives the identity: the
    /// same phrase and owner keys as the granting device.
    ///
    /// # Errors
    ///
    /// [`ClientError::Avp`] if the grant does not unwrap under `avp/owner-link/v1` with this
    /// session's key (a grant for another device, a tampered grant, another label).
    pub fn finish(self, grant: &LinkGrant) -> Result<OwnerIdentity> {
        let entropy = grant.open(&self.ephemeral)?;
        OwnerIdentity::from_entropy(entropy)
    }
}

impl Default for LinkSession {
    fn default() -> Self {
        LinkSession::new()
    }
}

/// The existing device's side (SPEC 11.6 steps 2 and 3): computes the request's confirmation code,
/// shows it to the owner through `confirm`, and only if the owner confirms that it matches the code
/// on the new device, wraps the entropy to the request's ephemeral key.
///
/// # Errors
///
/// [`ClientError::LinkNotConfirmed`] if `confirm` returns `false`; [`ClientError::Avp`] if the code
/// or the wrap cannot be computed.
pub fn approve(entropy: &[u8; 32], request: &LinkRequest, confirm: impl FnOnce(&str) -> bool) -> Result<LinkGrant> {
    let code = request.confirmation_code()?;
    if !confirm(&code) {
        return Err(ClientError::LinkNotConfirmed);
    }
    Ok(LinkGrant::seal(entropy, &request.ephemeral_public_key)?)
}
