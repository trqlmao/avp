// SPDX-License-Identifier: MIT

//! The challenge transcript of host-issued authentication (SPEC 3.3).
//!
//! A client never signs the host-chosen nonce as given. It signs
//! `CE(tag "avp/challenge/v1", bytes(hostKey), bytes(ed25519PublicKey), bytes(nonce))`, whose tag keeps
//! the message apart from every other signed construction (SPEC 4.1) and whose `hostKey` binds the
//! signature to the host being authenticated to.

use ed25519_dalek::{Signer, SigningKey};

use crate::crypto::ed25519_verify;
use crate::encoding::Ce;
use crate::error::AvpError;

/// The CE label of the challenge transcript (SPEC 3.3, 4.1).
pub const CHALLENGE_TAG: &str = "avp/challenge/v1";

/// The message a client signs to redeem a challenge (SPEC 3.3):
/// `CE(tag "avp/challenge/v1", bytes(hostKey), bytes(ed25519PublicKey), bytes(nonce))`.
///
/// `host_key` is the key of the host being authenticated to, `key` the key requesting the token, and
/// `nonce` the raw (base64-decoded) nonce bytes.
///
/// # Errors
///
/// [`AvpError::BadEncoding`] if the nonce is longer than `u32::MAX` bytes.
pub fn challenge_message(host_key: &[u8; 32], key: &[u8; 32], nonce: &[u8]) -> Result<Vec<u8>, AvpError> {
    let mut w = Ce::new(CHALLENGE_TAG);
    w.bytes(host_key).bytes(key).bytes(nonce);
    w.finish()
}

/// Signs the challenge transcript for `signer`'s key and the host `host_key`.
///
/// # Errors
///
/// As [`challenge_message`].
pub fn sign_challenge(host_key: &[u8; 32], signer: &SigningKey, nonce: &[u8]) -> Result<[u8; 64], AvpError> {
    let key = signer.verifying_key().to_bytes();
    Ok(signer.sign(&challenge_message(host_key, &key, nonce)?).to_bytes())
}

/// Verifies a challenge signature under `key` over the transcript built with `host_key`, the
/// verifying host's own key (SPEC 3.3), with strict Ed25519 (SPEC 2).
///
/// # Errors
///
/// [`AvpError::BadSignature`] if it does not verify, including a signature over the raw nonce or a
/// transcript built with another host key; [`AvpError::BadEncoding`] as [`challenge_message`].
pub fn verify_challenge(
    host_key: &[u8; 32],
    key: &[u8; 32],
    nonce: &[u8],
    signature: &[u8; 64],
) -> Result<(), AvpError> {
    ed25519_verify(key, &challenge_message(host_key, key, nonce)?, signature)
}
