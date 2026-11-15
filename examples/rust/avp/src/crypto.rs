// SPDX-License-Identifier: MIT

//! Cryptographic primitives (SPEC 2, 4.4): SHA-256, HKDF-SHA256, AES-256-GCM, X25519, Ed25519, and
//! the default wrap scheme `X25519-HKDF-SHA256-AESGCM-v1` with its `info` label.
//!
//! Ported from the 0.4 reference client, whose behavior the RFC-anchored vectors pin. `wrap` and
//! `unwrap` now take the `info` label: the data key wrap passes [`WRAP_INFO`] (the 0.4 label) and
//! device linking passes [`OWNER_LINK_INFO`].

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use ed25519_dalek::{Signature, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::AvpError;
use crate::manifest::WrappedKey;

/// The only wrap scheme id of 0.5 (SPEC 4.4).
pub const SCHEME_ID: &str = "X25519-HKDF-SHA256-AESGCM-v1";

/// The HKDF info and GCM AAD label of the data key wrap (SPEC 4.4).
pub const WRAP_INFO: &[u8] = b"avp/rdk-wrap/v1";

/// The HKDF info and GCM AAD label of a device link grant (SPEC 11.6).
pub const OWNER_LINK_INFO: &[u8] = b"avp/owner-link/v1";

/// SHA-256 (FIPS 180-4).
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// HKDF-SHA256 (RFC 5869): extract with `salt` (an empty salt is 32 zero bytes, RFC 5869 2.2),
/// then expand to `len` bytes with `info`.
///
/// # Errors
///
/// [`AvpError::Crypto`] if `len` exceeds the RFC 5869 limit of 255 * 32 bytes.
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, AvpError> {
    let zeros = [0u8; 32];
    let salt = if salt.is_empty() { &zeros[..] } else { salt };
    let mut okm = vec![0u8; len];
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut okm)
        .map_err(|_| AvpError::Crypto)?;
    Ok(okm)
}

/// HKDF-SHA256 to exactly 32 bytes, the length of every AVP key derivation.
pub(crate) fn hkdf_32(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32], AvpError> {
    let okm = hkdf_sha256(ikm, salt, info, 32)?;
    okm.try_into().map_err(|_| AvpError::Crypto)
}

/// AES-256-GCM encryption with a 12-byte IV; returns the ciphertext with the 16-byte tag appended.
///
/// # Errors
///
/// [`AvpError::Crypto`] if the plaintext or AAD exceed the GCM limits.
pub fn aes_gcm_seal(key: &[u8; 32], iv: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, AvpError> {
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .encrypt(&Nonce::from(*iv), Payload { msg: plaintext, aad })
        .map_err(|_| AvpError::Crypto)
}

/// AES-256-GCM decryption of `ciphertext || tag`.
///
/// # Errors
///
/// [`AvpError::Crypto`] if the tag does not authenticate (wrong key, wrong AAD, tampered or
/// truncated bytes), including a ciphertext shorter than the tag.
pub fn aes_gcm_open(key: &[u8; 32], iv: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, AvpError> {
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(&Nonce::from(*iv), Payload { msg: ciphertext, aad })
        .map_err(|_| AvpError::Crypto)
}

/// X25519 (RFC 7748): the raw, unhashed shared secret of `scalar` and the peer's u-coordinate.
#[must_use]
pub fn x25519(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    StaticSecret::from(*scalar)
        .diffie_hellman(&PublicKey::from(*u))
        .to_bytes()
}

/// The raw X25519 public key of a private key.
#[must_use]
pub fn x25519_public(secret: &StaticSecret) -> [u8; 32] {
    PublicKey::from(secret).to_bytes()
}

/// A fresh X25519 private key from the operating system's CSPRNG.
#[must_use]
pub fn x25519_random() -> StaticSecret {
    StaticSecret::from(random_bytes::<32>())
}

/// `N` bytes from a cryptographically secure RNG.
#[must_use]
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::fill(&mut out[..]);
    out
}

/// Verifies an Ed25519 signature (RFC 8032) under a raw 32-byte public key, with the strict
/// verification that rejects non-canonical and small-order encodings.
///
/// # Errors
///
/// [`AvpError::BadSignature`] if the key is not a valid point or the signature does not verify.
pub fn ed25519_verify(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<(), AvpError> {
    let key = VerifyingKey::from_bytes(public).map_err(|_| AvpError::BadSignature)?;
    key.verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| AvpError::BadSignature)
}

/// Compares two byte strings in constant time for equal lengths.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// The key-encryption key of the wrap scheme (SPEC 4.4 step 3).
fn wrap_kek(shared: &[u8; 32], ephemeral_public: &[u8; 32], info: &[u8]) -> Result<[u8; 32], AvpError> {
    hkdf_32(shared, ephemeral_public, info)
}

/// Wraps `secret` to a recipient's X25519 key with the default scheme (SPEC 4.4), using a fresh
/// ephemeral key and IV.
///
/// # Errors
///
/// [`AvpError::Crypto`] if the AEAD fails (not reachable for a secret of sane size).
pub fn wrap(recipient_x25519: &[u8; 32], secret: &[u8], info: &[u8]) -> Result<WrappedKey, AvpError> {
    wrap_with(recipient_x25519, secret, info, &x25519_random(), &random_bytes::<12>())
}

/// [`wrap`] with a caller-chosen ephemeral key and IV, for reproducing the vectors.
///
/// Real wraps MUST use a fresh random ephemeral key and IV each time; use [`wrap`].
///
/// # Errors
///
/// [`AvpError::Crypto`] if the AEAD fails.
pub fn wrap_with(
    recipient_x25519: &[u8; 32],
    secret: &[u8],
    info: &[u8],
    ephemeral: &StaticSecret,
    iv: &[u8; 12],
) -> Result<WrappedKey, AvpError> {
    let ephemeral_public = x25519_public(ephemeral);
    let shared = ephemeral.diffie_hellman(&PublicKey::from(*recipient_x25519)).to_bytes();
    let kek = wrap_kek(&shared, &ephemeral_public, info)?;
    let ciphertext = aes_gcm_seal(&kek, iv, secret, info)?;
    Ok(WrappedKey {
        scheme_id: SCHEME_ID.to_string(),
        ephemeral_public_key: ephemeral_public,
        iv: *iv,
        ciphertext,
    })
}

/// Unwraps a [`WrappedKey`] with the recipient's X25519 private key under the `info` label
/// (SPEC 4.4). A wrap made under one label fails under another.
///
/// # Errors
///
/// [`AvpError::BadEncoding`] for an unknown scheme id; [`AvpError::Crypto`] if the wrap does not
/// authenticate (wrong key, wrong label, or tampered bytes).
pub fn unwrap(recipient: &StaticSecret, wk: &WrappedKey, info: &[u8]) -> Result<Vec<u8>, AvpError> {
    if wk.scheme_id != SCHEME_ID {
        return Err(AvpError::BadEncoding(format!(
            "unsupported wrap scheme {:?}",
            wk.scheme_id
        )));
    }
    let shared = recipient
        .diffie_hellman(&PublicKey::from(wk.ephemeral_public_key))
        .to_bytes();
    let kek = wrap_kek(&shared, &wk.ephemeral_public_key, info)?;
    aes_gcm_open(&kek, &wk.iv, &wk.ciphertext, info)
}
