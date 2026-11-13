// SPDX-License-Identifier: MIT

//! Out-of-band tokens and addressing (SPEC 11): the invite token and host acceptance, the repo
//! locator and `avp://` URI, device link request and grant, the leave request, and fingerprints.

use std::fmt;

use ed25519_dalek::{Signer, SigningKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use x25519_dalek::StaticSecret;

use crate::crypto::{OWNER_LINK_INFO, ct_eq, ed25519_verify, random_bytes, sha256, unwrap, wrap_with, x25519_random};
use crate::encoding::{Ce, V2, b64_array, b64url_decode, b64url_encode};
use crate::error::AvpError;
use crate::manifest::WrappedKey;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A host's signed agreement to carry a repository for one joining member (SPEC 8.2, 11.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Acceptance {
    /// The repository.
    #[serde(rename = "repoId")]
    pub repo_id: String,
    /// The joining member's Ed25519 key.
    #[serde(rename = "memberKey", with = "b64_array")]
    pub member_key: [u8; 32],
    /// The accepting host's key.
    #[serde(rename = "hostKey", with = "b64_array")]
    pub host_key: [u8; 32],
    /// Epoch milliseconds after which the acceptance is void.
    #[serde(rename = "expiresAt")]
    pub expires_at: i64,
    /// The host's signature over [`Acceptance::message`].
    #[serde(rename = "signature", with = "b64_array")]
    pub signature: [u8; 64],
}

impl Acceptance {
    /// The signed message (SPEC 11.3): `CE(tag "avp/accept/v1", str(repoId), bytes(memberKey),
    /// bytes(hostKey), i64(expiresAt))`.
    ///
    /// # Errors
    ///
    /// Not reachable for these field sizes; the CE writer is fallible in general.
    pub fn message(&self) -> Result<Vec<u8>, AvpError> {
        let mut w = Ce::new("avp/accept/v1");
        w.str(&self.repo_id)
            .bytes(&self.member_key)
            .bytes(&self.host_key)
            .i64(self.expires_at);
        w.finish()
    }

    /// Signs the acceptance with the host key; `host_key` is set to that key's public key.
    ///
    /// # Errors
    ///
    /// As [`Acceptance::message`].
    pub fn sign(mut self, host: &SigningKey) -> Result<Acceptance, AvpError> {
        self.host_key = host.verifying_key().to_bytes();
        self.signature = host.sign(&self.message()?).to_bytes();
        Ok(self)
    }

    /// Verifies the signature under the acceptance's own `host_key`.
    ///
    /// # Errors
    ///
    /// [`AvpError::BadSignature`] if it does not verify.
    pub fn verify(&self) -> Result<(), AvpError> {
        self.verify_under(&self.host_key)
    }

    /// Verifies the signature under `host_key`.
    ///
    /// # Errors
    ///
    /// [`AvpError::BadSignature`] if it does not verify.
    pub fn verify_under(&self, host_key: &[u8; 32]) -> Result<(), AvpError> {
        ed25519_verify(host_key, &self.message()?, &self.signature)
    }
}

/// `InviteToken`, sent by the joiner to the owner (SPEC 11.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InviteToken {
    /// Always `2`.
    #[serde(rename = "v")]
    pub v: V2,
    /// The joiner's Ed25519 key.
    #[serde(rename = "ed25519PublicKey", with = "b64_array")]
    pub ed25519_public_key: [u8; 32],
    /// The joiner's X25519 key, the only key the owner wraps the data key to.
    #[serde(rename = "x25519PublicKey", with = "b64_array")]
    pub x25519_public_key: [u8; 32],
    /// The joiner's home host key.
    #[serde(rename = "homeHostKey", with = "b64_array")]
    pub home_host_key: [u8; 32],
    /// The joiner's home host locator.
    #[serde(rename = "homeHostLocator")]
    pub home_host_locator: String,
    /// The home host's acceptance.
    #[serde(rename = "acceptance")]
    pub acceptance: Acceptance,
}

impl InviteToken {
    /// The owner client's check before it adds a member or a host (SPEC 8.2): the acceptance
    /// verifies under its `hostKey`, names `repo_id`, names this token's Ed25519 key and home host
    /// key, and expires after `now_ms`.
    ///
    /// # Errors
    ///
    /// [`AvpError::BadSignature`] if the signature does not verify; [`AvpError::Reject`] with
    /// `forbidden` if any other condition fails.
    pub fn verify(&self, repo_id: &str, now_ms: i64) -> Result<(), AvpError> {
        let a = &self.acceptance;
        a.verify()?;
        let matches = a.repo_id == repo_id
            && ct_eq(&a.member_key, &self.ed25519_public_key)
            && ct_eq(&a.host_key, &self.home_host_key)
            && a.expires_at > now_ms;
        if matches {
            Ok(())
        } else {
            Err(AvpError::Reject(crate::RejectCode::Forbidden))
        }
    }
}

/// `RepoLocator`, sent by the owner to a joiner (SPEC 11.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RepoLocator {
    /// Always `2`.
    #[serde(rename = "v")]
    pub v: V2,
    /// The repository.
    #[serde(rename = "repoId")]
    pub repo_id: String,
    /// The owner's home host key.
    #[serde(rename = "hostKey", with = "b64_array")]
    pub host_key: [u8; 32],
    /// The owner's home host locator.
    #[serde(rename = "hostLocator")]
    pub host_locator: String,
    /// [`owner_fingerprint`] of the owner key.
    #[serde(rename = "ownerFingerprint")]
    pub owner_fingerprint: String,
}

/// `LinkRequest`, shown by a new owner device (SPEC 11.6).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LinkRequest {
    /// Always `2`.
    #[serde(rename = "v")]
    pub v: V2,
    /// The new device's ephemeral X25519 public key.
    #[serde(rename = "ephemeralPublicKey", with = "b64_array")]
    pub ephemeral_public_key: [u8; 32],
}

impl LinkRequest {
    /// A link request for an ephemeral X25519 public key.
    #[must_use]
    pub fn new(ephemeral_public_key: [u8; 32]) -> LinkRequest {
        LinkRequest {
            v: V2,
            ephemeral_public_key,
        }
    }

    /// The confirmation code (SPEC 11.6): the first 4 bytes of `SHA-256(CE(tag "avp/link-code/v1",
    /// bytes(ephemeralPublicKey)))` as `u32BE`, modulo 1 000 000, as 6 digits with leading zeros.
    ///
    /// # Errors
    ///
    /// Not reachable for a 32-byte key; the CE writer is fallible in general.
    pub fn confirmation_code(&self) -> Result<String, AvpError> {
        let mut w = Ce::new("avp/link-code/v1");
        w.bytes(&self.ephemeral_public_key);
        let d = sha256(&w.finish()?);
        let [a, b, c, e, ..] = d;
        Ok(format!("{:06}", u32::from_be_bytes([a, b, c, e]) % 1_000_000))
    }
}

/// `LinkGrant`, returned by an existing owner device (SPEC 11.6): the owner's mnemonic entropy
/// wrapped to the link request's ephemeral key under `avp/owner-link/v1`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LinkGrant {
    /// Always `2`.
    #[serde(rename = "v")]
    pub v: V2,
    /// The wrapped 32-byte entropy.
    #[serde(rename = "wrap")]
    pub wrap: WrappedKey,
}

impl LinkGrant {
    /// Wraps the 32-byte mnemonic entropy to `ephemeral_pub` with a fresh ephemeral key and IV.
    ///
    /// # Errors
    ///
    /// [`AvpError::Crypto`] if the AEAD fails.
    pub fn seal(entropy: &[u8; 32], ephemeral_pub: &[u8; 32]) -> Result<LinkGrant, AvpError> {
        LinkGrant::seal_with(entropy, ephemeral_pub, &x25519_random(), &random_bytes::<12>())
    }

    /// [`LinkGrant::seal`] with a caller-chosen wrap ephemeral key and IV, for reproducing the
    /// vectors. Real grants use [`LinkGrant::seal`].
    ///
    /// # Errors
    ///
    /// [`AvpError::Crypto`] if the AEAD fails.
    pub fn seal_with(
        entropy: &[u8; 32],
        ephemeral_pub: &[u8; 32],
        wrap_ephemeral: &StaticSecret,
        iv: &[u8; 12],
    ) -> Result<LinkGrant, AvpError> {
        Ok(LinkGrant {
            v: V2,
            wrap: wrap_with(ephemeral_pub, entropy, OWNER_LINK_INFO, wrap_ephemeral, iv)?,
        })
    }

    /// Unwraps the entropy with the new device's ephemeral private key under `avp/owner-link/v1`.
    ///
    /// # Errors
    ///
    /// [`AvpError::Crypto`] if the grant does not unwrap under that label, and
    /// [`AvpError::BadEncoding`] if the secret is not 32 bytes.
    pub fn open(&self, ephemeral_priv: &StaticSecret) -> Result<[u8; 32], AvpError> {
        let secret = unwrap(ephemeral_priv, &self.wrap, OWNER_LINK_INFO)?;
        let len = secret.len();
        secret
            .try_into()
            .map_err(|_| AvpError::BadEncoding(format!("link grant secret is {len} bytes, not 32")))
    }
}

/// A member's signed request to leave a repository (SPEC 8.4, 11.4). Sent as a JSON body, not as a
/// base64url token.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LeaveRequest {
    /// The repository.
    #[serde(rename = "repoId")]
    pub repo_id: String,
    /// The leaving member's Ed25519 key.
    #[serde(rename = "memberKey", with = "b64_array")]
    pub member_key: [u8; 32],
    /// The leaving client's time in epoch milliseconds.
    #[serde(rename = "at")]
    pub at: i64,
    /// The member's signature over [`LeaveRequest::message`].
    #[serde(rename = "signature", with = "b64_array")]
    pub signature: [u8; 64],
}

impl LeaveRequest {
    /// The signed message (SPEC 11.4): `CE(tag "avp/leave/v1", str(repoId), bytes(memberKey),
    /// i64(at))`.
    ///
    /// # Errors
    ///
    /// Not reachable for these field sizes; the CE writer is fallible in general.
    pub fn message(&self) -> Result<Vec<u8>, AvpError> {
        let mut w = Ce::new("avp/leave/v1");
        w.str(&self.repo_id).bytes(&self.member_key).i64(self.at);
        w.finish()
    }

    /// Signs the request with the member key; `member_key` is set to that key's public key.
    ///
    /// # Errors
    ///
    /// As [`LeaveRequest::message`].
    pub fn sign(mut self, member: &SigningKey) -> Result<LeaveRequest, AvpError> {
        self.member_key = member.verifying_key().to_bytes();
        self.signature = member.sign(&self.message()?).to_bytes();
        Ok(self)
    }

    /// Verifies the signature under `member_key` (SPEC 8.4).
    ///
    /// # Errors
    ///
    /// [`AvpError::BadSignature`] if it does not verify.
    pub fn verify(&self) -> Result<(), AvpError> {
        ed25519_verify(&self.member_key, &self.message()?, &self.signature)
    }
}

/// Encodes a token (SPEC 11.1): base64url-nopad over compact JSON with the fields in declaration
/// order, which is the SPEC order for every token type of this module.
///
/// # Errors
///
/// [`AvpError::BadEncoding`] if the value does not serialize.
pub fn encode_token<T: Serialize>(token: &T) -> Result<String, AvpError> {
    let json = serde_json::to_vec(token).map_err(|e| AvpError::BadEncoding(format!("token: {e}")))?;
    Ok(b64url_encode(&json))
}

/// Decodes a token (SPEC 11.1). Any field order and insignificant whitespace is accepted and
/// unknown fields are ignored; a `v` other than `2` and a binary field of the wrong length are
/// rejected.
///
/// # Errors
///
/// [`AvpError::BadEncoding`] if the text is not base64url-nopad or not a valid token of type `T`.
pub fn decode_token<T: DeserializeOwned>(text: &str) -> Result<T, AvpError> {
    let json = b64url_decode(text)?;
    serde_json::from_slice(&json).map_err(|e| AvpError::BadEncoding(format!("token: {e}")))
}

/// The member key fingerprint (SPEC 3.2): `hex(SHA-256(ed25519 || x25519)[0..8])` as
/// `xxxx-xxxx-xxxx-xxxx`.
#[must_use]
pub fn key_fingerprint(ed25519_public: &[u8; 32], x25519_public: &[u8; 32]) -> String {
    let mut both = [0u8; 64];
    for (dst, src) in both.iter_mut().zip(ed25519_public.iter().chain(x25519_public)) {
        *dst = *src;
    }
    let d = sha256(&both);
    let [a, b, c, e, f, g, h, i, ..] = d;
    format!("{}-{}-{}-{}", hex(&[a, b]), hex(&[c, e]), hex(&[f, g]), hex(&[h, i]))
}

/// The owner fingerprint of a repo locator (SPEC 11.2): `hex(SHA-256(ownerKey)[0..8])`.
#[must_use]
pub fn owner_fingerprint(owner_key: &[u8; 32]) -> String {
    let d = sha256(owner_key);
    hex(d.get(..8).unwrap_or_default())
}

/// An `avp://<hostLocator>/<repoId>` locator URI (SPEC 11.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AvpUri {
    /// The host locator, `host` or `host:port`.
    pub host_locator: String,
    /// The 22-character repository id.
    pub repo_id: String,
}

impl AvpUri {
    /// Parses `avp://<hostLocator>/<repoId>`.
    ///
    /// # Errors
    ///
    /// [`AvpError::BadEncoding`] if the scheme is not `avp://`, the locator is empty or holds a
    /// `/`, or the repoId is not 22 base64url characters.
    pub fn parse(uri: &str) -> Result<AvpUri, AvpError> {
        let bad = || AvpError::BadEncoding(format!("not an avp:// locator: {uri:?}"));
        let rest = uri.strip_prefix("avp://").ok_or_else(bad)?;
        let (host, repo) = rest.split_once('/').ok_or_else(bad)?;
        let repo_ok = repo.len() == 22
            && repo
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if host.is_empty() || !repo_ok {
            return Err(bad());
        }
        Ok(AvpUri {
            host_locator: host.to_string(),
            repo_id: repo.to_string(),
        })
    }
}

impl fmt::Display for AvpUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "avp://{}/{}", self.host_locator, self.repo_id)
    }
}
