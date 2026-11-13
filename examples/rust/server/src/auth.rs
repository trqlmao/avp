// SPDX-License-Identifier: MIT

//! Host-issued authentication (SPEC 3.3): challenges and bearer tokens.
//!
//! A challenge is 32 random bytes from a CSPRNG, issued for one Ed25519 key, single-use, and valid
//! for [`CHALLENGE_TTL_MS`]. A token is 32 random bytes (base64url), valid only at this host for
//! [`TOKEN_TTL_MS`], whose subject is the key that signed the challenge.
//!
//! Neither secret is stored: both maps are keyed by the SHA-256 digest of the secret, so a lookup
//! compares digests rather than the secret itself and its timing says nothing about the secret.
//! The challenge's bound key is compared in constant time.

use std::collections::HashMap;

use avp::crypto::{ct_eq, ed25519_verify, random_bytes, sha256};
use avp::encoding::b64url_encode;

/// How long a challenge nonce stays valid (SPEC 3.3: RECOMMENDED at most 2 minutes).
pub const CHALLENGE_TTL_MS: i64 = 2 * 60 * 1000;

/// How long a minted token stays valid (SPEC 3.3: tokens SHOULD be short-lived).
pub const TOKEN_TTL_MS: i64 = 15 * 60 * 1000;

/// Why a challenge or token request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// The nonce is unknown, already used, expired, issued for another key, or the signature does
    /// not verify: `401 unauthorized`.
    Unauthorized,
    /// Too many outstanding challenges or live tokens: `429 quota_exceeded`.
    Full,
}

struct Challenge {
    key: [u8; 32],
    expires_at: i64,
}

struct Session {
    subject: [u8; 32],
    expires_at: i64,
}

/// Outstanding challenges and live tokens, keyed by the SHA-256 digest of the secret.
#[derive(Default)]
pub struct Auth {
    challenges: HashMap<[u8; 32], Challenge>,
    tokens: HashMap<[u8; 32], Session>,
}

impl Auth {
    /// Issues a single-use challenge nonce for `key`, valid until `now + CHALLENGE_TTL_MS`.
    ///
    /// # Errors
    ///
    /// [`AuthError::Full`] when `max` unexpired challenges are outstanding.
    pub fn challenge(&mut self, key: [u8; 32], now: i64, max: usize) -> Result<[u8; 32], AuthError> {
        self.challenges.retain(|_, c| c.expires_at > now);
        if self.challenges.len() >= max {
            return Err(AuthError::Full);
        }
        let nonce = random_bytes::<32>();
        self.challenges.insert(
            sha256(&nonce),
            Challenge {
                key,
                expires_at: now.saturating_add(CHALLENGE_TTL_MS),
            },
        );
        Ok(nonce)
    }

    /// Redeems a signed challenge for a token whose subject is `key` (SPEC 3.3 step 2). The nonce
    /// is consumed whatever the outcome, so it can never be tried twice.
    ///
    /// Returns the token text and its expiry in epoch milliseconds.
    ///
    /// # Errors
    ///
    /// [`AuthError::Unauthorized`] if the nonce was not issued, was already used, has expired, was
    /// issued for another key, or the signature over the raw nonce bytes does not verify under
    /// `key`; [`AuthError::Full`] when `max_tokens` live tokens exist.
    pub fn token(
        &mut self,
        key: [u8; 32],
        nonce: &[u8],
        signature: &[u8; 64],
        now: i64,
        max_tokens: usize,
    ) -> Result<(String, i64), AuthError> {
        let challenge = self.challenges.remove(&sha256(nonce)).ok_or(AuthError::Unauthorized)?;
        if challenge.expires_at <= now || !ct_eq(&challenge.key, &key) {
            return Err(AuthError::Unauthorized);
        }
        ed25519_verify(&key, nonce, signature).map_err(|_| AuthError::Unauthorized)?;
        self.tokens.retain(|_, s| s.expires_at > now);
        if self.tokens.len() >= max_tokens {
            return Err(AuthError::Full);
        }
        let token = b64url_encode(&random_bytes::<32>());
        let expires_at = now.saturating_add(TOKEN_TTL_MS);
        self.tokens.insert(
            sha256(token.as_bytes()),
            Session {
                subject: key,
                expires_at,
            },
        );
        Ok((token, expires_at))
    }

    /// The subject of a live token issued by this host, or `None` for an unknown or expired one.
    #[must_use]
    pub fn subject(&self, token: &str, now: i64) -> Option<[u8; 32]> {
        self.tokens
            .get(&sha256(token.as_bytes()))
            .filter(|s| s.expires_at > now)
            .map(|s| s.subject)
    }
}
