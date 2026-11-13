// SPDX-License-Identifier: MIT

//! Host-issued authentication (SPEC 3.3): challenges and bearer tokens.
//!
//! A challenge is 32 random bytes from a CSPRNG, issued for one Ed25519 key, single-use, and valid
//! for [`CHALLENGE_TTL_MS`]. The client signs the challenge transcript
//! `CE(tag "avp/challenge/v1", bytes(hostKey), bytes(ed25519PublicKey), bytes(nonce))`, never the raw
//! nonce, and the host verifies it with its own host key. A token is 32 random bytes (base64url), valid only at this host for
//! [`TOKEN_TTL_MS`], whose subject is the key that signed the challenge.
//!
//! Neither secret is stored: both maps are keyed by the SHA-256 digest of the secret, so a lookup
//! compares digests rather than the secret itself and its timing says nothing about the secret.
//! The challenge's bound key is compared in constant time.
//!
//! Memory stays bounded by two caps per table ([`Caps`]): a per-key cap answered with
//! `429 quota_exceeded`, and a total cap at which the oldest entry is evicted, so one caller
//! filling the table cannot lock every other caller out.

use std::collections::HashMap;

use avp::auth::verify_challenge;
use avp::crypto::{ct_eq, random_bytes, sha256};
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
    /// This key already holds its share of outstanding challenges or live tokens:
    /// `429 quota_exceeded`.
    Full,
}

/// The size caps of one table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// Most live entries in all; at the cap the entry that expires first is evicted.
    pub total: usize,
    /// Most live entries for one key; more is [`AuthError::Full`].
    pub per_key: usize,
}

struct Entry {
    key: [u8; 32],
    expires_at: i64,
}

/// Drops expired entries, refuses a key at its per-key cap, and evicts the entry that expires
/// first while the table is at its total cap.
fn make_room(map: &mut HashMap<[u8; 32], Entry>, key: &[u8; 32], now: i64, caps: Caps) -> Result<(), AuthError> {
    map.retain(|_, e| e.expires_at > now);
    if caps.total == 0 || map.values().filter(|e| e.key == *key).count() >= caps.per_key {
        return Err(AuthError::Full);
    }
    while map.len() >= caps.total {
        let oldest = map.iter().min_by_key(|(_, e)| e.expires_at).map(|(d, _)| *d);
        match oldest {
            Some(d) => map.remove(&d),
            None => break,
        };
    }
    Ok(())
}

/// Outstanding challenges and live tokens, keyed by the SHA-256 digest of the secret.
#[derive(Default)]
pub struct Auth {
    challenges: HashMap<[u8; 32], Entry>,
    tokens: HashMap<[u8; 32], Entry>,
}

impl Auth {
    /// Issues a single-use challenge nonce for `key`, valid until `now + CHALLENGE_TTL_MS`.
    ///
    /// # Errors
    ///
    /// [`AuthError::Full`] when `key` already has `caps.per_key` outstanding challenges.
    pub fn challenge(&mut self, key: [u8; 32], now: i64, caps: Caps) -> Result<[u8; 32], AuthError> {
        make_room(&mut self.challenges, &key, now, caps)?;
        let nonce = random_bytes::<32>();
        self.challenges.insert(
            sha256(&nonce),
            Entry {
                key,
                expires_at: now.saturating_add(CHALLENGE_TTL_MS),
            },
        );
        Ok(nonce)
    }

    /// Redeems a signed challenge for a token whose subject is `key` (SPEC 3.3 step 2). The
    /// signature is verified over the challenge transcript built with `host_key`, this host's own
    /// key. The nonce is consumed whatever the outcome, so it can never be tried twice.
    ///
    /// Returns the token text and its expiry in epoch milliseconds.
    ///
    /// # Errors
    ///
    /// [`AuthError::Unauthorized`] if the nonce was not issued, was already used, has expired, was
    /// issued for another key, or the signature over the transcript does not verify under `key`
    /// (a signature over the raw nonce, or a transcript built with another host key, does not);
    /// [`AuthError::Full`] when `key` already has `caps.per_key` live tokens.
    pub fn token(
        &mut self,
        host_key: &[u8; 32],
        key: [u8; 32],
        nonce: &[u8],
        signature: &[u8; 64],
        now: i64,
        caps: Caps,
    ) -> Result<(String, i64), AuthError> {
        let challenge = self.challenges.remove(&sha256(nonce)).ok_or(AuthError::Unauthorized)?;
        if challenge.expires_at <= now || !ct_eq(&challenge.key, &key) {
            return Err(AuthError::Unauthorized);
        }
        verify_challenge(host_key, &key, nonce, signature).map_err(|_| AuthError::Unauthorized)?;
        make_room(&mut self.tokens, &key, now, caps)?;
        let token = b64url_encode(&random_bytes::<32>());
        let expires_at = now.saturating_add(TOKEN_TTL_MS);
        self.tokens.insert(sha256(token.as_bytes()), Entry { key, expires_at });
        Ok((token, expires_at))
    }

    /// The subject of a live token issued by this host, or `None` for an unknown or expired one.
    #[must_use]
    pub fn subject(&self, token: &str, now: i64) -> Option<[u8; 32]> {
        self.tokens
            .get(&sha256(token.as_bytes()))
            .filter(|e| e.expires_at > now)
            .map(|e| e.key)
    }
}
