// SPDX-License-Identifier: MIT

//! Manifest states (SPEC 4.2): the wire types, the canonical bytes `S`, the owner signature,
//! `manifestHash`, and the `repoId` derivation.

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};

use crate::crypto::{ct_eq, ed25519_verify, sha256};
use crate::encoding::{Ce, b64, b64_array, b64_ids, b64url_encode, sorted_unique};
use crate::error::AvpError;

/// A host that replicates the repository: its Ed25519 host key and a locator (SPEC 3.3, 4.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HostRef {
    /// The host key.
    #[serde(rename = "hostKey", with = "b64_array")]
    pub key: [u8; 32],
    /// The dialing hint, `host` or `host:port`.
    #[serde(rename = "locator")]
    pub locator: String,
}

/// A secret wrapped to one recipient with the default wrap scheme (SPEC 4.4).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WrappedKey {
    /// The wrap scheme id.
    #[serde(rename = "schemeId")]
    pub scheme_id: String,
    /// The raw ephemeral X25519 public key.
    #[serde(rename = "ephemeralPublicKey", with = "b64_array")]
    pub ephemeral_public_key: [u8; 32],
    /// The AES-GCM IV.
    #[serde(rename = "iv", with = "b64_array")]
    pub iv: [u8; 12],
    /// The wrapped secret with the 16-byte tag appended.
    #[serde(rename = "ciphertext", with = "b64")]
    pub ciphertext: Vec<u8>,
}

/// A member as the owner signed it (SPEC 4.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MemberEntry {
    /// The member's Ed25519 public key, its member id.
    #[serde(rename = "ed25519PublicKey", with = "b64_array")]
    pub ed25519_public_key: [u8; 32],
    /// The member's X25519 public key.
    #[serde(rename = "x25519PublicKey", with = "b64_array")]
    pub x25519_public_key: [u8; 32],
    /// The data key of `key_epoch` wrapped to `x25519_public_key`.
    #[serde(rename = "wrappedDataKey")]
    pub wrapped_data_key: WrappedKey,
    /// The epoch of the wrapped data key.
    #[serde(rename = "keyEpoch")]
    pub key_epoch: i64,
    /// The host key of the member's home host.
    #[serde(rename = "homeHostKey", with = "b64_array")]
    pub home_host_key: [u8; 32],
}

/// A removed member and its signed removal cutoff (SPEC 4.2, 7.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Removal {
    /// The removed member's Ed25519 key.
    #[serde(rename = "memberKey", with = "b64_array")]
    pub member_key: [u8; 32],
    /// The `manifestSeq` of the state that removed it.
    #[serde(rename = "removedAtSeq")]
    pub removed_at_seq: i64,
    /// The commit ids of the cutoff.
    #[serde(rename = "frontier", with = "b64_ids")]
    pub frontier: Vec<[u8; 32]>,
}

/// One manifest state (SPEC 4.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ManifestState {
    /// The repository id.
    #[serde(rename = "repoId")]
    pub repo_id: String,
    /// `1` at genesis, `+1` per state.
    #[serde(rename = "manifestSeq")]
    pub manifest_seq: i64,
    /// The previous state's `manifestHash`; empty at seq 1.
    #[serde(rename = "prevManifestHash", with = "b64", default)]
    pub prev_manifest_hash: Vec<u8>,
    /// The owner Ed25519 public key.
    #[serde(rename = "ownerKey", with = "b64_array")]
    pub owner_key: [u8; 32],
    /// 16 random bytes at seq 1; empty after.
    #[serde(rename = "genesisNonce", with = "b64", default)]
    pub genesis_nonce: Vec<u8>,
    /// The wrap scheme id.
    #[serde(rename = "schemeId")]
    pub scheme_id: String,
    /// The current data key epoch.
    #[serde(rename = "keyEpoch")]
    pub key_epoch: i64,
    /// The refresh-token policy (SPEC 5.1); absent means `false`.
    #[serde(rename = "shareRefreshTokens", default)]
    pub share_refresh_tokens: bool,
    /// The hosts that replicate this repository.
    #[serde(rename = "hosts")]
    pub hosts: Vec<HostRef>,
    /// The members, the owner included.
    #[serde(rename = "members")]
    pub members: Vec<MemberEntry>,
    /// Every member ever removed, cumulative.
    #[serde(rename = "removals", default)]
    pub removals: Vec<Removal>,
}

/// A manifest state with its owner signature (SPEC 4.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SignedManifest {
    /// The state.
    #[serde(rename = "state")]
    pub state: ManifestState,
    /// `Ed25519-Sign(ownerKey, S)`.
    #[serde(rename = "ownerSignature", with = "b64_array")]
    pub owner_signature: [u8; 64],
}

impl ManifestState {
    /// The canonical bytes `S` of the state (SPEC 4.2).
    ///
    /// Hosts are sorted by `hostKey`, members by `ed25519PublicKey`, removals by `memberKey`, and
    /// each frontier by commit id, so the order of every wire list does not matter.
    ///
    /// # Errors
    ///
    /// [`AvpError::BadEncoding`] if a list holds the same key twice (SPEC 4.2 wire form).
    pub fn encode(&self) -> Result<Vec<u8>, AvpError> {
        let mut w = Ce::new("avp/manifest/v1");
        w.str(&self.repo_id)
            .i64(self.manifest_seq)
            .bytes(&self.prev_manifest_hash)
            .bytes(&self.owner_key)
            .bytes(&self.genesis_nonce)
            .str(&self.scheme_id)
            .i64(self.key_epoch)
            .bool(self.share_refresh_tokens);

        let hosts = sorted_unique(&self.hosts, |h| &h.key, "hostKey")?;
        w.count(hosts.len());
        for h in hosts {
            w.bytes(&h.key).str(&h.locator);
        }

        let members = sorted_unique(&self.members, |m| &m.ed25519_public_key, "member ed25519PublicKey")?;
        w.count(members.len());
        for m in members {
            let wk = &m.wrapped_data_key;
            w.bytes(&m.ed25519_public_key)
                .bytes(&m.x25519_public_key)
                .str(&wk.scheme_id)
                .bytes(&wk.ephemeral_public_key)
                .bytes(&wk.iv)
                .bytes(&wk.ciphertext)
                .i64(m.key_epoch)
                .bytes(&m.home_host_key);
        }

        let removals = sorted_unique(&self.removals, |r| &r.member_key, "removal memberKey")?;
        w.count(removals.len());
        for r in removals {
            w.bytes(&r.member_key).i64(r.removed_at_seq);
            let frontier = sorted_unique(&r.frontier, |id| id, "frontier commit id")?;
            w.count(frontier.len());
            for id in frontier {
                w.bytes(id);
            }
        }
        w.finish()
    }

    /// Signs the state with the owner key: `ownerSignature = Ed25519-Sign(ownerKey, S)` (SPEC 4.2).
    ///
    /// The caller passes the key whose public key is `owner_key`; a state signed by another key
    /// fails [`SignedManifest::verify`].
    ///
    /// # Errors
    ///
    /// As [`ManifestState::encode`].
    pub fn sign(self, owner: &SigningKey) -> Result<SignedManifest, AvpError> {
        let owner_signature = owner.sign(&self.encode()?).to_bytes();
        Ok(SignedManifest {
            state: self,
            owner_signature,
        })
    }

    /// Whether `key` is a member of this state.
    #[must_use]
    pub fn has_member(&self, key: &[u8; 32]) -> bool {
        self.members.iter().any(|m| m.ed25519_public_key == *key)
    }

    /// Whether `key` is in this state's `hosts`.
    #[must_use]
    pub fn has_host(&self, key: &[u8; 32]) -> bool {
        self.hosts.iter().any(|h| h.key == *key)
    }

    /// The removal of `key` in this state, if any.
    #[must_use]
    pub fn removal_of(&self, key: &[u8; 32]) -> Option<&Removal> {
        self.removals.iter().find(|r| r.member_key == *key)
    }
}

impl SignedManifest {
    /// `manifestHash = SHA-256(S || ownerSignature)`, the raw 64-byte signature appended with no
    /// length prefix (SPEC 4.2).
    ///
    /// # Errors
    ///
    /// As [`ManifestState::encode`].
    pub fn hash(&self) -> Result<[u8; 32], AvpError> {
        let mut bytes = self.state.encode()?;
        bytes.extend_from_slice(&self.owner_signature);
        Ok(sha256(&bytes))
    }

    /// Verifies the owner signature over `S` under `ownerKey` (SPEC 4.2, 6.1 rule 2).
    ///
    /// # Errors
    ///
    /// [`AvpError::BadSignature`] if it does not verify; [`AvpError::BadEncoding`] if the state
    /// does not encode.
    pub fn verify(&self) -> Result<(), AvpError> {
        ed25519_verify(&self.state.owner_key, &self.state.encode()?, &self.owner_signature)
    }

    /// Whether this state links to `prev` (SPEC 6.3): `manifestSeq` is `prev`'s plus one and
    /// `prevManifestHash` is `prev`'s `manifestHash`.
    ///
    /// # Errors
    ///
    /// As [`SignedManifest::hash`] of `prev`.
    pub fn links_to(&self, prev: &SignedManifest) -> Result<bool, AvpError> {
        let next_seq = prev.state.manifest_seq.checked_add(1);
        Ok(next_seq == Some(self.state.manifest_seq) && ct_eq(&self.state.prev_manifest_hash, &prev.hash()?))
    }
}

/// The repository id (SPEC 4.2): `base64url-nopad(SHA-256(CE(tag "avp/repo-id/v1",
/// bytes(ownerKey), bytes(genesisNonce)))[0..16])`, 22 characters.
///
/// # Errors
///
/// Not reachable for these fixed-size inputs; the CE writer is fallible in general.
pub fn derive_repo_id(owner: &[u8; 32], nonce: &[u8; 16]) -> Result<String, AvpError> {
    let mut w = Ce::new("avp/repo-id/v1");
    w.bytes(owner).bytes(nonce);
    let digest = sha256(&w.finish()?);
    Ok(b64url_encode(digest.get(..16).unwrap_or_default()))
}
