// SPDX-License-Identifier: MIT

//! Commits (SPEC 4.3): the header bytes, `commitId`, the author signature, AAD v2, and the payload
//! AEAD.

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};

use crate::crypto::{aes_gcm_open, aes_gcm_seal, ct_eq, ed25519_verify, random_bytes, sha256};
use crate::encoding::{Ce, b64, b64_array, b64_ids, sorted_unique};
use crate::error::AvpError;

/// The fields of a commit an author chooses before sealing (SPEC 4.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommitHeader {
    /// The repository.
    pub repo_id: String,
    /// The parent commit ids: none for the first commit, two or more for a merge.
    pub parents: Vec<[u8; 32]>,
    /// The manifest state the author writes under.
    pub manifest_seq: i64,
    /// The `manifestHash` of that state.
    pub manifest_hash: [u8; 32],
    /// The epoch of the data key that encrypts the payload.
    pub key_epoch: i64,
}

/// A commit (SPEC 4.3), field names as in the proto.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Commit {
    /// The repository.
    #[serde(rename = "repoId")]
    pub repo_id: String,
    /// The commit id, `SHA-256(H)`.
    #[serde(rename = "commitId", with = "b64_array")]
    pub commit_id: [u8; 32],
    /// The parent commit ids.
    #[serde(rename = "parents", with = "b64_ids")]
    pub parents: Vec<[u8; 32]>,
    /// The manifest state the author wrote under.
    #[serde(rename = "manifestSeq")]
    pub manifest_seq: i64,
    /// The `manifestHash` of that state.
    #[serde(rename = "manifestHash", with = "b64_array")]
    pub manifest_hash: [u8; 32],
    /// The epoch of the data key that encrypts the payload.
    #[serde(rename = "keyEpoch")]
    pub key_epoch: i64,
    /// The author's member Ed25519 public key.
    #[serde(rename = "author", with = "b64_array")]
    pub author: [u8; 32],
    /// The payload AES-GCM IV.
    #[serde(rename = "iv", with = "b64_array")]
    pub iv: [u8; 12],
    /// The payload ciphertext with the 16-byte tag appended.
    #[serde(rename = "ciphertext", with = "b64")]
    pub ciphertext: Vec<u8>,
    /// `Ed25519-Sign(author, CE(tag "avp/commit-sig/v1", bytes(commitId)))`.
    #[serde(rename = "authorSignature", with = "b64_array")]
    pub author_signature: [u8; 64],
}

/// Writes `count(parents)` then each parent id, sorted.
fn write_parents(w: &mut Ce, parents: &[[u8; 32]]) -> Result<(), AvpError> {
    let sorted = sorted_unique(parents, |p| p, "parent id")?;
    w.count(sorted.len());
    for p in sorted {
        w.bytes(p);
    }
    Ok(())
}

/// The payload additional authenticated data, AAD v2 (SPEC 4.3), parents sorted.
///
/// # Errors
///
/// [`AvpError::BadEncoding`] if a parent id appears twice.
pub fn aad_v2(repo_id: &str, key_epoch: i64, author: &[u8; 32], parents: &[[u8; 32]]) -> Result<Vec<u8>, AvpError> {
    let mut w = Ce::new("avp/aad/v2");
    w.str(repo_id).i64(key_epoch).bytes(author);
    write_parents(&mut w, parents)?;
    w.finish()
}

/// The message an author signs (SPEC 4.3): `CE(tag "avp/commit-sig/v1", bytes(commitId))`.
///
/// # Errors
///
/// Not reachable for a 32-byte id; the CE writer is fallible in general.
pub fn commit_sig_message(commit_id: &[u8; 32]) -> Result<Vec<u8>, AvpError> {
    let mut w = Ce::new("avp/commit-sig/v1");
    w.bytes(commit_id);
    w.finish()
}

impl Commit {
    /// Encrypts `plaintext` under `data_key` with a fresh random IV and AAD v2, computes the
    /// commit id, and signs it with the author key (SPEC 4.3).
    ///
    /// # Errors
    ///
    /// [`AvpError::BadEncoding`] if a parent id appears twice; [`AvpError::Crypto`] if the AEAD
    /// fails.
    pub fn seal(
        data_key: &[u8; 32],
        header: CommitHeader,
        plaintext: &[u8],
        author: &SigningKey,
    ) -> Result<Commit, AvpError> {
        Commit::seal_with_iv(data_key, header, plaintext, author, &random_bytes::<12>())
    }

    /// [`Commit::seal`] with a caller-chosen IV, for reproducing the vectors.
    ///
    /// Real commits MUST use a fresh random IV each time; use [`Commit::seal`].
    ///
    /// # Errors
    ///
    /// As [`Commit::seal`].
    pub fn seal_with_iv(
        data_key: &[u8; 32],
        header: CommitHeader,
        plaintext: &[u8],
        author: &SigningKey,
        iv: &[u8; 12],
    ) -> Result<Commit, AvpError> {
        let author_key = author.verifying_key().to_bytes();
        let aad = aad_v2(&header.repo_id, header.key_epoch, &author_key, &header.parents)?;
        let ciphertext = aes_gcm_seal(data_key, iv, plaintext, &aad)?;
        let mut c = Commit {
            repo_id: header.repo_id,
            commit_id: [0; 32],
            parents: header.parents,
            manifest_seq: header.manifest_seq,
            manifest_hash: header.manifest_hash,
            key_epoch: header.key_epoch,
            author: author_key,
            iv: *iv,
            ciphertext,
            author_signature: [0; 64],
        };
        c.commit_id = c.id()?;
        c.author_signature = author.sign(&commit_sig_message(&c.commit_id)?).to_bytes();
        Ok(c)
    }

    /// The header bytes `H` (SPEC 4.3), parents sorted.
    ///
    /// # Errors
    ///
    /// [`AvpError::BadEncoding`] if a parent id appears twice.
    pub fn header_bytes(&self) -> Result<Vec<u8>, AvpError> {
        let mut w = Ce::new("avp/commit/v1");
        w.str(&self.repo_id);
        write_parents(&mut w, &self.parents)?;
        w.i64(self.manifest_seq)
            .bytes(&self.manifest_hash)
            .i64(self.key_epoch)
            .bytes(&self.author)
            .bytes(&self.iv)
            .bytes(&self.ciphertext);
        w.finish()
    }

    /// The commit id recomputed from the header, `SHA-256(H)` (SPEC 4.3).
    ///
    /// This is not the `commit_id` field; [`Commit::verify`] checks that the two match.
    ///
    /// # Errors
    ///
    /// As [`Commit::header_bytes`].
    pub fn id(&self) -> Result<[u8; 32], AvpError> {
        Ok(sha256(&self.header_bytes()?))
    }

    /// Checks SPEC 7.1: `commitId` recomputes from the header and `authorSignature` verifies under
    /// `author`.
    ///
    /// # Errors
    ///
    /// [`AvpError::BadSignature`] if the id does not recompute or the signature does not verify;
    /// [`AvpError::BadEncoding`] if a parent id appears twice.
    pub fn verify(&self) -> Result<(), AvpError> {
        if !ct_eq(&self.id()?, &self.commit_id) {
            return Err(AvpError::BadSignature);
        }
        ed25519_verify(
            &self.author,
            &commit_sig_message(&self.commit_id)?,
            &self.author_signature,
        )
    }

    /// Decrypts the payload under `data_key` with the AAD v2 built from this commit's own header
    /// fields (SPEC 4.3).
    ///
    /// # Errors
    ///
    /// [`AvpError::Crypto`] if the payload does not authenticate (wrong key, or any of repoId,
    /// epoch, author, or parent set differs from what was sealed); [`AvpError::BadEncoding`] if a
    /// parent id appears twice.
    pub fn open(&self, data_key: &[u8; 32]) -> Result<Vec<u8>, AvpError> {
        let aad = aad_v2(&self.repo_id, self.key_epoch, &self.author, &self.parents)?;
        aes_gcm_open(data_key, &self.iv, &self.ciphertext, &aad)
    }
}
