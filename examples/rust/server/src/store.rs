// SPDX-License-Identifier: MIT

//! What the host stores: one [`RepoView`] per repository and the acceptances it issued.
//!
//! A [`RepoView`] holds only owner-signed manifest states, signed commits (ciphertext), and signed
//! leave requests. Nothing here is a data key or a plaintext.

use std::collections::HashMap;

use avp::rules::RepoView;

/// The repositories this host carries and the acceptances it issued (SPEC 8.2).
#[derive(Debug, Clone, Default)]
pub struct Store {
    /// Each repository's engine view, by `repoId`.
    pub repos: HashMap<String, RepoView>,
    /// `(repoId, memberKey)` of each acceptance this host issued, to its `expiresAt`. Replication
    /// uses it to decide whether to store a repository it does not hold yet (SPEC 8.2).
    pub pending_join: HashMap<(String, [u8; 32]), i64>,
}

impl Store {
    /// How many repositories on this host have `owner` as their owner key.
    #[must_use]
    pub fn repos_owned_by(&self, owner: &[u8; 32]) -> usize {
        self.repos
            .values()
            .filter(|v| v.tip().is_some_and(|t| t.state.owner_key == *owner))
            .count()
    }

    /// Records an issued acceptance, after dropping expired ones. Returns `false`, recording
    /// nothing, when `max` unexpired acceptances are already recorded.
    #[must_use]
    pub fn record_acceptance(
        &mut self,
        repo_id: &str,
        member: [u8; 32],
        expires_at: i64,
        now: i64,
        max: usize,
    ) -> bool {
        self.pending_join.retain(|_, exp| *exp > now);
        let key = (repo_id.to_string(), member);
        if !self.pending_join.contains_key(&key) && self.pending_join.len() >= max {
            return false;
        }
        self.pending_join.insert(key, expires_at);
        true
    }
}
