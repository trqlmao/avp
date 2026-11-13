// SPDX-License-Identifier: MIT

//! Host acceptance rules (SPEC 6, 7, 8.3, 8.4): one host's view of one repository.
//!
//! [`RepoView`] models the decisions, not the transport. It holds the winning manifest chain,
//! every verified losing state (SPEC 6.5), every commit with its [`CommitStatus`], every verified
//! commit header (for the removal cutoff ancestry of SPEC 7.3), the rotation commit of each
//! epoch-raising state, and the pending leave requests. Each operation names the path it arrived
//! on ([`Via`]). It mirrors the TypeScript reference engine in `examples/conformance/src/rules.ts`
//! and is checked against `vectors/acceptance.json`.
//!
//! Every input is attacker-controlled. No method panics; every failure is a [`RejectCode`].

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::commit::Commit;
use crate::error::{AvpError, RejectCode};
use crate::manifest::{ManifestState, SignedManifest, derive_repo_id};
use crate::tokens::LeaveRequest;

/// A commit id or manifest hash.
type Id = [u8; 32];

/// The verdict of one operation.
type Verdict = Result<(), RejectCode>;

/// The path an item arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Via {
    /// A client write (`push`, `createRepo`, `publishManifest`, `leave`). The host has already
    /// authenticated the caller and passes the item only when the caller is the commit's author
    /// (the owner for a manifest and the commit carried with it, `memberKey` for a leave). The
    /// engine then checks that the author is a member of the tip (SPEC 7.1) and applies the head
    /// bound (SPEC 7.4); a manifest must be at tip + 1 (SPEC 6.3) and list this host (SPEC 6.1
    /// rule 6).
    Push,
    /// An item of a peer host's replication `offer` (SPEC 9.1): no caller check and no head bound,
    /// and diverged states meet the tie rule (SPEC 6.5). A state is not rejected for not listing
    /// this host: rule 6 applies to the tip of the chain being received, which the host checks
    /// before it applies the offer (SPEC 6.1, 9.2).
    Offer,
}

/// The status of a stored commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommitStatus {
    /// Accepted: a head unless an accepted commit names it as a parent.
    Accepted,
    /// Held until an owner device decides (SPEC 6.5): not a head, not served, not offered.
    Held,
    /// Stored but undecided: its removal cutoff waits on a frontier commit header it lacks
    /// (SPEC 7.3). Neither a head nor held.
    Pending,
    /// Rejected or dropped (SPEC 6.5, 7.3, 7.4).
    Rejected,
}

#[derive(Debug)]
struct StateRec {
    m: SignedManifest,
    hash: Id,
    seq: i64,
}

impl StateRec {
    fn state(&self) -> &ManifestState {
        &self.m.state
    }
}

#[derive(Debug, Clone)]
struct CommitRec {
    c: Arc<Commit>,
    status: CommitStatus,
}

/// Everything a view holds; cloned to make an operation atomic.
#[derive(Debug, Clone, Default)]
struct Store {
    /// The winning chain; `chain[i]` has `manifestSeq` `i + 1`.
    chain: Vec<Arc<StateRec>>,
    /// Every verified state, winning or losing, by manifest hash.
    states: HashMap<Id, Arc<StateRec>>,
    /// Manifest hash of each epoch-raising state to its rotation commit id.
    rotation: HashMap<Id, Id>,
    /// Commit ids in the order they were first stored.
    order: Vec<Id>,
    /// Every stored commit with its status.
    commits: HashMap<Id, CommitRec>,
    /// The parents of every commit whose id recomputes and whose signature verifies (SPEC 7.3).
    headers: HashMap<Id, Vec<Id>>,
    /// The latest leave request per member, sorted by member key.
    leaves: Vec<LeaveRequest>,
}

/// The classification of one commit by the membership, cutoff, and parent rules.
enum Classification {
    Accepted,
    Held,
    Rejected,
    Error(RejectCode),
}

/// The SPEC 6.5 verdict for a commit citing a verified losing state.
#[derive(PartialEq, Eq)]
enum Losing {
    Accepted,
    Held,
    Rejected,
    Undecided,
}

/// The SPEC 7.3 removal cutoff outcome.
#[derive(PartialEq, Eq)]
enum Cut {
    Ok,
    Fail,
    Undecided,
}

/// True when no two ids are equal.
fn distinct(ids: &[Id]) -> bool {
    let mut seen = HashSet::with_capacity(ids.len());
    ids.iter().all(|id| seen.insert(*id))
}

/// SPEC 6.1 rule 1: the binary fields the wire types do not fix have their lengths, the counters
/// are in range, and no list repeats a key. Fixed-length fields are checked by the decoder.
fn manifest_shape_ok(m: &SignedManifest) -> bool {
    let s = &m.state;
    if s.manifest_seq < 1 || s.key_epoch < 0 {
        return false;
    }
    let genesis = s.manifest_seq == 1;
    let (prev_len, nonce_len) = if genesis { (0, 16) } else { (32, 0) };
    if s.prev_manifest_hash.len() != prev_len || s.genesis_nonce.len() != nonce_len {
        return false;
    }
    if !s
        .members
        .iter()
        .all(|x| x.key_epoch >= 0 && x.wrapped_data_key.ciphertext.len() == 48)
    {
        return false;
    }
    if !s
        .removals
        .iter()
        .all(|r| r.removed_at_seq >= 0 && distinct(&r.frontier))
    {
        return false;
    }
    let hosts: Vec<Id> = s.hosts.iter().map(|h| h.key).collect();
    let members: Vec<Id> = s.members.iter().map(|x| x.ed25519_public_key).collect();
    let removed: Vec<Id> = s.removals.iter().map(|r| r.member_key).collect();
    distinct(&hosts) && distinct(&members) && distinct(&removed)
}

/// SPEC 7.1: the counters are in range, the ciphertext holds at least the GCM tag, and no parent
/// appears twice. Fixed-length fields are checked by the decoder.
fn commit_shape_ok(c: &Commit) -> bool {
    c.ciphertext.len() >= 16 && c.manifest_seq >= 1 && c.key_epoch >= 0 && distinct(&c.parents)
}

/// SPEC 6.2: the genesis state.
fn genesis_ok(s: &ManifestState) -> bool {
    if !s.prev_manifest_hash.is_empty() || s.key_epoch != 0 || !s.removals.is_empty() {
        return false;
    }
    let Ok(nonce) = <[u8; 16]>::try_from(s.genesis_nonce.as_slice()) else {
        return false;
    };
    let [only] = s.members.as_slice() else {
        return false;
    };
    if only.ed25519_public_key != s.owner_key {
        return false;
    }
    derive_repo_id(&s.owner_key, &nonce).is_ok_and(|id| id == s.repo_id)
}

fn same_frontier(a: &[Id], b: &[Id]) -> bool {
    let mut x = a.to_vec();
    let mut y = b.to_vec();
    x.sort_unstable();
    y.sort_unstable();
    x == y
}

/// Whether `epoch` is `prev + 1`, without overflow.
fn is_next(prev: i64, epoch: i64) -> bool {
    prev.checked_add(1) == Some(epoch)
}

/// SPEC 6.1 rule 5: the content rules, against the previous state when `prev` is given.
fn content_ok(s: &ManifestState, prev: Option<&ManifestState>) -> bool {
    if s.hosts.is_empty() {
        return false;
    }
    if s.members.iter().filter(|x| x.ed25519_public_key == s.owner_key).count() != 1 {
        return false;
    }
    if !s
        .members
        .iter()
        .all(|x| x.key_epoch == s.key_epoch && s.has_host(&x.home_host_key))
    {
        return false;
    }
    if s.members.iter().any(|x| s.removal_of(&x.ed25519_public_key).is_some()) {
        return false;
    }
    if !s
        .removals
        .iter()
        .all(|r| r.removed_at_seq >= 2 && r.removed_at_seq <= s.manifest_seq)
    {
        return false;
    }
    let Some(prev) = prev else {
        return true;
    };

    if s.repo_id != prev.repo_id
        || s.owner_key != prev.owner_key
        || s.scheme_id != prev.scheme_id
        || !s.genesis_nonce.is_empty()
    {
        return false;
    }
    if s.key_epoch != prev.key_epoch && !is_next(prev.key_epoch, s.key_epoch) {
        return false;
    }
    for r in &prev.removals {
        match s.removal_of(&r.member_key) {
            Some(same) if same.removed_at_seq == r.removed_at_seq && same_frontier(&same.frontier, &r.frontier) => {}
            _ => return false,
        }
    }
    let added: Vec<&Id> = s
        .removals
        .iter()
        .filter(|r| prev.removal_of(&r.member_key).is_none())
        .map(|r| &r.member_key)
        .collect();
    for r in s.removals.iter().filter(|r| prev.removal_of(&r.member_key).is_none()) {
        if r.removed_at_seq != s.manifest_seq || !prev.has_member(&r.member_key) {
            return false;
        }
    }
    for x in &prev.members {
        if s.has_member(&x.ed25519_public_key) {
            continue;
        }
        if x.ed25519_public_key == s.owner_key || !added.contains(&&x.ed25519_public_key) {
            return false;
        }
    }
    if !added.is_empty() && !is_next(prev.key_epoch, s.key_epoch) {
        return false;
    }
    true
}

/// One host's view of one repository.
///
/// Construct it with the host's own Ed25519 key, apply items in arrival order, and read
/// [`RepoView::heads`], [`RepoView::held`], and [`RepoView::tip`]. Every `apply_*` method is
/// atomic: an item that is rejected changes nothing, except that a state that loses the tie rule
/// but verifies is retained as a verified losing state (SPEC 6.5) and a commit header that verifies
/// stays known for ancestry (SPEC 7.3).
///
/// Host implementers: on the [`Via::Offer`] path this engine applies no per-state hosted check, so
/// it will adopt a whole repository whose states never list this host. The host MUST therefore
/// apply an offer (with its catch-up) to a trial copy of the view (it is [`Clone`]) and check the
/// validated resulting tip with [`RepoView::tip_lists_host`] (the received tip of SPEC 9.2). If the
/// host did not hold the repository and that tip does not list it, it MUST discard the trial copy
/// and answer `403 not_hosted` (a first copy is all or nothing). If it held the repository, it MUST
/// commit the trial copy atomically and answer `403 not_hosted` when that tip does not list it
/// (SPEC 8.6). A client publish this engine answers [`RejectCode::NotHosted`] passed every other
/// rule; the host MUST keep it by applying the same item again with [`Via::Offer`]. Serving and
/// client writes are gated on [`RepoView::tip_lists_host`] (SPEC 8.6, 10.1); there is no separate
/// not-hosted marker.
#[derive(Debug, Clone)]
pub struct RepoView {
    host_key: Id,
    head_bound: usize,
    st: Store,
}

impl RepoView {
    /// A view for the host whose Ed25519 host key is `host_key`, with the head bound for client
    /// writes (SPEC 7.4, RECOMMENDED 16).
    #[must_use]
    pub fn new(host_key: [u8; 32], head_bound: usize) -> RepoView {
        RepoView {
            host_key,
            head_bound,
            st: Store::default(),
        }
    }

    // ─── Applying items ───────────────────────────────────────────────────────────────

    /// Applies a client publish of a manifest state with no commit: [`RepoView::apply_manifest_with`]
    /// with no commit and [`Via::Push`].
    ///
    /// # Errors
    ///
    /// The SPEC 6 reject code of the first rule that fails.
    pub fn apply_manifest(&mut self, m: SignedManifest) -> Result<(), RejectCode> {
        self.apply_manifest_with(m, None, Via::Push)
    }

    /// Applies a signed manifest state (SPEC 6) together with the commit published with it: the
    /// first commit at genesis (`createRepo`, SPEC 8.2), the rotation commit of an epoch-raising
    /// state (SPEC 8.3), or an optional commit that cites any other state. The state and its
    /// commit are applied together or not at all.
    ///
    /// # Errors
    ///
    /// The reject code of the first rule that fails: SPEC 6.1 in order for the state, then SPEC 7
    /// for the commit.
    pub fn apply_manifest_with(
        &mut self,
        m: SignedManifest,
        commit: Option<Commit>,
        via: Via,
    ) -> Result<(), RejectCode> {
        let snap = self.st.clone();
        match self.state(m, commit, via) {
            Ok(v) => v,
            Err(_) => {
                self.restore(snap);
                Err(RejectCode::BadRequest)
            }
        }
    }

    /// Applies a client push of one commit: [`RepoView::apply_commit_via`] with [`Via::Push`].
    ///
    /// # Errors
    ///
    /// The SPEC 7 reject code of the first rule that fails.
    pub fn apply_commit(&mut self, c: Commit) -> Result<(), RejectCode> {
        self.apply_commit_via(c, Via::Push)
    }

    /// Applies one commit (SPEC 7): a client push, or a commit of a peer's offer. A commit the
    /// view already accepted is accepted again with no change.
    ///
    /// # Errors
    ///
    /// The SPEC 7 reject code of the first rule that fails; `forbidden` for a held commit;
    /// `missing_parents` when a parent, the cited state, or a frontier header is unknown (see
    /// [`RepoView::missing_for`]).
    pub fn apply_commit_via(&mut self, c: Commit, via: Via) -> Result<(), RejectCode> {
        let snap = self.st.clone();
        match self.one_commit(c, via, false) {
            Ok(v) => v,
            Err(_) => {
                self.restore(snap);
                Err(RejectCode::BadRequest)
            }
        }
    }

    /// Applies a client's leave request: [`RepoView::apply_leave_via`] with [`Via::Push`].
    ///
    /// # Errors
    ///
    /// As [`RepoView::apply_leave_via`].
    pub fn apply_leave(&mut self, l: LeaveRequest) -> Result<(), RejectCode> {
        self.apply_leave_via(l, Via::Push)
    }

    /// Applies a signed leave request (SPEC 8.4) and keeps the latest one per member. Replication
    /// skips only the caller check, which the host makes before a push reaches the engine, so both
    /// paths apply the same rules.
    ///
    /// # Errors
    ///
    /// `bad_request` if the signature does not verify or the repoId does not match; `forbidden` if
    /// the member is not a member of the tip or is the owner.
    pub fn apply_leave_via(&mut self, l: LeaveRequest, via: Via) -> Result<(), RejectCode> {
        let _ = via;
        if l.verify().is_err() {
            return Err(RejectCode::BadRequest);
        }
        let Some(tip) = self.tip_rec() else {
            return Err(RejectCode::BadRequest);
        };
        let s = tip.state();
        if l.repo_id != s.repo_id {
            return Err(RejectCode::BadRequest);
        }
        if !s.has_member(&l.member_key) || l.member_key == s.owner_key {
            return Err(RejectCode::Forbidden);
        }
        match self.st.leaves.binary_search_by(|x| x.member_key.cmp(&l.member_key)) {
            Ok(i) => {
                if let Some(cur) = self.st.leaves.get_mut(i) {
                    if l.at > cur.at {
                        *cur = l;
                    }
                }
            }
            Err(i) => self.st.leaves.insert(i, l),
        }
        Ok(())
    }

    // ─── Reading the view ─────────────────────────────────────────────────────────────

    /// The accepted commits with no accepted child, sorted.
    #[must_use]
    pub fn heads(&self) -> Vec<[u8; 32]> {
        let mut out = self.head_ids();
        out.sort_unstable();
        out
    }

    /// The held commits (SPEC 6.5), sorted.
    #[must_use]
    pub fn held(&self) -> Vec<[u8; 32]> {
        self.with_status(CommitStatus::Held)
    }

    /// The stored commits whose removal cutoff cannot be decided yet (SPEC 7.3), sorted.
    #[must_use]
    pub fn pending(&self) -> Vec<[u8; 32]> {
        self.with_status(CommitStatus::Pending)
    }

    /// The tip of the winning chain, or `None` before genesis.
    #[must_use]
    pub fn tip(&self) -> Option<&SignedManifest> {
        self.st.chain.last().map(|r| &r.m)
    }

    /// Whether the tip of the winning chain lists this host; `false` before genesis.
    ///
    /// A host does not serve a repository whose tip does not list it (SPEC 8.6, 10.1). States
    /// before the tip may not list it when the host got its first copy by replication (SPEC 6.1
    /// rule 6, 9.2).
    #[must_use]
    pub fn tip_lists_host(&self) -> bool {
        self.st.chain.last().is_some_and(|r| r.state().has_host(&self.host_key))
    }

    /// The head commits whose ids are not in `known`, sorted by id: the `heads` of a pull
    /// (SPEC 10.1).
    #[must_use]
    pub fn commits_since(&self, known: &[[u8; 32]]) -> Vec<Commit> {
        self.heads()
            .iter()
            .filter(|id| !known.contains(id))
            .filter_map(|id| self.st.commits.get(id).map(|r| (*r.c).clone()))
            .collect()
    }

    /// The winning chain's states with `manifestSeq` greater than `seq`, ascending: the
    /// `manifests` of a pull (SPEC 10.1).
    #[must_use]
    pub fn manifests_since(&self, seq: i64) -> Vec<SignedManifest> {
        self.st
            .chain
            .iter()
            .filter(|r| r.seq > seq)
            .map(|r| r.m.clone())
            .collect()
    }

    /// The pending leave requests (SPEC 8.4), one per member, sorted by member key.
    #[must_use]
    pub fn leaves(&self) -> &[LeaveRequest] {
        &self.st.leaves
    }

    /// The status of a stored commit.
    #[must_use]
    pub fn status(&self, id: &[u8; 32]) -> Option<CommitStatus> {
        self.st.commits.get(id).map(|r| r.status)
    }

    /// A verified state, on the winning chain or a verified losing state (SPEC 6.5), by hash.
    #[must_use]
    pub fn manifest(&self, hash: &[u8; 32]) -> Option<&SignedManifest> {
        self.st.states.get(hash).map(|r| &r.m)
    }

    /// Whether the state with this hash is on the winning chain.
    #[must_use]
    pub fn is_winning(&self, hash: &[u8; 32]) -> bool {
        self.st.states.get(hash).is_some_and(|r| self.winning(r))
    }

    /// The state with this hash and every state before it on its chain, ascending by
    /// `manifestSeq`: the `manifests` of a replication `fetch` by manifest hash (SPEC 9.1).
    #[must_use]
    pub fn chain_to(&self, hash: &[u8; 32]) -> Option<Vec<SignedManifest>> {
        let mut out = Vec::new();
        let mut cur = self.st.states.get(hash)?;
        loop {
            out.push(cur.m.clone());
            if cur.seq <= 1 {
                break;
            }
            let prev = <[u8; 32]>::try_from(cur.state().prev_manifest_hash.as_slice()).ok()?;
            cur = self.st.states.get(&prev)?;
        }
        out.reverse();
        Some(out)
    }

    /// The rotation commit recorded with an epoch-raising state (SPEC 8.3), even while it is held.
    #[must_use]
    pub fn rotation_commit(&self, hash: &[u8; 32]) -> Option<&Commit> {
        let id = self.st.rotation.get(hash)?;
        self.st.commits.get(id).map(|r| &*r.c)
    }

    /// A commit a replication `fetch` serves by id (SPEC 9.1): an accepted commit, or a rotation
    /// commit whatever its status. Other held, pending, and rejected commits are not served.
    #[must_use]
    pub fn fetch_commit(&self, id: &[u8; 32]) -> Option<&Commit> {
        let r = self.st.commits.get(id)?;
        let rotation = self.st.rotation.values().any(|x| x == id);
        (r.status == CommitStatus::Accepted || rotation).then_some(&*r.c)
    }

    /// The ids a `missing_parents` answer for `c` names (SPEC 7.2, 7.3, 7.4): the cited manifest
    /// hash when the view holds no such state, each parent it does not hold, and each frontier
    /// commit whose header it lacks for the removal cutoff of `c` or of a pending parent.
    #[must_use]
    pub fn missing_for(&self, c: &Commit) -> Vec<[u8; 32]> {
        fn add(out: &mut Vec<Id>, id: Id) {
            if !out.contains(&id) {
                out.push(id);
            }
        }
        let mut out: Vec<Id> = Vec::new();
        if self
            .st
            .states
            .get(&c.manifest_hash)
            .is_none_or(|b| b.seq != c.manifest_seq)
        {
            add(&mut out, c.manifest_hash);
        }
        let tip = self.tip_rec();
        let cutoff_of = |cm: &Commit| tip.as_ref().map(|t| self.cutoff_missing(cm, t)).unwrap_or_default();
        for id in cutoff_of(c) {
            add(&mut out, id);
        }
        for p in &c.parents {
            match self.st.commits.get(p) {
                None => add(&mut out, *p),
                Some(r) if r.status == CommitStatus::Pending => {
                    for id in cutoff_of(&r.c) {
                        add(&mut out, id);
                    }
                }
                Some(_) => {}
            }
        }
        out
    }

    // ─── Store ────────────────────────────────────────────────────────────────────────

    fn restore(&mut self, snap: Store) {
        // Verified headers stay known: ancestry uses them whether or not the commit was accepted
        // (SPEC 7.3). The re-check that ran inside the failed operation was reverted with it, so
        // run it again over the restored state for any header the operation learned.
        let headers = std::mem::take(&mut self.st.headers);
        self.st = snap;
        let mut learned = false;
        for (k, parents) in headers {
            if let std::collections::hash_map::Entry::Vacant(e) = self.st.headers.entry(k) {
                e.insert(parents);
                learned = true;
            }
        }
        if learned {
            self.recheck_cutoffs();
            self.propagate();
        }
    }

    fn tip_rec(&self) -> Option<Arc<StateRec>> {
        self.st.chain.last().cloned()
    }

    fn chain_at(&self, seq: i64) -> Option<&Arc<StateRec>> {
        let i = usize::try_from(seq.checked_sub(1)?).ok()?;
        self.st.chain.get(i)
    }

    fn winning(&self, r: &StateRec) -> bool {
        self.chain_at(r.seq).is_some_and(|w| w.hash == r.hash)
    }

    fn status_of(&self, id: &Id) -> Option<CommitStatus> {
        self.st.commits.get(id).map(|r| r.status)
    }

    fn set_status(&mut self, id: &Id, status: CommitStatus) {
        if let Some(r) = self.st.commits.get_mut(id) {
            r.status = status;
        }
    }

    fn insert_commit(&mut self, c: Commit, status: CommitStatus) {
        let id = c.commit_id;
        if self
            .st
            .commits
            .insert(id, CommitRec { c: Arc::new(c), status })
            .is_none()
        {
            self.st.order.push(id);
        }
    }

    /// The stored commits in first-stored order with their status at this moment.
    fn snapshot(&self) -> Vec<(Id, CommitStatus, Arc<Commit>)> {
        self.st
            .order
            .iter()
            .filter_map(|id| self.st.commits.get(id).map(|r| (*id, r.status, Arc::clone(&r.c))))
            .collect()
    }

    fn parent_statuses(&self, c: &Commit) -> Vec<Option<CommitStatus>> {
        c.parents.iter().map(|p| self.status_of(p)).collect()
    }

    fn with_status(&self, status: CommitStatus) -> Vec<Id> {
        let mut out: Vec<Id> = self
            .st
            .commits
            .iter()
            .filter(|(_, r)| r.status == status)
            .map(|(id, _)| *id)
            .collect();
        out.sort_unstable();
        out
    }

    fn head_ids(&self) -> Vec<Id> {
        let accepted: Vec<(&Id, &CommitRec)> = self
            .st
            .commits
            .iter()
            .filter(|(_, r)| r.status == CommitStatus::Accepted)
            .collect();
        let parents: HashSet<&Id> = accepted.iter().flat_map(|(_, r)| r.c.parents.iter()).collect();
        accepted
            .iter()
            .map(|(id, _)| **id)
            .filter(|id| !parents.contains(id))
            .collect()
    }

    // ─── Manifest states (SPEC 6, 8.3) ────────────────────────────────────────────────

    fn state(&mut self, m: SignedManifest, commit: Option<Commit>, via: Via) -> Result<Verdict, AvpError> {
        // Rule 1, structure; rule 2, owner signature.
        if !manifest_shape_ok(&m) || m.verify().is_err() {
            return Ok(Err(RejectCode::BadRequest));
        }
        let hash = m.hash()?;
        let seq = m.state.manifest_seq;
        let rec = Arc::new(StateRec { m, hash, seq });
        let s = rec.state();

        if seq == 1 {
            // createRepo carries the genesis and its first commit together (SPEC 8.2); without the
            // commit the client request is malformed.
            if via == Via::Push && commit.is_none() {
                return Ok(Err(RejectCode::BadRequest));
            }
            // Rule 3, genesis.
            if !genesis_ok(s) {
                return Ok(Err(RejectCode::BadRequest));
            }
            if let Some(first) = self.st.chain.first() {
                // Host level, not an engine verdict: a host answers createRepo for a repoId it
                // already holds with 409 duplicate_repo (SPEC 8.2, 12.3) before consulting the
                // engine. The answer below is a placeholder that no acceptance.json scenario pins.
                let same = first.hash == hash;
                return Ok(if same && via == Via::Offer && commit.is_none() {
                    Ok(())
                } else {
                    Err(RejectCode::ManifestConflict)
                });
            }
            if !content_ok(s, None) {
                return Ok(Err(RejectCode::BadRequest));
            }
            // Rule 6, hosted, on a client write. By replication it applies to the tip of the chain
            // being received, which the host checks before it applies any item (SPEC 6.1, 9.2).
            if via == Via::Push && !s.has_host(&self.host_key) {
                return Ok(Err(RejectCode::NotHosted));
            }
            return self.adopt(&rec, None, commit, via);
        }

        // Rule 4, chain link.
        let Some(tip) = self.tip_rec() else {
            return Ok(Err(RejectCode::ManifestConflict));
        };
        let prev = <[u8; 32]>::try_from(s.prev_manifest_hash.as_slice())
            .ok()
            .and_then(|h| self.st.states.get(&h));
        let Some(prev) = prev.filter(|p| seq.checked_sub(1) == Some(p.seq)).cloned() else {
            return Ok(Err(RejectCode::ManifestConflict));
        };
        if let Some(known) = self.st.states.get(&hash) {
            let winning = self.winning(known);
            if winning || via == Via::Push {
                // A retry of a state already on the chain: idempotent by replication, a conflict on
                // publish (SPEC 12.3). A retained losing state offered again is evaluated again.
                return Ok(if winning && via == Via::Offer && commit.is_none() {
                    Ok(())
                } else {
                    Err(RejectCode::ManifestConflict)
                });
            }
        }
        let content = content_ok(s, Some(prev.state()));
        if via == Via::Push && prev.hash != tip.hash {
            // Still rule 4: a client publish is accepted only at tip + 1 linked to the tip (SPEC
            // 6.3), and it fails here before the content rule; the tie rule is for states that
            // arrive by replication. A state that also passes rule 5 is kept as a verified losing
            // state (SPEC 6.5).
            if content {
                self.retain_losing(&rec, &prev, commit.as_ref())?;
            }
            return Ok(Err(RejectCode::ManifestConflict));
        }
        // Rule 5, content.
        if !content {
            return Ok(Err(RejectCode::BadRequest));
        }
        if !self.winning(&prev) {
            // Extends a losing chain: verified and retained, never adopted (SPEC 6.5).
            self.retain_losing(&rec, &prev, commit.as_ref())?;
            return Ok(Err(RejectCode::ManifestConflict));
        }
        if self.chain_at(seq).is_some_and(|at| hash > at.hash) {
            // Diverged and loses the tie rule: retained as a verified losing state (SPEC 6.5).
            self.retain_losing(&rec, &prev, commit.as_ref())?;
            return Ok(Err(RejectCode::ManifestConflict));
        }
        // Appends to the tip, or wins the tie rule at its seq (lower manifestHash). Rule 6 as above.
        if via == Via::Push && !s.has_host(&self.host_key) {
            return Ok(Err(RejectCode::NotHosted));
        }
        self.adopt(&rec, Some(&prev), commit, via)
    }

    fn retain_losing(&mut self, rec: &Arc<StateRec>, prev: &StateRec, commit: Option<&Commit>) -> Result<(), AvpError> {
        self.st.states.insert(rec.hash, Arc::clone(rec));
        let raising = is_next(prev.state().key_epoch, rec.state().key_epoch);
        let Some(c) = commit else {
            return Ok(());
        };
        if !raising || !self.rotation_shape_ok(rec, c) || !self.header_ok(c) {
            return Ok(());
        }
        // The rotation commit of a losing epoch-raising state is kept with it, held (SPEC 8.3).
        let id = c.commit_id;
        if !self.st.commits.contains_key(&id) {
            self.insert_commit(c.clone(), CommitStatus::Held);
        }
        self.st.rotation.insert(rec.hash, id);
        self.record_header(c);
        Ok(())
    }

    /// Records a verified commit header. A new one can complete the ancestry an undecided cutoff
    /// was waiting for (SPEC 7.3), so every path that learns a header re-runs the cutoff re-check.
    fn record_header(&mut self, c: &Commit) {
        if self.st.headers.contains_key(&c.commit_id) {
            return;
        }
        self.st.headers.insert(c.commit_id, c.parents.clone());
        self.recheck_cutoffs();
        self.propagate();
    }

    /// SPEC 8.2 and 8.3: the commit published with a genesis or epoch-raising state.
    fn rotation_shape_ok(&self, rec: &StateRec, c: &Commit) -> bool {
        let s = rec.state();
        commit_shape_ok(c)
            && c.manifest_seq == s.manifest_seq
            && c.manifest_hash == rec.hash
            && c.key_epoch == s.key_epoch
            && c.author == s.owner_key
            && (s.manifest_seq != 1 || c.parents.is_empty())
    }

    fn cites_state(rec: &StateRec, c: &Commit) -> bool {
        commit_shape_ok(c) && c.manifest_seq == rec.seq && c.manifest_hash == rec.hash
    }

    /// Adopts a state onto the winning chain together with its commit, or changes nothing (SPEC
    /// 8.2, 8.3).
    fn adopt(
        &mut self,
        rec: &Arc<StateRec>,
        prev: Option<&StateRec>,
        commit: Option<Commit>,
        via: Via,
    ) -> Result<Verdict, AvpError> {
        let snap = self.st.clone();
        let v = self.adopt_unchecked(rec, prev, commit, via)?;
        if v.is_err() {
            self.restore(snap);
        }
        Ok(v)
    }

    fn adopt_unchecked(
        &mut self,
        rec: &Arc<StateRec>,
        prev: Option<&StateRec>,
        commit: Option<Commit>,
        via: Via,
    ) -> Result<Verdict, AvpError> {
        let s = rec.state();
        let raising = prev.is_some_and(|p| is_next(p.state().key_epoch, s.key_epoch));
        if raising && commit.is_none() {
            return Ok(Err(RejectCode::BadRequest));
        }
        if let Some(c) = &commit {
            // The genesis commit and a rotation commit have a fixed shape (SPEC 8.2, 8.3); any
            // other commit published with a state is validated as a push that cites the new state.
            let shaped = if raising || prev.is_none() {
                self.rotation_shape_ok(rec, c)
            } else {
                Self::cites_state(rec, c)
            };
            if !shaped {
                return Ok(Err(RejectCode::BadRequest));
            }
        }

        // The state at `seq` goes at `chain[seq - 1]`; its predecessor is on the chain, so the chain
        // already holds at least `seq - 1` states.
        let index = rec.seq.checked_sub(1).and_then(|i| usize::try_from(i).ok());
        let Some(index) = index.filter(|i| *i <= self.st.chain.len()) else {
            return Ok(Err(RejectCode::BadRequest));
        };
        let switching = self.st.chain.len() > index;
        self.st.states.insert(rec.hash, Arc::clone(rec));
        self.st.chain.truncate(index);
        self.st.chain.push(Arc::clone(rec));

        if switching {
            self.recheck_accepted(rec.seq);
        }
        self.recheck_cutoffs();
        for r in &s.removals {
            self.st.leaves.retain(|l| l.member_key != r.member_key);
        }
        self.recheck_held();
        self.propagate();

        if let Some(c) = commit {
            let id = c.commit_id;
            let v = self.one_commit(c, via, true)?;
            if v.is_err() {
                return Ok(v);
            }
            if raising {
                self.st.rotation.insert(rec.hash, id);
            }
        }
        Ok(Ok(()))
    }

    // ─── Commits (SPEC 7, 6.5) ────────────────────────────────────────────────────────

    /// SPEC 7.1: the id recomputes and the author signature verifies.
    fn header_ok(&self, c: &Commit) -> bool {
        c.verify().is_ok()
    }

    fn one_commit(&mut self, c: Commit, via: Via, carried: bool) -> Result<Verdict, AvpError> {
        if !commit_shape_ok(&c) {
            return Ok(Err(RejectCode::BadRequest));
        }
        // Host level, not an engine verdict: a host answers 404 not_found for a repository it does
        // not hold (SPEC 10.1) before consulting the engine. The answer below is a placeholder that
        // no acceptance.json scenario pins.
        let Some(tip) = self.tip_rec() else {
            return Ok(Err(RejectCode::MissingParents));
        };
        if c.repo_id != tip.state().repo_id || !self.header_ok(&c) {
            return Ok(Err(RejectCode::BadRequest));
        }
        let id = c.commit_id;
        self.record_header(&c);

        // Caller check on the client routes: the caller is the author (the owner for a carried
        // commit) and is a member of the tip.
        if via == Via::Push {
            if carried && c.author != tip.state().owner_key {
                return Ok(Err(RejectCode::Forbidden));
            }
            if !tip.state().has_member(&c.author) {
                return Ok(Err(RejectCode::Forbidden));
            }
        }

        if let Some(existing) = self.status_of(&id) {
            return Ok(match existing {
                CommitStatus::Accepted => Ok(()),
                // Undecided cutoff: retryable once the missing frontier commit arrives (SPEC 7.3).
                CommitStatus::Pending => Err(RejectCode::MissingParents),
                CommitStatus::Held | CommitStatus::Rejected => Err(RejectCode::Forbidden),
            });
        }

        Ok(match self.classify(&c, via == Via::Push) {
            Classification::Error(code) => Err(code),
            Classification::Rejected => {
                self.insert_commit(c, CommitStatus::Rejected);
                Err(RejectCode::Forbidden)
            }
            Classification::Held => {
                self.insert_commit(c, CommitStatus::Held);
                Err(RejectCode::Forbidden)
            }
            Classification::Accepted => {
                self.insert_commit(c, CommitStatus::Accepted);
                Ok(())
            }
        })
    }

    /// SPEC 7.2 to 7.4 (and 6.5 for a commit citing a losing state).
    fn classify(&self, c: &Commit, apply_bound: bool) -> Classification {
        let Some(tip) = self.tip_rec() else {
            return Classification::Error(RejectCode::MissingParents);
        };
        // 7.2 manifest binding: the (seq, hash) pair must name a verified state this host holds.
        let Some(bound) = self.st.states.get(&c.manifest_hash).filter(|b| b.seq == c.manifest_seq) else {
            return Classification::Error(RejectCode::MissingParents);
        };

        let mut held = false;
        if self.winning(bound) {
            if !bound.state().has_member(&c.author) || c.key_epoch != bound.state().key_epoch {
                return Classification::Rejected;
            }
            match self.cutoff(c, &tip) {
                Cut::Fail => return Classification::Rejected,
                Cut::Undecided => return Classification::Error(RejectCode::MissingParents),
                Cut::Ok => {}
            }
        } else {
            match self.losing_verdict(c, &tip) {
                Losing::Undecided => return Classification::Error(RejectCode::MissingParents),
                Losing::Rejected => return Classification::Rejected,
                Losing::Held => held = true,
                Losing::Accepted => {}
            }
        }

        // 7.4 parents.
        let parents = self.parent_statuses(c);
        if parents.contains(&Some(CommitStatus::Rejected)) {
            return Classification::Rejected;
        }
        // A pending parent is not accepted and is waiting on a missing frontier commit: retryable.
        if parents.iter().any(|p| matches!(p, None | Some(CommitStatus::Pending))) {
            return Classification::Error(RejectCode::MissingParents);
        }
        if parents.contains(&Some(CommitStatus::Held)) {
            held = true;
        }

        if held {
            return Classification::Held;
        }
        if apply_bound {
            let heads: HashSet<Id> = self.head_ids().into_iter().collect();
            let named = c.parents.iter().filter(|p| heads.contains(*p)).count();
            if heads.len().saturating_sub(named).saturating_add(1) > self.head_bound {
                return Classification::Error(RejectCode::TooManyHeads);
            }
        }
        Classification::Accepted
    }

    /// SPEC 6.5: a commit citing a verified losing state, re-checked against the winning chain.
    /// The removal cutoff takes precedence; then accept if the winning state at that seq lists the
    /// author at the commit's epoch; then the drop test; otherwise held.
    fn losing_verdict(&self, c: &Commit, tip: &StateRec) -> Losing {
        match self.cutoff(c, tip) {
            Cut::Fail => return Losing::Rejected,
            Cut::Undecided => return Losing::Undecided,
            Cut::Ok => {}
        }
        if let Some(w) = self.chain_at(c.manifest_seq) {
            if w.state().has_member(&c.author) && w.state().key_epoch == c.key_epoch {
                return Losing::Accepted;
            }
        }
        if self.drop_test(c, tip) {
            return Losing::Rejected;
        }
        Losing::Held
    }

    /// SPEC 6.5 drop test: the tip's epoch passed the commit's, or the author was removed and the
    /// commit is not covered by the frontier. A cutoff that cannot be decided yet is not a drop
    /// (SPEC 7.3 says only that the host MUST NOT accept such a commit).
    fn drop_test(&self, c: &Commit, tip: &StateRec) -> bool {
        tip.state().key_epoch > c.key_epoch || self.cutoff(c, tip) == Cut::Fail
    }

    /// Walks the removal cutoff of `c` against the tip's removals (SPEC 7.3): a commit by a
    /// removed author is valid only if its id is in the frontier or it is an ancestor of a frontier
    /// commit, ancestry following the parents of every verified header. Returns whether `c` is
    /// covered and the ids on the way whose headers are unknown.
    fn cutoff_walk(&self, c: &Commit, tip: &StateRec) -> (bool, Vec<Id>) {
        let Some(r) = tip.state().removal_of(&c.author) else {
            return (true, Vec::new());
        };
        let target = c.commit_id;
        if r.frontier.contains(&target) {
            return (true, Vec::new());
        }
        let mut stack: Vec<Id> = r.frontier.clone();
        let mut seen: HashSet<Id> = stack.iter().copied().collect();
        let mut unknown = Vec::new();
        while let Some(h) = stack.pop() {
            let Some(parents) = self.st.headers.get(&h) else {
                unknown.push(h);
                continue;
            };
            for p in parents {
                if *p == target {
                    return (true, Vec::new());
                }
                if seen.insert(*p) {
                    stack.push(*p);
                }
            }
        }
        (false, unknown)
    }

    fn cutoff(&self, c: &Commit, tip: &StateRec) -> Cut {
        match self.cutoff_walk(c, tip) {
            (true, _) => Cut::Ok,
            (false, unknown) if unknown.is_empty() => Cut::Fail,
            (false, _) => Cut::Undecided,
        }
    }

    fn cutoff_missing(&self, c: &Commit, tip: &StateRec) -> Vec<Id> {
        self.cutoff_walk(c, tip).1
    }

    fn cutoff_ok(&self, c: &Commit) -> bool {
        self.tip_rec().is_some_and(|tip| self.cutoff(c, &tip) == Cut::Ok)
    }

    // ─── Re-checks after a new winning state or a new header ──────────────────────────

    /// SPEC 6.5: after a switch, every accepted commit citing a state from the fork point on.
    fn recheck_accepted(&mut self, fork_seq: i64) {
        let Some(tip) = self.tip_rec() else {
            return;
        };
        for (id, status, c) in self.snapshot() {
            if status != CommitStatus::Accepted || c.manifest_seq < fork_seq {
                continue;
            }
            let Some(bound) = self.st.states.get(&c.manifest_hash) else {
                continue;
            };
            if self.winning(bound) {
                continue;
            }
            match self.losing_verdict(&c, &tip) {
                Losing::Rejected => self.set_status(&id, CommitStatus::Rejected),
                Losing::Held => self.set_status(&id, CommitStatus::Held),
                Losing::Undecided => self.set_status(&id, CommitStatus::Pending),
                Losing::Accepted => {}
            }
        }
    }

    /// SPEC 7.3, run on each new winning state and each new verified header: every stored commit
    /// by a removed member is checked against the tip's cutoff. One that fails is dropped; an
    /// accepted one that cannot be decided leaves the heads as pending; a pending one that is now
    /// covered is decided again. A held commit stays held unless it fails.
    fn recheck_cutoffs(&mut self) {
        let Some(tip) = self.tip_rec() else {
            return;
        };
        for (id, status, c) in self.snapshot() {
            if status == CommitStatus::Rejected {
                continue;
            }
            match self.cutoff(&c, &tip) {
                Cut::Fail => self.set_status(&id, CommitStatus::Rejected),
                Cut::Undecided if status == CommitStatus::Accepted => self.set_status(&id, CommitStatus::Pending),
                Cut::Ok if status == CommitStatus::Pending => {
                    let next = self.decide_pending(&c);
                    self.set_status(&id, next);
                }
                _ => {}
            }
        }
    }

    /// The status of a pending commit whose own cutoff is now decided as covered. A commit citing
    /// a verified losing state goes through the rest of the SPEC 6.5 re-check (winning state at
    /// its seq, drop test, hold), as at its first classification; then its parents decide as in
    /// SPEC 7.4.
    fn decide_pending(&self, c: &Commit) -> CommitStatus {
        let Some(tip) = self.tip_rec() else {
            return CommitStatus::Pending;
        };
        let mut status = CommitStatus::Accepted;
        if let Some(bound) = self.st.states.get(&c.manifest_hash) {
            if !self.winning(bound) {
                match self.losing_verdict(c, &tip) {
                    Losing::Undecided => return CommitStatus::Pending,
                    Losing::Rejected => return CommitStatus::Rejected,
                    Losing::Held => status = CommitStatus::Held,
                    Losing::Accepted => {}
                }
            }
        }
        let parents = self.parent_statuses(c);
        if parents.contains(&Some(CommitStatus::Rejected)) {
            return CommitStatus::Rejected;
        }
        if parents.iter().any(|p| matches!(p, None | Some(CommitStatus::Pending))) {
            return CommitStatus::Pending;
        }
        if parents.contains(&Some(CommitStatus::Held)) {
            return CommitStatus::Held;
        }
        status
    }

    /// SPEC 6.5 deciding a held commit, against the new tip: dropped if it meets the drop test,
    /// accepted if the tip lists its author at its epoch, held otherwise. A held descendant waits
    /// for its held ancestors and is then re-checked in turn.
    fn recheck_held(&mut self) {
        let Some(tip) = self.tip_rec() else {
            return;
        };
        loop {
            let mut changed = false;
            self.propagate();
            for (id, status, c) in self.snapshot() {
                if status != CommitStatus::Held {
                    continue;
                }
                if self
                    .parent_statuses(&c)
                    .iter()
                    .any(|p| *p != Some(CommitStatus::Accepted))
                {
                    continue;
                }
                if self.drop_test(&c, &tip) {
                    self.set_status(&id, CommitStatus::Rejected);
                    changed = true;
                } else if self.cutoff(&c, &tip) == Cut::Ok
                    && tip.state().has_member(&c.author)
                    && tip.state().key_epoch == c.key_epoch
                {
                    self.set_status(&id, CommitStatus::Accepted);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }

    /// A commit with a rejected parent is rejected; an accepted commit with a held parent is held,
    /// and one with a pending parent is pending; a pending commit whose parents are decided is
    /// decided again.
    fn propagate(&mut self) {
        loop {
            let mut changed = false;
            for (id, status, c) in self.snapshot() {
                if status == CommitStatus::Rejected {
                    continue;
                }
                let parents = self.parent_statuses(&c);
                if parents.contains(&Some(CommitStatus::Rejected)) {
                    self.set_status(&id, CommitStatus::Rejected);
                    changed = true;
                } else if status == CommitStatus::Accepted && parents.contains(&Some(CommitStatus::Held)) {
                    self.set_status(&id, CommitStatus::Held);
                    changed = true;
                } else if status == CommitStatus::Accepted && parents.contains(&Some(CommitStatus::Pending)) {
                    self.set_status(&id, CommitStatus::Pending);
                    changed = true;
                } else if status == CommitStatus::Pending
                    && !parents.contains(&Some(CommitStatus::Pending))
                    && self.cutoff_ok(&c)
                {
                    // Waiting only on its parent: decided again, with the full re-check, once the
                    // parent is.
                    let next = self.decide_pending(&c);
                    if next != CommitStatus::Pending {
                        self.set_status(&id, next);
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }
    }
}
