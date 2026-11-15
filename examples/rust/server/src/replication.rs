// SPDX-License-Identifier: MIT

//! Host-to-host replication (SPEC 9) over the reference signed HTTP/JSON profile (SPEC 9.3).
//!
//! - [`Peers`] is the static peer list from `AVP_PEERS`. Only these keys may call the host routes,
//!   and every host request carries `AVP-Host-Key`, `AVP-Host-Time`, and `AVP-Host-Signature`, an
//!   Ed25519 signature over [`request_message`]. The receiver checks it over the exact path and body
//!   bytes it received and allows 60 seconds of clock skew ([`MAX_SKEW_MS`]).
//! - [`run`] starts one worker thread per peer, so a dead or slow peer delays only its own worker.
//!   A worker offers each accepted client write in the [`Outbox`] to its peer when the repository's
//!   tip lists both hosts, catches up from the peer when an offer from it was incomplete, and sweeps
//!   every held repository whose winning tip lists the peer at startup and every
//!   [`Config::sweep_interval`] (`heads`, then `fetch` for what this host lacks, SPEC 9.2). A peer
//!   that is not listed gets no request for the repository at all (SPEC 9.3).
//! - Every item a peer sends, by `offer` or in a `fetch` answer, goes through the engine with
//!   [`Via::Offer`] on a trial copy of the repository's view (SPEC 9: validated whatever the
//!   transport). The validated received tip then decides what is kept (SPEC 6.1 rule 6, 8.6, 9.2):
//!   a first copy is stored only if its tip lists this host and the sender; a held repository keeps
//!   the validated states even when the received tip drops this host, which then stops serving it.
//!
//! The state lock is never held across an outbound call: a worker reads what to send under the
//! lock, releases it, calls the peer with a timeout and a response size limit, and applies the
//! answer under the lock again. Peer answers are untrusted input: their size, list lengths, and the
//! number of catch-up rounds are bounded.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use avp::commit::Commit;
use avp::crypto::{ed25519_verify, sha256};
use avp::encoding::{Ce, b64_array, b64_decode_array, b64_encode, b64_ids};
use avp::manifest::SignedManifest;
use avp::rules::{CommitStatus, RepoView, Via};
use avp::tokens::LeaveRequest;
use avp::{AvpError, RejectCode};
use ed25519_dalek::{Signer, SigningKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use ureq::Agent;

use crate::State;

/// A commit id or manifest hash.
type Id = [u8; 32];

/// The domain tag of the host request signature (SPEC 9.3).
pub const HOST_REQ_TAG: &str = "avp/host-req/v1";

/// The largest allowed difference between `AVP-Host-Time` and the receiver's clock (SPEC 9.3).
pub const MAX_SKEW_MS: i64 = 60_000;

/// The header carrying the sender's host key, base64.
pub const HEADER_KEY: &str = "AVP-Host-Key";

/// The header carrying the sender's time in epoch milliseconds, decimal.
pub const HEADER_TIME: &str = "AVP-Host-Time";

/// The header carrying the request signature, base64.
pub const HEADER_SIGNATURE: &str = "AVP-Host-Signature";

/// Most entries kept in the outbox; the oldest is dropped beyond it (the sweep repairs the gap).
const OUTBOX_CAP: usize = 1024;

/// Most catch-up requests queued for all peers.
const CATCHUP_CAP: usize = 1024;

/// Most items in one list of an offer or a fetch answer, and most ids in a heads answer or a fetch.
pub(crate) const MAX_ITEMS: usize = 4096;

/// Most `fetch` rounds of one catch-up (each round fetches what the last one named as missing).
const MAX_ROUNDS: usize = 64;

/// Most ids one catch-up requests in all.
const MAX_REQUESTED: usize = 4096;

// ─── Configuration ──────────────────────────────────────────────────────────────────────

/// One peer host from `AVP_PEERS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    /// The peer's Ed25519 host key.
    pub key: [u8; 32],
    /// The peer's base URL, `http://...`, without a trailing `/`.
    pub url: String,
}

/// The static peer list (SPEC 9.3): the only host keys that may call the host routes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Peers {
    list: Vec<Peer>,
}

impl Peers {
    /// Parses `AVP_PEERS`: a comma-separated list of `<base64 hostKey>@<http base url>`.
    ///
    /// Blank text gives an empty list. Spaces around entries are ignored and a trailing `/` of the
    /// URL is dropped.
    ///
    /// # Errors
    ///
    /// [`AvpError::BadEncoding`] naming the entry if it has no `@`, the key is not 32 bytes of
    /// standard base64, the URL is not a plain `http://` URL with a host (this profile has no TLS)
    /// or contains whitespace, a query, or a fragment, or a key appears twice.
    pub fn from_env(text: &str) -> Result<Peers, AvpError> {
        let mut list: Vec<Peer> = Vec::new();
        for (n, entry) in text.split(',').map(str::trim).enumerate() {
            if entry.is_empty() {
                continue;
            }
            let bad = |why: &str| AvpError::BadEncoding(format!("AVP_PEERS entry {}: {why}", n + 1));
            let (key, url) = entry
                .split_once('@')
                .ok_or_else(|| bad("expected <base64 hostKey>@<url>"))?;
            let key = b64_decode_array::<32>(key.trim()).map_err(|_| bad("host key is not 32 bytes of base64"))?;
            let url = url.trim().trim_end_matches('/');
            let rest = url
                .strip_prefix("http://")
                .ok_or_else(|| bad("url must start with http://"))?;
            if rest.is_empty() || rest.starts_with('/') {
                return Err(bad("url has no host"));
            }
            if url.chars().any(|c| c.is_whitespace() || c == '?' || c == '#') {
                return Err(bad("url contains whitespace, a query, or a fragment"));
            }
            if list.iter().any(|p| p.key == key) {
                return Err(bad("host key appears twice"));
            }
            list.push(Peer {
                key,
                url: url.to_string(),
            });
        }
        Ok(Peers { list })
    }

    /// The number of peers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.list.len()
    }

    /// Whether the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Whether `key` is a peer.
    #[must_use]
    pub fn contains(&self, key: &[u8; 32]) -> bool {
        self.list.iter().any(|p| p.key == *key)
    }

    /// The peers in configuration order.
    pub fn iter(&self) -> impl Iterator<Item = &Peer> {
        self.list.iter()
    }
}

/// Replication settings. The binary uses [`Config::default`]; tests shorten the intervals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// How often each peer is swept (`heads`, then `fetch`). SPEC 9.3: every 5 seconds.
    pub sweep_interval: Duration,
    /// The whole-request timeout of an outbound host call, connection included.
    pub request_timeout: Duration,
    /// The largest peer response body read; a larger one is dropped unparsed.
    pub max_response_bytes: u64,
    /// Whether `POST /v1/test/replication` exists (`AVP_TEST_CONTROL=1`). Never on in production.
    pub test_control: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            sweep_interval: Duration::from_secs(5),
            request_timeout: Duration::from_secs(10),
            max_response_bytes: 16 * 1024 * 1024,
            test_control: false,
        }
    }
}

// ─── Shared runtime state (inside `State`, under its lock) ──────────────────────────────

/// Counters of the work replication did, so tests can bound it without timing it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Stats {
    /// Engine applications (`apply_manifest_with`, `apply_commit_via`) of received items, each of
    /// which verifies signatures and copies the repository view.
    pub engine_applications: u64,
}

/// What the request handlers and the peer workers share under the state lock.
#[derive(Debug, Default)]
pub(crate) struct Runtime {
    /// The peer list the host routes authenticate against.
    pub(crate) peers: Peers,
    /// Set by the test control route: no outbound host traffic, inbound host routes answer `503`.
    pub(crate) paused: bool,
    /// Bumped when replication is unpaused, so every worker sweeps at once.
    pub(crate) kick: u64,
    /// `(peer key, repoId)` pairs to catch up from, queued by incomplete offers.
    pub(crate) catchups: VecDeque<(Id, String)>,
    /// Wakes the workers; it waits on the state mutex.
    pub(crate) wake: Arc<Condvar>,
}

/// One accepted write to offer to the repository's other hosts (SPEC 9.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    /// The repository.
    pub repo_id: String,
    /// Manifest states (an epoch-raising state travels with its rotation commit in `commits`).
    pub manifests: Vec<SignedManifest>,
    /// Commits.
    pub commits: Vec<Commit>,
    /// Leave requests.
    pub leaves: Vec<LeaveRequest>,
}

/// The accepted client writes waiting to be offered, numbered so each peer worker keeps its own
/// cursor. Bounded: beyond [`OUTBOX_CAP`] entries the oldest is dropped, and the periodic sweep
/// brings a peer that missed it up to date.
#[derive(Debug, Clone, Default)]
pub struct Outbox {
    next: u64,
    items: VecDeque<(u64, Outgoing)>,
}

impl Outbox {
    /// Queues one write. A worker offers it to its peer if, when it sends, the repository's tip
    /// lists both this host and that peer.
    pub fn push(&mut self, item: Outgoing) {
        self.next = self.next.saturating_add(1);
        self.items.push_back((self.next, item));
        while self.items.len() > OUTBOX_CAP {
            self.items.pop_front();
        }
    }

    /// The queued writes, oldest first.
    pub fn entries(&self) -> impl Iterator<Item = &Outgoing> {
        self.items.iter().map(|(_, o)| o)
    }

    /// The entries after `cursor`, with the number of the last one.
    fn after(&self, cursor: u64) -> (Vec<Outgoing>, u64) {
        let mut last = cursor;
        let mut out = Vec::new();
        for (n, item) in self.items.iter().filter(|(n, _)| *n > cursor) {
            last = *n;
            out.push(item.clone());
        }
        (out, last)
    }
}

/// Queues an accepted client write for the peers and wakes the workers.
pub(crate) fn queue_offer(st: &mut State, item: Outgoing) {
    st.store.outbox.push(item);
    st.repl.wake.notify_all();
}

/// Queues a catch-up of `repo_id` from `peer` and wakes the workers.
pub(crate) fn queue_catchup(st: &mut State, peer: Id, repo_id: &str) {
    let q = &mut st.repl.catchups;
    if q.iter().any(|(p, r)| *p == peer && r == repo_id) {
        return;
    }
    if q.len() >= CATCHUP_CAP {
        q.pop_front();
    }
    q.push_back((peer, repo_id.to_string()));
    st.repl.wake.notify_all();
}

// ─── Host request signature (SPEC 9.3) ──────────────────────────────────────────────────

/// The signed message of a host request:
/// `CE(tag "avp/host-req/v1", str(method), str(path), bytes(SHA-256(body)), i64(time))`.
///
/// # Errors
///
/// Not reachable for in-memory requests; the CE writer is fallible in general.
pub fn request_message(method: &str, path: &str, body: &[u8], time: i64) -> Result<Vec<u8>, AvpError> {
    let mut w = Ce::new(HOST_REQ_TAG);
    w.str(method).str(path).bytes(&sha256(body)).i64(time);
    w.finish()
}

/// The three host headers of an incoming request, as received.
#[derive(Debug, Clone, Default)]
pub(crate) struct HostHeaders {
    pub(crate) key: Option<String>,
    pub(crate) time: Option<String>,
    pub(crate) signature: Option<String>,
}

/// `AVP-Host-Time` as SPEC 9.3 states it: decimal digits with an optional leading `-`, nothing
/// else (no `+`, no spaces, no other base).
fn decimal(text: &str) -> Option<i64> {
    let digits = text.strip_prefix('-').unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// The sender's key if the request is from a configured peer, is signed over exactly this method,
/// path, and body, and is within the skew window; `None` (answered `401`) otherwise.
pub(crate) fn authenticate(st: &State, method: &str, path: &str, body: &[u8], h: &HostHeaders) -> Option<Id> {
    let key = b64_decode_array::<32>(h.key.as_deref()?).ok()?;
    let time = decimal(h.time.as_deref()?)?;
    let signature = b64_decode_array::<64>(h.signature.as_deref()?).ok()?;
    if !st.repl.peers.contains(&key) {
        return None;
    }
    if st.now_ms().abs_diff(time) > MAX_SKEW_MS.unsigned_abs() {
        return None;
    }
    let message = request_message(method, path, body, time).ok()?;
    ed25519_verify(&key, &message, &signature).ok()?;
    Some(key)
}

// ─── Wire bodies of the host routes (schema/avp.schema.json) ────────────────────────────

/// `HeadsRequest`. SPEC 9.3 gives the body as `{}`; the schema lists `repoId`. Both are accepted.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HeadsBody {
    #[serde(rename = "repoId", default, skip_serializing_if = "Option::is_none")]
    pub(crate) repo_id: Option<String>,
}

/// `ManifestTip`.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ManifestTip {
    #[serde(rename = "manifestSeq")]
    pub(crate) seq: i64,
    #[serde(rename = "manifestHash", with = "b64_array")]
    pub(crate) hash: Id,
}

/// `HeadsResponse`. Peer answers are decoded tolerantly: a field this host does not know is ignored,
/// while every item still goes through the engine. Requests this host receives stay strict.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct HeadsReply {
    #[serde(rename = "manifestTip")]
    pub(crate) tip: ManifestTip,
    #[serde(with = "b64_ids")]
    pub(crate) heads: Vec<Id>,
}

/// `FetchRequest`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FetchBody {
    #[serde(rename = "repoId", default, skip_serializing_if = "Option::is_none")]
    pub(crate) repo_id: Option<String>,
    #[serde(with = "b64_ids")]
    pub(crate) ids: Vec<Id>,
}

/// `FetchResponse` (decoded tolerantly, like every peer answer), and the item lists of
/// `OfferRequest` (whose strict body type is [`OfferBody`]).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct Items {
    pub(crate) manifests: Vec<SignedManifest>,
    pub(crate) commits: Vec<Commit>,
    pub(crate) leaves: Vec<LeaveRequest>,
}

impl Items {
    /// Whether every list is within [`MAX_ITEMS`].
    pub(crate) fn bounded(&self) -> bool {
        self.manifests.len() <= MAX_ITEMS && self.commits.len() <= MAX_ITEMS && self.leaves.len() <= MAX_ITEMS
    }
}

/// `OfferRequest`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OfferBody {
    #[serde(rename = "repoId", default, skip_serializing_if = "Option::is_none")]
    pub(crate) repo_id: Option<String>,
    pub(crate) manifests: Vec<SignedManifest>,
    pub(crate) commits: Vec<Commit>,
    pub(crate) leaves: Vec<LeaveRequest>,
}

/// `RejectedItem`.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RejectedItem {
    #[serde(with = "b64_array")]
    pub(crate) id: Id,
    pub(crate) code: String,
}

/// `OfferResponse`.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct OfferReply {
    #[serde(with = "b64_ids")]
    pub(crate) accepted: Vec<Id>,
    pub(crate) rejected: Vec<RejectedItem>,
}

// ─── Applying received items (SPEC 9.1, 9.2) ────────────────────────────────────────────

/// The per-item outcome of applying received items to a view.
#[derive(Debug, Default)]
pub(crate) struct Applied {
    /// Manifest hashes and commit ids the engine accepted.
    pub(crate) accepted: Vec<Id>,
    /// Ids the engine rejected, with the code it would give a client.
    pub(crate) rejected: Vec<(Id, RejectCode)>,
    /// States not applied yet: their previous state is unknown (a gap in the chain), or they raise
    /// the epoch and their rotation commit still misses a parent, a cited state, or a frontier
    /// header. A catch-up carries them into its next round.
    pub(crate) deferred: Vec<SignedManifest>,
    /// Commits not applied yet for the same reasons, rotation commits of deferred states included.
    pub(crate) waiting: Vec<Commit>,
    /// Whether the sender may hold what this host lacks (`missing_parents` or `manifest_conflict`).
    pub(crate) incomplete: bool,
    /// The engine applications this took.
    pub(crate) applications: u64,
    /// Whether the engine-work budget ran out with items still to try.
    pub(crate) exhausted: bool,
}

impl Applied {
    fn reject(&mut self, id: Id, code: RejectCode) {
        if matches!(code, RejectCode::MissingParents | RejectCode::ManifestConflict) {
            self.incomplete = true;
        }
        self.rejected.push((id, code));
    }

    /// Whether some state could not be placed on a chain yet: the received tip is not known.
    pub(crate) fn has_gap(&self) -> bool {
        !self.deferred.is_empty()
    }

    /// The `OfferResponse` body.
    pub(crate) fn reply(&self) -> OfferReply {
        OfferReply {
            accepted: self.accepted.clone(),
            rejected: self
                .rejected
                .iter()
                .map(|(id, code)| RejectedItem {
                    id: *id,
                    code: code.as_str().to_string(),
                })
                .collect(),
        }
    }
}

/// The `keyEpoch` of the state `m` links to, if the view holds it.
fn prev_epoch(view: &RepoView, m: &SignedManifest) -> Option<i64> {
    let prev = <[u8; 32]>::try_from(m.state.prev_manifest_hash.as_slice()).ok()?;
    view.manifest(&prev).map(|p| p.state.key_epoch)
}

/// Whether `c` has the shape of the rotation commit of the state `m` whose hash is `hash` (SPEC
/// 8.3): it cites that state and its epoch and is authored by the owner. The engine checks the rest.
fn is_rotation_for(c: &Commit, m: &SignedManifest, hash: &Id) -> bool {
    c.manifest_hash == *hash
        && c.manifest_seq == m.state.manifest_seq
        && c.author == m.state.owner_key
        && c.key_epoch == m.state.key_epoch
}

/// A received state with its hash.
struct Pending {
    hash: Id,
    m: SignedManifest,
}

/// The most engine applications one [`apply_items`] call may make for `items` received items. An
/// honest batch in any order needs about two per item (one attempt, and one retry when its last
/// dependency lands); what is left when the budget runs out is reported and carried into the next
/// catch-up round.
fn budget(items: usize) -> u64 {
    u64::try_from(items)
        .unwrap_or(u64::MAX)
        .saturating_mul(3)
        .saturating_add(64)
}

/// The most rotation-commit candidates tried for one epoch-raising state.
const MAX_CANDIDATES: usize = 8;

/// One received item in the worklist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Task {
    State(usize),
    Commit(usize),
}

/// The worklist of [`apply_items`]: what to try next, and who waits on which id.
struct Worklist {
    queue: VecDeque<Task>,
    queued: HashSet<Task>,
    waiters: HashMap<Id, Vec<Task>>,
}

impl Worklist {
    fn push(&mut self, w: Task) {
        if self.queued.insert(w) {
            self.queue.push_back(w);
        }
    }

    fn pop(&mut self) -> Option<Task> {
        let w = self.queue.pop_front()?;
        self.queued.remove(&w);
        Some(w)
    }

    /// `w` is retried when an item with one of `ids` settles.
    fn wait(&mut self, w: Task, ids: impl IntoIterator<Item = Id>) {
        for id in ids {
            self.waiters.entry(id).or_default().push(w);
        }
    }

    /// The item with `id` settled (accepted, rejected, held, or a state adopted or retained): every
    /// item waiting on it is tried again. A header that a try records without the commit settling
    /// is not a reason to retry: such a commit is not kept, and neither is its header
    /// ([`apply_kept`]), so it cannot change what is stored.
    fn wake(&mut self, id: &Id) {
        for w in self.waiters.remove(id).unwrap_or_default() {
            self.push(w);
        }
    }
}

/// Applies received items to `view` with [`Via::Offer`] in the dependency order of SPEC 9.1,
/// whatever order the sender used: "a commit after the state it cites and after its parents", each
/// epoch-raising state with its rotation commit as one atomic pair, leave requests last (a failing
/// one is dropped).
///
/// Every item is tried once (states by ascending `manifestSeq`, then commits parents first). One
/// that cannot apply yet waits on the ids it misses (the previous state of a state; the rotation
/// commit's missing parents for a pair; for a commit, what [`RepoView::missing_for`] names) and is
/// tried again only when an item with one of those ids settles. The engine work is
/// therefore linear in the items, and it is also capped by [`budget`]. A commit that can never
/// apply in this batch (a parent or cited state neither held nor offered, a cited state behind a
/// gap nothing here fills or waiting for a rotation commit that cannot apply here, or a
/// descendant of such a commit) is not tried at all. An epoch-raising state tries each commit shaped like its
/// rotation commit (only verified ones, at most [`MAX_CANDIDATES`], those whose parents are all
/// accepted first) until one pairs with it, so a decoy (one with a missing or rejected parent, or a bad signature) does
/// not block the pair; the state settles with a candidate's error only when no candidate pairs and
/// none still waits on a missing item.
///
/// What is left is reported (`missing_parents` for a waiting pair and commit, `manifest_conflict`
/// for a state with an unknown previous state) and returned in [`Applied::deferred`] and
/// [`Applied::waiting`]. `cap` lowers the budget further (a catch-up passes what its own budget has
/// left). With `states_only`, only states and their rotation commits are applied.
/// Every item is validated by the engine; nothing here trusts the sender.
pub(crate) fn apply_items(view: &mut RepoView, repo_id: &str, items: Items, states_only: bool, cap: u64) -> Applied {
    let mut out = Applied::default();
    let Items {
        manifests,
        commits,
        leaves,
    } = items;
    let mut seen: HashSet<Id> = HashSet::new();
    let mut states: Vec<Pending> = Vec::new();
    for m in manifests {
        let Ok(hash) = m.hash() else {
            // A state whose canonical bytes cannot be built has no id to report; it is dropped.
            continue;
        };
        if !seen.insert(hash) {
            continue;
        }
        if m.state.repo_id != repo_id {
            out.reject(hash, RejectCode::BadRequest);
            continue;
        }
        states.push(Pending { hash, m });
    }
    states.sort_by_key(|p| p.m.state.manifest_seq);
    let commits = parents_first(commits);
    let limit = budget(states.len().saturating_add(commits.len())).min(cap);

    let state_at: HashMap<Id, usize> = states.iter().enumerate().map(|(i, p)| (p.hash, i)).collect();
    let commit_at: HashMap<Id, usize> = commits.iter().enumerate().map(|(i, c)| (c.commit_id, i)).collect();

    // Rotation-commit candidates of each state, and the state a candidate is reserved for. A
    // candidate must verify (id and owner signature): only the owner can make one, so a listed peer
    // cannot fill the cut with decoys. Before the cut, candidates whose parents are all accepted come
    // first, then those whose parents are all held or offered, then the rest; the sender's order
    // decides only among equals.
    let mut candidates: Vec<Vec<usize>> = vec![Vec::new(); states.len()];
    let mut reserved: Vec<Option<usize>> = vec![None; commits.len()];
    for (ci, c) in commits.iter().enumerate() {
        if let Some(&si) = state_at.get(&c.manifest_hash) {
            if let (Some(p), Some(list)) = (states.get(si), candidates.get_mut(si)) {
                // Only a state after the genesis with a raised epoch can have a rotation commit.
                let may_raise = p.m.state.manifest_seq > 1 && p.m.state.key_epoch > 0;
                if may_raise && is_rotation_for(c, &p.m, &p.hash) && c.verify().is_ok() {
                    list.push(ci);
                }
            }
        }
    }
    for (si, list) in candidates.iter_mut().enumerate() {
        list.sort_by_key(|&ci| {
            commits.get(ci).map_or(2u8, |c| {
                if c.parents.iter().all(|q| view.status(q) == Some(CommitStatus::Accepted)) {
                    0
                } else if c
                    .parents
                    .iter()
                    .all(|q| view.status(q).is_some() || commit_at.contains_key(q))
                {
                    1
                } else {
                    2
                }
            })
        });
        list.truncate(MAX_CANDIDATES);
        for &ci in list.iter() {
            if let Some(r) = reserved.get_mut(ci) {
                *r = Some(si);
            }
        }
    }

    // States behind a gap no item of this batch fills (the previous state is neither held nor
    // offered, or is itself behind such a gap), in ascending seq.
    let mut gap = vec![false; states.len()];
    for si in 0..states.len() {
        let Some(p) = states.get(si) else {
            continue;
        };
        let prev = <[u8; 32]>::try_from(p.m.state.prev_manifest_hash.as_slice()).ok();
        let filled = p.m.state.manifest_seq == 1
            || prev.is_some_and(|h| {
                view.manifest(&h).is_some() || state_at.get(&h).is_some_and(|&j| j < si && gap.get(j) == Some(&false))
            });
        if let Some(g) = gap.get_mut(si) {
            *g = !filled;
        }
    }

    // Commits that cannot apply in this batch whatever happens: never tried. `blocked` marks the
    // states that cannot settle in this batch.
    let hopeless_given = |blocked: &[bool]| {
        let mut hopeless = vec![false; commits.len()];
        for (ci, c) in commits.iter().enumerate() {
            let cited = view.manifest(&c.manifest_hash).is_some()
                || state_at
                    .get(&c.manifest_hash)
                    .is_some_and(|&si| blocked.get(si) == Some(&false));
            let parents = c.parents.iter().all(|p| {
                view.status(p).is_some()
                    || commit_at
                        .get(p)
                        .is_some_and(|&j| j < ci && hopeless.get(j) == Some(&false))
            });
            if let Some(h) = hopeless.get_mut(ci) {
                *h = !(cited && parents);
            }
        }
        hopeless
    };
    let mut blocked = gap.clone();
    let mut hopeless = hopeless_given(&blocked);
    // An epoch-raising state whose rotation candidates all cannot apply here waits for its rotation
    // commit, so it cannot settle in this batch either, nor can a state after it on its chain, nor
    // a commit citing one of them. A few rounds of this reach a fixed point in practice; what they
    // miss is only tried, never wrong.
    for _ in 0..8 {
        let mut changed = false;
        for si in 0..states.len() {
            let Some(p) = states.get(si) else {
                continue;
            };
            if blocked.get(si) == Some(&true) || view.manifest(&p.hash).is_some() {
                continue;
            }
            let prev = <[u8; 32]>::try_from(p.m.state.prev_manifest_hash.as_slice()).ok();
            let prev_at = prev.and_then(|h| state_at.get(&h).copied());
            let after_blocked = view.manifest(&prev.unwrap_or_default()).is_none()
                && prev_at.is_some_and(|j| j < si && blocked.get(j) == Some(&true));
            let prev_epoch = prev.and_then(|h| {
                view.manifest(&h)
                    .map(|m| m.state.key_epoch)
                    .or_else(|| prev_at.and_then(|j| states.get(j)).map(|q| q.m.state.key_epoch))
            });
            let raising =
                p.m.state.manifest_seq > 1 && prev_epoch.and_then(|e| e.checked_add(1)) == Some(p.m.state.key_epoch);
            let cands = candidates.get(si).map(Vec::as_slice).unwrap_or_default();
            let stuck = raising && !cands.is_empty() && cands.iter().all(|&ci| hopeless.get(ci) == Some(&true));
            if after_blocked || stuck {
                if let Some(b) = blocked.get_mut(si) {
                    *b = true;
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
        hopeless = hopeless_given(&blocked);
    }

    let mut state_done = vec![false; states.len()];
    let mut commit_done = vec![false; commits.len()];
    let mut work = Worklist {
        queue: VecDeque::new(),
        queued: HashSet::new(),
        waiters: HashMap::new(),
    };
    for si in 0..states.len() {
        work.push(Task::State(si));
    }
    if !states_only {
        for ci in 0..commits.len() {
            if hopeless.get(ci) == Some(&false) && reserved.get(ci) == Some(&None) {
                work.push(Task::Commit(ci));
            }
        }
    }
    let mut exhausted = false;

    while let Some(w) = work.pop() {
        if out.applications >= limit {
            exhausted = true;
            break;
        }
        match w {
            Task::State(si) => {
                let Some(p) = states.get(si) else {
                    continue;
                };
                if state_done.get(si) == Some(&true) {
                    continue;
                }
                let settle = |done: &mut Vec<bool>| {
                    if let Some(d) = done.get_mut(si) {
                        *d = true;
                    }
                };
                // Releases the candidates of a settled state as ordinary commits.
                let release = |reserved: &mut Vec<Option<usize>>, work: &mut Worklist, cands: &[usize]| {
                    for &ci in cands {
                        if let Some(r) = reserved.get_mut(ci) {
                            *r = None;
                        }
                        if !states_only && hopeless.get(ci) == Some(&false) {
                            work.push(Task::Commit(ci));
                        }
                    }
                };
                let cands: Vec<usize> = candidates.get(si).cloned().unwrap_or_default();
                if view.is_winning(&p.hash) {
                    // Already on the chain: accepted again with no change. Its rotation commit, if
                    // offered, is applied as an ordinary commit and accepted again the same way.
                    out.accepted.push(p.hash);
                    settle(&mut state_done);
                    release(&mut reserved, &mut work, &cands);
                    work.wake(&p.hash);
                    continue;
                }
                let genesis = p.m.state.manifest_seq == 1;
                let raising = match prev_epoch(view, &p.m) {
                    Some(e) => e.checked_add(1) == Some(p.m.state.key_epoch),
                    None if genesis => false,
                    None => {
                        // A gap: wait for the previous state.
                        if let Ok(prev) = <[u8; 32]>::try_from(p.m.state.prev_manifest_hash.as_slice()) {
                            work.wait(w, [prev]);
                        }
                        continue;
                    }
                };
                let mut live: Vec<usize> = if raising {
                    cands
                        .iter()
                        .copied()
                        .filter(|&ci| commit_done.get(ci) == Some(&false) && hopeless.get(ci) == Some(&false))
                        .collect()
                } else {
                    Vec::new()
                };
                // A candidate whose parents are all held goes first.
                live.sort_by_key(|&ci| {
                    commits
                        .get(ci)
                        .is_none_or(|c| !c.parents.iter().all(|q| view.status(q) == Some(CommitStatus::Accepted)))
                });
                if live.is_empty() && raising && cands.iter().any(|&ci| commit_done.get(ci) == Some(&false)) {
                    // Its rotation commit is offered but cannot apply in this batch (a parent is
                    // neither held nor offered): the pair waits for the next catch-up round.
                    continue;
                }
                if live.is_empty() {
                    out.applications += 1;
                    match view.apply_manifest_with(p.m.clone(), None, Via::Offer) {
                        Ok(()) => out.accepted.push(p.hash),
                        Err(code) => out.reject(p.hash, code),
                    }
                    settle(&mut state_done);
                    release(&mut reserved, &mut work, &cands);
                    work.wake(&p.hash);
                    continue;
                }
                let mut missing: Vec<Id> = Vec::new();
                let mut outcome: Option<(usize, Result<(), RejectCode>)> = None;
                // The first candidate that failed for a reason of its own, kept in case none pairs.
                let mut failed: Option<(usize, RejectCode)> = None;
                for &ci in &live {
                    if out.applications >= limit {
                        exhausted = true;
                        break;
                    }
                    let Some(c) = commits.get(ci) else {
                        continue;
                    };
                    out.applications += 1;
                    match view.apply_manifest_with(p.m.clone(), Some(c.clone()), Via::Offer) {
                        Err(RejectCode::MissingParents) => {
                            missing.extend(view.missing_for(c).into_iter().filter(|id| *id != p.hash));
                        }
                        Err(code) if code != RejectCode::ManifestConflict => {
                            // This candidate cannot be the rotation commit (a rejected parent, a bad
                            // signature, a wrong shape), or the state itself is invalid: another
                            // candidate may still pair with the state.
                            if failed.is_none() {
                                failed = Some((ci, code));
                            }
                        }
                        // A verified losing state that the engine kept without this candidate as its
                        // rotation commit (the candidate's shape or signature is wrong): a later
                        // candidate may be the real one (SPEC 8.3 keeps it with the losing state).
                        Err(RejectCode::ManifestConflict)
                            if view.manifest(&p.hash).is_some()
                                && view.rotation_commit(&p.hash).map(|r| r.commit_id) != Some(c.commit_id) =>
                        {
                            if failed.is_none() {
                                failed = Some((ci, RejectCode::ManifestConflict));
                            }
                        }
                        // Accepted, or a verified losing state kept with this candidate as its held
                        // rotation commit: settled.
                        result => {
                            outcome = Some((ci, result));
                            break;
                        }
                    }
                }
                if outcome.is_none() && missing.is_empty() && !exhausted {
                    outcome = failed.map(|(ci, code)| (ci, Err(code)));
                }
                match outcome {
                    Some((ci, result)) => {
                        let id = commits.get(ci).map(|c| c.commit_id);
                        match result {
                            Ok(()) => {
                                out.accepted.push(p.hash);
                                out.accepted.extend(id);
                            }
                            Err(code) => {
                                // Both items of a rejected pair carry the same code (SPEC 9.1).
                                out.reject(p.hash, code);
                                if let Some(id) = id {
                                    out.reject(id, code);
                                }
                            }
                        }
                        if let Some(d) = commit_done.get_mut(ci) {
                            *d = true;
                        }
                        settle(&mut state_done);
                        let others: Vec<usize> = cands.iter().copied().filter(|&o| o != ci).collect();
                        release(&mut reserved, &mut work, &others);
                        work.wake(&p.hash);
                        if let Some(id) = id {
                            work.wake(&id);
                        }
                    }
                    None if exhausted => break,
                    None => work.wait(w, missing),
                }
            }
            Task::Commit(ci) => {
                let Some(c) = commits.get(ci) else {
                    continue;
                };
                if commit_done.get(ci) == Some(&true) || reserved.get(ci).is_some_and(Option::is_some) {
                    continue;
                }
                let id = c.commit_id;
                out.applications += 1;
                match view.apply_commit_via(c.clone(), Via::Offer) {
                    Err(RejectCode::MissingParents) => {
                        work.wait(w, view.missing_for(c));
                    }
                    result => {
                        match result {
                            Ok(()) => out.accepted.push(id),
                            Err(code) => out.reject(id, code),
                        }
                        if let Some(d) = commit_done.get_mut(ci) {
                            *d = true;
                        }
                        work.wake(&id);
                    }
                }
            }
        }
    }
    out.exhausted = exhausted;

    // Report what is left, and return it for the next catch-up round.
    let mut reported: HashSet<Id> = HashSet::new();
    let mut deferred = Vec::new();
    for (si, p) in states.into_iter().enumerate() {
        if state_done.get(si) == Some(&true) {
            continue;
        }
        let code = if p.m.state.manifest_seq == 1 || prev_epoch(view, &p.m).is_some() {
            RejectCode::MissingParents
        } else {
            RejectCode::ManifestConflict
        };
        out.reject(p.hash, code);
        let pair = candidates
            .get(si)
            .and_then(|l| l.iter().find(|&&ci| commit_done.get(ci) == Some(&false)))
            .and_then(|&ci| commits.get(ci));
        if let Some(c) = pair {
            out.reject(c.commit_id, code);
            reported.insert(c.commit_id);
        }
        deferred.push(p.m);
    }
    let mut waiting = Vec::new();
    for (ci, c) in commits.into_iter().enumerate() {
        if commit_done.get(ci) == Some(&true) {
            continue;
        }
        if !states_only && !reported.contains(&c.commit_id) {
            out.reject(c.commit_id, RejectCode::MissingParents);
        }
        waiting.push(c);
    }
    if !states_only {
        for l in leaves {
            let _ = view.apply_leave_via(l, Via::Offer);
        }
    }
    out.deferred = deferred;
    out.waiting = waiting;
    out
}

/// Orders commits so that a commit comes after every parent that is in the same batch (Kahn's
/// algorithm over the claimed ids). Duplicates are dropped. Commits left in a claimed cycle, which
/// valid ids cannot form, go last; the engine rejects them.
fn parents_first(commits: Vec<Commit>) -> Vec<Commit> {
    let mut index: HashMap<Id, usize> = HashMap::with_capacity(commits.len());
    let mut unique: Vec<Commit> = Vec::with_capacity(commits.len());
    for c in commits {
        if let std::collections::hash_map::Entry::Vacant(e) = index.entry(c.commit_id) {
            e.insert(unique.len());
            unique.push(c);
        }
    }
    let mut waiting_on = vec![0usize; unique.len()];
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); unique.len()];
    for (i, c) in unique.iter().enumerate() {
        for p in &c.parents {
            if let Some(&j) = index.get(p) {
                if let (Some(n), Some(ch)) = (waiting_on.get_mut(i), children.get_mut(j)) {
                    *n = n.saturating_add(1);
                    ch.push(i);
                }
            }
        }
    }
    let mut ready: VecDeque<usize> = waiting_on
        .iter()
        .enumerate()
        .filter(|(_, n)| **n == 0)
        .map(|(i, _)| i)
        .collect();
    let mut order: Vec<usize> = Vec::with_capacity(unique.len());
    let mut placed = vec![false; unique.len()];
    while let Some(i) = ready.pop_front() {
        order.push(i);
        if let Some(p) = placed.get_mut(i) {
            *p = true;
        }
        for &k in children.get(i).map(Vec::as_slice).unwrap_or_default() {
            if let Some(n) = waiting_on.get_mut(k) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    ready.push_back(k);
                }
            }
        }
    }
    order.extend((0..unique.len()).filter(|i| placed.get(*i) == Some(&false)));
    let mut slots: Vec<Option<Commit>> = unique.into_iter().map(Some).collect();
    order
        .into_iter()
        .filter_map(|i| slots.get_mut(i).and_then(Option::take))
        .collect()
}

/// Applies `items` to a copy of `base` and returns it with the per-item outcome, keeping only what
/// the engine accepted or must store.
///
/// A listed peer must not be able to grow a repository with items the engine refuses: a commit the
/// engine rejects is stored with that status, and the header of a commit that misses a parent is
/// kept for ancestry (SPEC 7.3). So when an offered commit ends neither accepted, held, nor pending,
/// the copy is rebuilt from `base` with the states, the leave requests, and only the commits that
/// ended accepted, held, or pending. Held commits stay stored as SPEC 6.5 requires. A kept commit
/// depends only on states, on kept parents, and on verified headers; when a header of a dropped
/// commit was what decided it in the trial, the answer reports its stored status instead, so the
/// answer always matches what is stored. No engine change is involved.
pub(crate) fn apply_kept(
    base: &RepoView,
    repo_id: &str,
    items: Items,
    states_only: bool,
    cap: u64,
) -> (RepoView, Applied) {
    let manifests = items.manifests.clone();
    let commits = items.commits.clone();
    let leaves = items.leaves.clone();
    let mut trial = base.clone();
    let applied = apply_items(&mut trial, repo_id, items, states_only, cap);
    let kept = |c: &Commit| {
        matches!(
            trial.status(&c.commit_id),
            Some(CommitStatus::Accepted | CommitStatus::Held | CommitStatus::Pending)
        )
    };
    if commits.iter().all(kept) {
        return (trial, applied);
    }
    let commits: Vec<Commit> = commits.into_iter().filter(|c| kept(c)).collect();
    let mut clean = base.clone();
    let mut applied = applied;
    applied.applications += apply_items(
        &mut clean,
        repo_id,
        Items {
            manifests,
            commits: commits.clone(),
            leaves,
        },
        states_only,
        u64::MAX,
    )
    .applications;
    // The answer reports what is stored. A commit the trial accepted only thanks to a header the
    // rebuild left out (a dropped commit that resolved a removal cutoff, SPEC 7.3) is not stored as
    // accepted: it is reported with the code its stored status gives, and waits for a retry.
    let (stored, moved): (Vec<Id>, Vec<Id>) = std::mem::take(&mut applied.accepted)
        .into_iter()
        .partition(|id| clean.manifest(id).is_some() || clean.status(id) == Some(CommitStatus::Accepted));
    applied.accepted = stored;
    for id in moved {
        let code = match clean.status(&id) {
            Some(CommitStatus::Held | CommitStatus::Rejected) => RejectCode::Forbidden,
            _ => RejectCode::MissingParents,
        };
        applied.reject(id, code);
        if let Some(c) = commits.iter().find(|c| c.commit_id == id) {
            applied.waiting.push(c.clone());
        }
    }
    (clean, applied)
}

/// What happened to a trial view after the received-tip check (SPEC 9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admitted {
    /// Stored; the tip lists this host.
    Hosted,
    /// The received tip does not list this host: a held repository kept the validated states and
    /// is now not hosted; a first copy stored nothing.
    NotHosted,
    /// A first copy whose received tip does not list the sender: nothing stored.
    Forbidden,
    /// A first copy over the per-owner or store-wide repository cap: nothing stored.
    Quota,
    /// A first copy whose received tip is not known yet (no tip, or a gap in the chain): nothing
    /// stored; the catch-up decides.
    Incomplete,
}

/// The decision on a validated first copy (SPEC 9.2): stored only if its received tip lists this
/// host and the sender and the repository caps allow it; otherwise nothing is stored.
pub(crate) fn admit_first_copy(st: &mut State, repo_id: &str, sender: &Id, trial: RepoView) -> Admitted {
    let Some(tip) = trial.tip() else {
        return Admitted::Incomplete;
    };
    if tip.state.repo_id != repo_id || !trial.tip_lists_host() {
        return Admitted::NotHosted;
    }
    if !tip.state.has_host(sender) {
        return Admitted::Forbidden;
    }
    let owner = tip.state.owner_key;
    if st.store.repos.len() >= st.limits.max_repos || st.store.repos_owned_by(&owner) >= st.limits.max_repos_per_owner {
        return Admitted::Quota;
    }
    st.store.repos.insert(repo_id.to_string(), trial);
    Admitted::Hosted
}

/// Applies `items` from `sender` to a trial copy of `repo_id` (or a new view for a first copy),
/// checks the validated received tip, and installs what SPEC 6.1 rule 6, 8.6, and 9.2 allow.
///
/// A first copy is all or nothing ([`admit_first_copy`]); one with a gap in its chain is
/// [`Admitted::Incomplete`] and waits for the catch-up. A held repository always gets the result;
/// when the received tip does not list this host, only the validated states with their rotation
/// commits are kept, not the other items. Rejected items are never kept ([`apply_kept`]).
pub(crate) fn receive(st: &mut State, repo_id: &str, sender: &Id, items: Items, cap: u64) -> (Admitted, Applied) {
    let Some(base) = st.store.repos.get(repo_id).cloned() else {
        let fresh = RepoView::new(st.host_key(), st.limits.head_bound);
        let (trial, applied) = apply_kept(&fresh, repo_id, items, false, cap);
        st.replication_stats.engine_applications += applied.applications;
        if applied.has_gap() {
            return (Admitted::Incomplete, applied);
        }
        return (admit_first_copy(st, repo_id, sender, trial), applied);
    };
    let states = Items {
        manifests: items.manifests.clone(),
        commits: items.commits.clone(),
        leaves: Vec::new(),
    };
    let (trial, applied) = apply_kept(&base, repo_id, items, false, cap);
    st.replication_stats.engine_applications += applied.applications;
    if trial.tip_lists_host() {
        st.store.repos.insert(repo_id.to_string(), trial);
        return (Admitted::Hosted, applied);
    }
    // Held, and the received tip drops this host: keep the validated states (each epoch-raising
    // one with its rotation commit), not the other items (SPEC 8.6, 9.2).
    let (kept, _) = apply_kept(&base, repo_id, states, true, u64::MAX);
    st.store.repos.insert(repo_id.to_string(), kept);
    (Admitted::NotHosted, applied)
}

// ─── The peer workers ───────────────────────────────────────────────────────────────────

/// The running replication: one worker thread per peer. Dropping it stops and joins them; a call
/// in flight ends within [`Config::request_timeout`].
pub struct Replication {
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    wake: Arc<Condvar>,
    threads: Vec<JoinHandle<()>>,
}

impl Drop for Replication {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Notify under the lock so no worker misses it between its check and its wait.
        let guard = self.state.lock();
        self.wake.notify_all();
        drop(guard);
        for t in std::mem::take(&mut self.threads) {
            let _ = t.join();
        }
    }
}

/// Installs `peers` as the host's peer list (the keys the host routes accept) and starts one
/// worker thread per peer other than this host. Each worker sweeps its peer at once (the startup
/// replication of SPEC 9.3), then on every accepted write and every [`Config::sweep_interval`].
///
/// # Errors
///
/// An I/O error if the state lock is poisoned or a thread cannot be started; workers already
/// started are stopped.
pub fn run(state: Arc<Mutex<State>>, peers: Peers) -> io::Result<Replication> {
    let (signing, config, own, wake) = {
        let mut st = state.lock().map_err(|_| io::Error::other("state lock poisoned"))?;
        st.repl.peers = peers.clone();
        (
            st.host_signing_key().clone(),
            st.replication,
            st.host_key(),
            Arc::clone(&st.repl.wake),
        )
    };
    let agent: Agent = Agent::config_builder()
        .timeout_global(Some(config.request_timeout))
        .http_status_as_error(false)
        .max_redirects(0)
        .proxy(None)
        .build()
        .into();
    let stop = Arc::new(AtomicBool::new(false));
    let mut running = Replication {
        state: Arc::clone(&state),
        stop: Arc::clone(&stop),
        wake: Arc::clone(&wake),
        threads: Vec::new(),
    };
    for (i, peer) in peers.iter().filter(|p| p.key != own).enumerate() {
        let worker = Worker {
            state: Arc::clone(&state),
            peer: peer.clone(),
            signing: signing.clone(),
            agent: agent.clone(),
            config,
            stop: Arc::clone(&stop),
            wake: Arc::clone(&wake),
        };
        let handle = thread::Builder::new()
            .name(format!("avp-peer-{i}"))
            .spawn(move || worker.run())?;
        running.threads.push(handle);
    }
    Ok(running)
}

/// The work one wake-up of a worker found.
struct Work {
    offers: Vec<Outgoing>,
    repos: Vec<String>,
}

struct Worker {
    state: Arc<Mutex<State>>,
    peer: Peer,
    signing: SigningKey,
    agent: Agent,
    config: Config,
    stop: Arc<AtomicBool>,
    wake: Arc<Condvar>,
}

/// The path of a host route for `repo_id`, percent-encoding anything outside the unreserved set.
fn host_path(repo_id: &str, op: &str) -> String {
    let mut seg = String::with_capacity(repo_id.len());
    for b in repo_id.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            seg.push(char::from(b));
        } else {
            seg.push_str(&format!("%{b:02X}"));
        }
    }
    format!("/v1/host/repos/{seg}/{op}")
}

impl Worker {
    fn stopping(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    fn run(self) {
        let mut cursor = 0u64;
        let mut seen_kick = None;
        let mut next_sweep = Instant::now();
        while let Some(work) = self.next_work(&mut cursor, &mut seen_kick, &mut next_sweep) {
            for item in &work.offers {
                if self.stopping() {
                    return;
                }
                self.offer(item);
            }
            for repo_id in &work.repos {
                if self.stopping() {
                    return;
                }
                self.catch_up(repo_id);
            }
        }
    }

    /// Waits under the state lock until there is something to do, and takes it. `None` ends the
    /// worker (stop requested or a poisoned lock).
    fn next_work(&self, cursor: &mut u64, seen_kick: &mut Option<u64>, next_sweep: &mut Instant) -> Option<Work> {
        let mut guard = self.state.lock().ok()?;
        loop {
            if self.stopping() {
                return None;
            }
            let now = Instant::now();
            if !guard.repl.paused {
                if *seen_kick != Some(guard.repl.kick) {
                    *seen_kick = Some(guard.repl.kick);
                    *next_sweep = now;
                }
                let st: &mut State = &mut guard;
                let (queued, last) = st.store.outbox.after(*cursor);
                *cursor = last;
                let offers: Vec<Outgoing> = queued
                    .into_iter()
                    .filter(|o| {
                        st.store.repos.get(&o.repo_id).is_some_and(|v| {
                            v.tip_lists_host() && v.tip().is_some_and(|t| t.state.has_host(&self.peer.key))
                        })
                    })
                    .collect();
                let mut repos: Vec<String> = Vec::new();
                let key = self.peer.key;
                st.repl.catchups.retain(|(p, r)| {
                    if *p == key {
                        repos.push(r.clone());
                        false
                    } else {
                        true
                    }
                });
                if now >= *next_sweep {
                    // SPEC 9.3: only the repositories whose winning tip lists this peer, so a peer
                    // that is not listed never learns which repoIds this host holds.
                    let mut held: Vec<String> = st
                        .store
                        .repos
                        .iter()
                        .filter(|(_, v)| v.tip().is_some_and(|t| t.state.has_host(&key)))
                        .map(|(r, _)| r.clone())
                        .collect();
                    held.sort_unstable();
                    repos.extend(held);
                    *next_sweep = now + self.config.sweep_interval;
                }
                let mut seen = HashSet::new();
                repos.retain(|r| seen.insert(r.clone()));
                if !offers.is_empty() || !repos.is_empty() {
                    return Some(Work { offers, repos });
                }
            }
            let wait = if guard.repl.paused {
                self.config.sweep_interval
            } else {
                next_sweep.saturating_duration_since(now)
            };
            guard = self
                .wake
                .wait_timeout(guard, wait.max(Duration::from_millis(1)))
                .ok()?
                .0;
        }
    }

    /// One signed `POST` to the peer: the status and the body, read up to the size limit. `None`
    /// when paused, on a transport error or timeout, or for an oversized body.
    fn call(&self, path: &str, body: &[u8]) -> Option<(u16, Vec<u8>)> {
        let time = {
            let st = self.state.lock().ok()?;
            if st.repl.paused {
                return None;
            }
            st.now_ms()
        };
        let message = request_message("POST", path, body, time).ok()?;
        let signature = self.signing.sign(&message).to_bytes();
        let url = format!("{}{path}", self.peer.url);
        let mut response = self
            .agent
            .post(&url)
            .header(HEADER_KEY, b64_encode(&self.signing.verifying_key().to_bytes()))
            .header(HEADER_TIME, time.to_string())
            .header(HEADER_SIGNATURE, b64_encode(&signature))
            .content_type("application/json")
            .send(body)
            .ok()?;
        let status = response.status().as_u16();
        let bytes = response
            .body_mut()
            .with_config()
            .limit(self.config.max_response_bytes)
            .read_to_vec()
            .ok()?;
        Some((status, bytes))
    }

    /// A signed JSON call whose `200` answer decodes as `T`; anything else is `None`.
    fn post_json<T: DeserializeOwned>(&self, path: &str, body: &impl Serialize) -> Option<T> {
        let bytes = serde_json::to_vec(body).ok()?;
        let (status, reply) = self.call(path, &bytes)?;
        if status != 200 {
            return None;
        }
        serde_json::from_slice(&reply).ok()
    }

    /// Offers one accepted write. The answer needs no handling: a peer that lacks something
    /// catches up from this host itself (SPEC 9.2).
    fn offer(&self, item: &Outgoing) {
        let body = OfferBody {
            repo_id: Some(item.repo_id.clone()),
            manifests: item.manifests.clone(),
            commits: item.commits.clone(),
            leaves: item.leaves.clone(),
        };
        let _: Option<OfferReply> = self.post_json(&host_path(&item.repo_id, "offer"), &body);
    }

    /// Catch-up from the peer (SPEC 9.2): `heads`, then `fetch` for the tip state and the heads
    /// this host lacks, then, round after round, for what the carried items still miss (a previous
    /// state, a parent, a cited state, a frontier header), at most [`MAX_ROUNDS`] rounds and
    /// [`MAX_REQUESTED`] ids.
    ///
    /// The states and commits a round could not apply are carried to the next round, each with
    /// the ids it waits on. A carried item is tried again only when one of those ids arrived in
    /// that round or became known, or belongs to another carried item tried again (so a rotation
    /// pair and the commits citing its state come back together once the missing parent arrives).
    /// The carried items and the fetched ones together are at most [`MAX_ITEMS`] per round (the
    /// items carried longest are dropped first), and the whole catch-up makes at most
    /// [`CATCHUP_BUDGET`] engine applications, whatever the number of rounds. A round whose budget
    /// ran out is followed by one that continues on the carried items even when nothing new is
    /// fetched.
    ///
    /// A held repository goes through [`receive`] under the state lock. A first copy is private
    /// until it is admitted: it is built outside the lock on one trial view kept across the rounds,
    /// and decided once at the end by [`admit_first_copy`] under the lock (all or nothing; nothing
    /// is stored while the chain still has a gap). A peer that refuses (`403`, `404`, `503`) or
    /// answers badly ends the catch-up of this repository only.
    fn catch_up(&self, repo_id: &str) {
        let heads_body = HeadsBody {
            repo_id: Some(repo_id.to_string()),
        };
        let Some(heads) = self.post_json::<HeadsReply>(&host_path(repo_id, "heads"), &heads_body) else {
            return;
        };
        if heads.tip.seq < 1 || heads.heads.len() > MAX_ITEMS {
            return;
        }
        let (mut want, mut first_copy, host_key, head_bound) = {
            let Ok(st) = self.state.lock() else {
                return;
            };
            let view = st.store.repos.get(repo_id);
            let mut w = Vec::new();
            if view.is_none_or(|v| v.manifest(&heads.tip.hash).is_none()) {
                w.push(heads.tip.hash);
            }
            for h in heads.heads {
                if view.is_none_or(|v| v.status(&h).is_none()) && !w.contains(&h) {
                    w.push(h);
                }
            }
            let (key, bound) = (st.host_key(), st.limits.head_bound);
            (w, view.is_none().then(|| RepoView::new(key, bound)), key, bound)
        };
        let mut requested: HashSet<Id> = HashSet::new();
        let mut carried = Carried::default();
        let mut left = CATCHUP_BUDGET;
        let mut again = false;
        for round in 0..MAX_ROUNDS {
            if self.stopping() || left == 0 {
                break;
            }
            // The first round fetches even with nothing wanted: a fetch also returns the pending
            // leave requests (SPEC 9.1).
            let fetching = round == 0 || !want.is_empty();
            if !fetching && !again {
                break;
            }
            let items = if fetching {
                requested.extend(want.iter().copied());
                let body = FetchBody {
                    repo_id: Some(repo_id.to_string()),
                    ids: std::mem::take(&mut want),
                };
                match self.post_json::<Items>(&host_path(repo_id, "fetch"), &body) {
                    Some(items) if items.bounded() => items,
                    _ => break,
                }
            } else {
                Items::default()
            };
            // Carried and fetched together stay within one batch.
            carried.trim(MAX_ITEMS.saturating_sub(items.manifests.len().saturating_add(items.commits.len())));
            let held = {
                let Ok(st) = self.state.lock() else {
                    return;
                };
                // A sweep of a peer in step brings only known leave requests: nothing to apply.
                let nothing_new = items.manifests.is_empty()
                    && items.commits.is_empty()
                    && carried.is_empty()
                    && st
                        .store
                        .repos
                        .get(repo_id)
                        .is_some_and(|v| items.leaves.iter().all(|l| v.leaves().contains(l)));
                if nothing_new {
                    return;
                }
                st.store.repos.contains_key(repo_id)
            };
            let applied = if held {
                // Another path may have stored the repository meanwhile: it is held now.
                first_copy = None;
                let Ok(mut st) = self.state.lock() else {
                    return;
                };
                let Some(view) = st.store.repos.get(repo_id) else {
                    return;
                };
                let batch = carried.batch(view, items);
                let (_, applied) = receive(&mut st, repo_id, &self.peer.key, batch, left);
                let Some(view) = st.store.repos.get(repo_id) else {
                    return;
                };
                carried.after(view, &applied, round);
                want = carried.want(view, &requested);
                applied
            } else {
                let base = first_copy.take().unwrap_or_else(|| RepoView::new(host_key, head_bound));
                let batch = carried.batch(&base, items);
                let (trial, applied) = apply_kept(&base, repo_id, batch, false, left);
                if let Ok(mut st) = self.state.lock() {
                    st.replication_stats.engine_applications += applied.applications;
                }
                carried.after(&trial, &applied, round);
                want = carried.want(&trial, &requested);
                first_copy = Some(trial);
                applied
            };
            left = left.saturating_sub(applied.applications);
            again = applied.exhausted;
        }
        // A first copy is decided once, on the validated received tip, and only without a gap.
        if let (Some(trial), true) = (first_copy, carried.states.is_empty()) {
            if let Ok(mut st) = self.state.lock() {
                if !st.store.repos.contains_key(repo_id) {
                    let _ = admit_first_copy(&mut st, repo_id, &self.peer.key, trial);
                }
            }
        }
    }
}

/// The most engine applications one catch-up may make in all its rounds: two full batches' worth
/// of [`budget`]. An honest history needs about two per item it brings (the 40-rotation bootstrap,
/// 122 items, takes a few hundred), so this limits a peer that keeps the catch-up going, not the
/// length of an honest history; a held repository keeps what each round applied, and the next
/// sweep goes on from there.
const CATCHUP_BUDGET: u64 = 2 * (3 * MAX_ITEMS as u64 + 64);

/// One carried item: the ids it waits on and the round it was first carried in.
#[derive(Debug)]
struct Carry<T> {
    item: T,
    id: Id,
    deps: Vec<Id>,
    since: usize,
}

/// What a catch-up carries from one round to the next.
#[derive(Debug, Default)]
struct Carried {
    states: Vec<Carry<SignedManifest>>,
    commits: Vec<Carry<Commit>>,
    /// The first round of each carried item put back into this round's batch.
    taken: HashMap<Id, usize>,
}

impl Carried {
    fn is_empty(&self) -> bool {
        self.states.is_empty() && self.commits.is_empty()
    }

    /// Keeps at most `room` carried items, dropping those carried longest first.
    fn trim(&mut self, room: usize) {
        let total = self.states.len().saturating_add(self.commits.len());
        if total <= room {
            return;
        }
        let mut ages: Vec<usize> = self
            .states
            .iter()
            .map(|c| c.since)
            .chain(self.commits.iter().map(|c| c.since))
            .collect();
        ages.sort_unstable();
        // Items first carried before `cut` go, and as many of those carried in round `cut` as needed.
        let excess = total.saturating_sub(room);
        let cut = ages.get(excess.saturating_sub(1)).copied().unwrap_or(0);
        let mut drop_at_cut = ages.iter().take(excess).filter(|a| **a == cut).count();
        let mut keep = |since: usize| {
            if since < cut {
                false
            } else if since == cut && drop_at_cut > 0 {
                drop_at_cut -= 1;
                false
            } else {
                true
            }
        };
        self.states.retain(|c| keep(c.since));
        self.commits.retain(|c| keep(c.since));
    }

    /// The batch of a round: the fetched items, and the carried items whose wait is over (an id
    /// they wait on arrived in this round or is now known in `view`, or belongs to another carried
    /// item tried again). The others stay carried without being tried.
    fn batch(&mut self, view: &RepoView, mut items: Items) -> Items {
        let known = |id: &Id| view.manifest(id).is_some() || view.status(id).is_some();
        let carried_ids: HashSet<Id> = self
            .states
            .iter()
            .map(|c| c.id)
            .chain(self.commits.iter().map(|c| c.id))
            .collect();
        let mut arrived: HashSet<Id> = items
            .manifests
            .iter()
            .filter_map(|m| m.hash().ok())
            .chain(items.commits.iter().map(|c| c.commit_id))
            .filter(|id| !carried_ids.contains(id))
            .collect();
        // Which carried items wait on each id.
        let mut waiting_on: HashMap<Id, Vec<(bool, usize)>> = HashMap::new();
        for (i, c) in self.states.iter().enumerate() {
            for d in &c.deps {
                waiting_on.entry(*d).or_default().push((true, i));
            }
        }
        for (i, c) in self.commits.iter().enumerate() {
            for d in &c.deps {
                waiting_on.entry(*d).or_default().push((false, i));
            }
        }
        let mut take_state = vec![false; self.states.len()];
        let mut take_commit = vec![false; self.commits.len()];
        let mut queue: VecDeque<Id> = waiting_on
            .keys()
            .filter(|d| arrived.contains(*d) || known(d))
            .copied()
            .collect();
        while let Some(d) = queue.pop_front() {
            for (is_state, i) in waiting_on.remove(&d).unwrap_or_default() {
                let (flags, id) = if is_state {
                    (&mut take_state, self.states.get(i).map(|c| c.id))
                } else {
                    (&mut take_commit, self.commits.get(i).map(|c| c.id))
                };
                if let (Some(f), Some(id)) = (flags.get_mut(i), id) {
                    if !*f {
                        *f = true;
                        if arrived.insert(id) {
                            queue.push_back(id);
                        }
                    }
                }
            }
        }
        let taken = &mut self.taken;
        let mut i = 0;
        self.states.retain(|c| {
            let take = take_state.get(i) == Some(&true);
            i += 1;
            if take {
                items.manifests.push(c.item.clone());
                taken.insert(c.id, c.since);
            }
            !take
        });
        let mut i = 0;
        self.commits.retain(|c| {
            let take = take_commit.get(i) == Some(&true);
            i += 1;
            if take {
                items.commits.push(c.item.clone());
                taken.insert(c.id, c.since);
            }
            !take
        });
        items
    }

    /// Adds what a round left (`applied.deferred`, `applied.waiting`) to the carried items, with
    /// the ids each waits on in `view`; an item carried before keeps its first round. An item
    /// already carried and not tried this round stays as it was.
    fn after(&mut self, view: &RepoView, applied: &Applied, round: usize) {
        let present: HashSet<Id> = self
            .states
            .iter()
            .map(|c| c.id)
            .chain(self.commits.iter().map(|c| c.id))
            .collect();
        let since = std::mem::take(&mut self.taken);
        for m in &applied.deferred {
            let Ok(hash) = m.hash() else {
                continue;
            };
            if present.contains(&hash) {
                continue;
            }
            let prev = <[u8; 32]>::try_from(m.state.prev_manifest_hash.as_slice()).ok();
            let deps: Vec<Id> = match prev {
                Some(p) if m.state.manifest_seq > 1 && view.manifest(&p).is_none() => vec![p],
                _ => {
                    let mut d: Vec<Id> = applied
                        .waiting
                        .iter()
                        .filter(|c| is_rotation_for(c, m, &hash))
                        .flat_map(|c| view.missing_for(c))
                        .filter(|id| *id != hash)
                        .collect();
                    d.sort_unstable();
                    d.dedup();
                    d
                }
            };
            self.states.push(Carry {
                item: m.clone(),
                id: hash,
                deps,
                since: since.get(&hash).copied().unwrap_or(round),
            });
        }
        for c in &applied.waiting {
            if present.contains(&c.commit_id) {
                continue;
            }
            self.commits.push(Carry {
                item: c.clone(),
                id: c.commit_id,
                deps: view.missing_for(c),
                since: since.get(&c.commit_id).copied().unwrap_or(round),
            });
        }
        // An item that waits on nothing it can name cannot come back: it is dropped.
        self.states.retain(|c| !c.deps.is_empty());
        self.commits.retain(|c| !c.deps.is_empty());
    }

    /// The ids the next round fetches: what the carried items wait on, without what is carried or
    /// known already, ids already requested, or more than [`MAX_REQUESTED`] in all.
    fn want(&self, view: &RepoView, requested: &HashSet<Id>) -> Vec<Id> {
        let carried_ids: HashSet<Id> = self
            .states
            .iter()
            .map(|c| c.id)
            .chain(self.commits.iter().map(|c| c.id))
            .collect();
        let mut next: Vec<Id> = Vec::new();
        let mut seen: HashSet<Id> = HashSet::new();
        for d in self
            .states
            .iter()
            .flat_map(|c| c.deps.iter())
            .chain(self.commits.iter().flat_map(|c| c.deps.iter()))
        {
            if requested.len().saturating_add(next.len()) >= MAX_REQUESTED {
                break;
            }
            if carried_ids.contains(d)
                || requested.contains(d)
                || view.manifest(d).is_some()
                || view.status(d).is_some()
            {
                continue;
            }
            if seen.insert(*d) {
                next.push(*d);
            }
        }
        next
    }
}
