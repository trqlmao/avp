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
//!   every held repository against the peer at startup and every [`Config::sweep_interval`]
//!   (`heads`, then `fetch` for what this host lacks, SPEC 9.2).
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
use avp::rules::{RepoView, Via};
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

/// Most passes over the commits of one offer (commits are sorted parents first, so one pass
/// usually suffices; a pass that applies nothing ends the loop).
const MAX_PASSES: usize = 8;

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

/// The sender's key if the request is from a configured peer, is signed over exactly this method,
/// path, and body, and is within the skew window; `None` (answered `401`) otherwise.
pub(crate) fn authenticate(st: &State, method: &str, path: &str, body: &[u8], h: &HostHeaders) -> Option<Id> {
    let key = b64_decode_array::<32>(h.key.as_deref()?.trim()).ok()?;
    let time: i64 = h.time.as_deref()?.trim().parse().ok()?;
    let signature = b64_decode_array::<64>(h.signature.as_deref()?.trim()).ok()?;
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
#[serde(deny_unknown_fields)]
pub(crate) struct ManifestTip {
    #[serde(rename = "manifestSeq")]
    pub(crate) seq: i64,
    #[serde(rename = "manifestHash", with = "b64_array")]
    pub(crate) hash: Id,
}

/// `HeadsResponse`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// `FetchResponse`, and the item lists of `OfferRequest`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub(crate) struct RejectedItem {
    #[serde(with = "b64_array")]
    pub(crate) id: Id,
    pub(crate) code: String,
}

/// `OfferResponse`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Commits that still miss a parent, a cited state, or a frontier header.
    pub(crate) waiting: Vec<Commit>,
    /// Whether the sender may hold what this host lacks (`missing_parents` or `manifest_conflict`).
    pub(crate) incomplete: bool,
}

impl Applied {
    fn reject(&mut self, id: Id, code: RejectCode) {
        if matches!(code, RejectCode::MissingParents | RejectCode::ManifestConflict) {
            self.incomplete = true;
        }
        self.rejected.push((id, code));
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

/// Applies received items to `view` with [`Via::Offer`], in the dependency order of SPEC 9.1:
/// states by ascending `manifestSeq`, each epoch-raising one with its rotation commit as one atomic
/// pair; then the other commits, parents first; then the leave requests (a failing one is dropped).
///
/// With `states_only`, only the states and their rotation commits are applied. Every item is
/// validated by the engine; nothing here trusts the sender.
pub(crate) fn apply_items(view: &mut RepoView, repo_id: &str, items: Items, states_only: bool) -> Applied {
    let mut out = Applied::default();
    let Items {
        mut manifests,
        commits,
        leaves,
    } = items;
    manifests.sort_by_key(|m| m.state.manifest_seq);
    let mut commits: Vec<Option<Commit>> = commits.into_iter().map(Some).collect();

    for m in manifests {
        let Ok(hash) = m.hash() else {
            // A state whose canonical bytes cannot be built has no id to report; it is dropped.
            continue;
        };
        if m.state.repo_id != repo_id {
            out.reject(hash, RejectCode::BadRequest);
            continue;
        }
        if view.is_winning(&hash) {
            // Already on the chain: accepted again with no change. Its rotation commit, if offered,
            // is applied with the other commits and is accepted again the same way.
            out.accepted.push(hash);
            continue;
        }
        let raising = prev_epoch(view, &m).and_then(|e| e.checked_add(1)) == Some(m.state.key_epoch);
        let rotation = if raising {
            let seq = m.state.manifest_seq;
            let (owner, epoch) = (m.state.owner_key, m.state.key_epoch);
            commits
                .iter_mut()
                .find(|c| {
                    c.as_ref().is_some_and(|c| {
                        c.manifest_hash == hash && c.manifest_seq == seq && c.author == owner && c.key_epoch == epoch
                    })
                })
                .and_then(Option::take)
        } else {
            None
        };
        let rotation_id = rotation.as_ref().map(|c| c.commit_id);
        match view.apply_manifest_with(m, rotation, Via::Offer) {
            Ok(()) => {
                out.accepted.push(hash);
                out.accepted.extend(rotation_id);
            }
            Err(code) => {
                // Both items of a rejected pair carry the same code (SPEC 9.1).
                out.reject(hash, code);
                if let Some(id) = rotation_id {
                    out.reject(id, code);
                }
            }
        }
    }
    if states_only {
        return out;
    }

    let mut pending = parents_first(commits.into_iter().flatten().collect());
    for _ in 0..MAX_PASSES {
        let mut next = Vec::new();
        let mut progress = false;
        for c in pending {
            let id = c.commit_id;
            let probe = c.clone();
            match view.apply_commit_via(c, Via::Offer) {
                Ok(()) => {
                    out.accepted.push(id);
                    progress = true;
                }
                Err(RejectCode::MissingParents) => next.push(probe),
                Err(code) => out.reject(id, code),
            }
        }
        pending = next;
        if !progress || pending.is_empty() {
            break;
        }
    }
    for c in &pending {
        out.reject(c.commit_id, RejectCode::MissingParents);
    }
    out.waiting = pending;

    for l in leaves {
        let _ = view.apply_leave_via(l, Via::Offer);
    }
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
    /// A first copy with no validated tip yet (the chain has not arrived): nothing stored.
    Incomplete,
}

/// Applies `items` from `sender` to a trial copy of `repo_id` (or a new view for a first copy),
/// checks the validated received tip, and installs what SPEC 6.1 rule 6, 8.6, and 9.2 allow.
///
/// A first copy is all or nothing: it is stored only if its tip lists this host and the sender. A
/// held repository always gets the result; when the received tip does not list this host, only the
/// validated states with their rotation commits are kept, not the other items.
pub(crate) fn receive(st: &mut State, repo_id: &str, sender: &Id, items: Items) -> (Admitted, Applied) {
    let held = st.store.repos.get(repo_id).cloned();
    let was_held = held.is_some();
    let base = held.unwrap_or_else(|| RepoView::new(st.host_key(), st.limits.head_bound));
    let mut trial = base.clone();
    let states: Vec<SignedManifest> = items.manifests.clone();
    let commits_for_states: Vec<Commit> = items.commits.clone();
    let applied = apply_items(&mut trial, repo_id, items, false);
    let lists = trial.tip_lists_host();

    if !was_held {
        let Some(tip) = trial.tip() else {
            return (Admitted::Incomplete, applied);
        };
        if !lists {
            return (Admitted::NotHosted, applied);
        }
        if !tip.state.has_host(sender) {
            return (Admitted::Forbidden, applied);
        }
        st.store.repos.insert(repo_id.to_string(), trial);
        return (Admitted::Hosted, applied);
    }
    if lists {
        st.store.repos.insert(repo_id.to_string(), trial);
        return (Admitted::Hosted, applied);
    }
    // Held, and the received tip drops this host: keep the validated states (each epoch-raising
    // one with its rotation commit), not the other items (SPEC 8.6, 9.2).
    let mut kept = base;
    let states_only = Items {
        manifests: states,
        commits: commits_for_states,
        leaves: Vec::new(),
    };
    let _ = apply_items(&mut kept, repo_id, states_only, true);
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
                    let mut held: Vec<String> = st.store.repos.keys().cloned().collect();
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
    /// this host lacks, then for what the engine names as missing, for at most [`MAX_ROUNDS`]
    /// rounds and [`MAX_REQUESTED`] ids. Every round goes through [`receive`]. A peer that refuses
    /// (`403`, `404`, `503`) or answers badly ends the catch-up of this repository only.
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
        let mut want: Vec<Id> = {
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
            w
        };
        let mut requested: HashSet<Id> = HashSet::new();
        let mut waiting: Vec<Commit> = Vec::new();
        for round in 0..MAX_ROUNDS {
            // The first round runs even with nothing wanted: a fetch also returns the pending
            // leave requests (SPEC 9.1).
            if (round > 0 && want.is_empty()) || self.stopping() {
                return;
            }
            requested.extend(want.iter().copied());
            let body = FetchBody {
                repo_id: Some(repo_id.to_string()),
                ids: std::mem::take(&mut want),
            };
            let Some(mut items) = self.post_json::<Items>(&host_path(repo_id, "fetch"), &body) else {
                return;
            };
            if !items.bounded() {
                return;
            }
            let Ok(mut st) = self.state.lock() else {
                return;
            };
            // A sweep of a peer in step brings only known leave requests: nothing to apply.
            let nothing_new = items.manifests.is_empty()
                && items.commits.is_empty()
                && waiting.is_empty()
                && st
                    .store
                    .repos
                    .get(repo_id)
                    .is_some_and(|v| items.leaves.iter().all(|l| v.leaves().contains(l)));
            if nothing_new {
                return;
            }
            items.commits.append(&mut waiting);
            let (_, applied) = receive(&mut st, repo_id, &self.peer.key, items);
            let Some(view) = st.store.repos.get(repo_id) else {
                return;
            };
            let mut next: HashSet<Id> = HashSet::new();
            for c in &applied.waiting {
                for id in view.missing_for(c) {
                    if requested.len().saturating_add(next.len()) >= MAX_REQUESTED {
                        break;
                    }
                    if !requested.contains(&id) {
                        next.insert(id);
                    }
                }
            }
            waiting = applied.waiting;
            want = next.into_iter().collect();
        }
    }
}
