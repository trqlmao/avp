// SPDX-License-Identifier: MIT

//! One member device's copy of one repository: [`Vault`].
//!
//! The client never trusts a host's acceptance (SPEC 7.5). It keeps its own verified manifest
//! chain ([`Chain`]), pins its highest verified state and refuses a rollback (SPEC 6.4), checks
//! every pulled commit itself, merges every head it can read and pushes the merge (SPEC 5), leaves
//! an unreadable head alone (SPEC 7.5), retains every epoch's data key so it can merge old-epoch
//! heads forward, and strips `refreshToken` and `expiresAt` unless the signed policy is `true`
//! (SPEC 5.1). The owner operations of SPEC 8 (invite, remove, policy, leave processing) build and
//! sign new states here.
//!
//! Every host answer is untrusted input: nothing here panics on one, and a state or commit that
//! fails a check is discarded rather than used.

use std::collections::{HashMap, HashSet};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use avp::commit::{Commit, CommitHeader};
use avp::crypto::{SCHEME_ID, WRAP_INFO, ct_eq, random_bytes, unwrap, wrap, x25519_public, x25519_random};
use avp::encoding::{V2, b64_array, b64_decode, b64_encode, b64_ids};
use avp::manifest::{HostRef, ManifestState, MemberEntry, Removal, SignedManifest, derive_repo_id};
use avp::owner::OwnerKeys;
use avp::payload::{Field, Hlc, PayloadV2, Stamp, merge};
use avp::tokens::{Acceptance, InviteToken, LeaveRequest, RepoLocator, key_fingerprint, owner_fingerprint};
use ed25519_dalek::{Signer, SigningKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ureq::Agent;
use x25519_dalek::StaticSecret;

use crate::{ClientError, Result};

/// A commit id or manifest hash.
pub type Id = [u8; 32];

/// The largest host answer the client reads.
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

/// How often a write is retried on `422 missing_parents` (SPEC 10.4: the only retryable error),
/// and the pause between tries, while a host fetches the parents from its peers.
const MISSING_PARENTS_RETRIES: u32 = 40;
const RETRY_PAUSE: Duration = Duration::from_millis(100);

/// How often an owner rebuilds a publication on `409 manifest_conflict` (SPEC 6.3).
const CONFLICT_RETRIES: u32 = 3;

/// A token is renewed this long before it expires.
const TOKEN_SLACK_MS: i64 = 30_000;

/// The client's wall clock in epoch milliseconds; `0` for a clock before the epoch.
#[must_use]
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

// ─── Member identity ────────────────────────────────────────────────────────────────────

/// A member identity: a per-device Ed25519 and X25519 key pair (SPEC 3.2). The owner is the member
/// whose keys derive from the phrase ([`Member::from_owner`]).
#[derive(Clone)]
pub struct Member {
    /// The Ed25519 signing key; its public key is the member id.
    pub signing: SigningKey,
    /// The X25519 private key the data key is wrapped to.
    pub x25519: StaticSecret,
}

impl Member {
    /// A fresh member identity from the CSPRNG.
    #[must_use]
    pub fn generate() -> Member {
        Member {
            signing: SigningKey::from_bytes(&random_bytes::<32>()),
            x25519: x25519_random(),
        }
    }

    /// The owner's member identity (SPEC 3.1: the owner is one member entry).
    #[must_use]
    pub fn from_owner(owner: &OwnerKeys) -> Member {
        Member {
            signing: owner.signing.clone(),
            x25519: owner.x25519.clone(),
        }
    }

    /// The Ed25519 public key.
    #[must_use]
    pub fn ed25519_public(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// The X25519 public key.
    #[must_use]
    pub fn x25519_public(&self) -> [u8; 32] {
        x25519_public(&self.x25519)
    }

    /// The member id written into stamps (`by`): the base64 Ed25519 public key.
    #[must_use]
    pub fn id(&self) -> String {
        b64_encode(&self.ed25519_public())
    }

    /// The key fingerprint to show and compare (SPEC 3.2).
    #[must_use]
    pub fn fingerprint(&self) -> String {
        key_fingerprint(&self.ed25519_public(), &self.x25519_public())
    }
}

// ─── Transport ──────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct Discovery {
    #[serde(rename = "hostKey", with = "b64_array")]
    host_key: [u8; 32],
}

#[derive(Serialize)]
struct ChallengeBody {
    #[serde(rename = "ed25519PublicKey", with = "b64_array")]
    key: [u8; 32],
}

#[derive(Deserialize)]
struct ChallengeAnswer {
    nonce: String,
}

#[derive(Serialize)]
struct TokenBody {
    #[serde(rename = "ed25519PublicKey", with = "b64_array")]
    key: [u8; 32],
    nonce: String,
    #[serde(with = "b64_array")]
    signature: [u8; 64],
}

#[derive(Deserialize)]
struct TokenAnswer {
    token: String,
    #[serde(rename = "expiresAt")]
    expires_at: i64,
}

#[derive(Serialize)]
struct CreateBody<'a> {
    manifest: &'a SignedManifest,
    commit: &'a Commit,
}

#[derive(Serialize)]
struct PullBody {
    #[serde(rename = "sinceManifestSeq")]
    since: i64,
    #[serde(rename = "knownHeads", with = "b64_ids")]
    known: Vec<Id>,
}

#[derive(Serialize)]
struct PushBody<'a> {
    commit: &'a Commit,
}

#[derive(Deserialize)]
struct PushAnswer {
    #[serde(with = "b64_ids")]
    heads: Vec<Id>,
}

#[derive(Serialize)]
struct ManifestBody<'a> {
    manifest: &'a SignedManifest,
    #[serde(skip_serializing_if = "Option::is_none")]
    commit: Option<&'a Commit>,
}

#[derive(Serialize)]
struct PrepareJoinBody<'a> {
    #[serde(rename = "repoId")]
    repo_id: &'a str,
    #[serde(rename = "memberKey", with = "b64_array")]
    member_key: [u8; 32],
}

/// A bearer token minted by one host for one key (SPEC 3.3).
struct Token {
    subject: [u8; 32],
    value: String,
    expires_at: i64,
}

/// A connection to one host, matched by its host key (SPEC 3.3, 11.7).
///
/// It caches the bearer token that host minted and presents it only to that host. Every answer is
/// read up to a size limit and decoded as untrusted input.
pub struct HostClient {
    base: String,
    locator: String,
    key: [u8; 32],
    agent: Agent,
    token: Option<Token>,
}

impl HostClient {
    /// Connects to the host at `url` (`http://host:port`) and learns its host key from
    /// `GET /.well-known/avp` (SPEC 11.7).
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] if the host cannot be reached; [`ClientError::Host`] or
    /// [`ClientError::BadResponse`] if discovery does not answer with a host key.
    pub fn connect(url: &str) -> Result<HostClient> {
        let base = url.trim_end_matches('/').to_string();
        let locator = base
            .strip_prefix("http://")
            .or_else(|| base.strip_prefix("https://"))
            .unwrap_or(&base)
            .to_string();
        let agent: Agent = Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .http_status_as_error(false)
            .max_redirects(0)
            .build()
            .into();
        let mut host = HostClient {
            base,
            locator,
            key: [0; 32],
            agent,
            token: None,
        };
        let (status, bytes) = host.call("/.well-known/avp", None, None)?;
        if status != 200 {
            return Err(host_error(status, &bytes));
        }
        host.key = decode::<Discovery>(&bytes)?.host_key;
        Ok(host)
    }

    /// Connects to `url` and requires its discovery key to be `expected` (a key from a token or a
    /// manifest's `hosts`; hosts are matched by key, never by locator alone, SPEC 11.7).
    ///
    /// # Errors
    ///
    /// As [`HostClient::connect`], and [`ClientError::HostKeyMismatch`] for another key.
    pub fn connect_expecting(url: &str, expected: &[u8; 32]) -> Result<HostClient> {
        let host = HostClient::connect(url)?;
        if !ct_eq(&host.key, expected) {
            return Err(ClientError::HostKeyMismatch);
        }
        Ok(host)
    }

    /// The host key.
    #[must_use]
    pub fn key(&self) -> [u8; 32] {
        self.key
    }

    /// The locator (`host:port`) this client dials.
    #[must_use]
    pub fn locator(&self) -> &str {
        &self.locator
    }

    /// One HTTP exchange: the status and the body, read up to the size limit.
    fn call(&self, path: &str, body: Option<&[u8]>, bearer: Option<&str>) -> Result<(u16, Vec<u8>)> {
        let url = format!("{}{path}", self.base);
        let sent = match body {
            None => self.agent.get(&url).call(),
            Some(bytes) => {
                let mut req = self.agent.post(&url).content_type("application/json");
                if let Some(t) = bearer {
                    req = req.header("Authorization", format!("Bearer {t}"));
                }
                req.send(bytes)
            }
        };
        let mut resp = sent.map_err(|e| ClientError::Transport(e.to_string()))?;
        let status = resp.status().as_u16();
        let bytes = resp
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE_BYTES)
            .read_to_vec()
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        Ok((status, bytes))
    }

    /// An unauthenticated JSON `POST` whose `200` answer decodes as `T`.
    fn post_open<T: DeserializeOwned>(&self, path: &str, body: &impl Serialize) -> Result<T> {
        let (status, bytes) = self.call(path, Some(&encode(body)?), None)?;
        if status != 200 {
            return Err(host_error(status, &bytes));
        }
        decode(&bytes)
    }

    /// A bearer token for `me`, from the cache or from the challenge flow (SPEC 3.3): the client
    /// signs the raw nonce bytes.
    fn token(&mut self, me: &SigningKey) -> Result<String> {
        let subject = me.verifying_key().to_bytes();
        if let Some(t) = &self.token {
            if t.subject == subject && t.expires_at > now_ms().saturating_add(TOKEN_SLACK_MS) {
                return Ok(t.value.clone());
            }
        }
        let ChallengeAnswer { nonce } =
            self.post_open("/api/auth/keypair/challenge", &ChallengeBody { key: subject })?;
        let raw = b64_decode(&nonce).map_err(|_| ClientError::BadResponse("challenge nonce is not base64".into()))?;
        let signature = me.sign(&raw).to_bytes();
        let TokenAnswer { token, expires_at } = self.post_open(
            "/api/auth/keypair/token",
            &TokenBody {
                key: subject,
                nonce,
                signature,
            },
        )?;
        self.token = Some(Token {
            subject,
            value: token.clone(),
            expires_at,
        });
        Ok(token)
    }

    /// An authenticated JSON `POST` as `me` whose `200` answer decodes as `T`. A `401` drops the
    /// cached token and retries once with a fresh one.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`], [`ClientError::Host`] for a non-2xx answer, or
    /// [`ClientError::BadResponse`] for an answer that does not decode.
    pub fn post<T: DeserializeOwned>(&mut self, me: &SigningKey, path: &str, body: &impl Serialize) -> Result<T> {
        let bytes = encode(body)?;
        let mut fresh = false;
        loop {
            let token = self.token(me)?;
            let (status, answer) = self.call(path, Some(&bytes), Some(&token))?;
            match status {
                200 => return decode(&answer),
                401 if !fresh => {
                    self.token = None;
                    fresh = true;
                }
                _ => return Err(host_error(status, &answer)),
            }
        }
    }

    /// Pushes one commit as `me` (SPEC 10.1 `push`), retrying `422 missing_parents` while the host
    /// fetches the parents from its peers. Returns the host's heads.
    ///
    /// # Errors
    ///
    /// As [`HostClient::post`]; a `missing_parents` that outlasts the retries is returned.
    pub fn push(&mut self, me: &SigningKey, repo_id: &str, commit: &Commit) -> Result<Vec<Id>> {
        let path = repo_path(repo_id, "push");
        let mut tries = 0;
        loop {
            match self.post::<PushAnswer>(me, &path, &PushBody { commit }) {
                Err(e) if e.code() == Some("missing_parents") && tries < MISSING_PARENTS_RETRIES => {
                    tries += 1;
                    thread::sleep(RETRY_PAUSE);
                }
                other => return other.map(|a| a.heads),
            }
        }
    }
}

fn encode(body: &impl Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec(body).map_err(|e| ClientError::BadResponse(format!("request body: {e}")))
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|e| ClientError::BadResponse(e.to_string()))
}

/// The SPEC 10.4 error object of a non-2xx answer; the `code` is kept, the message is not parsed.
fn host_error(status: u16, bytes: &[u8]) -> ClientError {
    let body: Value = serde_json::from_slice(bytes).unwrap_or(Value::Null);
    let text = |k: &str| body.get(k).and_then(Value::as_str).map(str::to_string);
    ClientError::Host {
        status,
        code: text("code"),
        message: text("error").unwrap_or_default(),
    }
}

/// The path of a repository route, `repoId` percent-encoded as a path segment (SPEC 10.2).
fn repo_path(repo_id: &str, op: &str) -> String {
    let mut seg = String::with_capacity(repo_id.len());
    for b in repo_id.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            seg.push(char::from(b));
        } else {
            seg.push_str(&format!("%{b:02X}"));
        }
    }
    format!("/v1/repos/{seg}/{op}")
}

// ─── Manifest chain verification (SPEC 6) ───────────────────────────────────────────────

fn distinct(ids: impl IntoIterator<Item = Id>) -> bool {
    let mut seen = HashSet::new();
    ids.into_iter().all(|id| seen.insert(id))
}

/// SPEC 6.1 rule 1: counters in range, the variable-length binary fields at their lengths, no
/// repeated key. Fixed-length fields are already enforced by the decoder.
fn shape_ok(s: &ManifestState) -> bool {
    if s.manifest_seq < 1 || s.key_epoch < 0 {
        return false;
    }
    let (prev_len, nonce_len) = if s.manifest_seq == 1 { (0, 16) } else { (32, 0) };
    s.prev_manifest_hash.len() == prev_len
        && s.genesis_nonce.len() == nonce_len
        && s.members
            .iter()
            .all(|m| m.key_epoch >= 0 && m.wrapped_data_key.ciphertext.len() == 48)
        && s.removals.iter().all(|r| distinct(r.frontier.iter().copied()))
        && distinct(s.hosts.iter().map(|h| h.key))
        && distinct(s.members.iter().map(|m| m.ed25519_public_key))
        && distinct(s.removals.iter().map(|r| r.member_key))
}

/// SPEC 6.2: the genesis state, with `repoId` recomputed from `ownerKey` and `genesisNonce`.
fn genesis_ok(s: &ManifestState) -> bool {
    let Ok(nonce) = <[u8; 16]>::try_from(s.genesis_nonce.as_slice()) else {
        return false;
    };
    let [only] = s.members.as_slice() else {
        return false;
    };
    s.prev_manifest_hash.is_empty()
        && s.key_epoch == 0
        && s.removals.is_empty()
        && only.ed25519_public_key == s.owner_key
        && derive_repo_id(&s.owner_key, &nonce).is_ok_and(|id| id == s.repo_id)
}

/// SPEC 6.1 rule 5: the content rules, and against the previous state when there is one.
fn content_ok(s: &ManifestState, prev: Option<&ManifestState>) -> bool {
    let own = s.members.iter().filter(|m| m.ed25519_public_key == s.owner_key).count() == 1;
    let members_ok = s.members.iter().all(|m| {
        m.key_epoch == s.key_epoch && s.has_host(&m.home_host_key) && s.removal_of(&m.ed25519_public_key).is_none()
    });
    let removals_ok = s
        .removals
        .iter()
        .all(|r| r.removed_at_seq >= 2 && r.removed_at_seq <= s.manifest_seq);
    if s.hosts.is_empty() || !own || !members_ok || !removals_ok {
        return false;
    }
    let Some(prev) = prev else {
        return true;
    };
    let next_epoch = prev.key_epoch.checked_add(1);
    if s.repo_id != prev.repo_id
        || s.owner_key != prev.owner_key
        || s.scheme_id != prev.scheme_id
        || !s.genesis_nonce.is_empty()
        || (s.key_epoch != prev.key_epoch && Some(s.key_epoch) != next_epoch)
    {
        return false;
    }
    // Removals are cumulative and unchanged.
    let kept = prev.removals.iter().all(|r| {
        s.removal_of(&r.member_key).is_some_and(|same| {
            let mut a = same.frontier.clone();
            let mut b = r.frontier.clone();
            a.sort_unstable();
            b.sort_unstable();
            same.removed_at_seq == r.removed_at_seq && a == b
        })
    });
    let added: Vec<&Removal> = s
        .removals
        .iter()
        .filter(|r| prev.removal_of(&r.member_key).is_none())
        .collect();
    let added_ok = added
        .iter()
        .all(|r| r.removed_at_seq == s.manifest_seq && prev.has_member(&r.member_key));
    // Every member that disappears is removed, and never the owner.
    let dropped_ok = prev.members.iter().all(|m| {
        s.has_member(&m.ed25519_public_key)
            || (m.ed25519_public_key != s.owner_key && added.iter().any(|r| r.member_key == m.ed25519_public_key))
    });
    let rotated = added.is_empty() || Some(s.key_epoch) == next_epoch;
    kept && added_ok && dropped_ok && rotated
}

/// Validates one state by SPEC 6.1 rules 1 to 5 (rule 6, the hosted check, is a host rule), against
/// `prev` (the state at `manifestSeq - 1` on the client's chain) or as a genesis state. Returns its
/// `manifestHash`.
///
/// # Errors
///
/// [`ClientError::StateRejected`] naming the first rule that fails.
pub fn validate_state(m: &SignedManifest, prev: Option<&SignedManifest>) -> Result<Id> {
    let s = &m.state;
    if !shape_ok(s) || s.encode().is_err() {
        return Err(ClientError::StateRejected("malformed state"));
    }
    if m.verify().is_err() {
        return Err(ClientError::StateRejected("owner signature does not verify"));
    }
    match prev {
        None => {
            if s.manifest_seq != 1 || !genesis_ok(s) {
                return Err(ClientError::StateRejected("not a valid genesis state"));
            }
        }
        Some(p) => {
            if !m.links_to(p).unwrap_or(false) {
                return Err(ClientError::StateRejected("does not link to the previous state"));
            }
        }
    }
    if !content_ok(s, prev.map(|p| &p.state)) {
        return Err(ClientError::StateRejected("content rules"));
    }
    Ok(m.hash()?)
}

/// The client's verified manifest chain, from genesis to the pinned tip (SPEC 6.4).
///
/// Every state on it passed [`validate_state`] against its predecessor, so the chain is never
/// empty and its genesis fixes `repoId` and `ownerKey`.
#[derive(Debug, Clone)]
pub struct Chain {
    states: Vec<SignedManifest>,
    hashes: Vec<Id>,
    tip: SignedManifest,
    tip_hash: Id,
}

impl Chain {
    fn genesis(m: SignedManifest) -> Result<Chain> {
        let h = validate_state(&m, None)?;
        Ok(Chain {
            states: vec![m.clone()],
            hashes: vec![h],
            tip: m,
            tip_hash: h,
        })
    }

    /// Builds a chain from states in ascending seq, validating each one.
    ///
    /// # Errors
    ///
    /// [`ClientError::StateRejected`] if the list is empty or any state fails.
    pub fn from_states(states: &[SignedManifest]) -> Result<Chain> {
        let (first, rest) = states.split_first().ok_or(ClientError::StateRejected("empty chain"))?;
        let mut c = Chain::genesis(first.clone())?;
        for m in rest {
            c.extend(m.clone())?;
        }
        Ok(c)
    }

    /// The longest valid prefix of `states` and the number of states after it that were discarded.
    fn prefix(states: &[SignedManifest]) -> (Option<Chain>, usize) {
        let Some((first, rest)) = states.split_first() else {
            return (None, 0);
        };
        let Ok(mut c) = Chain::genesis(first.clone()) else {
            return (None, states.len());
        };
        for (i, m) in rest.iter().enumerate() {
            if c.extend(m.clone()).is_err() {
                return (Some(c), rest.len().saturating_sub(i));
            }
        }
        (Some(c), 0)
    }

    /// Appends the state after the tip, if it validates against the tip.
    fn extend(&mut self, m: SignedManifest) -> Result<()> {
        let h = validate_state(&m, Some(&self.tip))?;
        self.states.push(m.clone());
        self.hashes.push(h);
        self.tip = m;
        self.tip_hash = h;
        Ok(())
    }

    /// The states, genesis first.
    #[must_use]
    pub fn states(&self) -> &[SignedManifest] {
        &self.states
    }

    /// The pinned tip: the highest verified state.
    #[must_use]
    pub fn tip(&self) -> &SignedManifest {
        &self.tip
    }

    /// The `manifestHash` of the tip.
    #[must_use]
    pub fn tip_hash(&self) -> Id {
        self.tip_hash
    }

    /// The repository id fixed by genesis.
    #[must_use]
    pub fn repo_id(&self) -> &str {
        &self.tip.state.repo_id
    }

    fn index(seq: i64) -> Option<usize> {
        usize::try_from(seq.checked_sub(1)?).ok()
    }

    /// The fork point with `other` (the index of the first state that differs), or `None` if one
    /// chain is a prefix of the other.
    fn fork(&self, other: &Chain) -> Option<usize> {
        self.hashes.iter().zip(&other.hashes).position(|(a, b)| !ct_eq(a, b))
    }

    /// SPEC 6.4 with the 6.5 exception: `other` is adopted if it contains the pinned state, or if
    /// it diverges at a fork point at or below the pin (never at genesis, which fixes the
    /// repository) and its state there has the bytewise-lower `manifestHash`.
    fn accepts(&self, other: &Chain) -> bool {
        match self.fork(other) {
            None => other.hashes.len() >= self.hashes.len(),
            Some(0) => false,
            Some(i) => matches!((other.hashes.get(i), self.hashes.get(i)), (Some(o), Some(m)) if o < m),
        }
    }

    /// The client checks of SPEC 7.5 for one pulled commit, against this chain.
    ///
    /// 1. The commit decodes for this repository, `commitId` recomputes, and `authorSignature`
    ///    verifies.
    /// 2. Removal cutoff: a head by a removed member passes only if its id is in the removal's
    ///    frontier (removals are cumulative, so the tip holds them all).
    /// 3. Membership: if `(manifestSeq, manifestHash)` is the state on this chain at that seq, the
    ///    author is a member of it and `keyEpoch` is its epoch; otherwise the author is a member of
    ///    some state at or after the cited seq whose epoch is the commit's.
    ///
    /// # Errors
    ///
    /// [`ClientError::CommitRejected`] naming the check that fails.
    pub fn verify_commit(&self, c: &Commit) -> Result<()> {
        if c.repo_id != self.repo_id() || c.ciphertext.len() < 16 || c.manifest_seq < 1 || c.key_epoch < 0 {
            return Err(ClientError::CommitRejected("malformed or another repository"));
        }
        if c.verify().is_err() {
            return Err(ClientError::CommitRejected("id or author signature does not verify"));
        }
        if let Some(r) = self.tip.state.removal_of(&c.author) {
            if !r.frontier.iter().any(|id| ct_eq(id, &c.commit_id)) {
                return Err(ClientError::CommitRejected("removed author outside the frontier"));
            }
        }
        let member_at = |m: &SignedManifest| m.state.has_member(&c.author) && m.state.key_epoch == c.key_epoch;
        let cited = Chain::index(c.manifest_seq).and_then(|i| Some((self.states.get(i)?, self.hashes.get(i)?)));
        let ok = match cited {
            Some((m, h)) if ct_eq(h, &c.manifest_hash) => member_at(m),
            _ => self
                .states
                .iter()
                .filter(|m| m.state.manifest_seq >= c.manifest_seq)
                .any(member_at),
        };
        if !ok {
            return Err(ClientError::CommitRejected(
                "author is not a member at the commit's epoch",
            ));
        }
        Ok(())
    }
}

// ─── Payload edits ──────────────────────────────────────────────────────────────────────

/// Sets one field of an account with `stamp` (SPEC 5 writes), creating the account if needed.
pub fn set_field(payload: &mut PayloadV2, uuid: &str, name: &str, value: Value, stamp: &Stamp) {
    payload.accounts.entry(uuid.to_string()).or_default().fields.insert(
        name.to_string(),
        Field {
            value,
            at: stamp.at,
            n: stamp.n,
            by: stamp.by.clone(),
        },
    );
}

/// Deletes an account by setting its deletion marker to `stamp`; its fields stay (SPEC 5).
pub fn delete_account(payload: &mut PayloadV2, uuid: &str, stamp: &Stamp) {
    payload.accounts.entry(uuid.to_string()).or_default().deleted = Some(stamp.clone());
}

// ─── The vault ──────────────────────────────────────────────────────────────────────────

/// What one pull found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PullReport {
    /// States added to the verified chain.
    pub new_states: usize,
    /// Pulled states that failed SPEC 6.1 and were discarded, with every state after them.
    pub discarded_states: usize,
    /// The host served a chain that does not contain the pinned state and does not win the tie
    /// rule (SPEC 6.4): it was rejected and the pin did not move.
    pub rejected_chain: bool,
    /// Verified heads this device read.
    pub readable_heads: Vec<Id>,
    /// Verified heads this device cannot read (no key for the epoch, a payload that does not
    /// decrypt or is not `v: 2`); left for another member (SPEC 7.5).
    pub unreadable_heads: Vec<Id>,
    /// Heads that failed SPEC 7.5 and were discarded (never merged, never a parent).
    pub discarded_commits: Vec<Id>,
    /// Pulled items that did not decode at all.
    pub malformed_items: usize,
    /// Valid pending leave requests.
    pub leaves: usize,
    /// The merge commit pushed after this pull, if it merged more than one head (SPEC 5).
    pub merge_commit: Option<Id>,
}

/// A pull answer, each item decoded on its own so one malformed item does not hide the rest.
struct PullAnswer {
    manifests: Vec<SignedManifest>,
    heads: Vec<Commit>,
    leaves: Vec<LeaveRequest>,
    malformed: usize,
}

fn items<T: DeserializeOwned>(v: &Value, key: &str, malformed: &mut usize) -> Result<Vec<T>> {
    let list = v
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| ClientError::BadResponse(format!("pull answer has no {key} list")))?;
    let mut out = Vec::with_capacity(list.len());
    for item in list {
        match T::deserialize(item) {
            Ok(x) => out.push(x),
            Err(_) => *malformed += 1,
        }
    }
    Ok(out)
}

fn pull_raw(host: &mut HostClient, me: &Member, repo_id: &str, since: i64) -> Result<PullAnswer> {
    // knownHeads stays empty: the answer then lists every current head, which is how the client
    // learns which of the heads it merged are still heads.
    let v: Value = host.post(
        &me.signing,
        &repo_path(repo_id, "pull"),
        &PullBody {
            since,
            known: Vec::new(),
        },
    )?;
    let mut malformed = 0;
    Ok(PullAnswer {
        manifests: items(&v, "manifests", &mut malformed)?,
        heads: items(&v, "heads", &mut malformed)?,
        leaves: items(&v, "leaves", &mut malformed)?,
        malformed,
    })
}

/// The ancestry this device learned of one verified commit.
struct Seen {
    author: Id,
    parents: Vec<Id>,
}

/// One member device's copy of one repository, synced through its home host.
pub struct Vault {
    host: HostClient,
    me: Member,
    chain: Chain,
    /// Every data key this device has held, by `keyEpoch`, so it can read and merge old-epoch heads
    /// forward after a rotation (SPEC 7.5 SHOULD).
    pub retained_epoch_keys: HashMap<i64, [u8; 32]>,
    local: PayloadV2,
    hlc: Hlc,
    heads: Vec<Id>,
    unreadable: Vec<Id>,
    incoming: Vec<PayloadV2>,
    seen: HashMap<Id, Seen>,
    leaves: Vec<LeaveRequest>,
    left: bool,
}

/// Shows the repository and sync position only; never a key or a plaintext.
impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("repo_id", &self.repo_id())
            .field("manifest_seq", &self.tip().state.manifest_seq)
            .field("heads", &self.heads.len())
            .field("left", &self.left)
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Creates a repository on the owner's home host (SPEC 8.2 initial host): a random genesis
    /// nonce, a fresh epoch-0 data key wrapped to the owner, the genesis state listing `host`, and
    /// an empty first commit, sent together with `createRepo`.
    ///
    /// # Errors
    ///
    /// [`ClientError::Host`] if the host refuses; [`ClientError::Transport`] if it cannot be
    /// reached.
    pub fn create(mut host: HostClient, owner: &OwnerKeys) -> Result<Vault> {
        let me = Member::from_owner(owner);
        let owner_key = owner.owner_key();
        let nonce = random_bytes::<16>();
        let repo_id = derive_repo_id(&owner_key, &nonce)?;
        let data_key = random_bytes::<32>();
        let state = ManifestState {
            repo_id: repo_id.clone(),
            manifest_seq: 1,
            prev_manifest_hash: Vec::new(),
            owner_key,
            genesis_nonce: nonce.to_vec(),
            scheme_id: SCHEME_ID.to_string(),
            key_epoch: 0,
            share_refresh_tokens: false,
            hosts: vec![HostRef {
                key: host.key(),
                locator: host.locator().to_string(),
            }],
            members: vec![MemberEntry {
                ed25519_public_key: owner_key,
                x25519_public_key: owner.x25519_public(),
                wrapped_data_key: wrap(&owner.x25519_public(), &data_key, WRAP_INFO)?,
                key_epoch: 0,
                home_host_key: host.key(),
            }],
            removals: Vec::new(),
        };
        let genesis = state.sign(&owner.signing)?;
        let chain = Chain::genesis(genesis.clone())?;
        let header = CommitHeader {
            repo_id,
            parents: Vec::new(),
            manifest_seq: 1,
            manifest_hash: chain.tip_hash(),
            key_epoch: 0,
        };
        let first = Commit::seal(&data_key, header, &PayloadV2::default().to_json()?, &owner.signing)?;
        let _: Value = host.post(
            &me.signing,
            "/v1/repos",
            &CreateBody {
                manifest: &genesis,
                commit: &first,
            },
        )?;
        let mut v = Vault::new(host, me, chain);
        v.retained_epoch_keys.insert(0, data_key);
        v.record(&first);
        v.heads = vec![first.commit_id];
        Ok(v)
    }

    /// Opens a repository this device is a member of from its home host: pulls the whole chain,
    /// verifies it from genesis, unwraps every data key it was given, and reads the heads.
    ///
    /// # Errors
    ///
    /// [`ClientError::Host`] if the host does not serve it (`404`, `403` for a non-member);
    /// [`ClientError::StateRejected`] if the chain does not verify or is another repository;
    /// [`ClientError::NotPermitted`] if the verified tip does not list this member.
    pub fn open(host: HostClient, me: Member, repo_id: &str) -> Result<Vault> {
        Vault::open_checked(host, me, repo_id, |_| Ok(()))
    }

    /// Joins a repository after the owner's invite (SPEC 8.1): [`Vault::open`] from the joiner's
    /// home host, plus the SPEC 11.2 check that the genesis `ownerKey` matches the locator's
    /// `ownerFingerprint`.
    ///
    /// # Errors
    ///
    /// As [`Vault::open`], and [`ClientError::OwnerMismatch`] for another owner key.
    pub fn join(host: HostClient, me: Member, locator: &RepoLocator) -> Result<Vault> {
        let expected = locator.owner_fingerprint.clone();
        Vault::open_checked(host, me, &locator.repo_id, move |chain| {
            let genesis_owner = chain.states().first().map(|g| g.state.owner_key);
            match genesis_owner {
                Some(k) if ct_eq(owner_fingerprint(&k).as_bytes(), expected.as_bytes()) => Ok(()),
                _ => Err(ClientError::OwnerMismatch),
            }
        })
    }

    fn open_checked(
        mut host: HostClient,
        me: Member,
        repo_id: &str,
        check: impl FnOnce(&Chain) -> Result<()>,
    ) -> Result<Vault> {
        let answer = pull_raw(&mut host, &me, repo_id, 0)?;
        let (chain, _) = Chain::prefix(&answer.manifests);
        let chain = chain.ok_or(ClientError::StateRejected("no valid genesis state"))?;
        if chain.repo_id() != repo_id {
            return Err(ClientError::StateRejected("the chain is another repository"));
        }
        check(&chain)?;
        if !chain.tip().state.has_member(&me.ed25519_public()) {
            return Err(ClientError::NotPermitted(
                "this device is not a member of the verified tip",
            ));
        }
        let mut v = Vault::new(host, me, chain);
        v.adopt_keys(0);
        let mut report = PullReport::default();
        v.take_heads(answer.heads, &mut report);
        v.take_leaves(answer.leaves, &mut report);
        v.merge_heads()?;
        Ok(v)
    }

    fn new(host: HostClient, me: Member, chain: Chain) -> Vault {
        Vault {
            host,
            me,
            chain,
            retained_epoch_keys: HashMap::new(),
            local: PayloadV2::default(),
            hlc: Hlc::default(),
            heads: Vec::new(),
            unreadable: Vec::new(),
            incoming: Vec::new(),
            seen: HashMap::new(),
            leaves: Vec::new(),
            left: false,
        }
    }

    // ── Accessors ──

    /// The repository id.
    #[must_use]
    pub fn repo_id(&self) -> &str {
        self.chain.repo_id()
    }

    /// The verified chain.
    #[must_use]
    pub fn chain(&self) -> &Chain {
        &self.chain
    }

    /// The pinned tip state.
    #[must_use]
    pub fn tip(&self) -> &SignedManifest {
        self.chain.tip()
    }

    /// The `manifestHash` of the pinned tip.
    #[must_use]
    pub fn tip_hash(&self) -> Id {
        self.chain.tip_hash()
    }

    /// The local payload: the merge of every head this device has read, stripped by policy.
    #[must_use]
    pub fn payload(&self) -> &PayloadV2 {
        &self.local
    }

    /// The readable heads the local payload covers; the parents of the next write.
    #[must_use]
    pub fn heads(&self) -> &[Id] {
        &self.heads
    }

    /// The verified heads this device could not read at the last pull.
    #[must_use]
    pub fn unreadable_heads(&self) -> &[Id] {
        &self.unreadable
    }

    /// The hybrid logical clock.
    #[must_use]
    pub fn hlc(&self) -> Hlc {
        self.hlc
    }

    /// This device's member identity.
    #[must_use]
    pub fn member(&self) -> &Member {
        &self.me
    }

    /// The valid pending leave requests of the last pull.
    #[must_use]
    pub fn leaves(&self) -> &[LeaveRequest] {
        &self.leaves
    }

    /// The home host connection.
    pub fn host_mut(&mut self) -> &mut HostClient {
        &mut self.host
    }

    /// A repo locator naming this device's host as the owner's home host (SPEC 11.2).
    ///
    /// # Errors
    ///
    /// [`ClientError::NotPermitted`] unless this device is the owner.
    pub fn locator(&self) -> Result<RepoLocator> {
        self.require_owner()?;
        Ok(RepoLocator {
            v: V2,
            repo_id: self.repo_id().to_string(),
            host_key: self.host.key(),
            host_locator: self.host.locator().to_string(),
            owner_fingerprint: owner_fingerprint(&self.tip().state.owner_key),
        })
    }

    fn share_refresh(&self) -> bool {
        // SPEC 5.1 fail closed: on only when the latest verified state says `true`.
        self.chain.tip().state.share_refresh_tokens
    }

    fn is_owner(&self) -> bool {
        self.chain.tip().state.owner_key == self.me.ed25519_public()
    }

    fn require_owner(&self) -> Result<()> {
        if self.is_owner() {
            Ok(())
        } else {
            Err(ClientError::NotPermitted("only the owner changes the manifest"))
        }
    }

    fn require_syncing(&self) -> Result<()> {
        if self.left { Err(ClientError::Left) } else { Ok(()) }
    }

    // ── Pull ──

    /// Pulls from the home host and merges (SPEC 5, 6.4, 7.5, 10.1): verifies every new state and
    /// pins the highest, checks every head, reads the heads it can, and pushes a merge commit when
    /// more than one head is readable.
    ///
    /// # Errors
    ///
    /// [`ClientError::Left`] after [`Vault::leave`]; [`ClientError::Host`] or
    /// [`ClientError::Transport`] if the host does not answer; an unreadable head or a discarded
    /// state or commit is not an error (see the report).
    pub fn pull(&mut self) -> Result<PullReport> {
        let mut report = self.fetch()?;
        report.merge_commit = self.merge_heads()?;
        Ok(report)
    }

    /// The pull without the merge push.
    fn fetch(&mut self) -> Result<PullReport> {
        self.require_syncing()?;
        let repo_id = self.repo_id().to_string();
        let mut answer = pull_raw(&mut self.host, &self.me, &repo_id, self.chain.tip().state.manifest_seq)?;
        let mut report = PullReport {
            malformed_items: answer.malformed,
            ..PullReport::default()
        };
        let linked = match answer.manifests.first() {
            None => true,
            Some(first) => first.links_to(self.chain.tip()).unwrap_or(false),
        };
        if linked {
            let before = self.chain.states().len();
            let total = answer.manifests.len();
            for (i, m) in answer.manifests.drain(..).enumerate() {
                if self.chain.extend(m).is_err() {
                    report.discarded_states = total.saturating_sub(i);
                    break;
                }
            }
            report.new_states = self.chain.states().len().saturating_sub(before);
            self.adopt_keys(before);
        } else {
            // SPEC 6.4: the first state does not link to the pin; pull the whole chain and decide.
            answer = pull_raw(&mut self.host, &self.me, &repo_id, 0)?;
            report.malformed_items = report.malformed_items.saturating_add(answer.malformed);
            let (candidate, discarded) = Chain::prefix(&answer.manifests);
            report.discarded_states = discarded;
            match candidate {
                Some(c) if self.chain.accepts(&c) => {
                    let from = self.chain.fork(&c).unwrap_or(self.chain.states().len());
                    report.new_states = c.states().len().saturating_sub(from);
                    self.chain = c;
                    self.adopt_keys(from);
                }
                _ => report.rejected_chain = true,
            }
        }
        if !self.share_refresh() {
            self.local.strip_refresh();
        }
        self.take_heads(answer.heads, &mut report);
        self.take_leaves(answer.leaves, &mut report);
        Ok(report)
    }

    /// Unwraps this member's data key from every chain state from index `from` on.
    fn adopt_keys(&mut self, from: usize) {
        let me = self.me.ed25519_public();
        for m in self.chain.states().iter().skip(from) {
            let Some(entry) = m.state.members.iter().find(|e| e.ed25519_public_key == me) else {
                continue;
            };
            let key = unwrap(&self.me.x25519, &entry.wrapped_data_key, WRAP_INFO)
                .ok()
                .and_then(|k| <[u8; 32]>::try_from(k).ok());
            if let Some(k) = key {
                self.retained_epoch_keys.insert(m.state.key_epoch, k);
            }
        }
    }

    fn record(&mut self, c: &Commit) {
        self.seen.insert(
            c.commit_id,
            Seen {
                author: c.author,
                parents: c.parents.clone(),
            },
        );
    }

    /// Checks every pulled head (SPEC 7.5), then sorts the valid ones into readable and unreadable.
    fn take_heads(&mut self, heads: Vec<Commit>, report: &mut PullReport) {
        self.heads.clear();
        self.unreadable.clear();
        self.incoming.clear();
        let mut once = HashSet::new();
        for c in heads {
            if !once.insert(c.commit_id) {
                continue;
            }
            if self.chain.verify_commit(&c).is_err() {
                report.discarded_commits.push(c.commit_id);
                continue;
            }
            self.record(&c);
            match self.read(&c) {
                Some(p) => {
                    self.heads.push(c.commit_id);
                    self.incoming.push(p);
                    report.readable_heads.push(c.commit_id);
                }
                None => {
                    self.unreadable.push(c.commit_id);
                    report.unreadable_heads.push(c.commit_id);
                }
            }
        }
    }

    /// Decrypts a verified commit with the retained key of its epoch; `None` if this device cannot
    /// read it. Strips on read when the policy is not `true` (SPEC 5.1).
    fn read(&self, c: &Commit) -> Option<PayloadV2> {
        let key = self.retained_epoch_keys.get(&c.key_epoch)?;
        let plain = c.open(key).ok()?;
        let mut p = PayloadV2::from_json(&plain).ok()?;
        if !self.share_refresh() {
            p.strip_refresh();
        }
        Some(p)
    }

    /// Keeps the leave requests that verify for a current, non-owner member (SPEC 8.4).
    fn take_leaves(&mut self, leaves: Vec<LeaveRequest>, report: &mut PullReport) {
        let s = &self.chain.tip().state;
        self.leaves = leaves
            .into_iter()
            .filter(|l| {
                l.verify().is_ok()
                    && l.repo_id == s.repo_id
                    && s.has_member(&l.member_key)
                    && l.member_key != s.owner_key
            })
            .collect();
        report.leaves = self.leaves.len();
    }

    /// Merges the payloads read at the last pull into the local payload, after observing every one
    /// of their stamps (SPEC 5).
    fn absorb(&mut self) {
        let incoming = std::mem::take(&mut self.incoming);
        for p in &incoming {
            for s in p.stamps() {
                self.hlc.observe(&s);
            }
        }
        let mut all = Vec::with_capacity(incoming.len().saturating_add(1));
        all.push(std::mem::take(&mut self.local));
        all.extend(incoming);
        self.local = merge(&all);
        if !self.share_refresh() {
            self.local.strip_refresh();
        }
    }

    /// Merges every readable head into the local payload and, when more than one head is readable,
    /// pushes the merge commit whose parents are exactly those heads (SPEC 5). Unreadable heads are
    /// skipped: never merged, never parents (SPEC 7.5).
    ///
    /// # Errors
    ///
    /// [`ClientError::Left`] after [`Vault::leave`]; the push's errors.
    pub fn merge_heads(&mut self) -> Result<Option<Id>> {
        self.require_syncing()?;
        self.absorb();
        if self.heads.len() < 2 {
            return Ok(None);
        }
        let payload = self.local.clone();
        self.commit_payload(self.heads.clone(), &payload).map(Some)
    }

    // ── Write ──

    /// One edit (SPEC 5): `f` changes a copy of the local payload, taking its stamps from the clock
    /// with [`Hlc::tick`] after every stamp seen has been observed. The result is stripped by policy
    /// (SPEC 5.1), encrypted under the current epoch with the readable heads as parents, and
    /// pushed. Returns the new commit id.
    ///
    /// # Errors
    ///
    /// [`ClientError::Left`] after [`Vault::leave`]; [`ClientError::NoKey`] without the current
    /// epoch's key; [`ClientError::Host`] if the host refuses the push.
    pub fn write(&mut self, f: impl FnOnce(&mut PayloadV2, &mut Hlc)) -> Result<Id> {
        self.require_syncing()?;
        self.absorb();
        for s in self.local.stamps() {
            self.hlc.observe(&s);
        }
        let mut next = self.local.clone();
        f(&mut next, &mut self.hlc);
        if !self.share_refresh() {
            next.strip_refresh();
        }
        let id = self.commit_payload(self.heads.clone(), &next)?;
        self.local = next;
        Ok(id)
    }

    /// Seals `payload` under the tip's epoch, citing the tip, and pushes it.
    fn commit_payload(&mut self, parents: Vec<Id>, payload: &PayloadV2) -> Result<Id> {
        let tip = self.chain.tip();
        let epoch = tip.state.key_epoch;
        let key = *self.retained_epoch_keys.get(&epoch).ok_or(ClientError::NoKey(epoch))?;
        let header = CommitHeader {
            repo_id: tip.state.repo_id.clone(),
            parents,
            manifest_seq: tip.state.manifest_seq,
            manifest_hash: self.chain.tip_hash(),
            key_epoch: epoch,
        };
        let mut plain = payload.clone();
        if !self.share_refresh() {
            plain.strip_refresh();
        }
        let c = Commit::seal(&key, header, &plain.to_json()?, &self.me.signing)?;
        let repo_id = self.repo_id().to_string();
        self.host.push(&self.me.signing, &repo_id, &c)?;
        self.record(&c);
        self.heads = vec![c.commit_id];
        Ok(c.commit_id)
    }

    // ── Owner operations (SPEC 8) ──

    /// The next state after the tip, changed by `f` and signed by the owner.
    fn sign_next(&self, f: impl FnOnce(&mut ManifestState)) -> Result<SignedManifest> {
        let tip = self.chain.tip();
        let mut s = tip.state.clone();
        s.manifest_seq = tip
            .state
            .manifest_seq
            .checked_add(1)
            .ok_or(ClientError::StateRejected("manifestSeq overflow"))?;
        s.prev_manifest_hash = self.chain.tip_hash().to_vec();
        s.genesis_nonce = Vec::new();
        f(&mut s);
        Ok(s.sign(&self.me.signing)?)
    }

    /// Publishes a signed next state (with its commit) and, once the host accepts it, pins it. The
    /// state is validated against the tip first, so the owner never publishes what a client rejects.
    fn publish(&mut self, signed: SignedManifest, commit: Option<&Commit>) -> Result<()> {
        let mut next = self.chain.clone();
        next.extend(signed.clone())?;
        let path = repo_path(self.repo_id(), "manifest");
        let body = ManifestBody {
            manifest: &signed,
            commit,
        };
        let mut tries = 0;
        loop {
            match self.host.post::<Value>(&self.me.signing, &path, &body) {
                Err(e) if e.code() == Some("missing_parents") && tries < MISSING_PARENTS_RETRIES => {
                    tries += 1;
                    thread::sleep(RETRY_PAUSE);
                }
                Err(e) => return Err(e),
                Ok(_) => break,
            }
        }
        let from = self.chain.states().len();
        self.chain = next;
        self.adopt_keys(from);
        if !self.share_refresh() {
            self.local.strip_refresh();
        }
        Ok(())
    }

    /// Runs `attempt` again after a pull when the host answers `409 manifest_conflict` (SPEC 6.3).
    fn retry_conflict<T>(&mut self, mut attempt: impl FnMut(&mut Vault) -> Result<T>) -> Result<T> {
        let mut tries = 0;
        loop {
            match attempt(self) {
                Err(e) if e.code() == Some("manifest_conflict") && tries < CONFLICT_RETRIES => tries += 1,
                other => return other,
            }
        }
    }

    /// Invites a member from an invite token (SPEC 8.1, 8.2). The token's acceptance must verify
    /// under its `hostKey`, name this repository and the token's Ed25519 key, name the token's home
    /// host, and not have expired. The current data key is wrapped to exactly the token's X25519 key,
    /// never to a key served by a host, and the home host is added to `hosts` if missing.
    ///
    /// # Errors
    ///
    /// [`ClientError::InviteRefused`] for a token that fails verification, a current member, or a
    /// removed key; [`ClientError::NotPermitted`] unless this device is the owner; the publish's
    /// errors.
    pub fn invite(&mut self, token: &InviteToken) -> Result<()> {
        self.require_owner()?;
        token.verify(self.repo_id(), now_ms()).map_err(|_| {
            ClientError::InviteRefused("the acceptance does not verify for this repository, member, and home host")
        })?;
        self.retry_conflict(|v| {
            v.pull()?;
            let s = &v.chain.tip().state;
            if s.has_member(&token.ed25519_public_key) {
                return Err(ClientError::InviteRefused("already a member"));
            }
            if s.removal_of(&token.ed25519_public_key).is_some() {
                return Err(ClientError::InviteRefused("a removed key is never a member again"));
            }
            let epoch = s.key_epoch;
            let key = *v.retained_epoch_keys.get(&epoch).ok_or(ClientError::NoKey(epoch))?;
            let entry = MemberEntry {
                ed25519_public_key: token.ed25519_public_key,
                x25519_public_key: token.x25519_public_key,
                wrapped_data_key: wrap(&token.x25519_public_key, &key, WRAP_INFO)?,
                key_epoch: epoch,
                home_host_key: token.home_host_key,
            };
            let signed = v.sign_next(|n| {
                n.members.push(entry);
                if !n.has_host(&token.home_host_key) {
                    n.hosts.push(HostRef {
                        key: token.home_host_key,
                        locator: token.home_host_locator.clone(),
                    });
                }
            })?;
            v.publish(signed, None)
        })
    }

    /// Removes a member (SPEC 8.3) in one `publishManifest`: pulls and merges every readable head,
    /// generates the next epoch's data key and wraps it to every remaining member, drops the member
    /// with a removal whose frontier is every merged head plus every verified commit by the member
    /// that is not an ancestor of one, and carries the rotation commit (the merged state under the
    /// new epoch, parents the merged heads, citing the new state) with the state.
    ///
    /// # Errors
    ///
    /// [`ClientError::NotPermitted`] unless this device is the owner, for the owner key, or for a
    /// key that is not a member; the pull's and the publish's errors.
    pub fn remove(&mut self, member: [u8; 32]) -> Result<()> {
        self.require_owner()?;
        if member == self.me.ed25519_public() {
            return Err(ClientError::NotPermitted("the owner is never removed"));
        }
        self.retry_conflict(|v| {
            v.fetch()?;
            v.absorb();
            let tip = v.chain.tip();
            if !tip.state.has_member(&member) {
                return Err(ClientError::NotPermitted("not a member"));
            }
            let epoch = tip
                .state
                .key_epoch
                .checked_add(1)
                .ok_or(ClientError::StateRejected("keyEpoch overflow"))?;
            let new_key = random_bytes::<32>();
            let mut members = Vec::with_capacity(tip.state.members.len());
            for m in tip.state.members.iter().filter(|m| m.ed25519_public_key != member) {
                members.push(MemberEntry {
                    wrapped_data_key: wrap(&m.x25519_public_key, &new_key, WRAP_INFO)?,
                    key_epoch: epoch,
                    ..m.clone()
                });
            }
            let parents = v.heads.clone();
            let frontier = v.frontier(&member, &parents);
            let signed = v.sign_next(|n| {
                n.key_epoch = epoch;
                n.members = members;
                n.removals.push(Removal {
                    member_key: member,
                    removed_at_seq: n.manifest_seq,
                    frontier,
                });
            })?;
            let mut payload = v.local.clone();
            if !signed.state.share_refresh_tokens {
                payload.strip_refresh();
            }
            let header = CommitHeader {
                repo_id: signed.state.repo_id.clone(),
                parents,
                manifest_seq: signed.state.manifest_seq,
                manifest_hash: signed.hash()?,
                key_epoch: epoch,
            };
            let rotation = Commit::seal(&new_key, header, &payload.to_json()?, &v.me.signing)?;
            v.publish(signed, Some(&rotation))?;
            v.retained_epoch_keys.insert(epoch, new_key);
            v.record(&rotation);
            v.heads = vec![rotation.commit_id];
            v.leaves.retain(|l| l.member_key != member);
            Ok(())
        })
    }

    /// The removal frontier (SPEC 8.3): the merged heads, plus every verified commit by `member`
    /// that is not one of them or an ancestor of one, sorted.
    fn frontier(&self, member: &Id, heads: &[Id]) -> Vec<Id> {
        let mut ancestors = HashSet::new();
        let mut stack: Vec<Id> = heads.to_vec();
        while let Some(id) = stack.pop() {
            if let Some(s) = self.seen.get(&id) {
                for p in &s.parents {
                    if ancestors.insert(*p) {
                        stack.push(*p);
                    }
                }
            }
        }
        let mut out: Vec<Id> = heads.to_vec();
        for (id, s) in &self.seen {
            if s.author == *member && !ancestors.contains(id) && !out.contains(id) {
                out.push(*id);
            }
        }
        out.sort_unstable();
        out
    }

    /// Sets the refresh-token policy (SPEC 5.1, 8.5): a new owner-signed state, no commit.
    ///
    /// # Errors
    ///
    /// [`ClientError::NotPermitted`] unless this device is the owner; the publish's errors.
    pub fn set_share_refresh_tokens(&mut self, on: bool) -> Result<()> {
        self.require_owner()?;
        self.retry_conflict(|v| {
            v.pull()?;
            let signed = v.sign_next(|n| n.share_refresh_tokens = on)?;
            v.publish(signed, None)
        })
    }

    /// Leaves the repository (SPEC 8.4): sends a signed leave request and stops syncing at once;
    /// every later pull and write is [`ClientError::Left`].
    ///
    /// # Errors
    ///
    /// [`ClientError::NotPermitted`] for the owner; the host's errors.
    pub fn leave(&mut self) -> Result<()> {
        self.require_syncing()?;
        if self.is_owner() {
            return Err(ClientError::NotPermitted("the owner cannot leave"));
        }
        let request = LeaveRequest {
            repo_id: self.repo_id().to_string(),
            member_key: [0; 32],
            at: now_ms(),
            signature: [0; 64],
        }
        .sign(&self.me.signing)?;
        let path = repo_path(self.repo_id(), "leave");
        let _: Value = self.host.post(&self.me.signing, &path, &request)?;
        self.left = true;
        self.heads.clear();
        self.incoming.clear();
        Ok(())
    }

    /// Processes pending leave requests (SPEC 8.4): pulls, then removes each leaving member that is
    /// still a member, one removal each. Returns the removed keys.
    ///
    /// # Errors
    ///
    /// [`ClientError::NotPermitted`] unless this device is the owner; the pull's and the removals'
    /// errors.
    pub fn process_leaves(&mut self) -> Result<Vec<[u8; 32]>> {
        self.require_owner()?;
        self.pull()?;
        let pending: Vec<[u8; 32]> = self.leaves.iter().map(|l| l.member_key).collect();
        let mut removed = Vec::new();
        for key in pending {
            if self.chain.tip().state.has_member(&key) {
                self.remove(key)?;
                removed.push(key);
            }
        }
        Ok(removed)
    }
}

/// The joiner's step 2 of SPEC 8.1: asks its home host to carry `repo_id` (`prepareJoin`, SPEC 8.2),
/// checks the acceptance the host signed, and builds the invite token for the owner.
///
/// # Errors
///
/// [`ClientError::Host`] if the host refuses to carry the repository; [`ClientError::BadResponse`]
/// if the acceptance does not verify under the host's key or names another repository or member.
pub fn prepare_join(host: &mut HostClient, me: &Member, repo_id: &str) -> Result<InviteToken> {
    let member_key = me.ed25519_public();
    let acceptance: Acceptance = host.post(
        &me.signing,
        "/v1/prepare-join",
        &PrepareJoinBody { repo_id, member_key },
    )?;
    let ok = acceptance.verify_under(&host.key()).is_ok()
        && ct_eq(&acceptance.host_key, &host.key())
        && acceptance.repo_id == repo_id
        && ct_eq(&acceptance.member_key, &member_key);
    if !ok {
        return Err(ClientError::BadResponse("the acceptance does not verify".into()));
    }
    Ok(InviteToken {
        v: V2,
        ed25519_public_key: member_key,
        x25519_public_key: me.x25519_public(),
        home_host_key: host.key(),
        home_host_locator: host.locator().to_string(),
        acceptance,
    })
}
