// SPDX-License-Identifier: MIT

//! Routing, the client-facing operations of SPEC 10 over HTTP/JSON (SPEC 10.2), and the host routes
//! of the reference host-to-host profile (SPEC 9.3).
//!
//! Each request goes through the same steps: the body is read up to the size limit (`413`), the
//! route is matched (`404`), the bearer token is checked (`401`, every route but discovery and the
//! two auth routes), the body is decoded (`400`), the repository is looked up (`404 not_found`,
//! `403 not_hosted`), the caller is matched against the key SPEC 10.1 requires (`403 forbidden`),
//! and the item goes to the [`RepoView`] engine, whose [`RejectCode`] maps to the SPEC 10.4 status.
//! An accepted client write is queued for the repository's other hosts (SPEC 9.2).
//!
//! A host route answers `503` while replication is paused by the test control, then checks the host
//! request signature (`401`), decodes the body (`400`), and checks the repository: `404 not_found`
//! if not held, `403 not_hosted` if this host's winning tip does not list it, `403 forbidden` if
//! that tip does not list the calling peer (SPEC 9.2). `offer` instead checks the received tip
//! after validating the items ([`replication::receive`]).
//!
//! No path panics on input. Request bodies are never logged.

use std::collections::HashSet;
use std::io::Read;
use std::sync::Mutex;

use avp::RejectCode;
use avp::commit::Commit;
use avp::encoding::{b64, b64_array, b64_encode, b64_ids, b64url_decode};
use avp::manifest::SignedManifest;
use avp::rules::{RepoView, Via};
use avp::tokens::{Acceptance, LeaveRequest};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tiny_http::{Header, Method, Request, Response};

use crate::State;
use crate::auth::{AuthError, CHALLENGE_TTL_MS, Caps};
use crate::replication::{
    self, Admitted, FetchBody, HEADER_KEY, HEADER_SIGNATURE, HEADER_TIME, HeadsBody, HeadsReply, HostHeaders, Items,
    MAX_ITEMS, ManifestTip, OfferBody, Outgoing,
};

/// How long an acceptance from `prepareJoin` stays valid (SPEC 8.2: the reference hosts use 15
/// minutes).
pub const ACCEPTANCE_TTL_MS: i64 = 15 * 60 * 1000;

/// The protocol version in discovery (SPEC 11.7).
const VERSION: &str = "0.5";

// ─── Errors ─────────────────────────────────────────────────────────────────────────────

/// An error answer: the status, the SPEC 10.4 `code`, a human message, and optional `detail`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ApiError {
    status: u16,
    code: Option<&'static str>,
    message: String,
    detail: Option<String>,
    retry_after_s: Option<i64>,
}

impl ApiError {
    fn new(status: u16, code: &'static str, message: impl Into<String>) -> ApiError {
        ApiError {
            status,
            code: Some(code),
            message: message.into(),
            detail: None,
            retry_after_s: None,
        }
    }

    fn bad_request(message: impl Into<String>) -> ApiError {
        ApiError::new(400, "bad_request", message)
    }

    fn unauthorized(message: &str) -> ApiError {
        ApiError::new(401, "unauthorized", message)
    }

    fn forbidden(message: &str) -> ApiError {
        ApiError::new(403, "forbidden", message)
    }

    fn not_found(message: &str) -> ApiError {
        ApiError::new(404, "not_found", message)
    }

    fn quota(message: &str) -> ApiError {
        ApiError::new(429, "quota_exceeded", message)
    }

    fn too_large() -> ApiError {
        ApiError::new(413, "too_large", "request body too large")
    }

    /// `503` while replication is paused by the test control (SPEC 9.3); SPEC 10.4 has no code.
    fn paused() -> ApiError {
        ApiError {
            status: 503,
            code: None,
            message: "replication is paused".to_string(),
            detail: None,
            retry_after_s: None,
        }
    }

    /// A failure that is not the caller's fault (a poisoned lock, a failed serialization).
    fn internal() -> ApiError {
        ApiError {
            status: 500,
            code: None,
            message: "internal error".to_string(),
            detail: None,
            retry_after_s: None,
        }
    }

    /// The SPEC 10.4 answer for an engine verdict.
    fn reject(code: RejectCode) -> ApiError {
        let (status, message) = match code {
            RejectCode::BadRequest => (400, "malformed or invalid item"),
            RejectCode::Forbidden => (403, "not allowed by the repository's manifest"),
            RejectCode::NotHosted => (403, "this host is not in the manifest's hosts"),
            RejectCode::TooManyHeads => (409, "too many heads; merge first"),
            RejectCode::ManifestConflict => (409, "manifest state is not the tip + 1"),
            RejectCode::MissingParents => (422, "unknown parent, manifest state, or frontier commit"),
            _ => (400, "rejected"),
        };
        ApiError::new(status, code.as_str(), message)
    }

    /// `422 missing_parents` with `detail` listing the missing ids, base64, separated by `,`
    /// (SPEC 7.4, 10.4).
    fn missing(ids: &[[u8; 32]]) -> ApiError {
        let mut e = ApiError::reject(RejectCode::MissingParents);
        if !ids.is_empty() {
            e.detail = Some(ids.iter().map(|id| b64_encode(id)).collect::<Vec<_>>().join(","));
        }
        e
    }

    fn body(&self) -> Value {
        let mut v = json!({ "error": self.message });
        if let Some(code) = self.code {
            v["code"] = json!(code);
        }
        if let Some(detail) = &self.detail {
            v["detail"] = json!(detail);
        }
        v
    }
}

type Answer = Result<Value, ApiError>;

/// Serializes a response value; a failure here is the host's, not the caller's.
fn to_json<T: Serialize>(v: &T) -> Answer {
    serde_json::to_value(v).map_err(|_| ApiError::internal())
}

/// Decodes a JSON body; any malformed body, missing field, wrong type, bad base64, or wrong
/// binary length is `400 bad_request`.
fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|e| ApiError::bad_request(format!("malformed body: {e}")))
}

// ─── Request and response bodies (schema/avp.schema.json) ───────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeBody {
    #[serde(rename = "ed25519PublicKey", with = "b64_array")]
    key: [u8; 32],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenBody {
    #[serde(rename = "ed25519PublicKey", with = "b64_array")]
    key: [u8; 32],
    #[serde(with = "b64")]
    nonce: Vec<u8>,
    #[serde(with = "b64_array")]
    signature: [u8; 64],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRepoBody {
    manifest: SignedManifest,
    commit: Commit,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PullBody {
    #[serde(rename = "sinceManifestSeq")]
    since: i64,
    #[serde(rename = "knownHeads", with = "b64_ids")]
    known: Vec<[u8; 32]>,
}

#[derive(Serialize)]
struct PullReply<'a> {
    manifests: Vec<SignedManifest>,
    heads: Vec<Commit>,
    leaves: &'a [LeaveRequest],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PushBody {
    commit: Commit,
}

#[derive(Serialize)]
struct PushReply {
    accepted: bool,
    #[serde(with = "b64_ids")]
    heads: Vec<[u8; 32]>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestBody {
    manifest: SignedManifest,
    #[serde(default)]
    commit: Option<Commit>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TestControlBody {
    paused: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareJoinBody {
    #[serde(rename = "repoId")]
    repo_id: String,
    #[serde(rename = "memberKey", with = "b64_array")]
    member_key: [u8; 32],
}

// ─── Routing ────────────────────────────────────────────────────────────────────────────

/// A repository operation of SPEC 10.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RepoOp {
    Pull,
    Push,
    Manifest,
    Leave,
}

/// A host route of SPEC 9.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostOp {
    Heads,
    Fetch,
    Offer,
}

/// A matched route.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Route {
    Discovery,
    Challenge,
    Token,
    CreateRepo,
    PrepareJoin,
    Repo(String, RepoOp),
    Host(String, HostOp),
    TestControl,
}

/// A request read off the wire: method, path without the query, the `Authorization` value, the
/// three host request headers, and the body read up to the size limit.
struct Incoming {
    method: Method,
    path: String,
    authorization: Option<String>,
    host: HostHeaders,
    body: Vec<u8>,
}

/// Handles one request end to end and writes its response.
///
/// Every outcome is a response: a malformed, oversized, or unauthenticated request, a bad path, and
/// a poisoned lock each produce an error body, never a panic.
pub fn route(mut req: Request, state: &Mutex<State>) {
    let answer = read(&mut req, state).and_then(|incoming| handle(&incoming, state));
    let (status, value, retry_after) = match answer {
        Ok(v) => (200, v, None),
        Err(e) => (e.status, e.body(), e.retry_after_s),
    };
    let (status, bytes) = match serde_json::to_vec(&value) {
        Ok(b) => (status, b),
        Err(_) => (500, br#"{"error":"internal error"}"#.to_vec()),
    };
    let mut response = Response::from_data(bytes).with_status_code(status);
    if let Ok(h) = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]) {
        response.add_header(h);
    }
    if let Some(s) = retry_after {
        if let Ok(h) = Header::from_bytes(&b"Retry-After"[..], s.to_string().as_bytes()) {
            response.add_header(h);
        }
    }
    // A client that hung up is not an error for the host.
    let _ = req.respond(response);
}

/// Reads the request line, the `Authorization` header, and the body up to the size limit.
fn read(req: &mut Request, state: &Mutex<State>) -> Result<Incoming, ApiError> {
    let max = state.lock().map_err(|_| ApiError::internal())?.limits.max_body_bytes;
    if req.body_length().is_some_and(|n| n > max) {
        return Err(ApiError::too_large());
    }
    let mut body = Vec::new();
    let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    req.as_reader()
        .take(limit)
        .read_to_end(&mut body)
        .map_err(|_| ApiError::bad_request("unreadable request body"))?;
    if body.len() > max {
        return Err(ApiError::too_large());
    }
    let url = req.url();
    let path = url.split_once('?').map_or(url, |(p, _)| p).to_string();
    let header = |name: &'static str| {
        req.headers()
            .iter()
            .find(|h| h.field.equiv(name))
            .map(|h| h.value.as_str().to_string())
    };
    Ok(Incoming {
        method: req.method().clone(),
        path,
        authorization: header("Authorization"),
        host: HostHeaders {
            key: header(HEADER_KEY),
            time: header(HEADER_TIME),
            signature: header(HEADER_SIGNATURE),
        },
        body,
    })
}

/// Matches a method and path to a route.
fn parse_route(method: &Method, path: &str) -> Result<Route, ApiError> {
    let no_route = || ApiError::not_found("no such route");
    match (method, path) {
        (Method::Get, "/.well-known/avp") => return Ok(Route::Discovery),
        (Method::Post, "/api/auth/keypair/challenge") => return Ok(Route::Challenge),
        (Method::Post, "/api/auth/keypair/token") => return Ok(Route::Token),
        (Method::Post, "/v1/repos") => return Ok(Route::CreateRepo),
        (Method::Post, "/v1/prepare-join") => return Ok(Route::PrepareJoin),
        (Method::Post, "/v1/test/replication") => return Ok(Route::TestControl),
        _ => {}
    }
    if *method != Method::Post {
        return Err(no_route());
    }
    if let Some(rest) = path.strip_prefix("/v1/host/repos/") {
        let (segment, op) = rest.split_once('/').ok_or_else(no_route)?;
        let op = match op {
            "heads" => HostOp::Heads,
            "fetch" => HostOp::Fetch,
            "offer" => HostOp::Offer,
            _ => return Err(no_route()),
        };
        return Ok(Route::Host(percent_decode(segment)?, op));
    }
    let rest = path.strip_prefix("/v1/repos/").ok_or_else(no_route)?;
    let (segment, op) = rest.split_once('/').ok_or_else(no_route)?;
    let op = match op {
        "pull" => RepoOp::Pull,
        "push" => RepoOp::Push,
        "manifest" => RepoOp::Manifest,
        "leave" => RepoOp::Leave,
        _ => return Err(no_route()),
    };
    // The host routes on the escaped path and decodes the segment (SPEC 10.2, 12.4).
    Ok(Route::Repo(percent_decode(segment)?, op))
}

/// Decodes one percent-encoded path segment; a bad escape or non-UTF-8 result is `400`.
fn percent_decode(segment: &str) -> Result<String, ApiError> {
    let bad = || ApiError::bad_request("bad percent-encoding in path");
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&c) = bytes.get(i) {
        if c == b'%' {
            let hex = bytes.get(i + 1..i + 3).ok_or_else(bad)?;
            if !hex.iter().all(u8::is_ascii_hexdigit) {
                return Err(bad());
            }
            let text = std::str::from_utf8(hex).map_err(|_| bad())?;
            out.push(u8::from_str_radix(text, 16).map_err(|_| bad())?);
            i += 3;
        } else {
            out.push(c);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| bad())
}

/// Routes a read request under the state lock.
fn handle(req: &Incoming, state: &Mutex<State>) -> Answer {
    let route = parse_route(&req.method, &req.path)?;
    let mut guard = state.lock().map_err(|_| ApiError::internal())?;
    let st: &mut State = &mut guard;
    let body = req.body.as_slice();
    match route {
        Route::Discovery => discovery(st),
        Route::Challenge => challenge(st, body),
        Route::Token => token(st, body),
        Route::CreateRepo => {
            let caller = authenticate(st, req.authorization.as_deref())?;
            create_repo(st, caller, body)
        }
        Route::PrepareJoin => {
            let caller = authenticate(st, req.authorization.as_deref())?;
            prepare_join(st, caller, body)
        }
        Route::Repo(repo_id, op) => {
            let caller = authenticate(st, req.authorization.as_deref())?;
            match op {
                RepoOp::Pull => pull(st, caller, &repo_id, body),
                RepoOp::Push => push(st, caller, &repo_id, body),
                RepoOp::Manifest => publish_manifest(st, caller, &repo_id, body),
                RepoOp::Leave => leave(st, caller, &repo_id, body),
            }
        }
        Route::Host(repo_id, op) => {
            if st.repl.paused {
                return Err(ApiError::paused());
            }
            // SPEC 9.3: signed over the method, the path as sent, and the exact body bytes.
            let peer = replication::authenticate(st, req.method.as_str(), &req.path, body, &req.host)
                .ok_or_else(|| ApiError::unauthorized("bad host request signature"))?;
            match op {
                HostOp::Heads => host_heads(st, &peer, &repo_id, body),
                HostOp::Fetch => host_fetch(st, &peer, &repo_id, body),
                HostOp::Offer => host_offer(st, &peer, &repo_id, body),
            }
        }
        Route::TestControl => test_control(st, body),
    }
}

/// The token subject of `Authorization: Bearer <token>`; anything else is `401 unauthorized`.
fn authenticate(st: &State, authorization: Option<&str>) -> Result<[u8; 32], ApiError> {
    let value = authorization.ok_or_else(|| ApiError::unauthorized("missing bearer token"))?;
    let (scheme, token) = value
        .split_once(' ')
        .ok_or_else(|| ApiError::unauthorized("missing bearer token"))?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(ApiError::unauthorized("missing bearer token"));
    }
    st.auth
        .subject(token.trim(), st.now_ms())
        .ok_or_else(|| ApiError::unauthorized("unknown or expired bearer token"))
}

// ─── Discovery and authentication (SPEC 11.7, 3.3) ──────────────────────────────────────

fn discovery(st: &State) -> Answer {
    Ok(json!({ "version": VERSION, "profiles": ["http-json"], "hostKey": b64_encode(&st.host_key()) }))
}

fn challenge(st: &mut State, body: &[u8]) -> Answer {
    let ChallengeBody { key } = decode(body)?;
    let now = st.now_ms();
    let caps = Caps {
        total: st.limits.max_challenges,
        per_key: st.limits.max_challenges_per_key,
    };
    match st.auth.challenge(key, now, caps) {
        Ok(nonce) => Ok(json!({ "nonce": b64_encode(&nonce) })),
        Err(_) => {
            let mut e = ApiError::quota("too many outstanding challenges for this key");
            e.retry_after_s = Some(CHALLENGE_TTL_MS / 1000);
            Err(e)
        }
    }
}

fn token(st: &mut State, body: &[u8]) -> Answer {
    let TokenBody { key, nonce, signature } = decode(body)?;
    let now = st.now_ms();
    let caps = Caps {
        total: st.limits.max_tokens,
        per_key: st.limits.max_tokens_per_key,
    };
    match st.auth.token(key, &nonce, &signature, now, caps) {
        Ok((token, expires_at)) => Ok(json!({ "token": token, "expiresAt": expires_at })),
        Err(AuthError::Unauthorized) => Err(ApiError::unauthorized(
            "challenge nonce unknown, used, expired, or not issued for this key, or bad signature",
        )),
        Err(AuthError::Full) => Err(ApiError::quota("too many live tokens for this key")),
    }
}

// ─── createRepo and prepareJoin (SPEC 8.2) ──────────────────────────────────────────────

fn create_repo(st: &mut State, caller: [u8; 32], body: &[u8]) -> Answer {
    let CreateRepoBody { manifest, commit } = decode(body)?;
    let s = &manifest.state;
    // SPEC 8.2: the authenticated caller MUST equal the genesis ownerKey.
    if s.owner_key != caller {
        return Err(ApiError::forbidden("caller is not the genesis ownerKey"));
    }
    // createRepo carries the genesis state (SPEC 6.2, 10.1); any other seq is malformed.
    if s.manifest_seq != 1 {
        return Err(ApiError::bad_request(
            "createRepo needs the genesis state (manifestSeq 1)",
        ));
    }
    if s.members.len() > st.limits.max_members {
        return Err(ApiError::quota("member limit exceeded"));
    }
    // Validate first, on a fresh view: structure, owner signature, repoId recomputation, genesis
    // and first-commit rules, and the hosted check (SPEC 6, 8.2). Only a valid genesis can collide
    // with a held repoId, so a forged one never learns whether that id exists here.
    let mut view = RepoView::new(st.host_key(), st.limits.head_bound);
    let first = commit.clone();
    // The genesis state and its first commit are accepted together or not at all (SPEC 8.2).
    view.apply_manifest_with(manifest, Some(commit), Via::Push)
        .map_err(ApiError::reject)?;
    let tip = view.tip().cloned().ok_or_else(ApiError::internal)?;
    if st.store.repos.contains_key(&tip.state.repo_id) {
        return Err(ApiError::new(409, "duplicate_repo", "repository already exists"));
    }
    if st.store.repos_owned_by(&caller) >= st.limits.max_repos_per_owner {
        return Err(ApiError::quota("repository quota for this owner key exceeded"));
    }
    st.store.repos.insert(tip.state.repo_id.clone(), view);
    replication::queue_offer(
        st,
        Outgoing {
            repo_id: tip.state.repo_id.clone(),
            manifests: vec![tip.clone()],
            commits: vec![first],
            leaves: Vec::new(),
        },
    );
    to_json(&tip)
}

/// Whether `id` has the shape of a `repoId`: 22 characters of base64url-nopad over 16 bytes
/// (SPEC 4.2, 12.4).
fn is_repo_id(id: &str) -> bool {
    id.len() == 22 && b64url_decode(id).is_ok_and(|b| b.len() == 16)
}

fn prepare_join(st: &mut State, caller: [u8; 32], body: &[u8]) -> Answer {
    let PrepareJoinBody { repo_id, member_key } = decode(body)?;
    if !is_repo_id(&repo_id) {
        return Err(ApiError::bad_request("repoId is not a 22-character base64url id"));
    }
    // SPEC 8.2: the authenticated caller MUST equal memberKey.
    if member_key != caller {
        return Err(ApiError::forbidden("caller is not memberKey"));
    }
    let now = st.now_ms();
    let expires_at = now.saturating_add(ACCEPTANCE_TTL_MS);
    let acceptance = Acceptance {
        repo_id,
        member_key,
        host_key: [0; 32],
        expires_at,
        signature: [0; 64],
    }
    .sign(st.host_signing_key())
    .map_err(|_| ApiError::internal())?;
    let (total, per_key) = (st.limits.max_pending_joins, st.limits.max_pending_joins_per_key);
    if !st
        .store
        .record_acceptance(&acceptance.repo_id, member_key, expires_at, now, total, per_key)
    {
        return Err(ApiError::quota("too many outstanding acceptances for this key"));
    }
    to_json(&acceptance)
}

// ─── Repository operations (SPEC 10.1) ──────────────────────────────────────────────────

/// The repository's view: `404 not_found` if this host does not hold it, `403 not_hosted` if its
/// winning tip does not list this host (SPEC 8.6, 10.1). A repository dropped from this host's
/// `hosts` is not served and takes no client writes until a replicated tip lists the host again.
fn hosted<'a>(st: &'a mut State, repo_id: &str) -> Result<&'a mut RepoView, ApiError> {
    let view = st
        .store
        .repos
        .get_mut(repo_id)
        .ok_or_else(|| ApiError::not_found("repository not found"))?;
    if !view.tip_lists_host() {
        return Err(ApiError::reject(RejectCode::NotHosted));
    }
    Ok(view)
}

/// The tip state of a held repository.
fn tip(view: &RepoView) -> Result<&SignedManifest, ApiError> {
    view.tip().ok_or_else(|| ApiError::not_found("repository not found"))
}

fn pull(st: &mut State, caller: [u8; 32], repo_id: &str, body: &[u8]) -> Answer {
    let PullBody { since, known } = decode(body)?;
    let view = hosted(st, repo_id)?;
    // SPEC 10.1: the caller is a member of the tip.
    if !tip(view)?.state.has_member(&caller) {
        return Err(ApiError::forbidden("caller is not a member of the tip"));
    }
    to_json(&PullReply {
        manifests: view.manifests_since(since),
        heads: view.commits_since(&known),
        leaves: view.leaves(),
    })
}

fn push(st: &mut State, caller: [u8; 32], repo_id: &str, body: &[u8]) -> Answer {
    let PushBody { commit } = decode(body)?;
    let view = hosted(st, repo_id)?;
    // SPEC 7.1 order: the commit decodes, matches the repository, and its id and signature verify
    // (400) before the caller check (403).
    if commit.repo_id != repo_id || commit.verify().is_err() {
        return Err(ApiError::reject(RejectCode::BadRequest));
    }
    // SPEC 7.1, 10.1: the caller is the author; the engine checks the author is a member of the tip.
    if commit.author != caller {
        return Err(ApiError::forbidden("caller is not the commit's author"));
    }
    let probe = commit.clone();
    let answer = match view.apply_commit_via(commit, Via::Push) {
        Ok(()) => to_json(&PushReply {
            accepted: true,
            heads: view.heads(),
        }),
        Err(RejectCode::MissingParents) => Err(ApiError::missing(&view.missing_for(&probe))),
        Err(code) => Err(ApiError::reject(code)),
    };
    if answer.is_ok() {
        replication::queue_offer(
            st,
            Outgoing {
                repo_id: repo_id.to_string(),
                manifests: Vec::new(),
                commits: vec![probe],
                leaves: Vec::new(),
            },
        );
    }
    answer
}

fn publish_manifest(st: &mut State, caller: [u8; 32], repo_id: &str, body: &[u8]) -> Answer {
    let ManifestBody { manifest, commit } = decode(body)?;
    let max_members = st.limits.max_members;
    let view = hosted(st, repo_id)?;
    // SPEC 10.1: the caller is ownerKey.
    if tip(view)?.state.owner_key != caller {
        return Err(ApiError::forbidden("caller is not the ownerKey"));
    }
    if manifest.state.members.len() > max_members {
        return Err(ApiError::quota("member limit exceeded"));
    }
    let probe = commit.clone();
    let submitted = manifest.hash().ok();
    let kept = manifest.clone();
    let tip_epoch = tip(view)?.state.key_epoch;
    match view.apply_manifest_with(manifest, commit, Via::Push) {
        Ok(()) => {
            let answer = to_json(tip(view)?);
            replication::queue_offer(
                st,
                Outgoing {
                    repo_id: repo_id.to_string(),
                    manifests: vec![kept],
                    commits: probe.into_iter().collect(),
                    leaves: Vec::new(),
                },
            );
            answer
        }
        Err(RejectCode::NotHosted) => {
            // SPEC 6.1 rule 6, 8.6: the state passed every other rule. The host keeps it (its
            // winning tip then no longer lists this host), with only its rotation commit when it
            // raises the epoch: a carried non-rotation commit is not kept, since the offer path
            // skips the caller check and the head bound. It is not offered to peers.
            let raising = tip_epoch.checked_add(1) == Some(kept.state.key_epoch);
            let rotation = if raising { probe } else { None };
            let _ = view.apply_manifest_with(kept, rotation, Via::Offer);
            Err(ApiError::reject(RejectCode::NotHosted))
        }
        Err(RejectCode::MissingParents) => {
            // The engine has rolled the state back, so `missing_for` also names the state this
            // request carries; it is not missing (the commit was checked against it), so only the
            // ids the host really lacks go in `detail` (SPEC 7.4, 10.4).
            let ids: Vec<[u8; 32]> = probe
                .map(|c| view.missing_for(&c))
                .unwrap_or_default()
                .into_iter()
                .filter(|id| Some(*id) != submitted)
                .collect();
            Err(ApiError::missing(&ids))
        }
        Err(code) => Err(ApiError::reject(code)),
    }
}

fn leave(st: &mut State, caller: [u8; 32], repo_id: &str, body: &[u8]) -> Answer {
    let request: LeaveRequest = decode(body)?;
    let view = hosted(st, repo_id)?;
    // SPEC 8.4 order: the signature verifies and repoId matches (400), then the caller is memberKey,
    // and memberKey is a member of the tip and not the owner (403, the engine).
    if request.repo_id != repo_id || request.verify().is_err() {
        return Err(ApiError::reject(RejectCode::BadRequest));
    }
    if request.member_key != caller {
        return Err(ApiError::forbidden("caller is not the leaving member"));
    }
    let queued = request.clone();
    view.apply_leave_via(request, Via::Push).map_err(ApiError::reject)?;
    replication::queue_offer(
        st,
        Outgoing {
            repo_id: repo_id.to_string(),
            manifests: Vec::new(),
            commits: Vec::new(),
            leaves: vec![queued],
        },
    );
    Ok(json!({}))
}

// ─── Host routes (SPEC 9.1 to 9.3) and the test control ─────────────────────────────────

/// A body `repoId` must name the path's repository; the path is authoritative and the field may be
/// left out (SPEC 9.3 gives the heads body as `{}`).
fn same_repo(body: Option<&str>, repo_id: &str) -> Result<(), ApiError> {
    match body {
        Some(id) if id != repo_id => Err(ApiError::bad_request("body repoId does not match the path")),
        _ => Ok(()),
    }
}

/// The view a peer may read: `404 not_found` if not held, `403 not_hosted` if this host's winning
/// tip does not list it (SPEC 8.6), `403 forbidden` if that tip does not list the peer (SPEC 9.2).
fn served<'a>(st: &'a State, repo_id: &str, peer: &[u8; 32]) -> Result<&'a RepoView, ApiError> {
    let view = st
        .store
        .repos
        .get(repo_id)
        .ok_or_else(|| ApiError::not_found("repository not found"))?;
    if !view.tip_lists_host() {
        return Err(ApiError::reject(RejectCode::NotHosted));
    }
    if !view.tip().is_some_and(|t| t.state.has_host(peer)) {
        return Err(ApiError::forbidden("the calling host is not in the repository's hosts"));
    }
    Ok(view)
}

/// `heads` (SPEC 9.1): the verified tip and the head ids; held and pending commits are not heads.
fn host_heads(st: &mut State, peer: &[u8; 32], repo_id: &str, body: &[u8]) -> Answer {
    let request: HeadsBody = decode(body)?;
    same_repo(request.repo_id.as_deref(), repo_id)?;
    let view = served(st, repo_id, peer)?;
    let t = tip(view)?;
    to_json(&HeadsReply {
        tip: ManifestTip {
            seq: t.state.manifest_seq,
            hash: t.hash().map_err(|_| ApiError::internal())?,
        },
        heads: view.heads(),
    })
}

/// `fetch` (SPEC 9.1): for a manifest hash (winning or verified losing), that state and every state
/// before it, ascending, with the rotation commit of each epoch-raising state among them even while
/// held; for a commit id, that commit if accepted or a rotation commit; every pending leave request.
/// Unknown ids, other held commits, and pending commits are left out.
fn host_fetch(st: &mut State, peer: &[u8; 32], repo_id: &str, body: &[u8]) -> Answer {
    let request: FetchBody = decode(body)?;
    same_repo(request.repo_id.as_deref(), repo_id)?;
    if request.ids.len() > MAX_ITEMS {
        return Err(ApiError::bad_request("too many ids"));
    }
    let view = served(st, repo_id, peer)?;
    let mut manifests: Vec<SignedManifest> = Vec::new();
    let mut commits: Vec<Commit> = Vec::new();
    let mut seen_states: HashSet<[u8; 32]> = HashSet::new();
    let mut seen_commits: HashSet<[u8; 32]> = HashSet::new();
    for id in &request.ids {
        if let Some(chain) = view.chain_to(id) {
            for m in chain {
                let h = m.hash().map_err(|_| ApiError::internal())?;
                if !seen_states.insert(h) {
                    continue;
                }
                if let Some(rc) = view.rotation_commit(&h) {
                    if seen_commits.insert(rc.commit_id) {
                        commits.push(rc.clone());
                    }
                }
                manifests.push(m);
            }
        } else if let Some(c) = view.fetch_commit(id) {
            if seen_commits.insert(c.commit_id) {
                commits.push(c.clone());
            }
        }
    }
    manifests.sort_by_key(|m| m.state.manifest_seq);
    to_json(&Items {
        manifests,
        commits,
        leaves: view.leaves().to_vec(),
    })
}

/// `offer` (SPEC 9.1, 9.2). A held repository refuses a peer its tip does not list (`403
/// forbidden`). The items are then validated on a trial copy and the received tip decides:
/// `403 not_hosted` if it does not list this host (a held repository keeps the validated states),
/// `403 forbidden` for a first copy whose tip does not list the sender, and otherwise the
/// per-item answer. An incomplete offer also queues a catch-up from the sender.
fn host_offer(st: &mut State, peer: &[u8; 32], repo_id: &str, body: &[u8]) -> Answer {
    let request: OfferBody = decode(body)?;
    same_repo(request.repo_id.as_deref(), repo_id)?;
    let items = Items {
        manifests: request.manifests,
        commits: request.commits,
        leaves: request.leaves,
    };
    if !items.bounded() {
        return Err(ApiError::bad_request("too many items"));
    }
    if let Some(view) = st.store.repos.get(repo_id) {
        if !view.tip().is_some_and(|t| t.state.has_host(peer)) {
            return Err(ApiError::forbidden("the calling host is not in the repository's hosts"));
        }
    }
    let (admitted, applied) = replication::receive(st, repo_id, peer, items);
    if applied.incomplete || admitted == Admitted::Incomplete {
        replication::queue_catchup(st, *peer, repo_id);
    }
    match admitted {
        Admitted::Hosted | Admitted::Incomplete => to_json(&applied.reply()),
        Admitted::NotHosted => Err(ApiError::reject(RejectCode::NotHosted)),
        Admitted::Forbidden => Err(ApiError::forbidden("the sending host is not in the repository's hosts")),
    }
}

/// `POST /v1/test/replication { paused }` (SPEC 9.3), only with `AVP_TEST_CONTROL=1`; otherwise the
/// route does not exist.
fn test_control(st: &mut State, body: &[u8]) -> Answer {
    if !st.replication.test_control {
        return Err(ApiError::not_found("no such route"));
    }
    let TestControlBody { paused } = decode(body)?;
    st.repl.paused = paused;
    if !paused {
        st.repl.kick = st.repl.kick.wrapping_add(1);
    }
    st.repl.wake.notify_all();
    Ok(json!({ "paused": paused }))
}
