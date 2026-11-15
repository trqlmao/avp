// SPDX-License-Identifier: MIT

//! Black-box tests of the client-facing API (SPEC 3.3, 6 to 8, 10, 11.7, 12).
//!
//! Each test starts the host in-process on port 0 and talks to it over real HTTP. Every request
//! body is built with the `avp` crate, with real keys and signatures; the engine is not stubbed.
//! Expected statuses and codes are the ones SPEC 10.4 names for each case.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use avp::auth::sign_challenge;
use avp::commit::{Commit, CommitHeader, commit_sig_message};
use avp::crypto::{SCHEME_ID, WRAP_INFO, ed25519_verify, random_bytes, wrap, x25519_public, x25519_random};
use avp::encoding::{Ce, b64_decode, b64_decode_array, b64_encode};
use avp::manifest::{HostRef, ManifestState, MemberEntry, Removal, SignedManifest, derive_repo_id};
use avp::tokens::{Acceptance, LeaveRequest};
use avp_reference_server::{Serving, State, parse_bind, serve};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use x25519_dalek::StaticSecret;

// ─── Harness ────────────────────────────────────────────────────────────────────────────

/// A running host: its address, its shared state, and every response body it sent.
struct Host {
    serving: Serving,
    state: Arc<Mutex<State>>,
    bodies: Mutex<Vec<String>>,
}

struct Reply {
    status: u16,
    json: Value,
}

fn start() -> Host {
    start_with(|_| {})
}

fn start_with(configure: impl FnOnce(&mut State)) -> Host {
    let mut state = State::new(SigningKey::from_bytes(&random_bytes::<32>()));
    configure(&mut state);
    let state = Arc::new(Mutex::new(state));
    let serving = serve("127.0.0.1:0", Arc::clone(&state)).expect("bind an ephemeral port");
    Host {
        serving,
        state,
        bodies: Mutex::new(Vec::new()),
    }
}

impl Host {
    fn addr(&self) -> SocketAddr {
        self.serving.addr()
    }

    fn key(&self) -> [u8; 32] {
        self.state.lock().unwrap().host_key()
    }

    /// Sends one HTTP/1.1 request with `Connection: close` and parses the reply.
    fn raw(&self, method: &str, path: &str, token: Option<&str>, body: &[u8], extra: &str) -> Reply {
        let mut stream = TcpStream::connect(self.addr()).expect("connect");
        let mut head = format!("{method} {path} HTTP/1.1\r\nHost: vault.example\r\nConnection: close\r\n");
        if !extra.contains("Transfer-Encoding") {
            head.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        head.push_str("Content-Type: application/json\r\n");
        head.push_str(extra);
        if let Some(t) = token {
            head.push_str(&format!("Authorization: Bearer {t}\r\n"));
        }
        head.push_str("\r\n");
        stream.write_all(head.as_bytes()).unwrap();
        // The host may answer and close before reading an oversize body; a failed write is fine.
        let _ = stream.write_all(body);
        let _ = stream.flush();
        let mut raw = Vec::new();
        let _ = stream.read_to_end(&mut raw);
        let text = String::from_utf8(raw).expect("utf-8 reply");
        let (head, body) = text.split_once("\r\n\r\n").expect("header/body split");
        let status = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .expect("status line");
        self.bodies.lock().unwrap().push(body.to_string());
        let json = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(body).expect("json body")
        };
        Reply { status, json }
    }

    fn post(&self, path: &str, token: Option<&str>, body: &Value) -> Reply {
        self.raw("POST", path, token, body.to_string().as_bytes(), "")
    }

    fn get(&self, path: &str) -> Reply {
        self.raw("GET", path, None, b"", "")
    }

    /// The challenge and token flow of SPEC 3.3; returns the bearer token.
    fn login(&self, key: &SigningKey) -> String {
        let nonce = self.challenge(key);
        let r = self.redeem(key, &nonce, &self.sign_challenge(key, &nonce));
        assert_eq!(r.status, 200, "token: {}", r.json);
        r.json["token"].as_str().unwrap().to_string()
    }

    fn challenge(&self, key: &SigningKey) -> String {
        let r = self.post(
            "/api/auth/keypair/challenge",
            None,
            &json!({ "ed25519PublicKey": b64_encode(&pk(key)) }),
        );
        assert_eq!(r.status, 200, "challenge: {}", r.json);
        r.json["nonce"].as_str().unwrap().to_string()
    }

    /// `key`'s signature over the SPEC 3.3 transcript for this host's key and `nonce` (base64).
    fn sign_challenge(&self, key: &SigningKey, nonce: &str) -> [u8; 64] {
        sign_challenge(&self.key(), key, &b64_decode(nonce).unwrap()).unwrap()
    }

    fn redeem(&self, key: &SigningKey, nonce: &str, signature: &[u8; 64]) -> Reply {
        self.post(
            "/api/auth/keypair/token",
            None,
            &json!({
                "ed25519PublicKey": b64_encode(&pk(key)),
                "nonce": nonce,
                "signature": b64_encode(signature),
            }),
        )
    }

    fn advance_clock(&self, ms: i64) {
        self.state.lock().unwrap().clock_offset_ms += ms;
    }
}

fn now_ms() -> i64 {
    i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()).unwrap()
}

/// Asserts the SPEC 10.4 error object: `error` is a string, `code` is the expected machine code.
fn assert_error(r: &Reply, status: u16, code: &str) {
    assert_eq!(r.status, status, "body: {}", r.json);
    assert!(r.json["error"].is_string(), "error message present: {}", r.json);
    assert_eq!(r.json["code"], json!(code), "body: {}", r.json);
}

fn pk(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}

fn new_key() -> SigningKey {
    SigningKey::from_bytes(&random_bytes::<32>())
}

fn to_json<T: serde::Serialize>(v: &T) -> Value {
    serde_json::to_value(v).unwrap()
}

fn ids(v: &[[u8; 32]]) -> Value {
    json!(v.iter().map(|id| b64_encode(id)).collect::<Vec<_>>())
}

// ─── Repository fixtures built with the avp crate ───────────────────────────────────────

/// A member device: an Ed25519 signing key and an X25519 key.
struct Device {
    sign: SigningKey,
    x: StaticSecret,
}

impl Device {
    fn new() -> Device {
        Device {
            sign: new_key(),
            x: x25519_random(),
        }
    }

    fn key(&self) -> [u8; 32] {
        pk(&self.sign)
    }

    fn entry(&self, data_key: &[u8; 32], epoch: i64, home: [u8; 32]) -> MemberEntry {
        MemberEntry {
            ed25519_public_key: self.key(),
            x25519_public_key: x25519_public(&self.x),
            wrapped_data_key: wrap(&x25519_public(&self.x), data_key, WRAP_INFO).unwrap(),
            key_epoch: epoch,
            home_host_key: home,
        }
    }
}

/// A repository as its owner's client sees it.
struct Repo {
    owner: Device,
    data_key: [u8; 32],
    tip: SignedManifest,
    root: Commit,
}

impl Repo {
    fn id(&self) -> String {
        self.tip.state.repo_id.clone()
    }

    fn path(&self, op: &str) -> String {
        format!("/v1/repos/{}/{op}", self.id())
    }

    /// The next state on the tip, changed by `f`, signed by the owner.
    fn next(&self, f: impl FnOnce(&mut ManifestState)) -> SignedManifest {
        let mut s = self.tip.state.clone();
        s.manifest_seq += 1;
        s.prev_manifest_hash = self.tip.hash().unwrap().to_vec();
        s.genesis_nonce = Vec::new();
        f(&mut s);
        s.sign(&self.owner.sign).unwrap()
    }

    fn commit(&self, author: &SigningKey, parents: Vec<[u8; 32]>, plaintext: &[u8]) -> Commit {
        commit_on(&self.tip, &self.data_key, author, parents, plaintext)
    }
}

fn commit_on(
    cites: &SignedManifest,
    data_key: &[u8; 32],
    author: &SigningKey,
    parents: Vec<[u8; 32]>,
    plaintext: &[u8],
) -> Commit {
    let header = CommitHeader {
        repo_id: cites.state.repo_id.clone(),
        parents,
        manifest_seq: cites.state.manifest_seq,
        manifest_hash: cites.hash().unwrap(),
        key_epoch: cites.state.key_epoch,
    };
    Commit::seal(data_key, header, plaintext, author).unwrap()
}

const EMPTY_PAYLOAD: &[u8] = br#"{"v":2,"accounts":{}}"#;

/// The genesis state (SPEC 6.2) of a new repository listing `hosts`, and its first commit.
fn genesis(hosts: &[[u8; 32]]) -> Repo {
    let owner = Device::new();
    let data_key = random_bytes::<32>();
    let nonce = random_bytes::<16>();
    let home = hosts[0];
    let state = ManifestState {
        repo_id: derive_repo_id(&owner.key(), &nonce).unwrap(),
        manifest_seq: 1,
        prev_manifest_hash: Vec::new(),
        owner_key: owner.key(),
        genesis_nonce: nonce.to_vec(),
        scheme_id: SCHEME_ID.to_string(),
        key_epoch: 0,
        share_refresh_tokens: false,
        hosts: hosts
            .iter()
            .enumerate()
            .map(|(i, k)| HostRef {
                key: *k,
                locator: format!("h{i}.vault.example"),
            })
            .collect(),
        members: vec![owner.entry(&data_key, 0, home)],
        removals: Vec::new(),
    };
    let tip = state.sign(&owner.sign).unwrap();
    let root = commit_on(&tip, &data_key, &owner.sign, Vec::new(), EMPTY_PAYLOAD);
    Repo {
        owner,
        data_key,
        tip,
        root,
    }
}

fn create_body(repo: &Repo) -> Value {
    json!({ "manifest": to_json(&repo.tip), "commit": to_json(&repo.root) })
}

/// Creates a repository on `host` and returns it with the owner's token.
fn created(host: &Host) -> (Repo, String) {
    let repo = genesis(&[host.key()]);
    let token = host.login(&repo.owner.sign);
    let r = host.post("/v1/repos", Some(&token), &create_body(&repo));
    assert_eq!(r.status, 200, "createRepo: {}", r.json);
    (repo, token)
}

/// Publishes a state that adds `who` as a member (SPEC 8.1).
fn add_member(host: &Host, repo: &mut Repo, token: &str, who: &Device) {
    let home = host.key();
    let entry = who.entry(&repo.data_key, repo.tip.state.key_epoch, home);
    let next = repo.next(|s| s.members.push(entry));
    let r = host.post(
        &repo.path("manifest"),
        Some(token),
        &json!({ "manifest": to_json(&next) }),
    );
    assert_eq!(r.status, 200, "publishManifest: {}", r.json);
    repo.tip = next;
}

fn push(host: &Host, repo: &Repo, token: &str, c: &Commit) -> Reply {
    host.post(&repo.path("push"), Some(token), &json!({ "commit": to_json(c) }))
}

fn pull(host: &Host, repo: &Repo, token: &str, since: i64, known: &[[u8; 32]]) -> Reply {
    host.post(
        &repo.path("pull"),
        Some(token),
        &json!({ "sinceManifestSeq": since, "knownHeads": ids(known) }),
    )
}

fn leave_request(repo: &Repo, member: &SigningKey) -> LeaveRequest {
    LeaveRequest {
        repo_id: repo.id(),
        member_key: [0; 32],
        at: now_ms(),
        signature: [0; 64],
    }
    .sign(member)
    .unwrap()
}

// ─── Brief tests ────────────────────────────────────────────────────────────────────────

#[test]
fn create_pull_push_roundtrip() {
    let host = start();
    let (repo, token) = created(&host);

    // createRepo answers the stored SignedManifest (SPEC 10.2).
    let r = host.post("/v1/repos", Some(&token), &create_body(&genesis(&[host.key()])));
    assert_error(&r, 403, "forbidden"); // another owner's genesis: caller is not its ownerKey

    let r = pull(&host, &repo, &token, 0, &[]);
    assert_eq!(r.status, 200);
    assert_eq!(
        r.json,
        json!({ "manifests": [to_json(&repo.tip)], "heads": [to_json(&repo.root)], "leaves": [] })
    );

    let child = repo.commit(&repo.owner.sign, vec![repo.root.commit_id], EMPTY_PAYLOAD);
    let r = push(&host, &repo, &token, &child);
    assert_eq!(r.status, 200);
    assert_eq!(r.json, json!({ "accepted": true, "heads": ids(&[child.commit_id]) }));

    // A push of a commit the host already holds is accepted again with no change (SPEC 7, 12.3).
    let r = push(&host, &repo, &token, &child);
    assert_eq!(r.json, json!({ "accepted": true, "heads": ids(&[child.commit_id]) }));

    let r = pull(&host, &repo, &token, 1, &[child.commit_id]);
    assert_eq!(r.json, json!({ "manifests": [], "heads": [], "leaves": [] }));
    let r = pull(&host, &repo, &token, 1, &[repo.root.commit_id]);
    assert_eq!(r.json["heads"], json!([to_json(&child)]));
}

#[test]
fn create_returns_the_genesis_state() {
    let host = start();
    let repo = genesis(&[host.key()]);
    let token = host.login(&repo.owner.sign);
    let r = host.post("/v1/repos", Some(&token), &create_body(&repo));
    assert_eq!(r.status, 200);
    assert_eq!(r.json, to_json(&repo.tip));
}

#[test]
fn create_rejected_when_host_not_listed() {
    let host = start();
    let other = pk(&new_key());
    let repo = genesis(&[other]);
    let token = host.login(&repo.owner.sign);
    let r = host.post("/v1/repos", Some(&token), &create_body(&repo));
    assert_error(&r, 403, "not_hosted");
    assert!(host.state.lock().unwrap().store.repos.is_empty(), "nothing stored");
}

#[test]
fn push_concurrent_gives_two_heads() {
    let host = start();
    let (repo, token) = created(&host);
    let a = repo.commit(
        &repo.owner.sign,
        vec![repo.root.commit_id],
        br#"{"v":2,"accounts":{"a":1}}"#,
    );
    let b = repo.commit(
        &repo.owner.sign,
        vec![repo.root.commit_id],
        br#"{"v":2,"accounts":{"b":1}}"#,
    );
    assert_eq!(push(&host, &repo, &token, &a).status, 200);
    let r = push(&host, &repo, &token, &b);
    assert_eq!(r.status, 200);
    let mut want = vec![a.commit_id, b.commit_id];
    want.sort_unstable();
    assert_eq!(r.json, json!({ "accepted": true, "heads": ids(&want) }));
    let r = pull(&host, &repo, &token, 1, &[]);
    assert_eq!(r.json["heads"].as_array().unwrap().len(), 2);
}

#[test]
fn push_beyond_bound_is_too_many_heads() {
    let host = start();
    let (repo, token) = created(&host);
    let mut heads = Vec::new();
    for i in 0..16 {
        let c = repo.commit(&repo.owner.sign, vec![repo.root.commit_id], format!("{i}").as_bytes());
        assert_eq!(push(&host, &repo, &token, &c).status, 200, "head {i}");
        heads.push(c.commit_id);
    }
    // A 17th head would leave more than the bound of 16 (SPEC 7.4).
    let c = repo.commit(&repo.owner.sign, vec![repo.root.commit_id], b"17");
    assert_error(&push(&host, &repo, &token, &c), 409, "too_many_heads");
    // A merge at the bound reduces the heads and is accepted.
    let merge = repo.commit(&repo.owner.sign, heads.clone(), b"merge");
    let r = push(&host, &repo, &token, &merge);
    assert_eq!(r.json, json!({ "accepted": true, "heads": ids(&[merge.commit_id]) }));
}

#[test]
fn publish_manifest_wrong_seq_is_conflict() {
    let host = start();
    let (mut repo, token) = created(&host);
    let bob = Device::new();

    // seq 3 on a tip at seq 1.
    let skip = repo.next(|s| s.manifest_seq = 3);
    let r = host.post(
        &repo.path("manifest"),
        Some(&token),
        &json!({ "manifest": to_json(&skip) }),
    );
    assert_error(&r, 409, "manifest_conflict");

    add_member(&host, &mut repo, &token, &bob);
    assert_eq!(repo.tip.state.manifest_seq, 2);

    // A retry of the published state after success (SPEC 12.3).
    let r = host.post(
        &repo.path("manifest"),
        Some(&token),
        &json!({ "manifest": to_json(&repo.tip) }),
    );
    assert_error(&r, 409, "manifest_conflict");

    // seq 3 whose prevManifestHash is not the tip's.
    let mut s = repo.tip.state.clone();
    s.manifest_seq = 3;
    s.prev_manifest_hash = vec![7; 32];
    s.share_refresh_tokens = true;
    let wrong_prev = s.sign(&repo.owner.sign).unwrap();
    let r = host.post(
        &repo.path("manifest"),
        Some(&token),
        &json!({ "manifest": to_json(&wrong_prev) }),
    );
    assert_error(&r, 409, "manifest_conflict");

    // tip + 1 linked to the tip is accepted and answers the stored state.
    let ok = repo.next(|s| s.share_refresh_tokens = true);
    let r = host.post(
        &repo.path("manifest"),
        Some(&token),
        &json!({ "manifest": to_json(&ok) }),
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.json, to_json(&ok));
}

#[test]
fn removed_member_push_forbidden() {
    let host = start();
    let (mut repo, token) = created(&host);
    let bob = Device::new();
    add_member(&host, &mut repo, &token, &bob);
    let bob_token = host.login(&bob.sign);
    let bob_commit = repo.commit(&bob.sign, vec![repo.root.commit_id], b"bob");
    assert_eq!(push(&host, &repo, &bob_token, &bob_commit).status, 200);
    let at_seq2 = repo.tip.clone();
    let old_key = repo.data_key;

    // The owner removes bob (SPEC 8.3): new epoch, removal with frontier, rotation commit.
    let new_key = random_bytes::<32>();
    let owner_entry = repo.owner.entry(&new_key, 1, host.key());
    let removed = repo.next(|s| {
        s.key_epoch = 1;
        s.members = vec![owner_entry];
        s.removals = vec![Removal {
            member_key: bob.key(),
            removed_at_seq: 3,
            frontier: vec![bob_commit.commit_id],
        }];
    });
    let rotation = commit_on(&removed, &new_key, &repo.owner.sign, vec![bob_commit.commit_id], b"rot");

    // An epoch-raising state without its rotation commit is bad_request (SPEC 8.3).
    let r = host.post(
        &repo.path("manifest"),
        Some(&token),
        &json!({ "manifest": to_json(&removed) }),
    );
    assert_error(&r, 400, "bad_request");

    let r = host.post(
        &repo.path("manifest"),
        Some(&token),
        &json!({ "manifest": to_json(&removed), "commit": to_json(&rotation) }),
    );
    assert_eq!(r.status, 200, "{}", r.json);
    repo.tip = removed;
    repo.data_key = new_key;

    // Bob backdates a child of his frontier commit citing the old state and epoch. Through the
    // client route the 403 comes from the caller check: bob is no longer a member of the tip
    // (SPEC 7.1). The removal cutoff itself (SPEC 7.3) is pinned by the engine's acceptance tests.
    let late = commit_on(&at_seq2, &old_key, &bob.sign, vec![bob_commit.commit_id], b"late");
    assert_error(&push(&host, &repo, &bob_token, &late), 403, "forbidden");
    // And he can no longer pull: not a member of the tip.
    assert_error(&pull(&host, &repo, &bob_token, 0, &[]), 403, "forbidden");
    let heads = pull(&host, &repo, &token, 0, &[]).json["heads"].clone();
    assert_eq!(heads, json!([to_json(&rotation)]));
}

#[test]
fn leave_is_served_in_pull() {
    let host = start();
    let (mut repo, token) = created(&host);
    let bob = Device::new();
    add_member(&host, &mut repo, &token, &bob);
    let bob_token = host.login(&bob.sign);
    let leave = leave_request(&repo, &bob.sign);
    let r = host.post(&repo.path("leave"), Some(&bob_token), &to_json(&leave));
    assert_eq!(r.status, 200);
    assert_eq!(r.json, json!({}));
    // leave is idempotent (SPEC 12.3).
    assert_eq!(
        host.post(&repo.path("leave"), Some(&bob_token), &to_json(&leave))
            .status,
        200
    );

    let r = pull(&host, &repo, &token, 2, &[repo.root.commit_id]);
    assert_eq!(
        r.json,
        json!({ "manifests": [], "heads": [], "leaves": [to_json(&leave)] })
    );
}

#[test]
fn prepare_join_acceptance_verifies() {
    let host = start();
    let carol = new_key();
    let token = host.login(&carol);
    let repo_id = genesis(&[host.key()]).id();
    let before = now_ms();
    let r = host.post(
        "/v1/prepare-join",
        Some(&token),
        &json!({ "repoId": repo_id, "memberKey": b64_encode(&pk(&carol)) }),
    );
    let after = now_ms();
    assert_eq!(r.status, 200, "{}", r.json);
    let keys: HashSet<&str> = r.json.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        HashSet::from(["repoId", "memberKey", "hostKey", "expiresAt", "signature"])
    );

    let disco = host.get("/.well-known/avp");
    let host_key: [u8; 32] = b64_decode_array(disco.json["hostKey"].as_str().unwrap()).unwrap();
    let acc: Acceptance = serde_json::from_value(r.json.clone()).unwrap();
    assert_eq!(acc.repo_id, repo_id);
    assert_eq!(acc.member_key, pk(&carol));
    assert_eq!(acc.host_key, host_key);

    // expiresAt = now + 15 min (SPEC 8.2: the reference hosts use 15 minutes).
    let fifteen = 15 * 60 * 1000;
    assert!(
        acc.expires_at >= before + fifteen && acc.expires_at <= after + fifteen,
        "expiresAt"
    );

    // The signature verifies under the discovery hostKey over the CE message of plan-header.md.
    let mut w = Ce::new("avp/accept/v1");
    w.str(&repo_id).bytes(&pk(&carol)).bytes(&host_key).i64(acc.expires_at);
    let message = w.finish().unwrap();
    ed25519_verify(&host_key, &message, &acc.signature).expect("acceptance signature");

    // The host records the acceptance it issued (SPEC 8.2).
    let st = host.state.lock().unwrap();
    assert_eq!(st.store.pending_join.get(&(repo_id, pk(&carol))), Some(&acc.expires_at));
}

#[test]
fn token_required() {
    let host = start();
    let (repo, token) = created(&host);
    let leave = leave_request(&repo, &repo.owner.sign);
    let cases = [
        ("/v1/repos".to_string(), create_body(&genesis(&[host.key()]))),
        (repo.path("pull"), json!({ "sinceManifestSeq": 0, "knownHeads": [] })),
        (repo.path("push"), json!({ "commit": to_json(&repo.root) })),
        (repo.path("manifest"), json!({ "manifest": to_json(&repo.tip) })),
        (repo.path("leave"), to_json(&leave)),
        (
            "/v1/prepare-join".to_string(),
            json!({ "repoId": repo.id(), "memberKey": b64_encode(&repo.owner.key()) }),
        ),
    ];
    for (path, body) in &cases {
        assert_error(&host.post(path, None, body), 401, "unauthorized");
        assert_error(&host.post(path, Some("not-a-token"), body), 401, "unauthorized");
        let r = host.raw(
            "POST",
            path,
            None,
            body.to_string().as_bytes(),
            &format!("Authorization: Basic {token}\r\n"),
        );
        assert_error(&r, 401, "unauthorized");
    }
    // The valid token still works.
    assert_eq!(pull(&host, &repo, &token, 0, &[]).status, 200);
}

#[test]
fn server_never_sees_plaintext() {
    const MARKER: &str = "PLAINTEXT-MARKER-alice-alt-7f3c9e1b";
    let host = start();
    let (mut repo, token) = created(&host);
    let bob = Device::new();
    add_member(&host, &mut repo, &token, &bob);
    let bob_token = host.login(&bob.sign);

    let plaintext = format!(
        r#"{{"v":2,"accounts":{{"u1":{{"fields":{{"username":{{"value":"{MARKER}","at":1,"n":0,"by":"alice"}}}},"bans":{{}}}}}}}}"#
    );
    let c = repo.commit(&repo.owner.sign, vec![repo.root.commit_id], plaintext.as_bytes());
    assert_eq!(
        c.open(&repo.data_key).unwrap(),
        plaintext.as_bytes(),
        "the client really sealed the marker"
    );
    assert_eq!(push(&host, &repo, &token, &c).status, 200);
    let r = pull(&host, &repo, &bob_token, 0, &[]);
    assert_eq!(r.status, 200);
    let leave = leave_request(&repo, &bob.sign);
    assert_eq!(
        host.post(&repo.path("leave"), Some(&bob_token), &to_json(&leave))
            .status,
        200
    );

    // Every response body: no marker as text, and every served ciphertext lacks the marker bytes.
    for body in host.bodies.lock().unwrap().iter() {
        assert!(!body.contains(MARKER), "response body leaks the plaintext");
    }
    for head in r.json["heads"].as_array().unwrap() {
        let ct = b64_decode(head["ciphertext"].as_str().unwrap()).unwrap();
        assert!(!ct.windows(MARKER.len()).any(|w| w == MARKER.as_bytes()));
    }

    // Everything the store holds, rendered in full: neither the marker (as text or as the byte
    // list a Vec<u8> renders to) nor any data key is in it.
    let st = host.state.lock().unwrap();
    let dump = format!("{:?}", st.store);
    let as_bytes = |b: &[u8]| {
        let s = format!("{b:?}");
        s.trim_start_matches('[').trim_end_matches(']').to_string()
    };
    assert!(dump.contains(&as_bytes(&c.ciphertext)), "the dump renders stored bytes");
    assert!(!dump.contains(MARKER));
    assert!(!dump.contains(&as_bytes(MARKER.as_bytes())));
    assert!(
        !dump.contains(&as_bytes(&repo.data_key)),
        "the host never holds a data key"
    );
}

// ─── Discovery (SPEC 11.7) ──────────────────────────────────────────────────────────────

#[test]
fn discovery_reports_version_profiles_and_host_key() {
    let seed = [0x11; 32];
    let host = start();
    let r = host.get("/.well-known/avp");
    assert_eq!(r.status, 200);
    assert_eq!(
        r.json,
        json!({ "version": "0.5", "profiles": ["http-json"], "hostKey": b64_encode(&host.key()) })
    );

    // AVP_HOST_SEED (hex, 32 bytes) fixes the host identity.
    let parsed = avp_reference_server::parse_host_seed(&"11".repeat(32)).unwrap();
    assert_eq!(parsed, seed);
    assert!(avp_reference_server::parse_host_seed("11").is_err());
    assert!(avp_reference_server::parse_host_seed(&"zz".repeat(32)).is_err());
    let fixed = State::new(SigningKey::from_bytes(&seed));
    assert_eq!(fixed.host_key(), pk(&SigningKey::from_bytes(&seed)));
}

#[test]
fn bind_address_defaults_to_all_interfaces_and_honors_avp_bind() {
    // Unset AVP_BIND keeps the old 0.0.0.0 listener; a set one is the address bound.
    assert_eq!(parse_bind(None), Ok(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    assert_eq!(parse_bind(Some("127.0.0.1")), Ok(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    assert_eq!(parse_bind(Some(" ::1 ")), Ok(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    for bad in ["", "localhost", "127.0.0.256", "127.0.0.1:8787"] {
        assert!(parse_bind(Some(bad)).is_err(), "accepted AVP_BIND {bad:?}");
    }
    let ip = parse_bind(Some("127.0.0.1")).unwrap();
    let state = Arc::new(Mutex::new(State::new(SigningKey::from_bytes(&random_bytes::<32>()))));
    let serving = serve(&SocketAddr::new(ip, 0).to_string(), state).expect("bind loopback");
    assert_eq!(serving.addr().ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    serving.stop();
}

// ─── Authentication failure modes (SPEC 3.3) ────────────────────────────────────────────

#[test]
fn challenge_nonce_is_32_random_bytes() {
    let host = start();
    let key = new_key();
    let a = b64_decode(&host.challenge(&key)).unwrap();
    let b = b64_decode(&host.challenge(&key)).unwrap();
    assert!(a.len() >= 32 && b.len() >= 32);
    assert_ne!(a, b);
}

#[test]
fn token_response_has_token_and_expiry() {
    let host = start();
    let key = new_key();
    let nonce = host.challenge(&key);
    let r = host.redeem(&key, &nonce, &host.sign_challenge(&key, &nonce));
    assert_eq!(r.status, 200);
    let keys: HashSet<&str> = r.json.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys, HashSet::from(["token", "expiresAt"]));
    assert!(r.json["expiresAt"].as_i64().unwrap() > now_ms());
}

#[test]
fn expired_challenge_is_unauthorized() {
    let host = start();
    let key = new_key();
    let nonce = host.challenge(&key);
    // The challenge TTL is 2 minutes (SPEC 3.3 RECOMMENDED at most 2 minutes).
    host.advance_clock(2 * 60 * 1000 + 1);
    let r = host.redeem(&key, &nonce, &host.sign_challenge(&key, &nonce));
    assert_error(&r, 401, "unauthorized");
}

#[test]
fn reused_challenge_is_unauthorized() {
    let host = start();
    let key = new_key();
    let nonce = host.challenge(&key);
    let sig = host.sign_challenge(&key, &nonce);
    assert_eq!(host.redeem(&key, &nonce, &sig).status, 200);
    assert_error(&host.redeem(&key, &nonce, &sig), 401, "unauthorized");
}

#[test]
fn bad_challenge_signature_is_unauthorized() {
    let host = start();
    let key = new_key();
    let nonce = host.challenge(&key);
    // Signing the base64 text instead of the raw nonce bytes.
    let r = host.redeem(&key, &nonce, &key.sign(nonce.as_bytes()).to_bytes());
    assert_error(&r, 401, "unauthorized");
    // A failed attempt consumes the nonce: it is single-use.
    let r = host.redeem(&key, &nonce, &host.sign_challenge(&key, &nonce));
    assert_error(&r, 401, "unauthorized");
    // A signature by another key.
    let nonce = host.challenge(&key);
    let r = host.redeem(&key, &nonce, &host.sign_challenge(&new_key(), &nonce));
    assert_error(&r, 401, "unauthorized");
    // A nonce the host never issued.
    let fake = b64_encode(&random_bytes::<32>());
    let r = host.redeem(&key, &fake, &host.sign_challenge(&key, &fake));
    assert_error(&r, 401, "unauthorized");
}

#[test]
fn challenge_for_another_key_is_unauthorized() {
    let host = start();
    let alice = new_key();
    let mallory = new_key();
    let nonce = host.challenge(&alice);
    // Mallory signs alice's nonce correctly with her own key: not issued for that key.
    let r = host.redeem(&mallory, &nonce, &host.sign_challenge(&mallory, &nonce));
    assert_error(&r, 401, "unauthorized");
}

#[test]
fn raw_nonce_signature_is_unauthorized() {
    // SPEC 3.3: the old construction, a signature over the raw nonce bytes, is no longer accepted.
    let host = start();
    let key = new_key();
    let nonce = host.challenge(&key);
    let raw = key.sign(&b64_decode(&nonce).unwrap()).to_bytes();
    assert_error(&host.redeem(&key, &nonce, &raw), 401, "unauthorized");
}

#[test]
fn transcript_for_another_host_key_is_unauthorized() {
    // SPEC 3.3: the transcript binds the host key, so a signature a client made for another host
    // (here host b, relaying a's nonce) is rejected at host a.
    let a = start();
    let b = start();
    let key = new_key();
    let nonce = a.challenge(&key);
    let for_b = b.sign_challenge(&key, &nonce);
    assert_error(&a.redeem(&key, &nonce, &for_b), 401, "unauthorized");
    // The same nonce signed for a's key would have verified; the failed attempt consumed it.
    let r = a.redeem(&key, &nonce, &a.sign_challenge(&key, &nonce));
    assert_error(&r, 401, "unauthorized");
}

#[test]
fn transcript_signature_is_not_a_commit_signature() {
    // SPEC 4.1: a host that picks a commit id as its "nonce" gets a challenge-domain signature,
    // which never verifies as the author signature of that commit.
    let host = start();
    let (repo, _) = created(&host);
    let commit_id = repo.root.commit_id;
    let sig = sign_challenge(&host.key(), &repo.owner.sign, &commit_id).unwrap();
    let msg = commit_sig_message(&commit_id).unwrap();
    assert!(ed25519_verify(&pk(&repo.owner.sign), &msg, &sig).is_err());
    let forged = Commit {
        author_signature: sig,
        ..repo.root.clone()
    };
    assert!(forged.verify().is_err());
}

#[test]
fn token_of_another_host_is_unauthorized() {
    let a = start();
    let b = start();
    let (repo, _) = created(&a);
    let token_b = b.login(&repo.owner.sign);
    assert_error(&pull(&a, &repo, &token_b, 0, &[]), 401, "unauthorized");
}

#[test]
fn expired_token_is_unauthorized() {
    let host = start();
    let (repo, token) = created(&host);
    host.advance_clock(15 * 60 * 1000 + 1);
    assert_error(&pull(&host, &repo, &token, 0, &[]), 401, "unauthorized");
}

#[test]
fn malformed_auth_bodies_are_bad_request() {
    let host = start();
    let r = host.post(
        "/api/auth/keypair/challenge",
        None,
        &json!({ "ed25519PublicKey": "%%%" }),
    );
    assert_error(&r, 400, "bad_request");
    let r = host.post(
        "/api/auth/keypair/challenge",
        None,
        &json!({ "ed25519PublicKey": b64_encode(&[1; 31]) }),
    );
    assert_error(&r, 400, "bad_request");
    let r = host.post(
        "/api/auth/keypair/token",
        None,
        &json!({ "ed25519PublicKey": b64_encode(&[1; 32]) }),
    );
    assert_error(&r, 400, "bad_request");
    let r = host.raw("POST", "/api/auth/keypair/challenge", None, b"{not json", "");
    assert_error(&r, 400, "bad_request");
}

// ─── Per-operation caller checks (SPEC 10.1) ────────────────────────────────────────────

#[test]
fn create_by_non_owner_is_forbidden() {
    let host = start();
    let repo = genesis(&[host.key()]);
    let mallory = host.login(&new_key());
    assert_error(
        &host.post("/v1/repos", Some(&mallory), &create_body(&repo)),
        403,
        "forbidden",
    );
    assert!(host.state.lock().unwrap().store.repos.is_empty());
}

#[test]
fn publish_by_non_owner_is_forbidden() {
    let host = start();
    let (mut repo, token) = created(&host);
    let bob = Device::new();
    add_member(&host, &mut repo, &token, &bob);
    let bob_token = host.login(&bob.sign);
    let next = repo.next(|s| s.share_refresh_tokens = true);
    let r = host.post(
        &repo.path("manifest"),
        Some(&bob_token),
        &json!({ "manifest": to_json(&next) }),
    );
    assert_error(&r, 403, "forbidden");
    let outsider = host.login(&new_key());
    let r = host.post(
        &repo.path("manifest"),
        Some(&outsider),
        &json!({ "manifest": to_json(&next) }),
    );
    assert_error(&r, 403, "forbidden");
}

#[test]
fn pull_by_non_member_is_forbidden() {
    let host = start();
    let (repo, _) = created(&host);
    let outsider = host.login(&new_key());
    assert_error(&pull(&host, &repo, &outsider, 0, &[]), 403, "forbidden");
}

#[test]
fn push_by_non_author_is_forbidden() {
    let host = start();
    let (mut repo, token) = created(&host);
    let bob = Device::new();
    add_member(&host, &mut repo, &token, &bob);
    let bob_commit = repo.commit(&bob.sign, vec![repo.root.commit_id], b"bob");
    // The owner, a member, pushes a commit authored by bob.
    assert_error(&push(&host, &repo, &token, &bob_commit), 403, "forbidden");
    // A non-member pushes their own commit.
    let carol = Device::new();
    let carol_token = host.login(&carol.sign);
    let c = repo.commit(&carol.sign, vec![repo.root.commit_id], b"carol");
    assert_error(&push(&host, &repo, &carol_token, &c), 403, "forbidden");
    let heads = pull(&host, &repo, &token, 0, &[]).json["heads"].clone();
    assert_eq!(heads, json!([to_json(&repo.root)]));
}

#[test]
fn leave_for_another_member_is_forbidden() {
    let host = start();
    let (mut repo, token) = created(&host);
    let bob = Device::new();
    let carol = Device::new();
    add_member(&host, &mut repo, &token, &bob);
    add_member(&host, &mut repo, &token, &carol);
    let carol_token = host.login(&carol.sign);
    let bobs = leave_request(&repo, &bob.sign);
    assert_error(
        &host.post(&repo.path("leave"), Some(&carol_token), &to_json(&bobs)),
        403,
        "forbidden",
    );
    // The owner cannot leave (SPEC 8.4).
    let owners = leave_request(&repo, &repo.owner.sign);
    assert_error(
        &host.post(&repo.path("leave"), Some(&token), &to_json(&owners)),
        403,
        "forbidden",
    );
    // A leave request whose signature does not verify.
    let mut forged = leave_request(&repo, &carol.sign);
    forged.at += 1;
    assert_error(
        &host.post(&repo.path("leave"), Some(&carol_token), &to_json(&forged)),
        400,
        "bad_request",
    );
    let r = pull(&host, &repo, &token, 0, &[]);
    assert_eq!(r.json["leaves"], json!([]));
}

#[test]
fn prepare_join_for_another_key_is_forbidden() {
    let host = start();
    let carol = new_key();
    let mallory = host.login(&new_key());
    let r = host.post(
        "/v1/prepare-join",
        Some(&mallory),
        &json!({ "repoId": genesis(&[host.key()]).id(), "memberKey": b64_encode(&pk(&carol)) }),
    );
    assert_error(&r, 403, "forbidden");
    assert!(host.state.lock().unwrap().store.pending_join.is_empty());
}

// ─── Host-level answers (SPEC 8.2, 10.1, 10.4, 12) ──────────────────────────────────────

#[test]
fn second_create_is_duplicate_repo() {
    let host = start();
    let (repo, token) = created(&host);
    assert_error(
        &host.post("/v1/repos", Some(&token), &create_body(&repo)),
        409,
        "duplicate_repo",
    );
}

#[test]
fn unknown_repo_is_not_found() {
    let host = start();
    let (_, token) = created(&host);
    let other = genesis(&[host.key()]);
    let leave = leave_request(&other, &other.owner.sign);
    for (op, body) in [
        ("pull", json!({ "sinceManifestSeq": 0, "knownHeads": [] })),
        ("push", json!({ "commit": to_json(&other.root) })),
        ("manifest", json!({ "manifest": to_json(&other.tip) })),
        ("leave", to_json(&leave)),
    ] {
        assert_error(&host.post(&other.path(op), Some(&token), &body), 404, "not_found");
    }
}

#[test]
fn unknown_parent_is_missing_parents_with_detail() {
    let host = start();
    let (repo, token) = created(&host);
    let (p1, p2) = (random_bytes::<32>(), random_bytes::<32>());
    let c = repo.commit(&repo.owner.sign, vec![p1, p2], b"orphan");
    let r = push(&host, &repo, &token, &c);
    assert_error(&r, 422, "missing_parents");
    let listed: HashSet<&str> = r.json["detail"].as_str().unwrap().split(',').collect();
    assert_eq!(
        listed,
        HashSet::from([b64_encode(&p1).as_str(), b64_encode(&p2).as_str()])
    );

    // A cited manifest state the host does not hold is named by its hash (SPEC 7.2).
    let unknown = repo.next(|s| s.share_refresh_tokens = true);
    let c = commit_on(
        &unknown,
        &repo.data_key,
        &repo.owner.sign,
        vec![repo.root.commit_id],
        b"x",
    );
    let r = push(&host, &repo, &token, &c);
    assert_error(&r, 422, "missing_parents");
    assert_eq!(r.json["detail"], json!(b64_encode(&unknown.hash().unwrap())));
}

#[test]
fn malformed_bodies_are_bad_request() {
    let host = start();
    let (repo, token) = created(&host);
    let push_path = repo.path("push");
    let bad = [
        b"{not json".to_vec(),
        b"[]".to_vec(),
        br#"{"commit":{}}"#.to_vec(),
        br#"{"sinceManifestSeq":0}"#.to_vec(),
    ];
    for body in &bad {
        assert_error(
            &host.raw("POST", &push_path, Some(&token), body, ""),
            400,
            "bad_request",
        );
        assert_error(
            &host.raw("POST", &repo.path("pull"), Some(&token), body, ""),
            400,
            "bad_request",
        );
        assert_error(
            &host.raw("POST", &repo.path("manifest"), Some(&token), body, ""),
            400,
            "bad_request",
        );
        assert_error(
            &host.raw("POST", &repo.path("leave"), Some(&token), body, ""),
            400,
            "bad_request",
        );
        assert_error(
            &host.raw("POST", "/v1/repos", Some(&token), body, ""),
            400,
            "bad_request",
        );
        assert_error(
            &host.raw("POST", "/v1/prepare-join", Some(&token), body, ""),
            400,
            "bad_request",
        );
    }
    // Bad base64 in an id list, and an id of the wrong length.
    let r = host.post(
        &repo.path("pull"),
        Some(&token),
        &json!({ "sinceManifestSeq": 0, "knownHeads": ["%%%"] }),
    );
    assert_error(&r, 400, "bad_request");
    let r = host.post(
        &repo.path("pull"),
        Some(&token),
        &json!({ "sinceManifestSeq": 0, "knownHeads": [b64_encode(&[1; 31])] }),
    );
    assert_error(&r, 400, "bad_request");
    // A commit whose signature does not verify.
    let mut forged = repo.commit(&repo.owner.sign, vec![repo.root.commit_id], b"x");
    forged.author_signature[0] ^= 1;
    assert_error(&push(&host, &repo, &token, &forged), 400, "bad_request");
    // A commit for another repository.
    let other = genesis(&[host.key()]);
    let mut c = other.root.clone();
    c.repo_id = repo.id();
    assert_error(&push(&host, &repo, &token, &c), 400, "bad_request");
    // A repoId in prepareJoin that is not a 22-character base64url id (SPEC 12.4).
    let r = host.post(
        "/v1/prepare-join",
        Some(&token),
        &json!({ "repoId": "not-a-repo-id", "memberKey": b64_encode(&repo.owner.key()) }),
    );
    assert_error(&r, 400, "bad_request");
    // A path segment with a bad percent escape.
    let r = host.raw("POST", "/v1/repos/%zz/pull", Some(&token), b"{}", "");
    assert_error(&r, 400, "bad_request");
    // A genesis whose repoId does not recompute.
    let mut g = genesis(&[host.key()]);
    let mut s = g.tip.state.clone();
    s.repo_id = derive_repo_id(&g.owner.key(), &random_bytes::<16>()).unwrap();
    g.tip = s.sign(&g.owner.sign).unwrap();
    let t = host.login(&g.owner.sign);
    assert_error(&host.post("/v1/repos", Some(&t), &create_body(&g)), 400, "bad_request");
}

#[test]
fn percent_encoded_repo_id_routes() {
    let host = start();
    let (repo, token) = created(&host);
    let encoded: String = repo.id().bytes().map(|b| format!("%{b:02X}")).collect();
    let r = host.post(
        &format!("/v1/repos/{encoded}/pull"),
        Some(&token),
        &json!({ "sinceManifestSeq": 1, "knownHeads": [] }),
    );
    assert_eq!(r.status, 200, "{}", r.json);
}

#[test]
fn unknown_route_is_not_found() {
    let host = start();
    assert_error(&host.get("/v1/nothing"), 404, "not_found");
    assert_error(&host.get("/v1/repos"), 404, "not_found");
}

#[test]
fn oversize_body_is_too_large() {
    let host = start();
    let (repo, token) = created(&host);
    host.state.lock().unwrap().limits.max_body_bytes = 1024;
    let big = vec![b' '; 4096];
    let r = host.raw("POST", &repo.path("push"), Some(&token), &big, "");
    assert_error(&r, 413, "too_large");
    // Without Content-Length (chunked), the bounded read still stops at the limit.
    let mut chunked = format!("{:x}\r\n", big.len()).into_bytes();
    chunked.extend_from_slice(&big);
    chunked.extend_from_slice(b"\r\n0\r\n\r\n");
    let r = host.raw(
        "POST",
        &repo.path("push"),
        Some(&token),
        &chunked,
        "Transfer-Encoding: chunked\r\n",
    );
    assert_error(&r, 413, "too_large");
}

#[test]
fn member_limit_is_quota_exceeded() {
    let host = start_with(|s| s.limits.max_members = 2);
    let (mut repo, token) = created(&host);
    add_member(&host, &mut repo, &token, &Device::new());
    let third = Device::new().entry(&repo.data_key, 0, host.key());
    let next = repo.next(|s| s.members.push(third));
    let r = host.post(
        &repo.path("manifest"),
        Some(&token),
        &json!({ "manifest": to_json(&next) }),
    );
    assert_error(&r, 429, "quota_exceeded");
}

#[test]
fn repo_limit_per_owner_is_quota_exceeded() {
    let host = start_with(|s| s.limits.max_repos_per_owner = 1);
    let (repo, token) = created(&host);
    // A second repository by the same owner key.
    let mut second = genesis(&[host.key()]);
    let nonce = random_bytes::<16>();
    let entry = repo.owner.entry(&second.data_key, 0, host.key());
    let mut s = second.tip.state.clone();
    s.owner_key = repo.owner.key();
    s.genesis_nonce = nonce.to_vec();
    s.repo_id = derive_repo_id(&repo.owner.key(), &nonce).unwrap();
    s.members = vec![entry];
    second.tip = s.sign(&repo.owner.sign).unwrap();
    second.root = commit_on(
        &second.tip,
        &second.data_key,
        &repo.owner.sign,
        Vec::new(),
        EMPTY_PAYLOAD,
    );
    let r = host.post("/v1/repos", Some(&token), &create_body(&second));
    assert_error(&r, 429, "quota_exceeded");
}

#[test]
fn challenge_cap_per_key_is_quota_exceeded() {
    let host = start_with(|s| s.limits.max_challenges_per_key = 2);
    let key = new_key();
    host.challenge(&key);
    host.challenge(&key);
    let r = host.post(
        "/api/auth/keypair/challenge",
        None,
        &json!({ "ed25519PublicKey": b64_encode(&pk(&key)) }),
    );
    assert_error(&r, 429, "quota_exceeded");
    // Another key is not affected by this key's cap.
    host.challenge(&new_key());
    // Expired challenges free their slots.
    host.advance_clock(2 * 60 * 1000 + 1);
    host.challenge(&key);
}

#[test]
fn challenge_global_cap_evicts_the_oldest() {
    // One caller filling the global table cannot lock out the next caller: the oldest challenge is
    // evicted instead of answering 429.
    let host = start_with(|s| s.limits.max_challenges = 2);
    let (a, b, c) = (new_key(), new_key(), new_key());
    let na = host.challenge(&a);
    host.advance_clock(1);
    let nb = host.challenge(&b);
    host.advance_clock(1);
    let nc = host.challenge(&c);
    let sign = |k: &SigningKey, n: &str| host.sign_challenge(k, n);
    assert_error(&host.redeem(&a, &na, &sign(&a, &na)), 401, "unauthorized");
    assert_eq!(host.redeem(&b, &nb, &sign(&b, &nb)).status, 200);
    assert_eq!(host.redeem(&c, &nc, &sign(&c, &nc)).status, 200);
}

#[test]
fn token_cap_per_key_is_quota_exceeded() {
    let host = start_with(|s| s.limits.max_tokens_per_key = 2);
    let key = new_key();
    host.login(&key);
    host.login(&key);
    let nonce = host.challenge(&key);
    let r = host.redeem(&key, &nonce, &host.sign_challenge(&key, &nonce));
    assert_error(&r, 429, "quota_exceeded");
    // Another key still logs in.
    host.login(&new_key());
}

#[test]
fn token_global_cap_evicts_the_oldest() {
    let host = start_with(|s| s.limits.max_tokens = 2);
    let (r1, t1) = created(&host);
    host.advance_clock(1);
    let (r2, t2) = created(&host);
    host.advance_clock(1);
    let (r3, t3) = created(&host);
    assert_error(&pull(&host, &r1, &t1, 0, &[]), 401, "unauthorized");
    assert_eq!(pull(&host, &r2, &t2, 0, &[]).status, 200);
    assert_eq!(pull(&host, &r3, &t3, 0, &[]).status, 200);
}

fn prepare(host: &Host, key: &SigningKey, token: &str) -> Reply {
    host.post(
        "/v1/prepare-join",
        Some(token),
        &json!({ "repoId": genesis(&[host.key()]).id(), "memberKey": b64_encode(&pk(key)) }),
    )
}

#[test]
fn acceptance_cap_per_key_is_quota_exceeded() {
    let host = start_with(|s| s.limits.max_pending_joins_per_key = 2);
    let carol = new_key();
    let token = host.login(&carol);
    assert_eq!(prepare(&host, &carol, &token).status, 200);
    assert_eq!(prepare(&host, &carol, &token).status, 200);
    assert_error(&prepare(&host, &carol, &token), 429, "quota_exceeded");
    let bob = new_key();
    let bob_token = host.login(&bob);
    assert_eq!(
        prepare(&host, &bob, &bob_token).status,
        200,
        "another key is not affected"
    );
}

#[test]
fn acceptance_global_cap_evicts_the_oldest() {
    let host = start_with(|s| s.limits.max_pending_joins = 2);
    let mut issued = Vec::new();
    for _ in 0..3 {
        let k = new_key();
        let t = host.login(&k);
        let r = prepare(&host, &k, &t);
        assert_eq!(r.status, 200);
        issued.push((r.json["repoId"].as_str().unwrap().to_string(), pk(&k)));
        host.advance_clock(1);
    }
    let st = host.state.lock().unwrap();
    assert_eq!(st.store.pending_join.len(), 2);
    assert!(
        !st.store.pending_join.contains_key(&issued[0]),
        "the oldest acceptance is evicted"
    );
    assert!(st.store.pending_join.contains_key(&issued[1]));
    assert!(st.store.pending_join.contains_key(&issued[2]));
}

// ─── Fix round 1: reject paths SPEC lists ───────────────────────────────────────────────

fn sealed(key: &SigningKey, header: CommitHeader, data_key: &[u8; 32]) -> Commit {
    Commit::seal(data_key, header, EMPTY_PAYLOAD, key).unwrap()
}

#[test]
fn publish_carried_commit_missing_parent_lists_only_that_parent() {
    let host = start();
    let (repo, token) = created(&host);
    let next = repo.next(|s| s.share_refresh_tokens = true);
    let unknown = random_bytes::<32>();
    let c = commit_on(&next, &repo.data_key, &repo.owner.sign, vec![unknown], b"x");
    let r = host.post(
        &repo.path("manifest"),
        Some(&token),
        &json!({ "manifest": to_json(&next), "commit": to_json(&c) }),
    );
    assert_error(&r, 422, "missing_parents");
    assert_eq!(r.json["detail"], json!(b64_encode(&unknown)));
    // Nothing was adopted.
    let tip = pull(&host, &repo, &token, 0, &[]).json["manifests"].clone();
    assert_eq!(tip, json!([to_json(&repo.tip)]));
}

#[test]
fn publish_carried_commit_beyond_bound_is_too_many_heads() {
    let host = start();
    let (repo, token) = created(&host);
    for i in 0..16 {
        let c = repo.commit(&repo.owner.sign, vec![repo.root.commit_id], format!("{i}").as_bytes());
        assert_eq!(push(&host, &repo, &token, &c).status, 200);
    }
    let next = repo.next(|s| s.share_refresh_tokens = true);
    let c = commit_on(
        &next,
        &repo.data_key,
        &repo.owner.sign,
        vec![repo.root.commit_id],
        b"17",
    );
    let r = host.post(
        &repo.path("manifest"),
        Some(&token),
        &json!({ "manifest": to_json(&next), "commit": to_json(&c) }),
    );
    assert_error(&r, 409, "too_many_heads");
}

#[test]
fn create_non_genesis_state_is_bad_request() {
    let host = start();
    let repo = genesis(&[host.key()]);
    let token = host.login(&repo.owner.sign);
    let seq2 = repo.next(|s| s.share_refresh_tokens = true);
    let c = commit_on(&seq2, &repo.data_key, &repo.owner.sign, Vec::new(), EMPTY_PAYLOAD);
    let r = host.post(
        "/v1/repos",
        Some(&token),
        &json!({ "manifest": to_json(&seq2), "commit": to_json(&c) }),
    );
    assert_error(&r, 400, "bad_request");
}

#[test]
fn create_first_commit_rules_are_bad_request() {
    let host = start();
    let repo = genesis(&[host.key()]);
    let token = host.login(&repo.owner.sign);
    let g = &repo.tip;
    let base = CommitHeader {
        repo_id: repo.id(),
        parents: Vec::new(),
        manifest_seq: 1,
        manifest_hash: g.hash().unwrap(),
        key_epoch: 0,
    };
    let owner = &repo.owner.sign;
    let dk = &repo.data_key;
    let cases = [
        (
            "has a parent",
            sealed(
                owner,
                CommitHeader {
                    parents: vec![[5; 32]],
                    ..base.clone()
                },
                dk,
            ),
        ),
        (
            "wrong manifest hash",
            sealed(
                owner,
                CommitHeader {
                    manifest_hash: [6; 32],
                    ..base.clone()
                },
                dk,
            ),
        ),
        (
            "wrong seq",
            sealed(
                owner,
                CommitHeader {
                    manifest_seq: 2,
                    ..base.clone()
                },
                dk,
            ),
        ),
        ("author not owner", sealed(&new_key(), base.clone(), dk)),
        (
            "keyEpoch not 0",
            sealed(
                owner,
                CommitHeader {
                    key_epoch: 1,
                    ..base.clone()
                },
                dk,
            ),
        ),
    ];
    for (name, c) in &cases {
        let r = host.post(
            "/v1/repos",
            Some(&token),
            &json!({ "manifest": to_json(g), "commit": to_json(c) }),
        );
        assert_eq!(r.status, 400, "{name}: {}", r.json);
        assert_eq!(r.json["code"], json!("bad_request"), "{name}");
    }
    let r = host.post("/v1/repos", Some(&token), &json!({ "manifest": to_json(g) }));
    assert_error(&r, 400, "bad_request");
    assert!(host.state.lock().unwrap().store.repos.is_empty());
}

#[test]
fn forged_colliding_genesis_is_bad_request_not_duplicate() {
    let host = start();
    let (repo, _) = created(&host);
    // Mallory reuses the existing repoId under her own owner key: the repoId does not recompute.
    let mallory = genesis(&[host.key()]);
    let mut s = mallory.tip.state.clone();
    s.repo_id = repo.id();
    let forged = s.sign(&mallory.owner.sign).unwrap();
    let c = commit_on(
        &forged,
        &mallory.data_key,
        &mallory.owner.sign,
        Vec::new(),
        EMPTY_PAYLOAD,
    );
    let t = host.login(&mallory.owner.sign);
    let r = host.post(
        "/v1/repos",
        Some(&t),
        &json!({ "manifest": to_json(&forged), "commit": to_json(&c) }),
    );
    assert_error(&r, 400, "bad_request");
    // The same genesis with a bad owner signature.
    let mut bad_sig = repo.tip.clone();
    bad_sig.owner_signature[0] ^= 1;
    let t = host.login(&repo.owner.sign);
    let r = host.post(
        "/v1/repos",
        Some(&t),
        &json!({ "manifest": to_json(&bad_sig), "commit": to_json(&repo.root) }),
    );
    assert_error(&r, 400, "bad_request");
}

#[test]
fn push_epoch_mismatch_is_forbidden() {
    let host = start();
    let (repo, token) = created(&host);
    let header = CommitHeader {
        repo_id: repo.id(),
        parents: vec![repo.root.commit_id],
        manifest_seq: 1,
        manifest_hash: repo.tip.hash().unwrap(),
        key_epoch: 1,
    };
    let c = sealed(&repo.owner.sign, header, &repo.data_key);
    assert_error(&push(&host, &repo, &token, &c), 403, "forbidden");
}

#[test]
fn publish_dropping_this_host_is_not_hosted() {
    let host = start();
    let other = pk(&new_key());
    // The owner's home is the other host, so a state listing only it passes the content rules.
    let repo = genesis(&[other, host.key()]);
    let token = host.login(&repo.owner.sign);
    assert_eq!(host.post("/v1/repos", Some(&token), &create_body(&repo)).status, 200);
    let next = repo.next(|s| s.hosts.retain(|h| h.key == other));
    let r = host.post(
        &repo.path("manifest"),
        Some(&token),
        &json!({ "manifest": to_json(&next) }),
    );
    assert_error(&r, 403, "not_hosted");
}

#[test]
fn leave_by_outsider_is_forbidden() {
    let host = start();
    let (repo, _) = created(&host);
    let outsider = new_key();
    let t = host.login(&outsider);
    let own = leave_request(&repo, &outsider);
    assert_error(
        &host.post(&repo.path("leave"), Some(&t), &to_json(&own)),
        403,
        "forbidden",
    );
}

#[test]
fn pull_returns_states_after_since_in_ascending_order() {
    let host = start();
    let (mut repo, token) = created(&host);
    add_member(&host, &mut repo, &token, &Device::new());
    let seq2 = repo.tip.clone();
    add_member(&host, &mut repo, &token, &Device::new());
    let seq3 = repo.tip.clone();
    let r = pull(&host, &repo, &token, 1, &[]);
    assert_eq!(r.json["manifests"], json!([to_json(&seq2), to_json(&seq3)]));
    let r = pull(&host, &repo, &token, 3, &[]);
    assert_eq!(r.json["manifests"], json!([]));
}

#[test]
fn poisoned_state_is_an_error_response() {
    let host = start();
    let state = Arc::clone(&host.state);
    let _ = std::thread::spawn(move || {
        let _guard = state.lock().unwrap();
        panic!("poison the state lock");
    })
    .join();
    assert!(host.state.is_poisoned());
    let r = host.get("/.well-known/avp");
    assert_eq!(r.status, 500);
    assert!(r.json["error"].is_string());
    // The worker survived: a second request is answered too.
    assert_eq!(host.get("/.well-known/avp").status, 500);
}
