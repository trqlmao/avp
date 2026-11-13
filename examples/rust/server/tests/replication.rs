// SPDX-License-Identifier: MIT

//! Host-to-host replication tests (SPEC 6.1 rule 6, 6.5, 8.3, 8.6, 9, 10.1).
//!
//! Hosts run in-process on port 0 and replicate with each other over real HTTP with signed host
//! requests (SPEC 9.3). Some tests drive a host directly as a "fake peer": a test-held host key that
//! the host lists in its peers, so the test can send signed `heads`, `fetch`, and `offer` requests and
//! read the exact answers. Every item is built with the `avp` crate (real owner, member, and host
//! keys and signatures); the engine is the real `RepoView`.
//!
//! Convergence is polled every 25 ms for at most 15 s; the hosts sweep every 100 ms in these tests
//! (the default is 5 s).

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use avp::commit::{Commit, CommitHeader};
use avp::crypto::{SCHEME_ID, WRAP_INFO, random_bytes, sha256, wrap, x25519_public, x25519_random};
use avp::encoding::{Ce, b64_decode, b64_encode};
use avp::manifest::{HostRef, ManifestState, MemberEntry, Removal, SignedManifest, derive_repo_id};
use avp::rules::{CommitStatus, RepoView};
use avp::tokens::LeaveRequest;
use avp_reference_server::replication::{Outgoing, Peers, Replication, run};
use avp_reference_server::{Serving, State, serve};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use x25519_dalek::StaticSecret;

type Id = [u8; 32];

const SWEEP: Duration = Duration::from_millis(100);
const CONVERGE: Duration = Duration::from_secs(15);

// ─── Harness ────────────────────────────────────────────────────────────────────────────

/// A running host. `repl` is declared first so it stops before the listener.
struct Node {
    repl: Option<Replication>,
    serving: Serving,
    state: Arc<Mutex<State>>,
    sign: SigningKey,
}

struct Reply {
    status: u16,
    json: Value,
}

fn node() -> Node {
    node_with(true)
}

fn node_with(test_control: bool) -> Node {
    let sign = new_key();
    let mut state = State::new(sign.clone());
    state.replication.sweep_interval = SWEEP;
    state.replication.request_timeout = Duration::from_secs(1);
    state.replication.max_response_bytes = 256 * 1024;
    state.replication.test_control = test_control;
    let state = Arc::new(Mutex::new(state));
    let serving = serve("127.0.0.1:0", Arc::clone(&state)).expect("bind an ephemeral port");
    Node {
        repl: None,
        serving,
        state,
        sign,
    }
}

/// Peers every node with every other one (`AVP_PEERS` built from their keys and addresses).
fn link(nodes: &mut [&mut Node]) {
    let entries: Vec<String> = nodes.iter().map(|n| n.entry()).collect();
    for (i, n) in nodes.iter_mut().enumerate() {
        let others: Vec<String> = entries
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, e)| e.clone())
            .collect();
        n.peer_with(&others);
    }
}

impl Node {
    fn key(&self) -> Id {
        pk(&self.sign)
    }

    fn entry(&self) -> String {
        format!("{}@http://{}", b64_encode(&self.key()), self.serving.addr())
    }

    fn peer_with(&mut self, entries: &[String]) {
        let peers = Peers::from_env(&entries.join(",")).expect("valid AVP_PEERS");
        self.repl = Some(run(Arc::clone(&self.state), peers).expect("start replication"));
    }

    fn raw(&self, method: &str, path: &str, headers: &[(String, String)], body: &[u8]) -> Reply {
        raw_call(self.serving.addr(), method, path, headers, body)
    }

    fn post(&self, path: &str, token: Option<&str>, body: &Value) -> Reply {
        let mut headers = Vec::new();
        if let Some(t) = token {
            headers.push(("Authorization".to_string(), format!("Bearer {t}")));
        }
        self.raw("POST", path, &headers, body.to_string().as_bytes())
    }

    fn login(&self, key: &SigningKey) -> String {
        let r = self.post(
            "/api/auth/keypair/challenge",
            None,
            &json!({ "ed25519PublicKey": b64_encode(&pk(key)) }),
        );
        assert_eq!(r.status, 200, "challenge: {}", r.json);
        let nonce = r.json["nonce"].as_str().unwrap().to_string();
        let sig = key.sign(&b64_decode(&nonce).unwrap()).to_bytes();
        let r = self.post(
            "/api/auth/keypair/token",
            None,
            &json!({ "ed25519PublicKey": b64_encode(&pk(key)), "nonce": nonce, "signature": b64_encode(&sig) }),
        );
        assert_eq!(r.status, 200, "token: {}", r.json);
        r.json["token"].as_str().unwrap().to_string()
    }

    fn view<R>(&self, repo: &str, f: impl FnOnce(&RepoView) -> R) -> Option<R> {
        let st = self.state.lock().unwrap();
        st.store.repos.get(repo).map(f)
    }

    fn holds(&self, repo: &str) -> bool {
        self.view(repo, |_| ()).is_some()
    }

    fn heads(&self, repo: &str) -> Vec<Id> {
        self.view(repo, RepoView::heads).unwrap_or_default()
    }

    fn tip_hash(&self, repo: &str) -> Option<Id> {
        self.view(repo, |v| v.tip().map(|t| t.hash().unwrap())).flatten()
    }

    fn pause(&self, paused: bool) {
        let r = self.post("/v1/test/replication", None, &json!({ "paused": paused }));
        assert_eq!(r.status, 200, "test control: {}", r.json);
    }

    /// A signed host request from `peer` (SPEC 9.3), timestamped now.
    fn host(&self, peer: &SigningKey, repo: &str, op: &str, body: &Value) -> Reply {
        let path = host_path(repo, op);
        let bytes = body.to_string().into_bytes();
        self.raw(
            "POST",
            &path,
            &host_headers(peer, "POST", &path, &bytes, now_ms()),
            &bytes,
        )
    }
}

fn raw_call(addr: SocketAddr, method: &str, path: &str, headers: &[(String, String)], body: &[u8]) -> Reply {
    let mut stream = TcpStream::connect(addr).expect("connect");
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: vault.example\r\nConnection: close\r\n");
    head.push_str(&format!(
        "Content-Length: {}\r\nContent-Type: application/json\r\n",
        body.len()
    ));
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).unwrap();
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
    let json = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(body).expect("json body")
    };
    Reply { status, json }
}

fn host_path(repo: &str, op: &str) -> String {
    format!("/v1/host/repos/{repo}/{op}")
}

/// `AVP-Host-Signature` built here from the SPEC 9.3 layout, independently of the host:
/// `CE(tag "avp/host-req/v1", str(method), str(path), bytes(SHA-256(body)), i64(time))`.
fn host_signature(key: &SigningKey, method: &str, path: &str, body: &[u8], time: i64) -> String {
    let mut w = Ce::new("avp/host-req/v1");
    w.str(method).str(path).bytes(&sha256(body)).i64(time);
    b64_encode(&key.sign(&w.finish().unwrap()).to_bytes())
}

fn host_headers(key: &SigningKey, method: &str, path: &str, body: &[u8], time: i64) -> Vec<(String, String)> {
    vec![
        ("AVP-Host-Key".to_string(), b64_encode(&pk(key))),
        ("AVP-Host-Time".to_string(), time.to_string()),
        (
            "AVP-Host-Signature".to_string(),
            host_signature(key, method, path, body, time),
        ),
    ]
}

/// A test-held host key listed in a host's `AVP_PEERS` at an address nothing listens on.
struct FakePeer {
    sign: SigningKey,
}

impl FakePeer {
    fn new() -> FakePeer {
        FakePeer { sign: new_key() }
    }

    fn key(&self) -> Id {
        pk(&self.sign)
    }

    fn entry(&self) -> String {
        format!("{}@http://127.0.0.1:9", b64_encode(&self.key()))
    }
}

/// A host peered only with a fake peer.
fn node_with_fake() -> (Node, FakePeer) {
    let mut b = node();
    let p = FakePeer::new();
    b.peer_with(&[p.entry()]);
    (b, p)
}

fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + CONVERGE;
    while Instant::now() < deadline {
        if f() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("not reached within {CONVERGE:?}: {what}");
}

fn now_ms() -> i64 {
    i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()).unwrap()
}

fn assert_error(r: &Reply, status: u16, code: &str) {
    assert_eq!(r.status, status, "body: {}", r.json);
    assert!(r.json["error"].is_string(), "error message present: {}", r.json);
    assert_eq!(r.json["code"], json!(code), "body: {}", r.json);
}

fn pk(key: &SigningKey) -> Id {
    key.verifying_key().to_bytes()
}

fn new_key() -> SigningKey {
    SigningKey::from_bytes(&random_bytes::<32>())
}

fn to_json<T: serde::Serialize>(v: &T) -> Value {
    serde_json::to_value(v).unwrap()
}

fn ids(v: &[Id]) -> Value {
    json!(v.iter().map(|id| b64_encode(id)).collect::<Vec<_>>())
}

fn hash(m: &SignedManifest) -> Id {
    m.hash().unwrap()
}

fn sorted(mut v: Vec<Id>) -> Vec<Id> {
    v.sort_unstable();
    v
}

/// The ids of a JSON id list as a set.
fn id_set(v: &Value) -> HashSet<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect()
}

fn b64_set(v: &[Id]) -> HashSet<String> {
    v.iter().map(|id| b64_encode(id)).collect()
}

/// The `rejected` list of an offer answer as `(id, code)` pairs.
fn rejected(r: &Reply) -> HashSet<(String, String)> {
    r.json["rejected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                x["id"].as_str().unwrap().to_string(),
                x["code"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

fn pair(id: &Id, code: &str) -> (String, String) {
    (b64_encode(id), code.to_string())
}

// ─── Repository fixtures built with the avp crate ───────────────────────────────────────

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

    fn key(&self) -> Id {
        pk(&self.sign)
    }

    fn entry(&self, data_key: &[u8; 32], epoch: i64, home: Id) -> MemberEntry {
        MemberEntry {
            ed25519_public_key: self.key(),
            x25519_public_key: x25519_public(&self.x),
            wrapped_data_key: wrap(&x25519_public(&self.x), data_key, WRAP_INFO).unwrap(),
            key_epoch: epoch,
            home_host_key: home,
        }
    }
}

struct Repo {
    owner: Device,
    data_key: [u8; 32],
    genesis: SignedManifest,
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
        next_of(&self.tip, &self.owner.sign, f)
    }

    fn commit(&self, author: &SigningKey, parents: Vec<Id>, plaintext: &[u8]) -> Commit {
        commit_on(&self.tip, &self.data_key, author, parents, plaintext)
    }
}

fn next_of(tip: &SignedManifest, owner: &SigningKey, f: impl FnOnce(&mut ManifestState)) -> SignedManifest {
    let mut s = tip.state.clone();
    s.manifest_seq += 1;
    s.prev_manifest_hash = tip.hash().unwrap().to_vec();
    s.genesis_nonce = Vec::new();
    f(&mut s);
    s.sign(owner).unwrap()
}

fn commit_on(
    cites: &SignedManifest,
    data_key: &[u8; 32],
    author: &SigningKey,
    parents: Vec<Id>,
    text: &[u8],
) -> Commit {
    let header = CommitHeader {
        repo_id: cites.state.repo_id.clone(),
        parents,
        manifest_seq: cites.state.manifest_seq,
        manifest_hash: cites.hash().unwrap(),
        key_epoch: cites.state.key_epoch,
    };
    Commit::seal(data_key, header, text, author).unwrap()
}

const EMPTY_PAYLOAD: &[u8] = br#"{"v":2,"accounts":{}}"#;

/// The genesis state of a new repository listing `hosts`, with the owner homed on `home`.
fn genesis(hosts: &[Id], home: Id) -> Repo {
    let owner = Device::new();
    let data_key = random_bytes::<32>();
    let nonce = random_bytes::<16>();
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
        genesis: tip.clone(),
        tip,
        root,
    }
}

/// Creates `repo` on `node` through `createRepo` and returns the owner's token there.
fn create(node: &Node, repo: &Repo) -> String {
    let token = node.login(&repo.owner.sign);
    let r = node.post(
        "/v1/repos",
        Some(&token),
        &json!({ "manifest": to_json(&repo.tip), "commit": to_json(&repo.root) }),
    );
    assert_eq!(r.status, 200, "createRepo: {}", r.json);
    token
}

fn publish(node: &Node, repo: &Repo, token: &str, m: &SignedManifest, c: Option<&Commit>) -> Reply {
    let mut body = json!({ "manifest": to_json(m) });
    if let Some(c) = c {
        body["commit"] = to_json(c);
    }
    node.post(&repo.path("manifest"), Some(token), &body)
}

fn push(node: &Node, repo: &Repo, token: &str, c: &Commit) -> Reply {
    node.post(&repo.path("push"), Some(token), &json!({ "commit": to_json(c) }))
}

fn pull(node: &Node, repo: &Repo, token: &str) -> Reply {
    node.post(
        &repo.path("pull"),
        Some(token),
        &json!({ "sinceManifestSeq": 0, "knownHeads": [] }),
    )
}

fn offer(repo: &str, manifests: &[&SignedManifest], commits: &[&Commit], leaves: &[&LeaveRequest]) -> Value {
    json!({
        "repoId": repo,
        "manifests": manifests.iter().map(to_json).collect::<Vec<_>>(),
        "commits": commits.iter().map(to_json).collect::<Vec<_>>(),
        "leaves": leaves.iter().map(to_json).collect::<Vec<_>>(),
    })
}

fn fetch_body(repo: &str, want: &[Id]) -> Value {
    json!({ "repoId": repo, "ids": ids(want) })
}

/// An epoch-raising state on `repo`'s tip that keeps `members` (owner first), optionally removing
/// one with a frontier, and its rotation commit with `parents` (SPEC 8.3).
fn rotation(
    repo: &Repo,
    members: &[&Device],
    removed: Option<(&Device, Vec<Id>)>,
    parents: Vec<Id>,
    home: Id,
) -> (SignedManifest, Commit, [u8; 32]) {
    let new_key = random_bytes::<32>();
    let epoch = repo.tip.state.key_epoch + 1;
    let entries: Vec<MemberEntry> = members.iter().map(|d| d.entry(&new_key, epoch, home)).collect();
    let state = repo.next(|s| {
        s.key_epoch = epoch;
        s.members = entries;
        if let Some((who, frontier)) = removed {
            s.removals.push(Removal {
                member_key: who.key(),
                removed_at_seq: s.manifest_seq,
                frontier,
            });
        }
    });
    let commit = commit_on(&state, &new_key, &repo.owner.sign, parents, b"rotation");
    (state, commit, new_key)
}

/// The first of `make(0)`, `make(1)`, ... whose state hash is in the upper half (first byte at least
/// 0x80), so that [`winner_against`] finds a lower-hash state quickly whatever the random keys.
fn upper_half<T>(mut make: impl FnMut(u32) -> T, state: impl Fn(&T) -> &SignedManifest) -> T {
    for n in 0..64 {
        let t = make(n);
        if hash(state(&t))[0] >= 0x80 {
            return t;
        }
    }
    panic!("no upper-half variant found");
}

/// A state on `repo`'s tip that wins the tie rule against `loser` (bytewise-lower hash, SPEC 6.5):
/// the tip with its first host locator changed, retried until its hash is lower. Each try wins with
/// probability at least one half for an [`upper_half`] loser.
fn winner_against(repo: &Repo, loser: &SignedManifest) -> SignedManifest {
    for n in 0..256 {
        let w = repo.next(|s| s.hosts[0].locator = format!("v{n}.vault.example"));
        if hash(&w) < hash(loser) {
            return w;
        }
    }
    panic!("no winning variant found");
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
fn write_on_a_reaches_b() {
    let mut a = node();
    let mut b = node();
    link(&mut [&mut a, &mut b]);
    let mut repo = genesis(&[a.key(), b.key()], a.key());
    let token = create(&a, &repo);
    let id = repo.id();

    // createRepo is offered to B, which takes its first copy from the genesis (SPEC 9.2).
    eventually("B holds the genesis", || b.tip_hash(&id) == Some(hash(&repo.genesis)));
    eventually("B has the first commit", || b.heads(&id) == vec![repo.root.commit_id]);

    let c1 = repo.commit(&repo.owner.sign, vec![repo.root.commit_id], b"one");
    assert_eq!(push(&a, &repo, &token, &c1).status, 200);
    eventually("B has the pushed commit", || b.heads(&id) == vec![c1.commit_id]);

    // B serves it to a client: the owner pulls from B.
    let tb = b.login(&repo.owner.sign);
    let r = pull(&b, &repo, &tb);
    assert_eq!(r.status, 200, "{}", r.json);
    assert_eq!(r.json["heads"], json!([to_json(&c1)]));
    assert_eq!(r.json["manifests"], json!([to_json(&repo.genesis)]));

    // A manifest state replicates too.
    let s2 = repo.next(|s| s.share_refresh_tokens = true);
    assert_eq!(publish(&a, &repo, &token, &s2, None).status, 200);
    repo.tip = s2;
    eventually("B has seq 2", || b.tip_hash(&id) == Some(hash(&repo.tip)));
}

#[test]
fn partition_then_heal_converges() {
    let mut a = node();
    let mut b = node();
    link(&mut [&mut a, &mut b]);
    let repo = genesis(&[a.key(), b.key()], a.key());
    let ta = create(&a, &repo);
    let id = repo.id();
    eventually("B holds the repository", || b.heads(&id) == vec![repo.root.commit_id]);
    let tb = b.login(&repo.owner.sign);

    a.pause(true);
    b.pause(true);
    let ca = repo.commit(&repo.owner.sign, vec![repo.root.commit_id], b"on a");
    let cb = repo.commit(&repo.owner.sign, vec![repo.root.commit_id], b"on b");
    assert_eq!(push(&a, &repo, &ta, &ca).status, 200);
    assert_eq!(push(&b, &repo, &tb, &cb).status, 200);
    // Paused: no host traffic for several sweep intervals.
    thread::sleep(SWEEP * 6);
    assert_eq!(a.heads(&id), vec![ca.commit_id]);
    assert_eq!(b.heads(&id), vec![cb.commit_id]);

    a.pause(false);
    b.pause(false);
    let both = sorted(vec![ca.commit_id, cb.commit_id]);
    eventually("A and B report the same two heads", || {
        a.heads(&id) == both && b.heads(&id) == both
    });
}

#[test]
fn host_not_in_hosts_is_refused() {
    // Deviation from the brief (SPEC wins): a peer whose key is not in the repository's hosts in the
    // serving host's tip gets 403 forbidden on heads, fetch, and offer (SPEC 9.2, openapi.yaml).
    let mut a = node();
    let mut b = node();
    let mut c = node();
    link(&mut [&mut a, &mut b, &mut c]);
    let repo = genesis(&[a.key(), b.key()], a.key());
    create(&a, &repo);
    let id = repo.id();
    eventually("B holds the repository", || b.holds(&id));

    let r = a.host(&c.sign, &id, "heads", &json!({ "repoId": id }));
    assert_error(&r, 403, "forbidden");
    let r = a.host(&c.sign, &id, "fetch", &fetch_body(&id, &[hash(&repo.genesis)]));
    assert_error(&r, 403, "forbidden");
    let r = a.host(&c.sign, &id, "offer", &offer(&id, &[], &[&repo.root], &[]));
    assert_error(&r, 403, "forbidden");

    // A never offers the repository to C, and C never takes it.
    thread::sleep(SWEEP * 6);
    assert!(!c.holds(&id));
}

#[test]
fn bad_host_signature_rejected() {
    let (b, p) = node_with_fake();
    let repo = genesis(&[b.key(), p.key()], b.key());
    create(&b, &repo);
    let id = repo.id();
    let path = host_path(&id, "heads");
    let body = json!({ "repoId": id }).to_string().into_bytes();
    let now = now_ms();

    // Control: a correct signature is accepted.
    let r = b.raw("POST", &path, &host_headers(&p.sign, "POST", &path, &body, now), &body);
    assert_eq!(r.status, 200, "{}", r.json);

    // Signed by another key under the peer's key header.
    let mut h = host_headers(&p.sign, "POST", &path, &body, now);
    h[2].1 = host_signature(&new_key(), "POST", &path, &body, now);
    assert_error(&b.raw("POST", &path, &h, &body), 401, "unauthorized");

    // Random signature bytes; signature over another time; not base64; wrong length.
    let mut h = host_headers(&p.sign, "POST", &path, &body, now);
    h[2].1 = b64_encode(&random_bytes::<64>());
    assert_error(&b.raw("POST", &path, &h, &body), 401, "unauthorized");
    let mut h = host_headers(&p.sign, "POST", &path, &body, now);
    h[1].1 = (now + 1).to_string();
    assert_error(&b.raw("POST", &path, &h, &body), 401, "unauthorized");
    let mut h = host_headers(&p.sign, "POST", &path, &body, now);
    h[2].1 = "not base64!".to_string();
    assert_error(&b.raw("POST", &path, &h, &body), 401, "unauthorized");
    let mut h = host_headers(&p.sign, "POST", &path, &body, now);
    h[2].1 = b64_encode(&random_bytes::<32>());
    assert_error(&b.raw("POST", &path, &h, &body), 401, "unauthorized");

    // A correctly self-signed key that is not in the static peer list.
    let stranger = new_key();
    let h = host_headers(&stranger, "POST", &path, &body, now);
    assert_error(&b.raw("POST", &path, &h, &body), 401, "unauthorized");

    // Each header missing, a malformed key, a non-decimal time.
    for drop in 0..3 {
        let mut h = host_headers(&p.sign, "POST", &path, &body, now);
        h.remove(drop);
        assert_error(&b.raw("POST", &path, &h, &body), 401, "unauthorized");
    }
    let mut h = host_headers(&p.sign, "POST", &path, &body, now);
    h[0].1 = b64_encode(&random_bytes::<31>());
    assert_error(&b.raw("POST", &path, &h, &body), 401, "unauthorized");
    let mut h = host_headers(&p.sign, "POST", &path, &body, now);
    h[1].1 = "soon".to_string();
    assert_error(&b.raw("POST", &path, &h, &body), 401, "unauthorized");
}

#[test]
fn stale_timestamp_rejected() {
    let (b, p) = node_with_fake();
    let repo = genesis(&[b.key(), p.key()], b.key());
    create(&b, &repo);
    let id = repo.id();
    let path = host_path(&id, "heads");
    let body = json!({ "repoId": id }).to_string().into_bytes();

    // SPEC 9.3: |now - time| over 60 seconds is 401, in either direction.
    for skew in [-61_000, 61_000, -3_600_000] {
        let h = host_headers(&p.sign, "POST", &path, &body, now_ms() + skew);
        assert_error(&b.raw("POST", &path, &h, &body), 401, "unauthorized");
    }
    // Within the window it is accepted.
    for skew in [-59_000, 59_000] {
        let h = host_headers(&p.sign, "POST", &path, &body, now_ms() + skew);
        assert_eq!(b.raw("POST", &path, &h, &body).status, 200);
    }
}

#[test]
fn offer_revalidates() {
    let mut a = node();
    let mut b = node();
    let p = FakePeer::new();
    a.peer_with(&[b.entry()]);
    b.peer_with(&[a.entry(), p.entry()]);
    let repo = genesis(&[a.key(), b.key(), p.key()], a.key());
    create(&a, &repo);
    let id = repo.id();
    eventually("B holds the repository", || b.heads(&id) == vec![repo.root.commit_id]);

    // Commits A was tricked into storing: they go into A's outbox behind the engine's back, so A
    // offers them to B as if it had accepted them.
    let mut forged = repo.commit(&repo.owner.sign, vec![repo.root.commit_id], b"forged");
    forged.author_signature[0] ^= 1;
    let stranger = Device::new();
    let outsider = repo.commit(&stranger.sign, vec![repo.root.commit_id], b"outsider");
    a.state.lock().unwrap().store.outbox.push(Outgoing {
        repo_id: id.clone(),
        manifests: Vec::new(),
        commits: vec![forged.clone(), outsider.clone()],
        leaves: Vec::new(),
    });

    // B validates each item with the engine and rejects both (SPEC 9: whatever the transport).
    eventually("B rejected the outsider's commit", || {
        b.view(&id, |v| v.status(&outsider.commit_id)) == Some(Some(CommitStatus::Rejected))
    });
    assert_eq!(b.view(&id, |v| v.status(&forged.commit_id)), Some(None));
    assert_eq!(b.heads(&id), vec![repo.root.commit_id]);

    // The per-item codes are the ones the engine gives a client (SPEC 9.1).
    let orphan = repo.commit(&repo.owner.sign, vec![random_bytes::<32>()], b"orphan");
    let r = b.host(
        &p.sign,
        &id,
        "offer",
        &offer(&id, &[], &[&forged, &outsider, &orphan], &[]),
    );
    assert_eq!(r.status, 200, "{}", r.json);
    assert_eq!(r.json["accepted"], json!([]));
    assert_eq!(
        rejected(&r),
        HashSet::from([
            pair(&forged.commit_id, "bad_request"),
            pair(&outsider.commit_id, "forbidden"),
            pair(&orphan.commit_id, "missing_parents"),
        ])
    );
    assert_eq!(b.heads(&id), vec![repo.root.commit_id]);
}

// ─── Host request authentication (SPEC 9.3) ─────────────────────────────────────────────

#[test]
fn body_not_matching_signed_hash_rejected() {
    let (b, p) = node_with_fake();
    let repo = genesis(&[b.key(), p.key()], b.key());
    create(&b, &repo);
    let id = repo.id();
    let path = host_path(&id, "fetch");
    let signed = fetch_body(&id, &[]).to_string().into_bytes();
    let sent = fetch_body(&id, &[hash(&repo.genesis)]).to_string().into_bytes();
    let h = host_headers(&p.sign, "POST", &path, &signed, now_ms());
    assert_error(&b.raw("POST", &path, &h, &sent), 401, "unauthorized");
    // One extra byte of whitespace is a different body.
    let mut spaced = signed.clone();
    spaced.push(b' ');
    assert_error(&b.raw("POST", &path, &h, &spaced), 401, "unauthorized");
    // Control: the signed body itself is accepted, and the signature covers its hash.
    let r = b.raw("POST", &path, &h, &signed);
    assert_eq!(r.status, 200, "{}", r.json);
    let h = host_headers(&p.sign, "POST", &path, &sent, now_ms());
    let r = b.raw("POST", &path, &h, &sent);
    assert_eq!(r.status, 200, "{}", r.json);
    assert_eq!(r.json["manifests"], json!([to_json(&repo.genesis)]));
}

#[test]
fn path_not_matching_signed_path_rejected() {
    let (b, p) = node_with_fake();
    let repo = genesis(&[b.key(), p.key()], b.key());
    create(&b, &repo);
    let other = genesis(&[b.key(), p.key()], b.key());
    create(&b, &other);
    let id = repo.id();
    let body = json!({ "repoId": id }).to_string().into_bytes();
    // Signed for fetch, sent to heads.
    let h = host_headers(&p.sign, "POST", &host_path(&id, "fetch"), &body, now_ms());
    assert_error(&b.raw("POST", &host_path(&id, "heads"), &h, &body), 401, "unauthorized");
    // Signed for another repository, sent to this one.
    let h = host_headers(&p.sign, "POST", &host_path(&other.id(), "heads"), &body, now_ms());
    assert_error(&b.raw("POST", &host_path(&id, "heads"), &h, &body), 401, "unauthorized");
    // Signed without the query, sent with one: the path is signed as sent.
    let h = host_headers(&p.sign, "POST", &host_path(&id, "heads"), &body, now_ms());
    let with_query = format!("{}?x=1", host_path(&id, "heads"));
    let r = b.raw("POST", &with_query, &h, &body);
    assert_eq!(r.status, 200, "query is not part of the signed path: {}", r.json);
    // Signed with another method.
    let h = host_headers(&p.sign, "GET", &host_path(&id, "heads"), &body, now_ms());
    assert_error(&b.raw("POST", &host_path(&id, "heads"), &h, &body), 401, "unauthorized");
}

#[test]
fn peers_from_env_parses_and_rejects() {
    let k1 = b64_encode(&random_bytes::<32>());
    let k2 = b64_encode(&random_bytes::<32>());
    let peers = Peers::from_env(&format!(
        " {k1}@http://a.vault.example:8787/ , {k2}@http://127.0.0.1:9000"
    ))
    .unwrap();
    assert_eq!(peers.len(), 2);
    assert!(Peers::from_env("").unwrap().is_empty());
    assert!(Peers::from_env("  ").unwrap().is_empty());
    for bad in [
        k1.clone(),
        format!("{k1}@"),
        "@http://a.vault.example".to_string(),
        "not-base64@http://a.vault.example".to_string(),
        format!("{}@http://a.vault.example", b64_encode(&random_bytes::<31>())),
        format!("{k1}@https://a.vault.example"),
        format!("{k1}@a.vault.example"),
        format!("{k1}@http://"),
        format!("{k1}@http://a.vault.example/x y"),
        format!("{k1}@http://a.vault.example,{k1}@http://b.vault.example"),
    ] {
        assert!(Peers::from_env(&bad).is_err(), "accepted {bad:?}");
    }
}

// ─── Test control (SPEC 9.3) ────────────────────────────────────────────────────────────

#[test]
fn test_control_absent_without_flag() {
    let b = node_with(false);
    let r = b.post("/v1/test/replication", None, &json!({ "paused": true }));
    assert_error(&r, 404, "not_found");
}

#[test]
fn paused_host_answers_503() {
    let (b, p) = node_with_fake();
    let repo = genesis(&[b.key(), p.key()], b.key());
    create(&b, &repo);
    let id = repo.id();
    b.pause(true);
    for op in ["heads", "fetch", "offer"] {
        let body = match op {
            "fetch" => fetch_body(&id, &[]),
            "offer" => offer(&id, &[], &[], &[]),
            _ => json!({ "repoId": id }),
        };
        assert_eq!(b.host(&p.sign, &id, op, &body).status, 503, "{op}");
        // Even unsigned: paused answers before authentication.
        assert_eq!(b.post(&host_path(&id, op), None, &body).status, 503, "{op} unsigned");
    }
    // Client routes keep working.
    let token = b.login(&repo.owner.sign);
    assert_eq!(pull(&b, &repo, &token).status, 200);
    b.pause(false);
    assert_eq!(b.host(&p.sign, &id, "heads", &json!({ "repoId": id })).status, 200);
    // A malformed control body is 400.
    assert_error(
        &b.post("/v1/test/replication", None, &json!({ "paused": "yes" })),
        400,
        "bad_request",
    );
}

// ─── Host routes (SPEC 9.1, 9.2) ────────────────────────────────────────────────────────

#[test]
fn heads_and_fetch_answer_the_spec_shapes() {
    let (b, p) = node_with_fake();
    let mut repo = genesis(&[b.key(), p.key()], b.key());
    let token = create(&b, &repo);
    let id = repo.id();
    let bob = Device::new();
    let entry = bob.entry(&repo.data_key, 0, b.key());
    let s2 = repo.next(|s| s.members.push(entry));
    assert_eq!(publish(&b, &repo, &token, &s2, None).status, 200);
    repo.tip = s2.clone();
    let (s3, rot, _) = rotation(
        &repo,
        &[&repo.owner],
        Some((&bob, vec![])),
        vec![repo.root.commit_id],
        b.key(),
    );
    assert_eq!(publish(&b, &repo, &token, &s3, Some(&rot)).status, 200);

    let r = b.host(&p.sign, &id, "heads", &json!({ "repoId": id }));
    assert_eq!(r.status, 200, "{}", r.json);
    assert_eq!(
        r.json,
        json!({ "manifestTip": { "manifestSeq": 3, "manifestHash": b64_encode(&hash(&s3)) }, "heads": ids(&[rot.commit_id]) })
    );
    // The body repoId may be left out (SPEC 9.3 heads body is `{}`).
    assert_eq!(b.host(&p.sign, &id, "heads", &json!({})).status, 200);

    // fetch by the tip hash: the whole chain ascending, with the rotation commit of the
    // epoch-raising state; by a commit id: that commit; unknown ids are left out.
    let r = b.host(
        &p.sign,
        &id,
        "fetch",
        &fetch_body(&id, &[hash(&s3), repo.root.commit_id, random_bytes::<32>()]),
    );
    assert_eq!(r.status, 200, "{}", r.json);
    assert_eq!(
        r.json["manifests"],
        json!([to_json(&repo.genesis), to_json(&s2), to_json(&s3)])
    );
    assert_eq!(
        r.json["commits"]
            .as_array()
            .unwrap()
            .iter()
            .cloned()
            .collect::<HashSet<_>>(),
        HashSet::from([to_json(&rot), to_json(&repo.root)])
    );
    assert_eq!(r.json["leaves"], json!([]));

    // Unknown repository: 404; body repoId that differs from the path: 400.
    let unknown = genesis(&[b.key()], b.key()).id();
    assert_error(&b.host(&p.sign, &unknown, "heads", &json!({})), 404, "not_found");
    assert_error(
        &b.host(&p.sign, &id, "heads", &json!({ "repoId": unknown })),
        400,
        "bad_request",
    );
    assert_error(
        &b.host(&p.sign, &id, "fetch", &json!({ "repoId": id })),
        400,
        "bad_request",
    );
}

#[test]
fn newly_listed_host_bootstraps_by_replication() {
    let mut a = node();
    let mut b = node();
    link(&mut [&mut a, &mut b]);
    // The genesis lists only A: B is not offered it and does not hold it.
    let mut repo = genesis(&[a.key()], a.key());
    let token = create(&a, &repo);
    let id = repo.id();
    let c1 = repo.commit(&repo.owner.sign, vec![repo.root.commit_id], b"one");
    assert_eq!(push(&a, &repo, &token, &c1).status, 200);
    thread::sleep(SWEEP * 4);
    assert!(!b.holds(&id));

    // The owner invites bob, homed on B, adding B to hosts in seq 2 (SPEC 8.1). B takes its first
    // copy by replication from A, from the genesis on, though the genesis does not list it.
    let bob = Device::new();
    let entry = bob.entry(&repo.data_key, 0, b.key());
    let b_key = b.key();
    let s2 = repo.next(|s| {
        s.hosts.push(HostRef {
            key: b_key,
            locator: "b.vault.example".to_string(),
        });
        s.members.push(entry);
    });
    assert_eq!(publish(&a, &repo, &token, &s2, None).status, 200);
    repo.tip = s2.clone();
    eventually("B converges to A's tip and heads", || {
        b.tip_hash(&id) == Some(hash(&s2)) && b.heads(&id) == a.heads(&id)
    });
    assert_eq!(b.heads(&id), vec![c1.commit_id]);
    assert_eq!(b.view(&id, RepoView::tip_lists_host), Some(true));

    // Bob pulls from his home host.
    let tb = b.login(&bob.sign);
    let r = pull(&b, &repo, &tb);
    assert_eq!(r.status, 200, "{}", r.json);
    assert_eq!(r.json["manifests"], json!([to_json(&repo.genesis), to_json(&s2)]));
    assert_eq!(r.json["heads"], json!([to_json(&c1)]));
}

#[test]
fn rotation_reaches_b_atomically() {
    let mut a = node();
    let mut b = node();
    link(&mut [&mut a, &mut b]);
    let mut repo = genesis(&[a.key(), b.key()], a.key());
    let token = create(&a, &repo);
    let id = repo.id();
    let bob = Device::new();
    let entry = bob.entry(&repo.data_key, 0, a.key());
    let s2 = repo.next(|s| s.members.push(entry));
    assert_eq!(publish(&a, &repo, &token, &s2, None).status, 200);
    repo.tip = s2;
    let bob_token = a.login(&bob.sign);
    let bc = repo.commit(&bob.sign, vec![repo.root.commit_id], b"bob");
    assert_eq!(push(&a, &repo, &bob_token, &bc).status, 200);
    eventually("B has bob's commit", || b.heads(&id) == vec![bc.commit_id]);

    // Remove bob (SPEC 8.3): new epoch, frontier, rotation commit; published on A.
    let (s3, rot, _) = rotation(
        &repo,
        &[&repo.owner],
        Some((&bob, vec![bc.commit_id])),
        vec![bc.commit_id],
        a.key(),
    );
    assert_eq!(publish(&a, &repo, &token, &s3, Some(&rot)).status, 200);
    eventually("B adopted the rotation pair", || b.tip_hash(&id) == Some(hash(&s3)));
    // The state is never on B's chain without its rotation commit.
    assert_eq!(b.heads(&id), vec![rot.commit_id]);
    assert_eq!(
        b.view(&id, |v| v.rotation_commit(&hash(&s3)).cloned()),
        Some(Some(rot.clone()))
    );
}

#[test]
fn epoch_raise_offer_needs_its_rotation_commit() {
    let (b, p) = node_with_fake();
    let repo = genesis(&[b.key(), p.key()], b.key());
    create(&b, &repo);
    let id = repo.id();
    let (s2, rot, _) = rotation(&repo, &[&repo.owner], None, vec![repo.root.commit_id], b.key());

    // Without its rotation commit: 400 bad_request for the state, nothing adopted (SPEC 8.3, 9.1).
    let r = b.host(&p.sign, &id, "offer", &offer(&id, &[&s2], &[], &[]));
    assert_eq!(r.status, 200, "{}", r.json);
    assert_eq!(rejected(&r), HashSet::from([pair(&hash(&s2), "bad_request")]));
    assert_eq!(b.tip_hash(&id), Some(hash(&repo.genesis)));

    // With a forged rotation commit: both items of the pair are rejected with the same code.
    let mut bad = rot.clone();
    bad.author_signature[5] ^= 1;
    let r = b.host(&p.sign, &id, "offer", &offer(&id, &[&s2], &[&bad], &[]));
    assert_eq!(
        rejected(&r),
        HashSet::from([pair(&hash(&s2), "bad_request"), pair(&bad.commit_id, "bad_request")])
    );
    assert_eq!(b.tip_hash(&id), Some(hash(&repo.genesis)));
    assert_eq!(b.heads(&id), vec![repo.root.commit_id]);

    // With it: both accepted together.
    let r = b.host(&p.sign, &id, "offer", &offer(&id, &[&s2], &[&rot], &[]));
    assert_eq!(r.status, 200, "{}", r.json);
    assert_eq!(id_set(&r.json["accepted"]), b64_set(&[hash(&s2), rot.commit_id]));
    assert_eq!(r.json["rejected"], json!([]));
    assert_eq!(b.tip_hash(&id), Some(hash(&s2)));
    assert_eq!(b.heads(&id), vec![rot.commit_id]);

    // Offered again, the pair is accepted again with no change (SPEC 7, 12.3).
    let r = b.host(&p.sign, &id, "offer", &offer(&id, &[&s2], &[&rot], &[]));
    assert_eq!(id_set(&r.json["accepted"]), b64_set(&[hash(&s2), rot.commit_id]));
    assert_eq!(b.heads(&id), vec![rot.commit_id]);
}

#[test]
fn diverged_owner_states_converge() {
    let mut a = node();
    let mut b = node();
    link(&mut [&mut a, &mut b]);
    let repo = genesis(&[a.key(), b.key()], a.key());
    let ta = create(&a, &repo);
    let id = repo.id();
    eventually("B holds the repository", || b.heads(&id) == vec![repo.root.commit_id]);
    let tb = b.login(&repo.owner.sign);

    // Two owner devices publish different seq 2 states while the hosts cannot reach each other.
    a.pause(true);
    b.pause(true);
    let bob = Device::new();
    let entry = bob.entry(&repo.data_key, 0, b.key());
    let x = repo.next(|s| s.share_refresh_tokens = true);
    let y = repo.next(|s| s.members.push(entry));
    assert_eq!(publish(&a, &repo, &ta, &x, None).status, 200);
    assert_eq!(publish(&b, &repo, &tb, &y, None).status, 200);
    // Each side writes a commit citing its own seq 2.
    let cx = commit_on(&x, &repo.data_key, &repo.owner.sign, vec![repo.root.commit_id], b"x");
    let cy = commit_on(&y, &repo.data_key, &repo.owner.sign, vec![repo.root.commit_id], b"y");
    assert_eq!(push(&a, &repo, &ta, &cx).status, 200);
    assert_eq!(push(&b, &repo, &tb, &cy).status, 200);

    a.pause(false);
    b.pause(false);
    let (win, lose) = if hash(&x) < hash(&y) { (&x, &y) } else { (&y, &x) };
    eventually("both hosts hold the lower-hash tip", || {
        a.tip_hash(&id) == Some(hash(win)) && b.tip_hash(&id) == Some(hash(win))
    });
    // The owner is a member at epoch 0 in the winner, so the commit citing the losing state is
    // accepted after the re-check, not dropped (SPEC 6.5), and both hosts converge on both heads.
    let both = sorted(vec![cx.commit_id, cy.commit_id]);
    eventually("both hosts report both commits as heads", || {
        a.heads(&id) == both && b.heads(&id) == both
    });
    // Both keep the losing state, verified, off the chain (SPEC 6.5). The host that held the winner
    // may get it only through the commit that cites it (an offer sent while its peer was still
    // paused is answered 503 and lost; the catch-up fetches the cited state by hash, SPEC 7.2), so
    // this is checked once the heads have converged.
    for n in [&a, &b] {
        assert_eq!(n.view(&id, |v| v.manifest(&hash(lose)).is_some()), Some(true));
        assert_eq!(n.view(&id, |v| v.is_winning(&hash(lose))), Some(false));
        assert_eq!(n.tip_hash(&id), Some(hash(win)));
    }
}

#[test]
fn leave_replicates() {
    let mut a = node();
    let mut b = node();
    link(&mut [&mut a, &mut b]);
    let mut repo = genesis(&[a.key(), b.key()], a.key());
    let token = create(&a, &repo);
    let id = repo.id();
    let bob = Device::new();
    let entry = bob.entry(&repo.data_key, 0, a.key());
    let s2 = repo.next(|s| s.members.push(entry));
    assert_eq!(publish(&a, &repo, &token, &s2, None).status, 200);
    repo.tip = s2.clone();
    eventually("B has seq 2", || b.tip_hash(&id) == Some(hash(&s2)));

    let leave = leave_request(&repo, &bob.sign);
    let bob_token = a.login(&bob.sign);
    let r = a.post(&repo.path("leave"), Some(&bob_token), &to_json(&leave));
    assert_eq!(r.status, 200, "{}", r.json);
    eventually("B holds bob's leave request", || {
        b.view(&id, |v| v.leaves().to_vec()) == Some(vec![leave.clone()])
    });
    let tb = b.login(&repo.owner.sign);
    assert_eq!(pull(&b, &repo, &tb).json["leaves"], json!([to_json(&leave)]));
}

#[test]
fn fetch_serves_losing_state_with_rotation_commit() {
    let (b, p) = node_with_fake();
    let mut repo = genesis(&[b.key(), p.key()], b.key());
    let token = create(&b, &repo);
    let id = repo.id();

    // A losing epoch-raising seq 2 and its rotation commit; the winner is published first.
    let (lose, rot) = upper_half(
        |n| {
            let new_key = random_bytes::<32>();
            let entry = repo.owner.entry(&new_key, 1, b.key());
            let state = repo.next(|s| {
                s.key_epoch = 1;
                s.members = vec![entry];
                if let Some(h) = s.hosts.last_mut() {
                    h.locator = format!("l{n}.vault.example");
                }
            });
            let commit = commit_on(
                &state,
                &new_key,
                &repo.owner.sign,
                vec![repo.root.commit_id],
                b"rotation",
            );
            (state, commit)
        },
        |(m, _)| m,
    );
    let win = winner_against(&repo, &lose);
    assert_eq!(publish(&b, &repo, &token, &win, None).status, 200);
    let r = b.host(&p.sign, &id, "offer", &offer(&id, &[&lose], &[&rot], &[]));
    assert_eq!(r.status, 200, "{}", r.json);
    assert_eq!(r.json["accepted"], json!([]));
    assert_eq!(
        rejected(&r),
        HashSet::from([
            pair(&hash(&lose), "manifest_conflict"),
            pair(&rot.commit_id, "manifest_conflict")
        ])
    );
    repo.tip = win.clone();

    // SPEC 6.5, 9.1: served by hash with the chain before it and its rotation commit, though held.
    let r = b.host(&p.sign, &id, "fetch", &fetch_body(&id, &[hash(&lose)]));
    assert_eq!(r.status, 200, "{}", r.json);
    assert_eq!(r.json["manifests"], json!([to_json(&repo.genesis), to_json(&lose)]));
    assert_eq!(r.json["commits"], json!([to_json(&rot)]));
    // The rotation commit is served by id too, and is not a head.
    let r = b.host(&p.sign, &id, "fetch", &fetch_body(&id, &[rot.commit_id]));
    assert_eq!(r.json["commits"], json!([to_json(&rot)]));
    let r = b.host(&p.sign, &id, "heads", &json!({ "repoId": id }));
    assert_eq!(
        r.json,
        json!({ "manifestTip": { "manifestSeq": 2, "manifestHash": b64_encode(&hash(&win)) }, "heads": ids(&[repo.root.commit_id]) })
    );
}

#[test]
fn held_and_pending_commits_are_not_served() {
    let (b, p) = node_with_fake();
    let mut repo = genesis(&[b.key(), p.key()], b.key());
    let token = create(&b, &repo);
    let id = repo.id();

    // Held (SPEC 6.5): bob is a member only on the losing seq 2; his commit citing it is held.
    let bob = Device::new();
    let bob_entry = bob.entry(&repo.data_key, 0, b.key());
    let lose = upper_half(
        |n| {
            repo.next(|s| {
                s.members.push(bob_entry.clone());
                if let Some(h) = s.hosts.last_mut() {
                    h.locator = format!("l{n}.vault.example");
                }
            })
        },
        |m| m,
    );
    let win = winner_against(&repo, &lose);
    assert_eq!(publish(&b, &repo, &token, &win, None).status, 200);
    let r = b.host(&p.sign, &id, "offer", &offer(&id, &[&lose], &[], &[]));
    assert_eq!(rejected(&r), HashSet::from([pair(&hash(&lose), "manifest_conflict")]));
    let held = commit_on(&lose, &repo.data_key, &bob.sign, vec![repo.root.commit_id], b"held");
    let r = b.host(&p.sign, &id, "offer", &offer(&id, &[], &[&held], &[]));
    assert_eq!(rejected(&r), HashSet::from([pair(&held.commit_id, "forbidden")]));
    assert_eq!(b.view(&id, RepoView::held), Some(vec![held.commit_id]));
    let r = b.host(&p.sign, &id, "fetch", &fetch_body(&id, &[held.commit_id]));
    assert_eq!(r.json["commits"], json!([]));
    let r = b.host(&p.sign, &id, "heads", &json!({}));
    assert_eq!(r.json["heads"], ids(&[repo.root.commit_id]));
    repo.tip = win;

    // Pending (SPEC 7.3): carol's accepted commit becomes undecided when a removal names a frontier
    // commit whose header the host lacks.
    let carol = Device::new();
    let carol_entry = carol.entry(&repo.data_key, 0, b.key());
    let s3 = repo.next(|s| s.members.push(carol_entry));
    assert_eq!(publish(&b, &repo, &token, &s3, None).status, 200);
    repo.tip = s3;
    let x = repo.commit(&carol.sign, vec![repo.root.commit_id], b"carol");
    let r = b.host(&p.sign, &id, "offer", &offer(&id, &[], &[&x], &[]));
    assert_eq!(id_set(&r.json["accepted"]), b64_set(&[x.commit_id]));
    let unknown_frontier = random_bytes::<32>();
    let (s4, rot, _) = rotation(
        &repo,
        &[&repo.owner],
        Some((&carol, vec![unknown_frontier])),
        vec![repo.root.commit_id],
        b.key(),
    );
    assert_eq!(publish(&b, &repo, &token, &s4, Some(&rot)).status, 200);
    assert_eq!(b.view(&id, RepoView::pending), Some(vec![x.commit_id]));

    let r = b.host(&p.sign, &id, "fetch", &fetch_body(&id, &[x.commit_id]));
    assert_eq!(r.status, 200, "{}", r.json);
    assert_eq!(r.json["commits"], json!([]));
    let r = b.host(&p.sign, &id, "heads", &json!({}));
    assert_eq!(r.json["heads"], ids(&[rot.commit_id]));
}

// ─── Hosted rule by replication (SPEC 6.1 rule 6, 8.6, 9.2, 10.1) ──────────────────────

#[test]
fn dropped_by_replication_stops_serving_and_relisting_resumes() {
    let (b, p) = node_with_fake();
    let mut repo = genesis(&[p.key(), b.key()], p.key());
    let token = create(&b, &repo);
    let id = repo.id();

    // A validated seq 2 that drops B: B keeps it and answers 403 not_hosted (SPEC 8.6, 9.2).
    let p_key = p.key();
    let dropped = repo.next(|s| s.hosts.retain(|h| h.key == p_key));
    let r = b.host(&p.sign, &id, "offer", &offer(&id, &[&dropped], &[], &[]));
    assert_error(&r, 403, "not_hosted");
    assert_eq!(b.tip_hash(&id), Some(hash(&dropped)));
    assert_eq!(b.view(&id, RepoView::tip_lists_host), Some(false));
    repo.tip = dropped;

    // Not hosted: every client operation and every peer route answers 403 not_hosted (SPEC 10.1).
    assert_error(&pull(&b, &repo, &token), 403, "not_hosted");
    let c = repo.commit(&repo.owner.sign, vec![repo.root.commit_id], b"late");
    assert_error(&push(&b, &repo, &token, &c), 403, "not_hosted");
    let s3_unused = repo.next(|s| s.share_refresh_tokens = true);
    assert_error(&publish(&b, &repo, &token, &s3_unused, None), 403, "not_hosted");
    let bob = Device::new();
    assert_error(
        &b.post(
            &repo.path("leave"),
            Some(&token),
            &to_json(&leave_request(&repo, &bob.sign)),
        ),
        403,
        "not_hosted",
    );
    assert_error(&b.host(&p.sign, &id, "heads", &json!({})), 403, "not_hosted");
    assert_error(&b.host(&p.sign, &id, "fetch", &fetch_body(&id, &[])), 403, "not_hosted");
    assert_error(
        &b.host(&p.sign, &id, "offer", &offer(&id, &[], &[&c], &[])),
        403,
        "not_hosted",
    );
    assert_eq!(b.view(&id, |v| v.status(&c.commit_id)), Some(None));

    // A later replicated state that lists B again: hosted again (SPEC 8.6).
    let b_key = b.key();
    let relisted = repo.next(|s| {
        s.hosts.push(HostRef {
            key: b_key,
            locator: "b.vault.example".to_string(),
        })
    });
    let r = b.host(&p.sign, &id, "offer", &offer(&id, &[&relisted], &[], &[]));
    assert_eq!(r.status, 200, "{}", r.json);
    assert_eq!(id_set(&r.json["accepted"]), b64_set(&[hash(&relisted)]));
    repo.tip = relisted;
    let r = pull(&b, &repo, &token);
    assert_eq!(r.status, 200, "{}", r.json);
    assert_eq!(r.json["manifests"].as_array().unwrap().len(), 3);
    assert_eq!(b.host(&p.sign, &id, "heads", &json!({})).status, 200);
}

#[test]
fn client_publish_dropping_host_keeps_state_and_stops_serving() {
    let (b, p) = node_with_fake();
    let mut repo = genesis(&[p.key(), b.key()], p.key());
    let token = create(&b, &repo);
    let id = repo.id();

    // The owner publishes through B a state that drops B, carrying a non-rotation commit.
    let p_key = p.key();
    let dropped = repo.next(|s| s.hosts.retain(|h| h.key == p_key));
    let carried = commit_on(
        &dropped,
        &repo.data_key,
        &repo.owner.sign,
        vec![repo.root.commit_id],
        b"c",
    );
    let r = publish(&b, &repo, &token, &dropped, Some(&carried));
    assert_error(&r, 403, "not_hosted");
    // B records the state (SPEC 8.6) but not the carried commit, and does not offer the state.
    assert_eq!(b.tip_hash(&id), Some(hash(&dropped)));
    assert_eq!(b.view(&id, |v| v.status(&carried.commit_id)), Some(None));
    {
        let st = b.state.lock().unwrap();
        let offered = st
            .store
            .outbox
            .entries()
            .any(|o| o.manifests.iter().any(|m| hash(m) == hash(&dropped)));
        assert!(!offered, "a state that drops this host is not offered");
    }
    repo.tip = dropped;
    assert_error(&pull(&b, &repo, &token), 403, "not_hosted");
    assert_error(&b.host(&p.sign, &id, "heads", &json!({})), 403, "not_hosted");

    // An epoch-raising state that drops B is kept with its rotation commit, atomically.
    let mut repo2 = genesis(&[p.key(), b.key()], p.key());
    let token2 = create(&b, &repo2);
    let id2 = repo2.id();
    let (raised, rot, _) = rotation(&repo2, &[&repo2.owner], None, vec![repo2.root.commit_id], p.key());
    let mut raised_state = raised.state.clone();
    raised_state.hosts.retain(|h| h.key == p_key);
    let raised = raised_state.sign(&repo2.owner.sign).unwrap();
    let rot = Commit::seal(
        &random_bytes::<32>(),
        CommitHeader {
            repo_id: id2.clone(),
            parents: rot.parents.clone(),
            manifest_seq: 2,
            manifest_hash: hash(&raised),
            key_epoch: 1,
        },
        b"rotation",
        &repo2.owner.sign,
    )
    .unwrap();
    assert_error(&publish(&b, &repo2, &token2, &raised, Some(&rot)), 403, "not_hosted");
    assert_eq!(b.tip_hash(&id2), Some(hash(&raised)));
    assert_eq!(
        b.view(&id2, |v| v.rotation_commit(&hash(&raised)).cloned()),
        Some(Some(rot))
    );
    repo2.tip = raised;
    assert_error(&pull(&b, &repo2, &token2), 403, "not_hosted");
}

#[test]
fn first_copy_with_unlisted_tip_stores_nothing() {
    let (b, p) = node_with_fake();
    let p_key = p.key();
    let repo = genesis(&[p_key], p_key);
    let id = repo.id();

    // A valid repository whose received tip does not list B: 403 not_hosted, nothing stored.
    let r = b.host(&p.sign, &id, "offer", &offer(&id, &[&repo.genesis], &[&repo.root], &[]));
    assert_error(&r, 403, "not_hosted");
    assert!(!b.holds(&id));
    let s2 = repo.next(|s| s.share_refresh_tokens = true);
    let r = b.host(
        &p.sign,
        &id,
        "offer",
        &offer(&id, &[&repo.genesis, &s2], &[&repo.root], &[]),
    );
    assert_error(&r, 403, "not_hosted");
    assert!(!b.holds(&id));
    assert_error(&b.host(&p.sign, &id, "heads", &json!({})), 404, "not_found");

    // Control: the same genesis with a seq 2 that lists B is a first copy (SPEC 8.1, 9.2).
    let b_key = b.key();
    let listing = repo.next(|s| {
        s.hosts.push(HostRef {
            key: b_key,
            locator: "b.vault.example".to_string(),
        })
    });
    let r = b.host(
        &p.sign,
        &id,
        "offer",
        &offer(&id, &[&repo.genesis, &listing], &[&repo.root], &[]),
    );
    assert_eq!(r.status, 200, "{}", r.json);
    assert_eq!(
        id_set(&r.json["accepted"]),
        b64_set(&[hash(&repo.genesis), hash(&listing), repo.root.commit_id])
    );
    assert_eq!(b.tip_hash(&id), Some(hash(&listing)));
    assert_eq!(b.heads(&id), vec![repo.root.commit_id]);
}

#[test]
fn first_copy_whose_tip_omits_the_sender_stores_nothing() {
    // SPEC 9.2: a host never takes a repository from a host its signed hosts do not list. B is
    // peered with P and Q; Q offers a valid repository that lists B and P but not Q.
    let mut b = node();
    let p = FakePeer::new();
    let q = FakePeer::new();
    b.peer_with(&[p.entry(), q.entry()]);
    let repo = genesis(&[p.key(), b.key()], p.key());
    let id = repo.id();
    let r = b.host(&q.sign, &id, "offer", &offer(&id, &[&repo.genesis], &[&repo.root], &[]));
    assert_error(&r, 403, "forbidden");
    assert!(!b.holds(&id));
    // The same offer from P, which the tip lists, is a first copy.
    let r = b.host(&p.sign, &id, "offer", &offer(&id, &[&repo.genesis], &[&repo.root], &[]));
    assert_eq!(r.status, 200, "{}", r.json);
    assert_eq!(b.heads(&id), vec![repo.root.commit_id]);
}

#[test]
fn first_copy_with_forged_listing_state_stores_nothing() {
    let (b, p) = node_with_fake();
    let p_key = p.key();
    let b_key = b.key();
    let repo = genesis(&[p_key], p_key);
    let id = repo.id();
    // A seq 2 claiming to list B, signed by a key that is not the owner.
    let forged = next_of(&repo.genesis, &new_key(), |s| {
        s.hosts.push(HostRef {
            key: b_key,
            locator: "b.vault.example".to_string(),
        })
    });
    let r = b.host(
        &p.sign,
        &id,
        "offer",
        &offer(&id, &[&repo.genesis, &forged], &[&repo.root], &[]),
    );
    assert_error(&r, 403, "not_hosted");
    assert!(!b.holds(&id));
    // States of another repository offered under this repoId are not taken either.
    let other = genesis(&[b_key], b_key);
    let r = b.host(
        &p.sign,
        &id,
        "offer",
        &offer(&id, &[&other.genesis], &[&other.root], &[]),
    );
    assert_eq!(r.status, 200, "{}", r.json);
    assert!(rejected(&r).contains(&pair(&hash(&other.genesis), "bad_request")));
    assert!(!b.holds(&id));
    assert!(!b.holds(&other.id()));
}

// ─── Robustness against peers (SPEC 9: peer responses are untrusted input) ──────────────

/// A peer that answers every request badly, in turn: not JSON, oversized, the wrong shape, a
/// server error, too slow (beyond the request timeout), or a closed connection. It counts requests.
fn bad_peer(stop: Arc<AtomicBool>, hits: Arc<AtomicUsize>) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let handle = thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            let Ok((mut s, _)) = listener.accept() else {
                thread::sleep(Duration::from_millis(10));
                continue;
            };
            let _ = s.set_nonblocking(false);
            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            let mut buf = [0u8; 8192];
            let _ = s.read(&mut buf);
            let n = hits.fetch_add(1, Ordering::SeqCst);
            let reply: Vec<u8> = match n % 6 {
                0 => b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nnot json".to_vec(),
                1 => {
                    let body = vec![b'['; 300 * 1024];
                    let mut r = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
                    r.extend(body);
                    r
                }
                2 => {
                    let body = br#"{"manifestTip":{"manifestSeq":-5,"manifestHash":"AAAA"},"heads":"x"}"#;
                    let mut r = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
                    r.extend_from_slice(body);
                    r
                }
                3 => b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
                4 => {
                    thread::sleep(Duration::from_millis(1500));
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec()
                }
                _ => Vec::new(),
            };
            let _ = s.write_all(&reply);
        }
    });
    (addr, handle)
}

#[test]
fn bad_peer_responses_do_not_stop_replication() {
    let stop = Arc::new(AtomicBool::new(false));
    let hits = Arc::new(AtomicUsize::new(0));
    let (addr, server) = bad_peer(Arc::clone(&stop), Arc::clone(&hits));
    let bad_key = new_key();
    let mut a = node();
    let mut b = node();
    a.peer_with(&[b.entry()]);
    b.peer_with(&[a.entry(), format!("{}@http://{addr}", b64_encode(&pk(&bad_key)))]);
    let repo = genesis(&[b.key(), a.key(), pk(&bad_key)], b.key());
    let token = create(&b, &repo);
    let id = repo.id();

    // B keeps sweeping the bad peer through two full rounds of bad answers, and client requests on
    // B stay fast while a call to the bad peer hangs: the state lock is never held across a call.
    let deadline = Instant::now() + CONVERGE;
    while hits.load(Ordering::SeqCst) < 12 {
        assert!(Instant::now() < deadline, "B stopped calling the bad peer");
        let t = Instant::now();
        assert_eq!(pull(&b, &repo, &token).status, 200);
        assert!(
            t.elapsed() < Duration::from_secs(1),
            "a client request waited on a peer call"
        );
        thread::sleep(Duration::from_millis(20));
    }
    // Nothing from the bad peer was stored, and replication to a good peer still works.
    assert_eq!(b.tip_hash(&id), Some(hash(&repo.genesis)));
    let c = repo.commit(&repo.owner.sign, vec![repo.root.commit_id], b"after");
    assert_eq!(push(&b, &repo, &token, &c).status, 200);
    eventually("A has the commit written on B", || a.heads(&id) == vec![c.commit_id]);

    stop.store(true, Ordering::SeqCst);
    drop(b);
    let _ = server.join();
}
