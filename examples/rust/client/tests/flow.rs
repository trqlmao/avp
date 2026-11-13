// SPDX-License-Identifier: MIT

//! Client tests against real in-process reference hosts (`avp-reference-server`).
//!
//! Every item is real: owner, member, and host keys are generated, manifests are owner-signed,
//! commits are author-signed and encrypted, and the host is the real `RepoView` engine. Where a test
//! needs a host to misbehave (a forged manifest, a rollback, a commit the host would never serve),
//! it puts a **malicious in-process proxy** between the client and an honest host: the proxy
//! forwards every request unchanged, records every request body, and can rewrite the JSON answer of
//! a `pull`. That is the "malicious stub host" of the SPEC 7.5 premise: the client never trusts a
//! host's acceptance.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use avp::commit::{Commit, CommitHeader};
use avp::crypto::{WRAP_INFO, random_bytes, unwrap};
use avp::encoding::{b64_encode, b64url_encode};
use avp::manifest::{HostRef, ManifestState, Removal, SignedManifest, derive_repo_id};
use avp::owner::mnemonic_to_seed;
use avp::payload::{PayloadV2, Stamp};
use avp::rules::RepoView;
use avp::tokens::{
    Acceptance, InviteToken, LeaveRequest, LinkGrant, LinkRequest, decode_token, encode_token, owner_fingerprint,
};
use avp_reference_client::ClientError;
use avp_reference_client::flow;
use avp_reference_client::link::{LinkSession, OwnerIdentity, approve};
use avp_reference_client::sync::{Chain, HostClient, Member, Vault, delete_account, now_ms, prepare_join, set_field};
use avp_reference_server::replication::{Peers, Replication, run};
use avp_reference_server::{Serving, State, serve};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

type Id = [u8; 32];

const U1: &str = "00000000-0000-4000-8000-000000000001";
const U2: &str = "00000000-0000-4000-8000-000000000002";

// ─── Harness: in-process hosts ──────────────────────────────────────────────────────────

/// A running reference host. `repl` is declared first so it stops before the listener.
struct Node {
    repl: Option<Replication>,
    serving: Serving,
    state: Arc<Mutex<State>>,
}

fn node() -> Node {
    let mut state = State::new(SigningKey::from_bytes(&random_bytes::<32>()));
    state.replication.sweep_interval = Duration::from_millis(100);
    state.replication.request_timeout = Duration::from_secs(2);
    let state = Arc::new(Mutex::new(state));
    let serving = serve("127.0.0.1:0", Arc::clone(&state)).expect("bind an ephemeral port");
    Node {
        repl: None,
        serving,
        state,
    }
}

/// Two hosts peered with each other (`AVP_PEERS` built from their keys and addresses).
fn peered_pair() -> (Node, Node) {
    let mut a = node();
    let mut b = node();
    let entry = |n: &Node| format!("{}@{}", b64_encode(&n.key()), n.url());
    let (ea, eb) = (entry(&a), entry(&b));
    a.repl = Some(run(Arc::clone(&a.state), Peers::from_env(&eb).unwrap()).unwrap());
    b.repl = Some(run(Arc::clone(&b.state), Peers::from_env(&ea).unwrap()).unwrap());
    (a, b)
}

impl Node {
    fn url(&self) -> String {
        format!("http://{}", self.serving.addr())
    }

    fn key(&self) -> Id {
        self.state.lock().unwrap().host_key()
    }

    fn signing(&self) -> SigningKey {
        self.state.lock().unwrap().host_signing_key().clone()
    }

    fn view<R>(&self, repo: &str, f: impl FnOnce(&RepoView) -> R) -> Option<R> {
        let st = self.state.lock().unwrap();
        st.store.repos.get(repo).map(f)
    }

    fn tip_seq(&self, repo: &str) -> i64 {
        self.view(repo, |v| v.tip().map(|t| t.state.manifest_seq))
            .flatten()
            .unwrap_or(0)
    }

    fn heads(&self, repo: &str) -> Vec<Id> {
        self.view(repo, RepoView::heads).unwrap_or_default()
    }

    fn commit(&self, repo: &str, id: &Id) -> Commit {
        self.view(repo, |v| v.fetch_commit(id).cloned())
            .flatten()
            .expect("the host holds the commit")
    }
}

// ─── Harness: a malicious proxy in front of an honest host ──────────────────────────────

type Tamper = Box<dyn Fn(&str, &Value, &mut Value) + Send + Sync>;

struct Logged {
    path: String,
    body: Vec<u8>,
}

/// Forwards every request to `upstream` unchanged, records `(path, body)` of each, and lets the
/// test rewrite the JSON answer of a `200` reply. Stops on drop.
struct Proxy {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    log: Arc<Mutex<Vec<Logged>>>,
    tamper: Arc<Mutex<Option<Tamper>>>,
}

impl Proxy {
    fn new(upstream: &Node) -> Proxy {
        let upstream = upstream.url();
        let server = tiny_http::Server::http("127.0.0.1:0").expect("bind the proxy");
        let addr = server.server_addr().to_ip().expect("an IP listener");
        let stop = Arc::new(AtomicBool::new(false));
        let log = Arc::new(Mutex::new(Vec::new()));
        let tamper: Arc<Mutex<Option<Tamper>>> = Arc::new(Mutex::new(None));
        let (s, l, t) = (Arc::clone(&stop), Arc::clone(&log), Arc::clone(&tamper));
        let thread = thread::spawn(move || {
            let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
            while !s.load(Ordering::SeqCst) {
                let Ok(Some(mut req)) = server.recv_timeout(Duration::from_millis(20)) else {
                    continue;
                };
                let mut body = Vec::new();
                req.as_reader().read_to_end(&mut body).unwrap();
                let path = req.url().to_string();
                let auth = req
                    .headers()
                    .iter()
                    .find(|h| h.field.equiv("Authorization"))
                    .map(|h| h.value.as_str().to_string());
                l.lock().unwrap().push(Logged {
                    path: path.clone(),
                    body: body.clone(),
                });
                let url = format!("{upstream}{path}");
                let mut resp = if *req.method() == tiny_http::Method::Get {
                    agent.get(&url).call().unwrap()
                } else {
                    let mut r = agent.post(&url).content_type("application/json");
                    if let Some(a) = &auth {
                        r = r.header("Authorization", a);
                    }
                    r.send(&body[..]).unwrap()
                };
                let status = resp.status().as_u16();
                let mut bytes = resp.body_mut().with_config().limit(64 << 20).read_to_vec().unwrap();
                if status == 200 {
                    if let Some(f) = t.lock().unwrap().as_ref() {
                        let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                        let mut answer: Value = serde_json::from_slice(&bytes).unwrap();
                        f(&path, &request, &mut answer);
                        bytes = serde_json::to_vec(&answer).unwrap();
                    }
                }
                let _ = req.respond(tiny_http::Response::from_data(bytes).with_status_code(status));
            }
        });
        Proxy {
            addr,
            stop,
            thread: Some(thread),
            log,
            tamper,
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Rewrites the answer of every `pull` with `f(request, answer)`.
    fn on_pull(&self, f: impl Fn(&Value, &mut Value) + Send + Sync + 'static) {
        *self.tamper.lock().unwrap() = Some(Box::new(move |path, req, ans| {
            if path.ends_with("/pull") {
                f(req, ans);
            }
        }));
    }

    fn honest(&self) {
        *self.tamper.lock().unwrap() = None;
    }

    fn paths(&self) -> Vec<String> {
        self.log.lock().unwrap().iter().map(|l| l.path.clone()).collect()
    }

    fn bodies(&self) -> Vec<Vec<u8>> {
        self.log.lock().unwrap().iter().map(|l| l.body.clone()).collect()
    }

    fn request_count(&self) -> usize {
        self.log.lock().unwrap().len()
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────────────────

fn host(url: &str) -> HostClient {
    HostClient::connect(url).expect("discovery answers with a host key")
}

fn owner_vault(url: &str) -> (OwnerIdentity, Vault) {
    let id = OwnerIdentity::generate().unwrap();
    let v = Vault::create(host(url), &id.keys).unwrap();
    (id, v)
}

/// A new member homed on `home_url`, invited by `owner` from a real `prepareJoin` acceptance.
fn invite_member(owner: &mut Vault, home_url: &str) -> Vault {
    let me = Member::generate();
    let mut home = host(home_url);
    let token = prepare_join(&mut home, &me, owner.repo_id()).unwrap();
    owner.invite(&token).unwrap();
    let locator = owner.locator().unwrap();
    eventually("the joiner's home host holds the repository", || {
        Vault::join(host(home_url), me.clone(), &locator).is_ok()
    });
    Vault::join(home, me, &locator).unwrap()
}

/// One edit: one tick, the same stamp on every field set (SPEC 5).
fn set(v: &mut Vault, uuid: &str, fields: &[(&str, Value)], now: i64) -> Stamp {
    let by = v.member().id();
    let mut stamp = Stamp::default();
    v.write(|p, hlc| {
        let s = hlc.tick(now, &by);
        for (name, value) in fields {
            set_field(p, uuid, name, value.clone(), &s);
        }
        stamp = s;
    })
    .unwrap();
    stamp
}

fn field<'a>(p: &'a PayloadV2, uuid: &str, name: &str) -> Option<&'a Value> {
    p.accounts.get(uuid)?.fields.get(name).map(|f| &f.value)
}

fn decrypt(c: &Commit, key: &[u8; 32]) -> PayloadV2 {
    PayloadV2::from_json(&c.open(key).unwrap()).unwrap()
}

fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if f() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("not reached within 20 s: {what}");
}

fn sorted(mut v: Vec<Id>) -> Vec<Id> {
    v.sort_unstable();
    v
}

fn host_code(r: Result<impl std::fmt::Debug, ClientError>) -> String {
    match r {
        Err(e) => e.code().unwrap_or("none").to_string(),
        Ok(v) => panic!("expected a host error, got {v:?}"),
    }
}

/// A forged commit sealed with real keys, so only the client's own checks can stop it.
fn forge(key: &[u8; 32], header: CommitHeader, uuid: &str, author: &SigningKey) -> Commit {
    let mut p = PayloadV2::default();
    let stamp = Stamp {
        at: now_ms() + 1_000_000,
        n: 0,
        by: b64_encode(&author.verifying_key().to_bytes()),
    };
    set_field(&mut p, uuid, "username", json!("forged"), &stamp);
    Commit::seal(key, header, &p.to_json().unwrap(), author).unwrap()
}

fn header_at(v: &Vault, parents: Vec<Id>, seq: i64, hash: Id, epoch: i64) -> CommitHeader {
    CommitHeader {
        repo_id: v.repo_id().to_string(),
        parents,
        manifest_seq: seq,
        manifest_hash: hash,
        key_epoch: epoch,
    }
}

// ─── The nine named tests ───────────────────────────────────────────────────────────────

/// SPEC 3.1, 4.2, 6.2: the phrase is the identity. A vault created from a fresh phrase is reopened
/// on a new device from the phrase alone; a different phrase is not a member; a malformed phrase is
/// rejected.
#[test]
fn owner_create_and_reopen_from_mnemonic() {
    let a = node();
    let (id, mut v) = owner_vault(&a.url());
    let phrase = id.mnemonic();
    assert_eq!(phrase.split(' ').count(), 24, "24 words (SPEC 3.1)");

    let genesis = &v.chain().states()[0];
    let s = &genesis.state;
    assert_eq!(s.manifest_seq, 1);
    assert_eq!(s.key_epoch, 0);
    assert!(s.prev_manifest_hash.is_empty());
    assert_eq!(s.owner_key, id.keys.owner_key());
    let nonce: [u8; 16] = s.genesis_nonce.as_slice().try_into().unwrap();
    assert_eq!(
        s.repo_id,
        derive_repo_id(&s.owner_key, &nonce).unwrap(),
        "repoId (SPEC 4.2)"
    );
    assert_eq!(s.repo_id.len(), 22);
    assert_eq!(
        s.hosts,
        vec![HostRef {
            key: a.key(),
            locator: a.serving.addr().to_string()
        }]
    );
    assert_eq!(s.members.len(), 1, "genesis has exactly the owner (SPEC 6.2)");
    assert!(!s.share_refresh_tokens, "policy defaults to false (SPEC 5.1)");
    genesis.verify().unwrap();
    assert_eq!(a.tip_seq(v.repo_id()), 1);

    set(
        &mut v,
        U1,
        &[("username", json!("alice-alt")), ("accessToken", json!("at-1"))],
        now_ms(),
    );
    let repo = v.repo_id().to_string();
    drop(v);

    // A new device with only the phrase derives the same keys and reads the vault.
    let again = OwnerIdentity::from_mnemonic(&phrase).unwrap();
    assert_eq!(again.entropy, id.entropy);
    assert_eq!(again.keys.owner_key(), id.keys.owner_key());
    assert_eq!(again.keys.x25519_public(), id.keys.x25519_public());
    let reopened = Vault::open(host(&a.url()), Member::from_owner(&again.keys), &repo).unwrap();
    assert_eq!(field(reopened.payload(), U1, "username"), Some(&json!("alice-alt")));
    assert_eq!(field(reopened.payload(), U1, "accessToken"), Some(&json!("at-1")));
    assert_eq!(reopened.retained_epoch_keys.len(), 1);

    // Another phrase is another identity: not a member (SPEC 10.1).
    let other = OwnerIdentity::generate().unwrap();
    let r = Vault::open(host(&a.url()), Member::from_owner(&other.keys), &repo);
    assert_eq!(host_code(r), "forbidden");

    // SPEC 3.1: reject a phrase that is not exactly 24 words or has an unknown word.
    let short: Vec<&str> = phrase.split(' ').take(23).collect();
    assert!(OwnerIdentity::from_mnemonic(&short.join(" ")).is_err());
    let mut words: Vec<&str> = phrase.split(' ').collect();
    words[0] = "notaword";
    assert!(OwnerIdentity::from_mnemonic(&words.join(" ")).is_err());
}

/// SPEC 8.1, 8.2: the owner adds a member only from an invite token whose acceptance verifies, and
/// wraps the data key to exactly the token's X25519 key.
#[test]
fn invite_requires_valid_acceptance() {
    let a = node();
    let (_id, mut owner) = owner_vault(&a.url());
    let repo = owner.repo_id().to_string();
    set(&mut owner, U1, &[("username", json!("shared"))], now_ms());

    let bob = Member::generate();
    let mut home = host(&a.url());
    let good = prepare_join(&mut home, &bob, &repo).unwrap();
    assert_eq!(good.acceptance.host_key, a.key());
    assert_eq!(good.home_host_key, a.key());
    assert_eq!(good.acceptance.member_key, bob.ed25519_public());
    // The token is out-of-band text and round-trips (SPEC 11.1).
    let text = encode_token(&good).unwrap();
    assert_eq!(decode_token::<InviteToken>(&text).unwrap(), good);

    let host_key = a.signing();
    let signed = |repo_id: &str, member: Id, expires_at: i64| {
        Acceptance {
            repo_id: repo_id.to_string(),
            member_key: member,
            host_key: [0; 32],
            expires_at,
            signature: [0; 64],
        }
        .sign(&host_key)
        .unwrap()
    };
    let other_repo = b64url_encode(&random_bytes::<16>());
    let mut bad = Vec::new();
    // The acceptance names another repository.
    let mut t = good.clone();
    t.acceptance = signed(&other_repo, bob.ed25519_public(), now_ms() + 600_000);
    bad.push(("other repoId", t));
    // The acceptance is for another member key than the token's.
    let mut t = good.clone();
    t.ed25519_public_key = Member::generate().ed25519_public();
    bad.push(("memberKey mismatch", t));
    // The token's home host is not the host that accepted.
    let mut t = good.clone();
    t.home_host_key = random_bytes::<32>();
    bad.push(("homeHostKey mismatch", t));
    // Expired (signed by the real host key, expiresAt in the past).
    let mut t = good.clone();
    t.acceptance = signed(&repo, bob.ed25519_public(), now_ms() - 1);
    bad.push(("expired", t));
    // Tampered signature.
    let mut t = good.clone();
    t.acceptance.signature[0] ^= 1;
    bad.push(("bad signature", t));

    for (what, token) in &bad {
        let r = owner.invite(token);
        assert!(matches!(r, Err(ClientError::InviteRefused(_))), "{what}: {r:?}");
        assert_eq!(a.tip_seq(&repo), 1, "{what}: nothing published");
        assert_eq!(owner.tip().state.manifest_seq, 1, "{what}");
    }

    owner.invite(&good).unwrap();
    assert_eq!(a.tip_seq(&repo), 2);
    let s = &owner.tip().state;
    let entry = s
        .members
        .iter()
        .find(|m| m.ed25519_public_key == bob.ed25519_public())
        .unwrap();
    assert_eq!(entry.x25519_public_key, good.x25519_public_key);
    assert_eq!(entry.home_host_key, a.key());
    assert_eq!(entry.key_epoch, s.key_epoch);
    // Wrapped to exactly the token's X25519 key: bob's private key opens it to the data key.
    let dk = unwrap(&bob.x25519, &entry.wrapped_data_key, WRAP_INFO).unwrap();
    assert_eq!(dk.as_slice(), owner.retained_epoch_keys[&0].as_slice());

    let locator = owner.locator().unwrap();
    let joined = Vault::join(home, bob, &locator).unwrap();
    assert_eq!(field(joined.payload(), U1, "username"), Some(&json!("shared")));
}

/// SPEC 5: concurrent writes to different fields of one account both survive the merge; on the
/// same field the greater stamp wins; the merge commit names exactly the merged heads; the merging
/// client observes every stamp before its next tick.
#[test]
fn concurrent_writes_merge_per_field() {
    let a = node();
    let (_id, mut owner) = owner_vault(&a.url());
    let repo = owner.repo_id().to_string();
    let t = now_ms() + 10_000;
    set(
        &mut owner,
        U1,
        &[
            ("username", json!("u0")),
            ("accessToken", json!("t0")),
            ("lastUsed", json!(1)),
        ],
        t,
    );
    let mut bob = invite_member(&mut owner, &a.url());
    owner.pull().unwrap();

    // Both write from the same head, without pulling in between.
    let s_owner = set(
        &mut owner,
        U1,
        &[("username", json!("owner-name")), ("lastUsed", json!(100))],
        t + 10,
    );
    let s_bob = set(
        &mut bob,
        U1,
        &[("accessToken", json!("bob-token")), ("lastUsed", json!(200))],
        t + 20,
    );
    assert!(s_bob.order(&s_owner).is_gt());
    let (oh, bh) = (owner.heads()[0], bob.heads()[0]);
    assert_eq!(sorted(a.heads(&repo)), sorted(vec![oh, bh]), "two heads at the host");

    let report = owner.pull().unwrap();
    let merge = report
        .merge_commit
        .expect("two readable heads are merged and pushed (SPEC 5)");
    assert_eq!(owner.heads(), &[merge]);
    assert_eq!(a.heads(&repo), vec![merge]);
    let mc = a.commit(&repo, &merge);
    assert_eq!(
        sorted(mc.parents.clone()),
        sorted(vec![oh, bh]),
        "parents are exactly the merged heads"
    );
    assert_eq!(mc.author, owner.member().ed25519_public());

    let p = owner.payload();
    assert_eq!(field(p, U1, "username"), Some(&json!("owner-name")));
    assert_eq!(field(p, U1, "accessToken"), Some(&json!("bob-token")));
    assert_eq!(
        field(p, U1, "lastUsed"),
        Some(&json!(200)),
        "same field: greatest stamp wins"
    );
    assert_eq!(
        decrypt(&mc, &owner.retained_epoch_keys[&0]),
        *p,
        "the merge commit carries the merge"
    );

    // HLC: bob's stamp was observed, so the next write is greater even with an older wall clock.
    assert!(owner.hlc().at >= s_bob.at);
    let next = set(&mut owner, U2, &[("username", json!("later"))], t);
    assert!(next.order(&s_bob).is_gt(), "{next:?} > {s_bob:?}");

    bob.pull().unwrap();
    assert_eq!(field(bob.payload(), U1, "username"), Some(&json!("owner-name")));
    assert_eq!(field(bob.payload(), U1, "accessToken"), Some(&json!("bob-token")));
    assert_eq!(bob.payload(), owner.payload());
}

/// SPEC 5: an edit after a deletion brings the account back; a deletion after the edit removes it.
#[test]
fn delete_then_edit_revives_after_merge() {
    let a = node();
    let (_id, mut owner) = owner_vault(&a.url());
    let t = now_ms() + 10_000;
    set(&mut owner, U1, &[("username", json!("u0"))], t);
    let mut bob = invite_member(&mut owner, &a.url());
    owner.pull().unwrap();

    let by = owner.member().id();
    owner
        .write(|p, hlc| {
            let s = hlc.tick(t + 10, &by);
            delete_account(p, U1, &s);
        })
        .unwrap();
    assert!(owner.payload().accounts[U1].is_deleted());
    set(&mut bob, U1, &[("username", json!("edited"))], t + 20);

    owner.pull().unwrap();
    let acc = &owner.payload().accounts[U1];
    assert!(acc.deleted.is_some(), "the marker stays");
    assert!(!acc.is_deleted(), "the later edit revives the account");
    assert_eq!(field(owner.payload(), U1, "username"), Some(&json!("edited")));

    // A deletion after the edit removes it again, for everyone.
    owner
        .write(|p, hlc| {
            let s = hlc.tick(t, &by);
            delete_account(p, U1, &s);
        })
        .unwrap();
    assert!(owner.payload().accounts[U1].is_deleted());
    bob.pull().unwrap();
    assert!(bob.payload().accounts[U1].is_deleted());
    assert_eq!(bob.payload(), owner.payload());
}

/// SPEC 8.3, 7.3: removal rotates the key, rewraps to the remaining members, sets the frontier from
/// the merged heads, and publishes the rotation commit with the state in one `publishManifest`.
#[test]
fn remove_rotates_and_cuts_off() {
    let a = node();
    let proxy = Proxy::new(&a);
    let (_id, mut owner) = owner_vault(&proxy.url());
    let repo = owner.repo_id().to_string();
    set(&mut owner, U1, &[("username", json!("u0"))], now_ms());
    let mut bob = invite_member(&mut owner, &a.url());
    let mut carol = invite_member(&mut owner, &a.url());
    // Two concurrent heads, one by bob and one by carol: the removal merges both straight into the
    // rotation commit, so its frontier is both heads, by any author (SPEC 7.3, 8.3).
    set(&mut bob, U2, &[("username", json!("bob-wrote"))], now_ms());
    set(&mut carol, U1, &[("accessToken", json!("carol-wrote"))], now_ms());
    let b1 = bob.heads()[0];
    let c1 = carol.heads()[0];
    let merged = sorted(vec![b1, c1]);
    assert_eq!(sorted(a.heads(&repo)), merged);
    let before = owner.tip().clone();
    let old_key = owner.retained_epoch_keys[&0];

    let mark = proxy.request_count();
    owner.remove(bob.member().ed25519_public()).unwrap();
    let during: Vec<String> = proxy.paths()[mark..].to_vec();
    let publishes: Vec<&String> = during.iter().filter(|p| p.ends_with("/manifest")).collect();
    assert_eq!(publishes.len(), 1, "one publishManifest: {during:?}");
    assert!(
        !during.iter().any(|p| p.ends_with("/push")),
        "no separate push: {during:?}"
    );
    let body: Value =
        serde_json::from_slice(&proxy.bodies()[mark + during.iter().position(|p| p.ends_with("/manifest")).unwrap()])
            .unwrap();
    assert!(
        body["manifest"].is_object() && body["commit"].is_object(),
        "state and rotation commit together"
    );

    let tip = owner.tip().clone();
    let s = &tip.state;
    assert_eq!(s.manifest_seq, before.state.manifest_seq + 1);
    assert_eq!(s.key_epoch, 1, "epoch + 1");
    assert!(!s.has_member(&bob.member().ed25519_public()));
    let removal = s.removal_of(&bob.member().ed25519_public()).unwrap();
    assert_eq!(removal.removed_at_seq, s.manifest_seq);
    assert_eq!(
        sorted(removal.frontier.clone()),
        merged,
        "frontier = the heads merged into the rotation commit"
    );
    let new_key = owner.retained_epoch_keys[&1];
    assert_ne!(new_key, old_key);
    assert_eq!(owner.retained_epoch_keys[&0], old_key, "the old epoch key is retained");
    for m in &s.members {
        assert_eq!(m.key_epoch, 1);
    }
    let carol_entry = s
        .members
        .iter()
        .find(|m| m.ed25519_public_key == carol.member().ed25519_public())
        .unwrap();
    assert_eq!(
        unwrap(&carol.member().x25519, &carol_entry.wrapped_data_key, WRAP_INFO).unwrap(),
        new_key.to_vec()
    );

    // The host recorded the rotation commit with the state (SPEC 8.3).
    let h = tip.hash().unwrap();
    let rc = a
        .view(&repo, |v| v.rotation_commit(&h).cloned())
        .flatten()
        .expect("rotation commit recorded");
    assert_eq!(
        (rc.manifest_seq, rc.manifest_hash, rc.key_epoch),
        (s.manifest_seq, h, 1)
    );
    assert_eq!(rc.author, s.owner_key);
    assert_eq!(sorted(rc.parents.clone()), merged, "parents = the merged heads");
    assert_eq!(a.heads(&repo), vec![rc.commit_id]);
    let carried = decrypt(&rc, &new_key);
    assert_eq!(
        field(&carried, U2, "username"),
        Some(&json!("bob-wrote")),
        "carries the merged state"
    );
    assert_eq!(field(&carried, U1, "accessToken"), Some(&json!("carol-wrote")));

    // Carol gets the new key and the carried state.
    carol.pull().unwrap();
    assert_eq!(carol.retained_epoch_keys[&1], new_key);
    assert_eq!(field(carol.payload(), U2, "username"), Some(&json!("bob-wrote")));

    // Bob is cut off: no pull, and no backdated write citing his old state (SPEC 7.3).
    assert_eq!(host_code(bob.pull()), "forbidden");
    assert_eq!(host_code(bob.write(|_, _| {})), "forbidden");
}

/// SPEC 8.4: a leaving member signs a leave request and stops syncing; the owner processes it as a
/// removal the next time it is online.
#[test]
fn leave_processed_by_owner() {
    let a = node();
    let (_id, mut owner) = owner_vault(&a.url());
    let repo = owner.repo_id().to_string();
    let proxy = Proxy::new(&a);
    let mut bob = invite_member(&mut owner, &proxy.url());
    let bob_key = bob.member().ed25519_public();
    let seq = owner.tip().state.manifest_seq;

    bob.leave().unwrap();
    let after_leave = proxy.request_count();
    assert!(proxy.paths().iter().any(|p| p.ends_with("/leave")));
    assert!(matches!(bob.pull(), Err(ClientError::Left)));
    assert!(matches!(bob.write(|_, _| {}), Err(ClientError::Left)));
    assert_eq!(
        proxy.request_count(),
        after_leave,
        "a member that left sends nothing more"
    );

    let report = owner.pull().unwrap();
    assert_eq!(report.leaves, 1);
    assert_eq!(owner.leaves().len(), 1);
    assert_eq!(owner.leaves()[0].member_key, bob_key);
    let removed = owner.process_leaves().unwrap();
    assert_eq!(removed, vec![bob_key]);
    let s = &owner.tip().state;
    assert_eq!(s.manifest_seq, seq + 1);
    assert_eq!(s.key_epoch, 1, "processed by removal, with rotation");
    assert!(!s.has_member(&bob_key));
    assert!(s.removal_of(&bob_key).is_some());
    assert_eq!(a.tip_seq(&repo), seq + 1);

    // The host dropped the leave once a state removed the member.
    assert_eq!(owner.pull().unwrap().leaves, 0);
    assert!(owner.process_leaves().unwrap().is_empty());
}

/// SPEC 7.5, Review Focus 4: bob joined at epoch 1 sees a head written under epoch 0. He cannot
/// read it, so he leaves it without error and never names it as a parent; the owner, who retained
/// the epoch-0 key, merges it forward.
#[test]
fn skips_unreadable_head() {
    let a = node();
    let (_id, mut owner) = owner_vault(&a.url());
    let repo = owner.repo_id().to_string();
    set(&mut owner, U1, &[("username", json!("u0"))], now_ms());
    let mut carol = invite_member(&mut owner, &a.url());
    let dave = invite_member(&mut owner, &a.url());
    carol.pull().unwrap();

    owner.remove(dave.member().ed25519_public()).unwrap();
    assert_eq!(owner.tip().state.key_epoch, 1);
    let mut bob = invite_member(&mut owner, &a.url());
    assert!(
        !bob.retained_epoch_keys.contains_key(&0),
        "bob never held the epoch-0 key"
    );

    // Carol has not pulled since the rotation: she writes under epoch 0, citing the old state.
    set(&mut carol, U2, &[("username", json!("carol-epoch0"))], now_ms());
    let c = carol.heads()[0];
    assert_eq!(a.commit(&repo, &c).key_epoch, 0);
    assert_eq!(a.heads(&repo).len(), 2);

    let report = bob.pull().expect("an unreadable head does not fail the pull");
    assert_eq!(report.unreadable_heads, vec![c]);
    assert!(report.discarded_commits.is_empty(), "it is valid, only unreadable");
    assert_eq!(report.merge_commit, None, "one readable head: nothing to merge");
    assert_eq!(bob.unreadable_heads(), &[c]);
    assert!(!bob.heads().contains(&c));
    assert!(field(bob.payload(), U2, "username").is_none());

    set(&mut bob, U1, &[("lastUsedBy", json!("bob"))], now_ms());
    let bw = a.commit(&repo, &bob.heads()[0]);
    assert!(!bw.parents.contains(&c), "an unreadable head is never a parent");
    assert!(
        a.heads(&repo).contains(&c),
        "the head is left for another member, not dropped"
    );

    // The owner holds the epoch-0 key and merges the old head forward under epoch 1.
    let report = owner.pull().unwrap();
    let m = report.merge_commit.expect("the owner reads both heads and merges");
    let mc = a.commit(&repo, &m);
    assert_eq!(mc.key_epoch, 1);
    assert!(mc.parents.contains(&c));
    assert_eq!(field(owner.payload(), U2, "username"), Some(&json!("carol-epoch0")));

    bob.pull().unwrap();
    assert!(bob.unreadable_heads().is_empty());
    assert_eq!(field(bob.payload(), U2, "username"), Some(&json!("carol-epoch0")));
}

/// SPEC 11.6: device linking. Both devices show the same confirmation code, the grant carries the
/// entropy under `avp/owner-link/v1`, and the new device regenerates the same phrase; a grant for
/// another ephemeral key does not open.
#[test]
fn linked_device_shows_same_mnemonic() {
    let a = node();
    let (id, mut v) = owner_vault(&a.url());
    set(&mut v, U1, &[("username", json!("linked"))], now_ms());
    let repo = v.repo_id().to_string();

    let session = LinkSession::new();
    let code_new = session.confirmation_code().unwrap();
    assert_eq!(code_new.len(), 6);
    assert!(code_new.bytes().all(|b| b.is_ascii_digit()));
    // The request travels out of band as a token.
    let text = encode_token(session.request()).unwrap();
    let request: LinkRequest = decode_token(&text).unwrap();

    // The existing device refuses to continue unless the owner confirms the code.
    let r = approve(&id.entropy, &request, |_| false);
    assert!(matches!(r, Err(ClientError::LinkNotConfirmed)));

    let mut shown = String::new();
    let grant = approve(&id.entropy, &request, |code| {
        shown = code.to_string();
        code == code_new
    })
    .unwrap();
    assert_eq!(shown, code_new, "both devices show the same code");
    let grant: LinkGrant = decode_token(&encode_token(&grant).unwrap()).unwrap();
    let linked = session.finish(&grant).unwrap();
    assert_eq!(linked.mnemonic(), id.mnemonic(), "the same 24-word phrase");
    assert_eq!(linked.keys.owner_key(), id.keys.owner_key());

    let opened = Vault::open(host(&a.url()), Member::from_owner(&linked.keys), &repo).unwrap();
    assert_eq!(field(opened.payload(), U1, "username"), Some(&json!("linked")));

    // A grant made for another device's ephemeral key does not open here.
    let other = LinkSession::new();
    let stray = approve(&id.entropy, other.request(), |_| true).unwrap();
    let mine = LinkSession::new();
    assert!(mine.finish(&stray).is_err());
}

/// SPEC 5.1, Review Focus 5: with the policy not `true`, `refreshToken` and `expiresAt` are stripped
/// with their stamps on write and on read, including from a head written while the policy was on.
#[test]
fn refresh_tokens_stripped_when_policy_false() {
    let a = node();
    let (_id, mut owner) = owner_vault(&a.url());
    let repo = owner.repo_id().to_string();
    let mut bob = invite_member(&mut owner, &a.url());
    let key0 = owner.retained_epoch_keys[&0];

    // Write side: the owner's own payload never carries them.
    set(
        &mut owner,
        U1,
        &[
            ("accessToken", json!("at")),
            ("refreshToken", json!("rt")),
            ("expiresAt", json!(123)),
        ],
        now_ms(),
    );
    let written = decrypt(&a.commit(&repo, &owner.heads()[0]), &key0);
    let f = &written.accounts[U1].fields;
    assert!(f.contains_key("accessToken"));
    assert!(
        !f.contains_key("refreshToken") && !f.contains_key("expiresAt"),
        "stripped on write"
    );
    assert!(!owner.payload().accounts[U1].fields.contains_key("refreshToken"));

    // Read side: a modified build pushes a payload with a refresh token; every client drops it.
    bob.pull().unwrap();
    let mut p = bob.payload().clone();
    let st = Stamp {
        at: now_ms() + 5_000,
        n: 0,
        by: bob.member().id(),
    };
    set_field(&mut p, U2, "refreshToken", json!("rogue-rt"), &st);
    set_field(&mut p, U2, "expiresAt", json!(999), &st);
    set_field(&mut p, U2, "username", json!("rogue"), &st);
    let tip = bob.tip().clone();
    let rogue = Commit::seal(
        &key0,
        header_at(
            &bob,
            bob.heads().to_vec(),
            tip.state.manifest_seq,
            tip.hash().unwrap(),
            0,
        ),
        &p.to_json().unwrap(),
        &bob.member().signing,
    )
    .unwrap();
    let me = bob.member().signing.clone();
    bob.host_mut().push(&me, &repo, &rogue).unwrap();
    owner.pull().unwrap();
    let acc = &owner.payload().accounts[U2];
    assert_eq!(acc.fields.get("username").map(|f| &f.value), Some(&json!("rogue")));
    assert!(
        !acc.fields.contains_key("refreshToken") && !acc.fields.contains_key("expiresAt"),
        "stripped on read"
    );

    // Policy on: the field is kept and shared.
    owner.set_share_refresh_tokens(true).unwrap();
    assert!(owner.tip().state.share_refresh_tokens);
    set(
        &mut owner,
        U1,
        &[("refreshToken", json!("rt2")), ("expiresAt", json!(456))],
        now_ms(),
    );
    let on = owner.heads()[0];
    assert_eq!(field(owner.payload(), U1, "refreshToken"), Some(&json!("rt2")));
    bob.pull().unwrap();
    assert_eq!(
        field(bob.payload(), U1, "refreshToken"),
        Some(&json!("rt2")),
        "shared while on"
    );
    let carried = decrypt(&a.commit(&repo, &on), &key0);
    assert!(carried.accounts[U1].fields.contains_key("refreshToken"));

    // Policy back off: the head written while on still carries the field, and the merged result
    // has neither field, stamps included.
    owner.set_share_refresh_tokens(false).unwrap();
    bob.pull().unwrap();
    assert_eq!(a.heads(&repo), vec![on], "the head still carries refreshToken");
    let f = &bob.payload().accounts[U1].fields;
    assert!(
        !f.contains_key("refreshToken") && !f.contains_key("expiresAt"),
        "stripped from a merged-in head"
    );
    set(&mut bob, U1, &[("lastUsed", json!(7))], now_ms());
    let next = decrypt(&a.commit(&repo, &bob.heads()[0]), &key0);
    assert!(!next.accounts[U1].fields.contains_key("refreshToken"));
    assert!(!next.accounts[U1].fields.contains_key("expiresAt"));
}

// ─── Client checks against a malicious host (SPEC 6, 7.5) ───────────────────────────────

/// SPEC 6.1 rule 2, 5.1: a pulled state whose owner signature does not verify, or whose content was
/// rewritten under the original signature, is discarded; the pin and the policy do not move.
#[test]
fn pulled_manifest_with_bad_owner_signature_is_discarded() {
    let a = node();
    let (id, mut dev1) = owner_vault(&a.url());
    let repo = dev1.repo_id().to_string();
    let proxy = Proxy::new(&a);
    let mut dev2 = Vault::open(host(&proxy.url()), Member::from_owner(&id.keys), &repo).unwrap();
    dev1.set_share_refresh_tokens(true).unwrap();

    proxy.on_pull(|_, ans| {
        for m in ans["manifests"].as_array_mut().unwrap() {
            if m["state"]["manifestSeq"] == json!(2) {
                let sig = m["ownerSignature"].as_str().unwrap().to_string();
                let mut raw = avp::encoding::b64_decode(&sig).unwrap();
                raw[5] ^= 0x40;
                m["ownerSignature"] = json!(b64_encode(&raw));
            }
        }
    });
    let r = dev2.pull().unwrap();
    assert_eq!(r.discarded_states, 1);
    assert_eq!(dev2.tip().state.manifest_seq, 1, "pin stays");
    assert!(!dev2.tip().state.share_refresh_tokens);

    // A rewritten field under the original signature fails the same way.
    proxy.on_pull(|_, ans| {
        for m in ans["manifests"].as_array_mut().unwrap() {
            if m["state"]["manifestSeq"] == json!(2) {
                m["state"]["keyEpoch"] = json!(1);
            }
        }
    });
    let r = dev2.pull().unwrap();
    assert_eq!(r.discarded_states, 1);
    assert_eq!(dev2.tip().state.manifest_seq, 1);

    proxy.honest();
    let r = dev2.pull().unwrap();
    assert_eq!(r.discarded_states, 0);
    assert_eq!(dev2.tip().state.manifest_seq, 2);
    assert!(dev2.tip().state.share_refresh_tokens);
}

/// SPEC 6.4: the client pins its highest verified state and rejects a chain that does not contain
/// it (a genuine but shorter, owner-signed prefix), except a diverged chain that wins the tie rule
/// at a fork point at or below the pin (SPEC 6.5), to which it re-pins even at a lower seq.
#[test]
fn pulled_manifest_rollback_is_rejected() {
    let a = node();
    let (id, mut dev1) = owner_vault(&a.url());
    let repo = dev1.repo_id().to_string();
    dev1.set_share_refresh_tokens(true).unwrap();
    dev1.set_share_refresh_tokens(false).unwrap();
    let proxy = Proxy::new(&a);
    let mut dev2 = Vault::open(host(&proxy.url()), Member::from_owner(&id.keys), &repo).unwrap();
    let chain: Vec<SignedManifest> = dev2.chain().states().to_vec();
    assert_eq!(chain.len(), 3);
    let pinned = dev2.tip_hash();

    // Rollback: the host serves only the first two states.
    let prefix = serde_json::to_value(&chain[..2]).unwrap();
    proxy.on_pull(move |_, ans| ans["manifests"] = prefix.clone());
    let r = dev2.pull().unwrap();
    assert!(r.rejected_chain);
    assert_eq!(dev2.tip().state.manifest_seq, 3);
    assert_eq!(dev2.tip_hash(), pinned);

    // A diverged seq 2 signed by the owner: rejected if it loses the tie rule, adopted if it wins.
    let alt = |i: u32| {
        let mut s = chain[1].state.clone();
        s.hosts[0].locator = format!("v{i}.vault.example:443");
        s.sign(&id.keys.signing).unwrap()
    };
    let real2 = chain[1].hash().unwrap();
    let (mut lower, mut higher) = (None, None);
    for i in 0.. {
        let m = alt(i);
        if m.hash().unwrap() < real2 {
            lower.get_or_insert(m);
        } else {
            higher.get_or_insert(m);
        }
        if lower.is_some() && higher.is_some() {
            break;
        }
    }
    let (lower, higher) = (lower.unwrap(), higher.unwrap());

    let losing = serde_json::to_value(vec![chain[0].clone(), higher]).unwrap();
    proxy.on_pull(move |_, ans| ans["manifests"] = losing.clone());
    let r = dev2.pull().unwrap();
    assert!(
        r.rejected_chain,
        "a diverged chain that loses the tie rule is a rollback"
    );
    assert_eq!(dev2.tip_hash(), pinned);

    let winning = serde_json::to_value(vec![chain[0].clone(), lower.clone()]).unwrap();
    proxy.on_pull(move |_, ans| ans["manifests"] = winning.clone());
    let r = dev2.pull().unwrap();
    assert!(!r.rejected_chain);
    assert_eq!(
        dev2.tip().state.manifest_seq,
        2,
        "re-pinned to the winning tip below the old pin"
    );
    assert_eq!(dev2.tip_hash(), lower.hash().unwrap());
}

/// SPEC 7.5: the client checks every pulled commit itself. A bad signature, an author who is not a
/// member at the commit's epoch, an epoch mismatch, a removed author outside the frontier, and a
/// commit citing a state not on the chain by a non-member are discarded: never merged and never
/// named as a parent, although every one is sealed under a key the client holds.
#[test]
fn pulled_commit_failing_client_checks_is_discarded() {
    let a = node();
    let proxy = Proxy::new(&a);
    let (_id, mut owner) = owner_vault(&proxy.url());
    set(&mut owner, U1, &[("username", json!("u0"))], now_ms());
    let bob = invite_member(&mut owner, &a.url());
    let mut dave = invite_member(&mut owner, &a.url());
    dave.pull().unwrap();
    let dave_state = dave.tip().clone();
    owner.remove(dave.member().ed25519_public()).unwrap();
    let frontier = owner
        .tip()
        .state
        .removal_of(&dave.member().ed25519_public())
        .unwrap()
        .frontier
        .clone();
    let (k0, k1) = (owner.retained_epoch_keys[&0], owner.retained_epoch_keys[&1]);
    let tip = owner.tip().clone();
    let (seq, hash) = (tip.state.manifest_seq, tip.hash().unwrap());
    let parents = owner.heads().to_vec();
    let outsider = SigningKey::from_bytes(&random_bytes::<32>());

    let mut bad_sig = forge(
        &k1,
        header_at(&owner, parents.clone(), seq, hash, 1),
        "forged-bad-sig",
        &bob.member().signing,
    );
    bad_sig.author_signature[0] ^= 1;
    let forged = vec![
        bad_sig,
        forge(
            &k1,
            header_at(&owner, parents.clone(), seq, hash, 1),
            "forged-outsider",
            &outsider,
        ),
        forge(
            &k0,
            header_at(&owner, parents.clone(), seq, hash, 0),
            "forged-epoch",
            &bob.member().signing,
        ),
        forge(
            &k0,
            header_at(
                &owner,
                frontier.clone(),
                dave_state.state.manifest_seq,
                dave_state.hash().unwrap(),
                0,
            ),
            "forged-removed",
            &dave.member().signing,
        ),
        forge(
            &k0,
            header_at(&owner, parents.clone(), 1, random_bytes::<32>(), 0),
            "forged-off-chain",
            &outsider,
        ),
    ];
    let ids: Vec<Id> = forged.iter().map(|c| c.commit_id).collect();
    let extra = serde_json::to_value(&forged).unwrap();
    proxy.on_pull(move |_, ans| {
        let heads = ans["heads"].as_array_mut().unwrap();
        heads.extend(extra.as_array().unwrap().iter().cloned());
    });

    let r = owner.pull().unwrap();
    assert_eq!(sorted(r.discarded_commits.clone()), sorted(ids.clone()));
    assert_eq!(r.merge_commit, None, "nothing forged is merged");
    assert_eq!(owner.heads(), parents.as_slice());
    for uuid in [
        "forged-bad-sig",
        "forged-outsider",
        "forged-epoch",
        "forged-removed",
        "forged-off-chain",
    ] {
        assert!(!owner.payload().accounts.contains_key(uuid), "{uuid} merged");
    }
    proxy.honest();
    set(&mut owner, U2, &[("username", json!("after"))], now_ms());
    let w = a.commit(owner.repo_id(), &owner.heads()[0]);
    assert!(
        w.parents.iter().all(|p| !ids.contains(p)),
        "a discarded commit is never a parent"
    );
}

/// SPEC 7.5 rule 3, the not-on-chain branch: a commit citing a `(seq, hash)` that is not on the
/// client's chain passes only if its author is a member, at the commit's epoch, of a state at or
/// after the cited seq; and a removed author's head passes only when its id is in the frontier.
#[test]
fn commit_checks_follow_the_client_chain() {
    let a = node();
    let (_id, mut owner) = owner_vault(&a.url());
    let bob = invite_member(&mut owner, &a.url());
    let mut dave = invite_member(&mut owner, &a.url());
    set(&mut dave, U2, &[("username", json!("dave"))], now_ms());
    owner.remove(dave.member().ed25519_public()).unwrap();
    let chain = Chain::from_states(owner.chain().states()).unwrap();
    let (k0, k1) = (owner.retained_epoch_keys[&0], owner.retained_epoch_keys[&1]);
    let tip = owner.tip().clone();
    let fake = random_bytes::<32>();
    let outsider = SigningKey::from_bytes(&random_bytes::<32>());

    // Not on the chain, but bob is a member at epoch 0 of a state at or after seq 1: passes.
    let ok = forge(&k0, header_at(&owner, vec![], 1, fake, 0), "x", &bob.member().signing);
    chain.verify_commit(&ok).unwrap();
    // Same, at an epoch no such state has.
    let bad = forge(&k0, header_at(&owner, vec![], 1, fake, 7), "x", &bob.member().signing);
    assert!(chain.verify_commit(&bad).is_err());
    // Not a member of any state.
    let bad = forge(&k0, header_at(&owner, vec![], 1, fake, 0), "x", &outsider);
    assert!(chain.verify_commit(&bad).is_err());
    // On the chain: the cited state itself must list the author at that epoch.
    let bad = forge(
        &k1,
        header_at(&owner, vec![], 1, chain.states()[0].hash().unwrap(), 0),
        "x",
        &bob.member().signing,
    );
    assert!(
        chain.verify_commit(&bad).is_err(),
        "bob is not a member of the genesis state"
    );
    let ok = forge(
        &k1,
        header_at(&owner, vec![], tip.state.manifest_seq, tip.hash().unwrap(), 1),
        "x",
        &bob.member().signing,
    );
    chain.verify_commit(&ok).unwrap();
    // A removed author: only a frontier id passes; any other head fails, whatever it cites.
    let frontier = &tip.state.removal_of(&dave.member().ed25519_public()).unwrap().frontier;
    let any = forge(
        &k0,
        header_at(&owner, frontier.clone(), 3, fake, 0),
        "x",
        &dave.member().signing,
    );
    assert!(chain.verify_commit(&any).is_err());
    let honest = a.commit(owner.repo_id(), &frontier[0]);
    assert_eq!(
        honest.author,
        dave.member().ed25519_public(),
        "dave's write was the merged head"
    );
    chain.verify_commit(&honest).unwrap();
}

/// SPEC 8.2: an acceptance signed by another host key than the token's home host is refused.
#[test]
fn invite_refuses_acceptance_from_another_host_key() {
    let a = node();
    let b = node();
    let (_id, mut owner) = owner_vault(&a.url());
    let repo = owner.repo_id().to_string();
    let bob = Member::generate();

    // A real acceptance from host B in a token that claims host A as the home host.
    let mut hb = host(&b.url());
    let mut t = prepare_join(&mut hb, &bob, &repo).unwrap();
    t.home_host_key = a.key();
    t.home_host_locator = a.serving.addr().to_string();
    assert!(matches!(owner.invite(&t), Err(ClientError::InviteRefused(_))));

    // An acceptance that names host A but is signed with host B's key.
    let mut t = prepare_join(&mut host(&a.url()), &bob, &repo).unwrap();
    let mut forged = t.acceptance.clone().sign(&b.signing()).unwrap();
    forged.host_key = a.key();
    t.acceptance = forged;
    assert!(matches!(owner.invite(&t), Err(ClientError::InviteRefused(_))));
    assert_eq!(a.tip_seq(&repo), 1, "nothing published");
}

/// SPEC 3.1, 3.3, CLAUDE.md zero-knowledge: no request body the clients send, and nothing the host
/// stores, contains a plaintext, a data key, the phrase, its entropy or seed, or a private key.
#[test]
fn client_never_sends_secrets_or_plaintext() {
    let a = node();
    let pa = Proxy::new(&a);
    let pb = Proxy::new(&a);
    let (id, mut owner) = owner_vault(&pa.url());
    let repo = owner.repo_id().to_string();
    owner.set_share_refresh_tokens(true).unwrap();
    set(
        &mut owner,
        U1,
        &[
            ("username", json!("plain-username-7f3a")),
            ("accessToken", json!("plain-access-token-7f3a")),
            ("refreshToken", json!("plain-refresh-token-7f3a")),
        ],
        now_ms(),
    );
    let mut bob = invite_member(&mut owner, &pb.url());
    set(&mut bob, U2, &[("username", json!("plain-bob-alt-7f3a"))], now_ms());
    owner.pull().unwrap();
    bob.pull().unwrap();
    let mut carol = invite_member(&mut owner, &pb.url());
    owner.remove(bob.member().ed25519_public()).unwrap();
    carol.pull().unwrap();
    carol.leave().unwrap();
    owner.process_leaves().unwrap();
    let session = LinkSession::new();
    let grant = approve(&id.entropy, session.request(), |_| true).unwrap();
    let linked = session.finish(&grant).unwrap();
    let _again = Vault::open(host(&pa.url()), Member::from_owner(&linked.keys), &repo).unwrap();

    let phrase = id.mnemonic();
    let seed = mnemonic_to_seed(&phrase, "");
    let mut secrets: Vec<(String, Vec<u8>)> = vec![
        ("mnemonic".into(), phrase.clone().into_bytes()),
        (
            "first words".into(),
            phrase.split(' ').take(3).collect::<Vec<_>>().join(" ").into_bytes(),
        ),
        ("entropy".into(), id.entropy.to_vec()),
        ("seed".into(), seed.to_vec()),
        ("owner ed25519 seed".into(), id.keys.signing.to_bytes().to_vec()),
        ("owner x25519".into(), id.keys.x25519.to_bytes().to_vec()),
    ];
    for (who, m) in [("bob", bob.member()), ("carol", carol.member())] {
        secrets.push((format!("{who} ed25519 seed"), m.signing.to_bytes().to_vec()));
        secrets.push((format!("{who} x25519"), m.x25519.to_bytes().to_vec()));
    }
    for (e, k) in &owner.retained_epoch_keys {
        secrets.push((format!("data key {e}"), k.to_vec()));
    }
    for text in [
        "plain-username-7f3a",
        "plain-access-token-7f3a",
        "plain-refresh-token-7f3a",
        "plain-bob-alt-7f3a",
    ] {
        secrets.push((text.into(), text.as_bytes().to_vec()));
    }
    // Each secret in every encoding a body could carry it in.
    let mut needles: Vec<(String, Vec<u8>)> = Vec::new();
    for (what, raw) in &secrets {
        needles.push((format!("{what} raw"), raw.clone()));
        needles.push((format!("{what} base64"), b64_encode(raw).into_bytes()));
        needles.push((format!("{what} base64url"), b64url_encode(raw).into_bytes()));
        let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        needles.push((format!("{what} hex"), hex.into_bytes()));
    }

    let bodies: Vec<Vec<u8>> = pa.bodies().into_iter().chain(pb.bodies()).collect();
    assert!(bodies.len() > 20, "the flow went through the proxies");
    for body in &bodies {
        for (what, n) in &needles {
            assert!(
                !body.windows(n.len()).any(|w| w == n.as_slice()),
                "a request body carries the {what}"
            );
        }
    }

    // Everything the host stores: the engine view's debug dump (byte lists) and the served JSON.
    let (dump, served) = a
        .view(&repo, |v| {
            let mut served = serde_json::to_string(&v.manifests_since(0)).unwrap();
            served.push_str(&serde_json::to_string(&v.commits_since(&[])).unwrap());
            (format!("{v:?}"), served)
        })
        .unwrap();
    for (what, raw) in &secrets {
        let list: Vec<String> = raw.iter().map(u8::to_string).collect();
        assert!(!dump.contains(&list.join(", ")), "the host stores the {what}");
        if let Ok(text) = std::str::from_utf8(raw) {
            assert!(!dump.contains(text), "the host stores the {what} as text");
        }
        assert!(!served.contains(&b64_encode(raw)), "the host serves the {what}");
    }
}

/// Makes the proxy serve `chain ++ extra` to a pull from seq 0 and `extra` to any other pull.
fn serve_states(proxy: &Proxy, chain: Vec<SignedManifest>, extra: Vec<SignedManifest>) {
    proxy.on_pull(move |req, ans| {
        let list: Vec<SignedManifest> = if req["sinceManifestSeq"] == json!(0) {
            chain.iter().chain(&extra).cloned().collect()
        } else {
            extra.clone()
        };
        ans["manifests"] = serde_json::to_value(list).unwrap();
    });
}

/// SPEC 6.1 rules 1, 4, 5: states signed with the real owner key that break a structure, link, or
/// content rule are discarded by the client itself; the pin does not move. A valid next state is
/// then adopted through the same path.
#[test]
fn owner_signed_states_breaking_chain_rules_are_discarded() {
    let a = node();
    let (id, mut dev1) = owner_vault(&a.url());
    let bob = invite_member(&mut dev1, &a.url());
    let repo = dev1.repo_id().to_string();
    let proxy = Proxy::new(&a);
    let mut dev2 = Vault::open(host(&proxy.url()), Member::from_owner(&id.keys), &repo).unwrap();
    let chain = dev2.chain().states().to_vec();
    let tip = dev2.tip().clone();
    let pin = dev2.tip_hash();
    let bob_key = bob.member().ed25519_public();
    let bob_entry = tip
        .state
        .members
        .iter()
        .find(|m| m.ed25519_public_key == bob_key)
        .unwrap()
        .clone();
    let next = || {
        let mut s = tip.state.clone();
        s.manifest_seq += 1;
        s.prev_manifest_hash = pin.to_vec();
        s
    };
    let sign = |s: ManifestState| s.sign(&id.keys.signing).unwrap();
    let newcomer = |home: Id, ct_len: usize| {
        let mut m = bob_entry.clone();
        m.ed25519_public_key = Member::generate().ed25519_public();
        m.home_host_key = home;
        m.wrapped_data_key.ciphertext.truncate(ct_len);
        m
    };

    let mut cases: Vec<(&str, SignedManifest)> = Vec::new();
    let mut s = next();
    s.prev_manifest_hash = random_bytes::<32>().to_vec();
    cases.push(("wrong prevManifestHash (6.3)", sign(s)));
    let mut s = next();
    s.members.retain(|m| m.ed25519_public_key != bob_key);
    s.removals.push(Removal {
        member_key: bob_key,
        removed_at_seq: s.manifest_seq,
        frontier: Vec::new(),
    });
    cases.push(("removal without an epoch bump (6.1 rule 5)", sign(s)));
    let mut s = next();
    s.members.retain(|m| m.ed25519_public_key != bob_key);
    cases.push(("member dropped without a removal (6.1 rule 5)", sign(s)));
    let mut s = next();
    s.members.push(newcomer(random_bytes::<32>(), 48));
    cases.push(("homeHostKey not in hosts (6.1 rule 5)", sign(s)));
    let mut s = next();
    s.members.push(newcomer(a.key(), 47));
    cases.push(("47-byte wrapped ciphertext (6.1 rule 1)", sign(s)));
    // A state listing a member twice cannot be encoded, so no signature over it exists; the
    // owner's signature over the same state without the duplicate is attached.
    let mut s = next();
    let signature = sign(s.clone()).owner_signature;
    s.members.push(bob_entry.clone());
    cases.push((
        "duplicate members (4.2, 6.1 rule 1)",
        SignedManifest {
            state: s,
            owner_signature: signature,
        },
    ));

    for (what, bad) in cases {
        serve_states(&proxy, chain.clone(), vec![bad]);
        let r = dev2.pull().unwrap();
        assert_eq!(r.discarded_states, 1, "{what}");
        assert_eq!(r.new_states, 0, "{what}");
        assert_eq!(dev2.tip_hash(), pin, "{what}: the pin does not move");
    }

    let mut s = next();
    s.share_refresh_tokens = true;
    let good = sign(s);
    serve_states(&proxy, chain.clone(), vec![good.clone()]);
    let r = dev2.pull().unwrap();
    assert_eq!((r.discarded_states, r.new_states), (0, 1));
    assert_eq!(dev2.tip_hash(), good.hash().unwrap());
}

/// SPEC 6.2: `open` refuses a genesis whose `repoId` does not recompute from `ownerKey` and
/// `genesisNonce`, and a genesis with more than the owner, although both carry the owner's
/// signature.
#[test]
fn open_rejects_an_invalid_genesis() {
    let a = node();
    let (id, dev1) = owner_vault(&a.url());
    let repo = dev1.repo_id().to_string();
    let proxy = Proxy::new(&a);
    let g = dev1.chain().states()[0].clone();

    let mut s = g.state.clone();
    s.genesis_nonce = random_bytes::<16>().to_vec();
    let wrong_id = s.sign(&id.keys.signing).unwrap();
    let mut s = g.state.clone();
    let mut extra = s.members[0].clone();
    extra.ed25519_public_key = Member::generate().ed25519_public();
    s.members.push(extra);
    let two_members = s.sign(&id.keys.signing).unwrap();

    for (what, bad) in [("repoId does not recompute", wrong_id), ("two members", two_members)] {
        serve_states(&proxy, Vec::new(), vec![bad]);
        let r = Vault::open(host(&proxy.url()), Member::from_owner(&id.keys), &repo);
        assert!(matches!(r, Err(ClientError::StateRejected(_))), "{what}: {r:?}");
    }
    proxy.honest();
    Vault::open(host(&proxy.url()), Member::from_owner(&id.keys), &repo).unwrap();
}

/// SPEC 6.4, 6.2: genesis fixes the repository, so a competing owner-signed genesis for the same
/// `repoId` is never adopted, even with a lower `manifestHash` (the tie rule is not applied at seq 1).
#[test]
fn competing_genesis_is_never_adopted() {
    let a = node();
    let (id, dev1) = owner_vault(&a.url());
    let repo = dev1.repo_id().to_string();
    let proxy = Proxy::new(&a);
    let mut dev2 = Vault::open(host(&proxy.url()), Member::from_owner(&id.keys), &repo).unwrap();
    let real = dev2.tip_hash();
    let lower = (0..)
        .map(|i| {
            let mut s = dev1.chain().states()[0].state.clone();
            s.hosts[0].locator = format!("g{i}.vault.example:443");
            s.sign(&id.keys.signing).unwrap()
        })
        .find(|m| m.hash().unwrap() < real)
        .unwrap();
    assert_eq!(lower.state.repo_id, repo, "a valid genesis of the same repoId");

    serve_states(&proxy, Vec::new(), vec![lower]);
    let r = dev2.pull().unwrap();
    assert!(r.rejected_chain);
    assert_eq!(dev2.tip_hash(), real);
}

/// SPEC 11.2: the joiner checks that the genesis `ownerKey` matches the locator's fingerprint.
#[test]
fn join_checks_the_owner_fingerprint() {
    let a = node();
    let (_id, mut owner) = owner_vault(&a.url());
    let bob = Member::generate();
    let mut home = host(&a.url());
    let token = prepare_join(&mut home, &bob, owner.repo_id()).unwrap();
    owner.invite(&token).unwrap();
    let mut locator = owner.locator().unwrap();
    locator.owner_fingerprint = owner_fingerprint(&random_bytes::<32>());
    let r = Vault::join(host(&a.url()), bob.clone(), &locator);
    assert!(matches!(r, Err(ClientError::OwnerMismatch)), "{r:?}");
    Vault::join(home, bob, &owner.locator().unwrap()).unwrap();
}

/// SPEC 8.4: the owner acts only on leave requests that verify under `memberKey`, name this
/// repository, and come from a current member who is not the owner.
#[test]
fn invalid_leave_requests_are_ignored() {
    let a = node();
    let proxy = Proxy::new(&a);
    let (id, mut owner) = owner_vault(&proxy.url());
    let repo = owner.repo_id().to_string();
    let bob = invite_member(&mut owner, &a.url());
    let seq = owner.tip().state.manifest_seq;
    let leave = |repo_id: &str, key: &SigningKey| {
        LeaveRequest {
            repo_id: repo_id.to_string(),
            member_key: [0; 32],
            at: now_ms(),
            signature: [0; 64],
        }
        .sign(key)
        .unwrap()
    };
    let mut flipped = leave(&repo, &bob.member().signing);
    flipped.signature[0] ^= 1;
    let bad = vec![
        flipped,
        leave(&repo, &SigningKey::from_bytes(&random_bytes::<32>())),
        leave(&repo, &id.keys.signing),
        leave(&b64url_encode(&random_bytes::<16>()), &bob.member().signing),
    ];
    let injected = serde_json::to_value(&bad).unwrap();
    proxy.on_pull(move |_, ans| ans["leaves"] = injected.clone());
    let r = owner.pull().unwrap();
    assert_eq!(r.leaves, 0);
    assert!(owner.leaves().is_empty());
    assert!(owner.process_leaves().unwrap().is_empty(), "nobody is removed");
    assert_eq!(owner.tip().state.manifest_seq, seq);
    assert_eq!(a.tip_seq(&repo), seq);

    // The same path carries a valid request.
    let good = serde_json::to_value(vec![leave(&repo, &bob.member().signing)]).unwrap();
    proxy.on_pull(move |_, ans| ans["leaves"] = good.clone());
    assert_eq!(owner.pull().unwrap().leaves, 1);
}

/// SPEC 8.3: the frontier also lists every verified commit by the removed member that the owner
/// cannot show to be an ancestor of a merged head. Here the owner saw bob's `b1` as a head; the
/// merged head is carol's `c`, whose parent `b2` the owner never saw, so `b1` is listed too.
#[test]
fn frontier_lists_seen_commits_not_known_as_ancestors() {
    let a = node();
    let (_id, mut owner) = owner_vault(&a.url());
    let repo = owner.repo_id().to_string();
    let mut bob = invite_member(&mut owner, &a.url());
    let mut carol = invite_member(&mut owner, &a.url());
    set(&mut bob, U1, &[("username", json!("b1"))], now_ms());
    let b1 = bob.heads()[0];
    owner.pull().unwrap();
    assert_eq!(owner.heads(), &[b1]);
    set(&mut bob, U1, &[("username", json!("b2"))], now_ms());
    carol.pull().unwrap();
    set(&mut carol, U2, &[("username", json!("c"))], now_ms());
    let c = carol.heads()[0];
    assert_eq!(a.heads(&repo), vec![c]);

    owner.remove(bob.member().ed25519_public()).unwrap();
    let removal = owner
        .tip()
        .state
        .removal_of(&bob.member().ed25519_public())
        .unwrap()
        .clone();
    assert_eq!(sorted(removal.frontier), sorted(vec![c, b1]));
    assert_eq!(a.tip_seq(&repo), owner.tip().state.manifest_seq, "the host accepted it");
}

// ─── The worked flow ────────────────────────────────────────────────────────────────────

#[test]
fn worked_flow_one_host() {
    let a = node();
    let mut out = Vec::new();
    flow::run(&a.url(), None, &mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    for step in ["create", "invite", "merge", "leave", "link"] {
        assert!(text.contains(step), "missing step {step}: {text}");
    }
}

#[test]
fn worked_flow_two_peered_hosts() {
    let (a, b) = peered_pair();
    let mut out = Vec::new();
    flow::run(&a.url(), Some(&b.url()), &mut out).unwrap();
    let repo_on_b: HashSet<String> = b.state.lock().unwrap().store.repos.keys().cloned().collect();
    assert_eq!(repo_on_b.len(), 1, "bob's home host B carries the repository");
}
