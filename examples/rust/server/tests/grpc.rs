// SPDX-License-Identifier: MIT

//! Black-box tests of the gRPC client profile (SPEC 10.3).
//!
//! Each test starts the host in-process with HTTP/JSON on `127.0.0.1:0` and gRPC on `127.0.0.1:0`
//! over one shared state, and talks to it with the generated tonic client and with raw HTTP. Bodies
//! are built with the `avp` crate and carried into the proto types through their JSON form, so the
//! same values travel over both profiles. Profiles are compared by decoded values and verification,
//! never by transport bytes.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use avp::auth::sign_challenge;
use avp::commit::{Commit, CommitHeader};
use avp::crypto::{SCHEME_ID, WRAP_INFO, random_bytes, wrap, x25519_public, x25519_random};
use avp::encoding::{b64_decode, b64_encode};
use avp::manifest::{HostRef, ManifestState, MemberEntry, SignedManifest, derive_repo_id};
use avp::tokens::{Acceptance, LeaveRequest};
use avp_reference_server::api::Refused;
use avp_reference_server::grpc::proto::vault_client::VaultClient;
use avp_reference_server::grpc::{GrpcServing, proto, serve_grpc, status_of};
use avp_reference_server::{Serving, State, serve};
use ed25519_dalek::SigningKey;
use prost::Message;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::runtime::Runtime;
use tonic::transport::Channel;
use tonic::{Code, Request, Status};
use x25519_dalek::StaticSecret;

// ─── Harness ────────────────────────────────────────────────────────────────────────────

struct Host {
    http: Serving,
    grpc: Option<GrpcServing>,
    state: Arc<Mutex<State>>,
    rt: Runtime,
}

fn start() -> Host {
    let mut state = State::new(SigningKey::from_bytes(&random_bytes::<32>()));
    state.grpc = true;
    let state = Arc::new(Mutex::new(state));
    let http = serve("127.0.0.1:0", Arc::clone(&state)).expect("bind http");
    let grpc = serve_grpc("127.0.0.1:0", Arc::clone(&state)).expect("bind grpc");
    let rt = Runtime::new().expect("tokio runtime");
    Host {
        http,
        grpc: Some(grpc),
        state,
        rt,
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        if let Some(g) = self.grpc.take() {
            g.stop();
        }
    }
}

struct Reply {
    status: u16,
    json: Value,
}

impl Host {
    fn key(&self) -> [u8; 32] {
        self.state.lock().unwrap().host_key()
    }

    fn client(&self) -> VaultClient<Channel> {
        let addr = self.grpc.as_ref().unwrap().addr();
        self.rt
            .block_on(VaultClient::connect(format!("http://{addr}")))
            .expect("connect grpc")
    }

    fn raw(&self, method: &str, path: &str, token: Option<&str>, body: &[u8]) -> Reply {
        let mut stream = TcpStream::connect(self.http.addr()).expect("connect");
        let mut head = format!(
            "{method} {path} HTTP/1.1\r\nHost: vault.example\r\nConnection: close\r\nContent-Length: {}\r\n",
            body.len()
        );
        head.push_str("Content-Type: application/json\r\n");
        if let Some(t) = token {
            head.push_str(&format!("Authorization: Bearer {t}\r\n"));
        }
        head.push_str("\r\n");
        stream.write_all(head.as_bytes()).unwrap();
        stream.write_all(body).unwrap();
        let mut raw = Vec::new();
        let _ = stream.read_to_end(&mut raw);
        let text = String::from_utf8(raw).unwrap();
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        let status = head.lines().next().and_then(|l| l.split_whitespace().nth(1)).unwrap();
        Reply {
            status: status.parse().unwrap(),
            json: if body.is_empty() {
                Value::Null
            } else {
                serde_json::from_str(body).unwrap()
            },
        }
    }

    fn post(&self, path: &str, token: Option<&str>, body: &Value) -> Reply {
        self.raw("POST", path, token, body.to_string().as_bytes())
    }

    /// The SPEC 3.3 flow over HTTP/JSON.
    fn http_login(&self, key: &SigningKey) -> String {
        let r = self.post(
            "/api/auth/keypair/challenge",
            None,
            &json!({ "ed25519PublicKey": b64_encode(&pk(key)) }),
        );
        let nonce = r.json["nonce"].as_str().unwrap().to_string();
        let sig = sign_challenge(&self.key(), key, &b64_decode(&nonce).unwrap()).unwrap();
        let r = self.post(
            "/api/auth/keypair/token",
            None,
            &json!({ "ed25519PublicKey": b64_encode(&pk(key)), "nonce": nonce, "signature": b64_encode(&sig) }),
        );
        assert_eq!(r.status, 200, "token: {}", r.json);
        r.json["token"].as_str().unwrap().to_string()
    }

    /// The SPEC 3.3 flow over gRPC.
    fn grpc_login(&self, key: &SigningKey) -> String {
        let mut c = self.client();
        let challenge = self
            .rt
            .block_on(c.challenge(proto::ChallengeRequest {
                ed25519_public_key: b64_encode(&pk(key)),
            }))
            .expect("challenge")
            .into_inner();
        let sig = sign_challenge(&self.key(), key, &b64_decode(&challenge.nonce).unwrap()).unwrap();
        let token = self
            .rt
            .block_on(c.token(proto::TokenRequest {
                ed25519_public_key: b64_encode(&pk(key)),
                nonce: challenge.nonce,
                signature: b64_encode(&sig),
            }))
            .expect("token")
            .into_inner();
        assert!(token.expires_at > now_ms());
        token.token
    }
}

fn authed<T>(msg: T, token: &str) -> Request<T> {
    let mut r = Request::new(msg);
    r.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    r
}

fn proto_of<T: DeserializeOwned>(v: Value) -> T {
    serde_json::from_value(v).expect("json -> proto")
}

fn json_of<T: Serialize>(v: &T) -> Value {
    serde_json::to_value(v).unwrap()
}

fn pk(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}

fn now_ms() -> i64 {
    i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()).unwrap()
}

fn assert_status(s: &Status, code: Code, message: &str) {
    assert_eq!(s.code(), code, "status: {s:?}");
    assert_eq!(s.message(), message, "status: {s:?}");
}

// ─── Fixtures built with the avp crate ──────────────────────────────────────────────────

struct Device {
    sign: SigningKey,
    x: StaticSecret,
}

impl Device {
    fn new() -> Device {
        Device {
            sign: SigningKey::from_bytes(&random_bytes::<32>()),
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

struct Repo {
    owner: Device,
    data_key: [u8; 32],
    tip: SignedManifest,
    root: Commit,
}

const EMPTY_PAYLOAD: &[u8] = br#"{"v":2,"accounts":{}}"#;

fn genesis(host: [u8; 32]) -> Repo {
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
        hosts: vec![HostRef {
            key: host,
            locator: "a.vault.example".to_string(),
        }],
        members: vec![owner.entry(&data_key, 0, host)],
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

impl Repo {
    fn id(&self) -> String {
        self.tip.state.repo_id.clone()
    }

    fn path(&self, op: &str) -> String {
        format!("/v1/repos/{}/{op}", self.id())
    }

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

    fn create_request(&self) -> proto::CreateRepoRequest {
        proto_of(json!({ "manifest": json_of(&self.tip), "commit": json_of(&self.root) }))
    }
}

fn create_over_http(host: &Host, repo: &Repo, token: &str) {
    let r = host.post(
        "/v1/repos",
        Some(token),
        &json!({ "manifest": json_of(&repo.tip), "commit": json_of(&repo.root) }),
    );
    assert_eq!(r.status, 200, "createRepo: {}", r.json);
}

fn http_pull(host: &Host, repo: &Repo, token: &str) -> Value {
    let r = host.post(
        &repo.path("pull"),
        Some(token),
        &json!({ "sinceManifestSeq": 0, "knownHeads": [] }),
    );
    assert_eq!(r.status, 200, "pull: {}", r.json);
    r.json
}

fn grpc_pull(host: &Host, repo: &Repo, token: &str) -> Value {
    let mut c = host.client();
    let reply = host
        .rt
        .block_on(c.pull(authed(
            proto::PullRequest {
                since_manifest_seq: 0,
                known_heads: Vec::new(),
                repo_id: repo.id(),
            },
            token,
        )))
        .expect("grpc pull")
        .into_inner();
    json_of(&reply)
}

fn head_ids(pull: &Value) -> Vec<String> {
    let mut ids: Vec<String> = pull["heads"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["commitId"].as_str().unwrap().to_string())
        .collect();
    ids.sort();
    ids
}

// ─── Tests ──────────────────────────────────────────────────────────────────────────────

#[test]
fn get_host_info_answers_discovery_with_both_profiles() {
    let host = start();
    let discovery = host.raw("GET", "/.well-known/avp", None, b"");
    assert_eq!(discovery.status, 200);
    assert_eq!(discovery.json["profiles"], json!(["http-json", "grpc"]));
    let mut c = host.client();
    let info = host
        .rt
        .block_on(c.get_host_info(proto::HostInfoRequest {}))
        .expect("GetHostInfo")
        .into_inner();
    assert_eq!(info.version, "0.5");
    assert_eq!(info.profiles, vec!["http-json".to_string(), "grpc".to_string()]);
    assert_eq!(info.host_key, discovery.json["hostKey"].as_str().unwrap());
    assert_eq!(info.host_key, b64_encode(&host.key()));
}

#[test]
fn discovery_lists_only_http_json_when_grpc_is_off() {
    let state = Arc::new(Mutex::new(State::new(SigningKey::from_bytes(&random_bytes::<32>()))));
    let http = serve("127.0.0.1:0", Arc::clone(&state)).unwrap();
    let mut stream = TcpStream::connect(http.addr()).unwrap();
    stream
        .write_all(b"GET /.well-known/avp HTTP/1.1\r\nHost: vault.example\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut text = String::new();
    let _ = stream.read_to_string(&mut text);
    let body: Value = serde_json::from_str(text.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(body["profiles"], json!(["http-json"]));
}

#[test]
fn challenge_and_token_mint_a_token_both_profiles_accept() {
    let host = start();
    // minted over gRPC, used over HTTP
    let a = genesis(host.key());
    let token = host.grpc_login(&a.owner.sign);
    create_over_http(&host, &a, &token);
    assert_eq!(grpc_pull(&host, &a, &token), http_pull(&host, &a, &token));
    // minted over HTTP, used over gRPC
    let b = genesis(host.key());
    let token = host.http_login(&b.owner.sign);
    let mut c = host.client();
    host.rt
        .block_on(c.create_repo(authed(b.create_request(), &token)))
        .expect("createRepo with an HTTP-minted token");
}

#[test]
fn every_client_rpc_matches_its_http_route() {
    let host = start();
    let mut c = host.client();

    // createRepo over gRPC answers the sent genesis; the same body over HTTP is then duplicate_repo
    let mut a = genesis(host.key());
    let token = host.http_login(&a.owner.sign);
    let created = host
        .rt
        .block_on(c.create_repo(authed(a.create_request(), &token)))
        .expect("createRepo")
        .into_inner();
    assert_eq!(json_of(&created), json_of(&a.tip));
    let r = host.post(
        "/v1/repos",
        Some(&token),
        &json!({ "manifest": json_of(&a.tip), "commit": json_of(&a.root) }),
    );
    assert_eq!((r.status, r.json["code"].clone()), (409, json!("duplicate_repo")));
    // and the reverse on a second fixture
    let b = genesis(host.key());
    let token_b = host.http_login(&b.owner.sign);
    create_over_http(&host, &b, &token_b);
    let err = host
        .rt
        .block_on(c.create_repo(authed(b.create_request(), &token_b)))
        .unwrap_err();
    assert_status(&err, Code::AlreadyExists, "duplicate_repo");

    // pull: the same manifests, heads, and leaves on both profiles
    let over_grpc = grpc_pull(&host, &a, &token);
    let over_http = http_pull(&host, &a, &token);
    assert_eq!(over_grpc, over_http);
    assert_eq!(head_ids(&over_grpc), vec![b64_encode(&a.root.commit_id)]);

    // push over gRPC: accepted, and the same head set on both profiles after the write
    let next = a.commit(&a.owner.sign, vec![a.root.commit_id], br#"{"v":2,"accounts":{"x":{}}}"#);
    let pushed = host
        .rt
        .block_on(c.push(authed(proto_of(json!({ "commit": json_of(&next) })), &token)))
        .expect("push")
        .into_inner();
    assert!(pushed.accepted);
    assert_eq!(pushed.heads, vec![b64_encode(&next.commit_id)]);
    assert_eq!(head_ids(&grpc_pull(&host, &a, &token)), pushed.heads);
    assert_eq!(head_ids(&http_pull(&host, &a, &token)), pushed.heads);

    // publishManifest over gRPC: answers the sent state, and HTTP pull shows it as the tip
    let member = Device::new();
    let home = host.key();
    let entry = member.entry(&a.data_key, 0, home);
    let state2 = a.next(|s| s.members.push(entry));
    let published = host
        .rt
        .block_on(c.publish_manifest(authed(proto_of(json!({ "manifest": json_of(&state2) })), &token)))
        .expect("publishManifest")
        .into_inner();
    assert_eq!(json_of(&published), json_of(&state2));
    let manifests = http_pull(&host, &a, &token)["manifests"].clone();
    assert_eq!(manifests.as_array().unwrap().last().unwrap(), &json_of(&state2));
    a.tip = state2;

    // leave over gRPC: {} and served unchanged by an HTTP pull
    let member_token = host.grpc_login(&member.sign);
    let leave = LeaveRequest {
        repo_id: a.id(),
        member_key: [0; 32],
        at: now_ms(),
        signature: [0; 64],
    }
    .sign(&member.sign)
    .unwrap();
    let left = host
        .rt
        .block_on(c.leave(authed(proto_of::<proto::LeaveRequest>(json_of(&leave)), &member_token)))
        .expect("leave")
        .into_inner();
    assert_eq!(json_of(&left), json!({}));
    assert_eq!(http_pull(&host, &a, &token)["leaves"], json!([json_of(&leave)]));

    // prepareJoin: a fresh acceptance on each profile, each verifying under the host key
    let joiner = Device::new();
    let joiner_token = host.http_login(&joiner.sign);
    let body = json!({ "repoId": a.id(), "memberKey": b64_encode(&joiner.key()) });
    let over_grpc = host
        .rt
        .block_on(c.prepare_join(authed(
            proto_of::<proto::PrepareJoinRequest>(body.clone()),
            &joiner_token,
        )))
        .expect("prepareJoin")
        .into_inner();
    let over_http = host.post("/v1/prepare-join", Some(&joiner_token), &body);
    assert_eq!(over_http.status, 200);
    for acc in [json_of(&over_grpc), over_http.json] {
        let acc: Acceptance = serde_json::from_value(acc).unwrap();
        acc.verify_under(&host.key())
            .expect("acceptance verifies under the host key");
        assert_eq!(acc.repo_id, a.id());
        assert_eq!(acc.member_key, joiner.key());
        assert_eq!(acc.host_key, host.key());
    }
}

#[test]
fn errors_carry_the_avp_code_as_the_status_message() {
    let host = start();
    let mut c = host.client();
    let a = genesis(host.key());
    let token = host.grpc_login(&a.owner.sign);

    let unknown = genesis(host.key());
    let err = host
        .rt
        .block_on(c.pull(authed(
            proto::PullRequest {
                since_manifest_seq: 0,
                known_heads: Vec::new(),
                repo_id: unknown.id(),
            },
            &token,
        )))
        .unwrap_err();
    assert_status(&err, Code::NotFound, "not_found");

    // SPEC 10.3: the body names the repository, and a malformed repoId is bad_request
    let err = host
        .rt
        .block_on(c.pull(authed(
            proto::PullRequest {
                since_manifest_seq: 0,
                known_heads: Vec::new(),
                repo_id: "not-a-repo-id".to_string(),
            },
            &token,
        )))
        .unwrap_err();
    assert_status(&err, Code::InvalidArgument, "bad_request");

    let err = host.rt.block_on(c.create_repo(a.create_request())).unwrap_err();
    assert_status(&err, Code::Unauthenticated, "unauthorized");

    host.rt
        .block_on(c.create_repo(authed(a.create_request(), &token)))
        .expect("createRepo");
    let missing = random_bytes::<32>();
    let orphan = a.commit(&a.owner.sign, vec![missing], EMPTY_PAYLOAD);
    let err = host
        .rt
        .block_on(c.push(authed(proto_of(json!({ "commit": json_of(&orphan) })), &token)))
        .unwrap_err();
    assert_status(&err, Code::FailedPrecondition, "missing_parents");
    let detail = err
        .metadata()
        .get("avp-error-detail")
        .expect("avp-error-detail trailer");
    assert!(detail.to_str().unwrap().contains(&b64_encode(&missing)), "{detail:?}");
}

#[test]
fn status_of_maps_every_code_and_a_codeless_503_to_unavailable() {
    let table: [(&'static str, u16, Code); 12] = [
        ("bad_request", 400, Code::InvalidArgument),
        ("unauthorized", 401, Code::Unauthenticated),
        ("forbidden", 403, Code::PermissionDenied),
        ("policy_denied", 403, Code::PermissionDenied),
        ("not_hosted", 403, Code::PermissionDenied),
        ("not_found", 404, Code::NotFound),
        ("duplicate_repo", 409, Code::AlreadyExists),
        ("too_many_heads", 409, Code::FailedPrecondition),
        ("manifest_conflict", 409, Code::FailedPrecondition),
        ("missing_parents", 422, Code::FailedPrecondition),
        ("quota_exceeded", 429, Code::ResourceExhausted),
        ("too_large", 413, Code::ResourceExhausted),
    ];
    for (code, status, expected) in table {
        let s = status_of(&Refused::new(status, code, "x"));
        assert_status(&s, expected, code);
    }
    let mut with_extras = Refused::new(429, "quota_exceeded", "x");
    with_extras.detail = Some("some detail".to_string());
    with_extras.retry_after_s = Some(120);
    let s = status_of(&with_extras);
    assert_eq!(s.metadata().get("avp-error-detail").unwrap(), "some detail");
    assert_eq!(s.metadata().get("retry-after").unwrap(), "120");
    let codeless = |status| Refused {
        status,
        code: None,
        message: "x".to_string(),
        detail: None,
        retry_after_s: None,
    };
    assert_status(&status_of(&codeless(503)), Code::Unavailable, "unavailable");
    assert_status(&status_of(&codeless(500)), Code::Internal, "internal");
}

#[test]
fn an_absent_required_message_is_bad_request() {
    let host = start();
    let mut c = host.client();
    let a = genesis(host.key());
    let token = host.grpc_login(&a.owner.sign);
    host.rt
        .block_on(c.create_repo(authed(a.create_request(), &token)))
        .expect("createRepo");

    let mut no_commit = a.create_request();
    no_commit.commit = None;
    let err = host.rt.block_on(c.create_repo(authed(no_commit, &token))).unwrap_err();
    assert_status(&err, Code::InvalidArgument, "bad_request");

    let err = host
        .rt
        .block_on(c.push(authed(proto::PushRequest { commit: None }, &token)))
        .unwrap_err();
    assert_status(&err, Code::InvalidArgument, "bad_request");

    let err = host
        .rt
        .block_on(c.publish_manifest(authed(
            proto::PublishManifestRequest {
                manifest: None,
                commit: None,
            },
            &token,
        )))
        .unwrap_err();
    assert_status(&err, Code::InvalidArgument, "bad_request");

    let mut stateless: proto::SignedManifest = proto_of(json_of(&a.tip));
    stateless.state = None;
    let err = host
        .rt
        .block_on(c.publish_manifest(authed(
            proto::PublishManifestRequest {
                manifest: Some(stateless),
                commit: None,
            },
            &token,
        )))
        .unwrap_err();
    assert_status(&err, Code::InvalidArgument, "bad_request");
}

#[test]
fn items_written_over_grpc_pull_over_http_unchanged() {
    let host = start();
    let mut c = host.client();
    let a = genesis(host.key());
    let token = host.grpc_login(&a.owner.sign);
    host.rt
        .block_on(c.create_repo(authed(a.create_request(), &token)))
        .expect("createRepo");
    let next = a.commit(&a.owner.sign, vec![a.root.commit_id], br#"{"v":2,"accounts":{"y":{}}}"#);
    host.rt
        .block_on(c.push(authed(proto_of(json!({ "commit": json_of(&next) })), &token)))
        .expect("push");

    let pulled = http_pull(&host, &a, &token);
    assert_eq!(pulled["manifests"], json!([json_of(&a.tip)]));
    assert_eq!(pulled["heads"], json!([json_of(&next)]));
    let head: Commit = serde_json::from_value(pulled["heads"][0].clone()).unwrap();
    head.verify().expect("the commit pulled over HTTP verifies");
    let tip: SignedManifest = serde_json::from_value(pulled["manifests"][0].clone()).unwrap();
    tip.verify().expect("the state pulled over HTTP verifies");
}

#[test]
fn every_grpc_vector_encodes_to_its_bytes() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../vectors/grpc.json")).unwrap();
    let vectors: Value = serde_json::from_str(&text).unwrap();
    let cases = vectors["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 18);

    fn check<T: Message + Default + Serialize + DeserializeOwned>(name: &str, json: &Value, hex: &str) {
        let msg: T = serde_json::from_value(json.clone()).unwrap_or_else(|e| panic!("{name}: {e}"));
        let bytes = msg.encode_to_vec();
        let got: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, hex, "{name}: encoding");
        let back = T::decode(bytes.as_slice()).unwrap();
        assert_eq!(&serde_json::to_value(&back).unwrap(), json, "{name}: full form");
    }

    for case in cases {
        let name = case["name"].as_str().unwrap();
        let json = &case["json"];
        let hex = case["protoHex"].as_str().unwrap();
        match case["message"].as_str().unwrap() {
            "avp.HostInfoRequest" => check::<proto::HostInfoRequest>(name, json, hex),
            "avp.HostInfo" => check::<proto::HostInfo>(name, json, hex),
            "avp.ChallengeRequest" => check::<proto::ChallengeRequest>(name, json, hex),
            "avp.AuthChallenge" => check::<proto::AuthChallenge>(name, json, hex),
            "avp.TokenRequest" => check::<proto::TokenRequest>(name, json, hex),
            "avp.AuthToken" => check::<proto::AuthToken>(name, json, hex),
            "avp.CreateRepoRequest" => check::<proto::CreateRepoRequest>(name, json, hex),
            "avp.SignedManifest" => check::<proto::SignedManifest>(name, json, hex),
            "avp.PullRequest" => check::<proto::PullRequest>(name, json, hex),
            "avp.PullResponse" => check::<proto::PullResponse>(name, json, hex),
            "avp.PushRequest" => check::<proto::PushRequest>(name, json, hex),
            "avp.PushResponse" => check::<proto::PushResponse>(name, json, hex),
            "avp.PublishManifestRequest" => check::<proto::PublishManifestRequest>(name, json, hex),
            "avp.LeaveRequest" => check::<proto::LeaveRequest>(name, json, hex),
            "avp.LeaveResponse" => check::<proto::LeaveResponse>(name, json, hex),
            "avp.PrepareJoinRequest" => check::<proto::PrepareJoinRequest>(name, json, hex),
            "avp.Acceptance" => check::<proto::Acceptance>(name, json, hex),
            other => panic!("{name}: no check for {other}"),
        }
    }
}
