//! Micro reference server for the Alt Vault Protocol (AVP), HTTP/JSON profile.
//!
//! It implements the whole wire contract against an in-memory store so an implementer can point a
//! client at something real. It is intentionally tiny and NOT production code: state lives in memory
//! and is lost on restart, there is no TLS, and the bearer token is an opaque random string mapped to
//! a member id in this same process (a real deployment mints a JWT verifiable via JWKS, as the spec
//! describes). What it does honour is the part that matters: it is zero-knowledge. It stores only the
//! manifest, the encrypted envelope, the per-member wrapped keys, public keys, and counters that
//! clients send, and decrypts nothing. The only crypto it performs is verifying the Ed25519 challenge
//! signature. Field shapes follow ../../../schema/avp.schema.json.
//!
//! Run: `cargo run` (listens on 8787, or $PORT).
//!
//! SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use rand::RngCore;
use serde_json::{json, Value};
use tiny_http::{Header, Method, Request, Response, Server};

/// How long an issued authentication challenge nonce stays valid, in milliseconds
/// (2 minutes). After this window a nonce is rejected even if it has not been used.
const NONCE_TTL_MS: u128 = 2 * 60 * 1000;
/// Lifetime advertised for a minted bearer token, in milliseconds (1 hour). This
/// drives only the `expiresAt` value returned to the client; the in-memory token
/// map itself is not expired by this illustrative server.
const TOKEN_TTL_MS: u128 = 60 * 60 * 1000;

// ─── In-memory state ────────────────────────────────────────────────────────

/// A stored repository: the manifest and the current encrypted envelope, both as
/// the opaque JSON the client sent. The server reads only the counters and member
/// ids it needs to authorize; it never inspects the ciphertext.
struct StoredRepo {
    /// The repository manifest as the client sent it: member roster, scheme id, and
    /// the `keyEpoch` / `payloadVersion` counters the server reads for authorization
    /// and optimistic-concurrency checks.
    manifest: Value,
    /// The current encrypted envelope (ciphertext plus its IV and version metadata),
    /// stored verbatim. The server never decrypts or otherwise inspects the ciphertext.
    envelope: Value,
}

/// A pending challenge: the public key it was issued for and when it expires.
struct Challenge {
    /// The base64 Ed25519 public key this challenge was issued for. The signing key
    /// used at token time must match this exactly.
    public_key: String,
    /// Wall-clock expiry in epoch milliseconds (issue time + [`NONCE_TTL_MS`]).
    expires_at: u128,
}

/// All process-local state. A real deployment would not keep tokens or repos here.
#[derive(Default)]
struct State {
    /// repo id -> the manifest and encrypted envelope stored for it
    repos: HashMap<String, StoredRepo>,
    /// outstanding challenge nonce -> the [`Challenge`] (target key + expiry) it stands for
    nonces: HashMap<String, Challenge>,
    /// opaque bearer token -> member id (base64 Ed25519 public key)
    tokens: HashMap<String, String>,
}

/// Drops all state. Exposed so tests start from a clean slate.
#[cfg_attr(not(test), allow(dead_code))]
fn reset_state(state: &Mutex<State>) {
    let mut s = state.lock().unwrap();
    s.repos.clear();
    s.nonces.clear();
    s.tokens.clear();
}

// ─── Time / random helpers ───────────────────────────────────────────────────

/// Returns the current wall-clock time as milliseconds since the Unix epoch.
///
/// Panics if the system clock is set before the Unix epoch, which should not
/// happen on a sane host.
fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis()
}

/// Returns `n` cryptographically random bytes, used for challenge nonces and
/// bearer tokens.
fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

// ─── Crypto: verify an Ed25519 signature over raw bytes (SPEC section 3) ──────

/// Verifies an Ed25519 signature (base64) over the given message bytes against a
/// raw 32-byte Ed25519 public key (base64). Returns false on any decode/verify error.
fn verify_ed25519(public_key_base64: &str, message: &[u8], signature_base64: &str) -> bool {
    let pk_bytes = match STANDARD.decode(public_key_base64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let pk_arr: [u8; 32] = match pk_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let verifying_key = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig_bytes = match STANDARD.decode(signature_base64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_arr: [u8; 64] = match sig_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(&sig_arr);
    verifying_key.verify_strict(message, &signature).is_ok()
}

// ─── Tiny HTTP helpers ────────────────────────────────────────────────────────

/// Sends a JSON response with the given status code and consumes the request.
fn send(req: Request, status: u16, body: &Value) {
    let payload = body.to_string();
    let header =
        Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).expect("static content-type header");
    let response = Response::from_string(payload)
        .with_status_code(status)
        .with_header(header);
    // A failed write to a hung-up client is not fatal for an illustrative server.
    let _ = req.respond(response);
}

/// Reads and parses the request body as JSON. Returns an empty object for an empty body.
fn read_json(req: &mut Request) -> Result<Value, String> {
    let mut raw = String::new();
    req.as_reader().read_to_string(&mut raw).map_err(|e| e.to_string())?;
    if raw.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_str(&raw).map_err(|e| e.to_string())
}

/// Resolves the caller's member id from the `Authorization: Bearer <token>` header,
/// or None if the header is missing or the token is unknown.
fn caller_id(req: &Request, state: &Mutex<State>) -> Option<String> {
    let header = req.headers().iter().find(|h| h.field.equiv("Authorization"))?;
    let value = header.value.as_str();
    let token = value.strip_prefix("Bearer ")?;
    state.lock().unwrap().tokens.get(token).cloned()
}

/// Whether `member_id` (base64 Ed25519 key) appears in the manifest's member roster.
fn is_member(manifest: &Value, member_id: &str) -> bool {
    manifest
        .get("members")
        .and_then(Value::as_array)
        .map(|members| {
            members
                .iter()
                .any(|m| m.get("ed25519PublicKey").and_then(Value::as_str) == Some(member_id))
        })
        .unwrap_or(false)
}

/// Minimal percent-decoding for path segments (handles base64url + standard chars
/// like `+`, `/`, `=` that appear in member ids). Mirrors `decodeURIComponent`.
fn url_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ─── Routing ──────────────────────────────────────────────────────────────────

/// Handles one request end to end and writes its response. Mirrors the TypeScript
/// reference `route`.
///
/// `req` is the inbound request (consumed: a response is sent before returning on
/// every path). `state` is the shared in-memory store, guarded by a [`Mutex`].
///
/// The unauthenticated auth routes (`POST /api/auth/keypair/challenge` and
/// `POST /api/auth/keypair/token`) are matched first. Every other route requires a
/// valid bearer token and answers `401` otherwise: `POST /v1/repos` creates a repo;
/// the `/v1/repos/{repoId}/{pull|push|add-member|remove-member}` actions and
/// `GET /v1/repos/{repoId}/member/{memberId}` operate on an existing repo after a
/// membership check (`404` for an unknown repo, `403` for a non-member). Unmatched
/// requests get `404`. This function never panics on client input; malformed bodies
/// produce a `400`.
fn route(mut req: Request, state: &Mutex<State>) {
    let method = req.method().clone();
    // tiny_http gives the raw request target; strip any query string for path matching.
    let url = req.url().to_string();
    let path = url.split('?').next().unwrap_or("").to_string();

    // ── Auth: challenge -> token ──
    if method == Method::Post && path == "/api/auth/keypair/challenge" {
        let body = match read_json(&mut req) {
            Ok(b) => b,
            Err(detail) => return send(req, 400, &json!({"error": "bad request", "detail": detail})),
        };
        let public_key = body
            .get("ed25519PublicKey")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let nonce = STANDARD.encode(random_bytes(32));
        state.lock().unwrap().nonces.insert(
            nonce.clone(),
            Challenge {
                public_key,
                expires_at: now_ms() + NONCE_TTL_MS,
            },
        );
        return send(req, 200, &json!({ "nonce": nonce }));
    }

    if method == Method::Post && path == "/api/auth/keypair/token" {
        let body = match read_json(&mut req) {
            Ok(b) => b,
            Err(detail) => return send(req, 400, &json!({"error": "bad request", "detail": detail})),
        };
        let ed25519_public_key = body
            .get("ed25519PublicKey")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let nonce = body.get("nonce").and_then(Value::as_str).unwrap_or("").to_string();
        let signature = body.get("signature").and_then(Value::as_str).unwrap_or("").to_string();

        // Consume the nonce single-use, exactly like the TS reference (delete then check).
        let challenge = { state.lock().unwrap().nonces.remove(&nonce) };
        let valid = match challenge {
            Some(c) => c.public_key == ed25519_public_key && c.expires_at >= now_ms(),
            None => false,
        };
        if !valid {
            return send(req, 401, &json!({"error": "invalid or expired nonce"}));
        }
        // Verify the signature over the base64-DECODED nonce bytes.
        let nonce_bytes = match STANDARD.decode(&nonce) {
            Ok(b) => b,
            Err(_) => return send(req, 401, &json!({"error": "bad signature"})),
        };
        if !verify_ed25519(&ed25519_public_key, &nonce_bytes, &signature) {
            return send(req, 401, &json!({"error": "bad signature"}));
        }
        let token = URL_SAFE_NO_PAD.encode(random_bytes(32));
        state.lock().unwrap().tokens.insert(token.clone(), ed25519_public_key);
        return send(
            req,
            200,
            &json!({ "token": token, "expiresAt": (now_ms() + TOKEN_TTL_MS) as u64 }),
        );
    }

    // ── Everything below requires a bearer token ──
    let caller = match caller_id(&req, state) {
        Some(c) => c,
        None => return send(req, 401, &json!({"error": "missing or unknown bearer token"})),
    };

    // createRepo
    if method == Method::Post && path == "/v1/repos" {
        let body = match read_json(&mut req) {
            Ok(b) => b,
            Err(detail) => return send(req, 400, &json!({"error": "bad request", "detail": detail})),
        };
        let manifest = body.get("manifest").cloned().unwrap_or(Value::Null);
        let members = manifest.get("members").and_then(Value::as_array);
        let sole_member_is_caller = matches!(members, Some(m)
            if m.len() == 1
                && m[0].get("ed25519PublicKey").and_then(Value::as_str) == Some(caller.as_str()));
        if !sole_member_is_caller {
            return send(req, 403, &json!({"error": "creator must be the sole member"}));
        }
        let repo_id = match manifest.get("repoId").and_then(Value::as_str) {
            Some(id) => id.to_string(),
            None => return send(req, 400, &json!({"error": "manifest.repoId missing"})),
        };
        let initial_envelope = body.get("initialEnvelope").cloned().unwrap_or(Value::Null);
        let mut s = state.lock().unwrap();
        if s.repos.contains_key(&repo_id) {
            drop(s);
            return send(req, 409, &json!({"error": "repo already exists"}));
        }
        s.repos.insert(
            repo_id,
            StoredRepo {
                manifest: manifest.clone(),
                envelope: initial_envelope,
            },
        );
        drop(s);
        return send(req, 200, &manifest);
    }

    // Routes under /v1/repos/:repoId/...
    let (repo_id_raw, action, member_id_raw) = parse_repo_path(&path);
    let repo_id = repo_id_raw.as_ref().map(|r| url_decode(r));

    if let Some(repo_id) = repo_id {
        let s = state.lock().unwrap();
        // 404 when the repo is unknown.
        if !s.repos.contains_key(&repo_id) {
            drop(s);
            return send(req, 404, &json!({"error": "repo not found"}));
        }
        // 403 when the caller is not a member.
        if !is_member(&s.repos[&repo_id].manifest, &caller) {
            drop(s);
            return send(req, 403, &json!({"error": "caller is not a member"}));
        }

        // We must read the body OUTSIDE the lock (read_json borrows req mutably while the
        // closures above borrow it immutably). Release the lock, read, re-acquire.
        match (method.clone(), action.as_deref(), member_id_raw.as_ref()) {
            (Method::Post, Some("pull"), _) => {
                drop(s);
                let body = match read_json(&mut req) {
                    Ok(b) => b,
                    Err(d) => return send(req, 400, &json!({"error": "bad request", "detail": d})),
                };
                let s = state.lock().unwrap();
                let repo = &s.repos[&repo_id];
                let current = repo.manifest.get("payloadVersion").cloned().unwrap_or(Value::Null);
                let known = body.get("knownPayloadVersion").cloned().unwrap_or(Value::Null);
                let response = if known == current {
                    json!({ "manifest": repo.manifest, "envelope": Value::Null, "unchanged": true })
                } else {
                    json!({ "manifest": repo.manifest, "envelope": repo.envelope, "unchanged": false })
                };
                drop(s);
                send(req, 200, &response);
            }
            (Method::Post, Some("push"), _) => {
                drop(s);
                let body = match read_json(&mut req) {
                    Ok(b) => b,
                    Err(d) => return send(req, 400, &json!({"error": "bad request", "detail": d})),
                };
                let mut s = state.lock().unwrap();
                let repo = s.repos.get_mut(&repo_id).expect("repo presence checked");
                let current = repo.manifest.get("payloadVersion").cloned().unwrap_or(Value::Null);
                let expected = body.get("expectedPayloadVersion").cloned().unwrap_or(Value::Null);
                if expected != current {
                    let response = json!({
                        "accepted": false,
                        "conflict": true,
                        "payloadVersion": repo.manifest.get("payloadVersion").cloned().unwrap_or(Value::Null),
                        "keyEpoch": repo.manifest.get("keyEpoch").cloned().unwrap_or(Value::Null),
                    });
                    drop(s);
                    return send(req, 200, &response);
                }
                let envelope = body.get("envelope").cloned().unwrap_or(Value::Null);
                let new_version = envelope.get("payloadVersion").cloned().unwrap_or(Value::Null);
                let new_epoch = envelope.get("keyEpoch").cloned().unwrap_or(Value::Null);
                repo.envelope = envelope;
                repo.manifest["payloadVersion"] = new_version.clone();
                repo.manifest["keyEpoch"] = new_epoch.clone();
                if let Some(rotated) = body.get("rotatedMembers") {
                    if rotated.is_array() {
                        repo.manifest["members"] = rotated.clone();
                    }
                }
                let response = json!({
                    "accepted": true,
                    "conflict": false,
                    "payloadVersion": new_version,
                    "keyEpoch": new_epoch,
                });
                drop(s);
                send(req, 200, &response);
            }
            (Method::Post, Some("add-member"), _) => {
                drop(s);
                let body = match read_json(&mut req) {
                    Ok(b) => b,
                    Err(d) => return send(req, 400, &json!({"error": "bad request", "detail": d})),
                };
                let mut s = state.lock().unwrap();
                let repo = s.repos.get_mut(&repo_id).expect("repo presence checked");
                let member = body.get("member").cloned().unwrap_or(Value::Null);
                let member_id = member.get("ed25519PublicKey").and_then(Value::as_str);
                let already_present = match member_id {
                    Some(id) => is_member(&repo.manifest, id),
                    None => false,
                };
                if !already_present {
                    if let Some(members) = repo.manifest.get_mut("members").and_then(Value::as_array_mut) {
                        members.push(member);
                    }
                }
                let manifest = repo.manifest.clone();
                drop(s);
                send(req, 200, &manifest);
            }
            (Method::Post, Some("remove-member"), _) => {
                drop(s);
                let body = match read_json(&mut req) {
                    Ok(b) => b,
                    Err(d) => return send(req, 400, &json!({"error": "bad request", "detail": d})),
                };
                let mut s = state.lock().unwrap();
                let repo = s.repos.get_mut(&repo_id).expect("repo presence checked");
                let rewrapped = body.get("rewrappedMembers").cloned().unwrap_or(json!([]));
                let rotated_envelope = body.get("rotatedEnvelope").cloned().unwrap_or(Value::Null);
                let new_key_epoch = body.get("newKeyEpoch").cloned().unwrap_or(Value::Null);
                let new_version = rotated_envelope.get("payloadVersion").cloned().unwrap_or(Value::Null);
                repo.manifest["members"] = rewrapped;
                repo.envelope = rotated_envelope;
                repo.manifest["keyEpoch"] = new_key_epoch;
                repo.manifest["payloadVersion"] = new_version;
                let manifest = repo.manifest.clone();
                drop(s);
                send(req, 200, &manifest);
            }
            (Method::Get, None, Some(member_id_raw)) => {
                let member_id = url_decode(member_id_raw);
                let entry = s.repos[&repo_id]
                    .manifest
                    .get("members")
                    .and_then(Value::as_array)
                    .and_then(|members| {
                        members
                            .iter()
                            .find(|m| m.get("ed25519PublicKey").and_then(Value::as_str) == Some(member_id.as_str()))
                    })
                    .cloned();
                drop(s);
                match entry {
                    Some(e) => send(req, 200, &e),
                    None => send(req, 404, &json!({"error": "member not found"})),
                }
            }
            _ => {
                drop(s);
                send(req, 404, &json!({"error": "no such route"}));
            }
        }
        return;
    }

    send(req, 404, &json!({"error": "no such route"}));
}

/// Parses `/v1/repos/{repoId}/{pull|push|add-member|remove-member}` or
/// `/v1/repos/{repoId}/member/{memberId}`. Returns the raw (still URL-encoded)
/// repoId, an action verb (for the first form), and the raw memberId (for the second).
fn parse_repo_path(path: &str) -> (Option<String>, Option<String>, Option<String>) {
    let rest = match path.strip_prefix("/v1/repos/") {
        Some(r) => r,
        None => return (None, None, None),
    };
    let segments: Vec<&str> = rest.split('/').collect();
    match segments.as_slice() {
        [repo_id, action @ ("pull" | "push" | "add-member" | "remove-member")] => {
            (Some((*repo_id).to_string()), Some((*action).to_string()), None)
        }
        [repo_id, "member", member_id] => (Some((*repo_id).to_string()), None, Some((*member_id).to_string())),
        _ => (None, None, None),
    }
}

// ─── Entry point ────────────────────────────────────────────────────────────

/// Binds the HTTP server and serves requests sequentially until the process is killed.
///
/// Listens on `0.0.0.0:$PORT`, defaulting to port 8787 when `PORT` is unset or
/// unparseable. Panics if the address cannot be bound (for example, the port is
/// already in use). Each request is dispatched to [`route`] against a single shared
/// [`State`]; requests are handled one at a time on the main thread.
fn main() {
    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8787);
    let addr = format!("0.0.0.0:{port}");
    let server = Server::http(&addr).unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));
    let state: Mutex<State> = Mutex::new(State::default());
    println!("AVP reference server (in-memory) listening on http://localhost:{port}");
    for request in server.incoming_requests() {
        route(request, &state);
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::{Signer, SigningKey};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::thread;

    /// A parsed HTTP reply: the status code and the decoded JSON body.
    struct Reply {
        status: u16,
        json: Value,
    }

    /// A running test server: the ephemeral port it listens on and a handle to its
    /// shared state so a test can reset it between cases.
    struct Harness {
        port: u16,
        state: Arc<Mutex<State>>,
    }

    /// Boots the server on an ephemeral port in a background thread and returns a
    /// harness for driving raw HTTP/1.1 requests against it.
    fn boot() -> Harness {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().unwrap().port();
        let server = Server::from_listener(listener, None).expect("server from listener");
        let state: Arc<Mutex<State>> = Arc::new(Mutex::new(State::default()));
        let server_state = Arc::clone(&state);
        thread::spawn(move || {
            for request in server.incoming_requests() {
                route(request, &server_state);
            }
        });
        Harness { port, state }
    }

    /// Sends one HTTP request and parses the JSON reply. Minimal HTTP/1.1 client:
    /// the reference server always sets Content-Length, so we read to EOF after close.
    fn request(port: u16, method: &str, path: &str, token: Option<&str>, body: Option<&Value>) -> Reply {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let body_str = body.map(|b| b.to_string()).unwrap_or_default();
        let mut head = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
            body_str.len()
        );
        if let Some(t) = token {
            head.push_str(&format!("Authorization: Bearer {t}\r\n"));
        }
        head.push_str("\r\n");
        stream.write_all(head.as_bytes()).unwrap();
        stream.write_all(body_str.as_bytes()).unwrap();
        stream.flush().unwrap();

        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).unwrap();
        let text = String::from_utf8_lossy(&raw);
        let (head_part, body_part) = text.split_once("\r\n\r\n").expect("response has a header/body split");
        let status: u16 = head_part
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .expect("status line");
        let json = if body_part.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(body_part).expect("body is json")
        };
        Reply { status, json }
    }

    /// Convenience wrapper: issues a POST with a JSON body and an optional bearer token.
    fn post(port: u16, path: &str, body: &Value, token: Option<&str>) -> Reply {
        request(port, "POST", path, token, Some(body))
    }

    /// Convenience wrapper: issues a GET with a bearer token and no body.
    fn get(port: u16, path: &str, token: &str) -> Reply {
        request(port, "GET", path, Some(token), None)
    }

    /// An Ed25519 key pair for a test member: the base64 public key (used as the
    /// member id) alongside the signing key used to answer challenges.
    struct KeyPair {
        pub_b64: String,
        signing: SigningKey,
    }

    /// Generates a fresh random [`KeyPair`].
    fn keypair() -> KeyPair {
        // Build a signing key from 32 random bytes (avoids depending on the dalek
        // `rand_core` feature; any 32 bytes are a valid Ed25519 secret scalar seed).
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let signing = SigningKey::from_bytes(&seed);
        let pub_b64 = STANDARD.encode(signing.verifying_key().to_bytes());
        KeyPair { pub_b64, signing }
    }

    /// Runs the keypair challenge -> token flow and returns a bearer token.
    fn authenticate(port: u16, kp: &KeyPair) -> String {
        let challenge = post(
            port,
            "/api/auth/keypair/challenge",
            &json!({ "ed25519PublicKey": kp.pub_b64 }),
            None,
        );
        let nonce = challenge.json["nonce"].as_str().unwrap().to_string();
        let nonce_bytes = STANDARD.decode(&nonce).unwrap();
        let signature = STANDARD.encode(kp.signing.sign(&nonce_bytes).to_bytes());
        let token = post(
            port,
            "/api/auth/keypair/token",
            &json!({ "ed25519PublicKey": kp.pub_b64, "nonce": nonce, "signature": signature }),
            None,
        );
        token.json["token"].as_str().unwrap().to_string()
    }

    /// Builds a manifest member entry for `pub_b64` at the given key `epoch`, with a
    /// placeholder wrapped data key. The wrapped-key contents are opaque to the server.
    fn entry(pub_b64: &str, epoch: i64) -> Value {
        json!({
            "ed25519PublicKey": pub_b64,
            "x25519PublicKey": format!("x-{}", &pub_b64[..pub_b64.len().min(6)]),
            "wrappedDataKey": {
                "schemeId": "X25519-HKDF-SHA256-AESGCM-v1",
                "ephemeralPublicKey": "eph",
                "iv": "iv",
                "ciphertext": "wk"
            },
            "keyEpoch": epoch,
        })
    }

    /// Builds an encrypted-envelope value for `repo_id` at the given payload `version`
    /// and key `epoch`, with a placeholder ciphertext tagged by version.
    fn envelope(repo_id: &str, version: i64, epoch: i64) -> Value {
        json!({
            "repoId": repo_id,
            "payloadVersion": version,
            "keyEpoch": epoch,
            "iv": "iv",
            "ciphertext": format!("ct-{version}"),
        })
    }

    /// A vault route called without a bearer token is rejected with `401`.
    #[test]
    fn rejects_an_unauthenticated_vault_call() {
        let h = boot();
        reset_state(&h.state);
        let res = post(h.port, "/v1/repos", &json!({}), None);
        assert_eq!(res.status, 401);
    }

    /// Token issuance fails with `401` when the challenge signature does not verify.
    #[test]
    fn rejects_a_bad_challenge_signature() {
        let h = boot();
        reset_state(&h.state);
        let kp = keypair();
        let challenge = post(
            h.port,
            "/api/auth/keypair/challenge",
            &json!({ "ed25519PublicKey": kp.pub_b64 }),
            None,
        );
        let nonce = challenge.json["nonce"].as_str().unwrap().to_string();
        // Sign the WRONG message with a DIFFERENT key.
        let wrong_kp = keypair();
        let wrong = STANDARD.encode(wrong_kp.signing.sign(b"not the nonce").to_bytes());
        let token = post(
            h.port,
            "/api/auth/keypair/token",
            &json!({ "ed25519PublicKey": kp.pub_b64, "nonce": nonce, "signature": wrong }),
            None,
        );
        assert_eq!(token.status, 401);
    }

    /// Exercises the full repo lifecycle: create, pull (unchanged vs. behind), push
    /// (success vs. version conflict), add a member, fetch that member's key by id,
    /// then remove the member with a key rotation.
    #[test]
    fn full_lifecycle_create_pull_push_add_fetch_remove() {
        let h = boot();
        reset_state(&h.state);
        let alice = keypair();
        let alice_token = authenticate(h.port, &alice);
        let repo_id = "repo-lifecycle";

        let created = post(
            h.port,
            "/v1/repos",
            &json!({
                "manifest": {
                    "repoId": repo_id,
                    "schemeId": "scheme-v1",
                    "keyEpoch": 0,
                    "payloadVersion": 1,
                    "members": [entry(&alice.pub_b64, 0)]
                },
                "initialEnvelope": envelope(repo_id, 1, 0),
            }),
            Some(&alice_token),
        );
        assert_eq!(created.status, 200);
        assert_eq!(created.json["members"].as_array().unwrap().len(), 1);

        // pull at the current version => unchanged; at an older version => the envelope.
        let fresh = post(
            h.port,
            &format!("/v1/repos/{repo_id}/pull"),
            &json!({ "repoId": repo_id, "knownPayloadVersion": 1 }),
            Some(&alice_token),
        );
        assert_eq!(fresh.json["unchanged"], json!(true));
        assert_eq!(fresh.json["envelope"], Value::Null);

        let behind = post(
            h.port,
            &format!("/v1/repos/{repo_id}/pull"),
            &json!({ "repoId": repo_id, "knownPayloadVersion": 0 }),
            Some(&alice_token),
        );
        assert_eq!(behind.json["unchanged"], json!(false));
        assert_eq!(behind.json["envelope"]["ciphertext"], json!("ct-1"));

        // push with the right base version succeeds; a stale base version conflicts.
        let pushed = post(
            h.port,
            &format!("/v1/repos/{repo_id}/push"),
            &json!({ "repoId": repo_id, "envelope": envelope(repo_id, 2, 0), "expectedPayloadVersion": 1 }),
            Some(&alice_token),
        );
        assert_eq!(pushed.json["accepted"], json!(true));
        assert_eq!(pushed.json["payloadVersion"], json!(2));

        let stale = post(
            h.port,
            &format!("/v1/repos/{repo_id}/push"),
            &json!({ "repoId": repo_id, "envelope": envelope(repo_id, 2, 0), "expectedPayloadVersion": 1 }),
            Some(&alice_token),
        );
        assert_eq!(stale.json["conflict"], json!(true));
        assert_eq!(stale.json["accepted"], json!(false));

        // add a member, then fetch their key back (member id is base64 with + / =).
        let bob = keypair();
        let added = post(
            h.port,
            &format!("/v1/repos/{repo_id}/add-member"),
            &json!({ "repoId": repo_id, "member": entry(&bob.pub_b64, 0) }),
            Some(&alice_token),
        );
        assert_eq!(added.json["members"].as_array().unwrap().len(), 2);

        let encoded_id = url_encode_component(&bob.pub_b64);
        let fetched = get(
            h.port,
            &format!("/v1/repos/{repo_id}/member/{encoded_id}"),
            &alice_token,
        );
        assert_eq!(fetched.status, 200);
        assert_eq!(fetched.json["ed25519PublicKey"], json!(bob.pub_b64));

        // remove bob: rotate to {alice} at a new epoch and a bumped version.
        let removed = post(
            h.port,
            &format!("/v1/repos/{repo_id}/remove-member"),
            &json!({
                "repoId": repo_id,
                "removedMemberId": bob.pub_b64,
                "rotatedEnvelope": envelope(repo_id, 3, 1),
                "rewrappedMembers": [entry(&alice.pub_b64, 1)],
                "newKeyEpoch": 1,
            }),
            Some(&alice_token),
        );
        assert_eq!(removed.json["members"].as_array().unwrap().len(), 1);
        assert_eq!(removed.json["keyEpoch"], json!(1));
        assert_eq!(removed.json["payloadVersion"], json!(3));
    }

    /// An authenticated caller who is not on a repo's roster is denied with `403`.
    #[test]
    fn a_non_member_cannot_read_a_repo() {
        let h = boot();
        reset_state(&h.state);
        let alice = keypair();
        let alice_token = authenticate(h.port, &alice);
        let repo_id = "repo-private";
        post(
            h.port,
            "/v1/repos",
            &json!({
                "manifest": {
                    "repoId": repo_id, "schemeId": "s", "keyEpoch": 0, "payloadVersion": 1,
                    "members": [entry(&alice.pub_b64, 0)]
                },
                "initialEnvelope": envelope(repo_id, 1, 0),
            }),
            Some(&alice_token),
        );

        let mallory = keypair();
        let mallory_token = authenticate(h.port, &mallory);
        let res = post(
            h.port,
            &format!("/v1/repos/{repo_id}/pull"),
            &json!({ "repoId": repo_id, "knownPayloadVersion": 0 }),
            Some(&mallory_token),
        );
        assert_eq!(res.status, 403);
    }

    /// Operating on a repo id that was never created returns `404`.
    #[test]
    fn unknown_repo_is_404() {
        let h = boot();
        reset_state(&h.state);
        let alice = keypair();
        let alice_token = authenticate(h.port, &alice);
        let res = post(
            h.port,
            "/v1/repos/does-not-exist/pull",
            &json!({ "repoId": "does-not-exist", "knownPayloadVersion": 0 }),
            Some(&alice_token),
        );
        assert_eq!(res.status, 404);
    }

    /// Creating a repo whose id already exists returns `409`.
    #[test]
    fn duplicate_repo_is_409() {
        let h = boot();
        reset_state(&h.state);
        let alice = keypair();
        let alice_token = authenticate(h.port, &alice);
        let repo_id = "repo-dup";
        let body = json!({
            "manifest": {
                "repoId": repo_id, "schemeId": "s", "keyEpoch": 0, "payloadVersion": 1,
                "members": [entry(&alice.pub_b64, 0)]
            },
            "initialEnvelope": envelope(repo_id, 1, 0),
        });
        let first = post(h.port, "/v1/repos", &body, Some(&alice_token));
        assert_eq!(first.status, 200);
        let second = post(h.port, "/v1/repos", &body, Some(&alice_token));
        assert_eq!(second.status, 409);
    }

    /// Percent-encodes the base64 chars (`+`, `/`, `=`) a member id can contain, so the
    /// test exercises the server's URL-decoding path the way `encodeURIComponent` does.
    fn url_encode_component(input: &str) -> String {
        let mut out = String::new();
        for b in input.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }
}
