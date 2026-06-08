//! Micro reference client for the Alt Vault Protocol (AVP), HTTP/JSON profile.
//!
//! It drives the whole wire contract against a running server (the sibling `../server`, or any other
//! conformant HTTP/JSON server) so an implementer can see the full lifecycle end to end: generate
//! Ed25519 and X25519 keypairs, run the challenge -> sign -> token auth flow, create a repo with a real
//! encrypted payload, pull, push a new version, invite a second member, fetch that member's key, and
//! finally have the second member pull, unwrap the data key, and decrypt the payload.
//!
//! Unlike the other placeholder reference clients, the envelope and wrapped-key cryptography here is
//! REAL (SPEC sections 4-5): alice derives a per-repo data key, AES-256-GCM-encrypts the alt payload
//! (binding repoId/payloadVersion/keyEpoch into the AAD), and wraps the data key to each member's
//! X25519 key. The server stays zero-knowledge throughout; at the end bob recovers exactly what alice
//! stored. The constructions are verified byte-for-byte against the conformance vectors in
//! `vectors/*.json` by the `crypto` module's tests.
//!
//! Run: `cargo run` (talks to http://localhost:8787 by default). Point it at a server with the
//! `AVP_SERVER_URL` environment variable.
//!
//! SPDX-License-Identifier: MIT

mod crypto;

use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use serde_json::{json, Value};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// Read timeout applied to every HTTP call, so a hung server fails the transcript loudly rather than
/// blocking forever.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

// ─── Identity ─────────────────────────────────────────────────────────────────

/// A member identity: an Ed25519 signing keypair plus a real X25519 keypair for data-key wrapping.
///
/// The raw 32-byte Ed25519 public key, base64-encoded, is the member id (SPEC section 2). The X25519
/// private key is stored so this member can unwrap data keys wrapped to its public key.
struct Identity {
    /// Base64 raw 32-byte Ed25519 public key; this is the member id.
    ed25519_public_key: String,
    /// Base64 raw 32-byte X25519 public key.
    x25519_public_key: String,
    /// The Ed25519 signing key, used to sign auth challenge nonces.
    signing_key: SigningKey,
    /// The X25519 private key, used to unwrap data keys.
    x25519_private_key: StaticSecret,
}

/// Generates a fresh identity: an Ed25519 keypair and a real X25519 keypair.
///
/// Building the [`SigningKey`] directly from random bytes avoids depending on the dalek `rand_core`
/// feature; any 32 bytes are a valid Ed25519 secret-scalar seed.
fn generate_identity() -> Identity {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let ed25519_public_key = STANDARD.encode(signing_key.verifying_key().to_bytes());

    let x25519_private_key = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let x25519_pub = X25519PublicKey::from(&x25519_private_key);
    let x25519_public_key = STANDARD.encode(x25519_pub.as_bytes());

    Identity {
        ed25519_public_key,
        x25519_public_key,
        signing_key,
        x25519_private_key,
    }
}

// ─── HTTP helper ──────────────────────────────────────────────────────────────

/// Returns the base server URL from `AVP_SERVER_URL` (default `http://localhost:8787`), with any
/// trailing slash trimmed so paths can be appended directly.
fn base_url() -> String {
    let raw = std::env::var("AVP_SERVER_URL").unwrap_or_else(|_| "http://localhost:8787".to_string());
    raw.trim_end_matches('/').to_string()
}

/// Sends a JSON request to the server and parses the JSON response, returning an error on any non-2xx
/// status so the transcript fails loudly rather than silently mis-stepping.
fn call(base: &str, method: &str, path: &str, body: Option<&Value>, token: Option<&str>) -> Result<Value, String> {
    let url = format!("{base}{path}");
    let mut req = ureq::request(method, &url)
        .timeout(HTTP_TIMEOUT)
        .set("Content-Type", "application/json");
    if let Some(t) = token {
        req = req.set("Authorization", &format!("Bearer {t}"));
    }
    let result = match body {
        Some(b) => req.send_string(&b.to_string()),
        None => req.call(),
    };
    let response = match result {
        Ok(r) => r,
        Err(ureq::Error::Status(code, r)) => {
            let text = r.into_string().unwrap_or_default();
            return Err(format!("{method} {path} -> {code}: {text}"));
        }
        Err(ureq::Error::Transport(t)) => {
            return Err(format!("{method} {path} -> transport error: {t}"));
        }
    };
    let text = response
        .into_string()
        .map_err(|e| format!("{method} {path} -> body read error: {e}"))?;
    if text.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(&text).map_err(|e| format!("{method} {path} -> bad json: {e}"))
}

// ─── Auth flow: challenge -> sign nonce -> token (SPEC section 3) ──────────────

/// Runs the keypair challenge flow and returns a bearer token for this identity.
///
/// The client signs the RAW nonce bytes (the bytes obtained by base64-decoding the `nonce`), not the
/// base64 text — this is the part conformant servers verify.
fn authenticate(base: &str, identity: &Identity) -> Result<String, String> {
    let challenge = call(
        base,
        "POST",
        "/api/auth/keypair/challenge",
        Some(&json!({ "ed25519PublicKey": identity.ed25519_public_key })),
        None,
    )?;
    let nonce = challenge
        .get("nonce")
        .and_then(Value::as_str)
        .ok_or_else(|| "challenge response missing string `nonce`".to_string())?;
    let nonce_bytes = STANDARD
        .decode(nonce)
        .map_err(|e| format!("nonce is not valid base64: {e}"))?;
    let signature = STANDARD.encode(identity.signing_key.sign(&nonce_bytes).to_bytes());
    let auth = call(
        base,
        "POST",
        "/api/auth/keypair/token",
        Some(&json!({
            "ed25519PublicKey": identity.ed25519_public_key,
            "nonce": nonce,
            "signature": signature,
        })),
        None,
    )?;
    auth.get("token")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "token response missing string `token`".to_string())
}

// ─── Member entry ─────────────────────────────────────────────────────────────

/// Assembles a `MemberEntry`-shaped [`Value`] from an identity at a given key epoch, wrapping the
/// repo data key to the member's real X25519 public key.
fn member_entry(identity: &Identity, data_key: &[u8], key_epoch: i64) -> Value {
    let wrapped_data_key = crypto::wrap_data_key(&identity.x25519_public_key, data_key);
    json!({
        "ed25519PublicKey": identity.ed25519_public_key,
        "x25519PublicKey": identity.x25519_public_key,
        "wrappedDataKey": wrapped_data_key,
        "keyEpoch": key_epoch,
        "keyBindingSig": Value::Null,
    })
}

// ─── Misc helpers ─────────────────────────────────────────────────────────────

/// Returns a random version-4 UUID string for use as an opaque repoId.
fn random_uuid() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32],
    )
}

/// Percent-encodes a string for use as a single URL path segment (RFC 3986 unreserved set only).
fn encode_uri_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Returns a short, transcript-friendly prefix of a base64 value followed by an ellipsis.
fn short(value: &str) -> String {
    let prefix: String = value.chars().take(12).collect();
    format!("{prefix}...")
}

/// Renders a pull response's `envelope` field as the transcript word `present` or `null`.
fn envelope_state(pull_response: &Value) -> &'static str {
    match pull_response.get("envelope") {
        Some(v) if !v.is_null() => "present",
        _ => "null",
    }
}

/// Prints one transcript line with a padded step label so the output columns line up.
fn step(label: &str, detail: &str) {
    println!("  {label:<16} {detail}");
}

/// Encrypts an alt payload list as a JSON object and returns an `EncryptedEnvelope`-shaped Value.
fn encrypt_alts(
    data_key: &[u8],
    repo_id: &str,
    payload_version: i64,
    key_epoch: i64,
    alts: &Value,
) -> Value {
    let payload = json!({
        "alts": alts,
        "payloadVersion": payload_version,
    });
    let plaintext = payload.to_string();
    crypto::encrypt_payload(data_key, repo_id, payload_version, key_epoch, plaintext.as_bytes())
}

// ─── Lifecycle ─────────────────────────────────────────────────────────────────

/// Drives the full AVP lifecycle end to end against a running server and prints a transcript.
fn run(base: &str) -> Result<(), String> {
    println!("AVP reference client -> {base}");
    println!("(Envelope and wrapped-key crypto is real; the server stays zero-knowledge.)\n");

    // Two members, generated locally. alice creates the repo; bob joins later.
    let alice = generate_identity();
    let bob = generate_identity();
    step(
        "members",
        &format!(
            "alice={} bob={}",
            short(&alice.ed25519_public_key),
            short(&bob.ed25519_public_key)
        ),
    );

    // 1. Authenticate alice (challenge -> sign nonce -> token).
    let alice_token = authenticate(base, &alice)?;
    step("auth", &format!("alice token={}", short(&alice_token)));

    // 2. alice mints a per-repo data key and encrypts a real initial payload (v1, epoch 0).
    let mut data_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut data_key);
    let repo_id = random_uuid();

    let alts_v1 = json!([
        {
            "uuid": "11111111-1111-4111-8111-111111111111",
            "username": "alice_main",
            "accessToken": "secret-v1",
            "type": "MICROSOFT",
            "lastUsed": 1
        }
    ]);
    let initial_envelope = encrypt_alts(&data_key, &repo_id, 1, 0, &alts_v1);
    let alice_member = member_entry(&alice, &data_key, 0);

    // 3. createRepo — alice must be the sole member of the manifest she creates.
    let created = call(
        base,
        "POST",
        "/v1/repos",
        Some(&json!({
            "manifest": {
                "repoId": repo_id,
                "schemeId": crypto::SCHEME_ID,
                "keyEpoch": 0,
                "payloadVersion": 1,
                "members": [alice_member],
            },
            "initialEnvelope": initial_envelope,
        })),
        Some(&alice_token),
    )?;
    let created_version = created.get("payloadVersion").and_then(Value::as_i64).unwrap_or(0);
    let created_members = created.get("members").and_then(Value::as_array).map_or(0, Vec::len);
    let created_repo_id = created.get("repoId").and_then(Value::as_str).unwrap_or(&repo_id);
    step(
        "createRepo",
        &format!("repoId={created_repo_id} members={created_members} v={created_version}"),
    );

    let pull_path = format!("/v1/repos/{}/pull", encode_uri_component(&repo_id));

    // 4. pull at the version we already know — server reports unchanged and omits the envelope.
    let pull_same = call(
        base,
        "POST",
        &pull_path,
        Some(&json!({ "repoId": repo_id, "knownPayloadVersion": created_version })),
        Some(&alice_token),
    )?;
    step(
        "pull (known)",
        &format!(
            "unchanged={} envelope={}",
            pull_same.get("unchanged").and_then(Value::as_bool).unwrap_or(false),
            envelope_state(&pull_same),
        ),
    );

    // 5. pull from version 0 — server returns the current envelope.
    let pull_fresh = call(
        base,
        "POST",
        &pull_path,
        Some(&json!({ "repoId": repo_id, "knownPayloadVersion": 0 })),
        Some(&alice_token),
    )?;
    step(
        "pull (stale)",
        &format!(
            "unchanged={} envelope={}",
            pull_fresh.get("unchanged").and_then(Value::as_bool).unwrap_or(false),
            envelope_state(&pull_fresh),
        ),
    );

    let push_path = format!("/v1/repos/{}/push", encode_uri_component(&repo_id));
    let next_version = created_version + 1;

    // 6. push a real v2 payload with optimistic concurrency on the current version.
    let alts_v2 = json!([
        {
            "uuid": "11111111-1111-4111-8111-111111111111",
            "username": "alice_main",
            "accessToken": "secret-v1",
            "type": "MICROSOFT",
            "lastUsed": 1
        },
        {
            "uuid": "22222222-2222-4222-8222-222222222222",
            "username": "alice_alt",
            "accessToken": "secret-v2",
            "type": "MICROSOFT",
            "lastUsed": 2
        }
    ]);
    let env_v2 = encrypt_alts(&data_key, &repo_id, next_version, 0, &alts_v2);
    let push_result = call(
        base,
        "POST",
        &push_path,
        Some(&json!({
            "repoId": repo_id,
            "envelope": env_v2,
            "expectedPayloadVersion": created_version,
        })),
        Some(&alice_token),
    )?;
    step(
        "push",
        &format!(
            "accepted={} conflict={} v={}",
            push_result.get("accepted").and_then(Value::as_bool).unwrap_or(false),
            push_result.get("conflict").and_then(Value::as_bool).unwrap_or(false),
            push_result.get("payloadVersion").and_then(Value::as_i64).unwrap_or(0),
        ),
    );

    // 7. demonstrate the conflict path: pushing again at the now-stale expected version is rejected.
    let conflict = call(
        base,
        "POST",
        &push_path,
        Some(&json!({
            "repoId": repo_id,
            "envelope": encrypt_alts(&data_key, &repo_id, next_version + 1, 0, &alts_v2),
            "expectedPayloadVersion": created_version, // stale on purpose
        })),
        Some(&alice_token),
    )?;
    step(
        "push (stale)",
        &format!(
            "accepted={} conflict={} serverV={}",
            conflict.get("accepted").and_then(Value::as_bool).unwrap_or(false),
            conflict.get("conflict").and_then(Value::as_bool).unwrap_or(false),
            conflict.get("payloadVersion").and_then(Value::as_i64).unwrap_or(0),
        ),
    );

    // 8. addMember — alice wraps the data key to bob's X25519 key and records his entry.
    let bob_member = member_entry(&bob, &data_key, 0);
    let with_bob = call(
        base,
        "POST",
        &format!("/v1/repos/{}/add-member", encode_uri_component(&repo_id)),
        Some(&json!({ "repoId": repo_id, "member": bob_member })),
        Some(&alice_token),
    )?;
    let with_bob_members = with_bob.get("members").and_then(Value::as_array).map_or(0, Vec::len);
    step("addMember", &format!("members={with_bob_members} (added bob)"));

    // 9. fetchMemberKey — look up bob's stored entry by member id (URL-encoded).
    let bob_entry = call(
        base,
        "GET",
        &format!(
            "/v1/repos/{}/member/{}",
            encode_uri_component(&repo_id),
            encode_uri_component(&bob.ed25519_public_key),
        ),
        None,
        Some(&alice_token),
    )?;
    step(
        "fetchMemberKey",
        &format!(
            "bob x25519={} epoch={}",
            short(bob_entry.get("x25519PublicKey").and_then(Value::as_str).unwrap_or("")),
            bob_entry.get("keyEpoch").and_then(Value::as_i64).unwrap_or(0),
        ),
    );

    // 10. bob authenticates, pulls, unwraps the data key, and decrypts the payload.
    let bob_token = authenticate(base, &bob)?;
    let bob_pull = call(
        base,
        "POST",
        &pull_path,
        Some(&json!({ "repoId": repo_id, "knownPayloadVersion": 0 })),
        Some(&bob_token),
    )?;

    let bob_manifest_version = bob_pull
        .get("manifest")
        .and_then(|m| m.get("payloadVersion"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let bob_manifest_members = bob_pull
        .get("manifest")
        .and_then(|m| m.get("members"))
        .and_then(Value::as_array)
        .map_or(0, Vec::len);

    // Find bob's member entry in the manifest to unwrap his copy of the data key.
    let bob_wrapped_key = bob_pull
        .get("manifest")
        .and_then(|m| m.get("members"))
        .and_then(Value::as_array)
        .and_then(|members| {
            members
                .iter()
                .find(|m| m.get("ed25519PublicKey").and_then(Value::as_str) == Some(&bob.ed25519_public_key))
        })
        .and_then(|m| m.get("wrappedDataKey"))
        .cloned()
        .ok_or_else(|| "bob is not in the pulled roster".to_string())?;

    let bob_data_key = crypto::unwrap_data_key(&bob.x25519_private_key, &bob_wrapped_key)
        .map_err(|e| format!("bob unwrap: {e}"))?;

    let envelope = bob_pull
        .get("envelope")
        .filter(|v| !v.is_null())
        .ok_or_else(|| "bob's pull returned no envelope".to_string())?;

    let plaintext_bytes = crypto::decrypt_payload(&bob_data_key, envelope)
        .map_err(|e| format!("bob decrypt: {e}"))?;

    let payload: serde_json::Value =
        serde_json::from_slice(&plaintext_bytes).map_err(|e| format!("bob parse payload: {e}"))?;

    let alts = payload.get("alts").and_then(Value::as_array).cloned().unwrap_or_default();
    step(
        "bob pull",
        &format!(
            "members={bob_manifest_members} v={bob_manifest_version} alts={} (decrypted)",
            alts.len(),
        ),
    );
    for alt in &alts {
        let username = alt.get("username").and_then(Value::as_str).unwrap_or("?");
        let uuid = alt.get("uuid").and_then(Value::as_str).unwrap_or("?");
        step("  alt", &format!("{username} ({uuid})"));
    }

    println!("\nDone. Full lifecycle exercised against a zero-knowledge server; bob decrypted alice's payload.");
    Ok(())
}

/// Resolves the target server URL, drives the lifecycle, and maps any failure to a non-zero exit code.
fn main() {
    let base = base_url();
    if let Err(err) = run(&base) {
        eprintln!("\nClient failed: {err}");
        eprintln!("Is a server running? Start one with `cargo run` in ../server, or set AVP_SERVER_URL.");
        std::process::exit(1);
    }
}
