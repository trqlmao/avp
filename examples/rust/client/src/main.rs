//! Micro reference client for the Alt Vault Protocol (AVP), HTTP/JSON profile.
//!
//! It drives the whole wire contract against a running server (the sibling `../server`, or any other
//! conformant HTTP/JSON server) so an implementer can see the full lifecycle end to end: generate an
//! Ed25519 keypair, run the challenge -> sign -> token auth flow, create a repo, pull, push a new
//! version, invite a second member, fetch that member's key, and print a transcript. It is a sibling of
//! the [TypeScript reference client](../../../typescript/client/) and behaves identically.
//!
//! It is intentionally tiny and NOT production code. Crucially, the envelope and wrapped-key crypto is
//! OUT OF SCOPE here: this client carries the alt payload as an opaque placeholder ciphertext and never
//! actually encrypts anything. A real client derives a per-repo data key, AES-256-GCM encrypts the alt
//! payload (binding repoId/payloadVersion/keyEpoch into the AAD), and wraps the data key to each
//! member's X25519 key. See SPEC sections 4-5 and the `lol.trq.alts` reference for that part. The only
//! real crypto here is the Ed25519 challenge signature, which IS part of the wire contract.
//!
//! Run: `cargo run` (talks to http://localhost:8787 by default). Point it at a server with the
//! `AVP_SERVER_URL` environment variable.
//!
//! SPDX-License-Identifier: MIT

use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use serde_json::{json, Value};

/// Identifier of the wrapping scheme this example advertises in manifests and wrapped keys.
///
/// It must match the `schemeId` the server stores; the server treats it as an opaque label and never
/// performs the wrap the id names (SPEC section 4).
const SCHEME_ID: &str = "X25519-HKDF-SHA256-AESGCM-v1";

/// Read timeout applied to every HTTP call, so a hung server fails the transcript loudly rather than
/// blocking forever.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

// ─── Ed25519 keypair + identity (SPEC section 3) ──────────────────────────

/// A member identity: an Ed25519 signing keypair plus a placeholder X25519 public key.
///
/// The raw 32-byte Ed25519 public key, base64-encoded, is the member id (SPEC section 2). The X25519
/// key would be a real Curve25519 public key in a production client; here it is an opaque placeholder,
/// because this example performs no key wrapping.
struct Identity {
    /// Base64 raw 32-byte Ed25519 public key; this is the member id.
    ed25519_public_key: String,
    /// Base64 placeholder X25519 public key (no real key agreement happens in this example).
    x25519_public_key: String,
    /// The Ed25519 signing key, used only to sign the auth challenge nonce.
    signing_key: SigningKey,
}

/// Generates a fresh Ed25519 identity from 32 random seed bytes.
///
/// Building the [`SigningKey`] directly from random bytes avoids depending on the dalek `rand_core`
/// feature; any 32 bytes are a valid Ed25519 secret-scalar seed. This mirrors how the sibling server's
/// test harness mints keypairs.
///
/// # Arguments
///
/// * `label` - Human-readable name (e.g. `"alice"`) woven into the placeholder X25519 key so the
///   transcript stays readable; it has no cryptographic meaning.
///
/// # Returns
///
/// A new [`Identity`] with a real Ed25519 keypair and a placeholder X25519 public key.
fn generate_identity(label: &str) -> Identity {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let ed25519_public_key = STANDARD.encode(signing_key.verifying_key().to_bytes());
    Identity {
        ed25519_public_key,
        // Placeholder, not a real X25519 key — clearly labelled so nobody mistakes it for key material.
        x25519_public_key: STANDARD.encode(format!("x25519-placeholder-{label}")),
        signing_key,
    }
}

// ─── HTTP helper ──────────────────────────────────────────────────────────

/// Returns the base server URL from `AVP_SERVER_URL` (default `http://localhost:8787`), with any
/// trailing slash trimmed so paths can be appended directly.
fn base_url() -> String {
    let raw = std::env::var("AVP_SERVER_URL").unwrap_or_else(|_| "http://localhost:8787".to_string());
    raw.trim_end_matches('/').to_string()
}

/// Sends a JSON request to the server and parses the JSON response, returning an error on any non-2xx
/// status so the transcript fails loudly rather than silently mis-stepping.
///
/// `ureq` already raises [`ureq::Error::Status`] for non-2xx responses; this helper maps it (and any
/// transport error) into a flat [`String`] message that includes the method, path, status, and body.
///
/// # Arguments
///
/// * `base` - Base server URL (see [`base_url`]); `path` is appended to it.
/// * `method` - HTTP method (`"GET"`, `"POST"`, ...).
/// * `path` - Path appended to `base` (must start with `"/"`).
/// * `body` - Optional value to JSON-encode as the request body; pass `None` for bodyless requests
///   like GET.
/// * `token` - Optional bearer token; when present it is sent as `Authorization: Bearer <token>`.
///
/// # Returns
///
/// The parsed response body as a [`Value`], or [`Value::Null`] when the response has no body.
///
/// # Errors
///
/// Returns `Err` if the response status is not 2xx (the message includes method, path, status, and
/// body) or if the request could not be sent or its body could not be parsed as JSON.
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
        // ureq surfaces non-2xx as Error::Status; render the server's body for a useful message.
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

// ─── Auth flow: challenge -> sign nonce -> token (SPEC section 3) ──────────

/// Runs the keypair challenge flow and returns a bearer token for this identity.
///
/// The client signs the RAW nonce bytes (the bytes obtained by base64-decoding the `nonce`), not the
/// base64 text — this is the part conformant servers verify.
///
/// # Arguments
///
/// * `base` - Base server URL.
/// * `identity` - The member identity whose private key signs the challenge nonce.
///
/// # Returns
///
/// A bearer token to authorize subsequent calls for this identity.
///
/// # Errors
///
/// Returns `Err` if either auth leg returns a non-2xx status (propagated from [`call`]), if the
/// challenge response omits a string `nonce`, if the nonce is not valid base64, or if the token
/// response omits a string `token`.
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
    // Ed25519 signs the message bytes directly (no pre-hash).
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

// ─── Placeholder envelope + wrapped key (NOT real crypto) ──────────────────

/// Builds an opaque placeholder envelope.
///
/// A real client AES-256-GCM-encrypts the alt payload and binds `(repoId, payloadVersion, keyEpoch)`
/// into the AAD (SPEC section 4). Here `ciphertext` is just a base64 blob so the server has something to
/// store; the server never decrypts it, which is the whole point.
///
/// # Arguments
///
/// * `repo_id` - Repo the envelope belongs to.
/// * `payload_version` - Payload version this envelope represents.
/// * `key_epoch` - Key epoch the (notional) payload was encrypted under.
///
/// # Returns
///
/// An `EncryptedEnvelope`-shaped [`Value`] with a random IV and a labelled placeholder ciphertext.
fn placeholder_envelope(repo_id: &str, payload_version: i64, key_epoch: i64) -> Value {
    json!({
        "repoId": repo_id,
        "payloadVersion": payload_version,
        "keyEpoch": key_epoch,
        "iv": STANDARD.encode(random_bytes(12)),
        "ciphertext": STANDARD.encode(format!("opaque-placeholder-payload-v{payload_version}")),
    })
}

/// Builds an opaque placeholder wrapped data key for a member.
///
/// A real client runs X25519 ECDH against the member's X25519 key, derives an AES key via HKDF, and
/// AES-256-GCM-encrypts the repo data key. Here it is a labelled placeholder; the server stores and
/// serves it without ever being able to read it.
///
/// # Arguments
///
/// * `member_label` - Human-readable member name woven into the placeholder fields for transcript
///   readability; it has no cryptographic meaning.
///
/// # Returns
///
/// A `WrappedKey`-shaped [`Value`] advertising [`SCHEME_ID`] with a random IV and labelled placeholders.
fn placeholder_wrapped_key(member_label: &str) -> Value {
    json!({
        "schemeId": SCHEME_ID,
        "ephemeralPublicKey": STANDARD.encode(format!("ephemeral-x25519-for-{member_label}")),
        "iv": STANDARD.encode(random_bytes(12)),
        "ciphertext": STANDARD.encode(format!("wrapped-data-key-for-{member_label}")),
    })
}

/// Assembles a `MemberEntry`-shaped [`Value`] from an identity at a given key epoch.
///
/// # Arguments
///
/// * `identity` - The member whose public keys populate the entry.
/// * `label` - Human-readable member name passed through to [`placeholder_wrapped_key`].
/// * `key_epoch` - Key epoch this entry's wrapped key belongs to.
///
/// # Returns
///
/// A member entry with a placeholder wrapped data key and a `null` key-binding signature.
fn member_entry(identity: &Identity, label: &str, key_epoch: i64) -> Value {
    json!({
        "ed25519PublicKey": identity.ed25519_public_key,
        "x25519PublicKey": identity.x25519_public_key,
        "wrappedDataKey": placeholder_wrapped_key(label),
        "keyEpoch": key_epoch,
        "keyBindingSig": Value::Null,
    })
}

/// Returns `n` cryptographically random bytes, used only for placeholder IVs in this example.
///
/// # Arguments
///
/// * `n` - Number of random bytes to return.
fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

// ─── Transcript ─────────────────────────────────────────────────────────

/// Prints one transcript line with a padded step label so the output columns line up.
///
/// # Arguments
///
/// * `label` - Short step name shown left-aligned in a fixed-width column.
/// * `detail` - Free-form detail printed after the label.
fn step(label: &str, detail: &str) {
    println!("  {label:<16} {detail}");
}

/// Percent-encodes a string for use as a single URL path segment, mirroring JavaScript's
/// `encodeURIComponent`.
///
/// A member id is a base64 string and can contain `+`, `/`, and `=`, which are not safe to place
/// literally in a path; this encodes everything except the RFC 3986 unreserved set
/// (`A-Z a-z 0-9 - _ . ~`). The sibling server's `url_decode` reverses exactly this.
///
/// # Arguments
///
/// * `input` - The raw path-segment value (e.g. a base64 member id).
///
/// # Returns
///
/// The percent-encoded segment, safe to splice into a URL path.
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
///
/// # Arguments
///
/// * `value` - The full value (e.g. a member id or token) to abbreviate.
///
/// # Returns
///
/// At most the first 12 characters of `value`, suffixed with `…`.
fn short(value: &str) -> String {
    let prefix: String = value.chars().take(12).collect();
    format!("{prefix}…")
}

/// Returns a random version-4 UUID string for use as an opaque repoId.
///
/// A real repoId is whatever the deploying client mints; this formats 16 random bytes into an RFC 4122
/// version-4 UUID by hand (setting the version and variant bits).
///
/// # Returns
///
/// A random version-4 UUID string.
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

// ─── Lifecycle ─────────────────────────────────────────────────────────

/// Drives the full AVP lifecycle end to end against a running server and prints a transcript.
///
/// The steps, in order: generate two local identities (alice, bob); authenticate alice; create a repo
/// with alice as sole member; pull at the known version (unchanged) and from version 0 (envelope
/// returned); push a new version; demonstrate the optimistic-concurrency conflict path with a stale
/// expected version; add bob as a member; fetch bob's stored key entry; then authenticate bob and have
/// him pull the shared repo.
///
/// # Arguments
///
/// * `base` - Base server URL the transcript runs against.
///
/// # Errors
///
/// Returns `Err` if any server call returns a non-2xx status (propagated from [`call`]) or if any
/// expected field is missing from a response; [`main`] turns this into a non-zero exit code.
fn run(base: &str) -> Result<(), String> {
    println!("AVP reference client -> {base}");
    println!("(Envelope/wrapped-key crypto is a placeholder; only the Ed25519 auth is real.)\n");

    // Two members, generated locally. alice creates the repo; bob joins later.
    let alice = generate_identity("alice");
    let bob = generate_identity("bob");
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

    // 2. createRepo — alice must be the sole member of the manifest she creates.
    // A real repoId is whatever the deploying client mints; we use a random UUID.
    let repo_id = random_uuid();
    let initial_envelope = placeholder_envelope(&repo_id, 1, 0);
    let created = call(
        base,
        "POST",
        "/v1/repos",
        Some(&json!({
            "manifest": {
                "repoId": repo_id,
                "schemeId": SCHEME_ID,
                "keyEpoch": 0,
                "payloadVersion": 1,
                "members": [member_entry(&alice, "alice", 0)],
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

    // 3. pull at the version we already know — server reports unchanged and omits the envelope.
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

    // 4. pull from version 0 — server returns the current envelope.
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

    // 5. push a new payload version with optimistic concurrency on the current version.
    let push_result = call(
        base,
        "POST",
        &push_path,
        Some(&json!({
            "repoId": repo_id,
            "envelope": placeholder_envelope(&repo_id, next_version, 0),
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

    // 6. demonstrate the conflict path: pushing again at the now-stale expected version is rejected.
    let conflict = call(
        base,
        "POST",
        &push_path,
        Some(&json!({
            "repoId": repo_id,
            "envelope": placeholder_envelope(&repo_id, next_version + 1, 0),
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

    // 7. addMember — alice (any member may invite, v1 policy) records bob's entry. In a real client bob
    // would publish his public keys via the join handshake (SPEC section 8.1) and alice would wrap the
    // data key to bob's X25519 key; here the wrapped key is a placeholder.
    let with_bob = call(
        base,
        "POST",
        &format!("/v1/repos/{}/add-member", encode_uri_component(&repo_id)),
        Some(&json!({ "repoId": repo_id, "member": member_entry(&bob, "bob", 0) })),
        Some(&alice_token),
    )?;
    let with_bob_members = with_bob.get("members").and_then(Value::as_array).map_or(0, Vec::len);
    step("addMember", &format!("members={with_bob_members} (added bob)"));

    // 8. fetchMemberKey — look up bob's stored entry by member id. The id is base64, which can contain
    // + / =, so it MUST be URL-encoded in the path.
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

    // 9. bob authenticates with his own keypair and pulls the shared repo.
    let bob_token = authenticate(base, &bob)?;
    let bob_pull = call(
        base,
        "POST",
        &pull_path,
        Some(&json!({ "repoId": repo_id, "knownPayloadVersion": 0 })),
        Some(&bob_token),
    )?;
    let bob_manifest_members = bob_pull
        .get("manifest")
        .and_then(|m| m.get("members"))
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let bob_manifest_version = bob_pull
        .get("manifest")
        .and_then(|m| m.get("payloadVersion"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    step(
        "bob pull",
        &format!(
            "members={bob_manifest_members} v={bob_manifest_version} envelope={}",
            envelope_state(&bob_pull),
        ),
    );

    println!("\nDone. Full lifecycle exercised against a zero-knowledge server.");
    Ok(())
}

/// Renders a pull response's `envelope` field as the transcript word `present` or `null`.
///
/// # Arguments
///
/// * `pull_response` - A `PullResponse`-shaped [`Value`].
///
/// # Returns
///
/// `"present"` when the response carries a non-null `envelope`, otherwise `"null"`.
fn envelope_state(pull_response: &Value) -> &'static str {
    match pull_response.get("envelope") {
        Some(v) if !v.is_null() => "present",
        _ => "null",
    }
}

/// Resolves the target server URL, drives the lifecycle, and maps any failure to a non-zero exit code.
///
/// On error it prints the failing step's message plus a hint to start a server, then exits with status
/// `1`. The base URL defaults to `http://localhost:8787` and is overridable via `AVP_SERVER_URL`.
fn main() {
    let base = base_url();
    if let Err(err) = run(&base) {
        eprintln!("\nClient failed: {err}");
        eprintln!("Is a server running? Start one with `cargo run` in ../server, or set AVP_SERVER_URL.");
        std::process::exit(1);
    }
}
