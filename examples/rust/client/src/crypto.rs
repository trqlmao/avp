// SPDX-License-Identifier: MIT

//! AVP cryptographic core: AAD construction, HKDF-SHA256, payload AEAD, and the default
//! X25519-HKDF-SHA256-AESGCM-v1 data-key wrap scheme (SPEC sections 4-5).
//!
//! All wire byte fields (keys, IVs, ciphertext) are standard base64 with padding, matching the Go
//! reference implementation. The constructions here are checked byte-for-byte against the
//! conformance vectors in `vectors/*.json` by the `#[cfg(test)]` module below.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// HKDF info string and AES-GCM AAD for the default data-key wrap scheme.
const WRAP_INFO: &[u8] = b"avp/rdk-wrap/v1";

/// Scheme identifier stored in every `WrappedKey` on the wire.
pub const SCHEME_ID: &str = "X25519-HKDF-SHA256-AESGCM-v1";

// ─── AAD ─────────────────────────────────────────────────────────────────────

/// Constructs the additional authenticated data bound into every payload envelope (SPEC section 4):
///
/// ```text
/// AAD = UTF8(repoId) || 0x1F || int64BE(payloadVersion) || int64BE(keyEpoch)
/// ```
///
/// The unit-separator byte and the two big-endian counters make a stale-epoch or stale-version
/// envelope fail authentication, defeating rollback and cross-epoch replay.
pub fn build_aad(repo_id: &str, payload_version: i64, key_epoch: i64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(repo_id.len() + 1 + 16);
    aad.extend_from_slice(repo_id.as_bytes());
    aad.push(0x1F);
    aad.extend_from_slice(&payload_version.to_be_bytes());
    aad.extend_from_slice(&key_epoch.to_be_bytes());
    aad
}

// ─── HKDF-SHA256 ─────────────────────────────────────────────────────────────

/// Derives `len` bytes from `ikm` using HKDF-SHA256 (RFC 5869).
///
/// An empty salt is replaced by 32 zero bytes per RFC 5869 section 2.2.
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let salt_buf;
    let effective_salt: &[u8] = if salt.is_empty() {
        salt_buf = [0u8; 32];
        &salt_buf
    } else {
        salt
    };
    let hkdf = Hkdf::<Sha256>::new(Some(effective_salt), ikm);
    let mut okm = vec![0u8; len];
    hkdf.expand(info, &mut okm).expect("HKDF expand: length too large");
    okm
}

// ─── Payload AEAD ─────────────────────────────────────────────────────────────

/// AES-256-GCM-encrypts `plaintext` into an `EncryptedEnvelope`-shaped [`serde_json::Value`],
/// binding `(repo_id, payload_version, key_epoch)` into the AAD (SPEC section 4).
///
/// A fresh random 12-byte IV is generated per call. The 16-byte GCM tag is appended to the
/// ciphertext and the whole thing is base64-encoded (standard, with padding).
pub fn encrypt_payload(
    data_key: &[u8],
    repo_id: &str,
    payload_version: i64,
    key_epoch: i64,
    plaintext: &[u8],
) -> serde_json::Value {
    use rand::RngCore;
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let aad = build_aad(repo_id, payload_version, key_epoch);
    let ct = aes_gcm_seal(data_key, &iv, plaintext, &aad);
    serde_json::json!({
        "repoId": repo_id,
        "payloadVersion": payload_version,
        "keyEpoch": key_epoch,
        "iv": STANDARD.encode(iv),
        "ciphertext": STANDARD.encode(ct),
    })
}

/// Reverses [`encrypt_payload`]. Rebuilds the AAD from the envelope's own counters, so a tampered
/// counter fails authentication.
///
/// # Errors
///
/// Returns `Err` if the envelope fields are missing or not valid base64, or if AES-GCM
/// authentication fails.
pub fn decrypt_payload(data_key: &[u8], env: &serde_json::Value) -> Result<Vec<u8>, String> {
    let iv_b64 = env["iv"].as_str().ok_or("envelope missing `iv`")?;
    let ct_b64 = env["ciphertext"].as_str().ok_or("envelope missing `ciphertext`")?;
    let repo_id = env["repoId"].as_str().ok_or("envelope missing `repoId`")?;
    let payload_version = env["payloadVersion"].as_i64().ok_or("envelope missing `payloadVersion`")?;
    let key_epoch = env["keyEpoch"].as_i64().ok_or("envelope missing `keyEpoch`")?;

    let iv = STANDARD.decode(iv_b64).map_err(|e| format!("decode iv: {e}"))?;
    let ct = STANDARD.decode(ct_b64).map_err(|e| format!("decode ciphertext: {e}"))?;
    let aad = build_aad(repo_id, payload_version, key_epoch);

    aes_gcm_open(data_key, &iv, &ct, &aad).map_err(|e| format!("aes-gcm open: {e}"))
}

// ─── Key wrap ─────────────────────────────────────────────────────────────────

/// Wraps a 32-byte data key to a recipient's X25519 public key using
/// X25519-HKDF-SHA256-AESGCM-v1 (SPEC section 4):
///
/// 1. Ephemeral X25519 keypair.
/// 2. `shared = X25519(ephPriv, recipientPub)` (raw 32 bytes, unhashed).
/// 3. `kek = HKDF-SHA256(ikm=shared, salt=ephPubRaw, info="avp/rdk-wrap/v1", L=32)`.
/// 4. `ct = AES-256-GCM(kek, iv12, aad="avp/rdk-wrap/v1", plaintext=dataKey)`, tag appended.
///
/// Returns a `WrappedKey`-shaped [`serde_json::Value`].
pub fn wrap_data_key(recipient_x25519_pub_b64: &str, data_key: &[u8]) -> serde_json::Value {
    use rand::RngCore;

    // Decode recipient public key.
    let pub_bytes = STANDARD.decode(recipient_x25519_pub_b64).expect("recipient x25519 is valid base64");
    assert_eq!(
        pub_bytes.len(),
        32,
        "recipient x25519 public key must be 32 bytes, got {}",
        pub_bytes.len()
    );
    let mut pub_arr = [0u8; 32];
    pub_arr.copy_from_slice(&pub_bytes);
    let recipient_pub = PublicKey::from(pub_arr);

    // Ephemeral keypair.
    let eph_priv = StaticSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph_priv);
    let eph_pub_raw = eph_pub.as_bytes();

    // X25519 shared secret (raw, unhashed).
    let shared = eph_priv.diffie_hellman(&recipient_pub);
    let shared_raw = shared.as_bytes();

    // KEK via HKDF-SHA256.
    let kek = hkdf_sha256(shared_raw, eph_pub_raw, WRAP_INFO, 32);

    // Random IV.
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);

    // AES-256-GCM wrap.
    let ct = aes_gcm_seal(&kek, &iv, data_key, WRAP_INFO);

    serde_json::json!({
        "schemeId": SCHEME_ID,
        "ephemeralPublicKey": STANDARD.encode(eph_pub_raw),
        "iv": STANDARD.encode(iv),
        "ciphertext": STANDARD.encode(ct),
    })
}

/// Unwraps a `WrappedKey`-shaped value using the recipient's X25519 private key.
///
/// # Errors
///
/// Returns `Err` if the scheme id is wrong, base64 decoding fails, or AES-GCM authentication fails.
pub fn unwrap_data_key(recipient_priv: &StaticSecret, wk: &serde_json::Value) -> Result<Vec<u8>, String> {
    let scheme = wk["schemeId"].as_str().ok_or("wrappedKey missing `schemeId`")?;
    if scheme != SCHEME_ID {
        return Err(format!("unsupported wrap scheme {scheme:?}"));
    }
    let eph_pub_b64 = wk["ephemeralPublicKey"].as_str().ok_or("wrappedKey missing `ephemeralPublicKey`")?;
    let iv_b64 = wk["iv"].as_str().ok_or("wrappedKey missing `iv`")?;
    let ct_b64 = wk["ciphertext"].as_str().ok_or("wrappedKey missing `ciphertext`")?;

    let eph_pub_raw = STANDARD.decode(eph_pub_b64).map_err(|e| format!("decode ephemeral key: {e}"))?;
    let iv = STANDARD.decode(iv_b64).map_err(|e| format!("decode iv: {e}"))?;
    let ct = STANDARD.decode(ct_b64).map_err(|e| format!("decode ciphertext: {e}"))?;

    if eph_pub_raw.len() != 32 {
        return Err(format!("ephemeral key: expected 32 bytes, got {}", eph_pub_raw.len()));
    }
    let mut eph_pub_arr = [0u8; 32];
    eph_pub_arr.copy_from_slice(&eph_pub_raw);
    let eph_pub = PublicKey::from(eph_pub_arr);

    // Recompute shared secret.
    let shared = recipient_priv.diffie_hellman(&eph_pub);
    let shared_raw = shared.as_bytes();

    // Recompute KEK.
    let kek = hkdf_sha256(shared_raw, &eph_pub_raw, WRAP_INFO, 32);

    aes_gcm_open(&kek, &iv, &ct, WRAP_INFO).map_err(|e| format!("aes-gcm open: {e}"))
}

// ─── AES-256-GCM primitives ───────────────────────────────────────────────────

/// AES-256-GCM encrypt: returns `ciphertext || tag` (tag is 16 bytes appended).
fn aes_gcm_seal(key: &[u8], iv: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("key is 32 bytes");
    let nonce = Nonce::from_slice(iv);
    cipher
        .encrypt(nonce, aes_gcm::aead::Payload { msg: plaintext, aad })
        .expect("AES-GCM encrypt should not fail")
}

/// AES-256-GCM decrypt. Returns an error if authentication fails.
fn aes_gcm_open(key: &[u8], iv: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("bad key: {e}"))?;
    let nonce = Nonce::from_slice(iv);
    cipher
        .decrypt(nonce, aes_gcm::aead::Payload { msg: ciphertext, aad })
        .map_err(|_| "AES-GCM authentication failed".to_string())
}

// ─── Conformance vector tests ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn load_vector(name: &str) -> Value {
        let path = format!(
            "{}/../../../vectors/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {path}: {e}"))
    }

    fn must_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    fn must_b64(s: &str) -> Vec<u8> {
        STANDARD.decode(s).expect("valid standard base64")
    }

    #[test]
    fn test_aad_vectors() {
        let file = load_vector("aad.json");
        let cases = file["cases"].as_array().expect("cases array");
        assert!(!cases.is_empty(), "no AAD cases");
        for c in cases {
            let repo_id = c["repoId"].as_str().unwrap();
            let payload_version = c["payloadVersion"].as_i64().unwrap();
            let key_epoch = c["keyEpoch"].as_i64().unwrap();
            let expected_hex = c["expectedAadHex"].as_str().unwrap();
            let got = build_aad(repo_id, payload_version, key_epoch);
            let got_hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(
                got_hex, expected_hex,
                "repoId={repo_id} v={payload_version} epoch={key_epoch}"
            );
        }
    }

    #[test]
    fn test_key_binding_message_vectors() {
        let file = load_vector("key-binding-message.json");
        let cases = file["cases"].as_array().expect("cases array");
        for c in cases {
            let ed_pub = c["ed25519PublicKey"].as_str().unwrap();
            let x_pub = c["x25519PublicKey"].as_str().unwrap();
            let expected = c["expectedMessageUtf8"].as_str().unwrap();
            let got = format!("{ed_pub}|{x_pub}");
            assert_eq!(got, expected);
        }
    }

    #[test]
    fn test_hkdf_vectors() {
        let file = load_vector("hkdf.json");
        let cases = file["cases"].as_array().expect("cases array");
        for c in cases {
            let name = c["name"].as_str().unwrap();
            let ikm = must_hex(c["ikmHex"].as_str().unwrap());
            let salt_hex = c["saltHex"].as_str().unwrap();
            let info = must_hex(c["infoHex"].as_str().unwrap());
            let length = c["length"].as_u64().unwrap() as usize;
            let expected_okm = c["okmHex"].as_str().unwrap();

            // The salt passed to hkdf_sha256 may be empty; the function handles the RFC 5869
            // empty-salt rule internally.
            let salt = must_hex(salt_hex);
            let okm = hkdf_sha256(&ikm, &salt, &info, length);
            let okm_hex: String = okm.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(okm_hex, expected_okm, "{name}: OKM mismatch");
        }
    }

    #[test]
    fn test_x25519_vectors() {
        let file = load_vector("x25519.json");
        let cases = file["cases"].as_array().expect("cases array");
        for c in cases {
            let name = c["name"].as_str().unwrap();
            let scalar = must_hex(c["scalarHex"].as_str().unwrap());
            let u_coord = must_hex(c["uCoordinateHex"].as_str().unwrap());
            let expected_output = c["outputHex"].as_str().unwrap();

            let mut scalar_arr = [0u8; 32];
            scalar_arr.copy_from_slice(&scalar);
            let priv_key = StaticSecret::from(scalar_arr);

            let mut u_arr = [0u8; 32];
            u_arr.copy_from_slice(&u_coord);
            let pub_key = PublicKey::from(u_arr);

            let shared = priv_key.diffie_hellman(&pub_key);
            let shared_hex: String = shared.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(shared_hex, expected_output, "{name}: shared secret mismatch");
        }
    }

    #[test]
    fn test_ed25519_vectors() {
        use ed25519_dalek::{Signer, SigningKey};

        let file = load_vector("ed25519.json");
        let cases = file["cases"].as_array().expect("cases array");
        for c in cases {
            let name = c["name"].as_str().unwrap();
            let seed = must_hex(c["seedHex"].as_str().unwrap());
            let expected_pub = c["publicKeyHex"].as_str().unwrap();
            let msg = must_hex(c["messageHex"].as_str().unwrap());
            let expected_sig = c["signatureHex"].as_str().unwrap();

            let mut seed_arr = [0u8; 32];
            seed_arr.copy_from_slice(&seed);
            let signing_key = SigningKey::from_bytes(&seed_arr);
            let pub_bytes = signing_key.verifying_key().to_bytes();
            let pub_hex: String = pub_bytes.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(pub_hex, expected_pub, "{name}: public key mismatch");

            let sig = signing_key.sign(&msg);
            let sig_hex: String = sig.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(sig_hex, expected_sig, "{name}: signature mismatch");
        }
    }

    #[test]
    fn test_payload_aead_vectors() {
        let file = load_vector("payload-aead.json");
        let cases = file["cases"].as_array().expect("cases array");
        for c in cases {
            let name = c["name"].as_str().unwrap();
            let key = must_b64(c["keyB64"].as_str().unwrap());
            let iv = must_b64(c["ivB64"].as_str().unwrap());
            let repo_id = c["repoId"].as_str().unwrap();
            let payload_version = c["payloadVersion"].as_i64().unwrap();
            let key_epoch = c["keyEpoch"].as_i64().unwrap();
            let expected_aad_hex = c["aadHex"].as_str().unwrap();
            let plaintext = c["plaintextUtf8"].as_str().unwrap().as_bytes();
            let expected_ct_b64 = c["ciphertextB64"].as_str().unwrap();
            let tamper_epoch = c["tamperEpoch"].as_i64().unwrap();

            // (a) AAD check.
            let aad = build_aad(repo_id, payload_version, key_epoch);
            let aad_hex: String = aad.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(aad_hex, expected_aad_hex, "{name}: AAD mismatch");

            // (b) Re-encrypt with committed key+iv and assert ciphertext.
            let ct = aes_gcm_seal(&key, &iv, plaintext, &aad);
            let ct_b64 = STANDARD.encode(&ct);
            assert_eq!(ct_b64, expected_ct_b64, "{name}: ciphertext mismatch");

            // (c) Decrypt and assert plaintext recovery.
            let ct_bytes = must_b64(expected_ct_b64);
            let pt = aes_gcm_open(&key, &iv, &ct_bytes, &aad).expect("decrypt should succeed");
            assert_eq!(pt, plaintext, "{name}: plaintext recovery mismatch");

            // (d) Tampered epoch in AAD must fail authentication.
            let tampered_aad = build_aad(repo_id, payload_version, tamper_epoch);
            assert!(
                aes_gcm_open(&key, &iv, &ct_bytes, &tampered_aad).is_err(),
                "{name}: tampered-epoch decryption should have failed"
            );
        }
    }

    #[test]
    fn test_key_wrap_vectors() {
        let file = load_vector("key-wrap.json");
        let cases = file["cases"].as_array().expect("cases array");
        for c in cases {
            let name = c["name"].as_str().unwrap();

            // Decode recipient private key and derive the public key.
            let recipient_priv_raw = must_b64(c["recipientPrivateKeyB64"].as_str().unwrap());
            let mut priv_arr = [0u8; 32];
            priv_arr.copy_from_slice(&recipient_priv_raw);
            let recipient_priv = StaticSecret::from(priv_arr);
            let recipient_pub = PublicKey::from(&recipient_priv);
            let recipient_pub_b64 = STANDARD.encode(recipient_pub.as_bytes());
            assert_eq!(
                recipient_pub_b64,
                c["recipientPublicKeyB64"].as_str().unwrap(),
                "{name}: recipient public key mismatch"
            );

            // Extract committed ephemeral public key and compute shared secret.
            let wk = &c["wrappedKey"];
            let eph_pub_raw = must_b64(wk["ephemeralPublicKey"].as_str().unwrap());
            let mut eph_pub_arr = [0u8; 32];
            eph_pub_arr.copy_from_slice(&eph_pub_raw);
            let eph_pub = PublicKey::from(eph_pub_arr);
            let shared = recipient_priv.diffie_hellman(&eph_pub);
            let shared_hex: String = shared.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(shared_hex, c["sharedSecretHex"].as_str().unwrap(), "{name}: shared secret mismatch");

            // Derive KEK.
            let info_str = c["info"].as_str().unwrap();
            let kek = hkdf_sha256(shared.as_bytes(), &eph_pub_raw, info_str.as_bytes(), 32);
            let kek_hex: String = kek.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(kek_hex, c["kekHex"].as_str().unwrap(), "{name}: KEK mismatch");

            // (a) Re-wrap with committed IV and assert ciphertext.
            let iv = must_b64(wk["iv"].as_str().unwrap());
            let data_key = must_b64(c["dataKeyB64"].as_str().unwrap());
            let ct = aes_gcm_seal(&kek, &iv, &data_key, info_str.as_bytes());
            let ct_b64 = STANDARD.encode(&ct);
            assert_eq!(ct_b64, wk["ciphertext"].as_str().unwrap(), "{name}: wrapped ciphertext mismatch");

            // (b) Unwrap via public API and assert data-key recovery.
            let recovered = unwrap_data_key(&recipient_priv, wk).expect("unwrap should succeed");
            assert_eq!(recovered, data_key, "{name}: data key recovery mismatch");
        }
    }
}
