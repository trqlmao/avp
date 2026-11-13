// SPDX-License-Identifier: MIT

//! Conformance vectors: every case of the shared `vectors/*.json` files, asserted byte for byte.
//!
//! Every expected value is read from the vector file (RFC anchors, the Trezor BIP39 anchors, or the
//! values `vectors/generate.ts` derived from documented seeds and the Node runner cross-checks). No
//! expected value is produced by the function under test.

use std::fs;

use avp::auth::{challenge_message, sign_challenge, verify_challenge};
use avp::commit::{Commit, CommitHeader, aad_v2, commit_sig_message};
use avp::crypto::{self, OWNER_LINK_INFO, WRAP_INFO};
use avp::encoding::Ce;
use avp::manifest::{SignedManifest, WrappedKey, derive_repo_id};
use avp::owner::{OwnerKeys, entropy_to_mnemonic, mnemonic_to_entropy, mnemonic_to_seed};
use avp::tokens::{
    Acceptance, AvpUri, InviteToken, LeaveRequest, LinkGrant, LinkRequest, RepoLocator, decode_token, encode_token,
    key_fingerprint, owner_fingerprint,
};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use serde_json::Value;
use x25519_dalek::StaticSecret;

fn load(name: &str) -> Value {
    let path = format!("{}/../../../vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn unhex32(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("32 bytes")
}

fn b64(s: &str) -> Vec<u8> {
    STANDARD.decode(s).expect("base64")
}

fn b64_32(s: &str) -> [u8; 32] {
    b64(s).try_into().expect("32 bytes")
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("string field {k}"))
}

fn arr<'a>(v: &'a Value, k: &str) -> &'a Vec<Value> {
    v[k].as_array().unwrap_or_else(|| panic!("array field {k}"))
}

fn sha256_label(label: &str) -> [u8; 32] {
    crypto::sha256(label.as_bytes())
}

// ─── CE writer (SPEC 4.1), expected bytes written by hand from the SPEC table ───────────────

#[test]
fn ce_writer_items() {
    let mut w = Ce::new("avp/x");
    assert_eq!(hex(&w.clone().finish().unwrap()), "6176702f7800");
    w.bytes(&[0xde, 0xad, 0xbe]);
    assert_eq!(hex(&w.clone().finish().unwrap()), "6176702f780000000003deadbe");

    let mut w = Ce::new("t");
    w.str("ab").i64(2).bool(true).count(1).bytes(&[0xff]);
    assert_eq!(
        hex(&w.finish().unwrap()),
        format!(
            "7400{}{}{}{}{}",
            "000000026162", "0000000000000002", "01", "00000001", "00000001ff"
        )
    );

    let mut w = Ce::new("t");
    w.i64(-1)
        .i64(4_294_967_298)
        .i64(i64::MAX)
        .i64(i64::MIN)
        .bool(false)
        .count(0)
        .str("aé")
        .bytes(&[]);
    let expected = [
        "7400",             // tag("t")
        "ffffffffffffffff", // i64(-1)
        "0000000100000002", // i64(2^32 + 2): a 32-bit truncation would give ...00000002
        "7fffffffffffffff", // i64(MAX)
        "8000000000000000", // i64(MIN)
        "00",               // bool(false)
        "00000000",         // count(0)
        "0000000361c3a9",   // str("aé"): U+00E9 is c3 a9, so the length is 3
        "00000000",         // bytes(empty)
    ]
    .concat();
    assert_eq!(hex(&w.finish().unwrap()), expected);
}

#[test]
fn ce_tag_with_nul_is_rejected() {
    assert!(Ce::new("a\0b").finish().is_err());
}

// ─── hkdf.json (RFC 5869) ───────────────────────────────────────────────────────────────

#[test]
fn hkdf() {
    let file = load("hkdf.json");
    let cases = arr(&file, "cases");
    assert_eq!(cases.len(), 2);
    for c in cases {
        let len = usize::try_from(c["length"].as_u64().unwrap()).unwrap();
        let okm = crypto::hkdf_sha256(
            &unhex(s(c, "ikmHex")),
            &unhex(s(c, "saltHex")),
            &unhex(s(c, "infoHex")),
            len,
        )
        .unwrap();
        assert_eq!(hex(&okm), s(c, "okmHex"), "{}", s(c, "name"));
    }
}

// ─── x25519.json (RFC 7748) ─────────────────────────────────────────────────────────────

#[test]
fn x25519() {
    let file = load("x25519.json");
    let cases = arr(&file, "cases");
    assert_eq!(cases.len(), 3);
    for c in cases {
        let out = crypto::x25519(&unhex32(s(c, "scalarHex")), &unhex32(s(c, "uCoordinateHex")));
        assert_eq!(hex(&out), s(c, "outputHex"), "{}", s(c, "name"));
    }
}

// ─── ed25519.json (RFC 8032) ────────────────────────────────────────────────────────────

#[test]
fn ed25519() {
    use ed25519_dalek::Signer;
    let file = load("ed25519.json");
    let cases = arr(&file, "cases");
    assert_eq!(cases.len(), 2);
    for c in cases {
        let key = SigningKey::from_bytes(&unhex32(s(c, "seedHex")));
        let public = key.verifying_key().to_bytes();
        assert_eq!(hex(&public), s(c, "publicKeyHex"));
        let msg = unhex(s(c, "messageHex"));
        let sig = key.sign(&msg).to_bytes();
        assert_eq!(hex(&sig), s(c, "signatureHex"));
        crypto::ed25519_verify(&public, &msg, &sig).unwrap();
    }
}

// ─── key-wrap.json (SPEC 4.4) ───────────────────────────────────────────────────────────

#[test]
fn key_wrap() {
    let file = load("key-wrap.json");
    let cases = arr(&file, "cases");
    assert_eq!(cases.len(), 1);
    for c in cases {
        let recipient = StaticSecret::from(b64_32(s(c, "recipientPrivateKeyB64")));
        assert_eq!(
            crypto::x25519_public(&recipient).to_vec(),
            b64(s(c, "recipientPublicKeyB64"))
        );
        let wk: WrappedKey = serde_json::from_value(c["wrappedKey"].clone()).unwrap();
        let shared = crypto::x25519(&recipient.to_bytes(), &wk.ephemeral_public_key);
        assert_eq!(hex(&shared), s(c, "sharedSecretHex"));
        assert_eq!(s(c, "info").as_bytes(), WRAP_INFO);
        let kek = crypto::hkdf_sha256(&shared, &wk.ephemeral_public_key, WRAP_INFO, 32).unwrap();
        assert_eq!(hex(&kek), s(c, "kekHex"));
        let data_key = b64(s(c, "dataKeyB64"));
        let kek: [u8; 32] = kek.try_into().unwrap();
        let resealed = crypto::aes_gcm_seal(&kek, &wk.iv, &data_key, WRAP_INFO).unwrap();
        assert_eq!(resealed, wk.ciphertext);
        assert_eq!(crypto::unwrap(&recipient, &wk, WRAP_INFO).unwrap(), data_key);
        // The wire form round-trips with its exact field names.
        assert_eq!(serde_json::to_value(&wk).unwrap(), c["wrappedKey"]);
    }
}

// ─── bip39-owner.json (SPEC 3.1) ────────────────────────────────────────────────────────

#[test]
fn bip39_owner() {
    let path = format!("{}/../../../vectors/bip39-english.txt", env!("CARGO_MANIFEST_DIR"));
    let words = fs::read(&path).unwrap();
    assert_eq!(
        hex(&crypto::sha256(&words)),
        "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
    );

    let file = load("bip39-owner.json");
    let anchors = &file["anchors"];
    assert_eq!(s(anchors, "passphrase"), "TREZOR");
    let anchor_cases = arr(anchors, "cases");
    assert_eq!(anchor_cases.len(), 3);
    for a in anchor_cases {
        let entropy = unhex32(s(a, "entropyHex"));
        assert_eq!(entropy_to_mnemonic(&entropy), s(a, "mnemonic"));
        assert_eq!(mnemonic_to_entropy(s(a, "mnemonic")).unwrap(), entropy);
        assert_eq!(hex(&mnemonic_to_seed(s(a, "mnemonic"), "TREZOR")), s(a, "seedHex"));
    }

    let cases = arr(&file, "cases");
    assert_eq!(cases.len(), 3);
    for c in cases {
        assert_eq!(s(c, "passphrase"), "");
        let entropy = unhex32(s(c, "entropyHex"));
        assert_eq!(entropy_to_mnemonic(&entropy), s(c, "mnemonic"), "{}", s(c, "name"));
        assert_eq!(mnemonic_to_entropy(s(c, "mnemonic")).unwrap(), entropy);
        let seed = mnemonic_to_seed(s(c, "mnemonic"), "");
        assert_eq!(hex(&seed), s(c, "seedHex"));
        let keys = OwnerKeys::from_seed(&seed).unwrap();
        assert_eq!(hex(&keys.signing.to_bytes()), s(c, "ed25519SeedHex"));
        assert_eq!(hex(&keys.owner_key()), s(c, "ed25519PublicKeyHex"));
        assert_eq!(hex(&keys.x25519.to_bytes()), s(c, "x25519PrivateHex"));
        assert_eq!(hex(&keys.x25519_public()), s(c, "x25519PublicKeyHex"));
    }
}

// ─── manifest.json (SPEC 4.1, 4.2) ──────────────────────────────────────────────────────

#[test]
fn manifest() {
    let file = load("manifest.json");
    let seeds = &file["seeds"];
    let owner = SigningKey::from_bytes(&unhex32(s(&seeds["owner"], "ed25519SeedHex")));
    let cases = arr(&file, "cases");
    let names: Vec<&str> = cases.iter().map(|c| s(c, "name")).collect();
    assert_eq!(names, ["genesis", "add-members", "remove-member", "policy-flip"]);

    let mut prev: Option<SignedManifest> = None;
    for c in cases {
        let name = s(c, "name");
        let wire = &c["signedManifest"];
        let m: SignedManifest = serde_json::from_value(wire.clone()).unwrap();
        let expected = &c["expected"];

        // S, the owner signature, the hash, and the wire form.
        assert_eq!(hex(&m.state.encode().unwrap()), s(expected, "stateHex"), "{name} S");
        let resigned = m.state.clone().sign(&owner).unwrap();
        assert_eq!(resigned.owner_signature, m.owner_signature, "{name} ownerSignature");
        m.verify().unwrap();
        assert_eq!(
            hex(&m.hash().unwrap()),
            s(expected, "manifestHashHex"),
            "{name} manifestHash"
        );
        assert_eq!(serde_json::to_value(&m).unwrap(), *wire, "{name} wire round trip");

        // The encoding sorts every list, so any input order gives the same bytes.
        let mut shuffled = m.state.clone();
        shuffled.hosts.reverse();
        shuffled.members.rotate_left(1);
        shuffled.removals.reverse();
        for r in &mut shuffled.removals {
            r.frontier.reverse();
        }
        assert_eq!(
            hex(&shuffled.encode().unwrap()),
            s(expected, "stateHex"),
            "{name} order independent"
        );

        if m.state.manifest_seq == 1 {
            let nonce: [u8; 16] = m.state.genesis_nonce.clone().try_into().unwrap();
            assert_eq!(
                derive_repo_id(&m.state.owner_key, &nonce).unwrap(),
                s(expected, "repoId")
            );
            assert_eq!(m.state.repo_id, s(expected, "repoId"));
        }
        if let Some(p) = &prev {
            assert!(m.links_to(p).unwrap(), "{name} links to the previous state");
        }
        prev = Some(m);
    }
}

#[test]
fn manifest_wraps() {
    let file = load("manifest.json");
    let seeds = &file["seeds"];
    // label, ed25519 public key, x25519 private key
    let mut parties = vec![(
        "owner".to_string(),
        s(&seeds["owner"], "ownerKey").to_string(),
        unhex32(s(&seeds["owner"], "x25519PrivateHex")),
    )];
    for m in arr(seeds, "members") {
        parties.push((
            s(m, "label").into(),
            s(m, "ed25519PublicKey").into(),
            unhex32(s(m, "x25519PrivateHex")),
        ));
    }
    let data_key = |epoch: i64| {
        let k = arr(seeds, "dataKeys")
            .iter()
            .find(|k| k["keyEpoch"].as_i64() == Some(epoch))
            .unwrap();
        unhex(s(k, "dataKeyHex"))
    };

    let mut checked = 0;
    for c in arr(&file, "cases") {
        let m: SignedManifest = serde_json::from_value(c["signedManifest"].clone()).unwrap();
        for member in &m.state.members {
            let id = STANDARD.encode(member.ed25519_public_key);
            let (label, _, x_priv) = parties.iter().find(|p| p.1 == id).unwrap();
            let recipient = StaticSecret::from(*x_priv);
            assert_eq!(crypto::x25519_public(&recipient), member.x25519_public_key);
            let expected_key = data_key(member.key_epoch);
            assert_eq!(
                crypto::unwrap(&recipient, &member.wrapped_data_key, WRAP_INFO).unwrap(),
                expected_key
            );

            // wrapDerivation: the documented ephemeral key and IV reproduce the wrap byte for byte.
            let eph = StaticSecret::from(sha256_label(&format!(
                "avp/vectors/wrap-ephemeral/{}/{label}",
                member.key_epoch
            )));
            let iv: [u8; 12] = sha256_label(&format!("avp/vectors/wrap-iv/{}/{label}", member.key_epoch))[..12]
                .try_into()
                .unwrap();
            let rewrapped = crypto::wrap_with(&member.x25519_public_key, &expected_key, WRAP_INFO, &eph, &iv).unwrap();
            assert_eq!(rewrapped, member.wrapped_data_key);
            checked += 1;
        }
    }
    assert_eq!(checked, 1 + 4 + 3 + 3);
}

// ─── commit.json (SPEC 4.3) ─────────────────────────────────────────────────────────────

#[test]
fn commit() {
    let file = load("commit.json");
    let seeds = &file["seeds"];
    let data_key = unhex32(s(seeds, "dataKeyHex"));
    let iv: [u8; 12] = unhex(s(seeds, "ivHex")).try_into().unwrap();
    let author_key = |label: &str| {
        let a = arr(seeds, "authors").iter().find(|a| s(a, "label") == label).unwrap();
        SigningKey::from_bytes(&unhex32(s(a, "ed25519SeedHex")))
    };
    let cases = arr(&file, "cases");
    let names: Vec<&str> = cases.iter().map(|c| s(c, "name")).collect();
    assert_eq!(names, ["root", "single-parent", "three-parent-merge"]);

    for c in cases {
        let name = s(c, "name");
        let wire = &c["commit"];
        let cm: Commit = serde_json::from_value(wire.clone()).unwrap();
        let expected = &c["expected"];
        assert_eq!(
            hex(&cm.header_bytes().unwrap()),
            s(expected, "headerHex"),
            "{name} header"
        );
        assert_eq!(hex(&cm.id().unwrap()), s(expected, "commitIdHex"), "{name} id");
        assert_eq!(hex(&cm.commit_id), s(expected, "commitIdHex"));
        let aad = aad_v2(&cm.repo_id, cm.key_epoch, &cm.author, &cm.parents).unwrap();
        assert_eq!(hex(&aad), s(expected, "aadHex"), "{name} aad");
        cm.verify().unwrap();
        crypto::ed25519_verify(
            &cm.author,
            &commit_sig_message(&cm.commit_id).unwrap(),
            &cm.author_signature,
        )
        .unwrap();
        let plaintext = s(c, "plaintextUtf8").as_bytes();
        assert_eq!(cm.open(&data_key).unwrap(), plaintext, "{name} open");

        // Sealing the same header and plaintext with the seeded key and IV reproduces the commit.
        let header = CommitHeader {
            repo_id: cm.repo_id.clone(),
            parents: cm.parents.clone(),
            manifest_seq: cm.manifest_seq,
            manifest_hash: cm.manifest_hash,
            key_epoch: cm.key_epoch,
        };
        let sealed = Commit::seal_with_iv(&data_key, header, plaintext, &author_key(s(c, "authorLabel")), &iv).unwrap();
        assert_eq!(serde_json::to_value(&sealed).unwrap(), *wire, "{name} sealed commit");
    }
}

// ─── federation.json (SPEC 11) ──────────────────────────────────────────────────────────

fn token_case<'a>(file: &'a Value, name: &str) -> &'a Value {
    arr(file, "tokens").iter().find(|t| s(t, "name") == name).unwrap()
}

/// Asserts the decode oracle, the canonical encoding, and the re-encoding of one token case.
fn check_token<T: serde::Serialize + serde::de::DeserializeOwned>(t: &Value) -> T {
    let name = s(t, "name");
    assert_eq!(
        URL_SAFE_NO_PAD.decode(s(t, "base64url")).unwrap(),
        s(t, "canonicalJson").as_bytes(),
        "{name}"
    );
    let decoded: T = decode_token(s(t, "base64url")).unwrap();
    assert_eq!(serde_json::to_value(&decoded).unwrap(), t["decoded"], "{name} decoded");
    assert_eq!(
        serde_json::to_string(&decoded).unwrap(),
        s(t, "canonicalJson"),
        "{name} canonical JSON"
    );
    assert_eq!(encode_token(&decoded).unwrap(), s(t, "base64url"), "{name} base64url");

    // Any field order and whitespace decodes; a v other than 2 is rejected.
    let mut fields: Vec<(String, Value)> = t["decoded"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    fields.reverse();
    let body = fields
        .iter()
        .map(|(k, v)| format!("\"{k}\" : {v}"))
        .collect::<Vec<_>>()
        .join(" ,\n ");
    let reordered = URL_SAFE_NO_PAD.encode(format!("{{ {body} }}"));
    let again: T = decode_token(&reordered).unwrap();
    assert_eq!(serde_json::to_value(&again).unwrap(), t["decoded"], "{name} reordered");
    if t["decoded"].get("v").is_some() {
        for v in ["1", "3", "\"2\""] {
            let bad = s(t, "canonicalJson").replacen("\"v\":2", &format!("\"v\":{v}"), 1);
            assert!(decode_token::<T>(&URL_SAFE_NO_PAD.encode(bad)).is_err(), "{name} v {v}");
        }
    }
    decoded
}

#[test]
fn federation() {
    let file = load("federation.json");
    let manifest = load("manifest.json");
    let host_b = arr(&manifest["seeds"], "hosts")
        .iter()
        .find(|h| s(h, "label") == "b")
        .unwrap();
    let host_b_key = SigningKey::from_bytes(&unhex32(s(host_b, "ed25519SeedHex")));
    let member_seed = |label: &str| {
        let m = arr(&manifest["seeds"], "members")
            .iter()
            .find(|m| s(m, "label") == label)
            .unwrap();
        SigningKey::from_bytes(&unhex32(s(m, "ed25519SeedHex")))
    };

    assert_eq!(arr(&file, "tokens").len(), 5);

    // Invite token and its acceptance (SPEC 11.3, 8.2).
    let t = token_case(&file, "invite-token");
    let invite: InviteToken = check_token(t);
    let acc = &invite.acceptance;
    assert_eq!(hex(&acc.message().unwrap()), s(t, "acceptanceMessageHex"));
    acc.verify().unwrap();
    let resigned = Acceptance {
        signature: [0; 64],
        ..acc.clone()
    }
    .sign(&host_b_key)
    .unwrap();
    assert_eq!(resigned, *acc, "acceptance signature reproduces");
    invite.verify(&acc.repo_id, acc.expires_at - 1).unwrap();
    assert!(
        invite.verify(&acc.repo_id, acc.expires_at).is_err(),
        "an expired acceptance is rejected"
    );
    assert!(
        invite.verify("ndV4hcP0XHhIOjCt8XXhrg", acc.expires_at - 1).is_err(),
        "another repoId is rejected"
    );

    // Repo locators (SPEC 11.2).
    for name in ["repo-locator", "repo-locator-port"] {
        let loc: RepoLocator = check_token(token_case(&file, name));
        let owner_key = b64_32(s(&file["fingerprints"]["owner"], "ownerKey"));
        assert_eq!(loc.owner_fingerprint, owner_fingerprint(&owner_key));
    }

    // Link request and grant (SPEC 11.6).
    let req: LinkRequest = check_token(token_case(&file, "link-request"));
    let t = token_case(&file, "link-grant");
    let grant: LinkGrant = check_token(t);
    let link_priv = StaticSecret::from(unhex32(s(&t["checker"], "linkEphemeralPrivateHex")));
    assert_eq!(crypto::x25519_public(&link_priv), req.ephemeral_public_key);
    let entropy = unhex32(s(&t["checker"], "entropyHex"));
    assert_eq!(grant.open(&link_priv).unwrap(), entropy);
    let eph = StaticSecret::from(sha256_label("avp/vectors/link-wrap-ephemeral"));
    let iv: [u8; 12] = sha256_label("avp/vectors/link-wrap-iv")[..12].try_into().unwrap();
    let resealed = LinkGrant::seal_with(&entropy, &req.ephemeral_public_key, &eph, &iv).unwrap();
    assert_eq!(resealed, grant);
    assert!(
        crypto::unwrap(&link_priv, &grant.wrap, WRAP_INFO).is_err(),
        "the data key label does not open it"
    );
    assert_eq!(
        crypto::unwrap(&link_priv, &grant.wrap, OWNER_LINK_INFO).unwrap(),
        entropy
    );

    // Leave requests (SPEC 11.4).
    let leaves = arr(&file, "leaves");
    assert_eq!(leaves.len(), 2);
    for (l, label) in leaves.iter().zip(["alice", "bob"]) {
        let leave: LeaveRequest = serde_json::from_value(l["decoded"].clone()).unwrap();
        assert_eq!(serde_json::to_value(&leave).unwrap(), l["decoded"]);
        assert_eq!(hex(&leave.message().unwrap()), s(l, "signatureMessageHex"));
        leave.verify().unwrap();
        let resigned = LeaveRequest {
            signature: [0; 64],
            ..leave.clone()
        }
        .sign(&member_seed(label))
        .unwrap();
        assert_eq!(resigned, leave);
    }

    // Link confirmation codes (SPEC 11.6).
    let codes = arr(&file, "linkCodes");
    assert_eq!(codes.len(), 2);
    for c in codes {
        let req = LinkRequest::new(b64_32(s(c, "ephemeralPublicKey")));
        assert_eq!(req.confirmation_code().unwrap(), s(c, "code"));
    }

    // Fingerprints (SPEC 3.2, 11.2).
    let fp = &file["fingerprints"];
    for m in arr(fp, "members") {
        assert_eq!(
            key_fingerprint(&b64_32(s(m, "ed25519PublicKey")), &b64_32(s(m, "x25519PublicKey"))),
            s(m, "fingerprint")
        );
    }
    assert_eq!(
        owner_fingerprint(&b64_32(s(&fp["owner"], "ownerKey"))),
        s(&fp["owner"], "ownerFingerprint")
    );

    // avp:// URIs (SPEC 11.2).
    let uris = arr(&file, "uris");
    assert_eq!(uris.len(), 2);
    for u in uris {
        let parsed = AvpUri::parse(s(u, "uri")).unwrap();
        assert_eq!(parsed.host_locator, s(u, "host"));
        assert_eq!(parsed.repo_id, s(u, "repoId"));
        assert_eq!(parsed.to_string(), s(u, "uri"));
    }
}

// ─── federation.json challenges: the challenge transcript (SPEC 3.3) ─────────────────────

/// The Ed25519 seed of a `manifest.json` party (the owner or a member) by its public key.
fn seed_of(manifest: &Value, public: &str) -> SigningKey {
    let owner = &manifest["seeds"]["owner"];
    let seed = if s(owner, "ownerKey") == public {
        s(owner, "ed25519SeedHex")
    } else {
        let m = arr(&manifest["seeds"], "members")
            .iter()
            .find(|m| s(m, "ed25519PublicKey") == public)
            .unwrap_or_else(|| panic!("no manifest.json seed for {public}"));
        s(m, "ed25519SeedHex")
    };
    SigningKey::from_bytes(&unhex32(seed))
}

#[test]
fn challenges() {
    let file = load("federation.json");
    let manifest = load("manifest.json");
    let host_keys: Vec<[u8; 32]> = arr(&manifest["seeds"], "hosts")
        .iter()
        .map(|h| b64_32(s(h, "hostKey")))
        .collect();
    let cases = arr(&file, "challenges");
    assert_eq!(cases.len(), 2);
    for c in cases {
        let name = s(c, "name");
        let host_key = b64_32(s(c, "hostKey"));
        let key = b64_32(s(c, "ed25519PublicKey"));
        let nonce = b64(s(c, "nonce"));
        let sig: [u8; 64] = b64(s(c, "signature")).try_into().unwrap();
        assert!(nonce.len() >= 32, "{name}: nonce of at least 32 bytes");
        assert_eq!(
            hex(&challenge_message(&host_key, &key, &nonce).unwrap()),
            s(c, "messageHex"),
            "{name}"
        );
        // The SPEC 3.3 layout written out by hand: tag, then three length-prefixed fields.
        let mut by_hand = b"avp/challenge/v1\0".to_vec();
        for field in [&host_key[..], &key[..], &nonce[..]] {
            by_hand.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
            by_hand.extend_from_slice(field);
        }
        assert_eq!(hex(&by_hand), s(c, "messageHex"), "{name}: hand-built transcript");
        verify_challenge(&host_key, &key, &nonce, &sig).unwrap();
        let signer = seed_of(&manifest, s(c, "ed25519PublicKey"));
        assert_eq!(
            sign_challenge(&host_key, &signer, &nonce).unwrap(),
            sig,
            "{name}: signature reproduces"
        );
        for other in host_keys.iter().filter(|k| **k != host_key) {
            assert!(
                verify_challenge(other, &key, &nonce, &sig).is_err(),
                "{name}: bound to its host key"
            );
        }
        assert!(
            crypto::ed25519_verify(&key, &nonce, &sig).is_err(),
            "{name}: not over the raw nonce"
        );
    }
}

// ─── negative.json (MUST reject, and each base MUST be accepted) ────────────────────────

/// Applies the case's operation and reports whether the input was accepted.
fn accepted(c: &Value) -> bool {
    match s(c, "op") {
        "ed25519-verify" => {
            let public = unhex32(s(c, "publicKeyHex"));
            let sig: [u8; 64] = unhex(s(c, "signatureHex")).try_into().unwrap();
            crypto::ed25519_verify(&public, &unhex(s(c, "messageHex")), &sig).is_ok()
        }
        "key-unwrap" => {
            let wk = WrappedKey {
                scheme_id: crypto::SCHEME_ID.to_string(),
                ephemeral_public_key: b64_32(s(c, "ephemeralPublicKeyB64")),
                iv: b64(s(c, "ivB64")).try_into().unwrap(),
                ciphertext: b64(s(c, "ciphertextB64")),
            };
            let recipient = StaticSecret::from(b64_32(s(c, "recipientPrivateKeyB64")));
            crypto::unwrap(&recipient, &wk, WRAP_INFO).is_ok()
        }
        "wrap-unwrap" => {
            let wk: WrappedKey = serde_json::from_value(c["wrap"].clone()).unwrap();
            let recipient = StaticSecret::from(unhex32(s(c, "recipientPrivateKeyHex")));
            crypto::unwrap(&recipient, &wk, s(c, "info").as_bytes()).is_ok()
        }
        "manifest-verify" => {
            let m: SignedManifest = serde_json::from_value(c["signedManifest"].clone()).unwrap();
            m.verify().is_ok()
        }
        "manifest-link" => {
            let prev: SignedManifest = serde_json::from_value(c["prev"].clone()).unwrap();
            let next: SignedManifest = serde_json::from_value(c["next"].clone()).unwrap();
            // The mutation keeps the owner signature valid, so only the chain link can reject it.
            next.verify().unwrap();
            next.links_to(&prev).unwrap()
        }
        "commit-verify" => {
            let cm: Commit = serde_json::from_value(c["commit"].clone()).unwrap();
            cm.verify().is_ok()
        }
        "payload-decrypt" => {
            let a = &c["aad"];
            let parents: Vec<[u8; 32]> = arr(a, "parents").iter().map(|p| b64_32(p.as_str().unwrap())).collect();
            let aad = aad_v2(
                s(a, "repoId"),
                a["keyEpoch"].as_i64().unwrap(),
                &b64_32(s(a, "author")),
                &parents,
            )
            .unwrap();
            let iv: [u8; 12] = b64(s(c, "ivB64")).try_into().unwrap();
            crypto::aes_gcm_open(&unhex32(s(c, "dataKeyHex")), &iv, &b64(s(c, "ciphertextB64")), &aad).is_ok()
        }
        "acceptance-verify" => {
            let acc: Acceptance = serde_json::from_value(c["acceptance"].clone()).unwrap();
            acc.verify_under(&b64_32(s(c, "verifyHostKey"))).is_ok()
        }
        "leave-verify" => {
            let leave: LeaveRequest = serde_json::from_value(c["leave"].clone()).unwrap();
            leave.verify().is_ok()
        }
        "challenge-verify" => {
            let sig: [u8; 64] = b64(s(c, "signature")).try_into().unwrap();
            verify_challenge(
                &b64_32(s(c, "hostKey")),
                &b64_32(s(c, "ed25519PublicKey")),
                &b64(s(c, "nonce")),
                &sig,
            )
            .is_ok()
        }
        op => panic!("unknown op {op}"),
    }
}

#[test]
fn negative() {
    let file = load("negative.json");
    let cases = arr(&file, "cases");
    // 23 cases, the six strict Ed25519 rejects of SPEC 2, then the five challenge cases (SPEC 3.3, 4.1).
    assert_eq!(cases.len(), 34);
    let names: Vec<&str> = cases.iter().map(|c| s(c, "name")).collect();
    for n in [
        "challenge/signature-presented-as-commit-signature",
        "challenge/commit-sig-message-as-nonce",
        "challenge/commit-signature-presented-as-challenge",
        "challenge/made-for-other-host-key",
        "challenge/signature-over-raw-nonce",
    ] {
        assert!(names[29..].contains(&n), "missing or misplaced negative {n}");
    }
    let mut with_base = 0;
    for c in cases {
        let name = s(c, "name");
        assert_eq!(s(c, "expect"), "reject");
        assert!(!accepted(c), "{name} must be rejected");
        if let Some(base) = c.get("base") {
            let mut restored = c.clone();
            for (k, v) in base.as_object().unwrap() {
                restored[k] = v.clone();
            }
            assert!(accepted(&restored), "{name}: the unmutated base must be accepted");
            with_base += 1;
        } else {
            assert!(
                ["key-unwrap", "ed25519-verify"].contains(&s(c, "op")),
                "{name}: every 0.5 case carries a base"
            );
        }
    }
    assert_eq!(with_base, 20);
}
