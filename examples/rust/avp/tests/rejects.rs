// SPDX-License-Identifier: MIT

//! Reject paths below the rules engine: decoders refuse binary fields of the wrong length (SPEC
//! 6.1 rule 1, 7.1), tokens refuse a bad outer encoding or `v` (SPEC 11.1), and
//! `mnemonic_to_entropy` refuses every phrase SPEC 3.1 says a client MUST reject.

use std::fs;

use avp::AvpError;
use avp::commit::Commit;
use avp::encoding::Ce;
use avp::manifest::{SignedManifest, WrappedKey};
use avp::owner::mnemonic_to_entropy;
use avp::tokens::{LeaveRequest, LinkRequest, decode_token};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = format!("{}/../../../vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

/// The base64 of `n` bytes of `0x01`.
fn bytes_b64(n: usize) -> Value {
    Value::String(STANDARD.encode(vec![1u8; n]))
}

// ─── Decoder length checks ──────────────────────────────────────────────────────────────

#[test]
fn commit_decoder_checks_lengths() {
    let file = load("commit.json");
    let base = file["cases"][1]["commit"].clone();
    serde_json::from_value::<Commit>(base.clone()).unwrap();
    for (field, bad) in [
        ("commitId", 31),
        ("commitId", 33),
        ("manifestHash", 31),
        ("author", 0),
        ("iv", 11),
        ("iv", 13),
        ("authorSignature", 63),
        ("authorSignature", 65),
    ] {
        let mut c = base.clone();
        c[field] = bytes_b64(bad);
        assert!(serde_json::from_value::<Commit>(c).is_err(), "{field} of {bad} bytes");
    }
    let mut c = base.clone();
    c["parents"] = Value::Array(vec![bytes_b64(31)]);
    assert!(serde_json::from_value::<Commit>(c).is_err(), "a 31-byte parent id");
    let mut c = base.clone();
    c["iv"] = Value::String("not base64!".into());
    assert!(serde_json::from_value::<Commit>(c).is_err(), "iv that is not base64");
    let mut c = base;
    c["manifestSeq"] = serde_json::json!(1.5);
    assert!(
        serde_json::from_value::<Commit>(c).is_err(),
        "a non-integer manifestSeq"
    );
}

#[test]
fn manifest_decoder_checks_lengths() {
    let file = load("manifest.json");
    let base = file["cases"][2]["signedManifest"].clone();
    serde_json::from_value::<SignedManifest>(base.clone()).unwrap();
    let mutations = [
        ("/ownerSignature", 63),
        ("/state/ownerKey", 31),
        ("/state/hosts/0/hostKey", 33),
        ("/state/members/0/ed25519PublicKey", 31),
        ("/state/members/0/x25519PublicKey", 31),
        ("/state/members/0/homeHostKey", 0),
        ("/state/members/0/wrappedDataKey/ephemeralPublicKey", 31),
        ("/state/members/0/wrappedDataKey/iv", 11),
        ("/state/removals/0/memberKey", 31),
        ("/state/removals/0/frontier/0", 31),
    ];
    for (pointer, len) in mutations {
        let mut m = base.clone();
        *m.pointer_mut(pointer).unwrap() = bytes_b64(len);
        assert!(
            serde_json::from_value::<SignedManifest>(m).is_err(),
            "{pointer} of {len} bytes"
        );
    }
}

#[test]
fn wrapped_key_decoder_checks_lengths() {
    let wire = load("key-wrap.json")["cases"][0]["wrappedKey"].clone();
    serde_json::from_value::<WrappedKey>(wire.clone()).unwrap();
    for (field, bad) in [("ephemeralPublicKey", 31), ("iv", 12 + 1)] {
        let mut w = wire.clone();
        w[field] = bytes_b64(bad);
        assert!(serde_json::from_value::<WrappedKey>(w).is_err(), "{field}");
    }
}

#[test]
fn leave_decoder_checks_lengths() {
    let wire = load("federation.json")["leaves"][0]["decoded"].clone();
    serde_json::from_value::<LeaveRequest>(wire.clone()).unwrap();
    for (field, bad) in [("memberKey", 31), ("signature", 63)] {
        let mut l = wire.clone();
        l[field] = bytes_b64(bad);
        assert!(serde_json::from_value::<LeaveRequest>(l).is_err(), "{field}");
    }
}

#[test]
fn token_decoder_rejects_bad_outer_encoding() {
    let good = URL_SAFE_NO_PAD.encode(format!(
        r#"{{"v":2,"ephemeralPublicKey":"{}"}}"#,
        STANDARD.encode([5u8; 32])
    ));
    decode_token::<LinkRequest>(&good).unwrap();
    // Padding, the standard alphabet, and non-JSON are all refused.
    assert!(decode_token::<LinkRequest>(&format!("{good}=")).is_err());
    assert!(decode_token::<LinkRequest>(&format!("{}+/", &good[..good.len() - 2])).is_err());
    assert!(decode_token::<LinkRequest>(&URL_SAFE_NO_PAD.encode("not json")).is_err());
    assert!(
        decode_token::<LinkRequest>(&URL_SAFE_NO_PAD.encode(r#"{"v":2}"#)).is_err(),
        "a missing field"
    );
    let short = URL_SAFE_NO_PAD.encode(format!(
        r#"{{"v":2,"ephemeralPublicKey":"{}"}}"#,
        STANDARD.encode([5u8; 31])
    ));
    assert!(decode_token::<LinkRequest>(&short).is_err(), "a 31-byte key");
}

#[test]
fn ce_count_and_lengths_are_u32() {
    // Within range the writer is exact (SPEC 4.1); the u32 bound itself is checked in the writer.
    let mut w = Ce::new("t");
    w.count(0xffff_ffff);
    assert_eq!(w.finish().unwrap(), [0x74, 0x00, 0xff, 0xff, 0xff, 0xff]);
}

// ─── mnemonic_to_entropy (SPEC 3.1) ─────────────────────────────────────────────────────

const VALID: &str = "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length";

#[test]
fn mnemonic_valid_decodes() {
    let e = mnemonic_to_entropy(VALID).unwrap();
    assert_eq!(e[0], 0x68);
    assert_eq!(e[31], 0x7c);
}

#[test]
fn mnemonic_rejects_wrong_word_count() {
    let words: Vec<&str> = VALID.split(' ').collect();
    let cases = [
        words[..23].join(" "),
        format!("{VALID} abandon"),
        // A valid 12-word BIP39 phrase (128 bits) is not an AVP phrase.
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
        String::new(),
    ];
    for phrase in cases {
        assert!(
            matches!(mnemonic_to_entropy(&phrase), Err(AvpError::BadEncoding(_))),
            "{phrase:?}"
        );
    }
}

#[test]
fn mnemonic_rejects_unknown_word() {
    let mut words: Vec<&str> = VALID.split(' ').collect();
    words[5] = "notaword";
    assert!(matches!(
        mnemonic_to_entropy(&words.join(" ")),
        Err(AvpError::BadEncoding(_))
    ));
    // A doubled space is an empty word, which is not in the list.
    let words: Vec<&str> = VALID.split(' ').collect();
    let doubled = format!("{}  {}", words[..22].join(" "), words[23]);
    assert!(matches!(mnemonic_to_entropy(&doubled), Err(AvpError::BadEncoding(_))));
    // Case matters: the list is lowercase.
    assert!(matches!(
        mnemonic_to_entropy(&VALID.replacen("hamster", "Hamster", 1)),
        Err(AvpError::BadEncoding(_))
    ));
}

#[test]
fn mnemonic_rejects_bad_checksum() {
    // 24 x "abandon" is all-zero entropy, whose checksum word is "art", not "abandon".
    let zeros = vec!["abandon"; 24].join(" ");
    assert!(matches!(mnemonic_to_entropy(&zeros), Err(AvpError::BadChecksum)));
    // Changing only the last word (which carries the checksum bits) fails the checksum.
    let mut words: Vec<&str> = VALID.split(' ').collect();
    words[23] = "zoo";
    assert!(matches!(
        mnemonic_to_entropy(&words.join(" ")),
        Err(AvpError::BadChecksum)
    ));
}
