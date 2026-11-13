// SPDX-License-Identifier: MIT

//! Payload v2 merge, deletion, refresh-token stripping, and the hybrid logical clock (SPEC 5, 5.1)
//! against `vectors/merge.json`.
//!
//! Every `expected` in merge.json is hand-written from the SPEC 5 merge rule, not produced by the
//! merge under test. Each case is checked for every permutation of its inputs, for idempotence, and
//! for associativity over every ordered triple of inputs.

use std::fs;

use avp::payload::{Account, Field, Hlc, PayloadV2, Stamp, merge};
use serde_json::Value;

fn load() -> Value {
    let path = format!("{}/../../../vectors/merge.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

struct Case {
    name: String,
    strip: bool,
    inputs: Vec<PayloadV2>,
    expected: PayloadV2,
    expected_deleted: Vec<(String, bool)>,
}

fn cases() -> Vec<Case> {
    let file = load();
    let cases = file["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 9);
    cases
        .iter()
        .map(|c| {
            let expected: PayloadV2 = serde_json::from_value(c["expected"].clone()).unwrap();
            // The payload type round-trips the hand-written JSON exactly.
            assert_eq!(serde_json::to_value(&expected).unwrap(), c["expected"]);
            Case {
                name: c["name"].as_str().unwrap().to_string(),
                strip: c["stripRefresh"].as_bool().unwrap_or(false),
                inputs: c["inputs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| serde_json::from_value(p.clone()).unwrap())
                    .collect(),
                expected,
                expected_deleted: c["expectedDeleted"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(k, v)| (k.clone(), v.as_bool().unwrap()))
                    .collect(),
            }
        })
        .collect()
}

fn finish(c: &Case, mut p: PayloadV2) -> PayloadV2 {
    if c.strip {
        p.strip_refresh();
    }
    p
}

fn permutations<T: Clone>(xs: &[T]) -> Vec<Vec<T>> {
    if xs.len() <= 1 {
        return vec![xs.to_vec()];
    }
    let mut out = Vec::new();
    for i in 0..xs.len() {
        let mut rest = xs.to_vec();
        let x = rest.remove(i);
        for mut p in permutations(&rest) {
            p.insert(0, x.clone());
            out.push(p);
        }
    }
    out
}

#[test]
fn merge_vectors_all_permutations() {
    for c in cases() {
        assert!(c.inputs.len() >= 2, "{}", c.name);
        for perm in permutations(&c.inputs) {
            assert_eq!(finish(&c, merge(&perm)), c.expected, "{}", c.name);
        }
    }
}

#[test]
fn merge_is_idempotent() {
    for c in cases() {
        for input in c.inputs.iter().chain([&c.expected]) {
            assert_eq!(
                finish(&c, merge(&[c.expected.clone(), input.clone()])),
                c.expected,
                "{}",
                c.name
            );
            assert_eq!(
                finish(&c, merge(&[input.clone(), c.expected.clone()])),
                c.expected,
                "{}",
                c.name
            );
        }
        for input in &c.inputs {
            assert_eq!(
                merge(&[input.clone(), input.clone()]),
                merge(std::slice::from_ref(input)),
                "{}",
                c.name
            );
        }
    }
}

#[test]
fn merge_is_associative() {
    for c in cases() {
        for a in &c.inputs {
            for b in &c.inputs {
                for d in &c.inputs {
                    let left = merge(&[merge(&[a.clone(), b.clone()]), d.clone()]);
                    let right = merge(&[a.clone(), merge(&[b.clone(), d.clone()])]);
                    assert_eq!(left, right, "{}", c.name);
                    assert_eq!(left, merge(&[a.clone(), b.clone(), d.clone()]), "{}", c.name);
                }
            }
        }
    }
}

#[test]
fn merge_deletion_state() {
    for c in cases() {
        let merged = finish(&c, merge(&c.inputs));
        let mut uuids: Vec<&String> = merged.accounts.keys().collect();
        uuids.sort();
        let mut named: Vec<&String> = c.expected_deleted.iter().map(|(k, _)| k).collect();
        named.sort();
        assert_eq!(uuids, named, "{}", c.name);
        for (uuid, deleted) in &c.expected_deleted {
            assert_eq!(merged.accounts[uuid].is_deleted(), *deleted, "{} {uuid}", c.name);
        }
    }
}

#[test]
fn strip_after_policy_off_removes_both_fields() {
    let all = cases();
    let c = all.iter().find(|c| c.name == "strip-after-policy-off").unwrap();
    assert!(c.strip);
    let has = |p: &PayloadV2, f: &str| p.accounts.values().any(|a| a.fields.contains_key(f));
    let unstripped = merge(&c.inputs);
    let mut stripped = unstripped.clone();
    stripped.strip_refresh();
    for f in ["refreshToken", "expiresAt"] {
        assert!(c.inputs.iter().any(|p| has(p, f)), "an input carries {f}");
        assert!(has(&unstripped, f), "the unstripped merge carries {f}");
        assert!(!has(&stripped, f), "the stripped merge carries no {f}");
        assert!(!has(&c.expected, f));
    }
}

#[test]
fn strip_then_deleted() {
    let all = cases();
    let c = all.iter().find(|c| c.name == "strip-then-deleted").unwrap();
    let merged = merge(&c.inputs);
    let uuid = &c.expected_deleted[0].0;
    assert!(!merged.accounts[uuid].is_deleted());
    let mut stripped = merged.clone();
    stripped.strip_refresh();
    assert!(stripped.accounts[uuid].is_deleted());
}

#[test]
fn deletion_needs_a_strictly_greater_stamp() {
    let stamp = |at: i64, n: i64| Stamp { at, n, by: "x".into() };
    let field = |at: i64, n: i64| Field {
        value: Value::String("u".into()),
        at,
        n,
        by: "x".into(),
    };
    let mut a = Account {
        deleted: Some(stamp(10, 0)),
        ..Account::default()
    };
    a.fields.insert("username".into(), field(10, 0));
    assert!(!a.is_deleted(), "an equal stamp does not delete");
    a.deleted = Some(stamp(10, 1));
    assert!(a.is_deleted());
    let mut b = Account {
        deleted: Some(stamp(10, 0)),
        ..Account::default()
    };
    b.bans.insert(
        "srv".into(),
        Field {
            value: Value::Null,
            at: 11,
            n: 0,
            by: "x".into(),
        },
    );
    assert!(!b.is_deleted(), "a later ban stamp revives the account");
    assert!(!Account::default().is_deleted());
}

#[test]
fn stamps_compare_by_utf8_bytes() {
    // "Z" (0x5a) sorts before "a" (0x61) by bytes; a case-insensitive compare would invert it.
    let p = |by: &str, value: &str| {
        let mut a = Account::default();
        a.fields.insert(
            "username".into(),
            Field {
                value: Value::String(value.into()),
                at: 1,
                n: 0,
                by: by.into(),
            },
        );
        let mut p = PayloadV2::default();
        p.accounts.insert("u".into(), a);
        p
    };
    let merged = merge(&[p("a", "lower"), p("Z", "upper")]);
    assert_eq!(
        merged.accounts["u"].fields["username"].value,
        Value::String("lower".into())
    );
}

#[test]
fn payload_with_other_version_is_unreadable() {
    assert!(serde_json::from_str::<PayloadV2>(r#"{"v":1,"accounts":{}}"#).is_err());
    assert!(serde_json::from_str::<PayloadV2>(r#"{"accounts":{}}"#).is_err());
    let p: PayloadV2 = serde_json::from_str(r#"{"v":2,"accounts":{}}"#).unwrap();
    assert_eq!(serde_json::to_string(&p).unwrap(), r#"{"v":2,"accounts":{}}"#);
}

#[test]
fn hlc_tick_and_observe() {
    let by = "0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc=";
    let mut clock = Hlc::default();
    clock.observe(&Stamp {
        at: 9,
        n: 2,
        by: by.into(),
    });
    assert_eq!(
        clock.tick(5, by),
        Stamp {
            at: 9,
            n: 3,
            by: by.into()
        }
    );
    assert_eq!(
        clock.tick(10, by),
        Stamp {
            at: 10,
            n: 0,
            by: by.into()
        }
    );
}

#[test]
fn hlc_vectors() {
    let file = load();
    let cases = file["hlc"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for h in cases {
        let name = h["name"].as_str().unwrap();
        let mut clock = Hlc {
            at: h["start"]["at"].as_i64().unwrap(),
            n: h["start"]["n"].as_i64().unwrap(),
        };
        for (i, step) in h["steps"].as_array().unwrap().iter().enumerate() {
            let want = (
                step["expect"]["at"].as_i64().unwrap(),
                step["expect"]["n"].as_i64().unwrap(),
            );
            match step["op"].as_str().unwrap() {
                "tick" => {
                    let st = clock.tick(step["now"].as_i64().unwrap(), "me");
                    assert_eq!((st.at, st.n), want, "{name} step {i} tick result");
                }
                "observe" => {
                    let stamp: Stamp = serde_json::from_value(step["stamp"].clone()).unwrap();
                    clock.observe(&stamp);
                }
                op => panic!("unknown op {op}"),
            }
            assert_eq!((clock.at, clock.n), want, "{name} step {i}");
        }
    }
}
