// SPDX-License-Identifier: MIT

//! Host acceptance rules (SPEC 6, 7, 8.3, 8.4) against `vectors/acceptance.json`, run through the
//! `RepoView` rules engine.
//!
//! Every step's `expect`, and every scenario's `finalHeads`, `finalHeld`, `finalTip`, and
//! `finalLeaves`, is literal data written by hand from the SPEC rule the scenario cites; this file
//! only replays the steps and compares. No scenario is skipped, filtered, or special-cased.

use std::fs;

use avp::RejectCode;
use avp::commit::{Commit, CommitHeader};
use avp::manifest::{MemberEntry, SignedManifest};
use avp::rules::{RepoView, Via};
use avp::tokens::LeaveRequest;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::SigningKey;
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = format!("{}/../../../vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}

fn b64_32(s: &str) -> [u8; 32] {
    STANDARD.decode(s).unwrap().try_into().unwrap()
}

fn unhex32(s: &str) -> [u8; 32] {
    let v: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    v.try_into().unwrap()
}

fn code(r: Result<(), RejectCode>) -> String {
    match r {
        Ok(()) => "ok".into(),
        Err(c) => c.as_str().into(),
    }
}

fn via(step: &Value) -> Via {
    match step["via"].as_str().unwrap() {
        "push" => Via::Push,
        "offer" => Via::Offer,
        v => panic!("unknown via {v}"),
    }
}

/// Decodes a wire item. A body that does not decode (for example a binary field of the wrong
/// length) is malformed, which a host answers with `400 bad_request` before the engine runs (SPEC
/// 6.1 rule 1, 7.1, 10.4).
fn decode<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T, RejectCode> {
    serde_json::from_value(v.clone()).map_err(|_| RejectCode::BadRequest)
}

fn apply(view: &mut RepoView, step: &Value) -> Result<(), RejectCode> {
    let item = &step["item"];
    match step["op"].as_str().unwrap() {
        "manifest" => {
            let m: SignedManifest = decode(&item["manifest"])?;
            let c: Option<Commit> = match item.get("commit") {
                Some(c) => Some(decode(c)?),
                None => None,
            };
            view.apply_manifest_with(m, c, via(step))
        }
        "commit" => view.apply_commit_via(decode(item)?, via(step)),
        "leave" => view.apply_leave_via(decode(item)?, via(step)),
        op => panic!("unknown op {op}"),
    }
}

fn sorted(v: &Value) -> Vec<String> {
    let mut out: Vec<String> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect();
    out.sort();
    out
}

fn sorted_ids(ids: Vec<[u8; 32]>) -> Vec<String> {
    let mut out: Vec<String> = ids.iter().map(|i| b64(i)).collect();
    out.sort();
    out
}

#[test]
fn acceptance_scenarios() {
    let file = load("acceptance.json");
    let scenarios = file["scenarios"].as_array().unwrap();
    assert_eq!(scenarios.len(), 78);
    for sc in scenarios {
        let name = sc["name"].as_str().unwrap();
        let bound = usize::try_from(sc["headBound"].as_u64().unwrap()).unwrap();
        let mut view = RepoView::new(b64_32(sc["hostKey"].as_str().unwrap()), bound);
        for (i, step) in sc["steps"].as_array().unwrap().iter().enumerate() {
            let got = code(apply(&mut view, step));
            assert_eq!(
                got,
                step["expect"].as_str().unwrap(),
                "{name}: step {i} ({} {} via {})",
                step["op"],
                step["label"],
                step["via"]
            );
        }
        assert_eq!(
            sorted_ids(view.heads()),
            sorted(&sc["finalHeads"]),
            "{name}: final heads"
        );
        assert_eq!(sorted_ids(view.held()), sorted(&sc["finalHeld"]), "{name}: final held");
        let tip = view.tip().map(|t| b64(&t.hash().unwrap()));
        assert_eq!(tip.as_deref(), sc["finalTip"].as_str(), "{name}: final tip");
        if let Some(want) = sc.get("finalLeaves") {
            let mut got: Vec<(String, i64)> = view.leaves().iter().map(|l| (b64(&l.member_key), l.at)).collect();
            got.sort();
            let mut want: Vec<(String, i64)> = want
                .as_array()
                .unwrap()
                .iter()
                .map(|l| (l["memberKey"].as_str().unwrap().to_string(), l["at"].as_i64().unwrap()))
                .collect();
            want.sort();
            assert_eq!(got, want, "{name}: final leaves");
        }
    }
}

// ─── Diverged owner states (SPEC 6.5) ───────────────────────────────────────────────────

struct Fixture {
    host_a: [u8; 32],
    owner: SigningKey,
    genesis: SignedManifest,
    root: Commit,
    alice: MemberEntry,
    carol: MemberEntry,
}

fn fixture() -> Fixture {
    let manifest = load("manifest.json");
    let commits = load("commit.json");
    let seeds = &manifest["seeds"];
    let owner = SigningKey::from_bytes(&unhex32(seeds["owner"]["ed25519SeedHex"].as_str().unwrap()));
    let cases = manifest["cases"].as_array().unwrap();
    let genesis: SignedManifest = serde_json::from_value(cases[0]["signedManifest"].clone()).unwrap();
    let add: SignedManifest = serde_json::from_value(cases[1]["signedManifest"].clone()).unwrap();
    let member = |label: &str| {
        let key = seeds["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["label"] == label)
            .unwrap();
        let k = b64_32(key["ed25519PublicKey"].as_str().unwrap());
        add.state
            .members
            .iter()
            .find(|m| m.ed25519_public_key == k)
            .unwrap()
            .clone()
    };
    let root: Commit = serde_json::from_value(commits["cases"][0]["commit"].clone()).unwrap();
    let host_a = b64_32(seeds["hosts"][0]["hostKey"].as_str().unwrap());
    Fixture {
        host_a,
        owner,
        genesis,
        root,
        alice: member("alice"),
        carol: member("carol"),
    }
}

/// A seq 2 state on genesis that adds `member`.
fn seq2(f: &Fixture, member: &MemberEntry) -> SignedManifest {
    let mut s = f.genesis.state.clone();
    s.manifest_seq = 2;
    s.prev_manifest_hash = f.genesis.hash().unwrap().to_vec();
    s.genesis_nonce = Vec::new();
    s.members.push(member.clone());
    s.sign(&f.owner).unwrap()
}

#[test]
fn diverged_owner_states_converge() {
    let f = fixture();
    let x = seq2(&f, &f.alice);
    let y = seq2(&f, &f.carol);
    let (xh, yh) = (x.hash().unwrap(), y.hash().unwrap());
    assert_ne!(xh, yh);
    let lower = xh.min(yh);

    let mut tips = Vec::new();
    for order in [[&x, &y], [&y, &x]] {
        let mut view = RepoView::new(f.host_a, 16);
        view.apply_manifest_with(f.genesis.clone(), Some(f.root.clone()), Via::Push)
            .unwrap();
        // Both arrive by replication; the first appends to the tip, the second meets the tie rule.
        let first = view.apply_manifest_with(order[0].clone(), None, Via::Offer);
        let second = view.apply_manifest_with(order[1].clone(), None, Via::Offer);
        assert_eq!(first, Ok(()));
        let second_wins = order[1].hash().unwrap() == lower;
        assert_eq!(
            second,
            if second_wins {
                Ok(())
            } else {
                Err(RejectCode::ManifestConflict)
            }
        );
        let tip = view.tip().unwrap().hash().unwrap();
        assert_eq!(tip, lower, "the bytewise-lower manifestHash wins (SPEC 6.5)");
        // The loser is retained as a verified losing state and served by manifest hash.
        let loser = if lower == xh { yh } else { xh };
        assert!(view.manifest(&loser).is_some());
        let chain = view.chain_to(&loser).unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].hash().unwrap(), f.genesis.hash().unwrap());
        tips.push(tip);
    }
    assert_eq!(tips[0], tips[1], "both orders converge on the same tip");
}

#[test]
fn diverged_owner_commit_by_member_of_both_is_accepted() {
    // Review focus 1: a commit citing the losing state by an author who is a member at that epoch in
    // the winner is accepted after the re-check, not dropped (SPEC 6.5). Both states keep the owner.
    let f = fixture();
    let x = seq2(&f, &f.alice);
    let y = seq2(&f, &f.carol);
    let (winner, loser) = if x.hash().unwrap() < y.hash().unwrap() {
        (x, y)
    } else {
        (y, x)
    };
    let owner_commit = |cites: &SignedManifest| {
        let header = CommitHeader {
            repo_id: cites.state.repo_id.clone(),
            parents: vec![f.root.commit_id],
            manifest_seq: 2,
            manifest_hash: cites.hash().unwrap(),
            key_epoch: 0,
        };
        Commit::seal(&[0x42; 32], header, br#"{"v":2,"accounts":{}}"#, &f.owner).unwrap()
    };

    let mut view = RepoView::new(f.host_a, 16);
    view.apply_manifest_with(f.genesis.clone(), Some(f.root.clone()), Via::Push)
        .unwrap();
    view.apply_manifest_with(loser.clone(), None, Via::Offer).unwrap();
    let c = owner_commit(&loser);
    view.apply_commit(c.clone()).unwrap();
    assert_eq!(view.heads(), vec![c.commit_id]);
    // The winner replaces the loser; the commit is re-checked against the winner at seq 2.
    view.apply_manifest_with(winner.clone(), None, Via::Offer).unwrap();
    assert_eq!(view.tip().unwrap().hash().unwrap(), winner.hash().unwrap());
    assert_eq!(view.heads(), vec![c.commit_id], "still a head after the switch");
    assert!(view.held().is_empty());
}

#[test]
fn engine_reports_what_a_missing_parents_answer_lacks() {
    let f = fixture();
    let mut view = RepoView::new(f.host_a, 16);
    view.apply_manifest_with(f.genesis.clone(), Some(f.root.clone()), Via::Push)
        .unwrap();
    let unknown_parent = [7u8; 32];
    let unknown_state = [9u8; 32];
    let header = CommitHeader {
        repo_id: f.genesis.state.repo_id.clone(),
        parents: vec![unknown_parent],
        manifest_seq: 1,
        manifest_hash: f.genesis.hash().unwrap(),
        key_epoch: 0,
    };
    let c = Commit::seal(&[0x42; 32], header.clone(), b"{}", &f.owner).unwrap();
    assert_eq!(view.apply_commit(c.clone()), Err(RejectCode::MissingParents));
    assert_eq!(view.missing_for(&c), vec![unknown_parent]);

    let header = CommitHeader {
        manifest_seq: 2,
        manifest_hash: unknown_state,
        parents: vec![f.root.commit_id],
        ..header
    };
    let c = Commit::seal(&[0x42; 32], header, b"{}", &f.owner).unwrap();
    assert_eq!(view.apply_commit(c.clone()), Err(RejectCode::MissingParents));
    assert_eq!(view.missing_for(&c), vec![unknown_state]);
}

#[test]
fn pull_and_fetch_views() {
    let f = fixture();
    let mut view = RepoView::new(f.host_a, 16);
    assert!(view.tip().is_none());
    assert!(view.heads().is_empty());
    view.apply_manifest_with(f.genesis.clone(), Some(f.root.clone()), Via::Push)
        .unwrap();
    let x = seq2(&f, &f.alice);
    view.apply_manifest(x.clone()).unwrap();
    assert_eq!(view.manifests_since(0), vec![f.genesis.clone(), x.clone()]);
    assert_eq!(view.manifests_since(1), vec![x.clone()]);
    assert!(view.manifests_since(2).is_empty());
    assert_eq!(view.commits_since(&[]), vec![f.root.clone()]);
    assert!(view.commits_since(&[f.root.commit_id]).is_empty());
    assert_eq!(view.fetch_commit(&f.root.commit_id), Some(&f.root));
    assert_eq!(view.fetch_commit(&[1; 32]), None);
}

#[test]
fn malformed_leave_is_bad_request() {
    let f = fixture();
    let mut view = RepoView::new(f.host_a, 16);
    view.apply_manifest_with(f.genesis.clone(), Some(f.root.clone()), Via::Push)
        .unwrap();
    let leave = LeaveRequest {
        repo_id: f.genesis.state.repo_id.clone(),
        member_key: [3; 32],
        at: 0,
        signature: [0; 64],
    };
    assert_eq!(view.apply_leave(leave), Err(RejectCode::BadRequest));
    assert!(view.leaves().is_empty());
}

// ─── The hosted rule by path (SPEC 6.1 rule 6, 9.2, 10.1) ──────────────────────────────────

#[test]
fn tip_lists_host_follows_a_first_copy_by_replication() {
    let file = load("acceptance.json");
    let sc = file["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "new-host-first-copy-by-offer")
        .unwrap();
    let steps = sc["steps"].as_array().unwrap();
    let mut view = RepoView::new(b64_32(sc["hostKey"].as_str().unwrap()), 16);
    assert!(!view.tip_lists_host(), "no tip before genesis");
    // The genesis lists only b.vault.example: accepted by offer, but the tip does not list a.
    assert_eq!(apply(&mut view, &steps[0]), Ok(()));
    assert!(!view.tip_lists_host(), "the genesis does not list a.vault.example");
    // The seq 2 state adds a.vault.example.
    assert_eq!(apply(&mut view, &steps[1]), Ok(()));
    assert!(view.tip_lists_host(), "seq 2 lists a.vault.example");
}

#[test]
fn unlisted_genesis_is_not_hosted_on_push_and_taken_by_offer() {
    // The manifest.json genesis lists a.vault.example and b.vault.example; this host is neither.
    let f = fixture();
    let unlisted = [0x55; 32];
    assert!(!f.genesis.state.has_host(&unlisted));

    let mut pushed = RepoView::new(unlisted, 16);
    assert_eq!(
        pushed.apply_manifest_with(f.genesis.clone(), Some(f.root.clone()), Via::Push),
        Err(RejectCode::NotHosted)
    );
    assert!(pushed.tip().is_none(), "a rejected client write stores nothing");

    let mut offered = RepoView::new(unlisted, 16);
    assert_eq!(
        offered.apply_manifest_with(f.genesis.clone(), Some(f.root.clone()), Via::Offer),
        Ok(())
    );
    assert!(!offered.tip_lists_host(), "the host layer refuses to serve this tip");

    let mut listed = RepoView::new(f.host_a, 16);
    listed
        .apply_manifest_with(f.genesis.clone(), Some(f.root.clone()), Via::Push)
        .unwrap();
    assert!(listed.tip_lists_host());
}

// ─── A refused write leaves nothing behind (SPEC 7.1, 7.3) ─────────────────────────────────

/// A commit sealed by `author` on `parents`, citing `cites` at `seq`.
fn sealed(f: &Fixture, author: &SigningKey, parents: Vec<[u8; 32]>, seq: i64, cites: [u8; 32]) -> Commit {
    let header = CommitHeader {
        repo_id: f.genesis.state.repo_id.clone(),
        parents,
        manifest_seq: seq,
        manifest_hash: cites,
        key_epoch: 0,
    };
    Commit::seal(&[0x42; 32], header, b"{}", author).unwrap()
}

#[test]
fn removed_member_push_does_not_decide_a_cutoff() {
    let file = load("acceptance.json");
    let sc = file["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == "removed-member-ancestor-of-frontier")
        .unwrap();
    let steps = sc["steps"].as_array().unwrap();
    let mut view = RepoView::new(b64_32(sc["hostKey"].as_str().unwrap()), 16);
    // Up to bob's removal at seq 3 (frontier {a1, b1, b2}) and the first offer of b0, which waits for
    // frontier commit b2 (SPEC 7.3).
    for step in &steps[..6] {
        assert_eq!(code(apply(&mut view, step)), step["expect"].as_str().unwrap());
    }
    let b0: Commit = decode(&steps[5]["item"]).unwrap();
    let b2: Commit = decode(&steps[6]["item"]).unwrap();
    assert_eq!(view.missing_for(&b0), vec![b2.commit_id]);
    let before = format!("{view:?}");

    // bob is not a member of the tip, so his own push of b2 is refused (SPEC 7.1), and its header
    // does not decide b0's cutoff: nothing changed.
    assert_eq!(view.apply_commit(b2.clone()), Err(RejectCode::Forbidden));
    assert_eq!(format!("{view:?}"), before, "a refused caller changes nothing");
    assert_eq!(view.missing_for(&b0), vec![b2.commit_id]);
    assert_eq!(
        view.apply_commit_via(b0.clone(), Via::Offer),
        Err(RejectCode::MissingParents),
        "b0 still waits for b2"
    );

    // b2 by replication then decides it, as the scenario expects.
    for step in &steps[6..] {
        assert_eq!(code(apply(&mut view, step)), step["expect"].as_str().unwrap());
    }
    assert_eq!(sorted_ids(view.heads()), sorted(&sc["finalHeads"]));
}

#[test]
fn stranger_push_leaves_no_state() {
    let f = fixture();
    let mut view = RepoView::new(f.host_a, 16);
    view.apply_manifest_with(f.genesis.clone(), Some(f.root.clone()), Via::Push)
        .unwrap();
    let before = format!("{view:?}");
    let stranger = SigningKey::from_bytes(&[0x66; 32]);
    let parents: Vec<[u8; 32]> = (0..200u8).map(|j| [j; 32]).collect();
    let c = sealed(&f, &stranger, parents, 1, f.genesis.hash().unwrap());

    // The signature is checked first (400 before 403, SPEC 7.1).
    let mut forged = c.clone();
    forged.author_signature[0] ^= 1;
    assert_eq!(view.apply_commit(forged), Err(RejectCode::BadRequest));
    // A signed commit by a key the tip does not list is refused and stores nothing, its header
    // included.
    assert_eq!(view.apply_commit(c.clone()), Err(RejectCode::Forbidden));
    assert_eq!(format!("{view:?}"), before, "a refused caller changes nothing");
    assert_eq!(view.status(&c.commit_id), None);
}

#[test]
fn refused_publish_keeps_no_header_of_its_commit() {
    let f = fixture();
    let mut view = RepoView::new(f.host_a, 16);
    view.apply_manifest_with(f.genesis.clone(), Some(f.root.clone()), Via::Push)
        .unwrap();
    let before = format!("{view:?}");
    let x = seq2(&f, &f.alice);
    let c = sealed(&f, &f.owner, vec![[7; 32]], 2, x.hash().unwrap());
    // The state and its commit are applied together or not at all (SPEC 8.3): the commit's unknown
    // parent refuses both, and the commit's header is not kept either.
    assert_eq!(
        view.apply_manifest_with(x, Some(c), Via::Push),
        Err(RejectCode::MissingParents)
    );
    assert_eq!(format!("{view:?}"), before, "a refused publish changes nothing");
}
