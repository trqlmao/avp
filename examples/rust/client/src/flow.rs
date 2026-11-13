// SPDX-License-Identifier: MIT

//! The worked flow `main` runs against live hosts, printing one line per step.
//!
//! The owner creates a repository on host A and writes an account; bob prepares a join on his home
//! host (B when given, else A) and is invited; both write the same account concurrently and the
//! merge keeps both edits; bob leaves and the owner processes the leave as a removal; a new owner
//! device is linked and regenerates the same phrase. With two hosts, every step that crosses hosts
//! waits for replication.
//!
//! The phrase is printed once, at creation, as a client shows it by design (SPEC 3.1). No other
//! secret is printed.

use std::io::Write;
use std::thread;
use std::time::{Duration, Instant};

use avp::encoding::b64_encode;
use avp::payload::PayloadV2;
use avp::tokens::encode_token;
use serde_json::{Value, json};

use crate::link::{LinkSession, OwnerIdentity, approve};
use crate::sync::{HostClient, Member, Vault, now_ms, prepare_join, set_field};
use crate::{ClientError, Result};

/// The account the flow writes; a fixed player UUID.
const ACCOUNT: &str = "0b5e7f2a-5d1c-4a6e-9c1e-1f0d4a7b3c21";

/// How long a step waits for replication between hosts.
const WAIT: Duration = Duration::from_secs(60);

fn say(out: &mut dyn Write, line: &str) -> Result<()> {
    writeln!(out, "{line}").map_err(|e| ClientError::Flow(format!("cannot print: {e}")))
}

/// Retries `f` until it yields a value, for at most [`WAIT`]; the last error is returned if it
/// never does.
fn poll<T>(what: &str, mut f: impl FnMut() -> Result<Option<T>>) -> Result<T> {
    let deadline = Instant::now() + WAIT;
    loop {
        let last = match f() {
            Ok(Some(v)) => return Ok(v),
            Ok(None) => ClientError::Flow(format!("timed out waiting: {what}")),
            Err(e) => e,
        };
        if Instant::now() >= deadline {
            return Err(last);
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn field<'a>(p: &'a PayloadV2, name: &str) -> Option<&'a Value> {
    p.accounts.get(ACCOUNT)?.fields.get(name).map(|f| &f.value)
}

fn short(id: &[u8; 32]) -> String {
    b64_encode(id).chars().take(12).collect()
}

/// Runs the worked flow against host `url_a` and, when given, bob's home host `url_b` (which must
/// replicate with A).
///
/// # Errors
///
/// The first step that fails, or [`ClientError::Flow`] if a step does not end as expected.
pub fn run(url_a: &str, url_b: Option<&str>, out: &mut dyn Write) -> Result<()> {
    let host_a = HostClient::connect(url_a)?;
    say(
        out,
        &format!(
            "hosts: A at {} (host key {})",
            host_a.locator(),
            b64_encode(&host_a.key())
        ),
    )?;
    let bob_url = url_b.unwrap_or(url_a);
    if let Some(b) = url_b {
        let host_b = HostClient::connect(b)?;
        say(
            out,
            &format!(
                "hosts: B at {} (host key {})",
                host_b.locator(),
                b64_encode(&host_b.key())
            ),
        )?;
    }

    // Owner identity and repository creation (SPEC 3.1, 8.2).
    let owner_id = OwnerIdentity::generate()?;
    say(
        out,
        "create: new owner identity; recovery phrase, shown once (write it down):",
    )?;
    say(out, &format!("  {}", owner_id.mnemonic()))?;
    let mut owner = Vault::create(host_a, &owner_id.keys)?;
    let locator = owner.locator()?;
    say(
        out,
        &format!(
            "create: repository {} on A, owner fingerprint {}",
            owner.repo_id(),
            locator.owner_fingerprint
        ),
    )?;
    say(out, &format!("create: repo locator token {}", encode_token(&locator)?))?;

    let by = owner.member().id();
    owner.write(|p, hlc| {
        let s = hlc.tick(now_ms(), &by);
        set_field(p, ACCOUNT, "username", json!("alice-alt"), &s);
        set_field(p, ACCOUNT, "accessToken", json!("access-token-1"), &s);
        set_field(p, ACCOUNT, "type", json!("MICROSOFT"), &s);
        set_field(p, ACCOUNT, "sourceClient", json!("reference-client"), &s);
    })?;
    say(out, "write: owner added one account")?;

    // Invite (SPEC 8.1, 8.2).
    let bob = Member::generate();
    let mut bob_home = HostClient::connect(bob_url)?;
    let token = prepare_join(&mut bob_home, &bob, owner.repo_id())?;
    say(
        out,
        &format!(
            "invite: bob prepared a join on {} (key fingerprint {}), invite token {} chars",
            if url_b.is_some() { "B" } else { "A" },
            bob.fingerprint(),
            encode_token(&token)?.len()
        ),
    )?;
    owner.invite(&token)?;
    say(
        out,
        &format!(
            "invite: owner verified the acceptance and wrapped the data key to bob's key (fingerprint {}), seq {}",
            bob.fingerprint(),
            owner.tip().state.manifest_seq
        ),
    )?;
    let mut bob_vault = poll("bob's home host carries the repository", || {
        let v = Vault::join(HostClient::connect(bob_url)?, bob.clone(), &locator)?;
        Ok(field(v.payload(), "username").is_some().then_some(v))
    })?;
    say(
        out,
        &format!(
            "invite: bob joined and reads {} account(s)",
            bob_vault.payload().accounts.len()
        ),
    )?;

    // Concurrent writes and the merge (SPEC 5).
    let t = now_ms();
    owner.write(|p, hlc| {
        let s = hlc.tick(t, &by);
        set_field(p, ACCOUNT, "username", json!("alice-renamed"), &s);
    })?;
    let bob_id = bob.id();
    bob_vault.write(|p, hlc| {
        let s = hlc.tick(t, &bob_id);
        set_field(p, ACCOUNT, "lastUsed", json!(t), &s);
        set_field(p, ACCOUNT, "lastUsedBy", json!(bob_id.clone()), &s);
    })?;
    say(
        out,
        "write: owner renamed the account while bob marked it used, concurrently",
    )?;
    let merged = poll("the owner sees bob's write", || {
        let r = owner.pull()?;
        Ok((field(owner.payload(), "lastUsedBy").is_some()).then_some(r))
    })?;
    match merged.merge_commit {
        Some(id) => say(
            out,
            &format!("merge: owner merged two heads into commit {}", short(&id)),
        )?,
        None => say(out, "merge: owner already holds one head covering both writes")?,
    }
    let want = owner.payload().clone();
    poll("bob sees the merge", || {
        bob_vault.pull()?;
        Ok((*bob_vault.payload() == want).then_some(()))
    })?;
    let username = field(bob_vault.payload(), "username").cloned().unwrap_or(Value::Null);
    let used_by = field(bob_vault.payload(), "lastUsedBy").cloned().unwrap_or(Value::Null);
    if username != json!("alice-renamed") || used_by != json!(bob.id()) {
        return Err(ClientError::Flow("the merge lost an edit".into()));
    }
    say(
        out,
        &format!("merge: bob sees both edits, username {username}, lastUsedBy bob"),
    )?;

    // Leave (SPEC 8.4).
    bob_vault.leave()?;
    if !matches!(bob_vault.pull(), Err(ClientError::Left)) {
        return Err(ClientError::Flow("bob kept syncing after leaving".into()));
    }
    say(out, "leave: bob sent a signed leave request and stopped syncing")?;
    let removed = poll("the owner sees bob's leave request", || {
        let r = owner.process_leaves()?;
        Ok((!r.is_empty()).then_some(r))
    })?;
    say(
        out,
        &format!(
            "leave: owner processed {} leave request(s) as removal: seq {}, key epoch {}",
            removed.len(),
            owner.tip().state.manifest_seq,
            owner.tip().state.key_epoch
        ),
    )?;

    // Device linking (SPEC 11.6).
    let session = LinkSession::new();
    let code_new = session.confirmation_code()?;
    say(out, &format!("link: new device shows link request and code {code_new}"))?;
    let mut code_shown = String::new();
    let grant = approve(&owner_id.entropy, session.request(), |code| {
        code_shown = code.to_string();
        code == code_new
    })?;
    say(
        out,
        &format!("link: existing device shows code {code_shown}; the owner confirms they match"),
    )?;
    let linked = session.finish(&grant)?;
    if linked.mnemonic() != owner_id.mnemonic() {
        return Err(ClientError::Flow("the linked device derived another phrase".into()));
    }
    say(
        out,
        "link: the new device regenerated the same 24-word phrase and owner keys",
    )?;
    let linked_vault = Vault::open(
        HostClient::connect(url_a)?,
        Member::from_owner(&linked.keys),
        owner.repo_id(),
    )?;
    say(
        out,
        &format!(
            "link: the new device reads {} account(s) at seq {}",
            linked_vault.payload().accounts.len(),
            linked_vault.tip().state.manifest_seq
        ),
    )?;
    say(out, "done")?;
    Ok(())
}
