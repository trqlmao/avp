// SPDX-License-Identifier: MIT

//! `avp-reference-server`: the AVP 0.5 reference host binary.
//!
//! Listens on `0.0.0.0:$PORT` (default 8787). The host key comes from `AVP_HOST_SEED` (64 hex
//! digits, the 32-byte Ed25519 seed) or is random for each start. Peers come from `AVP_PEERS`
//! (`<base64 hostKey>@<http base url>,...`, SPEC 9.3); `AVP_TEST_CONTROL=1` enables the test control
//! route. A bad value exits with code 1 and a message. Request bodies are never logged.

use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use avp::crypto::random_bytes;
use avp::encoding::b64_encode;
use avp_reference_server::replication::{Peers, run};
use avp_reference_server::{DEFAULT_PORT, State, parse_host_seed, serve};
use ed25519_dalek::SigningKey;

fn main() -> ExitCode {
    let port = match std::env::var("PORT") {
        Ok(text) => match text.trim().parse::<u16>() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("PORT must be a port number");
                return ExitCode::FAILURE;
            }
        },
        Err(_) => DEFAULT_PORT,
    };
    let seed = match std::env::var("AVP_HOST_SEED") {
        Ok(hex) => match parse_host_seed(&hex) {
            Ok(seed) => seed,
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::FAILURE;
            }
        },
        Err(_) => random_bytes::<32>(),
    };
    let peers = match Peers::from_env(&std::env::var("AVP_PEERS").unwrap_or_default()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let mut state = State::new(SigningKey::from_bytes(&seed));
    state.replication.test_control = std::env::var("AVP_TEST_CONTROL").is_ok_and(|v| v.trim() == "1");
    let host_key = b64_encode(&state.host_key());
    let state = Arc::new(Mutex::new(state));
    let serving = match serve(&format!("0.0.0.0:{port}"), Arc::clone(&state)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot listen on port {port}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let peer_count = peers.len();
    let replication = match run(state, peers) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cannot start replication: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "AVP 0.5 reference host listening on http://{}, host key {host_key}, {peer_count} peer(s)",
        serving.addr()
    );
    serving.wait();
    drop(replication);
    ExitCode::SUCCESS
}
