// SPDX-License-Identifier: MIT

//! `avp-reference-server`: the AVP 0.5 reference host binary.
//!
//! Listens on `0.0.0.0:$PORT` (default 8787). The host key comes from `AVP_HOST_SEED` (64 hex
//! digits, the 32-byte Ed25519 seed) or is random for each start. Request bodies are never logged.

use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use avp::crypto::random_bytes;
use avp::encoding::b64_encode;
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
    let state = State::new(SigningKey::from_bytes(&seed));
    let host_key = b64_encode(&state.host_key());
    let serving = match serve(&format!("0.0.0.0:{port}"), Arc::new(Mutex::new(state))) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot listen on port {port}: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "AVP 0.5 reference host listening on http://{}, host key {host_key}",
        serving.addr()
    );
    serving.wait();
    ExitCode::SUCCESS
}
