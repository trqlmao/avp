// SPDX-License-Identifier: MIT

//! `avp-reference-client`: runs the AVP 0.5 worked flow against live hosts and prints each step.
//!
//! `AVP_SERVER_URL` is the owner's host (default `http://localhost:8787`). With
//! `AVP_SERVER_URL_B` set, bob's home host is that second host, which must replicate with the
//! first. Exits 0 when every step succeeds and 1 with the error otherwise.

use std::io;
use std::process::ExitCode;

use avp_reference_client::flow;

fn main() -> ExitCode {
    let url_a = std::env::var("AVP_SERVER_URL").unwrap_or_else(|_| "http://localhost:8787".to_string());
    let url_b = std::env::var("AVP_SERVER_URL_B").ok().filter(|u| !u.trim().is_empty());
    let mut out = io::stdout().lock();
    match flow::run(&url_a, url_b.as_deref(), &mut out) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
