// SPDX-License-Identifier: MIT

//! In-memory AVP 0.5 reference host, HTTP/JSON profile, client-facing API.
//!
//! The host is a thin layer over the shared `avp` crate: [`api`] authenticates the caller, decodes
//! the body, checks the caller identity each operation requires (SPEC 10.1), and hands the item to
//! [`avp::rules::RepoView`], which does every SPEC 6 and 7 check. The host maps the engine's
//! [`avp::RejectCode`] to the SPEC 10.4 status table and adds the answers the engine does not give
//! (`401`, `404 not_found`, `409 duplicate_repo`, `413 too_large`, `429 quota_exceeded`).
//!
//! It is zero-knowledge: it stores only manifest states (public keys, wrapped keys, counters, owner
//! signatures), commits (ciphertext, ids, signatures), and leave requests. It never holds a data
//! key, decrypts nothing, and never logs a request body.
//!
//! - [`auth`]: the host-issued challenge and token flow (SPEC 3.3).
//! - [`store`]: the repositories and the acceptances this host issued.
//! - [`api`]: routing and the per-operation rules of SPEC 10.
//!
//! Illustrative reference code, not production: state lives in memory and there is no TLS.

#![warn(missing_docs)]

pub mod api;
pub mod auth;
pub mod store;

use std::io;
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use tiny_http::Server;

use crate::auth::Auth;
use crate::store::Store;

/// The default port of the binary (`PORT` overrides it).
pub const DEFAULT_PORT: u16 = 8787;

/// The number of worker threads that take requests off the listener.
const WORKERS: usize = 4;

/// The deployment limits of SPEC 12.1, each answered with the terminal error SPEC 12.1 names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest request body in bytes; a larger one is `413 too_large`.
    pub max_body_bytes: usize,
    /// Most members a manifest state may list; more is `429 quota_exceeded`.
    pub max_members: usize,
    /// Most repositories one owner key may create on this host; more is `429 quota_exceeded`.
    pub max_repos_per_owner: usize,
    /// Most outstanding challenges in all; at the cap the oldest is evicted, so one caller cannot
    /// lock everyone out.
    pub max_challenges: usize,
    /// Most outstanding challenges for one key; more is `429 quota_exceeded`.
    pub max_challenges_per_key: usize,
    /// Most live bearer tokens in all; at the cap the oldest is evicted.
    pub max_tokens: usize,
    /// Most live bearer tokens for one key; more is `429 quota_exceeded`.
    pub max_tokens_per_key: usize,
    /// Most recorded unexpired acceptances (SPEC 8.2) in all; at the cap the oldest is evicted.
    pub max_pending_joins: usize,
    /// Most recorded unexpired acceptances for one member key; more is `429 quota_exceeded`.
    pub max_pending_joins_per_key: usize,
    /// The head bound for client writes (SPEC 7.4); more is `409 too_many_heads`.
    pub head_bound: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_body_bytes: 4 * 1024 * 1024,
            max_members: 500,
            max_repos_per_owner: 1000,
            max_challenges: 10_000,
            max_challenges_per_key: 16,
            max_tokens: 100_000,
            max_tokens_per_key: 32,
            max_pending_joins: 10_000,
            max_pending_joins_per_key: 64,
            head_bound: 16,
        }
    }
}

/// Everything one host process holds.
///
/// The replication task (host-to-host routes, peers) adds its own fields here; the client routes
/// only read [`State::store`], [`State::auth`], and the host key.
pub struct State {
    /// This host's Ed25519 host key (SPEC 3.3). It signs acceptances and identifies the host.
    host: SigningKey,
    /// The repositories and recorded acceptances.
    pub store: Store,
    /// Outstanding challenges and live tokens.
    pub auth: Auth,
    /// The deployment limits.
    pub limits: Limits,
    /// Added to the system clock. Zero in the binary; tests move it to expire challenges and tokens.
    pub clock_offset_ms: i64,
}

impl State {
    /// A fresh, empty host with the given host key and the default limits.
    #[must_use]
    pub fn new(host: SigningKey) -> State {
        State {
            host,
            store: Store::default(),
            auth: Auth::default(),
            limits: Limits::default(),
            clock_offset_ms: 0,
        }
    }

    /// The host's public host key.
    #[must_use]
    pub fn host_key(&self) -> [u8; 32] {
        self.host.verifying_key().to_bytes()
    }

    /// The host signing key, for acceptances (SPEC 8.2) and, later, host request signatures.
    #[must_use]
    pub fn host_signing_key(&self) -> &SigningKey {
        &self.host
    }

    /// The host's current time in epoch milliseconds.
    #[must_use]
    pub fn now_ms(&self) -> i64 {
        system_ms().saturating_add(self.clock_offset_ms)
    }
}

/// The system clock in epoch milliseconds; `0` for a clock set before the epoch.
fn system_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Parses `AVP_HOST_SEED`: 64 hex digits, the 32-byte Ed25519 seed of the host key.
///
/// # Errors
///
/// A message naming the problem if the text is not exactly 64 hex digits.
pub fn parse_host_seed(hex: &str) -> Result<[u8; 32], String> {
    let text = hex.trim();
    if text.len() != 64 || !text.is_ascii() {
        return Err("AVP_HOST_SEED must be 64 hex digits (32 bytes)".to_string());
    }
    let mut out = [0u8; 32];
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let digits = std::str::from_utf8(pair).map_err(|_| "AVP_HOST_SEED is not ASCII".to_string())?;
        *slot = u8::from_str_radix(digits, 16).map_err(|_| "AVP_HOST_SEED has a non-hex digit".to_string())?;
    }
    Ok(out)
}

/// A running server: the bound address and the worker threads.
///
/// Dropping it (or calling [`Serving::stop`]) stops the workers and closes the listener.
pub struct Serving {
    addr: SocketAddr,
    server: Arc<Server>,
    stopping: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
}

impl Serving {
    /// The address the listener is bound to; with port `0` this is the port the OS chose.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Blocks until every worker exits, which happens only after [`Serving::stop`] from another
    /// handle or a fatal listener error. The binary calls this to serve forever.
    pub fn wait(mut self) {
        for w in std::mem::take(&mut self.workers) {
            let _ = w.join();
        }
    }

    /// Stops the workers, waits for them, and closes the listener.
    pub fn stop(self) {
        drop(self);
    }

    fn shutdown(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
        for _ in &self.workers {
            self.server.unblock();
        }
        for w in std::mem::take(&mut self.workers) {
            let _ = w.join();
        }
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Binds `addr` and serves the client-facing API from a few worker threads over one shared
/// [`State`].
///
/// The brief's shape is `serve(addr, state) -> JoinHandle`; this returns a [`Serving`] instead so
/// that a bind failure is an error rather than a panic, the port chosen for `addr` port `0` is
/// readable through [`Serving::addr`], and tests can stop the server.
///
/// # Errors
///
/// The I/O error if `addr` cannot be bound or a worker thread cannot be started.
pub fn serve(addr: &str, state: Arc<Mutex<State>>) -> io::Result<Serving> {
    let listener = TcpListener::bind(addr)?;
    let bound = listener.local_addr()?;
    let server = Server::from_listener(listener, None).map_err(io::Error::other)?;
    let mut serving = Serving {
        addr: bound,
        server: Arc::new(server),
        stopping: Arc::new(AtomicBool::new(false)),
        workers: Vec::with_capacity(WORKERS),
    };
    for i in 0..WORKERS {
        let server = Arc::clone(&serving.server);
        let stopping = Arc::clone(&serving.stopping);
        let state = Arc::clone(&state);
        let worker = thread::Builder::new().name(format!("avp-worker-{i}")).spawn(move || {
            while !stopping.load(Ordering::SeqCst) {
                // An accept error or an unblock is not a request; the loop re-checks the flag.
                if let Ok(req) = server.recv() {
                    api::route(req, &state);
                }
            }
        })?;
        serving.workers.push(worker);
    }
    Ok(serving)
}
