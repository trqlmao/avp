// SPDX-License-Identifier: MIT

//! The gRPC client profile (SPEC 10.3): the `avp.Vault` service over the same engine as the
//! HTTP/JSON routes.
//!
//! Every RPC **transcodes**. The request message becomes the exact JSON body the HTTP/JSON route
//! takes (the generated types carry the profile's camelCase field names), [`client_call`] runs the
//! operation, and its JSON answer becomes the reply message. There is one implementation of each
//! operation and two framings of it, so the profiles cannot drift. The repository is the one the
//! body names; `Pull` carries it in `repoId`, which is taken out of the body and passed as the route
//! id, as the HTTP path segment would be.
//!
//! Before the operation runs, the front refuses an absent required message field with
//! `bad_request` (proto3 cannot tell absent from empty for scalars, but it can for messages) and a
//! JSON body over the host's body limit with `too_large`. A refusal maps to the canonical status by
//! the SPEC 10.3 table, with the SPEC 10.4 `code` as the status message and `detail` and
//! `Retry-After` in the `avp-error-detail` and `retry-after` trailers.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::sync::oneshot;
use tonic::metadata::{MetadataMap, MetadataValue};
use tonic::transport::Server;
use tonic::transport::server::TcpIncoming;
use tonic::{Code, Request, Response, Status};

use crate::State;
use crate::api::{ClientOp, Refused, client_call, is_repo_id};

/// The code generated from `proto/avp.proto`: the messages, with serde derives in the HTTP/JSON
/// field names, and the `Vault` and `Replication` server and client stubs.
#[allow(missing_docs, clippy::all, clippy::pedantic)]
pub mod proto {
    tonic::include_proto!("avp");
}

use proto::vault_server::{Vault, VaultServer};

/// The canonical gRPC status of a SPEC 10.4 `code` (SPEC 10.3).
fn code_of(code: &str) -> Code {
    match code {
        "bad_request" => Code::InvalidArgument,
        "unauthorized" => Code::Unauthenticated,
        "forbidden" | "policy_denied" | "not_hosted" => Code::PermissionDenied,
        "not_found" => Code::NotFound,
        "duplicate_repo" => Code::AlreadyExists,
        "too_many_heads" | "manifest_conflict" | "missing_parents" => Code::FailedPrecondition,
        "quota_exceeded" | "too_large" => Code::ResourceExhausted,
        _ => Code::Internal,
    }
}

/// The gRPC status of a refused call (SPEC 10.3): the status message is the SPEC 10.4 `code`,
/// `detail` travels in the `avp-error-detail` trailer and `Retry-After` in `retry-after`. A
/// refusal without a code maps by its HTTP status: `503` (replication paused) is `UNAVAILABLE`
/// "unavailable", anything else `INTERNAL` "internal".
#[must_use]
pub fn status_of(refused: &Refused) -> Status {
    let (code, message) = match refused.code {
        Some(c) => (code_of(c), c),
        None if refused.status == 503 => (Code::Unavailable, "unavailable"),
        None => (Code::Internal, "internal"),
    };
    let mut metadata = MetadataMap::new();
    if let Some(detail) = &refused.detail {
        if let Ok(v) = MetadataValue::try_from(detail.as_str()) {
            metadata.insert("avp-error-detail", v);
        }
    }
    if let Some(s) = refused.retry_after_s {
        if let Ok(v) = MetadataValue::try_from(s.to_string()) {
            metadata.insert("retry-after", v);
        }
    }
    Status::with_metadata(code, message, metadata)
}

fn bad_request(message: &str) -> Status {
    status_of(&Refused::new(400, "bad_request", message))
}

fn internal() -> Status {
    status_of(&Refused::new(500, "internal", "internal error"))
}

/// The `Vault` service over one host's state.
struct Front {
    state: Arc<Mutex<State>>,
    max_body_bytes: usize,
}

/// The `authorization` metadata, as the HTTP `Authorization` header.
fn authorization<T>(request: &Request<T>) -> Option<String> {
    request
        .metadata()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// The repository a body names, refused as `bad_request` when it is not a `repoId` (SPEC 10.3).
fn named_repo(id: &str) -> Result<String, Status> {
    if is_repo_id(id) {
        Ok(id.to_string())
    } else {
        Err(bad_request("repoId is not a 22-character base64url id"))
    }
}

/// The state of a manifest that must be present: an absent one is `bad_request`.
fn state_of(manifest: Option<&proto::SignedManifest>) -> Result<&proto::ManifestState, Status> {
    manifest
        .ok_or_else(|| bad_request("manifest is required"))?
        .state
        .as_ref()
        .ok_or_else(|| bad_request("manifest state is required"))
}

impl Front {
    /// Runs `op` over the JSON form of `body` and decodes the JSON answer as `Rep`.
    async fn run<Rep: DeserializeOwned>(
        &self,
        op: ClientOp,
        authorization: Option<String>,
        body: Value,
    ) -> Result<Response<Rep>, Status> {
        let bytes = serde_json::to_vec(&body).map_err(|_| internal())?;
        if bytes.len() > self.max_body_bytes {
            return Err(status_of(&Refused::new(413, "too_large", "request body too large")));
        }
        let state = Arc::clone(&self.state);
        let answer = tokio::task::spawn_blocking(move || client_call(&state, op, authorization.as_deref(), &bytes))
            .await
            .map_err(|_| internal())?
            .map_err(|r| status_of(&r))?;
        serde_json::from_value(answer)
            .map(Response::new)
            .map_err(|_| internal())
    }
}

fn json<T: Serialize>(message: &T) -> Result<Value, Status> {
    serde_json::to_value(message).map_err(|_| internal())
}

#[tonic::async_trait]
impl Vault for Front {
    async fn create_repo(
        &self,
        request: Request<proto::CreateRepoRequest>,
    ) -> Result<Response<proto::SignedManifest>, Status> {
        let auth = authorization(&request);
        let body = request.into_inner();
        state_of(body.manifest.as_ref())?;
        if body.commit.is_none() {
            return Err(bad_request("commit is required"));
        }
        self.run(ClientOp::CreateRepo, auth, json(&body)?).await
    }

    async fn pull(&self, request: Request<proto::PullRequest>) -> Result<Response<proto::PullResponse>, Status> {
        let auth = authorization(&request);
        let body = request.into_inner();
        let repo_id = named_repo(&body.repo_id)?;
        let mut value = json(&body)?;
        if let Some(obj) = value.as_object_mut() {
            // gRPC-only addressing field: the HTTP/JSON pull body never carries it (SPEC 10.3).
            obj.remove("repoId");
        }
        self.run(ClientOp::Pull(repo_id), auth, value).await
    }

    async fn push(&self, request: Request<proto::PushRequest>) -> Result<Response<proto::PushResponse>, Status> {
        let auth = authorization(&request);
        let body = request.into_inner();
        let commit = body.commit.as_ref().ok_or_else(|| bad_request("commit is required"))?;
        let repo_id = named_repo(&commit.repo_id)?;
        self.run(ClientOp::Push(repo_id), auth, json(&body)?).await
    }

    async fn publish_manifest(
        &self,
        request: Request<proto::PublishManifestRequest>,
    ) -> Result<Response<proto::SignedManifest>, Status> {
        let auth = authorization(&request);
        let body = request.into_inner();
        let repo_id = named_repo(&state_of(body.manifest.as_ref())?.repo_id)?;
        self.run(ClientOp::Manifest(repo_id), auth, json(&body)?).await
    }

    async fn leave(&self, request: Request<proto::LeaveRequest>) -> Result<Response<proto::LeaveResponse>, Status> {
        let auth = authorization(&request);
        let body = request.into_inner();
        let repo_id = named_repo(&body.repo_id)?;
        self.run(ClientOp::Leave(repo_id), auth, json(&body)?).await
    }

    async fn prepare_join(
        &self,
        request: Request<proto::PrepareJoinRequest>,
    ) -> Result<Response<proto::Acceptance>, Status> {
        let auth = authorization(&request);
        let body = request.into_inner();
        self.run(ClientOp::PrepareJoin, auth, json(&body)?).await
    }

    async fn get_host_info(
        &self,
        _request: Request<proto::HostInfoRequest>,
    ) -> Result<Response<proto::HostInfo>, Status> {
        self.run(ClientOp::Discovery, None, Value::Null).await
    }

    async fn challenge(
        &self,
        request: Request<proto::ChallengeRequest>,
    ) -> Result<Response<proto::AuthChallenge>, Status> {
        let body = request.into_inner();
        self.run(ClientOp::Challenge, None, json(&body)?).await
    }

    async fn token(&self, request: Request<proto::TokenRequest>) -> Result<Response<proto::AuthToken>, Status> {
        let body = request.into_inner();
        self.run(ClientOp::Token, None, json(&body)?).await
    }
}

/// A running gRPC listener: the bound address and the thread that runs its runtime.
///
/// Dropping it (or calling [`GrpcServing::stop`]) shuts the server down and joins the thread.
pub struct GrpcServing {
    addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl GrpcServing {
    /// The address the listener is bound to; with port `0` this is the port the OS chose.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Blocks until the server thread exits, which happens only after a fatal server error.
    pub fn wait(mut self) {
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }

    /// Shuts the server down and waits for its thread.
    pub fn stop(self) {
        drop(self);
    }
}

impl Drop for GrpcServing {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Binds `addr` and serves the `avp.Vault` service over `state` from a dedicated thread running a
/// tokio runtime. The decoding limit is the host's body limit (SPEC 12.1).
///
/// # Errors
///
/// The I/O error if `addr` cannot be bound, the runtime cannot be built, or the thread cannot be
/// started.
pub fn serve_grpc(addr: &str, state: Arc<Mutex<State>>) -> io::Result<GrpcServing> {
    let max_body_bytes = state
        .lock()
        .map_err(|_| io::Error::other("host state lock poisoned"))?
        .limits
        .max_body_bytes;
    let std_listener = std::net::TcpListener::bind(addr)?;
    let bound = std_listener.local_addr()?;
    std_listener.set_nonblocking(true)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("avp-grpc-worker")
        .enable_all()
        .build()?;
    let listener = {
        let _entered = runtime.enter();
        tokio::net::TcpListener::from_std(std_listener)?
    };
    let (tx, rx) = oneshot::channel::<()>();
    let service = VaultServer::new(Front { state, max_body_bytes }).max_decoding_message_size(max_body_bytes);
    let thread = thread::Builder::new().name("avp-grpc".to_string()).spawn(move || {
        runtime.block_on(async move {
            let shutdown = async {
                let _ = rx.await;
            };
            // A server error ends the thread; `wait` then returns.
            let _ = Server::builder()
                .add_service(service)
                .serve_with_incoming_shutdown(TcpIncoming::from(listener), shutdown)
                .await;
        });
    })?;
    Ok(GrpcServing {
        addr: bound,
        shutdown: Some(tx),
        thread: Some(thread),
    })
}
