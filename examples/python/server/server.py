"""Micro reference server for the Alt Vault Protocol (AVP), HTTP/JSON profile.

It implements the whole wire contract against an in-memory store so an implementer can point a
client at something real. It is intentionally tiny and NOT production code: state lives in memory
and is lost on restart, there is no TLS, and the bearer token is an opaque random string mapped to
a member id in this same process (a real deployment mints a JWT verifiable via JWKS, as the spec
describes). What it does honour is the part that matters: it is zero-knowledge. It stores only the
manifest, the encrypted envelope, the per-member wrapped keys, public keys, and counters that
clients send, and decrypts nothing. The only cryptography it performs is verifying the Ed25519
challenge signature. Field shapes follow ../../../schema/avp.schema.json.

Run: ``pip install -r requirements.txt && python server.py`` (listens on http://localhost:8787;
set the PORT environment variable to change). Standard-library ``http.server`` plus the
``cryptography`` package for Ed25519 verification.

SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock
from typing import Any, Optional
from urllib.parse import unquote

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# --- In-memory state --------------------------------------------------------
#
# Everything lives in plain dicts guarded by a single lock (the server is
# threaded). It is lost on restart; that is fine for a reference.

_REPOS: dict[str, dict[str, Any]] = {}  # repoId -> {"manifest": ..., "envelope": ...}
_NONCES: dict[str, dict[str, Any]] = {}  # nonce -> {"publicKey": str, "expiresAt": ms}
_TOKENS: dict[str, str] = {}  # opaque bearer token -> member id (Ed25519 public key)
_LOCK = Lock()

NONCE_TTL_MS = 2 * 60 * 1000
TOKEN_TTL_MS = 60 * 60 * 1000


def _now_ms() -> int:
    """Return the current wall-clock time in milliseconds since the Unix epoch.

    Returns:
        The current time in integer milliseconds, used for nonce and token expiry.
    """
    return int(time.time() * 1000)


# --- Crypto: verify an Ed25519 signature over raw bytes (SPEC section 3) -----


def verify_ed25519(public_key_base64: str, message: bytes, signature_base64: str) -> bool:
    """Verify an Ed25519 signature (base64) over ``message`` using a raw 32-byte key (base64).

    This is the only cryptography the reference server performs; it underpins the keypair
    challenge/response in SPEC section 3.

    Args:
        public_key_base64: The signer's raw 32-byte Ed25519 public key, base64-encoded.
        message: The exact bytes that were signed (here, the decoded challenge nonce).
        signature_base64: The detached Ed25519 signature over ``message``, base64-encoded.

    Returns:
        ``True`` if the signature is valid for ``message`` under the given key; ``False`` if
        the signature is invalid or any input is malformed (bad base64, wrong key length).
    """
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_base64))
        key.verify(base64.b64decode(signature_base64), message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# --- Helpers ----------------------------------------------------------------


def _is_member(manifest: dict[str, Any], member_id: str) -> bool:
    """Report whether ``member_id`` is listed among a manifest's members.

    Args:
        manifest: A repo manifest dict whose ``members`` list holds member entries.
        member_id: The candidate member id, i.e. a base64 raw Ed25519 public key.

    Returns:
        ``True`` if any member entry's ``ed25519PublicKey`` equals ``member_id``,
        otherwise ``False``.
    """
    return any(m.get("ed25519PublicKey") == member_id for m in manifest.get("members", []))


def reset_state() -> None:
    """Drop all state. Exposed so tests start from a clean slate."""
    with _LOCK:
        _REPOS.clear()
        _NONCES.clear()
        _TOKENS.clear()


# --- Request handling -------------------------------------------------------


class AvpHandler(BaseHTTPRequestHandler):
    """Routes the AVP HTTP/JSON surface against the in-memory store."""

    protocol_version = "HTTP/1.1"

    # Quiet the default stderr access log; uncomment to see requests.
    def log_message(self, fmt: str, *args: Any) -> None:
        """Suppress the default per-request access log written to stderr.

        Overrides ``BaseHTTPRequestHandler.log_message`` to keep test and demo output quiet.

        Args:
            fmt: The printf-style format string the base class would have logged.
            *args: The values for ``fmt``.
        """
        return

    # -- tiny response/parse helpers --

    def _send(self, status: int, body: Any) -> None:
        """Serialize ``body`` to JSON and write it as the full HTTP response.

        Args:
            status: The HTTP status code to send.
            body: Any JSON-serializable object to use as the response payload.
        """
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read_json(self) -> Any:
        """Read and parse the request body as JSON.

        Reads exactly ``Content-Length`` bytes from the request stream and decodes them as
        UTF-8 JSON.

        Returns:
            The parsed JSON value, or an empty dict when the request has no body.

        Raises:
            json.JSONDecodeError: If the body is present but not valid JSON. The dispatch
                wrappers turn this into a 400 response.
        """
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        return json.loads(raw.decode("utf-8")) if raw else {}

    def _caller_id(self) -> Optional[str]:
        """Resolve the caller's member id from the Bearer token, or None if unauthenticated."""
        header = self.headers.get("Authorization")
        if not header or not header.startswith("Bearer "):
            return None
        with _LOCK:
            return _TOKENS.get(header[len("Bearer ") :])

    # -- dispatch --

    def do_POST(self) -> None:  # noqa: N802 (http.server naming)
        """Handle an HTTP POST, dispatching to :meth:`_route_post`.

        Any exception raised while routing (e.g. malformed JSON, a missing required field) is
        caught and surfaced as a 400 response; that broad catch is acceptable here because this
        is a reference server, not production code.
        """
        try:
            self._route_post()
        except Exception as err:  # noqa: BLE001 — reference server: surface as 400
            self._send(400, {"error": "bad request", "detail": str(err)})

    def do_GET(self) -> None:  # noqa: N802
        """Handle an HTTP GET, dispatching to :meth:`_route_get`.

        Mirrors :meth:`do_POST`: any routing exception becomes a 400 response.
        """
        try:
            self._route_get()
        except Exception as err:  # noqa: BLE001
            self._send(400, {"error": "bad request", "detail": str(err)})

    def _route_post(self) -> None:
        """Route a POST request to the matching AVP endpoint and send its response.

        Handles the keypair auth flow (``/api/auth/keypair/challenge`` and ``.../token``) and,
        once a valid bearer token is present, the repo write operations: create, pull, push,
        add-member, and remove-member. Unmatched paths produce a 404; the response is always
        written via :meth:`_send` before returning.
        """
        path = self.path.split("?", 1)[0]

        # -- Auth: challenge -> token --
        if path == "/api/auth/keypair/challenge":
            body = self._read_json()
            nonce = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
            with _LOCK:
                _NONCES[nonce] = {
                    "publicKey": body.get("ed25519PublicKey"),
                    "expiresAt": _now_ms() + NONCE_TTL_MS,
                }
            return self._send(200, {"nonce": nonce})

        if path == "/api/auth/keypair/token":
            body = self._read_json()
            nonce = body.get("nonce")
            with _LOCK:
                challenge = _NONCES.pop(nonce, None)  # single-use
            if (
                challenge is None
                or challenge["publicKey"] != body.get("ed25519PublicKey")
                or challenge["expiresAt"] < _now_ms()
            ):
                return self._send(401, {"error": "invalid or expired nonce"})
            # Verify the signature over the base64-DECODED nonce bytes.
            if not verify_ed25519(
                body["ed25519PublicKey"],
                base64.b64decode(nonce),
                body.get("signature", ""),
            ):
                return self._send(401, {"error": "bad signature"})
            token = secrets.token_urlsafe(32)
            with _LOCK:
                _TOKENS[token] = body["ed25519PublicKey"]
            return self._send(200, {"token": token, "expiresAt": _now_ms() + TOKEN_TTL_MS})

        # -- Everything below requires a bearer token --
        caller = self._caller_id()
        if caller is None:
            return self._send(401, {"error": "missing or unknown bearer token"})

        # createRepo
        if path == "/v1/repos":
            body = self._read_json()
            manifest = body["manifest"]
            members = manifest.get("members", [])
            if len(members) != 1 or members[0].get("ed25519PublicKey") != caller:
                return self._send(403, {"error": "creator must be the sole member"})
            repo_id = manifest["repoId"]
            with _LOCK:
                if repo_id in _REPOS:
                    return self._send(409, {"error": "repo already exists"})
                _REPOS[repo_id] = {"manifest": manifest, "envelope": body["initialEnvelope"]}
            return self._send(200, manifest)

        # routes under /v1/repos/{repoId}/{op}
        op, repo_id = self._match_repo_op(path)
        if op is None:
            return self._send(404, {"error": "no such route"})

        stored = self._authorized_repo(repo_id, caller)
        if isinstance(stored, int):  # an error status was already sent
            return None

        if op == "pull":
            body = self._read_json()
            manifest = stored["manifest"]
            if body.get("knownPayloadVersion") == manifest["payloadVersion"]:
                return self._send(200, {"manifest": manifest, "envelope": None, "unchanged": True})
            return self._send(
                200,
                {"manifest": manifest, "envelope": stored["envelope"], "unchanged": False},
            )

        if op == "push":
            body = self._read_json()
            manifest = stored["manifest"]
            if body.get("expectedPayloadVersion") != manifest["payloadVersion"]:
                return self._send(
                    200,
                    {
                        "accepted": False,
                        "conflict": True,
                        "payloadVersion": manifest["payloadVersion"],
                        "keyEpoch": manifest["keyEpoch"],
                    },
                )
            envelope = body["envelope"]
            with _LOCK:
                stored["envelope"] = envelope
                manifest["payloadVersion"] = envelope["payloadVersion"]
                manifest["keyEpoch"] = envelope["keyEpoch"]
                if isinstance(body.get("rotatedMembers"), list):
                    manifest["members"] = body["rotatedMembers"]
            return self._send(
                200,
                {
                    "accepted": True,
                    "conflict": False,
                    "payloadVersion": manifest["payloadVersion"],
                    "keyEpoch": manifest["keyEpoch"],
                },
            )

        if op == "add-member":
            body = self._read_json()
            member = body["member"]
            manifest = stored["manifest"]
            with _LOCK:
                if not _is_member(manifest, member.get("ed25519PublicKey")):
                    manifest["members"].append(member)
            return self._send(200, manifest)

        if op == "remove-member":
            body = self._read_json()
            manifest = stored["manifest"]
            rotated = body["rotatedEnvelope"]
            with _LOCK:
                manifest["members"] = body["rewrappedMembers"]
                stored["envelope"] = rotated
                manifest["keyEpoch"] = body["newKeyEpoch"]
                manifest["payloadVersion"] = rotated["payloadVersion"]
            return self._send(200, manifest)

        return self._send(404, {"error": "no such route"})

    def _route_get(self) -> None:
        """Route a GET request and send its response.

        The only GET surface is ``/v1/repos/{repoId}/member/{memberId}``, which returns a
        single member entry. Requires a valid bearer token and repo membership; sends 401 when
        unauthenticated, 404 for an unknown route, repo, or member, and 403 when the caller is
        not a member of the target repo.
        """
        path = self.path.split("?", 1)[0]

        caller = self._caller_id()
        if caller is None:
            return self._send(401, {"error": "missing or unknown bearer token"})

        repo_id, member_id = self._match_member(path)
        if repo_id is None:
            return self._send(404, {"error": "no such route"})

        stored = self._authorized_repo(repo_id, caller)
        if isinstance(stored, int):
            return None

        # URL-decode the member id before comparing: base64 ids contain + / =.
        member_id = unquote(member_id)
        entry = next(
            (m for m in stored["manifest"]["members"] if m.get("ed25519PublicKey") == member_id),
            None,
        )
        if entry is None:
            return self._send(404, {"error": "member not found"})
        return self._send(200, entry)

    # -- routing + authorization helpers --

    @staticmethod
    def _match_repo_op(path: str) -> tuple[Optional[str], Optional[str]]:
        """Match a repo-operation path of the form ``/v1/repos/{repoId}/{op}``.

        Args:
            path: The request path, already stripped of any query string.

        Returns:
            A ``(op, repoId)`` tuple with the operation name and the URL-decoded repo id when
            the path matches a known op (``pull``, ``push``, ``add-member``, ``remove-member``);
            otherwise ``(None, None)``.
        """
        prefix = "/v1/repos/"
        if not path.startswith(prefix):
            return None, None
        rest = path[len(prefix) :]
        parts = rest.split("/")
        if len(parts) != 2:
            return None, None
        repo_id_raw, op = parts
        if op not in ("pull", "push", "add-member", "remove-member"):
            return None, None
        return op, unquote(repo_id_raw)

    @staticmethod
    def _match_member(path: str) -> tuple[Optional[str], Optional[str]]:
        """Match a member-lookup path of the form ``/v1/repos/{repoId}/member/{memberId}``.

        Args:
            path: The request path, already stripped of any query string.

        Returns:
            A ``(repoId, memberId)`` tuple with the URL-decoded repo id and the still-encoded
            member id (the caller decodes it) when the path matches; otherwise ``(None, None)``.
        """
        prefix = "/v1/repos/"
        if not path.startswith(prefix):
            return None, None
        rest = path[len(prefix) :]
        parts = rest.split("/")
        if len(parts) != 3 or parts[1] != "member":
            return None, None
        return unquote(parts[0]), parts[2]

    def _authorized_repo(self, repo_id: str, caller: str) -> dict[str, Any] | int:
        """Return the stored repo if it exists and ``caller`` is a member; else send 404/403.

        On error this sends the response and returns the status code (an int) so the caller can
        bail out without sending twice.

        Args:
            repo_id: The (already URL-decoded) repo id to look up.
            caller: The authenticated caller's member id (base64 Ed25519 public key).

        Returns:
            The stored repo dict (``{"manifest": ..., "envelope": ...}``) when the repo exists
            and ``caller`` is a member. Otherwise the HTTP status code already sent: ``404`` if
            the repo is unknown, ``403`` if the caller is not a member.
        """
        with _LOCK:
            stored = _REPOS.get(repo_id)
        if stored is None:
            self._send(404, {"error": "repo not found"})
            return 404
        if not _is_member(stored["manifest"], caller):
            self._send(403, {"error": "caller is not a member"})
            return 403
        return stored


def make_server(port: int = 8787) -> ThreadingHTTPServer:
    """Build (but do not start) the threaded HTTP server. Importable for tests.

    Binds to ``127.0.0.1`` only; the caller is responsible for starting and stopping it.

    Args:
        port: The TCP port to bind. Pass ``0`` to let the OS choose a free port, which the
            tests use to avoid collisions; read the chosen port back from ``server_address``.

    Returns:
        An unstarted :class:`~http.server.ThreadingHTTPServer` serving the AVP handler.
    """
    return ThreadingHTTPServer(("127.0.0.1", port), AvpHandler)


def main() -> None:
    """Run the reference server until interrupted.

    Reads the listen port from the ``PORT`` environment variable (default ``8787``), serves
    requests forever, and shuts down cleanly on ``KeyboardInterrupt`` (Ctrl-C).
    """
    port = int(os.environ.get("PORT", "8787"))
    httpd = make_server(port)
    print(f"AVP reference server (in-memory) listening on http://localhost:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    main()
