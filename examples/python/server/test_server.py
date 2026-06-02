"""Integration tests for the AVP Python reference server.

Drives the server over real HTTP with a real Ed25519 keypair (so the challenge/token flow is
exercised end to end), then walks the full repository lifecycle. Run with ``python -m pytest`` or
``python -m unittest``; only the standard library and ``cryptography`` are required.

SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64
import json
import threading
import unittest
from http.client import HTTPConnection
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import server as srv


def _keypair() -> tuple[str, Ed25519PrivateKey]:
    """Generate a fresh Ed25519 keypair for use as a test member identity.

    Returns:
        A ``(member_id, private_key)`` tuple, where ``member_id`` is the base64 raw public key
        the server uses as the member id, and ``private_key`` signs challenge nonces.
    """
    priv = Ed25519PrivateKey.generate()
    raw_pub = priv.public_key().public_bytes_raw()
    return base64.b64encode(raw_pub).decode("ascii"), priv


def _entry(pub: str, epoch: int = 0) -> dict[str, Any]:
    """Build a stand-in member entry for ``pub`` with placeholder wrapped-key fields.

    The cryptographic fields are dummies: the reference server stores them verbatim and never
    decrypts, so the tests only need shapes the spec recognizes, not real key material.

    Args:
        pub: The member's base64 Ed25519 public key (its member id).
        epoch: The key epoch this entry's wrapped key belongs to.

    Returns:
        A member-entry dict matching the manifest member shape.
    """
    return {
        "ed25519PublicKey": pub,
        "x25519PublicKey": f"x-{pub[:6]}",
        "wrappedDataKey": {
            "schemeId": "X25519-HKDF-SHA256-AESGCM-v1",
            "ephemeralPublicKey": "eph",
            "iv": "iv",
            "ciphertext": "wk",
        },
        "keyEpoch": epoch,
    }


def _envelope(repo_id: str, version: int, epoch: int = 0) -> dict[str, Any]:
    """Build a stand-in encrypted envelope with a recognizable placeholder ciphertext.

    Like :func:`_entry`, the crypto fields are dummies; ``ciphertext`` is tagged with the
    version (``ct-<version>``) so tests can assert the server returns the envelope byte for byte.

    Args:
        repo_id: The repo this envelope belongs to.
        version: The payload version the envelope represents.
        epoch: The key epoch the envelope was encrypted under.

    Returns:
        An envelope dict matching the envelope shape in the schema.
    """
    return {
        "repoId": repo_id,
        "payloadVersion": version,
        "keyEpoch": epoch,
        "iv": "iv",
        "ciphertext": f"ct-{version}",
    }


class AvpServerTest(unittest.TestCase):
    """End-to-end tests that drive the reference server over real HTTP.

    A single server instance is shared across the test methods (started in
    :meth:`setUpClass`, stopped in :meth:`tearDownClass`); each test starts from cleared state
    via :meth:`setUp`.
    """

    @classmethod
    def setUpClass(cls) -> None:
        """Start the reference server on an OS-chosen port in a background daemon thread."""
        cls.httpd = srv.make_server(port=0)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        """Stop the server and join its serving thread."""
        cls.httpd.shutdown()
        cls.thread.join(timeout=5)

    def setUp(self) -> None:
        """Reset the server's in-memory state so each test starts from a clean slate."""
        srv.reset_state()

    # -- HTTP helpers --

    def _request(
        self, method: str, path: str, body: Optional[Any] = None, token: Optional[str] = None
    ) -> tuple[int, Any]:
        """Send one HTTP request to the test server and read the response.

        Args:
            method: The HTTP method (``"GET"`` or ``"POST"``).
            path: The request path, including any path-encoded segments.
            body: An optional JSON-serializable request body; sent with a JSON content type.
            token: An optional bearer token to send in the ``Authorization`` header.

        Returns:
            A ``(status, body)`` tuple: the HTTP status code and the parsed JSON response body,
            or ``None`` when the response has no body.
        """
        conn = HTTPConnection("127.0.0.1", self.port)
        headers: dict[str, str] = {}
        payload = b""
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        return resp.status, (json.loads(raw) if raw else None)

    def _post(self, path: str, body: Any, token: Optional[str] = None) -> tuple[int, Any]:
        """Send a POST request with a JSON body. See :meth:`_request` for the return shape.

        Args:
            path: The request path.
            body: The JSON-serializable request body.
            token: An optional bearer token.

        Returns:
            A ``(status, body)`` tuple.
        """
        return self._request("POST", path, body, token)

    def _get(self, path: str, token: str) -> tuple[int, Any]:
        """Send an authenticated GET request. See :meth:`_request` for the return shape.

        Args:
            path: The request path.
            token: The bearer token to authenticate with.

        Returns:
            A ``(status, body)`` tuple.
        """
        return self._request("GET", path, None, token)

    def _authenticate(self, pub: str, priv: Ed25519PrivateKey) -> str:
        """Run the keypair challenge/response flow and return a usable bearer token.

        Requests a challenge nonce for ``pub``, signs the decoded nonce with ``priv``, and
        exchanges the signature for a token.

        Args:
            pub: The member's base64 Ed25519 public key (its member id).
            priv: The matching private key used to sign the challenge nonce.

        Returns:
            The opaque bearer token string to send on subsequent authenticated requests.
        """
        _, challenge = self._post("/api/auth/keypair/challenge", {"ed25519PublicKey": pub})
        nonce = challenge["nonce"]
        signature = base64.b64encode(priv.sign(base64.b64decode(nonce))).decode("ascii")
        _, token = self._post(
            "/api/auth/keypair/token",
            {"ed25519PublicKey": pub, "nonce": nonce, "signature": signature},
        )
        return token["token"]

    # -- tests --

    def test_rejects_unauthenticated_vault_call(self) -> None:
        """A repo write with no bearer token is rejected with 401."""
        status, _ = self._post("/v1/repos", {})
        self.assertEqual(status, 401)

    def test_rejects_bad_challenge_signature(self) -> None:
        """A token request whose signature does not match the nonce is rejected with 401."""
        pub, _ = _keypair()
        _, challenge = self._post("/api/auth/keypair/challenge", {"ed25519PublicKey": pub})
        wrong_priv = Ed25519PrivateKey.generate()
        wrong_sig = base64.b64encode(wrong_priv.sign(b"not the nonce")).decode("ascii")
        status, _ = self._post(
            "/api/auth/keypair/token",
            {"ed25519PublicKey": pub, "nonce": challenge["nonce"], "signature": wrong_sig},
        )
        self.assertEqual(status, 401)

    def test_rejects_reused_nonce(self) -> None:
        """A challenge nonce is single-use: the first exchange succeeds, a replay gets 401."""
        pub, priv = _keypair()
        _, challenge = self._post("/api/auth/keypair/challenge", {"ed25519PublicKey": pub})
        nonce = challenge["nonce"]
        sig = base64.b64encode(priv.sign(base64.b64decode(nonce))).decode("ascii")
        body = {"ed25519PublicKey": pub, "nonce": nonce, "signature": sig}
        first, _ = self._post("/api/auth/keypair/token", body)
        self.assertEqual(first, 200)
        second, _ = self._post("/api/auth/keypair/token", body)  # single-use
        self.assertEqual(second, 401)

    def test_full_lifecycle(self) -> None:
        """Walk a repo through its whole lifecycle.

        Covers create (and duplicate-id conflict), pull (unchanged vs. behind), push (success
        vs. stale-base conflict), adding a member and fetching their key back, and removing a
        member with a key rotation that bumps the epoch and payload version.
        """
        alice_pub, alice_priv = _keypair()
        token = self._authenticate(alice_pub, alice_priv)
        repo_id = "repo-lifecycle"

        status, created = self._post(
            "/v1/repos",
            {
                "manifest": {
                    "repoId": repo_id,
                    "schemeId": "scheme-v1",
                    "keyEpoch": 0,
                    "payloadVersion": 1,
                    "members": [_entry(alice_pub)],
                },
                "initialEnvelope": _envelope(repo_id, 1),
            },
            token,
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(created["members"]), 1)

        # duplicate repoId conflicts
        dup, _ = self._post(
            "/v1/repos",
            {
                "manifest": {
                    "repoId": repo_id,
                    "schemeId": "scheme-v1",
                    "keyEpoch": 0,
                    "payloadVersion": 1,
                    "members": [_entry(alice_pub)],
                },
                "initialEnvelope": _envelope(repo_id, 1),
            },
            token,
        )
        self.assertEqual(dup, 409)

        # pull: current version => unchanged; older => the envelope, byte for byte
        _, fresh = self._post(
            f"/v1/repos/{repo_id}/pull", {"repoId": repo_id, "knownPayloadVersion": 1}, token
        )
        self.assertTrue(fresh["unchanged"])
        self.assertIsNone(fresh["envelope"])
        _, behind = self._post(
            f"/v1/repos/{repo_id}/pull", {"repoId": repo_id, "knownPayloadVersion": 0}, token
        )
        self.assertFalse(behind["unchanged"])
        self.assertEqual(behind["envelope"]["ciphertext"], "ct-1")

        # push: right base version succeeds; stale base version conflicts
        _, pushed = self._post(
            f"/v1/repos/{repo_id}/push",
            {"repoId": repo_id, "envelope": _envelope(repo_id, 2), "expectedPayloadVersion": 1},
            token,
        )
        self.assertTrue(pushed["accepted"])
        self.assertEqual(pushed["payloadVersion"], 2)
        _, stale = self._post(
            f"/v1/repos/{repo_id}/push",
            {"repoId": repo_id, "envelope": _envelope(repo_id, 2), "expectedPayloadVersion": 1},
            token,
        )
        self.assertTrue(stale["conflict"])
        self.assertFalse(stale["accepted"])

        # add a member, then fetch their key back (member id is URL-encoded)
        bob_pub, _ = _keypair()
        _, added = self._post(
            f"/v1/repos/{repo_id}/add-member",
            {"repoId": repo_id, "member": _entry(bob_pub)},
            token,
        )
        self.assertEqual(len(added["members"]), 2)
        from urllib.parse import quote

        status, fetched = self._get(
            f"/v1/repos/{repo_id}/member/{quote(bob_pub, safe='')}", token
        )
        self.assertEqual(status, 200)
        self.assertEqual(fetched["ed25519PublicKey"], bob_pub)

        # remove bob: rotate to {alice} at a new epoch and a bumped version
        _, removed = self._post(
            f"/v1/repos/{repo_id}/remove-member",
            {
                "repoId": repo_id,
                "removedMemberId": bob_pub,
                "rotatedEnvelope": _envelope(repo_id, 3, 1),
                "rewrappedMembers": [_entry(alice_pub, 1)],
                "newKeyEpoch": 1,
            },
            token,
        )
        self.assertEqual(len(removed["members"]), 1)
        self.assertEqual(removed["keyEpoch"], 1)
        self.assertEqual(removed["payloadVersion"], 3)

    def test_non_member_cannot_read_repo(self) -> None:
        """An authenticated caller who is not a repo member is denied with 403."""
        alice_pub, alice_priv = _keypair()
        alice_token = self._authenticate(alice_pub, alice_priv)
        repo_id = "repo-private"
        self._post(
            "/v1/repos",
            {
                "manifest": {
                    "repoId": repo_id,
                    "schemeId": "s",
                    "keyEpoch": 0,
                    "payloadVersion": 1,
                    "members": [_entry(alice_pub)],
                },
                "initialEnvelope": _envelope(repo_id, 1),
            },
            alice_token,
        )

        mallory_pub, mallory_priv = _keypair()
        mallory_token = self._authenticate(mallory_pub, mallory_priv)
        status, _ = self._post(
            f"/v1/repos/{repo_id}/pull",
            {"repoId": repo_id, "knownPayloadVersion": 0},
            mallory_token,
        )
        self.assertEqual(status, 403)

    def test_unknown_repo_is_404(self) -> None:
        """Operating on a repo id that does not exist returns 404."""
        pub, priv = _keypair()
        token = self._authenticate(pub, priv)
        status, _ = self._post(
            "/v1/repos/does-not-exist/pull",
            {"repoId": "does-not-exist", "knownPayloadVersion": 0},
            token,
        )
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
