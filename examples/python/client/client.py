"""Micro reference client for the Alt Vault Protocol (AVP), HTTP/JSON profile.

It drives the whole wire contract against a running server (the sibling ``../server``, or any other
conformant HTTP/JSON server) so an implementer can see the full lifecycle end to end: generate an
Ed25519 keypair, run the challenge -> sign -> token auth flow, create a repo, pull, push a new
version, invite a second member, fetch that member's key, and print a transcript.

It is intentionally tiny and NOT production code. Crucially, the envelope and wrapped-key crypto is
OUT OF SCOPE here: this client carries the alt payload as an opaque placeholder ciphertext and never
actually encrypts anything. A real client derives a per-repo data key, AES-256-GCM encrypts the alt
payload (binding repoId/payloadVersion/keyEpoch into the AAD), and wraps the data key to each member's
X25519 key. See SPEC sections 4-5 and the ``lol.trq.alts`` reference for that part. The only real
crypto here is the Ed25519 challenge signature, which IS part of the wire contract.

Run: ``pip install -r requirements.txt && python client.py`` (standard library for HTTP, the
``cryptography`` package for Ed25519). Point it at a server with the ``AVP_SERVER_URL`` environment
variable (default ``http://localhost:8787``).

SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# --- Constants --------------------------------------------------------------

#: Identifier of the wrapping scheme this example advertises in manifests and wrapped keys.
SCHEME_ID = "X25519-HKDF-SHA256-AESGCM-v1"

#: Base server URL from ``AVP_SERVER_URL`` (default localhost:8787), with any trailing slash trimmed.
BASE_URL = os.environ.get("AVP_SERVER_URL", "http://localhost:8787").rstrip("/")


# --- Ed25519 keypair + identity (SPEC section 3) ----------------------------


@dataclass
class Identity:
    """A member identity: an Ed25519 signing keypair plus a placeholder X25519 public key.

    The raw 32-byte Ed25519 public key, base64-encoded, is the member id (SPEC section 2). The
    X25519 key would be a real Curve25519 public key in a production client; here it is an opaque
    placeholder, because this example performs no key wrapping.

    Attributes:
        ed25519_public_key: Base64 raw 32-byte Ed25519 public key; this is the member id.
        x25519_public_key: Base64 placeholder X25519 public key (no real key agreement happens).
        private_key: The Ed25519 private key, used only to sign the auth challenge nonce.
    """

    ed25519_public_key: str
    x25519_public_key: str
    private_key: Ed25519PrivateKey


def generate_identity(label: str) -> Identity:
    """Generate a fresh Ed25519 identity with a labelled placeholder X25519 public key.

    The ``cryptography`` library exposes the raw 32-byte public key directly via
    ``public_bytes_raw()`` (RFC 8032), which is exactly the encoding the member id uses.

    Args:
        label: Human-readable name (e.g. ``"alice"``) woven into the placeholder X25519 key so the
            transcript stays readable; it has no cryptographic meaning.

    Returns:
        A new :class:`Identity` with a real Ed25519 keypair and a placeholder X25519 public key.
    """
    private_key = Ed25519PrivateKey.generate()
    raw_public = private_key.public_key().public_bytes_raw()
    return Identity(
        ed25519_public_key=base64.b64encode(raw_public).decode("ascii"),
        # Placeholder, not a real X25519 key — clearly labelled so nobody mistakes it for key material.
        x25519_public_key=base64.b64encode(f"x25519-placeholder-{label}".encode("utf-8")).decode("ascii"),
        private_key=private_key,
    )


# --- HTTP helper ------------------------------------------------------------


def call(
    method: str,
    path: str,
    body: Optional[Any] = None,
    token: Optional[str] = None,
) -> Any:
    """Send a JSON request to the server and parse the JSON response.

    Raises on any non-2xx status so the transcript fails loudly rather than silently mis-stepping.

    Args:
        method: HTTP method (``"GET"``, ``"POST"``, ...).
        path: Path appended to :data:`BASE_URL` (must start with ``"/"``).
        body: Optional value to JSON-encode as the request body; pass ``None`` for bodyless
            requests like GET.
        token: Optional bearer token; when present it is sent as ``Authorization: Bearer <token>``.

    Returns:
        The parsed response body, or ``{}`` when the response has no body.

    Raises:
        RuntimeError: If the response status is not 2xx; the message includes the method, path,
            status, and body.
    """
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(f"{BASE_URL}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request) as response:
            text = response.read().decode("utf-8")
    except urllib.error.HTTPError as err:
        detail = err.read().decode("utf-8", "replace")
        raise RuntimeError(f"{method} {path} -> {err.code}: {detail}") from err
    return json.loads(text) if text else {}


# --- Auth flow: challenge -> sign nonce -> token (SPEC section 3) -----------


def authenticate(identity: Identity) -> str:
    """Run the keypair challenge flow and return a bearer token for this identity.

    The client signs the RAW nonce bytes (the bytes obtained by base64-decoding the ``nonce``), not
    the base64 text — this is the part conformant servers verify. Ed25519 signs the message directly
    (no pre-hash).

    Args:
        identity: The member identity whose private key signs the challenge nonce.

    Returns:
        A bearer token to authorize subsequent calls for this identity.

    Raises:
        RuntimeError: If either auth leg returns a non-2xx status (propagated from :func:`call`).
    """
    challenge = call(
        "POST",
        "/api/auth/keypair/challenge",
        {"ed25519PublicKey": identity.ed25519_public_key},
    )
    nonce_bytes = base64.b64decode(challenge["nonce"])
    signature = base64.b64encode(identity.private_key.sign(nonce_bytes)).decode("ascii")
    auth = call(
        "POST",
        "/api/auth/keypair/token",
        {
            "ed25519PublicKey": identity.ed25519_public_key,
            "nonce": challenge["nonce"],
            "signature": signature,
        },
    )
    return auth["token"]


# --- Placeholder envelope + wrapped key (NOT real crypto) -------------------


def placeholder_iv() -> str:
    """Return a base64 placeholder for a 12-byte AES-GCM IV.

    No real encryption happens in this example, so the bytes need not be random for security; they
    are filled deterministically so the transcript stays reproducible while still being well-formed.

    Returns:
        A base64 string standing in for a 12-byte AEAD nonce/IV.
    """
    return base64.b64encode(b"iv-placeholder").decode("ascii")


def placeholder_envelope(repo_id: str, payload_version: int, key_epoch: int) -> dict[str, Any]:
    """Build an opaque placeholder :class:`EncryptedEnvelope`.

    A real client AES-256-GCM-encrypts the alt payload and binds ``(repoId, payloadVersion,
    keyEpoch)`` into the AAD (SPEC section 4). Here ``ciphertext`` is just a base64 blob so the
    server has something to store; the server never decrypts it, which is the whole point.

    Args:
        repo_id: Repo the envelope belongs to.
        payload_version: Payload version this envelope represents.
        key_epoch: Key epoch the (notional) payload was encrypted under.

    Returns:
        An envelope dict with a placeholder IV and a labelled placeholder ciphertext.
    """
    return {
        "repoId": repo_id,
        "payloadVersion": payload_version,
        "keyEpoch": key_epoch,
        "iv": placeholder_iv(),
        "ciphertext": base64.b64encode(
            f"opaque-placeholder-payload-v{payload_version}".encode("utf-8")
        ).decode("ascii"),
    }


def placeholder_wrapped_key(member_label: str) -> dict[str, Any]:
    """Build an opaque placeholder :class:`WrappedKey` for a member.

    A real client runs X25519 ECDH against the member's X25519 key, derives an AES key via
    HKDF, and AES-256-GCM-encrypts the repo data key. Here it is a labelled placeholder; the server
    stores and serves it without ever being able to read it.

    Args:
        member_label: Human-readable member name woven into the placeholder fields for transcript
            readability; it has no cryptographic meaning.

    Returns:
        A wrapped-key dict advertising :data:`SCHEME_ID` with a placeholder IV and labelled fields.
    """
    return {
        "schemeId": SCHEME_ID,
        "ephemeralPublicKey": base64.b64encode(
            f"ephemeral-x25519-for-{member_label}".encode("utf-8")
        ).decode("ascii"),
        "iv": placeholder_iv(),
        "ciphertext": base64.b64encode(
            f"wrapped-data-key-for-{member_label}".encode("utf-8")
        ).decode("ascii"),
    }


def member_entry(identity: Identity, label: str, key_epoch: int) -> dict[str, Any]:
    """Assemble a :class:`MemberEntry` from an identity at a given key epoch.

    Args:
        identity: The member whose public keys populate the entry.
        label: Human-readable member name passed through to :func:`placeholder_wrapped_key`.
        key_epoch: Key epoch this entry's wrapped key belongs to.

    Returns:
        A member-entry dict with a placeholder wrapped data key and no key-binding signature.
    """
    return {
        "ed25519PublicKey": identity.ed25519_public_key,
        "x25519PublicKey": identity.x25519_public_key,
        "wrappedDataKey": placeholder_wrapped_key(label),
        "keyEpoch": key_epoch,
        "keyBindingSig": None,
    }


# --- Transcript -------------------------------------------------------------


def step(label: str, detail: str) -> None:
    """Print one transcript line with a padded step label so the output columns line up.

    Args:
        label: Short step name shown left-aligned in a fixed-width column.
        detail: Free-form detail printed after the label.
    """
    print(f"  {label:<16} {detail}")


def main() -> None:
    """Drive the full AVP lifecycle end to end against a running server and print a transcript.

    The steps, in order: generate two local identities (alice, bob); authenticate alice; create a
    repo with alice as sole member; pull at the known version (unchanged) and from version 0
    (envelope returned); push a new version; demonstrate the optimistic-concurrency conflict path
    with a stale expected version; add bob as a member; fetch bob's stored key entry; then
    authenticate bob and have him pull the shared repo.

    Raises:
        RuntimeError: If any server call returns a non-2xx status (propagated from :func:`call`);
            the ``__main__`` guard turns this into a non-zero exit code.
    """
    print(f"AVP reference client -> {BASE_URL}")
    print("(Envelope/wrapped-key crypto is a placeholder; only the Ed25519 auth is real.)\n")

    # Two members, generated locally. alice creates the repo; bob joins later.
    alice = generate_identity("alice")
    bob = generate_identity("bob")
    step(
        "members",
        f"alice={alice.ed25519_public_key[:12]}… bob={bob.ed25519_public_key[:12]}…",
    )

    # 1. Authenticate alice (challenge -> sign nonce -> token).
    alice_token = authenticate(alice)
    step("auth", f"alice token={alice_token[:12]}…")

    # 2. createRepo — alice must be the sole member of the manifest she creates.
    # A real repoId is whatever the deploying client mints; we use a random UUID.
    repo_id = str(uuid.uuid4())
    initial_envelope = placeholder_envelope(repo_id, 1, 0)
    created_manifest = call(
        "POST",
        "/v1/repos",
        {
            "manifest": {
                "repoId": repo_id,
                "schemeId": SCHEME_ID,
                "keyEpoch": 0,
                "payloadVersion": 1,
                "members": [member_entry(alice, "alice", 0)],
            },
            "initialEnvelope": initial_envelope,
        },
        alice_token,
    )
    step(
        "createRepo",
        f"repoId={created_manifest['repoId']} members={len(created_manifest['members'])} "
        f"v={created_manifest['payloadVersion']}",
    )

    encoded_repo = urllib.parse.quote(repo_id, safe="")

    # 3. pull at the version we already know — server reports unchanged and omits the envelope.
    pull_same = call(
        "POST",
        f"/v1/repos/{encoded_repo}/pull",
        {"repoId": repo_id, "knownPayloadVersion": created_manifest["payloadVersion"]},
        alice_token,
    )
    step(
        "pull (known)",
        f"unchanged={pull_same['unchanged']} "
        f"envelope={'null' if pull_same.get('envelope') is None else 'present'}",
    )

    # 4. pull from version 0 — server returns the current envelope.
    pull_fresh = call(
        "POST",
        f"/v1/repos/{encoded_repo}/pull",
        {"repoId": repo_id, "knownPayloadVersion": 0},
        alice_token,
    )
    step(
        "pull (stale)",
        f"unchanged={pull_fresh['unchanged']} "
        f"envelope={'null' if pull_fresh.get('envelope') is None else 'present'}",
    )

    # 5. push a new payload version with optimistic concurrency on the current version.
    next_version = created_manifest["payloadVersion"] + 1
    push_result = call(
        "POST",
        f"/v1/repos/{encoded_repo}/push",
        {
            "repoId": repo_id,
            "envelope": placeholder_envelope(repo_id, next_version, 0),
            "expectedPayloadVersion": created_manifest["payloadVersion"],
        },
        alice_token,
    )
    step(
        "push",
        f"accepted={push_result['accepted']} conflict={push_result['conflict']} "
        f"v={push_result['payloadVersion']}",
    )

    # 6. demonstrate the conflict path: pushing again at the now-stale expected version is rejected.
    conflict = call(
        "POST",
        f"/v1/repos/{encoded_repo}/push",
        {
            "repoId": repo_id,
            "envelope": placeholder_envelope(repo_id, next_version + 1, 0),
            "expectedPayloadVersion": created_manifest["payloadVersion"],  # stale on purpose
        },
        alice_token,
    )
    step(
        "push (stale)",
        f"accepted={conflict['accepted']} conflict={conflict['conflict']} "
        f"serverV={conflict['payloadVersion']}",
    )

    # 7. addMember — alice (any member may invite, v1 policy) records bob's entry. In a real client
    # bob would publish his public keys via the join handshake (SPEC section 8.1) and alice would
    # wrap the data key to bob's X25519 key; here the wrapped key is a placeholder.
    with_bob = call(
        "POST",
        f"/v1/repos/{encoded_repo}/add-member",
        {"repoId": repo_id, "member": member_entry(bob, "bob", 0)},
        alice_token,
    )
    step("addMember", f"members={len(with_bob['members'])} (added bob)")

    # 8. fetchMemberKey — look up bob's stored entry by member id. The id is base64, which can
    # contain + / =, so it MUST be URL-encoded in the path.
    bob_entry = call(
        "GET",
        f"/v1/repos/{encoded_repo}/member/{urllib.parse.quote(bob.ed25519_public_key, safe='')}",
        None,
        alice_token,
    )
    step(
        "fetchMemberKey",
        f"bob x25519={bob_entry['x25519PublicKey'][:12]}… epoch={bob_entry['keyEpoch']}",
    )

    # 9. bob authenticates with his own keypair and pulls the shared repo.
    bob_token = authenticate(bob)
    bob_pull = call(
        "POST",
        f"/v1/repos/{encoded_repo}/pull",
        {"repoId": repo_id, "knownPayloadVersion": 0},
        bob_token,
    )
    step(
        "bob pull",
        f"members={len(bob_pull['manifest']['members'])} v={bob_pull['manifest']['payloadVersion']} "
        f"envelope={'null' if bob_pull.get('envelope') is None else 'present'}",
    )

    print("\nDone. Full lifecycle exercised against a zero-knowledge server.")


if __name__ == "__main__":
    try:
        main()
    except Exception as err:  # noqa: BLE001 — reference client: surface the failure and exit non-zero
        print(f"\nClient failed: {err}")
        print(
            "Is a server running? Start one with `python server.py` in ../server, "
            "or set AVP_SERVER_URL."
        )
        raise SystemExit(1) from err
