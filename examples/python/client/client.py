"""Micro reference client for the Alt Vault Protocol (AVP), HTTP/JSON profile.

It drives the whole wire contract against a running server (the sibling ``../server``, or any other
conformant HTTP/JSON server) so an implementer can see the full lifecycle end to end: generate an
Ed25519 keypair and an X25519 keypair, run the challenge -> sign -> token auth flow, create a repo,
pull, push a new version, invite a second member, fetch that member's key, and have the second member
pull, unwrap, and decrypt the payload.

The envelope and wrapped-key crypto is REAL (SPEC sections 4-5): alice derives a per-repo data key,
AES-256-GCM-encrypts the alt payload binding (repoId, payloadVersion, keyEpoch) into the AAD, and
wraps the data key to each member's X25519 key. The server stays zero-knowledge throughout, so bob
recovers exactly what alice stored. The crypto lives in the sibling ``crypto`` module and is verified
against ../../../vectors by ``test_crypto.py``.

It is intentionally tiny and NOT production code. The only non-standard library dependency is the
``cryptography`` package (Ed25519 signing + X25519 + AES-GCM).

Run: ``pip install -r requirements.txt && python client.py`` (standard library for HTTP, the
``cryptography`` package for all key material). Point it at a server with the ``AVP_SERVER_URL``
environment variable (default ``http://localhost:8787``).

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

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import crypto

# --- Constants --------------------------------------------------------------

#: Base server URL from ``AVP_SERVER_URL`` (default localhost:8787), with any trailing slash trimmed.
BASE_URL = os.environ.get("AVP_SERVER_URL", "http://localhost:8787").rstrip("/")


# --- Ed25519 + X25519 keypair identity (SPEC sections 3 and 4) -------------


@dataclass
class Identity:
    """A member identity: an Ed25519 signing keypair and an X25519 key-wrapping keypair.

    The raw 32-byte Ed25519 public key, base64-encoded, is the member id (SPEC section 2). The
    X25519 private key is used to unwrap the repo data key on pull; its base64 raw public key is
    published in the member entry so others can wrap the data key to this member.

    Attributes:
        ed25519_public_key: Base64 raw 32-byte Ed25519 public key; this is the member id.
        x25519_public_key: Base64 raw 32-byte X25519 public key for data-key wrapping.
        ed25519_private_key: The Ed25519 private key, used only to sign the auth challenge nonce.
        x25519_private_key: The X25519 private key, used only to unwrap a received data key.
    """

    ed25519_public_key: str
    x25519_public_key: str
    ed25519_private_key: Ed25519PrivateKey
    x25519_private_key: X25519PrivateKey


def generate_identity() -> Identity:
    """Generate a fresh Ed25519 + X25519 identity.

    The ``cryptography`` library exposes the raw 32-byte public keys directly via
    ``public_bytes_raw()`` (RFC 8032 / RFC 7748), which is exactly the encoding the member id and
    member entry X25519 field use.

    Returns:
        A new :class:`Identity` with real Ed25519 and X25519 keypairs.
    """
    ed_priv = Ed25519PrivateKey.generate()
    x_priv = X25519PrivateKey.generate()
    return Identity(
        ed25519_public_key=base64.b64encode(ed_priv.public_key().public_bytes_raw()).decode("ascii"),
        x25519_public_key=base64.b64encode(x_priv.public_key().public_bytes_raw()).decode("ascii"),
        ed25519_private_key=ed_priv,
        x25519_private_key=x_priv,
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
    the base64 text -- this is the part conformant servers verify. Ed25519 signs the message directly
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
    signature = base64.b64encode(identity.ed25519_private_key.sign(nonce_bytes)).decode("ascii")
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


# --- Member entry with real wrapped data key --------------------------------


def member_entry(identity: Identity, data_key: bytes, key_epoch: int) -> dict[str, Any]:
    """Assemble a MemberEntry with the data key really wrapped to the identity's X25519 key.

    Args:
        identity: The member whose public keys populate the entry; the X25519 public key is the
            wrap recipient.
        data_key: The 32-byte repo data key to wrap to this member's X25519 key.
        key_epoch: Key epoch this entry's wrapped key belongs to.

    Returns:
        A member-entry dict with a real X25519-HKDF-SHA256-AESGCM-v1 wrapped data key.
    """
    return {
        "ed25519PublicKey": identity.ed25519_public_key,
        "x25519PublicKey": identity.x25519_public_key,
        "wrappedDataKey": crypto.wrap_data_key(identity.x25519_public_key, data_key),
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

    The steps, in order: generate two local identities (alice, bob); authenticate alice; mint a
    per-repo data key; create a repo with alice as sole member (real encrypted payload); pull at the
    known version (unchanged) and from version 0 (envelope returned); push a new version; demonstrate
    the optimistic-concurrency conflict path; add bob as a member (data key wrapped to bob's X25519
    key); fetch bob's stored key entry; authenticate bob, pull, unwrap the data key, and decrypt the
    payload to recover the alt list.

    Raises:
        RuntimeError: If any server call returns a non-2xx status (propagated from :func:`call`);
            the ``__main__`` guard turns this into a non-zero exit code.
    """
    print(f"AVP reference client -> {BASE_URL}")
    print("(Envelope and wrapped-key crypto is real; the server stays zero-knowledge.)\n")

    # Two members, generated locally. alice creates the repo; bob joins later.
    alice = generate_identity()
    bob = generate_identity()
    step(
        "members",
        f"alice={alice.ed25519_public_key[:12]}... bob={bob.ed25519_public_key[:12]}...",
    )

    # 1. Authenticate alice (challenge -> sign nonce -> token).
    alice_token = authenticate(alice)
    step("auth", f"alice token={alice_token[:12]}...")

    # 2. alice mints a per-repo data key and encrypts a real initial payload.
    data_key = os.urandom(32)
    repo_id = str(uuid.uuid4())

    alts_v1 = [
        {
            "uuid": "11111111-1111-4111-8111-111111111111",
            "username": "alice_main",
            "accessToken": "secret-v1",
            "type": "MICROSOFT",
            "lastUsed": 1,
        }
    ]
    envelope_v1 = crypto.encrypt_payload(
        data_key, repo_id, 1, 0, json.dumps({"alts": alts_v1, "payloadVersion": 1}).encode("utf-8")
    )

    created_manifest = call(
        "POST",
        "/v1/repos",
        {
            "manifest": {
                "repoId": repo_id,
                "schemeId": crypto.WRAP_SCHEME_ID,
                "keyEpoch": 0,
                "payloadVersion": 1,
                "members": [member_entry(alice, data_key, 0)],
            },
            "initialEnvelope": envelope_v1,
        },
        alice_token,
    )
    step(
        "createRepo",
        f"repoId={created_manifest['repoId']} members={len(created_manifest['members'])} "
        f"v={created_manifest['payloadVersion']}",
    )

    encoded_repo = urllib.parse.quote(repo_id, safe="")

    # 3. pull at the version we already know -- server reports unchanged and omits the envelope.
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

    # 4. pull from version 0 -- server returns the current envelope.
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

    # 5. push a real v2 payload with optimistic concurrency on the current version.
    next_version = created_manifest["payloadVersion"] + 1
    alts_v2 = alts_v1 + [
        {
            "uuid": "22222222-2222-4222-8222-222222222222",
            "username": "alice_alt",
            "accessToken": "secret-v2",
            "type": "MICROSOFT",
            "lastUsed": 2,
        }
    ]
    envelope_v2 = crypto.encrypt_payload(
        data_key, repo_id, next_version, 0, json.dumps({"alts": alts_v2, "payloadVersion": next_version}).encode("utf-8")
    )
    push_result = call(
        "POST",
        f"/v1/repos/{encoded_repo}/push",
        {
            "repoId": repo_id,
            "envelope": envelope_v2,
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
            "envelope": crypto.encrypt_payload(
                data_key, repo_id, next_version + 1, 0, b'{"alts":[]}'
            ),
            "expectedPayloadVersion": created_manifest["payloadVersion"],  # stale on purpose
        },
        alice_token,
    )
    step(
        "push (stale)",
        f"accepted={conflict['accepted']} conflict={conflict['conflict']} "
        f"serverV={conflict['payloadVersion']}",
    )

    # 7. addMember -- alice wraps the data key to bob's X25519 key and records his entry.
    with_bob = call(
        "POST",
        f"/v1/repos/{encoded_repo}/add-member",
        {"repoId": repo_id, "member": member_entry(bob, data_key, 0)},
        alice_token,
    )
    step("addMember", f"members={len(with_bob['members'])} (added bob)")

    # 8. fetchMemberKey -- look up bob's stored entry by member id. The id is base64, which can
    # contain + / =, so it MUST be URL-encoded in the path.
    bob_entry = call(
        "GET",
        f"/v1/repos/{encoded_repo}/member/{urllib.parse.quote(bob.ed25519_public_key, safe='')}",
        None,
        alice_token,
    )
    step(
        "fetchMemberKey",
        f"bob x25519={bob_entry['x25519PublicKey'][:12]}... epoch={bob_entry['keyEpoch']}",
    )

    # 9. bob authenticates with his own keypair, pulls the shared repo, unwraps the data key, and
    # decrypts the payload to recover the alt list.
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

    # Find bob's member entry in the pulled manifest to retrieve his wrapped data key.
    bob_manifest_entry = next(
        (m for m in bob_pull["manifest"]["members"] if m["ed25519PublicKey"] == bob.ed25519_public_key),
        None,
    )
    if bob_manifest_entry is None:
        raise RuntimeError("bob is not in the pulled roster")
    if bob_pull.get("envelope") is None:
        raise RuntimeError("bob's pull returned no envelope")

    dk = crypto.unwrap_data_key(bob.x25519_private_key, bob_manifest_entry["wrappedDataKey"])
    plaintext = json.loads(crypto.decrypt_payload(dk, bob_pull["envelope"]))
    alts = plaintext.get("alts", [])
    step("bob decrypt", f"v={plaintext.get('payloadVersion')} alts={len(alts)} (decrypted)")
    for alt in alts:
        step("  alt", f"{alt['username']} ({alt['uuid']})")

    print("\nDone. Full lifecycle exercised against a zero-knowledge server; bob decrypted alice's payload.")


if __name__ == "__main__":
    try:
        main()
    except Exception as err:  # noqa: BLE001 -- reference client: surface the failure and exit non-zero
        print(f"\nClient failed: {err}")
        print(
            "Is a server running? Start one with `python server.py` in ../server, "
            "or set AVP_SERVER_URL."
        )
        raise SystemExit(1) from err
