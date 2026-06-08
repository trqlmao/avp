# SPDX-License-Identifier: MIT
"""Real AVP envelope and key-wrap crypto (SPEC sections 4 and 9), using the
``cryptography`` package. Verified byte-for-byte against ../../../vectors by
test_crypto.py. Standard base64 with padding for all wire bytes."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

WRAP_SCHEME_ID = "X25519-HKDF-SHA256-AESGCM-v1"
_WRAP_INFO = b"avp/rdk-wrap/v1"


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


_b64d = base64.b64decode


def build_aad(repo_id: str, payload_version: int, key_epoch: int) -> bytes:
    """AAD = UTF8(repoId) || 0x1F || int64BE(payloadVersion) || int64BE(keyEpoch)."""
    return repo_id.encode("utf-8") + b"\x1f" + struct.pack(">q", payload_version) + struct.pack(">q", key_epoch)


def key_binding_message(ed25519_pub_b64: str, x25519_pub_b64: str) -> bytes:
    """UTF8(ed25519PublicKey + '|' + x25519PublicKey) (SPEC section 9)."""
    return f"{ed25519_pub_b64}|{x25519_pub_b64}".encode("utf-8")


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 (RFC 5869). Empty salt -> 32 zero bytes."""
    if not salt:
        salt = b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, prev, counter = b"", b"", 1
    while len(out) < length:
        prev = hmac.new(prk, prev + info + bytes([counter]), hashlib.sha256).digest()
        out += prev
        counter += 1
    return out[:length]


def encrypt_payload(data_key: bytes, repo_id: str, payload_version: int, key_epoch: int, plaintext: bytes) -> dict[str, Any]:
    """AES-256-GCM encrypt into an EncryptedEnvelope dict (random 12-byte IV)."""
    iv = os.urandom(12)
    ct = AESGCM(data_key).encrypt(iv, plaintext, build_aad(repo_id, payload_version, key_epoch))
    return {"repoId": repo_id, "payloadVersion": payload_version, "keyEpoch": key_epoch, "iv": _b64e(iv), "ciphertext": _b64e(ct)}


def decrypt_payload(data_key: bytes, env: dict[str, Any]) -> bytes:
    """Reverse encrypt_payload; rebuilds AAD from the envelope's own counters."""
    aad = build_aad(env["repoId"], env["payloadVersion"], env["keyEpoch"])
    return AESGCM(data_key).decrypt(_b64d(env["iv"]), _b64d(env["ciphertext"]), aad)


def wrap_data_key(recipient_x25519_pub_b64: str, data_key: bytes) -> dict[str, Any]:
    """Wrap data_key to a recipient X25519 key (X25519-HKDF-SHA256-AESGCM-v1)."""
    recipient = X25519PublicKey.from_public_bytes(_b64d(recipient_x25519_pub_b64))
    ephemeral = X25519PrivateKey.generate()
    eph_pub_raw = ephemeral.public_key().public_bytes_raw()
    shared = ephemeral.exchange(recipient)  # raw 32 bytes, unhashed
    kek = hkdf_sha256(shared, eph_pub_raw, _WRAP_INFO, 32)
    iv = os.urandom(12)
    ct = AESGCM(kek).encrypt(iv, data_key, _WRAP_INFO)
    return {"schemeId": WRAP_SCHEME_ID, "ephemeralPublicKey": _b64e(eph_pub_raw), "iv": _b64e(iv), "ciphertext": _b64e(ct)}


def unwrap_data_key(recipient_x25519_priv: X25519PrivateKey, wk: dict[str, Any]) -> bytes:
    """Reverse wrap_data_key with the recipient's X25519 private key."""
    if wk["schemeId"] != WRAP_SCHEME_ID:
        raise ValueError(f"unsupported wrap scheme {wk['schemeId']!r}")
    eph_pub_raw = _b64d(wk["ephemeralPublicKey"])
    shared = recipient_x25519_priv.exchange(X25519PublicKey.from_public_bytes(eph_pub_raw))
    kek = hkdf_sha256(shared, eph_pub_raw, _WRAP_INFO, 32)
    return AESGCM(kek).decrypt(_b64d(wk["iv"]), _b64d(wk["ciphertext"]), _WRAP_INFO)
