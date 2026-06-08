# SPDX-License-Identifier: MIT
"""Vector tests for crypto.py -- checked byte-for-byte against ../../../vectors.

Porting the 7 conformance cases from examples/go/avp/crypto_test.go plus two
round-trip tests (encrypt_payload->decrypt_payload, wrap_data_key->unwrap_data_key).
"""
from __future__ import annotations

import base64
import json
import os
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

import crypto

# Resolve the repo-root vectors directory relative to this file.
_VECTORS = os.path.join(os.path.dirname(__file__), "..", "..", "..", "vectors")


def _load(name: str) -> dict:
    with open(os.path.join(_VECTORS, name), encoding="utf-8") as f:
        return json.load(f)


def _hex(b: bytes) -> str:
    return b.hex()


def _from_hex(s: str) -> bytes:
    return bytes.fromhex(s)


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


class TestAADVectors(unittest.TestCase):
    """build_aad matches aad.json expectedAadHex byte-for-byte."""

    def test_aad(self) -> None:
        file = _load("aad.json")
        cases = file["cases"]
        self.assertTrue(len(cases) > 0, "no cases")
        for c in cases:
            got = _hex(crypto.build_aad(c["repoId"], c["payloadVersion"], c["keyEpoch"]))
            self.assertEqual(
                got,
                c["expectedAadHex"],
                f"repoId={c['repoId']!r} v={c['payloadVersion']} epoch={c['keyEpoch']}",
            )


class TestKeyBindingMessageVectors(unittest.TestCase):
    """key_binding_message matches key-binding-message.json expectedMessageUtf8."""

    def test_key_binding_message(self) -> None:
        file = _load("key-binding-message.json")
        for c in file["cases"]:
            got = crypto.key_binding_message(c["ed25519PublicKey"], c["x25519PublicKey"]).decode("utf-8")
            self.assertEqual(got, c["expectedMessageUtf8"])


class TestHKDFVectors(unittest.TestCase):
    """hkdf_sha256 matches hkdf.json okmHex (including empty-salt rule) byte-for-byte."""

    def test_hkdf(self) -> None:
        file = _load("hkdf.json")
        for c in file["cases"]:
            okm = crypto.hkdf_sha256(
                _from_hex(c["ikmHex"]),
                _from_hex(c["saltHex"]),
                _from_hex(c["infoHex"]),
                c["length"],
            )
            self.assertEqual(_hex(okm), c["okmHex"], c["name"])


class TestX25519Vectors(unittest.TestCase):
    """X25519 key agreement matches x25519.json outputHex (unhashed raw shared secret)."""

    def test_x25519(self) -> None:
        file = _load("x25519.json")
        for c in file["cases"]:
            priv = X25519PrivateKey.from_private_bytes(_from_hex(c["scalarHex"]))
            pub = X25519PublicKey.from_public_bytes(_from_hex(c["uCoordinateHex"]))
            shared = priv.exchange(pub)
            self.assertEqual(shared.hex(), c["outputHex"], c["name"])


class TestEd25519Vectors(unittest.TestCase):
    """Ed25519 derive-public-key + sign matches ed25519.json byte-for-byte."""

    def test_ed25519(self) -> None:
        file = _load("ed25519.json")
        for c in file["cases"]:
            priv = Ed25519PrivateKey.from_private_bytes(_from_hex(c["seedHex"]))
            pub_raw = priv.public_key().public_bytes_raw()
            self.assertEqual(pub_raw.hex(), c["publicKeyHex"], f"{c['name']}: public key")
            sig = priv.sign(_from_hex(c["messageHex"]))
            self.assertEqual(sig.hex(), c["signatureHex"], f"{c['name']}: signature")


class TestPayloadAEADVectors(unittest.TestCase):
    """Payload AEAD matches payload-aead.json: AAD, encrypt, decrypt, tamper-fail."""

    def test_payload_aead(self) -> None:
        file = _load("payload-aead.json")
        cases = file["cases"]
        self.assertTrue(len(cases) > 0, "payload-aead.json has no cases")
        for c in cases:
            key = _b64d(c["keyB64"])
            iv = _b64d(c["ivB64"])
            aad = crypto.build_aad(c["repoId"], c["payloadVersion"], c["keyEpoch"])

            # (a) AAD bytes match the committed hex.
            self.assertEqual(aad.hex(), c["aadHex"], f"{c['name']}: AAD hex")

            # (b) Re-encrypt plaintext with the committed iv/aad and compare ciphertext.
            ct = AESGCM(key).encrypt(iv, c["plaintextUtf8"].encode("utf-8"), aad)
            self.assertEqual(base64.b64encode(ct).decode("ascii"), c["ciphertextB64"], f"{c['name']}: ciphertext")

            # (c) Decrypt and recover plaintext.
            pt = AESGCM(key).decrypt(iv, _b64d(c["ciphertextB64"]), aad)
            self.assertEqual(pt.decode("utf-8"), c["plaintextUtf8"], f"{c['name']}: plaintext")

            # (d) Tampered epoch must fail authentication.
            tampered_aad = crypto.build_aad(c["repoId"], c["payloadVersion"], c["tamperEpoch"])
            with self.assertRaises(InvalidTag, msg=f"{c['name']}: tampered epoch should fail"):
                AESGCM(key).decrypt(iv, _b64d(c["ciphertextB64"]), tampered_aad)


class TestKeyWrapVectors(unittest.TestCase):
    """Key wrap matches key-wrap.json: public-key derivation, shared-secret, KEK, unwrap."""

    def test_key_wrap(self) -> None:
        file = _load("key-wrap.json")
        cases = file["cases"]
        self.assertTrue(len(cases) > 0, "key-wrap.json has no cases")
        for c in cases:
            # Recipient private key derives the correct public key.
            recipient_priv = X25519PrivateKey.from_private_bytes(_b64d(c["recipientPrivateKeyB64"]))
            got_pub = base64.b64encode(recipient_priv.public_key().public_bytes_raw()).decode("ascii")
            self.assertEqual(got_pub, c["recipientPublicKeyB64"], f"{c['name']}: recipient public key")

            wk = c["wrappedKey"]

            # Shared secret: X25519(recipientPriv, ephemeralPub), unhashed.
            eph_pub_raw = _b64d(wk["ephemeralPublicKey"])
            shared = recipient_priv.exchange(X25519PublicKey.from_public_bytes(eph_pub_raw))
            self.assertEqual(shared.hex(), c["sharedSecretHex"], f"{c['name']}: shared secret")

            # KEK: HKDF-SHA256(shared, salt=ephPubRaw, info, 32).
            kek = crypto.hkdf_sha256(shared, eph_pub_raw, c["info"].encode("utf-8"), 32)
            self.assertEqual(kek.hex(), c["kekHex"], f"{c['name']}: KEK")

            # unwrap_data_key recovers the data key.
            recovered = crypto.unwrap_data_key(recipient_priv, wk)
            self.assertEqual(
                base64.b64encode(recovered).decode("ascii"),
                c["dataKeyB64"],
                f"{c['name']}: unwrapped data key",
            )


class TestPayloadRoundTrip(unittest.TestCase):
    """encrypt_payload -> decrypt_payload round-trips correctly."""

    def test_round_trip(self) -> None:
        data_key = bytes(range(32))
        plaintext = b'{"alts":[],"payloadVersion":3}'
        env = crypto.encrypt_payload(data_key, "repo-x", 3, 1, plaintext)
        recovered = crypto.decrypt_payload(data_key, env)
        self.assertEqual(recovered, plaintext)


class TestWrapRoundTrip(unittest.TestCase):
    """wrap_data_key -> unwrap_data_key round-trips correctly."""

    def test_round_trip(self) -> None:
        priv = X25519PrivateKey.generate()
        pub_b64 = base64.b64encode(priv.public_key().public_bytes_raw()).decode("ascii")
        data_key = bytes([0xAB] * 32)
        wk = crypto.wrap_data_key(pub_b64, data_key)
        recovered = crypto.unwrap_data_key(priv, wk)
        self.assertEqual(recovered, data_key)


if __name__ == "__main__":
    unittest.main()
