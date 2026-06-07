// SPDX-License-Identifier: MIT

// Package avp implements the Alt Vault Protocol (AVP) cryptographic core and its
// HTTP/JSON wire types, for the reference client and server in this module.
//
// Unlike the other reference examples in this repository, which stub the envelope
// and wrapped-key crypto, this one implements the real constructions from SPEC §4
// and §9 end to end: the payload AEAD (AES-256-GCM with the AVP AAD), the default
// data-key wrap scheme X25519-HKDF-SHA256-AESGCM-v1, and the Ed25519 challenge
// signature and anti-MITM key binding. Every construction here is checked
// byte-for-byte against ../../../vectors/*.json by crypto_test.go, so a new
// implementation can read this package as a worked, conformance-verified reference
// for the parts that are easiest to get subtly wrong.
//
// The whole package is pure standard library and has no dependencies. HKDF-SHA256
// is hand-rolled from crypto/hmac (it is a short, vector-pinned construction); on
// Go 1.24+ the standard crypto/hkdf, or golang.org/x/crypto/hkdf on older
// toolchains, are drop-in replacements for HKDFSHA256.
//
// Encodings follow the spec: all key, nonce, signature, IV, and ciphertext fields
// on the wire are standard base64 with padding (base64url is used only for the §8
// federation tokens, which the client/server flow here does not exercise).
package avp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
)

// WrapSchemeID names the default data-key wrapping scheme (SPEC §4).
const WrapSchemeID = "X25519-HKDF-SHA256-AESGCM-v1"

// wrapInfo is both the HKDF info label and the AES-GCM AAD for data-key wrapping.
const wrapInfo = "avp/rdk-wrap/v1"

// std is standard base64 with padding, the encoding AVP uses for all wire bytes.
var std = base64.StdEncoding

// BuildAAD constructs the additional authenticated data bound into every payload
// envelope (SPEC §4):
//
//	AAD = UTF8(repoId) || 0x1F || int64BE(payloadVersion) || int64BE(keyEpoch)
//
// The 0x1F unit separator and the two big-endian counters make a stale-epoch or
// stale-version envelope fail authentication, which is what defeats rollback and
// cross-epoch replay.
func BuildAAD(repoID string, payloadVersion, keyEpoch int64) []byte {
	aad := make([]byte, 0, len(repoID)+1+16)
	aad = append(aad, repoID...)
	aad = append(aad, 0x1F)
	aad = binary.BigEndian.AppendUint64(aad, uint64(payloadVersion))
	aad = binary.BigEndian.AppendUint64(aad, uint64(keyEpoch))
	return aad
}

// KeyBindingMessage returns the canonical anti-MITM binding message (SPEC §9),
// whose UTF-8 bytes the identity provider signs:
//
//	bindingMessage = UTF8(ed25519PublicKey + "|" + x25519PublicKey)
//
// Both keys are their base64 wire forms.
func KeyBindingMessage(ed25519PubB64, x25519PubB64 string) []byte {
	return []byte(ed25519PubB64 + "|" + x25519PubB64)
}

// HKDFSHA256 derives length bytes from ikm using HKDF-SHA256 (RFC 5869): extract a
// pseudorandom key with HMAC, then expand it. An empty salt is replaced by HashLen
// zero bytes per RFC 5869 §2.2. AVP uses this to derive the 32-byte key-encryption
// key in the default wrap scheme (SPEC §4).
func HKDFSHA256(ikm, salt, info []byte, length int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	return hkdfExpand(hkdfExtract(salt, ikm), info, length)
}

// hkdfExtract is the RFC 5869 extract step: PRK = HMAC-SHA256(salt, ikm).
func hkdfExtract(salt, ikm []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// hkdfExpand is the RFC 5869 expand step: T(i) = HMAC(PRK, T(i-1) || info || i),
// output = first length bytes of T(1) || T(2) || ...
func hkdfExpand(prk, info []byte, length int) []byte {
	out := make([]byte, 0, length)
	var prev []byte
	for counter := byte(1); len(out) < length; counter++ {
		mac := hmac.New(sha256.New, prk)
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{counter})
		prev = mac.Sum(nil)
		out = append(out, prev...)
	}
	return out[:length]
}

// aesgcmSeal encrypts plaintext with AES-256-GCM (12-byte iv, 16-byte tag appended
// to the ciphertext) under the given AAD.
func aesgcmSeal(key, iv, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, iv, plaintext, aad), nil
}

// aesgcmOpen reverses aesgcmSeal, returning an error if the tag or AAD do not check.
func aesgcmOpen(key, iv, ciphertext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, iv, ciphertext, aad)
}

// newGCM builds an AES-GCM AEAD with the default 12-byte nonce and 16-byte tag.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// EncryptPayload AES-256-GCM-encrypts plaintext into an EncryptedEnvelope, binding
// (repoID, payloadVersion, keyEpoch) into the AAD (SPEC §4). dataKey must be 32
// bytes; a fresh random 12-byte IV is generated per call.
func EncryptPayload(dataKey []byte, repoID string, payloadVersion, keyEpoch int64, plaintext []byte) (EncryptedEnvelope, error) {
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return EncryptedEnvelope{}, err
	}
	ct, err := aesgcmSeal(dataKey, iv, plaintext, BuildAAD(repoID, payloadVersion, keyEpoch))
	if err != nil {
		return EncryptedEnvelope{}, err
	}
	return EncryptedEnvelope{
		RepoID:         repoID,
		PayloadVersion: payloadVersion,
		KeyEpoch:       keyEpoch,
		IV:             std.EncodeToString(iv),
		Ciphertext:     std.EncodeToString(ct),
	}, nil
}

// DecryptPayload reverses EncryptPayload. It rebuilds the AAD from the envelope's
// own (repoId, payloadVersion, keyEpoch), so a tampered counter fails authentication.
func DecryptPayload(dataKey []byte, env EncryptedEnvelope) ([]byte, error) {
	iv, err := std.DecodeString(env.IV)
	if err != nil {
		return nil, fmt.Errorf("decode iv: %w", err)
	}
	ct, err := std.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	return aesgcmOpen(dataKey, iv, ct, BuildAAD(env.RepoID, env.PayloadVersion, env.KeyEpoch))
}

// WrapDataKey wraps a 32-byte data key to a recipient's X25519 public key using the
// default scheme X25519-HKDF-SHA256-AESGCM-v1 (SPEC §4): an ephemeral X25519 key
// agreement (the shared secret is used raw, never hashed), an HKDF-SHA256 KEK
// salted by the ephemeral public key, and AES-256-GCM over the data key.
func WrapDataKey(recipientX25519PubB64 string, dataKey []byte) (WrappedKey, error) {
	recipientPub, err := ParseX25519PublicKey(recipientX25519PubB64)
	if err != nil {
		return WrappedKey{}, fmt.Errorf("recipient x25519 key: %w", err)
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return WrappedKey{}, err
	}
	shared, err := ephemeral.ECDH(recipientPub)
	if err != nil {
		return WrappedKey{}, err
	}
	ephemeralPubRaw := ephemeral.PublicKey().Bytes()
	kek := HKDFSHA256(shared, ephemeralPubRaw, []byte(wrapInfo), 32)
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return WrappedKey{}, err
	}
	ct, err := aesgcmSeal(kek, iv, dataKey, []byte(wrapInfo))
	if err != nil {
		return WrappedKey{}, err
	}
	return WrappedKey{
		SchemeID:           WrapSchemeID,
		EphemeralPublicKey: std.EncodeToString(ephemeralPubRaw),
		IV:                 std.EncodeToString(iv),
		Ciphertext:         std.EncodeToString(ct),
	}, nil
}

// UnwrapDataKey reverses WrapDataKey with the recipient's X25519 private key,
// recomputing the same shared secret and KEK and decrypting the wrapped data key.
func UnwrapDataKey(recipientPriv *ecdh.PrivateKey, wk WrappedKey) ([]byte, error) {
	if wk.SchemeID != WrapSchemeID {
		return nil, fmt.Errorf("unsupported wrap scheme %q", wk.SchemeID)
	}
	ephemeralPubRaw, err := std.DecodeString(wk.EphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode ephemeral key: %w", err)
	}
	ephemeralPub, err := ecdh.X25519().NewPublicKey(ephemeralPubRaw)
	if err != nil {
		return nil, fmt.Errorf("ephemeral x25519 key: %w", err)
	}
	shared, err := recipientPriv.ECDH(ephemeralPub)
	if err != nil {
		return nil, err
	}
	kek := HKDFSHA256(shared, ephemeralPubRaw, []byte(wrapInfo), 32)
	iv, err := std.DecodeString(wk.IV)
	if err != nil {
		return nil, fmt.Errorf("decode iv: %w", err)
	}
	ct, err := std.DecodeString(wk.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	return aesgcmOpen(kek, iv, ct, []byte(wrapInfo))
}

// GenerateX25519Key generates a fresh X25519 keypair for key wrapping.
func GenerateX25519Key() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// ParseX25519PublicKey decodes a base64 raw 32-byte X25519 public key.
func ParseX25519PublicKey(b64 string) (*ecdh.PublicKey, error) {
	raw, err := std.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPublicKey(raw)
}

// VerifyEd25519 reports whether sigB64 is a valid Ed25519 signature over message by
// the raw 32-byte public key pubB64 (both base64). This is the only cryptography
// the reference server performs: the challenge/response of SPEC §3.
func VerifyEd25519(pubB64 string, message []byte, sigB64 string) bool {
	pub, err := std.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := std.DecodeString(sigB64)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), message, sig)
}

// EncodeStd base64-encodes b with the standard AVP wire encoding. It is a thin
// helper so callers outside this package do not each reach for encoding/base64.
func EncodeStd(b []byte) string { return std.EncodeToString(b) }

// DecodeStd reverses EncodeStd.
func DecodeStd(s string) ([]byte, error) { return std.DecodeString(s) }
