// SPDX-License-Identifier: MIT

package avp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"testing"
)

// The single committed composition vectors prove byte-exactness for one input
// tuple; these fuzz tests cover the rest of the input space for the property the
// vectors cannot: that encrypt/decrypt and wrap/unwrap round-trip for arbitrary
// keys, repo ids, counters, and payloads. The seed corpus runs as ordinary tests
// under `go test`; `go test -fuzz=Fuzz...` explores further.

// FuzzPayloadRoundTrip asserts DecryptPayload recovers whatever EncryptPayload
// produced, for any data key, repo id, version, epoch, and plaintext.
func FuzzPayloadRoundTrip(f *testing.F) {
	f.Add([]byte("seed-key"), "repo-1", int64(1), int64(0), []byte(`{"alts":[],"payloadVersion":1}`))
	f.Add([]byte(""), "", int64(-1), int64(9223372036854775807), []byte(""))
	f.Add([]byte("k"), "repo/with/slashes\x1f", int64(0), int64(0), bytes.Repeat([]byte{0}, 4096))
	f.Fuzz(func(t *testing.T, keySeed []byte, repoID string, version, epoch int64, plaintext []byte) {
		key := sha256.Sum256(keySeed) // any input -> a valid 32-byte AES-256 key
		env, err := EncryptPayload(key[:], repoID, version, epoch, plaintext)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		got, err := DecryptPayload(key[:], env)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("payload round-trip mismatch: got %x want %x", got, plaintext)
		}
		// The counters are bound into the AAD: tampering one must fail authentication.
		if version != version+1 { // always true; guards against an int64 overflow no-op
			tampered := env
			tampered.PayloadVersion = version + 1
			if _, err := DecryptPayload(key[:], tampered); err == nil {
				t.Fatalf("decrypt with tampered version unexpectedly succeeded")
			}
		}
	})
}

// FuzzWrapRoundTrip asserts UnwrapDataKey recovers the data key WrapDataKey wrapped,
// for any data key and recipient keypair.
func FuzzWrapRoundTrip(f *testing.F) {
	f.Add([]byte("key-seed"), []byte("scalar-seed"))
	f.Add([]byte(""), []byte(""))
	f.Fuzz(func(t *testing.T, dataKeySeed, scalarSeed []byte) {
		dataKey := sha256.Sum256(dataKeySeed)
		scalar := sha256.Sum256(scalarSeed) // any 32 bytes is a valid X25519 scalar
		recipient, err := ecdh.X25519().NewPrivateKey(scalar[:])
		if err != nil {
			t.Skip() // vanishingly unlikely (e.g. all-zero scalar)
		}
		wk, err := WrapDataKey(std.EncodeToString(recipient.PublicKey().Bytes()), dataKey[:])
		if err != nil {
			t.Fatalf("wrap: %v", err)
		}
		got, err := UnwrapDataKey(recipient, wk)
		if err != nil {
			t.Fatalf("unwrap: %v", err)
		}
		if !bytes.Equal(got, dataKey[:]) {
			t.Fatalf("wrap round-trip mismatch")
		}
	})
}
