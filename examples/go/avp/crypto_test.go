// SPDX-License-Identifier: MIT

package avp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// These tests check the constructions in crypto.go byte-for-byte against the
// repository's shared conformance vectors in ../../../vectors. They are the proof
// that this example interoperates: every primitive is pinned to a published RFC
// vector, and the composition vectors (payload AEAD and key wrap) are the same
// blobs the Node conformance runner and the Java reference implementation agree on.

// vectorsDir resolves the repo-root vectors directory relative to this package.
func vectorsDir() string { return filepath.Join("..", "..", "..", "vectors") }

// loadVector reads and JSON-decodes one vector file into dst.
func loadVector(t *testing.T, name string, dst any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorsDir(), name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
}

// mustHex decodes lowercase hex or fails the test.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestAADVectors(t *testing.T) {
	var file struct {
		Cases []struct {
			RepoID         string `json:"repoId"`
			PayloadVersion int64  `json:"payloadVersion"`
			KeyEpoch       int64  `json:"keyEpoch"`
			ExpectedAADHex string `json:"expectedAadHex"`
		} `json:"cases"`
	}
	loadVector(t, "aad.json", &file)
	if len(file.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range file.Cases {
		got := hex.EncodeToString(BuildAAD(c.RepoID, c.PayloadVersion, c.KeyEpoch))
		if got != c.ExpectedAADHex {
			t.Errorf("repoId=%q v=%d epoch=%d: AAD = %s, want %s",
				c.RepoID, c.PayloadVersion, c.KeyEpoch, got, c.ExpectedAADHex)
		}
	}
}

func TestKeyBindingMessageVectors(t *testing.T) {
	var file struct {
		Cases []struct {
			Ed25519PublicKey    string `json:"ed25519PublicKey"`
			X25519PublicKey     string `json:"x25519PublicKey"`
			ExpectedMessageUtf8 string `json:"expectedMessageUtf8"`
		} `json:"cases"`
	}
	loadVector(t, "key-binding-message.json", &file)
	for _, c := range file.Cases {
		got := string(KeyBindingMessage(c.Ed25519PublicKey, c.X25519PublicKey))
		if got != c.ExpectedMessageUtf8 {
			t.Errorf("binding message = %q, want %q", got, c.ExpectedMessageUtf8)
		}
	}
}

func TestHKDFVectors(t *testing.T) {
	var file struct {
		Cases []struct {
			Name    string `json:"name"`
			IKMHex  string `json:"ikmHex"`
			SaltHex string `json:"saltHex"`
			InfoHex string `json:"infoHex"`
			Length  int    `json:"length"`
			PRKHex  string `json:"prkHex"`
			OKMHex  string `json:"okmHex"`
		} `json:"cases"`
	}
	loadVector(t, "hkdf.json", &file)
	for _, c := range file.Cases {
		salt := mustHex(t, c.SaltHex)
		if len(salt) == 0 {
			salt = make([]byte, 32) // RFC 5869 §2.2: empty salt -> HashLen zero bytes
		}
		prk := hkdfExtract(salt, mustHex(t, c.IKMHex))
		if got := hex.EncodeToString(prk); got != c.PRKHex {
			t.Errorf("%s: PRK = %s, want %s", c.Name, got, c.PRKHex)
		}
		okm := HKDFSHA256(mustHex(t, c.IKMHex), mustHex(t, c.SaltHex), mustHex(t, c.InfoHex), c.Length)
		if got := hex.EncodeToString(okm); got != c.OKMHex {
			t.Errorf("%s: OKM = %s, want %s", c.Name, got, c.OKMHex)
		}
	}
}

func TestX25519Vectors(t *testing.T) {
	var file struct {
		Cases []struct {
			Name           string `json:"name"`
			ScalarHex      string `json:"scalarHex"`
			UCoordinateHex string `json:"uCoordinateHex"`
			OutputHex      string `json:"outputHex"`
		} `json:"cases"`
	}
	loadVector(t, "x25519.json", &file)
	for _, c := range file.Cases {
		priv, err := ecdh.X25519().NewPrivateKey(mustHex(t, c.ScalarHex))
		if err != nil {
			t.Errorf("%s: NewPrivateKey: %v", c.Name, err)
			continue
		}
		pub, err := ecdh.X25519().NewPublicKey(mustHex(t, c.UCoordinateHex))
		if err != nil {
			t.Errorf("%s: NewPublicKey: %v", c.Name, err)
			continue
		}
		shared, err := priv.ECDH(pub)
		if err != nil {
			t.Errorf("%s: ECDH: %v", c.Name, err)
			continue
		}
		if got := hex.EncodeToString(shared); got != c.OutputHex {
			t.Errorf("%s: shared = %s, want %s", c.Name, got, c.OutputHex)
		}
	}
}

func TestEd25519Vectors(t *testing.T) {
	var file struct {
		Cases []struct {
			Name         string `json:"name"`
			SeedHex      string `json:"seedHex"`
			PublicKeyHex string `json:"publicKeyHex"`
			MessageHex   string `json:"messageHex"`
			SignatureHex string `json:"signatureHex"`
		} `json:"cases"`
	}
	loadVector(t, "ed25519.json", &file)
	for _, c := range file.Cases {
		priv := ed25519.NewKeyFromSeed(mustHex(t, c.SeedHex))
		pub := priv.Public().(ed25519.PublicKey)
		if got := hex.EncodeToString(pub); got != c.PublicKeyHex {
			t.Errorf("%s: public key = %s, want %s", c.Name, got, c.PublicKeyHex)
		}
		msg := mustHex(t, c.MessageHex)
		sig := ed25519.Sign(priv, msg)
		if got := hex.EncodeToString(sig); got != c.SignatureHex {
			t.Errorf("%s: signature = %s, want %s", c.Name, got, c.SignatureHex)
		}
		if !ed25519.Verify(pub, msg, sig) {
			t.Errorf("%s: signature did not verify", c.Name)
		}
	}
}

func TestPayloadAEADVectors(t *testing.T) {
	var file struct {
		Cases []struct {
			Name          string `json:"name"`
			KeyB64        string `json:"keyB64"`
			IVB64         string `json:"ivB64"`
			RepoID        string `json:"repoId"`
			PayloadVer    int64  `json:"payloadVersion"`
			KeyEpoch      int64  `json:"keyEpoch"`
			AADHex        string `json:"aadHex"`
			PlaintextUtf8 string `json:"plaintextUtf8"`
			CiphertextB64 string `json:"ciphertextB64"`
			TamperEpoch   int64  `json:"tamperEpoch"`
		} `json:"cases"`
	}
	loadVector(t, "payload-aead.json", &file)
	for _, c := range file.Cases {
		key := mustB64(t, c.KeyB64)
		iv := mustB64(t, c.IVB64)
		aad := BuildAAD(c.RepoID, c.PayloadVer, c.KeyEpoch)
		if got := hex.EncodeToString(aad); got != c.AADHex {
			t.Errorf("%s: AAD = %s, want %s", c.Name, got, c.AADHex)
		}
		// (a) re-encrypt and assert the committed ciphertext.
		ct, err := aesgcmSeal(key, iv, []byte(c.PlaintextUtf8), aad)
		if err != nil {
			t.Fatalf("%s: seal: %v", c.Name, err)
		}
		if got := std.EncodeToString(ct); got != c.CiphertextB64 {
			t.Errorf("%s: ciphertext = %s, want %s", c.Name, got, c.CiphertextB64)
		}
		// (b) decrypt and assert plaintext recovery.
		pt, err := aesgcmOpen(key, iv, mustB64(t, c.CiphertextB64), aad)
		if err != nil {
			t.Fatalf("%s: open: %v", c.Name, err)
		}
		if string(pt) != c.PlaintextUtf8 {
			t.Errorf("%s: plaintext = %q, want %q", c.Name, pt, c.PlaintextUtf8)
		}
		// (c) a tampered epoch in the AAD must fail authentication.
		tampered := BuildAAD(c.RepoID, c.PayloadVer, c.TamperEpoch)
		if _, err := aesgcmOpen(key, iv, mustB64(t, c.CiphertextB64), tampered); err == nil {
			t.Errorf("%s: decryption with tampered epoch %d unexpectedly succeeded", c.Name, c.TamperEpoch)
		}
	}
}

func TestKeyWrapVectors(t *testing.T) {
	var file struct {
		Cases []struct {
			Name                   string     `json:"name"`
			RecipientPrivateKeyB64 string     `json:"recipientPrivateKeyB64"`
			RecipientPublicKeyB64  string     `json:"recipientPublicKeyB64"`
			DataKeyB64             string     `json:"dataKeyB64"`
			SharedSecretHex        string     `json:"sharedSecretHex"`
			KEKHex                 string     `json:"kekHex"`
			Info                   string     `json:"info"`
			WrappedKey             WrappedKey `json:"wrappedKey"`
		} `json:"cases"`
	}
	loadVector(t, "key-wrap.json", &file)
	for _, c := range file.Cases {
		recipientPriv, err := ecdh.X25519().NewPrivateKey(mustB64(t, c.RecipientPrivateKeyB64))
		if err != nil {
			t.Fatalf("%s: recipient private key: %v", c.Name, err)
		}
		// The recipient public key derives from the private key.
		if got := std.EncodeToString(recipientPriv.PublicKey().Bytes()); got != c.RecipientPublicKeyB64 {
			t.Errorf("%s: recipient public = %s, want %s", c.Name, got, c.RecipientPublicKeyB64)
		}
		ephemeralPubRaw := mustB64(t, c.WrappedKey.EphemeralPublicKey)
		ephemeralPub, err := ecdh.X25519().NewPublicKey(ephemeralPubRaw)
		if err != nil {
			t.Fatalf("%s: ephemeral public key: %v", c.Name, err)
		}
		// shared = X25519(recipientPriv, ephemeralPub), unhashed.
		shared, err := recipientPriv.ECDH(ephemeralPub)
		if err != nil {
			t.Fatalf("%s: ECDH: %v", c.Name, err)
		}
		if got := hex.EncodeToString(shared); got != c.SharedSecretHex {
			t.Errorf("%s: shared = %s, want %s", c.Name, got, c.SharedSecretHex)
		}
		// KEK = HKDF-SHA256(shared, salt=ephemeralPubRaw, info, 32).
		kek := HKDFSHA256(shared, ephemeralPubRaw, []byte(c.Info), 32)
		if got := hex.EncodeToString(kek); got != c.KEKHex {
			t.Errorf("%s: KEK = %s, want %s", c.Name, got, c.KEKHex)
		}
		// (a) re-wrap with the committed IV and assert the committed ciphertext.
		rewrapped, err := aesgcmSeal(kek, mustB64(t, c.WrappedKey.IV), mustB64(t, c.DataKeyB64), []byte(c.Info))
		if err != nil {
			t.Fatalf("%s: seal: %v", c.Name, err)
		}
		if got := std.EncodeToString(rewrapped); got != c.WrappedKey.Ciphertext {
			t.Errorf("%s: wrapped ciphertext = %s, want %s", c.Name, got, c.WrappedKey.Ciphertext)
		}
		// (b) unwrap via the public API and assert data-key recovery.
		dataKey, err := UnwrapDataKey(recipientPriv, c.WrappedKey)
		if err != nil {
			t.Fatalf("%s: unwrap: %v", c.Name, err)
		}
		if !bytes.Equal(dataKey, mustB64(t, c.DataKeyB64)) {
			t.Errorf("%s: unwrapped data key did not match", c.Name)
		}
	}
}

// TestWrapRoundTrip exercises the random-IV public API: a freshly wrapped key
// unwraps back to the original data key.
func TestWrapRoundTrip(t *testing.T) {
	recipient, err := GenerateX25519Key()
	if err != nil {
		t.Fatal(err)
	}
	dataKey := bytes.Repeat([]byte{0xAB}, 32)
	wk, err := WrapDataKey(std.EncodeToString(recipient.PublicKey().Bytes()), dataKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapDataKey(recipient, wk)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, dataKey) {
		t.Fatal("round-tripped data key did not match")
	}
}

// TestPayloadRoundTrip exercises the random-IV payload API end to end.
func TestPayloadRoundTrip(t *testing.T) {
	dataKey := bytes.Repeat([]byte{0x11}, 32)
	env, err := EncryptPayload(dataKey, "repo-x", 3, 1, []byte(`{"alts":[],"payloadVersion":3}`))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := DecryptPayload(dataKey, env)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != `{"alts":[],"payloadVersion":3}` {
		t.Fatalf("plaintext = %q", pt)
	}
}

// mustB64 standard-base64-decodes or fails the test.
func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := std.DecodeString(s)
	if err != nil {
		t.Fatalf("bad base64 %q: %v", s, err)
	}
	return b
}
