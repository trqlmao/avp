// SPDX-License-Identifier: MIT

// Command client is a runnable reference client for the Alt Vault Protocol (AVP),
// HTTP/JSON profile. It drives the whole wire contract against a running server (the
// sibling ../server, or any conformant server) so an implementer can watch the full
// lifecycle end to end: generate keypairs, run the challenge -> sign -> token auth
// flow, create a repo, pull, push a new version, invite a second member, fetch that
// member's key, and finally have the second member pull, unwrap, and decrypt.
//
// Unlike the other reference clients in this repository, the envelope and
// wrapped-key cryptography here is REAL (SPEC §4): alice derives a per-repo data
// key, AES-256-GCM-encrypts the alt payload binding (repoId, payloadVersion,
// keyEpoch) into the AAD, and wraps the data key to each member's X25519 key with
// X25519 + HKDF-SHA256. The server stays zero-knowledge throughout, so at the end
// bob recovers exactly what alice stored. The crypto lives in the sibling avp
// package and is verified against ../../../vectors by that package's tests.
//
// Run: go run . (drives the flow against http://localhost:8787). Point it at another
// server with the AVP_SERVER_URL environment variable.
package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"avp.example/reference/avp"
)

var std = base64.StdEncoding

// member is one member's full keypair set: an Ed25519 signing key (its base64 raw
// public key is the member id) and an X25519 key for data-key wrapping.
type member struct {
	edPriv ed25519.PrivateKey
	edPub  string
	xPriv  *ecdh.PrivateKey
	xPub   string
}

func main() {
	if err := run(); err != nil {
		fmt.Printf("\nClient failed: %v\n", err)
		fmt.Println("Is a server running? Start one with `go run .` in ../server, or set AVP_SERVER_URL.")
		os.Exit(1)
	}
}

func run() error {
	base := strings.TrimRight(envOr("AVP_SERVER_URL", "http://localhost:8787"), "/")
	fmt.Printf("AVP reference client -> %s\n", base)
	fmt.Println("(Envelope and wrapped-key crypto is real; the server stays zero-knowledge.)")
	fmt.Println()

	alice, err := newIdentity()
	if err != nil {
		return err
	}
	bob, err := newIdentity()
	if err != nil {
		return err
	}
	step("members", fmt.Sprintf("alice=%s… bob=%s…", short(alice.edPub), short(bob.edPub)))

	// 1. Authenticate alice (challenge -> sign nonce -> token).
	aliceToken, err := authenticate(base, alice)
	if err != nil {
		return err
	}
	step("auth", fmt.Sprintf("alice token=%s…", short(aliceToken)))

	// 2. alice mints a per-repo data key and encrypts a real initial payload.
	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		return err
	}
	repoID, err := uuid4()
	if err != nil {
		return err
	}
	encPath := "/v1/repos/" + url.PathEscape(repoID)

	altsV1 := []avp.Alt{{UUID: "11111111-1111-4111-8111-111111111111", Username: "alice_main", AccessToken: "secret-v1", Type: "MICROSOFT", LastUsed: 1}}
	envV1, err := encryptAlts(dataKey, repoID, 1, 0, altsV1)
	if err != nil {
		return err
	}
	aliceEntry, err := memberEntry(alice, dataKey, 0)
	if err != nil {
		return err
	}

	// 3. createRepo: alice must be the sole member of the manifest she creates.
	var manifest avp.VaultManifest
	if err := callJSON(base, "POST", "/v1/repos", avp.CreateRepoRequest{
		Manifest: avp.VaultManifest{
			RepoID:         repoID,
			SchemeID:       avp.WrapSchemeID,
			KeyEpoch:       0,
			PayloadVersion: 1,
			Members:        []avp.MemberEntry{aliceEntry},
		},
		InitialEnvelope: envV1,
	}, aliceToken, &manifest); err != nil {
		return err
	}
	step("createRepo", fmt.Sprintf("repoId=%s members=%d v=%d", manifest.RepoID, len(manifest.Members), manifest.PayloadVersion))

	// 4. pull at the version we already know: unchanged, envelope omitted.
	var pullKnown avp.PullResponse
	if err := callJSON(base, "POST", encPath+"/pull", avp.PullRequest{RepoID: repoID, KnownPayloadVersion: manifest.PayloadVersion}, aliceToken, &pullKnown); err != nil {
		return err
	}
	step("pull (known)", fmt.Sprintf("unchanged=%v envelope=%s", pullKnown.Unchanged, present(pullKnown.Envelope)))

	// 5. pull from version 0: the current envelope comes back.
	var pullStale avp.PullResponse
	if err := callJSON(base, "POST", encPath+"/pull", avp.PullRequest{RepoID: repoID, KnownPayloadVersion: 0}, aliceToken, &pullStale); err != nil {
		return err
	}
	step("pull (stale)", fmt.Sprintf("unchanged=%v envelope=%s", pullStale.Unchanged, present(pullStale.Envelope)))

	// 6. push a real v2 payload with optimistic concurrency on the current version.
	altsV2 := append(altsV1, avp.Alt{UUID: "22222222-2222-4222-8222-222222222222", Username: "alice_alt", AccessToken: "secret-v2", Type: "MICROSOFT", LastUsed: 2})
	envV2, err := encryptAlts(dataKey, repoID, 2, 0, altsV2)
	if err != nil {
		return err
	}
	var push avp.PushResponse
	if err := callJSON(base, "POST", encPath+"/push", avp.PushRequest{RepoID: repoID, Envelope: envV2, ExpectedPayloadVersion: manifest.PayloadVersion}, aliceToken, &push); err != nil {
		return err
	}
	step("push", fmt.Sprintf("accepted=%v conflict=%v v=%d", push.Accepted, push.Conflict, push.PayloadVersion))

	// 7. re-push at the now-stale expected version to show the conflict path.
	var conflict avp.PushResponse
	if err := callJSON(base, "POST", encPath+"/push", avp.PushRequest{RepoID: repoID, Envelope: envV2, ExpectedPayloadVersion: manifest.PayloadVersion}, aliceToken, &conflict); err != nil {
		return err
	}
	step("push (stale)", fmt.Sprintf("accepted=%v conflict=%v serverV=%d", conflict.Accepted, conflict.Conflict, conflict.PayloadVersion))

	// 8. addMember: alice wraps the data key to bob's X25519 key and records his entry.
	bobEntry, err := memberEntry(bob, dataKey, 0)
	if err != nil {
		return err
	}
	var withBob avp.VaultManifest
	if err := callJSON(base, "POST", encPath+"/add-member", avp.MemberAddRequest{RepoID: repoID, Member: bobEntry}, aliceToken, &withBob); err != nil {
		return err
	}
	step("addMember", fmt.Sprintf("members=%d (added bob)", len(withBob.Members)))

	// 9. fetchMemberKey: look bob's entry back up by member id (URL-encoded path).
	var fetched avp.MemberEntry
	if err := callJSON(base, "GET", encPath+"/member/"+url.PathEscape(bob.edPub), nil, aliceToken, &fetched); err != nil {
		return err
	}
	step("fetchMemberKey", fmt.Sprintf("bob x25519=%s… epoch=%d", short(fetched.X25519PublicKey), fetched.KeyEpoch))

	// 10. bob authenticates, pulls, unwraps the data key, and decrypts the payload.
	bobToken, err := authenticate(base, bob)
	if err != nil {
		return err
	}
	var bobPull avp.PullResponse
	if err := callJSON(base, "POST", encPath+"/pull", avp.PullRequest{RepoID: repoID, KnownPayloadVersion: 0}, bobToken, &bobPull); err != nil {
		return err
	}
	if bobPull.Envelope == nil {
		return fmt.Errorf("bob's pull returned no envelope")
	}
	bobEntryPulled := findMember(bobPull.Manifest, bob.edPub)
	if bobEntryPulled == nil {
		return fmt.Errorf("bob is not in the pulled roster")
	}
	bobDataKey, err := avp.UnwrapDataKey(bob.xPriv, bobEntryPulled.WrappedDataKey)
	if err != nil {
		return fmt.Errorf("bob unwrap: %w", err)
	}
	plaintext, err := avp.DecryptPayload(bobDataKey, *bobPull.Envelope)
	if err != nil {
		return fmt.Errorf("bob decrypt: %w", err)
	}
	var payload avp.Plaintext
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return fmt.Errorf("bob parse payload: %w", err)
	}
	step("bob pull", fmt.Sprintf("v=%d alts=%d (decrypted)", bobPull.Manifest.PayloadVersion, len(payload.Alts)))
	for _, alt := range payload.Alts {
		step("  alt", fmt.Sprintf("%s (%s)", alt.Username, alt.UUID))
	}

	fmt.Println("\nDone. Full lifecycle exercised against a zero-knowledge server; bob decrypted alice's payload.")
	return nil
}

// --- identity ---------------------------------------------------------------

func newIdentity() (member, error) {
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return member{}, err
	}
	xPriv, err := avp.GenerateX25519Key()
	if err != nil {
		return member{}, err
	}
	return member{
		edPriv: edPriv,
		edPub:  std.EncodeToString(edPriv.Public().(ed25519.PublicKey)),
		xPriv:  xPriv,
		xPub:   std.EncodeToString(xPriv.PublicKey().Bytes()),
	}, nil
}

// memberEntry builds a MemberEntry with the data key really wrapped to the member's
// X25519 public key (SPEC §4).
func memberEntry(m member, dataKey []byte, epoch int64) (avp.MemberEntry, error) {
	wk, err := avp.WrapDataKey(m.xPub, dataKey)
	if err != nil {
		return avp.MemberEntry{}, err
	}
	return avp.MemberEntry{Ed25519PublicKey: m.edPub, X25519PublicKey: m.xPub, WrappedDataKey: wk, KeyEpoch: epoch}, nil
}

// --- auth + HTTP ------------------------------------------------------------

func authenticate(base string, m member) (string, error) {
	resp, err := call(base, "POST", "/api/auth/keypair/challenge", map[string]string{"ed25519PublicKey": m.edPub}, "")
	if err != nil {
		return "", err
	}
	var ch struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(resp, &ch); err != nil {
		return "", err
	}
	// Sign the RAW nonce bytes (base64-decoded), which is what a server verifies.
	nonceBytes, err := std.DecodeString(ch.Nonce)
	if err != nil {
		return "", err
	}
	sig := std.EncodeToString(ed25519.Sign(m.edPriv, nonceBytes))
	resp, err = call(base, "POST", "/api/auth/keypair/token", map[string]string{
		"ed25519PublicKey": m.edPub, "nonce": ch.Nonce, "signature": sig,
	}, "")
	if err != nil {
		return "", err
	}
	var tok struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(resp, &tok); err != nil {
		return "", err
	}
	return tok.Token, nil
}

// callJSON sends a request and unmarshals a successful response into out.
func callJSON(base, method, path string, body any, token string, out any) error {
	resp, err := call(base, method, path, body, token)
	if err != nil {
		return err
	}
	return json.Unmarshal(resp, out)
}

// call sends a JSON request and returns the response body, raising on non-2xx.
func call(base, method, path string, body any, token string) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, base+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("%s %s -> %d: %s", method, path, res.StatusCode, data)
	}
	return data, nil
}

// --- small helpers ----------------------------------------------------------

func encryptAlts(dataKey []byte, repoID string, version, epoch int64, alts []avp.Alt) (avp.EncryptedEnvelope, error) {
	body, err := json.Marshal(avp.Plaintext{Alts: alts, PayloadVersion: version})
	if err != nil {
		return avp.EncryptedEnvelope{}, err
	}
	return avp.EncryptPayload(dataKey, repoID, version, epoch, body)
}

func findMember(m avp.VaultManifest, id string) *avp.MemberEntry {
	for i := range m.Members {
		if m.Members[i].Ed25519PublicKey == id {
			return &m.Members[i]
		}
	}
	return nil
}

func step(label, detail string) { fmt.Printf("  %-16s %s\n", label, detail) }

func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

func present(e *avp.EncryptedEnvelope) string {
	if e == nil {
		return "null"
	}
	return "present"
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// uuid4 returns a random RFC 4122 version-4 UUID string for use as an opaque repoId.
func uuid4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
