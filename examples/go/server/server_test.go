// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"avp.example/reference/avp"
)

// These tests boot the reference server on an ephemeral port and drive it with real
// Ed25519 and X25519 keypairs, mirroring the smoke tests of the other reference
// servers. The headline test goes further than the placeholder examples: it does
// the real envelope crypto end to end and asserts that a second member decrypts,
// through the zero-knowledge server, exactly what the first member encrypted.

var b64 = base64.StdEncoding

// identity is a member's full keypair set for a test.
type identity struct {
	edPriv ed25519.PrivateKey
	edPub  string // base64 raw Ed25519 public key (the member id)
	xPriv  *ecdh.PrivateKey
	xPub   string // base64 raw X25519 public key
}

func newIdentity(t *testing.T) identity {
	t.Helper()
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xPriv, err := avp.GenerateX25519Key()
	if err != nil {
		t.Fatal(err)
	}
	return identity{
		edPriv: edPriv,
		edPub:  b64.EncodeToString(edPriv.Public().(ed25519.PublicKey)),
		xPriv:  xPriv,
		xPub:   b64.EncodeToString(xPriv.PublicKey().Bytes()),
	}
}

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(NewServer())
	t.Cleanup(srv.Close)
	return srv
}

func TestRejectsUnauthenticatedVaultCall(t *testing.T) {
	srv := newTestServer(t)
	status, _ := doPost(t, srv.URL, "/v1/repos", map[string]any{}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", status)
	}
}

func TestRejectsBadChallengeSignature(t *testing.T) {
	srv := newTestServer(t)
	alice := newIdentity(t)
	impostor := newIdentity(t)

	_, resp := doPost(t, srv.URL, "/api/auth/keypair/challenge",
		map[string]string{"ed25519PublicKey": alice.edPub}, "")
	nonce := decodeField(t, resp, "nonce")
	nonceBytes, err := b64.DecodeString(nonce)
	if err != nil {
		t.Fatal(err)
	}
	// Sign with the wrong key: the signature cannot verify against alice's pubkey.
	badSig := b64.EncodeToString(ed25519.Sign(impostor.edPriv, nonceBytes))
	status, _ := doPost(t, srv.URL, "/api/auth/keypair/token", map[string]string{
		"ed25519PublicKey": alice.edPub,
		"nonce":            nonce,
		"signature":        badSig,
	}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", status)
	}
}

func TestRejectsReusedNonce(t *testing.T) {
	srv := newTestServer(t)
	alice := newIdentity(t)

	_, resp := doPost(t, srv.URL, "/api/auth/keypair/challenge",
		map[string]string{"ed25519PublicKey": alice.edPub}, "")
	nonce := decodeField(t, resp, "nonce")
	nonceBytes, _ := b64.DecodeString(nonce)
	sig := b64.EncodeToString(ed25519.Sign(alice.edPriv, nonceBytes))
	body := map[string]string{"ed25519PublicKey": alice.edPub, "nonce": nonce, "signature": sig}

	if status, _ := doPost(t, srv.URL, "/api/auth/keypair/token", body, ""); status != http.StatusOK {
		t.Fatalf("first redemption status = %d, want 200", status)
	}
	if status, _ := doPost(t, srv.URL, "/api/auth/keypair/token", body, ""); status != http.StatusUnauthorized {
		t.Fatalf("second redemption status = %d, want 401", status)
	}
}

func TestFullLifecycleWithRealCrypto(t *testing.T) {
	srv := newTestServer(t)
	alice := newIdentity(t)
	bob := newIdentity(t)
	aliceToken := authenticate(t, srv.URL, alice)

	// alice mints a per-repo data key and encrypts a real payload under it.
	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		t.Fatal(err)
	}
	repoID := "repo-" + randomHex(t, 8)
	encPath := "/v1/repos/" + url.PathEscape(repoID)

	altsV1 := []avp.Alt{{UUID: "11111111-1111-4111-8111-111111111111", Username: "alice_main", AccessToken: "secret-v1", Type: "MICROSOFT", LastUsed: 1}}
	envV1 := encryptPayload(t, dataKey, repoID, 1, 0, altsV1)

	manifest := avp.VaultManifest{
		RepoID:         repoID,
		SchemeID:       avp.WrapSchemeID,
		KeyEpoch:       0,
		PayloadVersion: 1,
		Members:        []avp.MemberEntry{memberEntry(t, alice, dataKey, 0)},
	}
	status, resp := doPost(t, srv.URL, "/v1/repos",
		avp.CreateRepoRequest{Manifest: manifest, InitialEnvelope: envV1}, aliceToken)
	if status != http.StatusOK {
		t.Fatalf("createRepo status = %d: %s", status, resp)
	}

	// pull at the known version: unchanged, no envelope.
	status, resp = doPost(t, srv.URL, encPath+"/pull",
		avp.PullRequest{RepoID: repoID, KnownPayloadVersion: 1}, aliceToken)
	var known avp.PullResponse
	decode(t, resp, &known)
	if status != http.StatusOK || !known.Unchanged || known.Envelope != nil {
		t.Fatalf("pull(known): status=%d unchanged=%v envelope=%v", status, known.Unchanged, known.Envelope)
	}

	// pull from version 0: the current envelope comes back.
	_, resp = doPost(t, srv.URL, encPath+"/pull",
		avp.PullRequest{RepoID: repoID, KnownPayloadVersion: 0}, aliceToken)
	var stale avp.PullResponse
	decode(t, resp, &stale)
	if stale.Unchanged || stale.Envelope == nil {
		t.Fatalf("pull(stale): unchanged=%v envelope=%v", stale.Unchanged, stale.Envelope)
	}

	// push a real v2 payload with optimistic concurrency on the current version.
	altsV2 := append(altsV1, avp.Alt{UUID: "22222222-2222-4222-8222-222222222222", Username: "alice_alt", AccessToken: "secret-v2", Type: "MICROSOFT", LastUsed: 2})
	envV2 := encryptPayload(t, dataKey, repoID, 2, 0, altsV2)
	status, resp = doPost(t, srv.URL, encPath+"/push",
		avp.PushRequest{RepoID: repoID, Envelope: envV2, ExpectedPayloadVersion: 1}, aliceToken)
	var push avp.PushResponse
	decode(t, resp, &push)
	if status != http.StatusOK || !push.Accepted || push.Conflict || push.PayloadVersion != 2 {
		t.Fatalf("push: status=%d %+v", status, push)
	}

	// pushing again at the now-stale expected version is a conflict.
	_, resp = doPost(t, srv.URL, encPath+"/push",
		avp.PushRequest{RepoID: repoID, Envelope: envV2, ExpectedPayloadVersion: 1}, aliceToken)
	var conflict avp.PushResponse
	decode(t, resp, &conflict)
	if conflict.Accepted || !conflict.Conflict {
		t.Fatalf("expected conflict, got %+v", conflict)
	}

	// addMember: alice wraps the data key to bob's X25519 key and records his entry.
	status, resp = doPost(t, srv.URL, encPath+"/add-member",
		avp.MemberAddRequest{RepoID: repoID, Member: memberEntry(t, bob, dataKey, 0)}, aliceToken)
	var withBob avp.VaultManifest
	decode(t, resp, &withBob)
	if status != http.StatusOK || len(withBob.Members) != 2 {
		t.Fatalf("addMember: status=%d members=%d", status, len(withBob.Members))
	}

	// fetchMemberKey: look bob's entry back up by member id (URL-encoded path).
	status, resp = doGet(t, srv.URL, encPath+"/member/"+url.PathEscape(bob.edPub), aliceToken)
	var fetched avp.MemberEntry
	decode(t, resp, &fetched)
	if status != http.StatusOK || fetched.Ed25519PublicKey != bob.edPub {
		t.Fatalf("fetchMember: status=%d id=%s", status, fetched.Ed25519PublicKey)
	}

	// bob authenticates, pulls, unwraps the data key from his entry, and decrypts.
	bobToken := authenticate(t, srv.URL, bob)
	_, resp = doPost(t, srv.URL, encPath+"/pull",
		avp.PullRequest{RepoID: repoID, KnownPayloadVersion: 0}, bobToken)
	var bobPull avp.PullResponse
	decode(t, resp, &bobPull)
	if bobPull.Envelope == nil {
		t.Fatal("bob pull returned no envelope")
	}
	var bobEntry *avp.MemberEntry
	for i := range bobPull.Manifest.Members {
		if bobPull.Manifest.Members[i].Ed25519PublicKey == bob.edPub {
			bobEntry = &bobPull.Manifest.Members[i]
		}
	}
	if bobEntry == nil {
		t.Fatal("bob is not in the pulled roster")
	}
	bobDataKey, err := avp.UnwrapDataKey(bob.xPriv, bobEntry.WrappedDataKey)
	if err != nil {
		t.Fatalf("bob unwrap: %v", err)
	}
	plaintext, err := avp.DecryptPayload(bobDataKey, *bobPull.Envelope)
	if err != nil {
		t.Fatalf("bob decrypt: %v", err)
	}
	var got avp.Plaintext
	if err := json.Unmarshal(plaintext, &got); err != nil {
		t.Fatalf("bob parse payload: %v", err)
	}
	// The zero-knowledge server round-tripped alice's v2 payload to bob intact.
	want, _ := json.Marshal(altsV2)
	gotJSON, _ := json.Marshal(got.Alts)
	if !bytes.Equal(want, gotJSON) {
		t.Fatalf("bob recovered alts %s, want %s", gotJSON, want)
	}
	if !bytes.Equal(bobDataKey, dataKey) {
		t.Fatal("bob recovered a different data key than alice's")
	}
}

func TestNonMemberCannotReadRepo(t *testing.T) {
	srv := newTestServer(t)
	alice := newIdentity(t)
	charlie := newIdentity(t)
	aliceToken := authenticate(t, srv.URL, alice)

	dataKey := make([]byte, 32)
	_, _ = rand.Read(dataKey)
	repoID := "repo-" + randomHex(t, 8)
	env := encryptPayload(t, dataKey, repoID, 1, 0, nil)
	manifest := avp.VaultManifest{RepoID: repoID, SchemeID: avp.WrapSchemeID, PayloadVersion: 1, Members: []avp.MemberEntry{memberEntry(t, alice, dataKey, 0)}}
	if status, resp := doPost(t, srv.URL, "/v1/repos", avp.CreateRepoRequest{Manifest: manifest, InitialEnvelope: env}, aliceToken); status != http.StatusOK {
		t.Fatalf("createRepo: %d %s", status, resp)
	}

	charlieToken := authenticate(t, srv.URL, charlie)
	status, _ := doPost(t, srv.URL, "/v1/repos/"+url.PathEscape(repoID)+"/pull",
		avp.PullRequest{RepoID: repoID, KnownPayloadVersion: 0}, charlieToken)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", status)
	}
}

func TestUnknownRepoIs404(t *testing.T) {
	srv := newTestServer(t)
	alice := newIdentity(t)
	token := authenticate(t, srv.URL, alice)
	status, _ := doPost(t, srv.URL, "/v1/repos/does-not-exist/pull",
		avp.PullRequest{RepoID: "does-not-exist", KnownPayloadVersion: 0}, token)
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", status)
	}
}

// TestManifestPreservesShareRefreshTokens pins SPEC §5.1: the server MUST persist the
// refresh-token sharing policy and return it in every manifest it serves. The failure
// this guards is silent, not loud: a manifest record without the field answers 200 to
// a create that enabled the policy, then reports it absent forever after, and clients
// read that absence as "withhold". So this asserts the raw JSON too, not just a decode
// (a decode into a struct that lost the field would report the zero value and pass).
func TestManifestPreservesShareRefreshTokens(t *testing.T) {
	srv := newTestServer(t)
	alice := newIdentity(t)
	bob := newIdentity(t)
	aliceToken := authenticate(t, srv.URL, alice)

	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		t.Fatal(err)
	}
	repoID := "repo-" + randomHex(t, 8)
	encPath := "/v1/repos/" + url.PathEscape(repoID)

	manifest := avp.VaultManifest{
		RepoID:             repoID,
		SchemeID:           avp.WrapSchemeID,
		PayloadVersion:     1,
		Members:            []avp.MemberEntry{memberEntry(t, alice, dataKey, 0)},
		ShareRefreshTokens: true,
	}
	status, resp := doPost(t, srv.URL, "/v1/repos",
		avp.CreateRepoRequest{Manifest: manifest, InitialEnvelope: encryptPayload(t, dataKey, repoID, 1, 0, nil)}, aliceToken)
	if status != http.StatusOK {
		t.Fatalf("createRepo: %d %s", status, resp)
	}
	if !bytes.Contains(resp, []byte(`"shareRefreshTokens":true`)) {
		t.Fatalf("createRepo response dropped the policy: %s", resp)
	}

	// It survives a pull...
	_, resp = doPost(t, srv.URL, encPath+"/pull", avp.PullRequest{RepoID: repoID}, aliceToken)
	var pulled avp.PullResponse
	decode(t, resp, &pulled)
	if !pulled.Manifest.ShareRefreshTokens {
		t.Fatalf("pull lost the policy: %s", resp)
	}

	// ...a push, which rewrites the counters but must not touch the policy...
	envV2 := encryptPayload(t, dataKey, repoID, 2, 0, nil)
	if status, resp = doPost(t, srv.URL, encPath+"/push",
		avp.PushRequest{RepoID: repoID, Envelope: envV2, ExpectedPayloadVersion: 1}, aliceToken); status != http.StatusOK {
		t.Fatalf("push: %d %s", status, resp)
	}
	_, resp = doPost(t, srv.URL, encPath+"/pull", avp.PullRequest{RepoID: repoID}, aliceToken)
	decode(t, resp, &pulled)
	if !pulled.Manifest.ShareRefreshTokens {
		t.Fatalf("push lost the policy: %s", resp)
	}

	// ...and a roster change.
	_, resp = doPost(t, srv.URL, encPath+"/add-member",
		avp.MemberAddRequest{RepoID: repoID, Member: memberEntry(t, bob, dataKey, 0)}, aliceToken)
	var withBob avp.VaultManifest
	decode(t, resp, &withBob)
	if !withBob.ShareRefreshTokens {
		t.Fatalf("addMember lost the policy: %s", resp)
	}
}

// TestAbsentShareRefreshTokensReadsAsFalse pins the fail-closed default (SPEC §5.1):
// a manifest written by a client that predates the field carries no policy, and that
// absence means "withhold", never "share". The request body here is a hand-built map
// with the key genuinely missing, which is what an older peer puts on the wire.
func TestAbsentShareRefreshTokensReadsAsFalse(t *testing.T) {
	srv := newTestServer(t)
	alice := newIdentity(t)
	aliceToken := authenticate(t, srv.URL, alice)

	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		t.Fatal(err)
	}
	repoID := "repo-" + randomHex(t, 8)

	legacyManifest := map[string]any{
		"repoId":         repoID,
		"schemeId":       avp.WrapSchemeID,
		"keyEpoch":       0,
		"payloadVersion": 1,
		"members":        []avp.MemberEntry{memberEntry(t, alice, dataKey, 0)},
	}
	status, resp := doPost(t, srv.URL, "/v1/repos", map[string]any{
		"manifest":        legacyManifest,
		"initialEnvelope": encryptPayload(t, dataKey, repoID, 1, 0, nil),
	}, aliceToken)
	if status != http.StatusOK {
		t.Fatalf("createRepo: %d %s", status, resp)
	}
	var created avp.VaultManifest
	decode(t, resp, &created)
	if created.ShareRefreshTokens {
		t.Fatalf("absent policy must read as false, got true: %s", resp)
	}
}

// --- test helpers -----------------------------------------------------------

func authenticate(t *testing.T, base string, id identity) string {
	t.Helper()
	_, resp := doPost(t, base, "/api/auth/keypair/challenge", map[string]string{"ed25519PublicKey": id.edPub}, "")
	nonce := decodeField(t, resp, "nonce")
	nonceBytes, err := b64.DecodeString(nonce)
	if err != nil {
		t.Fatal(err)
	}
	sig := b64.EncodeToString(ed25519.Sign(id.edPriv, nonceBytes))
	status, resp := doPost(t, base, "/api/auth/keypair/token", map[string]string{
		"ed25519PublicKey": id.edPub, "nonce": nonce, "signature": sig,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("authenticate: status %d: %s", status, resp)
	}
	return decodeField(t, resp, "token")
}

// memberEntry builds a MemberEntry with the data key really wrapped to id's X25519 key.
func memberEntry(t *testing.T, id identity, dataKey []byte, epoch int64) avp.MemberEntry {
	t.Helper()
	wk, err := avp.WrapDataKey(id.xPub, dataKey)
	if err != nil {
		t.Fatal(err)
	}
	return avp.MemberEntry{Ed25519PublicKey: id.edPub, X25519PublicKey: id.xPub, WrappedDataKey: wk, KeyEpoch: epoch}
}

// encryptPayload encrypts the alts as the JSON payload at the given version/epoch.
func encryptPayload(t *testing.T, dataKey []byte, repoID string, version, epoch int64, alts []avp.Alt) avp.EncryptedEnvelope {
	t.Helper()
	body, err := json.Marshal(avp.Plaintext{Alts: alts, PayloadVersion: version})
	if err != nil {
		t.Fatal(err)
	}
	env, err := avp.EncryptPayload(dataKey, repoID, version, epoch, body)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func doPost(t *testing.T, base, path string, body any, token string) (int, []byte) {
	t.Helper()
	return do(t, http.MethodPost, base, path, body, token)
}

func doGet(t *testing.T, base, path, token string) (int, []byte) {
	t.Helper()
	return do(t, http.MethodGet, base, path, nil, token)
}

func do(t *testing.T, method, base, path string, body any, token string) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, base+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, data
}

func decode(t *testing.T, data []byte, dst any) {
	t.Helper()
	if err := json.Unmarshal(data, dst); err != nil {
		t.Fatalf("decode %s: %v", data, err)
	}
}

func decodeField(t *testing.T, data []byte, field string) string {
	t.Helper()
	var m map[string]json.RawMessage
	decode(t, data, &m)
	var s string
	if err := json.Unmarshal(m[field], &s); err != nil {
		t.Fatalf("field %q in %s: %v", field, data, err)
	}
	return s
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}
