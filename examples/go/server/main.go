// SPDX-License-Identifier: MIT

// Command server is an in-memory reference server for the Alt Vault Protocol (AVP),
// HTTP/JSON profile. It implements the whole wire contract so an implementer can
// point a client at something real, and it is a sibling of the TypeScript, Rust,
// Python, and Java reference servers in this repository: it behaves identically on
// the wire.
//
// It is intentionally tiny and NOT production code: state lives in process memory
// and is lost on restart, there is no TLS, and the bearer token is an opaque random
// string mapped to a member id in this same process (a real deployment mints a JWT
// verifiable via JWKS, as SPEC §3 describes). What it does honour is the part that
// matters: it is zero-knowledge. It stores only the manifest, the encrypted
// envelope, the per-member wrapped keys, public keys, and the version/epoch counters
// that clients send, and it decrypts nothing. The only cryptography it performs is
// verifying the Ed25519 challenge signature. Field shapes follow
// ../../../schema/avp.schema.json.
//
// Run: go run . (listens on http://localhost:8787; set PORT to change).
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"avp.example/reference/avp"
)

const (
	nonceTTL = 2 * time.Minute
	tokenTTL = time.Hour
)

// storedRepo is the manifest plus the latest encrypted envelope for one repository.
type storedRepo struct {
	manifest avp.VaultManifest
	envelope avp.EncryptedEnvelope
}

// pendingNonce is an issued, not-yet-redeemed auth challenge.
type pendingNonce struct {
	publicKey string
	expiresAt time.Time
}

// Server holds all protocol state in memory behind a single mutex. It is lost on
// restart; that is fine for a reference.
type Server struct {
	mu     sync.Mutex
	repos  map[string]*storedRepo
	nonces map[string]pendingNonce
	tokens map[string]string // opaque bearer token -> member id (Ed25519 public key)
}

// NewServer returns an empty, ready-to-serve Server. It implements http.Handler.
func NewServer() *Server {
	return &Server{
		repos:  map[string]*storedRepo{},
		nonces: map[string]pendingNonce{},
		tokens: map[string]string{},
	}
}

// ServeHTTP routes a request. The two auth routes are open; everything else needs a
// bearer token resolved from the in-memory token map. Routing uses the escaped path
// so a percent-encoded slash in a base64 member id is not mistaken for a separator.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.EscapedPath()
	switch {
	case r.Method == http.MethodPost && path == "/api/auth/keypair/challenge":
		s.handleChallenge(w, r)
	case r.Method == http.MethodPost && path == "/api/auth/keypair/token":
		s.handleToken(w, r)
	default:
		s.handleAuthed(w, r)
	}
}

// --- Auth: challenge -> token (SPEC §3) -------------------------------------

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Ed25519PublicKey string `json:"ed25519PublicKey"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	nonce := base64.StdEncoding.EncodeToString(randomBytes(32))
	s.mu.Lock()
	s.nonces[nonce] = pendingNonce{publicKey: body.Ed25519PublicKey, expiresAt: time.Now().Add(nonceTTL)}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"nonce": nonce})
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Ed25519PublicKey string `json:"ed25519PublicKey"`
		Nonce            string `json:"nonce"`
		Signature        string `json:"signature"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	s.mu.Lock()
	challenge, ok := s.nonces[body.Nonce]
	delete(s.nonces, body.Nonce) // single-use
	s.mu.Unlock()
	if !ok || challenge.publicKey != body.Ed25519PublicKey || time.Now().After(challenge.expiresAt) {
		writeJSON(w, http.StatusUnauthorized, errBody("invalid or expired nonce"))
		return
	}
	// Verify the signature over the base64-DECODED nonce bytes.
	nonceBytes, err := base64.StdEncoding.DecodeString(body.Nonce)
	if err != nil || !avp.VerifyEd25519(body.Ed25519PublicKey, nonceBytes, body.Signature) {
		writeJSON(w, http.StatusUnauthorized, errBody("bad signature"))
		return
	}
	token := base64.RawURLEncoding.EncodeToString(randomBytes(32))
	s.mu.Lock()
	s.tokens[token] = body.Ed25519PublicKey
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"token":     token,
		"expiresAt": time.Now().Add(tokenTTL).UnixMilli(),
	})
}

// --- Authenticated vault operations -----------------------------------------

func (s *Server) handleAuthed(w http.ResponseWriter, r *http.Request) {
	caller := s.callerID(r)
	if caller == "" {
		writeJSON(w, http.StatusUnauthorized, errBody("missing or unknown bearer token"))
		return
	}
	path := r.URL.EscapedPath()

	if r.Method == http.MethodPost && path == "/v1/repos" {
		s.handleCreateRepo(w, r, caller)
		return
	}
	if r.Method == http.MethodGet {
		if repoID, memberID, ok := matchMember(path); ok {
			s.handleFetchMember(w, caller, repoID, memberID)
			return
		}
	}
	if r.Method == http.MethodPost {
		if op, repoID, ok := matchRepoOp(path); ok {
			s.handleRepoOp(w, r, caller, op, repoID)
			return
		}
	}
	writeJSON(w, http.StatusNotFound, errBody("no such route"))
}

func (s *Server) handleCreateRepo(w http.ResponseWriter, r *http.Request, caller string) {
	var req avp.CreateRepoRequest
	if !readJSON(w, r, &req) {
		return
	}
	members := req.Manifest.Members
	if len(members) != 1 || members[0].Ed25519PublicKey != caller {
		writeJSON(w, http.StatusForbidden, errBody("creator must be the sole member"))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.repos[req.Manifest.RepoID]; exists {
		writeJSON(w, http.StatusConflict, errBody("repo already exists"))
		return
	}
	s.repos[req.Manifest.RepoID] = &storedRepo{manifest: req.Manifest, envelope: req.InitialEnvelope}
	writeJSON(w, http.StatusOK, req.Manifest)
}

func (s *Server) handleRepoOp(w http.ResponseWriter, r *http.Request, caller, op, repoID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.authorizedRepo(w, repoID, caller)
	if !ok {
		return
	}
	switch op {
	case "pull":
		var req avp.PullRequest
		if !readJSON(w, r, &req) {
			return
		}
		if req.KnownPayloadVersion == stored.manifest.PayloadVersion {
			writeJSON(w, http.StatusOK, avp.PullResponse{Manifest: stored.manifest, Unchanged: true})
			return
		}
		envelope := stored.envelope
		writeJSON(w, http.StatusOK, avp.PullResponse{Manifest: stored.manifest, Envelope: &envelope})
	case "push":
		var req avp.PushRequest
		if !readJSON(w, r, &req) {
			return
		}
		if req.ExpectedPayloadVersion != stored.manifest.PayloadVersion {
			writeJSON(w, http.StatusOK, avp.PushResponse{
				Conflict:       true,
				PayloadVersion: stored.manifest.PayloadVersion,
				KeyEpoch:       stored.manifest.KeyEpoch,
			})
			return
		}
		stored.envelope = req.Envelope
		stored.manifest.PayloadVersion = req.Envelope.PayloadVersion
		stored.manifest.KeyEpoch = req.Envelope.KeyEpoch
		if req.RotatedMembers != nil {
			stored.manifest.Members = req.RotatedMembers
		}
		writeJSON(w, http.StatusOK, avp.PushResponse{
			Accepted:       true,
			PayloadVersion: stored.manifest.PayloadVersion,
			KeyEpoch:       stored.manifest.KeyEpoch,
		})
	case "add-member":
		var req avp.MemberAddRequest
		if !readJSON(w, r, &req) {
			return
		}
		if !isMember(stored.manifest, req.Member.Ed25519PublicKey) {
			stored.manifest.Members = append(stored.manifest.Members, req.Member)
		}
		writeJSON(w, http.StatusOK, stored.manifest)
	case "remove-member":
		var req avp.MemberRemoveRequest
		if !readJSON(w, r, &req) {
			return
		}
		stored.manifest.Members = req.RewrappedMembers
		stored.envelope = req.RotatedEnvelope
		stored.manifest.KeyEpoch = req.NewKeyEpoch
		stored.manifest.PayloadVersion = req.RotatedEnvelope.PayloadVersion
		writeJSON(w, http.StatusOK, stored.manifest)
	default:
		writeJSON(w, http.StatusNotFound, errBody("no such route"))
	}
}

func (s *Server) handleFetchMember(w http.ResponseWriter, caller, repoID, memberID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.authorizedRepo(w, repoID, caller)
	if !ok {
		return
	}
	for _, m := range stored.manifest.Members {
		if m.Ed25519PublicKey == memberID {
			writeJSON(w, http.StatusOK, m)
			return
		}
	}
	writeJSON(w, http.StatusNotFound, errBody("member not found"))
}

// authorizedRepo returns the stored repo when it exists and caller is a member; it
// otherwise writes the 404/403 response and reports ok=false. Callers must hold s.mu.
func (s *Server) authorizedRepo(w http.ResponseWriter, repoID, caller string) (*storedRepo, bool) {
	stored, ok := s.repos[repoID]
	if !ok {
		writeJSON(w, http.StatusNotFound, errBody("repo not found"))
		return nil, false
	}
	if !isMember(stored.manifest, caller) {
		writeJSON(w, http.StatusForbidden, errBody("caller is not a member"))
		return nil, false
	}
	return stored, true
}

// callerID resolves the member id behind a Bearer token, or "" if unauthenticated.
func (s *Server) callerID(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokens[strings.TrimPrefix(header, "Bearer ")]
}

// --- Routing helpers --------------------------------------------------------

// matchRepoOp matches /v1/repos/{repoId}/{op} and URL-decodes the repo id.
func matchRepoOp(path string) (op, repoID string, ok bool) {
	rest, found := strings.CutPrefix(path, "/v1/repos/")
	if !found {
		return "", "", false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 2 {
		return "", "", false
	}
	switch parts[1] {
	case "pull", "push", "add-member", "remove-member":
		return parts[1], urlDecode(parts[0]), true
	}
	return "", "", false
}

// matchMember matches /v1/repos/{repoId}/member/{memberId} and URL-decodes both
// (base64 member ids contain + / =, which clients percent-encode in the path).
func matchMember(path string) (repoID, memberID string, ok bool) {
	rest, found := strings.CutPrefix(path, "/v1/repos/")
	if !found {
		return "", "", false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 || parts[1] != "member" {
		return "", "", false
	}
	return urlDecode(parts[0]), urlDecode(parts[2]), true
}

func urlDecode(s string) string {
	if decoded, err := url.PathUnescape(s); err == nil {
		return decoded
	}
	return s
}

// --- Small shared helpers ---------------------------------------------------

func isMember(m avp.VaultManifest, id string) bool {
	for _, member := range m.Members {
		if member.Ed25519PublicKey == id {
			return true
		}
	}
	return false
}

func errBody(msg string) map[string]string { return map[string]string{"error": msg} }

// readJSON decodes the request body into dst, writing a 400 and returning false on
// malformed input.
func readJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request", "detail": err.Error()})
		return false
	}
	return true
}

// writeJSON serializes body as the full JSON response with the given status.
func writeJSON(w http.ResponseWriter, status int, body any) {
	payload, err := json.Marshal(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	return b
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8787"
	}
	addr := "127.0.0.1:" + port
	fmt.Printf("AVP reference server (in-memory) listening on http://localhost:%s\n", port)
	if err := http.ListenAndServe(addr, NewServer()); err != nil {
		log.Fatal(err)
	}
}
