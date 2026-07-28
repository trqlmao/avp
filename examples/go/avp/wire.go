// SPDX-License-Identifier: MIT

package avp

// This file holds the AVP HTTP/JSON message shapes. Field names are the proto
// field names in camelCase (see ../../../schema/avp.schema.json); the gRPC profile
// carries the same fields. Counters are int64 so they never round-trip through a
// float, and the opaque cryptographic blobs (wrapped keys, IVs, ciphertext) are
// plain base64 strings the server stores and echoes without ever interpreting.

// WrappedKey is a repo data key encrypted to one member's X25519 public key under
// the scheme named by SchemeID (the default is WrapSchemeID). All byte fields are
// standard base64.
type WrappedKey struct {
	SchemeID           string `json:"schemeId"`
	EphemeralPublicKey string `json:"ephemeralPublicKey"`
	IV                 string `json:"iv"`
	Ciphertext         string `json:"ciphertext"`
}

// MemberEntry is one member's public identity plus the data key wrapped to them at
// a given key epoch. KeyBindingSig is the optional anti-MITM signature (SPEC §9);
// it is a pointer so an absent binding serializes as JSON null, matching the other
// reference implementations.
type MemberEntry struct {
	Ed25519PublicKey string     `json:"ed25519PublicKey"`
	X25519PublicKey  string     `json:"x25519PublicKey"`
	WrappedDataKey   WrappedKey `json:"wrappedDataKey"`
	KeyEpoch         int64      `json:"keyEpoch"`
	KeyBindingSig    *string    `json:"keyBindingSig"`
}

// EncryptedEnvelope is the AES-256-GCM-encrypted alt payload. The server stores it
// verbatim and decrypts nothing; RepoID, PayloadVersion, and KeyEpoch are bound
// into the AAD (SPEC §4), so a peer reconstructs the exact AAD on decrypt.
type EncryptedEnvelope struct {
	RepoID         string `json:"repoId"`
	PayloadVersion int64  `json:"payloadVersion"`
	KeyEpoch       int64  `json:"keyEpoch"`
	IV             string `json:"iv"`
	Ciphertext     string `json:"ciphertext"`
}

// VaultManifest is the public, unencrypted description of a repository: its scheme,
// the current version and epoch counters, the member roster, and the refresh-token
// sharing policy.
//
// ShareRefreshTokens is why a typed manifest needs care (SPEC §5.1). A server that
// models the manifest as a fixed record and omits this field drops it: the create
// answers 200 having discarded the policy, the next pull reports it absent, every
// client reads that absence as false, and refresh tokens are stripped from then on
// with no error at any step. It is serialized without omitempty so the server
// always states the policy explicitly rather than leaving it to be inferred.
type VaultManifest struct {
	RepoID             string        `json:"repoId"`
	SchemeID           string        `json:"schemeId"`
	KeyEpoch           int64         `json:"keyEpoch"`
	PayloadVersion     int64         `json:"payloadVersion"`
	Members            []MemberEntry `json:"members"`
	ShareRefreshTokens bool          `json:"shareRefreshTokens"`
}

// Plaintext is the decrypted payload carried inside an EncryptedEnvelope.
type Plaintext struct {
	Alts           []Alt `json:"alts"`
	PayloadVersion int64 `json:"payloadVersion"`
}

// Alt is one stored account inside the (encrypted) payload. Only ever seen in
// plaintext on a member's own machine; the server never sees these fields.
type Alt struct {
	UUID        string `json:"uuid"`
	Username    string `json:"username"`
	AccessToken string `json:"accessToken"`
	Type        string `json:"type"`
	LastUsed    int64  `json:"lastUsed"`
}

// --- Request / response envelopes -------------------------------------------

// CreateRepoRequest is the body of POST /v1/repos.
type CreateRepoRequest struct {
	Manifest        VaultManifest     `json:"manifest"`
	InitialEnvelope EncryptedEnvelope `json:"initialEnvelope"`
}

// PullRequest is the body of POST /v1/repos/{repoId}/pull.
type PullRequest struct {
	RepoID              string `json:"repoId"`
	KnownPayloadVersion int64  `json:"knownPayloadVersion"`
}

// PullResponse is returned by pull. Envelope is omitted (null) when the caller is
// already current, i.e. Unchanged is true.
type PullResponse struct {
	Manifest  VaultManifest      `json:"manifest"`
	Envelope  *EncryptedEnvelope `json:"envelope"`
	Unchanged bool               `json:"unchanged"`
}

// PushRequest is the body of POST /v1/repos/{repoId}/push. RotatedMembers, when
// present, atomically replaces the roster with the write.
type PushRequest struct {
	RepoID                 string            `json:"repoId"`
	Envelope               EncryptedEnvelope `json:"envelope"`
	ExpectedPayloadVersion int64             `json:"expectedPayloadVersion"`
	RotatedMembers         []MemberEntry     `json:"rotatedMembers,omitempty"`
}

// PushResponse is returned by push. On an optimistic-concurrency miss, Accepted is
// false, Conflict is true, and the counters report the server's current state.
type PushResponse struct {
	Accepted       bool  `json:"accepted"`
	Conflict       bool  `json:"conflict"`
	PayloadVersion int64 `json:"payloadVersion"`
	KeyEpoch       int64 `json:"keyEpoch"`
}

// MemberAddRequest is the body of POST /v1/repos/{repoId}/add-member.
type MemberAddRequest struct {
	RepoID string      `json:"repoId"`
	Member MemberEntry `json:"member"`
}

// MemberRemoveRequest is the body of POST /v1/repos/{repoId}/remove-member. The
// rotation is applied atomically: drop the removed id, install the re-wrapped
// roster and rotated envelope, and bump the key epoch.
type MemberRemoveRequest struct {
	RepoID           string            `json:"repoId"`
	RemovedMemberID  string            `json:"removedMemberId"`
	RotatedEnvelope  EncryptedEnvelope `json:"rotatedEnvelope"`
	RewrappedMembers []MemberEntry     `json:"rewrappedMembers"`
	NewKeyEpoch      int64             `json:"newKeyEpoch"`
}
