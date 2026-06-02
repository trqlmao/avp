/**
 * Micro reference client for the Alt Vault Protocol (AVP), HTTP/JSON profile.
 *
 * It drives the whole wire contract against a running server (the sibling `../server`, or any other
 * conformant HTTP/JSON server) so an implementer can see the full lifecycle end to end: generate an
 * Ed25519 keypair, run the challenge -> sign -> token auth flow, create a repo, pull, push a new
 * version, invite a second member, fetch that member's key, and print a transcript.
 *
 * It is intentionally tiny and NOT production code. Crucially, the envelope and wrapped-key crypto is
 * OUT OF SCOPE here: this client carries the alt payload as an opaque placeholder ciphertext and never
 * actually encrypts anything. A real client derives a per-repo data key, AES-256-GCM encrypts the alt
 * payload (binding repoId/payloadVersion/keyEpoch into the AAD), and wraps the data key to each member's
 * X25519 key. See SPEC sections 4-5 and the `lol.trq.alts` reference for that part. The only real crypto
 * here is the Ed25519 challenge signature, which IS part of the wire contract.
 *
 * Run: `npm install && npm start` (uses tsx; no runtime dependencies, only Node's built-in crypto).
 * Point it at a server with `AVP_SERVER_URL` (default http://localhost:8787).
 *
 * SPDX-License-Identifier: MIT
 */

import {
  generateKeyPairSync,
  randomBytes,
  sign as cryptoSign,
  type KeyObject,
} from "node:crypto";

// ─── Wire types (HTTP/JSON profile) — mirror schema/avp.schema.json ───────

/**
 * A repo data key wrapped to a single member's X25519 public key (SPEC section 5).
 *
 * In a real client this is the output of an X25519 ECDH + HKDF + AES-256-GCM wrap; the server stores and
 * serves it verbatim but can never read it. This example fills every field with a labelled placeholder.
 */
interface WrappedKey {
  /** Identifier of the wrapping scheme; must match the manifest's `schemeId`. */
  schemeId: string;
  /** Base64 ephemeral X25519 public key the sender used for the ECDH (the recipient's half of the wrap). */
  ephemeralPublicKey: string;
  /** Base64 AES-GCM nonce/IV used to wrap the data key. */
  iv: string;
  /** Base64 AES-GCM ciphertext of the wrapped repo data key (with its auth tag appended). */
  ciphertext: string;
}
/**
 * One member of a vault: their public identity keys plus the repo data key wrapped to them.
 *
 * Each member entry lets exactly one participant unwrap the shared repo data key. The `ed25519PublicKey`
 * doubles as the member id used to address this entry (SPEC section 2).
 */
interface MemberEntry {
  /** Base64 raw 32-byte Ed25519 public key; also the member id. */
  ed25519PublicKey: string;
  /** Base64 X25519 public key the data key is wrapped to. */
  x25519PublicKey: string;
  /** The repo data key wrapped to this member's X25519 key. */
  wrappedDataKey: WrappedKey;
  /** Key epoch this entry's wrapped key belongs to; bumped on every rekey. */
  keyEpoch: number;
  /** Optional base64 signature binding the member's X25519 key to their Ed25519 identity; null if absent. */
  keyBindingSig?: string | null;
}
/**
 * The encrypted alt payload as stored and transferred (SPEC section 4).
 *
 * The server treats `ciphertext` as opaque. A real client AES-256-GCM-encrypts the payload and binds
 * `(repoId, payloadVersion, keyEpoch)` into the AAD so the ciphertext cannot be replayed under a different
 * identity. This example uses a placeholder ciphertext and performs no encryption.
 */
interface EncryptedEnvelope {
  /** Repo this envelope belongs to. */
  repoId: string;
  /** Monotonically increasing payload version; drives optimistic concurrency on push/pull. */
  payloadVersion: number;
  /** Key epoch the payload was encrypted under. */
  keyEpoch: number;
  /** Base64 AES-GCM nonce/IV used to encrypt the payload. */
  iv: string;
  /** Base64 AES-GCM ciphertext of the alt payload (with its auth tag appended). */
  ciphertext: string;
}
/**
 * The metadata view of a repo: scheme, current epoch/version, and the full member set.
 *
 * The manifest carries no plaintext — only public keys and wrapped key material — so the server can serve
 * it without ever holding decryptable secrets.
 */
interface VaultManifest {
  /** Repo identifier. */
  repoId: string;
  /** Identifier of the crypto scheme all wrapped keys in this manifest use. */
  schemeId: string;
  /** Current key epoch for the repo. */
  keyEpoch: number;
  /** Current payload version for the repo. */
  payloadVersion: number;
  /** Every member with access to the repo, each carrying their own wrapped data key. */
  members: MemberEntry[];
}
/**
 * Response to a pull (SPEC section 6).
 *
 * When the caller's `knownPayloadVersion` already matches the server's, `unchanged` is true and `envelope`
 * is omitted (null) to save bandwidth; otherwise the current `envelope` is returned.
 */
interface PullResponse {
  /** The current manifest for the repo. */
  manifest: VaultManifest;
  /** The current encrypted envelope, or null when the caller is already up to date. */
  envelope: EncryptedEnvelope | null;
  /** True when the caller's known version matches the server's and no envelope was sent. */
  unchanged: boolean;
}
/**
 * Response to a push (SPEC section 6).
 *
 * A push uses optimistic concurrency: if `expectedPayloadVersion` is stale the server rejects it with
 * `accepted: false` and `conflict: true`, returning its own current version so the caller can re-pull.
 */
interface PushResponse {
  /** True when the new payload was stored. */
  accepted: boolean;
  /** True when the push was rejected because the expected version was stale. */
  conflict: boolean;
  /** The server's payload version after the call (the new version on accept, the current one on conflict). */
  payloadVersion: number;
  /** The server's current key epoch. */
  keyEpoch: number;
}
/** Response to the first leg of the auth flow: the server-issued nonce the client must sign. */
interface AuthChallenge {
  /** Base64-encoded random nonce; the client signs its RAW decoded bytes. */
  nonce: string;
}
/** Response to the second leg of the auth flow: a bearer token for the authenticated identity. */
interface AuthToken {
  /** Opaque bearer token to send as `Authorization: Bearer <token>`. */
  token: string;
  /** Unix epoch (ms or s, per server) at which the token expires. */
  expiresAt: number;
}

/** Identifier of the wrapping scheme this example advertises in manifests and wrapped keys. */
const SCHEME_ID = "X25519-HKDF-SHA256-AESGCM-v1";

// ─── Ed25519 keypair + identity (SPEC section 3) ──────────────────────────

/**
 * A member identity: an Ed25519 signing keypair plus a placeholder X25519 public key.
 *
 * The raw 32-byte Ed25519 public key, base64-encoded, is the member id (SPEC section 2). The X25519 key
 * would be a real Curve25519 public key in a production client; here it is an opaque placeholder, because
 * this example performs no key wrapping.
 */
interface Identity {
  /** Base64 raw 32-byte Ed25519 public key; this is the member id. */
  ed25519PublicKey: string;
  /** Base64 placeholder X25519 public key (no real key agreement happens in this example). */
  x25519PublicKey: string;
  /** The Ed25519 private key, used only to sign the auth challenge nonce. */
  privateKey: KeyObject;
}

/**
 * Generates a fresh Ed25519 identity, extracting the raw 32-byte public key from its SPKI DER.
 *
 * @param label - Human-readable name (e.g. "alice") woven into the placeholder X25519 key so the
 *   transcript stays readable; it has no cryptographic meaning.
 * @returns A new {@link Identity} with a real Ed25519 keypair and a placeholder X25519 public key.
 */
function generateIdentity(label: string): Identity {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  // An Ed25519 SPKI document is a 12-byte header followed by the raw 32-byte key.
  const raw = spki.subarray(spki.length - 32);
  return {
    ed25519PublicKey: raw.toString("base64"),
    // Placeholder, not a real X25519 key — clearly labelled so nobody mistakes it for key material.
    x25519PublicKey: Buffer.from(`x25519-placeholder-${label}`).toString("base64"),
    privateKey,
  };
}

// ─── HTTP helper ──────────────────────────────────────────────────────────

/** Base server URL from `AVP_SERVER_URL` (default localhost:8787), with any trailing slash trimmed. */
const BASE_URL = (process.env.AVP_SERVER_URL ?? "http://localhost:8787").replace(/\/$/, "");

/**
 * Sends a JSON request to the server and parses the JSON response, throwing on any non-2xx status so the
 * transcript fails loudly rather than silently mis-stepping.
 *
 * @typeParam T - Expected shape of the parsed response body.
 * @param method - HTTP method ("GET", "POST", ...).
 * @param path - Path appended to {@link BASE_URL} (must start with "/").
 * @param body - Optional value to JSON-encode as the request body; omit for bodyless requests like GET.
 * @param token - Optional bearer token; when present it is sent as `Authorization: Bearer <token>`.
 * @returns The parsed response body as `T`, or `{}` cast to `T` when the response has no body.
 * @throws Error if the response status is not 2xx; the message includes the method, path, status, and body.
 */
async function call<T>(method: string, path: string, body?: unknown, token?: string): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`${method} ${path} -> ${res.status}: ${text}`);
  }
  return (text ? JSON.parse(text) : {}) as T;
}

// ─── Auth flow: challenge -> sign nonce -> token (SPEC section 3) ──────────

/**
 * Runs the keypair challenge flow and returns a bearer token for this identity.
 *
 * The client signs the RAW nonce bytes (the bytes obtained by base64-decoding the `nonce`), not the
 * base64 text — this is the part conformant servers verify.
 *
 * @param identity - The member identity whose private key signs the challenge nonce.
 * @returns A bearer token to authorize subsequent calls for this identity.
 * @throws Error if either auth leg returns a non-2xx status (propagated from {@link call}).
 */
async function authenticate(identity: Identity): Promise<string> {
  const challenge = await call<AuthChallenge>("POST", "/api/auth/keypair/challenge", {
    ed25519PublicKey: identity.ed25519PublicKey,
  });
  const nonceBytes = Buffer.from(challenge.nonce, "base64");
  // Ed25519 signs the message directly (no pre-hash); pass `null` as the algorithm.
  const signature = cryptoSign(null, nonceBytes, identity.privateKey).toString("base64");
  const auth = await call<AuthToken>("POST", "/api/auth/keypair/token", {
    ed25519PublicKey: identity.ed25519PublicKey,
    nonce: challenge.nonce,
    signature,
  });
  return auth.token;
}

// ─── Placeholder envelope + wrapped key (NOT real crypto) ──────────────────

/**
 * Builds an opaque placeholder envelope. A real client AES-256-GCM-encrypts the alt payload and binds
 * `(repoId, payloadVersion, keyEpoch)` into the AAD (SPEC section 4). Here `ciphertext` is just a base64
 * blob so the server has something to store; the server never decrypts it, which is the whole point.
 *
 * @param repoId - Repo the envelope belongs to.
 * @param payloadVersion - Payload version this envelope represents.
 * @param keyEpoch - Key epoch the (notional) payload was encrypted under.
 * @returns An {@link EncryptedEnvelope} with a random IV and a labelled placeholder ciphertext.
 */
function placeholderEnvelope(repoId: string, payloadVersion: number, keyEpoch: number): EncryptedEnvelope {
  return {
    repoId,
    payloadVersion,
    keyEpoch,
    iv: randomBytes(12).toString("base64"),
    ciphertext: Buffer.from(`opaque-placeholder-payload-v${payloadVersion}`).toString("base64"),
  };
}

/**
 * Builds an opaque placeholder wrapped data key for a member. A real client runs X25519 ECDH against the
 * member's X25519 key, derives an AES key via HKDF, and AES-256-GCM-encrypts the repo data key. Here it
 * is a labelled placeholder; the server stores and serves it without ever being able to read it.
 *
 * @param memberLabel - Human-readable member name woven into the placeholder fields for transcript
 *   readability; it has no cryptographic meaning.
 * @returns A {@link WrappedKey} advertising {@link SCHEME_ID} with a random IV and labelled placeholders.
 */
function placeholderWrappedKey(memberLabel: string): WrappedKey {
  return {
    schemeId: SCHEME_ID,
    ephemeralPublicKey: Buffer.from(`ephemeral-x25519-for-${memberLabel}`).toString("base64"),
    iv: randomBytes(12).toString("base64"),
    ciphertext: Buffer.from(`wrapped-data-key-for-${memberLabel}`).toString("base64"),
  };
}

/**
 * Assembles a {@link MemberEntry} from an identity at a given key epoch.
 *
 * @param identity - The member whose public keys populate the entry.
 * @param label - Human-readable member name passed through to {@link placeholderWrappedKey}.
 * @param keyEpoch - Key epoch this entry's wrapped key belongs to.
 * @returns A member entry with a placeholder wrapped data key and no key-binding signature.
 */
function memberEntry(identity: Identity, label: string, keyEpoch: number): MemberEntry {
  return {
    ed25519PublicKey: identity.ed25519PublicKey,
    x25519PublicKey: identity.x25519PublicKey,
    wrappedDataKey: placeholderWrappedKey(label),
    keyEpoch,
    keyBindingSig: null,
  };
}

// ─── Transcript ─────────────────────────────────────────────────────────

/**
 * Prints one transcript line with a padded step label so the output columns line up.
 *
 * @param label - Short step name shown left-aligned in a fixed-width column.
 * @param detail - Free-form detail printed after the label.
 */
function step(label: string, detail: string): void {
  console.log(`  ${label.padEnd(16)} ${detail}`);
}

/**
 * Drives the full AVP lifecycle end to end against a running server and prints a transcript.
 *
 * The steps, in order: generate two local identities (alice, bob); authenticate alice; create a repo with
 * alice as sole member; pull at the known version (unchanged) and from version 0 (envelope returned); push
 * a new version; demonstrate the optimistic-concurrency conflict path with a stale expected version; add
 * bob as a member; fetch bob's stored key entry; then authenticate bob and have him pull the shared repo.
 *
 * @returns A promise that resolves once the full transcript has been printed.
 * @throws Error if any server call returns a non-2xx status (propagated from {@link call}); the top-level
 *   `main().catch(...)` handler turns this into a non-zero exit code.
 */
async function main(): Promise<void> {
  console.log(`AVP reference client -> ${BASE_URL}`);
  console.log("(Envelope/wrapped-key crypto is a placeholder; only the Ed25519 auth is real.)\n");

  // Two members, generated locally. alice creates the repo; bob joins later.
  const alice = generateIdentity("alice");
  const bob = generateIdentity("bob");
  step("members", `alice=${alice.ed25519PublicKey.slice(0, 12)}… bob=${bob.ed25519PublicKey.slice(0, 12)}…`);

  // 1. Authenticate alice (challenge -> sign nonce -> token).
  const aliceToken = await authenticate(alice);
  step("auth", `alice token=${aliceToken.slice(0, 12)}…`);

  // 2. createRepo — alice must be the sole member of the manifest she creates.
  // A real repoId is whatever the deploying client mints; we use a random UUID.
  const repoId = randomUuid();
  const initialEnvelope = placeholderEnvelope(repoId, 1, 0);
  const createdManifest = await call<VaultManifest>(
    "POST",
    "/v1/repos",
    {
      manifest: {
        repoId,
        schemeId: SCHEME_ID,
        keyEpoch: 0,
        payloadVersion: 1,
        members: [memberEntry(alice, "alice", 0)],
      } satisfies VaultManifest,
      initialEnvelope,
    },
    aliceToken,
  );
  step("createRepo", `repoId=${createdManifest.repoId} members=${createdManifest.members.length} v=${createdManifest.payloadVersion}`);

  // 3. pull at the version we already know — server reports unchanged and omits the envelope.
  const pullSame = await call<PullResponse>(
    "POST",
    `/v1/repos/${encodeURIComponent(repoId)}/pull`,
    { repoId, knownPayloadVersion: createdManifest.payloadVersion },
    aliceToken,
  );
  step("pull (known)", `unchanged=${pullSame.unchanged} envelope=${pullSame.envelope === null ? "null" : "present"}`);

  // 4. pull from version 0 — server returns the current envelope.
  const pullFresh = await call<PullResponse>(
    "POST",
    `/v1/repos/${encodeURIComponent(repoId)}/pull`,
    { repoId, knownPayloadVersion: 0 },
    aliceToken,
  );
  step("pull (stale)", `unchanged=${pullFresh.unchanged} envelope=${pullFresh.envelope === null ? "null" : "present"}`);

  // 5. push a new payload version with optimistic concurrency on the current version.
  const nextVersion = createdManifest.payloadVersion + 1;
  const pushResult = await call<PushResponse>(
    "POST",
    `/v1/repos/${encodeURIComponent(repoId)}/push`,
    {
      repoId,
      envelope: placeholderEnvelope(repoId, nextVersion, 0),
      expectedPayloadVersion: createdManifest.payloadVersion,
    },
    aliceToken,
  );
  step("push", `accepted=${pushResult.accepted} conflict=${pushResult.conflict} v=${pushResult.payloadVersion}`);

  // 6. demonstrate the conflict path: pushing again at the now-stale expected version is rejected.
  const conflict = await call<PushResponse>(
    "POST",
    `/v1/repos/${encodeURIComponent(repoId)}/push`,
    {
      repoId,
      envelope: placeholderEnvelope(repoId, nextVersion + 1, 0),
      expectedPayloadVersion: createdManifest.payloadVersion, // stale on purpose
    },
    aliceToken,
  );
  step("push (stale)", `accepted=${conflict.accepted} conflict=${conflict.conflict} serverV=${conflict.payloadVersion}`);

  // 7. addMember — alice (any member may invite, v1 policy) records bob's entry. In a real client bob
  // would publish his public keys via the join handshake (SPEC section 8.1) and alice would wrap the
  // data key to bob's X25519 key; here the wrapped key is a placeholder.
  const withBob = await call<VaultManifest>(
    "POST",
    `/v1/repos/${encodeURIComponent(repoId)}/add-member`,
    { repoId, member: memberEntry(bob, "bob", 0) },
    aliceToken,
  );
  step("addMember", `members=${withBob.members.length} (added bob)`);

  // 8. fetchMemberKey — look up bob's stored entry by member id. The id is base64, which can contain
  // + / =, so it MUST be URL-encoded in the path.
  const bobEntry = await call<MemberEntry>(
    "GET",
    `/v1/repos/${encodeURIComponent(repoId)}/member/${encodeURIComponent(bob.ed25519PublicKey)}`,
    undefined,
    aliceToken,
  );
  step("fetchMemberKey", `bob x25519=${bobEntry.x25519PublicKey.slice(0, 12)}… epoch=${bobEntry.keyEpoch}`);

  // 9. bob authenticates with his own keypair and pulls the shared repo.
  const bobToken = await authenticate(bob);
  const bobPull = await call<PullResponse>(
    "POST",
    `/v1/repos/${encodeURIComponent(repoId)}/pull`,
    { repoId, knownPayloadVersion: 0 },
    bobToken,
  );
  step("bob pull", `members=${bobPull.manifest.members.length} v=${bobPull.manifest.payloadVersion} envelope=${bobPull.envelope === null ? "null" : "present"}`);

  console.log("\nDone. Full lifecycle exercised against a zero-knowledge server.");
}

/**
 * Returns a random UUID for use as an opaque repoId.
 *
 * Prefers the global `crypto.randomUUID` (Node 19+); on older runtimes it falls back to formatting random
 * bytes into a RFC 4122 version-4 UUID by hand (setting the version and variant bits).
 *
 * @returns A random version-4 UUID string.
 */
function randomUuid(): string {
  // crypto.randomUUID is available on the global crypto in Node 19+; fall back to bytes if not.
  const g = globalThis.crypto;
  if (g && typeof g.randomUUID === "function") {
    return g.randomUUID();
  }
  const b = randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = b.toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

main().catch((err) => {
  console.error("\nClient failed:", err instanceof Error ? err.message : err);
  console.error("Is a server running? Start one with `npm start` in ../server, or set AVP_SERVER_URL.");
  process.exitCode = 1;
});
