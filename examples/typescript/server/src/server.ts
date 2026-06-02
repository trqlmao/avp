/**
 * Micro reference server for the Alt Vault Protocol (AVP), HTTP/JSON profile.
 *
 * It implements the whole wire contract against an in-memory store so an implementer can point a client
 * at something real. It is intentionally tiny and NOT production code: state lives in memory and is lost
 * on restart, there is no TLS, and the bearer token is an opaque random string mapped to a member id in
 * this same process (a real deployment mints a JWT verifiable via JWKS, as the spec describes). What it
 * does honour is the part that matters: it is zero-knowledge. It stores only the manifest, the encrypted
 * envelope, the per-member wrapped keys, public keys, and counters that clients send, and decrypts
 * nothing. Field shapes follow schema/avp.schema.json.
 *
 * Run: `npm install && npm start` (uses tsx; no runtime dependencies, only Node's built-in crypto/http).
 *
 * SPDX-License-Identifier: MIT
 */

import { createServer, IncomingMessage, ServerResponse } from "node:http";
import { createPublicKey, randomBytes, verify as cryptoVerify } from "node:crypto";
import { pathToFileURL } from "node:url";

// ─── Wire types (HTTP/JSON profile) ──────────────────────────────────────

/**
 * A data key that has been wrapped (encrypted) for exactly one member, using
 * the key-agreement scheme named by {@link schemeId}. The server stores this
 * blob verbatim and never unwraps it; only the holder of the matching private
 * key can recover the data key.
 */
interface WrappedKey {
  /** Identifier of the wrapping scheme (e.g. `X25519-HKDF-SHA256-AESGCM-v1`). */
  schemeId: string;
  /** Base64 ephemeral public key produced during key agreement, for the recipient. */
  ephemeralPublicKey: string;
  /** Base64 initialization vector / nonce used to wrap the data key. */
  iv: string;
  /** Base64 ciphertext of the wrapped data key. */
  ciphertext: string;
}

/**
 * One member's slot in a {@link VaultManifest}: the member's public keys plus
 * the data key wrapped for that member at the current epoch.
 */
interface MemberEntry {
  /** Base64 raw 32-byte Ed25519 public key; doubles as the member's identity. */
  ed25519PublicKey: string;
  /** Base64 X25519 public key the member uses for key agreement. */
  x25519PublicKey: string;
  /** The data key wrapped for this member; see {@link WrappedKey}. */
  wrappedDataKey: WrappedKey;
  /** Key epoch the {@link wrappedDataKey} belongs to; bumps on rotation. */
  keyEpoch: number;
  /** Optional base64 signature binding the member's X25519 key to their Ed25519 identity. */
  keyBindingSig?: string | null;
}

/**
 * The repo's encrypted payload. The server treats {@link ciphertext} as opaque
 * bytes and stores it alongside the version/epoch counters needed for
 * optimistic concurrency and key rotation.
 */
interface EncryptedEnvelope {
  /** Identifier of the repo this envelope belongs to. */
  repoId: string;
  /** Monotonic payload version; bumped on every successful push. */
  payloadVersion: number;
  /** Key epoch the payload was encrypted under. */
  keyEpoch: number;
  /** Base64 initialization vector / nonce for the payload ciphertext. */
  iv: string;
  /** Base64 ciphertext of the encrypted payload. */
  ciphertext: string;
}

/**
 * The public, non-secret description of a repo: its scheme and counters plus
 * the per-member key material. Clients pull this to learn who the members are
 * and which wrapped key to unwrap.
 */
interface VaultManifest {
  /** Stable repo identifier. */
  repoId: string;
  /** Identifier of the key-agreement scheme all members use. */
  schemeId: string;
  /** Current key epoch; advances when a member is removed and keys rotate. */
  keyEpoch: number;
  /** Current payload version; matches the stored {@link EncryptedEnvelope}. */
  payloadVersion: number;
  /** Every current member of the repo. */
  members: MemberEntry[];
}

// ─── In-memory state ──────────────────────────────────────────────────────
//
// All state is held in process memory and lost on restart. A real deployment
// would back these with a database and an identity provider.

/** Stored repos, keyed by `repoId`: the manifest plus its current envelope. */
const repos = new Map<string, { manifest: VaultManifest; envelope: EncryptedEnvelope }>();
/** Outstanding auth challenges, keyed by nonce: the claimed public key and expiry. */
const nonces = new Map<string, { publicKey: string; expiresAt: number }>();
/** Issued bearer tokens mapped to the member id (Ed25519 public key) they authenticate. */
const tokens = new Map<string, string>();

/** How long an unredeemed auth challenge nonce stays valid, in milliseconds. */
const NONCE_TTL_MS = 2 * 60 * 1000;
/** Advertised bearer token lifetime, in milliseconds (reported to clients; not enforced here). */
const TOKEN_TTL_MS = 60 * 60 * 1000;

// ─── Crypto: verify an Ed25519 signature over raw bytes (SPEC section 3) ──

/**
 * Wraps a raw 32-byte Ed25519 public key into a {@link KeyObject} Node's crypto
 * API can use. Node only accepts SPKI-encoded keys, so the raw key bytes are
 * prefixed with the fixed Ed25519 SPKI DER header before parsing.
 *
 * @param rawBase64 - The base64-encoded raw 32-byte Ed25519 public key.
 * @returns A public {@link KeyObject} suitable for signature verification.
 */
function ed25519PublicKeyObject(rawBase64: string) {
  const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(rawBase64, "base64")]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

/**
 * Verifies an Ed25519 signature over the given message bytes. Any error
 * (malformed key, malformed signature) is treated as a verification failure
 * rather than thrown, so callers get a plain boolean.
 *
 * @param publicKeyBase64 - The signer's base64-encoded raw Ed25519 public key.
 * @param message - The exact message bytes that were signed.
 * @param signatureBase64 - The base64-encoded signature to check.
 * @returns `true` if the signature is valid for the key and message, else `false`.
 */
function verifyEd25519(publicKeyBase64: string, message: Buffer, signatureBase64: string): boolean {
  try {
    return cryptoVerify(null, message, ed25519PublicKeyObject(publicKeyBase64), Buffer.from(signatureBase64, "base64"));
  } catch {
    return false;
  }
}

// ─── Tiny HTTP helpers ────────────────────────────────────────────────────

/**
 * Writes a JSON response with the given HTTP status. Always sets the
 * `application/json` content type and ends the response.
 *
 * @param res - The HTTP response to write to.
 * @param status - The HTTP status code to send.
 * @param body - The value to JSON-serialize as the response body.
 */
function send(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

/**
 * Reads the full request body and parses it as JSON.
 *
 * @param req - The incoming HTTP request to drain.
 * @returns The parsed JSON value, or an empty object if the body is empty.
 * @throws SyntaxError if the body is present but not valid JSON.
 */
async function readJson(req: IncomingMessage): Promise<any> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(chunk as Buffer);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : {};
}

/**
 * Resolves the caller's member id from the request's `Authorization: Bearer`
 * header by looking the token up in the in-memory {@link tokens} map.
 *
 * @param req - The incoming HTTP request.
 * @returns The member id (Ed25519 public key) if the token is known, else `null`.
 */
function callerId(req: IncomingMessage): string | null {
  const header = req.headers["authorization"];
  if (!header || !header.startsWith("Bearer ")) {
    return null;
  }
  return tokens.get(header.slice("Bearer ".length)) ?? null;
}

/**
 * Reports whether a member id is currently part of a repo.
 *
 * @param manifest - The repo manifest to check against.
 * @param memberId - The member id (Ed25519 public key) to look for.
 * @returns `true` if the id matches a current member, else `false`.
 */
function isMember(manifest: VaultManifest, memberId: string): boolean {
  return manifest.members.some((m) => m.ed25519PublicKey === memberId);
}

// ─── Request handling ─────────────────────────────────────────────────────

/**
 * The HTTP server instance. Exported so tests can drive it on an ephemeral
 * port; it only begins listening when this file is run directly (see the
 * bottom of the module). Each request is handed to {@link route}, and any
 * uncaught error is reported as a `400 bad request`.
 */
export const server = createServer(async (req, res) => {
  try {
    await route(req, res);
  } catch (err) {
    send(res, 400, { error: "bad request", detail: String(err) });
  }
});

/**
 * Dispatches a single request to the matching AVP operation and writes the
 * response. Handles the two auth endpoints unauthenticated; every other route
 * requires a valid bearer token, and the repo-scoped routes additionally
 * require the caller to be a member of the target repo. Parse errors and other
 * exceptions bubble up to the {@link server} wrapper, which answers `400`.
 *
 * @param req - The incoming HTTP request.
 * @param res - The HTTP response to write the result to.
 * @returns A promise that resolves once a response has been sent.
 */
async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? "/", "http://localhost");
  const path = url.pathname;
  const method = req.method ?? "GET";

  // ── Auth: challenge -> token ──
  if (method === "POST" && path === "/api/auth/keypair/challenge") {
    const body = await readJson(req);
    const nonce = randomBytes(32).toString("base64");
    nonces.set(nonce, { publicKey: body.ed25519PublicKey, expiresAt: Date.now() + NONCE_TTL_MS });
    return send(res, 200, { nonce });
  }

  if (method === "POST" && path === "/api/auth/keypair/token") {
    const body = await readJson(req);
    const challenge = nonces.get(body.nonce);
    nonces.delete(body.nonce); // single-use
    if (!challenge || challenge.publicKey !== body.ed25519PublicKey || challenge.expiresAt < Date.now()) {
      return send(res, 401, { error: "invalid or expired nonce" });
    }
    if (!verifyEd25519(body.ed25519PublicKey, Buffer.from(body.nonce, "base64"), body.signature)) {
      return send(res, 401, { error: "bad signature" });
    }
    const token = randomBytes(32).toString("base64url");
    tokens.set(token, body.ed25519PublicKey);
    return send(res, 200, { token, expiresAt: Date.now() + TOKEN_TTL_MS });
  }

  // ── Everything below requires a bearer token ──
  const caller = callerId(req);
  if (caller === null) {
    return send(res, 401, { error: "missing or unknown bearer token" });
  }

  // createRepo
  if (method === "POST" && path === "/v1/repos") {
    const body = await readJson(req);
    const manifest: VaultManifest = body.manifest;
    if (manifest.members.length !== 1 || manifest.members[0].ed25519PublicKey !== caller) {
      return send(res, 403, { error: "creator must be the sole member" });
    }
    if (repos.has(manifest.repoId)) {
      return send(res, 409, { error: "repo already exists" });
    }
    repos.set(manifest.repoId, { manifest, envelope: body.initialEnvelope });
    return send(res, 200, manifest);
  }

  // routes under /v1/repos/:repoId/...
  const match = path.match(/^\/v1\/repos\/([^/]+)\/(pull|push|add-member|remove-member)$/);
  const memberMatch = path.match(/^\/v1\/repos\/([^/]+)\/member\/([^/]+)$/);
  const repoIdRaw = match?.[1] ?? memberMatch?.[1];
  const repoId = repoIdRaw ? decodeURIComponent(repoIdRaw) : undefined;
  const stored = repoId ? repos.get(repoId) : undefined;
  if (!stored) {
    return send(res, 404, { error: "repo not found" });
  }
  if (!isMember(stored.manifest, caller)) {
    return send(res, 403, { error: "caller is not a member" });
  }

  // pull: if the caller is already at the current version, send the manifest
  // but omit the envelope (nothing to transfer); otherwise send both.
  if (method === "POST" && match?.[2] === "pull") {
    const body = await readJson(req);
    if (body.knownPayloadVersion === stored.manifest.payloadVersion) {
      return send(res, 200, { manifest: stored.manifest, envelope: null, unchanged: true });
    }
    return send(res, 200, { manifest: stored.manifest, envelope: stored.envelope, unchanged: false });
  }

  // push: optimistic concurrency. The write is rejected as a conflict unless
  // the caller's expected base version still matches the stored version.
  if (method === "POST" && match?.[2] === "push") {
    const body = await readJson(req);
    if (body.expectedPayloadVersion !== stored.manifest.payloadVersion) {
      return send(res, 200, {
        accepted: false,
        conflict: true,
        payloadVersion: stored.manifest.payloadVersion,
        keyEpoch: stored.manifest.keyEpoch,
      });
    }
    stored.envelope = body.envelope;
    stored.manifest.payloadVersion = body.envelope.payloadVersion;
    stored.manifest.keyEpoch = body.envelope.keyEpoch;
    // A push may also carry re-wrapped member keys after a key rotation.
    if (Array.isArray(body.rotatedMembers)) {
      stored.manifest.members = body.rotatedMembers;
    }
    return send(res, 200, {
      accepted: true,
      conflict: false,
      payloadVersion: stored.manifest.payloadVersion,
      keyEpoch: stored.manifest.keyEpoch,
    });
  }

  // add-member: idempotent — re-adding an existing member is a no-op.
  if (method === "POST" && match?.[2] === "add-member") {
    const body = await readJson(req);
    const member: MemberEntry = body.member;
    if (!isMember(stored.manifest, member.ed25519PublicKey)) {
      stored.manifest.members.push(member);
    }
    return send(res, 200, stored.manifest);
  }

  // remove-member: atomically replace the member set, envelope, and counters
  // with the rotated material the client computed for the new key epoch.
  if (method === "POST" && match?.[2] === "remove-member") {
    const body = await readJson(req);
    stored.manifest.members = body.rewrappedMembers;
    stored.envelope = body.rotatedEnvelope;
    stored.manifest.keyEpoch = body.newKeyEpoch;
    stored.manifest.payloadVersion = body.rotatedEnvelope.payloadVersion;
    return send(res, 200, stored.manifest);
  }

  if (method === "GET" && memberMatch) {
    const memberId = decodeURIComponent(memberMatch[2]);
    const entry = stored.manifest.members.find((m) => m.ed25519PublicKey === memberId);
    return entry ? send(res, 200, entry) : send(res, 404, { error: "member not found" });
  }

  return send(res, 404, { error: "no such route" });
}

/**
 * Clears every repo, outstanding challenge nonce, and issued token. Exposed so
 * the test suite can start each case from a clean slate.
 */
export function resetState(): void {
  repos.clear();
  nonces.clear();
  tokens.clear();
}

// Only start listening when this file is executed directly (e.g. `npm start`),
// not when it is imported by the test suite. The check compares this module's
// URL against the file URL of the script Node was launched with.
const isMain = process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const port = Number(process.env.PORT ?? 8787);
  server.listen(port, () => console.log(`AVP reference server (in-memory) listening on http://localhost:${port}`));
}
