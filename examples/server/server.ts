/**
 * Micro reference server for the Alt Vault Protocol (AVP), HTTP/JSON profile.
 *
 * It implements the whole wire contract against an in-memory store so an implementer can point a client
 * at something real. It is intentionally tiny and NOT production code: state lives in memory and is lost
 * on restart, there is no TLS, and the bearer token is an opaque random string mapped to a member id in
 * this same process (a real deployment mints a JWT verifiable via JWKS, as the spec describes). What it
 * does honour is the part that matters: it is zero-knowledge. It stores only the manifest, the encrypted
 * envelope, the per-member wrapped keys, public keys, and counters that clients send, and decrypts
 * nothing.
 *
 * Run: `npm install && npm start` (uses tsx; no runtime dependencies, only Node's built-in crypto/http).
 *
 * SPDX-License-Identifier: MIT
 */

import { createServer, IncomingMessage, ServerResponse } from "node:http";
import { createPublicKey, randomBytes, verify as cryptoVerify } from "node:crypto";

// ─── Wire types (HTTP/JSON profile; see ../../schema/avp.schema.json) ───

interface WrappedKey {
  schemeId: string;
  ephemeralPublicKey: string;
  iv: string;
  ciphertext: string;
}
interface MemberEntry {
  ed25519PublicKey: string;
  x25519PublicKey: string;
  wrappedDataKey: WrappedKey;
  keyEpoch: number;
  keyBindingSig?: string | null;
}
interface EncryptedEnvelope {
  repoId: string;
  payloadVersion: number;
  keyEpoch: number;
  iv: string;
  ciphertext: string;
}
interface VaultManifest {
  repoId: string;
  schemeId: string;
  keyEpoch: number;
  payloadVersion: number;
  members: MemberEntry[];
}

// ─── In-memory state ────────────────────────────────────────────────────

const repos = new Map<string, { manifest: VaultManifest; envelope: EncryptedEnvelope }>();
const nonces = new Map<string, { publicKey: string; expiresAt: number }>();
const tokens = new Map<string, string>(); // opaque bearer token -> member id (Ed25519 public key)

const NONCE_TTL_MS = 2 * 60 * 1000;
const TOKEN_TTL_MS = 60 * 60 * 1000;

// ─── Crypto: verify an Ed25519 signature over raw bytes (SPEC section 3) ──

/** Wraps a raw 32-byte Ed25519 public key (base64) into an SPKI key object. */
function ed25519PublicKeyObject(rawBase64: string) {
  const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(rawBase64, "base64")]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

/** Verifies an Ed25519 signature (base64) over the given message bytes. */
function verifyEd25519(publicKeyBase64: string, message: Buffer, signatureBase64: string): boolean {
  try {
    return cryptoVerify(null, message, ed25519PublicKeyObject(publicKeyBase64), Buffer.from(signatureBase64, "base64"));
  } catch {
    return false;
  }
}

// ─── Tiny HTTP helpers ────────────────────────────────────────────────────

function send(res: ServerResponse, status: number, body: unknown): void {
  const json = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(json);
}

async function readJson(req: IncomingMessage): Promise<any> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(chunk as Buffer);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : {};
}

/** Returns the caller's member id from the Bearer token, or null if unauthenticated. */
function callerId(req: IncomingMessage): string | null {
  const header = req.headers["authorization"];
  if (!header || !header.startsWith("Bearer ")) {
    return null;
  }
  return tokens.get(header.slice("Bearer ".length)) ?? null;
}

function isMember(manifest: VaultManifest, memberId: string): boolean {
  return manifest.members.some((m) => m.ed25519PublicKey === memberId);
}

// ─── Request handling ─────────────────────────────────────────────────────

const server = createServer(async (req, res) => {
  try {
    await route(req, res);
  } catch (err) {
    send(res, 400, { error: "bad request", detail: String(err) });
  }
});

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
  const repoId = match?.[1] ?? memberMatch?.[1];
  const stored = repoId ? repos.get(repoId) : undefined;
  if (!stored) {
    return send(res, 404, { error: "repo not found" });
  }
  if (!isMember(stored.manifest, caller)) {
    return send(res, 403, { error: "caller is not a member" });
  }

  if (method === "POST" && match?.[2] === "pull") {
    const body = await readJson(req);
    if (body.knownPayloadVersion === stored.manifest.payloadVersion) {
      return send(res, 200, { manifest: stored.manifest, envelope: null, unchanged: true });
    }
    return send(res, 200, { manifest: stored.manifest, envelope: stored.envelope, unchanged: false });
  }

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

  if (method === "POST" && match?.[2] === "add-member") {
    const body = await readJson(req);
    const member: MemberEntry = body.member;
    if (!isMember(stored.manifest, member.ed25519PublicKey)) {
      stored.manifest.members.push(member);
    }
    return send(res, 200, stored.manifest);
  }

  if (method === "POST" && match?.[2] === "remove-member") {
    const body = await readJson(req);
    stored.manifest.members = body.rewrappedMembers;
    stored.envelope = body.rotatedEnvelope;
    stored.manifest.keyEpoch = body.newKeyEpoch;
    stored.manifest.payloadVersion = body.rotatedEnvelope.payloadVersion;
    return send(res, 200, stored.manifest);
  }

  if (method === "GET" && memberMatch) {
    const entry = stored.manifest.members.find((m) => m.ed25519PublicKey === memberMatch[2]);
    return entry ? send(res, 200, entry) : send(res, 404, { error: "member not found" });
  }

  return send(res, 404, { error: "no such route" });
}

const port = Number(process.env.PORT ?? 8787);
server.listen(port, () => console.log(`AVP reference server (in-memory) listening on http://localhost:${port}`));
