/**
 * gRPC reference server for the Alt Vault Protocol.
 *
 * It implements the canonical `Vault` service (../../proto/avp.proto) plus the example `Auth` service
 * (../avp-auth.proto) against in-memory state. Like the HTTP reference it is intentionally tiny and NOT
 * production: state is lost on restart, there is no TLS, and the bearer token is an opaque random string
 * mapped to a member id in this process (a real deployment mints a JWT verifiable via JWKS). What it
 * honours is the part that matters: it is zero-knowledge. It stores only the manifest, the encrypted
 * envelope, the per-member wrapped keys, public keys, and counters that clients send, and decrypts
 * nothing. The only cryptography it performs is verifying the Ed25519 challenge signature.
 *
 * Run: `npm install && npm run server` (uses tsx). Set PORT to override 50051.
 *
 * SPDX-License-Identifier: MIT
 */

import { createPublicKey, randomBytes, verify as cryptoVerify } from "node:crypto";
import type { ServerUnaryCall, sendUnaryData } from "@grpc/grpc-js";

import { avp, grpc } from "../proto.ts";

// ─── In-memory state (lost on restart) ──────────────────────────────────────────

const repos = new Map<string, { manifest: any; envelope: any }>();
const nonces = new Map<string, { publicKey: string; expiresAt: number }>();
const tokens = new Map<string, string>();

const NONCE_TTL_MS = 2 * 60 * 1000;
const TOKEN_TTL_MS = 60 * 60 * 1000;

// ─── Ed25519 verify over raw bytes (SPEC section 3) ──────────────────────────────

function verifyEd25519(publicKeyBase64: string, message: Buffer, signatureBase64: string): boolean {
  try {
    const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(publicKeyBase64, "base64")]);
    const key = createPublicKey({ key: der, format: "der", type: "spki" });
    return cryptoVerify(null, message, key, Buffer.from(signatureBase64, "base64"));
  } catch {
    return false;
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────────

type Call = ServerUnaryCall<any, any>;
type Cb = sendUnaryData<any>;

function fail(cb: Cb, code: number, message: string): void {
  cb({ code, details: message } as any, null);
}

/** Resolve the caller's member id from the `authorization` metadata, or null. */
function callerId(call: Call): string | null {
  const header = call.metadata.get("authorization")[0];
  if (typeof header !== "string" || !header.startsWith("Bearer ")) {
    return null;
  }
  return tokens.get(header.slice("Bearer ".length)) ?? null;
}

const isMember = (manifest: any, id: string) => manifest.members.some((m: any) => m.ed25519PublicKey === id);

/** Wrap a member-scoped Vault handler: authenticate, find the repo, and check membership. */
function withMember(handler: (call: Call, cb: Cb, stored: { manifest: any; envelope: any }, caller: string) => void) {
  return (call: Call, cb: Cb): void => {
    const caller = callerId(call);
    if (caller === null) {
      return fail(cb, grpc.status.UNAUTHENTICATED, "missing or unknown bearer token");
    }
    const stored = repos.get(call.request.repoId);
    if (!stored) {
      return fail(cb, grpc.status.NOT_FOUND, "repo not found");
    }
    if (!isMember(stored.manifest, caller)) {
      return fail(cb, grpc.status.PERMISSION_DENIED, "caller is not a member");
    }
    handler(call, cb, stored, caller);
  };
}

// ─── Auth service ────────────────────────────────────────────────────────────────

const auth = {
  Challenge(call: Call, cb: Cb): void {
    const nonce = randomBytes(32).toString("base64");
    nonces.set(nonce, { publicKey: call.request.ed25519PublicKey, expiresAt: Date.now() + NONCE_TTL_MS });
    cb(null, { nonce });
  },

  Token(call: Call, cb: Cb): void {
    const { ed25519PublicKey, nonce, signature } = call.request;
    const challenge = nonces.get(nonce);
    nonces.delete(nonce); // single-use
    if (!challenge || challenge.publicKey !== ed25519PublicKey || challenge.expiresAt < Date.now()) {
      return fail(cb, grpc.status.UNAUTHENTICATED, "invalid or expired nonce");
    }
    if (!verifyEd25519(ed25519PublicKey, Buffer.from(nonce, "base64"), signature)) {
      return fail(cb, grpc.status.UNAUTHENTICATED, "bad signature");
    }
    const token = randomBytes(32).toString("base64url");
    tokens.set(token, ed25519PublicKey);
    cb(null, { token, expiresAt: Date.now() + TOKEN_TTL_MS });
  },
};

// ─── Vault service ─────────────────────────────────────────────────────────────────

const vault = {
  CreateRepo(call: Call, cb: Cb): void {
    const caller = callerId(call);
    if (caller === null) {
      return fail(cb, grpc.status.UNAUTHENTICATED, "missing or unknown bearer token");
    }
    const manifest = call.request.manifest;
    if (manifest.members.length !== 1 || manifest.members[0].ed25519PublicKey !== caller) {
      return fail(cb, grpc.status.PERMISSION_DENIED, "creator must be the sole member");
    }
    if (repos.has(manifest.repoId)) {
      return fail(cb, grpc.status.ALREADY_EXISTS, "repo already exists");
    }
    repos.set(manifest.repoId, { manifest, envelope: call.request.initialEnvelope });
    cb(null, manifest);
  },

  Pull: withMember((call, cb, stored) => {
    if (call.request.knownPayloadVersion === stored.manifest.payloadVersion) {
      return cb(null, { manifest: stored.manifest, unchanged: true });
    }
    cb(null, { manifest: stored.manifest, envelope: stored.envelope, unchanged: false });
  }),

  Push: withMember((call, cb, stored) => {
    if (call.request.expectedPayloadVersion !== stored.manifest.payloadVersion) {
      return cb(null, {
        accepted: false,
        conflict: true,
        payloadVersion: stored.manifest.payloadVersion,
        keyEpoch: stored.manifest.keyEpoch,
      });
    }
    stored.envelope = call.request.envelope;
    stored.manifest.payloadVersion = call.request.envelope.payloadVersion;
    stored.manifest.keyEpoch = call.request.envelope.keyEpoch;
    if (Array.isArray(call.request.rotatedMembers) && call.request.rotatedMembers.length > 0) {
      stored.manifest.members = call.request.rotatedMembers;
    }
    cb(null, { accepted: true, conflict: false, payloadVersion: stored.manifest.payloadVersion, keyEpoch: stored.manifest.keyEpoch });
  }),

  AddMember: withMember((call, cb, stored) => {
    const member = call.request.member;
    if (!isMember(stored.manifest, member.ed25519PublicKey)) {
      stored.manifest.members.push(member);
    }
    cb(null, stored.manifest);
  }),

  RemoveMember: withMember((call, cb, stored) => {
    stored.manifest.members = call.request.rewrappedMembers;
    stored.envelope = call.request.rotatedEnvelope;
    stored.manifest.keyEpoch = call.request.newKeyEpoch;
    stored.manifest.payloadVersion = call.request.rotatedEnvelope.payloadVersion;
    cb(null, stored.manifest);
  }),

  FetchMemberKey: withMember((call, cb, stored) => {
    const entry = stored.manifest.members.find((m: any) => m.ed25519PublicKey === call.request.memberId);
    if (!entry) {
      return fail(cb, grpc.status.NOT_FOUND, "member not found");
    }
    cb(null, entry);
  }),
};

// ─── Start ───────────────────────────────────────────────────────────────────────

const port = Number(process.env.PORT ?? 50051);
const server = new grpc.Server();
server.addService(avp.Vault.service, vault);
server.addService(avp.Auth.service, auth);
server.bindAsync(`0.0.0.0:${port}`, grpc.ServerCredentials.createInsecure(), (err, bound) => {
  if (err) {
    console.error("bind failed:", err.message);
    process.exitCode = 1;
    return;
  }
  console.log(`AVP reference gRPC server (in-memory) listening on 0.0.0.0:${bound}`);
});
