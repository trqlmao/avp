/**
 * Micro reference client for the Alt Vault Protocol (AVP), HTTP/JSON profile.
 *
 * It drives the whole wire contract against a running server (the sibling `../server`, or any other
 * conformant HTTP/JSON server) so an implementer can see the full lifecycle end to end: generate an
 * Ed25519 + X25519 keypair, run the challenge -> sign -> token auth flow, create a repo, pull, push a
 * new version, invite a second member, fetch that member's key, and finally have the second member pull,
 * unwrap the data key, and decrypt the payload.
 *
 * The envelope and wrapped-key cryptography here is REAL (SPEC sections 4-5): alice derives a per-repo
 * data key, AES-256-GCM-encrypts the alt payload binding (repoId, payloadVersion, keyEpoch) into the
 * AAD, and wraps the data key to each member's X25519 key with X25519 + HKDF-SHA256. The server stays
 * zero-knowledge throughout; at the end bob recovers exactly what alice stored. The crypto lives in
 * the sibling `crypto.ts` and is tested against `vectors/*.json` by `crypto.test.ts`.
 *
 * Run: `bun install && bun run start` (uses tsx; no runtime dependencies, only Node's built-in crypto).
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

import {
  buildAad,
  decryptPayload,
  encryptPayload,
  generateX25519,
  unwrapDataKey,
  wrapDataKey,
  type EncryptedEnvelopeFields,
  type WrappedKeyFields,
} from "./crypto.ts";

// ─── Wire types (HTTP/JSON profile) — mirror schema/avp.schema.json ───────

/**
 * A repo data key wrapped to a single member's X25519 public key (SPEC section 5).
 *
 * The server stores and serves it verbatim but can never read it.
 */
interface WrappedKey {
  /** Identifier of the wrapping scheme; must match the manifest's `schemeId`. */
  schemeId: string;
  /** Base64 ephemeral X25519 public key the sender used for the ECDH. */
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
 * The server treats `ciphertext` as opaque. This client AES-256-GCM-encrypts the payload and binds
 * `(repoId, payloadVersion, keyEpoch)` into the AAD so the ciphertext cannot be replayed under a
 * different identity.
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

/** The plaintext payload structure carried inside an encrypted envelope. */
interface Plaintext {
  alts: Alt[];
  payloadVersion: number;
}

/** One stored account inside the (encrypted) payload. */
interface Alt {
  uuid: string;
  username: string;
  accessToken: string;
  type: string;
  lastUsed: number;
}

/** Identifier of the wrapping scheme this example uses. */
const SCHEME_ID = "X25519-HKDF-SHA256-AESGCM-v1";

// ─── Ed25519 + X25519 keypair + identity (SPEC sections 2, 3) ─────────────────

/**
 * A member identity: an Ed25519 signing keypair and a real X25519 wrapping keypair.
 *
 * The raw 32-byte Ed25519 public key, base64-encoded, is the member id (SPEC section 2).
 */
interface Identity {
  /** Base64 raw 32-byte Ed25519 public key; this is the member id. */
  ed25519PublicKey: string;
  /** Base64 raw 32-byte X25519 public key (used to wrap the repo data key to this member). */
  x25519PublicKey: string;
  /** The Ed25519 private key, used only to sign the auth challenge nonce. */
  edPrivateKey: KeyObject;
  /** The X25519 private key, used to unwrap the repo data key. */
  xPrivateKey: KeyObject;
}

/**
 * Generates a fresh identity: an Ed25519 signing keypair plus a real X25519 wrapping keypair.
 *
 * @returns A new {@link Identity} with real keypairs.
 */
function generateIdentity(): Identity {
  // Ed25519 for auth / member id.
  const { publicKey: edPub, privateKey: edPriv } = generateKeyPairSync("ed25519");
  const spki = edPub.export({ format: "der", type: "spki" }) as Buffer;
  // An Ed25519 SPKI document is a 12-byte header followed by the raw 32-byte key.
  const edPubRaw = spki.subarray(spki.length - 32);

  // X25519 for data-key wrapping.
  const { privateKey: xPriv, publicKeyRaw: xPubRaw } = generateX25519();

  return {
    ed25519PublicKey: edPubRaw.toString("base64"),
    x25519PublicKey: xPubRaw.toString("base64"),
    edPrivateKey: edPriv,
    xPrivateKey: xPriv,
  };
}

// ─── HTTP helper ──────────────────────────────────────────────────────────────

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

// ─── Auth flow: challenge -> sign nonce -> token (SPEC section 3) ─────────────

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
  const signature = cryptoSign(null, nonceBytes, identity.edPrivateKey).toString("base64");
  const auth = await call<AuthToken>("POST", "/api/auth/keypair/token", {
    ed25519PublicKey: identity.ed25519PublicKey,
    nonce: challenge.nonce,
    signature,
  });
  return auth.token;
}

// ─── Real envelope + wrapped key crypto ────────────────────────────────────────

/**
 * Encrypts a plaintext alt payload into an {@link EncryptedEnvelope}, binding
 * `(repoId, payloadVersion, keyEpoch)` into the AES-256-GCM AAD (SPEC section 4).
 *
 * @param dataKey - The 32-byte repo data key.
 * @param repoId - Repo the envelope belongs to.
 * @param payloadVersion - Payload version for this write.
 * @param keyEpoch - Key epoch for this write.
 * @param plaintext - The plaintext payload.
 * @returns An {@link EncryptedEnvelope} with a fresh random IV.
 */
function buildEnvelope(
  dataKey: Buffer,
  repoId: string,
  payloadVersion: number,
  keyEpoch: number,
  plaintext: Plaintext,
): EncryptedEnvelope {
  const body = Buffer.from(JSON.stringify(plaintext), "utf8");
  return encryptPayload(dataKey, repoId, payloadVersion, keyEpoch, body) as EncryptedEnvelope;
}

/**
 * Assembles a {@link MemberEntry} from an identity, wrapping the shared data key to
 * the member's X25519 public key (SPEC section 4).
 *
 * @param identity - The member whose public keys populate the entry.
 * @param dataKey - The 32-byte repo data key to wrap.
 * @param keyEpoch - Key epoch this entry's wrapped key belongs to.
 * @returns A member entry with a real wrapped data key and no key-binding signature.
 */
function buildMemberEntry(identity: Identity, dataKey: Buffer, keyEpoch: number): MemberEntry {
  const wk = wrapDataKey(identity.x25519PublicKey, dataKey) as WrappedKey;
  return {
    ed25519PublicKey: identity.ed25519PublicKey,
    x25519PublicKey: identity.x25519PublicKey,
    wrappedDataKey: wk,
    keyEpoch,
    keyBindingSig: null,
  };
}

// ─── Transcript ───────────────────────────────────────────────────────────────

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
 * The steps, in order: generate two local identities (alice, bob); authenticate alice; create a repo
 * with alice as sole member and a real encrypted v1 payload; pull at the known version (unchanged) and
 * from version 0 (envelope returned); push a real v2 payload; demonstrate the optimistic-concurrency
 * conflict path with a stale expected version; add bob as a member; fetch bob's stored key entry;
 * then authenticate bob and have him pull the shared repo, unwrap the data key, and decrypt the payload.
 *
 * @returns A promise that resolves once the full transcript has been printed.
 * @throws Error if any server call returns a non-2xx status (propagated from {@link call}); the top-level
 *   `main().catch(...)` handler turns this into a non-zero exit code.
 */
async function main(): Promise<void> {
  console.log(`AVP reference client -> ${BASE_URL}`);
  console.log("(Envelope and wrapped-key crypto is real; the server stays zero-knowledge.)\n");

  // Two members, generated locally. alice creates the repo; bob joins later.
  const alice = generateIdentity();
  const bob = generateIdentity();
  step("members", `alice=${alice.ed25519PublicKey.slice(0, 12)}… bob=${bob.ed25519PublicKey.slice(0, 12)}…`);

  // 1. Authenticate alice (challenge -> sign nonce -> token).
  const aliceToken = await authenticate(alice);
  step("auth", `alice token=${aliceToken.slice(0, 12)}…`);

  // 2. alice mints a per-repo data key and encrypts a real initial payload.
  const dataKey = randomBytes(32);
  const repoId = randomUuid();

  const altsV1: Alt[] = [
    { uuid: "11111111-1111-4111-8111-111111111111", username: "alice_main", accessToken: "secret-v1", type: "MICROSOFT", lastUsed: 1 },
  ];
  const envelopeV1 = buildEnvelope(dataKey, repoId, 1, 0, { alts: altsV1, payloadVersion: 1 });

  const createdManifest = await call<VaultManifest>(
    "POST",
    "/v1/repos",
    {
      manifest: {
        repoId,
        schemeId: SCHEME_ID,
        keyEpoch: 0,
        payloadVersion: 1,
        members: [buildMemberEntry(alice, dataKey, 0)],
      } satisfies VaultManifest,
      initialEnvelope: envelopeV1,
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

  // 5. push a real v2 payload (adds alice_alt) with optimistic concurrency on the current version.
  const altsV2: Alt[] = [
    ...altsV1,
    { uuid: "22222222-2222-4222-8222-222222222222", username: "alice_alt", accessToken: "secret-v2", type: "MICROSOFT", lastUsed: 2 },
  ];
  const nextVersion = createdManifest.payloadVersion + 1;
  const envelopeV2 = buildEnvelope(dataKey, repoId, nextVersion, 0, { alts: altsV2, payloadVersion: nextVersion });
  const pushResult = await call<PushResponse>(
    "POST",
    `/v1/repos/${encodeURIComponent(repoId)}/push`,
    {
      repoId,
      envelope: envelopeV2,
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
      envelope: envelopeV2,
      expectedPayloadVersion: createdManifest.payloadVersion, // stale on purpose
    },
    aliceToken,
  );
  step("push (stale)", `accepted=${conflict.accepted} conflict=${conflict.conflict} serverV=${conflict.payloadVersion}`);

  // 7. addMember — alice wraps the data key to bob's X25519 key and records his entry.
  const withBob = await call<VaultManifest>(
    "POST",
    `/v1/repos/${encodeURIComponent(repoId)}/add-member`,
    { repoId, member: buildMemberEntry(bob, dataKey, 0) },
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

  // 9. bob authenticates, pulls, unwraps the data key, and decrypts the payload.
  const bobToken = await authenticate(bob);
  const bobPull = await call<PullResponse>(
    "POST",
    `/v1/repos/${encodeURIComponent(repoId)}/pull`,
    { repoId, knownPayloadVersion: 0 },
    bobToken,
  );
  if (bobPull.envelope === null) {
    throw new Error("bob's pull returned no envelope");
  }

  // Find bob's own member entry in the manifest to get his wrapped data key.
  const bobMemberEntry = bobPull.manifest.members.find((m) => m.ed25519PublicKey === bob.ed25519PublicKey);
  if (!bobMemberEntry) {
    throw new Error("bob is not in the pulled roster");
  }

  // Unwrap bob's data key and decrypt the payload.
  const bobDataKey = unwrapDataKey(bob.xPrivateKey, bobMemberEntry.wrappedDataKey as WrappedKeyFields);
  const plaintext = decryptPayload(bobDataKey, bobPull.envelope as EncryptedEnvelopeFields);
  const payload = JSON.parse(plaintext.toString("utf8")) as Plaintext;

  step("bob pull", `v=${bobPull.manifest.payloadVersion} alts=${payload.alts.length} (decrypted)`);
  for (const alt of payload.alts) {
    step("  alt", `${alt.username} (${alt.uuid})`);
  }

  console.log("\nDone. Full lifecycle exercised against a zero-knowledge server; bob decrypted alice's payload.");
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
  console.error("Is a server running? Start one with `bun run start` in ../server, or set AVP_SERVER_URL.");
  process.exitCode = 1;
});
