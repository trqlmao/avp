/**
 * Builds vectors/grpc.json: the proto3 binary encoding of one request or reply body for every RPC of
 * the avp.Vault service (SPEC 10.3). The bodies are fixed values taken from the worked examples in
 * examples/*.json and from manifest.json, commit.json, and federation.json; nothing is random, so the
 * file is a pure function of the proto and those inputs.
 *
 * protobufjs writes a scalar that is explicitly set to its default (`fromObject({ a: "" })` emits field
 * `a` with length 0), so every body is reduced to its minimal form before it is encoded.
 *
 * Illustrative reference code, not production. SPDX-License-Identifier: MIT
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import protobuf from "protobufjs";

const here = dirname(fileURLToPath(import.meta.url));
// examples/conformance/src -> repo root
const root = join(here, "..", "..", "..");

/** The canonical encoding every `protoHex` in vectors/grpc.json uses. */
export const CANONICAL_ENCODING =
  "Canonical encoding: fields in ascending field number, scalars at their proto3 default and empty " +
  "repeated fields omitted, absent message fields omitted, packed encoding not used (no packable " +
  "fields exist).";

/** One body: the fully qualified message, its full-form JSON, and its canonical proto bytes in hex. */
export interface GrpcCase {
  readonly name: string;
  readonly message: string;
  readonly json: Record<string, any>;
  readonly protoHex: string;
}

/** The shape of vectors/grpc.json. */
export interface GrpcVectors {
  readonly description: string;
  readonly proto: string;
  readonly cases: GrpcCase[];
}

/**
 * Loads and resolves proto/avp.proto.
 *
 * @returns The resolved protobufjs root.
 */
export function loadAvpProto(): protobuf.Root {
  const proto = protobuf.loadSync(join(root, "proto", "avp.proto"));
  proto.resolveAll();
  return proto;
}

/**
 * Drops every scalar at its proto3 default (`""`, `0`, `false`) and every empty array, recursively,
 * keeping message-typed values (an empty object stays: it is a present message).
 *
 * @param value - A full-form or partial JSON body.
 * @returns The minimal form protobufjs encodes canonically.
 */
export function minimal(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(minimal);
  if (value === null || typeof value !== "object") return value;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value)) {
    if (v === "" || v === 0 || v === false) continue;
    if (Array.isArray(v) && v.length === 0) continue;
    out[k] = minimal(v);
  }
  return out;
}

/**
 * Encodes a JSON body as the canonical proto bytes of `message`.
 *
 * @param proto - The resolved avp.proto root.
 * @param message - The fully qualified message name, for example `avp.PushRequest`.
 * @param json - The body, full or minimal form.
 * @returns The encoded bytes.
 */
export function encode(proto: protobuf.Root, message: string, json: unknown): Uint8Array {
  const type = proto.lookupType(message);
  return type.encode(type.fromObject(minimal(json) as Record<string, unknown>)).finish();
}

// Drops null (absent) message fields and lists the keys in field-number order, recursively.
function fullForm(type: protobuf.Type, obj: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const f of [...type.fieldsArray].sort((a, b) => a.id - b.id)) {
    const v = obj[f.name];
    if (v === null || v === undefined) continue;
    const sub = f.resolvedType instanceof protobuf.Type ? f.resolvedType : null;
    if (sub && Array.isArray(v)) out[f.name] = v.map((el) => fullForm(sub, el as Record<string, unknown>));
    else if (sub) out[f.name] = fullForm(sub, v as Record<string, unknown>);
    else out[f.name] = v;
  }
  return out;
}

/**
 * Decodes proto bytes into the full form: every scalar present (defaults included), repeated fields as
 * arrays, absent message fields omitted.
 *
 * @param proto - The resolved avp.proto root.
 * @param message - The fully qualified message name.
 * @param protoHex - The encoded bytes in hex.
 * @returns The full-form JSON body.
 */
export function decodeFull(proto: protobuf.Root, message: string, protoHex: string): Record<string, any> {
  const type = proto.lookupType(message);
  const decoded = type.decode(Buffer.from(protoHex, "hex"));
  const obj = type.toObject(decoded, { longs: Number, defaults: true, arrays: true });
  return fullForm(type, obj) as Record<string, any>;
}

function readJson(rel: string): any {
  return JSON.parse(readFileSync(join(root, rel), "utf8"));
}

function byName<T extends { name: string }>(list: T[], name: string): T {
  const found = list.find((x) => x.name === name);
  if (!found) throw new Error(`no case named ${name}`);
  return found;
}

/**
 * Derives vectors/grpc.json.
 *
 * @returns The vectors, in the order the cases are listed.
 */
export function buildGrpcVectors(): GrpcVectors {
  const proto = loadAvpProto();
  const manifest = readJson("vectors/manifest.json");
  const commit = readJson("vectors/commit.json");
  const federation = readJson("vectors/federation.json");

  const challenge = byName<any>(federation.challenges, "alice-to-a");
  const leave = byName<any>(federation.leaves, "alice-leaves").decoded;
  const acceptance = byName<any>(federation.tokens, "invite-token").decoded.acceptance;
  const genesis = byName<any>(manifest.cases, "genesis").signedManifest;
  const addMembers = byName<any>(manifest.cases, "add-members").signedManifest;
  const root = byName<any>(commit.cases, "root").commit;
  const child = byName<any>(commit.cases, "single-parent").commit;

  const bodies: Array<[string, string, unknown]> = [
    ["host-info-request", "avp.HostInfoRequest", {}],
    ["host-info", "avp.HostInfo", { version: "0.5", profiles: ["http-json", "grpc"], hostKey: challenge.hostKey }],
    ["challenge-request", "avp.ChallengeRequest", { ed25519PublicKey: challenge.ed25519PublicKey }],
    ["auth-challenge", "avp.AuthChallenge", { nonce: challenge.nonce }],
    [
      "token-request",
      "avp.TokenRequest",
      { ed25519PublicKey: challenge.ed25519PublicKey, nonce: challenge.nonce, signature: challenge.signature },
    ],
    // The token format is host-defined and opaque (SPEC 3.3): any non-empty string.
    ["auth-token", "avp.AuthToken", { token: "opaque-host-token", expiresAt: 1767226500000 }],
    ["create-repo-request", "avp.CreateRepoRequest", readJson("examples/create-repo-request.json")],
    ["signed-manifest", "avp.SignedManifest", genesis],
    [
      "pull-request",
      "avp.PullRequest",
      { sinceManifestSeq: 1, knownHeads: [root.commitId], repoId: root.repoId },
    ],
    ["pull-response", "avp.PullResponse", readJson("examples/pull-response.json")],
    ["push-request", "avp.PushRequest", readJson("examples/push-request.json")],
    ["push-response", "avp.PushResponse", { accepted: true, heads: [child.commitId] }],
    ["publish-manifest-request", "avp.PublishManifestRequest", { manifest: addMembers }],
    [
      "publish-manifest-request-with-commit",
      "avp.PublishManifestRequest",
      readJson("examples/publish-manifest-request.json"),
    ],
    ["leave-request", "avp.LeaveRequest", leave],
    ["leave-response", "avp.LeaveResponse", {}],
    ["prepare-join-request", "avp.PrepareJoinRequest", { repoId: acceptance.repoId, memberKey: acceptance.memberKey }],
    ["acceptance", "avp.Acceptance", acceptance],
  ];

  const cases = bodies.map(([name, message, body]): GrpcCase => {
    const protoHex = Buffer.from(encode(proto, message, body)).toString("hex");
    return { name, message, json: decodeFull(proto, message, protoHex), protoHex };
  });

  return {
    description:
      "Proto3 binary encodings of the avp.Vault request and reply bodies (SPEC 10.3): one case per " +
      "message, with `message` its fully qualified name, `json` its full form (every scalar field " +
      "present, defaults included; repeated fields as arrays; absent message fields omitted, in the " +
      "proto field names in camelCase as in the HTTP/JSON profile), and `protoHex` its bytes. " +
      CANONICAL_ENCODING +
      " Generated by examples/conformance/scripts/grpc-vectors.ts.",
    proto: "proto/avp.proto",
    cases,
  };
}
