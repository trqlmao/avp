/**
 * Proto/schema parity as protobufjs reads proto/avp.proto (an independent parser from the regex one
 * in schema.test.ts), plus the shape of the gRPC client profile (SPEC 10.3): the Vault service
 * carries every client operation, PullRequest addresses its repository, and HostInfo mirrors the
 * discovery document.
 *
 * SPDX-License-Identifier: MIT
 */

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import protobuf from "protobufjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..", "..");

const schema = JSON.parse(readFileSync(join(root, "schema", "avp.schema.json"), "utf8"));
const defs = schema.$defs as Record<string, { properties?: Record<string, unknown> }>;
const protoRoot = protobuf.loadSync(join(root, "proto", "avp.proto"));
protoRoot.resolveAll();

// gRPC-only addressing fields: in the proto, never in an HTTP/JSON body (schema stays additionalProperties: false).
const GRPC_ONLY: Record<string, string[]> = { PullRequest: ["repoId"] };

function avpType(name: string): protobuf.Type {
  return protoRoot.lookupType(name);
}

function schemaDef(message: string): { properties: Record<string, unknown> } {
  const def = defs[message];
  assert.ok(def, `schema is missing $def ${message}`);
  return { properties: def.properties ?? {} };
}

function field(type: string, name: string): protobuf.Field {
  const f = avpType(type).fields[name];
  assert.ok(f, `${type} has no field ${name}`);
  return f;
}

function fieldIds(type: string): Record<string, number> {
  return Object.fromEntries(Object.values(avpType(type).fields).map((f) => [f.name, f.id]));
}

function sortedMethodNames(service: string): string[] {
  return Object.keys(protoRoot.lookupService(service).methods).sort();
}

function protoMessageNames(): string[] {
  const ns = protoRoot.lookup("avp") as protobuf.Namespace;
  return ns.nestedArray.filter((n): n is protobuf.Type => n instanceof protobuf.Type).map((t) => t.name);
}

test("every proto message the schema mirrors has the same camelCase fields", () => {
  const mirrored = protoMessageNames().filter((n) => n in defs);
  assert.ok(mirrored.length > 20, "expected the schema to mirror the proto messages");
  for (const name of mirrored) {
    const grpcOnly = new Set(GRPC_ONLY[name] ?? []);
    const protoFields = Object.keys(avpType(name).fields)
      .filter((f) => !grpcOnly.has(f))
      .sort();
    assert.deepEqual(Object.keys(schemaDef(name).properties).sort(), protoFields, name);
  }
});

test("the schema never carries a gRPC-only field", () => {
  for (const [m, fs] of Object.entries(GRPC_ONLY)) {
    for (const f of fs) assert.ok(!(f in schemaDef(m).properties), `${m}.${f} must stay out of the schema`);
  }
});

test("the Vault service carries every client operation of SPEC 10.1 and GetHostInfo", () => {
  assert.deepEqual(sortedMethodNames("avp.Vault"), [
    "Challenge",
    "CreateRepo",
    "GetHostInfo",
    "Leave",
    "PrepareJoin",
    "PublishManifest",
    "Pull",
    "Push",
    "Token",
  ]);
});

test("the new Vault rpcs take and return the auth and discovery messages", () => {
  const methods = protoRoot.lookupService("avp.Vault").methods;
  const io = (m: string) => [methods[m]?.requestType, methods[m]?.responseType];
  assert.deepEqual(io("GetHostInfo"), ["HostInfoRequest", "HostInfo"]);
  assert.deepEqual(io("Challenge"), ["ChallengeRequest", "AuthChallenge"]);
  assert.deepEqual(io("Token"), ["TokenRequest", "AuthToken"]);
});

test("PullRequest addresses its repository", () => {
  assert.equal(field("avp.PullRequest", "repoId").id, 3);
  assert.equal(field("avp.PullRequest", "repoId").type, "string");
});

test("HostInfo mirrors the discovery document", () => {
  assert.deepEqual(fieldIds("avp.HostInfo"), { version: 1, profiles: 2, hostKey: 3 });
  assert.equal(field("avp.HostInfo", "profiles").repeated, true);
  assert.deepEqual(fieldIds("avp.HostInfoRequest"), {});
});
