/**
 * vectors/grpc.json: the proto3 binary encoding of every avp.Vault request and reply body (SPEC 10.3).
 * The committed file must be what the builder derives, every case must encode to its bytes and decode
 * back to its full-form JSON, and the bytes must be in the canonical encoding the file describes (no
 * default-valued field on the wire, field numbers ascending).
 *
 * SPDX-License-Identifier: MIT
 */

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import protobuf from "protobufjs";

import { buildGrpcVectors, decodeFull, encode, loadAvpProto, type GrpcCase } from "../src/grpc-vectors.ts";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..", "..");

function readJson(rel: string): any {
  return JSON.parse(readFileSync(join(root, rel), "utf8"));
}

const committed = readJson("vectors/grpc.json");
const cases: GrpcCase[] = committed.cases;
const proto = loadAvpProto();

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

interface WireField {
  readonly id: number;
  readonly field: protobuf.Field;
  readonly value: number | Uint8Array;
}

// Reads one encoded message field by field, recursing into message-typed fields.
function walk(type: protobuf.Type, bytes: Uint8Array, visit: (type: protobuf.Type, fields: WireField[]) => void): void {
  const reader = protobuf.Reader.create(bytes);
  const fields: WireField[] = [];
  while (reader.pos < reader.len) {
    const tag = reader.uint32();
    const id = tag >>> 3;
    const wire = tag & 7;
    const field = type.fieldsById[id];
    assert.ok(field, `${type.name}: unknown field number ${id}`);
    if (wire === 0) {
      fields.push({ id, field, value: Number(reader.int64().toString()) });
    } else if (wire === 2) {
      const value = reader.bytes();
      fields.push({ id, field, value });
      if (field.resolvedType instanceof protobuf.Type) walk(field.resolvedType, value, visit);
    } else {
      assert.fail(`${type.name}.${field.name}: unexpected wire type ${wire}`);
    }
  }
  visit(type, fields);
}

test("grpc.json is what the builder derives", () => {
  assert.deepEqual(committed, buildGrpcVectors());
});

test("grpc.json names the proto and states the canonical encoding", () => {
  assert.equal(committed.proto, "proto/avp.proto");
  assert.match(committed.description, /ascending field number/);
  assert.match(committed.description, /omitted/);
});

test("every case encodes to its bytes", () => {
  for (const c of cases) assert.equal(hex(encode(proto, c.message, c.json)), c.protoHex, c.name);
});

test("every case decodes to its full-form json", () => {
  for (const c of cases) assert.deepEqual(decodeFull(proto, c.message, c.protoHex), c.json, c.name);
});

test("there is a case for the request and the reply of every Vault RPC", () => {
  const covered = new Set(cases.map((c) => c.message));
  const methods = proto.lookupService("avp.Vault").methodsArray;
  assert.equal(methods.length, 9);
  for (const m of methods) {
    assert.ok(covered.has(`avp.${m.requestType}`), `${m.name} request ${m.requestType}`);
    assert.ok(covered.has(`avp.${m.responseType}`), `${m.name} reply ${m.responseType}`);
  }
});

test("case names are unique and every message is a fully qualified avp type", () => {
  assert.equal(new Set(cases.map((c) => c.name)).size, cases.length);
  assert.equal(cases.length, 18);
  for (const c of cases) assert.ok(proto.lookupType(c.message) && c.message.startsWith("avp."), c.message);
});

test("no protoHex carries a default-valued field", () => {
  for (const c of cases) {
    walk(proto.lookupType(c.message), Buffer.from(c.protoHex, "hex"), (type, fields) => {
      for (const f of fields) {
        const where = `${c.name}: ${type.name}.${f.field.name}`;
        if (f.field.type === "string") assert.ok((f.value as Uint8Array).length > 0, `${where} is an empty string`);
        if (f.field.type === "int64" || f.field.type === "bool") assert.notEqual(f.value, 0, `${where} is zero`);
      }
    });
  }
});

test("field numbers ascend within every encoded message", () => {
  for (const c of cases) {
    walk(proto.lookupType(c.message), Buffer.from(c.protoHex, "hex"), (type, fields) => {
      for (let i = 1; i < fields.length; i++) {
        const [a, b] = [fields[i - 1], fields[i]];
        assert.ok(b.id >= a.id, `${c.name}: ${type.name} field ${b.id} after ${a.id}`);
        if (b.id === a.id) assert.ok(b.field.repeated, `${c.name}: ${type.name}.${b.field.name} repeats`);
      }
    });
  }
});

test("the full form carries every scalar and repeated field, and omits only absent messages", () => {
  for (const c of cases) {
    const type = proto.lookupType(c.message);
    const check = (t: protobuf.Type, obj: Record<string, unknown>, where: string) => {
      for (const f of t.fieldsArray) {
        const v = obj[f.name];
        if (f.repeated) assert.ok(Array.isArray(v), `${where}.${f.name} must be an array`);
        else if (f.resolvedType instanceof protobuf.Type) {
          if (v !== undefined) check(f.resolvedType, v as Record<string, unknown>, `${where}.${f.name}`);
        } else assert.notEqual(v, undefined, `${where}.${f.name} must be present`);
        if (f.repeated && f.resolvedType instanceof protobuf.Type) {
          for (const [i, el] of (v as Record<string, unknown>[]).entries()) {
            check(f.resolvedType, el, `${where}.${f.name}[${i}]`);
          }
        }
      }
    };
    check(type, c.json, c.name);
  }
});

test("the publish case with a commit and the one without differ only by that commit", () => {
  const byName = Object.fromEntries(cases.map((c) => [c.name, c]));
  assert.equal(byName["publish-manifest-request"].json.commit, undefined);
  assert.ok(byName["publish-manifest-request-with-commit"].json.commit);
});
