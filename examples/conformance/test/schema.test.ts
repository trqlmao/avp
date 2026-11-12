/**
 * Consistency checks across the repository's machine-readable artifacts, so the proto, the JSON
 * schema, the worked example bodies, the vector index, and the OpenAPI description cannot silently
 * drift apart. The expected values below are written out as literal data from the AVP 0.5 plan
 * (route table, error table, Interfaces block) and SPEC.md; they are not read back from the files
 * under test.
 *
 *   - proto/avp.proto declares exactly the 0.5 services, rpcs, messages, and field numbers;
 *   - every proto message has a same-named schema `$def` with the same field set in camelCase, in
 *     both directions, and the schema-only `$defs` are exactly the listed ones;
 *   - every example body in examples/*-request.json and *-response.json validates against its
 *     `$def`, and deliberately wrong bodies fail;
 *   - openapi.yaml has exactly the 0.5 routes, each with its listed status set, bodies, and tags;
 *   - vectors/index.json lists exactly the vector files present in vectors/.
 *
 * SPDX-License-Identifier: MIT
 */

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";
import { parse as parseYaml } from "yaml";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..", ".."); // examples/conformance/test -> repo root

const schema = JSON.parse(readFileSync(join(root, "schema", "avp.schema.json"), "utf8"));
const protoText = readFileSync(join(root, "proto", "avp.proto"), "utf8");
const openapiText = readFileSync(join(root, "openapi.yaml"), "utf8");

const ajv = new Ajv2020({ strict: false, allErrors: true });
ajv.addSchema(schema, "avp");

function validatorFor(def: string) {
  const validate = ajv.getSchema(`avp#/$defs/${def}`);
  assert.ok(validate, `schema is missing $def ${def}`);
  return validate;
}

// ---------------------------------------------------------------------------------------------
// Expected shapes (literal data from the plan and SPEC.md)
// ---------------------------------------------------------------------------------------------

const EXPECTED_SERVICES: Record<string, Record<string, readonly [string, string]>> = {
  Vault: {
    CreateRepo: ["CreateRepoRequest", "SignedManifest"],
    Pull: ["PullRequest", "PullResponse"],
    Push: ["PushRequest", "PushResponse"],
    PublishManifest: ["PublishManifestRequest", "SignedManifest"],
    Leave: ["LeaveRequest", "LeaveResponse"],
    PrepareJoin: ["PrepareJoinRequest", "Acceptance"],
  },
  Replication: {
    Heads: ["HeadsRequest", "HeadsResponse"],
    Fetch: ["FetchRequest", "FetchResponse"],
    Offer: ["OfferRequest", "OfferResponse"],
  },
};

// Field names and numbers of the messages the plan's Interfaces block pins, plus the messages
// SPEC.md section 9.1 and section 10 add (ManifestTip, RejectedItem, the request/response pairs).
const EXPECTED_FIELDS: Record<string, Record<string, number>> = {
  WrappedKey: { scheme_id: 1, ephemeral_public_key: 2, iv: 3, ciphertext: 4 },
  HostRef: { host_key: 1, locator: 2 },
  MemberEntry: { ed25519_public_key: 1, x25519_public_key: 2, wrapped_data_key: 3, key_epoch: 4, home_host_key: 6 },
  Removal: { member_key: 1, removed_at_seq: 2, frontier: 3 },
  ManifestState: {
    repo_id: 1,
    manifest_seq: 2,
    prev_manifest_hash: 3,
    owner_key: 4,
    genesis_nonce: 5,
    scheme_id: 6,
    key_epoch: 7,
    share_refresh_tokens: 8,
    hosts: 9,
    members: 10,
    removals: 11,
  },
  SignedManifest: { state: 1, owner_signature: 2 },
  Commit: {
    repo_id: 1,
    commit_id: 2,
    parents: 3,
    manifest_seq: 4,
    manifest_hash: 5,
    key_epoch: 6,
    author: 7,
    iv: 8,
    ciphertext: 9,
    author_signature: 10,
  },
  LeaveRequest: { repo_id: 1, member_key: 2, at: 3, signature: 4 },
  LeaveResponse: {},
  Acceptance: { repo_id: 1, member_key: 2, host_key: 3, expires_at: 4, signature: 5 },
  CreateRepoRequest: { manifest: 1, commit: 2 },
  PullRequest: { since_manifest_seq: 1, known_heads: 2 },
  PullResponse: { manifests: 1, heads: 2, leaves: 3 },
  PushRequest: { commit: 1 },
  PushResponse: { accepted: 1, heads: 2 },
  PublishManifestRequest: { manifest: 1, commit: 2 },
  PrepareJoinRequest: { repo_id: 1, member_key: 2 },
  ManifestTip: { manifest_seq: 1, manifest_hash: 2 },
  HeadsRequest: { repo_id: 1 },
  HeadsResponse: { manifest_tip: 1, heads: 2 },
  FetchRequest: { repo_id: 1, ids: 2 },
  FetchResponse: { manifests: 1, commits: 2, leaves: 3 },
  OfferRequest: { repo_id: 1, manifests: 2, commits: 3, leaves: 4 },
  RejectedItem: { id: 1, code: 2 },
  OfferResponse: { accepted: 1, rejected: 2 },
  ChallengeRequest: { ed25519_public_key: 1 },
  AuthChallenge: { nonce: 1 },
  TokenRequest: { ed25519_public_key: 1, nonce: 2, signature: 3 },
  AuthToken: { token: 1, expires_at: 2 },
};

// `$defs` that exist only in the JSON schema (no proto message): the error body, the payload
// plaintext (inside commit ciphertext), the out-of-band tokens (SPEC section 11), and a helper.
const EXPECTED_SCHEMA_ONLY_DEFS = [
  "Account",
  "Base64",
  "BanInfo",
  "Error",
  "Field",
  "InviteToken",
  "LinkGrant",
  "LinkRequest",
  "RepoLocator",
  "Stamp",
  "VaultPayload",
];

const REMOVED_0_4_NAMES = ["EncryptedEnvelope", "VaultManifest", "MemberAddRequest", "MemberRemoveRequest"];

// Error codes: the SPEC section 10.4 table plus too_large and policy_denied (SPEC section 12.1).
const EXPECTED_ERROR_CODES = [
  "bad_request",
  "unauthorized",
  "forbidden",
  "not_hosted",
  "not_found",
  "duplicate_repo",
  "too_many_heads",
  "manifest_conflict",
  "missing_parents",
  "quota_exceeded",
  "too_large",
  "policy_denied",
];

// Example bodies: file -> `$def` it must validate against. The set of files is also pinned.
const EXAMPLE_BODIES: Record<string, string> = {
  "create-repo-request.json": "CreateRepoRequest",
  "offer-request.json": "OfferRequest",
  "publish-manifest-request.json": "PublishManifestRequest",
  "pull-response.json": "PullResponse",
  "push-request.json": "PushRequest",
};

interface RouteExpectation {
  readonly request: string | null;
  readonly response: string | null;
  readonly statuses: readonly string[];
  readonly tag: string;
  readonly security: "bearer" | "none" | "host";
}

// The plan's route table with the statuses each route may return, drawn from the plan's error
// table (and 413 from SPEC section 12.1, 503 from the replication test control, SPEC section 9.3).
const EXPECTED_ROUTES: Record<string, RouteExpectation> = {
  "POST /api/auth/keypair/challenge": {
    request: "ChallengeRequest",
    response: "AuthChallenge",
    statuses: ["200", "400"],
    tag: "auth",
    security: "none",
  },
  "POST /api/auth/keypair/token": {
    request: "TokenRequest",
    response: "AuthToken",
    statuses: ["200", "400", "401"],
    tag: "auth",
    security: "none",
  },
  "POST /v1/repos": {
    request: "CreateRepoRequest",
    response: "SignedManifest",
    statuses: ["200", "400", "401", "403", "409", "413", "429"],
    tag: "vault",
    security: "bearer",
  },
  "POST /v1/repos/{repoId}/pull": {
    request: "PullRequest",
    response: "PullResponse",
    statuses: ["200", "400", "401", "403", "404"],
    tag: "vault",
    security: "bearer",
  },
  "POST /v1/repos/{repoId}/push": {
    request: "PushRequest",
    response: "PushResponse",
    statuses: ["200", "400", "401", "403", "404", "409", "413", "422", "429"],
    tag: "vault",
    security: "bearer",
  },
  "POST /v1/repos/{repoId}/manifest": {
    request: "PublishManifestRequest",
    response: "SignedManifest",
    statuses: ["200", "400", "401", "403", "404", "409", "413", "422", "429"],
    tag: "vault",
    security: "bearer",
  },
  "POST /v1/repos/{repoId}/leave": {
    request: "LeaveRequest",
    response: "LeaveResponse",
    statuses: ["200", "400", "401", "403", "404"],
    tag: "vault",
    security: "bearer",
  },
  "POST /v1/prepare-join": {
    request: "PrepareJoinRequest",
    response: "Acceptance",
    statuses: ["200", "400", "401", "403", "429"],
    tag: "vault",
    security: "bearer",
  },
  "POST /v1/host/repos/{repoId}/heads": {
    request: "HeadsRequest",
    response: "HeadsResponse",
    statuses: ["200", "400", "401", "403", "404", "503"],
    tag: "replication",
    security: "host",
  },
  "POST /v1/host/repos/{repoId}/fetch": {
    request: "FetchRequest",
    response: "FetchResponse",
    statuses: ["200", "400", "401", "403", "404", "503"],
    tag: "replication",
    security: "host",
  },
  "POST /v1/host/repos/{repoId}/offer": {
    request: "OfferRequest",
    response: "OfferResponse",
    statuses: ["200", "400", "401", "403", "404", "413", "503"],
    tag: "replication",
    security: "host",
  },
  "GET /.well-known/avp": {
    request: null,
    response: null, // Discovery is an inline component schema, not a $defs entry
    statuses: ["200", "404"],
    tag: "discovery",
    security: "none",
  },
};

// ---------------------------------------------------------------------------------------------
// Proto parsing
// ---------------------------------------------------------------------------------------------

interface ProtoField {
  readonly num: number;
  readonly type: string;
  readonly repeated: boolean;
  readonly optional: boolean;
}
interface ProtoMessage {
  readonly fields: Map<string, ProtoField>;
  readonly reservedNumbers: number[];
  readonly reservedNames: string[];
}

function stripComments(text: string): string {
  return text.replace(/\/\/[^\n]*/g, "");
}

function parseProto(text: string) {
  const src = stripComments(text);
  const messages = new Map<string, ProtoMessage>();
  for (const m of src.matchAll(/message\s+(\w+)\s*\{([^}]*)\}/g)) {
    const fields = new Map<string, ProtoField>();
    const reservedNumbers: number[] = [];
    const reservedNames: string[] = [];
    for (const raw of m[2].split(";")) {
      const stmt = raw.trim();
      if (!stmt) continue;
      const reserved = stmt.match(/^reserved\s+(.+)$/);
      if (reserved) {
        for (const part of reserved[1].split(",")) {
          const p = part.trim();
          if (/^\d+$/.test(p)) reservedNumbers.push(Number(p));
          else if (/^"[^"]+"$/.test(p)) reservedNames.push(p.slice(1, -1));
          else assert.fail(`unsupported reserved clause in ${m[1]}: ${stmt}`);
        }
        continue;
      }
      const f = stmt.match(/^(optional\s+|repeated\s+)?([\w.]+)\s+(\w+)\s*=\s*(\d+)$/);
      assert.ok(f, `cannot parse proto statement in ${m[1]}: ${stmt}`);
      fields.set(f[3], {
        num: Number(f[4]),
        type: f[2],
        repeated: (f[1] ?? "").trim() === "repeated",
        optional: (f[1] ?? "").trim() === "optional",
      });
    }
    messages.set(m[1], { fields, reservedNumbers, reservedNames });
  }
  const services = new Map<string, Map<string, [string, string]>>();
  for (const s of src.matchAll(/service\s+(\w+)\s*\{([^}]*)\}/g)) {
    const rpcs = new Map<string, [string, string]>();
    for (const r of s[2].matchAll(/rpc\s+(\w+)\s*\(\s*(\w+)\s*\)\s*returns\s*\(\s*(\w+)\s*\)/g)) {
      rpcs.set(r[1], [r[2], r[3]]);
    }
    services.set(s[1], rpcs);
  }
  return { messages, services };
}

function camel(snake: string): string {
  return snake.replace(/_([a-z0-9])/g, (_, c: string) => c.toUpperCase());
}

const proto = parseProto(protoText);
const defs = schema.$defs as Record<string, any>;

test("proto declares exactly the 0.5 services and rpcs", () => {
  const actual: Record<string, Record<string, readonly [string, string]>> = {};
  for (const [svc, rpcs] of proto.services) actual[svc] = Object.fromEntries(rpcs);
  assert.deepEqual(actual, EXPECTED_SERVICES);
});

test("proto declares exactly the 0.5 messages with the pinned field names and numbers", () => {
  assert.deepEqual([...proto.messages.keys()].sort(), Object.keys(EXPECTED_FIELDS).sort());
  for (const [name, expected] of Object.entries(EXPECTED_FIELDS)) {
    const actual = Object.fromEntries([...proto.messages.get(name)!.fields].map(([f, v]) => [f, v.num]));
    assert.deepEqual(actual, expected, `field numbers of ${name}`);
  }
});

test("proto field numbers are unique within each message", () => {
  for (const [name, msg] of proto.messages) {
    const nums = [...msg.fields.values()].map((f) => f.num);
    assert.equal(new Set(nums).size, nums.length, `duplicate field number in ${name}`);
  }
});

test("MemberEntry reserves field 5 and the name key_binding_sig", () => {
  const member = proto.messages.get("MemberEntry")!;
  assert.deepEqual(member.reservedNumbers, [5]);
  assert.deepEqual(member.reservedNames, ["key_binding_sig"]);
  assert.ok(![...member.fields.values()].some((f) => f.num === 5), "field 5 must not be used");
  assert.ok(!member.fields.has("key_binding_sig"), "key_binding_sig must not be a field");
});

test("every rpc request and response type is a declared message", () => {
  for (const rpcs of proto.services.values()) {
    for (const [rpc, [req, res]] of rpcs) {
      assert.ok(proto.messages.has(req), `${rpc} request ${req} is not a message`);
      assert.ok(proto.messages.has(res), `${rpc} response ${res} is not a message`);
    }
  }
});

test("the proto header documents that 0.5 is breaking and removes the 0.4 envelope and manifest", () => {
  assert.match(protoText, /BREAKING/);
  assert.match(protoText, /EncryptedEnvelope/); // named only in the header comment
  assert.ok(!proto.messages.has("EncryptedEnvelope"));
  assert.ok(!proto.messages.has("VaultManifest"));
});

// ---------------------------------------------------------------------------------------------
// Proto <-> schema
// ---------------------------------------------------------------------------------------------

test("schema $defs are exactly the proto messages plus the listed schema-only defs", () => {
  const expected = [...proto.messages.keys(), ...EXPECTED_SCHEMA_ONLY_DEFS].sort();
  assert.deepEqual(Object.keys(defs).sort(), expected);
  for (const gone of REMOVED_0_4_NAMES) assert.ok(!(gone in defs), `${gone} must be gone from the schema`);
});

for (const name of Object.keys(EXPECTED_FIELDS)) {
  test(`schema $defs/${name} has the same field set as proto message ${name}, in camelCase`, () => {
    const def = defs[name];
    assert.ok(def, `schema is missing $def ${name}`);
    assert.equal(def.type, "object");
    assert.equal(def.additionalProperties, false, `${name} must forbid unknown properties`);
    const protoFields = [...proto.messages.get(name)!.fields.keys()].map(camel).sort();
    const schemaFields = Object.keys(def.properties ?? {}).sort();
    assert.deepEqual(schemaFields, protoFields, `${name}: proto vs schema fields`);
    // every required field is a declared property, and every non-optional proto field is required
    // (the two documented exceptions below are optional in the schema on purpose)
    const required: string[] = def.required ?? [];
    for (const r of required) assert.ok(schemaFields.includes(r), `${name}.${r} is required but not a property`);
    const optionalInSchema = new Set(
      name === "ManifestState" ? ["shareRefreshTokens"] : name === "PublishManifestRequest" ? ["commit"] : [],
    );
    const mustBeRequired = schemaFields.filter((f) => !optionalInSchema.has(f));
    assert.deepEqual([...required].sort(), mustBeRequired.sort(), `${name}: required set`);
  });

  test(`schema $defs/${name} agrees with proto on message-typed and repeated fields`, () => {
    const def = defs[name];
    for (const [fname, f] of proto.messages.get(name)!.fields) {
      const prop = def.properties[camel(fname)];
      const isMessage = proto.messages.has(f.type);
      if (f.repeated) {
        assert.equal(prop.type, "array", `${name}.${fname} must be an array`);
        const items = prop.items;
        if (isMessage) assert.equal(items.$ref, `#/$defs/${f.type}`, `${name}.${fname} items`);
      } else if (isMessage) {
        assert.equal(prop.$ref, `#/$defs/${f.type}`, `${name}.${fname} must $ref ${f.type}`);
      }
    }
  });
}

test("schema Error codes are exactly the SPEC section 10.4 table plus too_large and policy_denied", () => {
  assert.deepEqual([...defs.Error.properties.code.enum].sort(), [...EXPECTED_ERROR_CODES].sort());
});

test("schema pins the error body shape { error, code?, detail? }", () => {
  assert.deepEqual(defs.Error.required, ["error"]);
  assert.deepEqual(Object.keys(defs.Error.properties).sort(), ["code", "detail", "error"]);
});

// ---------------------------------------------------------------------------------------------
// Example bodies
// ---------------------------------------------------------------------------------------------

test("examples/ holds exactly the pinned request/response example files", () => {
  const present = readdirSync(join(root, "examples"))
    .filter((f) => /-(request|response)\.json$/.test(f))
    .sort();
  assert.deepEqual(present, Object.keys(EXAMPLE_BODIES).sort());
});

function loadExample(file: string): any {
  return JSON.parse(readFileSync(join(root, "examples", file), "utf8"));
}

for (const [file, def] of Object.entries(EXAMPLE_BODIES)) {
  test(`examples/${file} validates against ${def}`, () => {
    const validate = validatorFor(def);
    const ok = validate(loadExample(file));
    assert.ok(ok, `schema errors:\n${JSON.stringify(validate.errors, null, 2)}`);
  });
}

test("the validator is active: wrong bodies fail", () => {
  const create = validatorFor("CreateRepoRequest");
  const good = loadExample("create-repo-request.json");
  assert.ok(create(good), "baseline example must validate");

  // a missing required field
  const noCommit = structuredClone(good);
  delete noCommit.commit;
  assert.equal(create(noCommit), false, "missing commit must fail");
  const noSig = structuredClone(good);
  delete noSig.manifest.ownerSignature;
  assert.equal(create(noSig), false, "missing ownerSignature must fail");

  // an unknown property
  const extra = structuredClone(good);
  extra.manifest.state.surprise = 1;
  assert.equal(create(extra), false, "unknown property must fail");

  // the removed 0.4 field must not validate
  const legacy = structuredClone(good);
  legacy.manifest.state.members[0].keyBindingSig = null;
  assert.equal(create(legacy), false, "keyBindingSig is gone in 0.5");

  // a wrong type
  const wrongType = structuredClone(good);
  wrongType.manifest.state.manifestSeq = "1";
  assert.equal(create(wrongType), false, "string manifestSeq must fail");

  // binary fields are base64 with padding
  const badB64 = structuredClone(good);
  badB64.manifest.ownerSignature = "not base64!";
  assert.equal(create(badB64), false, "non-base64 signature must fail");

  // every example fails when emptied
  for (const [file, def] of Object.entries(EXAMPLE_BODIES)) {
    assert.equal(validatorFor(def)({}), false, `{} must not validate as ${def} (${file})`);
  }
});

test("offer and publish examples carry what SPEC.md says they carry", () => {
  const publish = loadExample("publish-manifest-request.json");
  const prev = publish.manifest.state;
  // an epoch-raising state carries its rotation commit in the same call (SPEC 8.3)
  assert.ok(publish.commit, "the publish example is epoch-raising and must carry its rotation commit");
  assert.equal(publish.commit.manifestSeq, prev.manifestSeq);
  assert.equal(publish.commit.keyEpoch, prev.keyEpoch);
  assert.ok(prev.removals.length > 0 && prev.removals[0].frontier.length > 0);
  const offer = loadExample("offer-request.json");
  assert.ok(Array.isArray(offer.manifests) && Array.isArray(offer.commits) && Array.isArray(offer.leaves));
});

// ---------------------------------------------------------------------------------------------
// vectors/index.json
// ---------------------------------------------------------------------------------------------

test("vectors/index.json lists exactly the vector files present", () => {
  const index = JSON.parse(readFileSync(join(root, "vectors", "index.json"), "utf8"));
  const listed = (index.vectors as Array<{ file: string }>).map((v) => v.file).sort();
  const present = readdirSync(join(root, "vectors"))
    .filter((f) => f.endsWith(".json") && f !== "index.json")
    .sort();
  assert.deepEqual(listed, present, "index.json and vectors/ are out of sync");
});

// ---------------------------------------------------------------------------------------------
// openapi.yaml
// ---------------------------------------------------------------------------------------------

const openapi = parseYaml(openapiText);

function resolveRef<T>(node: any): T {
  if (node && typeof node === "object" && typeof node.$ref === "string" && node.$ref.startsWith("#/")) {
    return node.$ref
      .slice(2)
      .split("/")
      .reduce((acc: any, key: string) => acc[key], openapi);
  }
  return node;
}

function defNameOf(node: any): string | null {
  const ref = node?.$ref as string | undefined;
  const m = ref?.match(/^\.\/schema\/avp\.schema\.json#\/\$defs\/(\w+)$/);
  return m ? m[1] : null;
}

test("openapi.yaml is OpenAPI 3.1 for protocol version 0.5", () => {
  assert.equal(openapi.openapi, "3.1.0");
  assert.equal(openapi.info.version, "0.5");
});

test("openapi.yaml parses and every schema $ref resolves to a $def", () => {
  const refs = [...openapiText.matchAll(/avp\.schema\.json#\/\$defs\/(\w+)/g)].map((m) => m[1]);
  const known = new Set(Object.keys(defs));
  const missing = [...new Set(refs)].filter((r) => !known.has(r));
  assert.deepEqual(missing, [], `OpenAPI references unknown schema $defs: ${missing.join(", ")}`);
  assert.ok(refs.length > 0, "expected openapi.yaml to reference the schema");
});

test("openapi.yaml does not redefine message shapes", () => {
  const schemas = Object.keys(openapi.components?.schemas ?? {});
  assert.deepEqual(schemas, ["Discovery"], "only Discovery may be an inline component schema");
});

test("openapi.yaml has exactly the 0.5 routes and no others", () => {
  const actual: string[] = [];
  for (const [path, item] of Object.entries<any>(openapi.paths)) {
    for (const method of Object.keys(item)) {
      if (["get", "put", "post", "delete", "patch", "head", "options"].includes(method)) {
        actual.push(`${method.toUpperCase()} ${path}`);
      }
    }
  }
  assert.deepEqual(actual.sort(), Object.keys(EXPECTED_ROUTES).sort());
});

for (const [route, expected] of Object.entries(EXPECTED_ROUTES)) {
  const [method, path] = route.split(" ");
  test(`openapi ${route}: statuses, bodies, tag, and security`, () => {
    const op = openapi.paths[path][method.toLowerCase()];
    assert.ok(op, `missing ${route}`);
    assert.deepEqual(Object.keys(op.responses).sort(), [...expected.statuses].sort(), "status set");
    assert.deepEqual(op.tags, [expected.tag]);

    if (expected.request) {
      assert.equal(defNameOf(op.requestBody.content["application/json"].schema), expected.request, "request body");
    } else {
      assert.equal(op.requestBody, undefined);
    }
    if (expected.response) {
      const ok = op.responses["200"].content["application/json"].schema;
      assert.equal(defNameOf(ok), expected.response, "200 body");
    }
    // every non-200 response that has a body documents the Error shape
    for (const [status, response] of Object.entries<any>(op.responses)) {
      if (status === "200" || route === "GET /.well-known/avp") continue;
      const r = resolveRef<any>(response);
      const content = r.content?.["application/json"];
      if (status === "503") continue; // a paused reference host answers 503 with no AVP error body
      assert.equal(defNameOf(content?.schema), "Error", `${route} ${status} must use the Error shape`);
    }

    if (expected.security === "bearer") {
      assert.equal(op.security, undefined, "inherits the global bearer requirement");
      assert.deepEqual(openapi.security, [{ bearerAuth: [] }]);
    } else {
      assert.deepEqual(op.security, [], "no bearer token");
    }
  });
}

test("openapi host routes document the three AVP-Host-* headers", () => {
  const hostRoutes = Object.entries(EXPECTED_ROUTES).filter(([, e]) => e.security === "host");
  assert.equal(hostRoutes.length, 3);
  for (const [route] of hostRoutes) {
    const [method, path] = route.split(" ");
    const op = openapi.paths[path][method.toLowerCase()];
    const params = (op.parameters as any[]).map((p) => resolveRef<any>(p));
    const headers = params.filter((p) => p.in === "header").map((p) => p.name).sort();
    assert.deepEqual(headers, ["AVP-Host-Key", "AVP-Host-Signature", "AVP-Host-Time"], route);
    for (const p of params.filter((p) => p.in === "header")) assert.equal(p.required, true);
    assert.ok(params.some((p) => p.in === "path" && p.name === "repoId"));
  }
});

test("openapi tags include replication", () => {
  const names = (openapi.tags as Array<{ name: string }>).map((t) => t.name);
  assert.ok(names.includes("replication"));
});
