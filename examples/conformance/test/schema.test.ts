/**
 * Consistency checks across the repository's machine-readable artifacts, so the schema, the worked
 * example bodies, the vector index, and the OpenAPI description cannot silently drift apart:
 *
 *   - every example body in examples/*.json validates against its schema/avp.schema.json `$def`;
 *   - vectors/index.json lists exactly the vector files present in vectors/;
 *   - every `$ref` openapi.yaml makes into the JSON Schema resolves to a real `$def`, and the
 *     OpenAPI document parses as YAML.
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

const ajv = new Ajv2020({ strict: false, allErrors: true });
ajv.addSchema(schema, "avp");

function validatorFor(def: string) {
  const validate = ajv.getSchema(`avp#/$defs/${def}`);
  assert.ok(validate, `schema is missing $def ${def}`);
  return validate;
}

const EXAMPLE_BODIES: ReadonlyArray<readonly [string, string]> = [
  ["create-repo-request.json", "CreateRepoRequest"],
  ["pull-response.json", "PullResponse"],
  ["push-request.json", "PushRequest"],
];

for (const [file, def] of EXAMPLE_BODIES) {
  test(`examples/${file} validates against ${def}`, () => {
    const data = JSON.parse(readFileSync(join(root, "examples", file), "utf8"));
    const validate = validatorFor(def);
    const ok = validate(data);
    assert.ok(ok, `schema errors:\n${JSON.stringify(validate.errors, null, 2)}`);
  });
}

test("vectors/index.json lists exactly the vector files present", () => {
  const index = JSON.parse(readFileSync(join(root, "vectors", "index.json"), "utf8"));
  const listed = (index.vectors as Array<{ file: string }>).map((v) => v.file).sort();
  const present = readdirSync(join(root, "vectors"))
    .filter((f) => f.endsWith(".json") && f !== "index.json")
    .sort();
  assert.deepEqual(listed, present, "index.json and vectors/ are out of sync");
});

test("openapi.yaml parses and every schema $ref resolves to a $def", () => {
  const text = readFileSync(join(root, "openapi.yaml"), "utf8");
  assert.ok(parseYaml(text), "openapi.yaml did not parse as YAML");
  const refs = [...text.matchAll(/avp\.schema\.json#\/\$defs\/(\w+)/g)].map((m) => m[1]);
  const defs = new Set(Object.keys(schema.$defs));
  const missing = [...new Set(refs)].filter((r) => !defs.has(r));
  assert.deepEqual(missing, [], `OpenAPI references unknown schema $defs: ${missing.join(", ")}`);
  assert.ok(refs.length > 0, "expected openapi.yaml to reference the schema");
});
