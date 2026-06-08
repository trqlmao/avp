/**
 * Federation handshake and addressing vectors (SPEC section 8): the base64url join-handshake tokens
 * (invite request, repo locator) and the avp:// repository URI. Token cases are a decode oracle and a
 * canonical-encode check; the URI cases pin parse and format of avp://<host>/<repoId>.
 *
 * SPDX-License-Identifier: MIT
 */

import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..", "..");

const schema = JSON.parse(readFileSync(join(root, "schema", "avp.schema.json"), "utf8"));
const fed = JSON.parse(readFileSync(join(root, "vectors", "federation.json"), "utf8"));

const ajv = new Ajv2020({ strict: false, allErrors: true });
ajv.addSchema(schema, "avp");

for (const tc of fed.tokens as Array<any>) {
  test(`federation token ${tc.name}: decoding base64url yields the object`, () => {
    const obj = JSON.parse(Buffer.from(tc.base64url, "base64url").toString("utf8"));
    assert.deepEqual(obj, tc.decoded);
  });

  test(`federation token ${tc.name}: canonical minified encoding round-trips`, () => {
    const json = JSON.stringify(tc.decoded);
    assert.equal(json, tc.canonicalJson, "canonical JSON mismatch (field order or whitespace)");
    assert.equal(Buffer.from(json, "utf8").toString("base64url"), tc.base64url, "base64url mismatch");
  });

  test(`federation token ${tc.name}: decoded object validates against ${tc.schema}`, () => {
    const validate = ajv.getSchema(`avp#/$defs/${tc.schema}`);
    assert.ok(validate, `schema is missing $def ${tc.schema}`);
    assert.ok(validate(tc.decoded), JSON.stringify(validate.errors, null, 2));
  });
}

// avp://<host>/<repoId>: the authority is the host (or host:port); the repoId is the single opaque
// path segment and never encodes the host.
const AVP_URI = /^avp:\/\/([^/]+)\/(.+)$/;

function parseAvpUri(uri: string): { host: string; repoId: string } {
  const m = AVP_URI.exec(uri);
  if (!m) {
    throw new Error(`not an avp:// uri: ${uri}`);
  }
  return { host: m[1], repoId: m[2] };
}

function formatAvpUri(host: string, repoId: string): string {
  return `avp://${host}/${repoId}`;
}

for (const tc of fed.uris as Array<any>) {
  test(`avp uri ${tc.name}: parses into host and repoId`, () => {
    assert.deepEqual(parseAvpUri(tc.uri), { host: tc.host, repoId: tc.repoId });
  });

  test(`avp uri ${tc.name}: formats back to the same string`, () => {
    assert.equal(formatAvpUri(tc.host, tc.repoId), tc.uri);
  });
}
