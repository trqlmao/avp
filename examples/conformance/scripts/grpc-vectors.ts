/**
 * Writes or checks vectors/grpc.json.
 *
 *   bun examples/conformance/scripts/grpc-vectors.ts --write   regenerate vectors/grpc.json
 *   bun examples/conformance/scripts/grpc-vectors.ts --check   exit 1 if the committed file drifted
 *
 * Illustrative reference code, not production. SPDX-License-Identifier: MIT
 */

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { buildGrpcVectors } from "../src/grpc-vectors.ts";

const here = dirname(fileURLToPath(import.meta.url));
const target = join(here, "..", "..", "..", "vectors", "grpc.json");

const mode = process.argv[2] ?? "--check";
const expected = `${JSON.stringify(buildGrpcVectors(), null, 2)}\n`;

if (mode === "--write") {
  writeFileSync(target, expected);
  console.log("Wrote vectors/grpc.json");
} else if (mode === "--check") {
  let actual = "";
  try {
    actual = readFileSync(target, "utf8");
  } catch {
    actual = "";
  }
  if (actual !== expected) {
    console.error("vectors/grpc.json is out of sync. Run: bun examples/conformance/scripts/grpc-vectors.ts --write");
    process.exit(1);
  }
  console.log("vectors/grpc.json is in sync");
} else {
  console.error(`unknown flag ${mode}; use --write or --check`);
  process.exit(2);
}
