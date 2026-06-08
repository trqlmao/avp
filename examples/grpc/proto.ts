/**
 * Shared loader for the gRPC reference example.
 *
 * It loads the canonical schema (../../proto/avp.proto) dynamically with @grpc/proto-loader, so this
 * example exercises the real proto with no codegen step and no committed generated stubs. The example's
 * own auth service (avp-auth.proto) is loaded alongside it; both live in `package avp`. `keepCase: false`
 * renders the snake_case proto fields as the camelCase the rest of AVP uses, and `longs: Number` maps
 * int64 counters to JS numbers.
 *
 * SPDX-License-Identifier: MIT
 */

import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";

const here = dirname(fileURLToPath(import.meta.url));
const protoDir = join(here, "..", "..", "proto");

const definition = protoLoader.loadSync(["avp.proto", "avp-auth.proto"], {
  keepCase: false,
  longs: Number,
  enums: String,
  defaults: true,
  oneofs: true,
  includeDirs: [protoDir, here],
});

// The `avp` package: { Vault, Auth, <messages> }.
export const avp = (grpc.loadPackageDefinition(definition) as any).avp;
export { grpc };
