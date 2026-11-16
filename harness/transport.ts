/**
 * The harness's two transport profiles behind one request shape.
 *
 * The suites speak HTTP/JSON paths and bodies (SPEC 10.2). `httpTransport` sends them as they are.
 * `grpcTransport` maps each client path to its `avp.Vault` RPC (SPEC 10.3) and the JSON body to the
 * request message (the proto field names in camelCase, binary as base64 strings, the same values),
 * and answers in the same shape: a reply is `{ status: 200, body }`, a refused call is the SPEC 10.4
 * error object rebuilt from the gRPC status (the status message is the `code`, `detail` is the
 * `avp-error-detail` trailer), with the HTTP status the code implies and the raw gRPC status code in
 * `grpcCode`. `text` is `JSON.stringify(body)` on gRPC, so the zero-knowledge scan sees every answer.
 *
 * `grpc://host:port` is plaintext HTTP/2, `grpcs://host:port` TLS. The gRPC libraries are imported on
 * first use, so the HTTP/JSON profile runs without them.
 *
 * SPDX-License-Identifier: MIT
 */

import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export interface Resp {
  status: number;
  body: any;
  text: string;
  /** The gRPC status code of a refused call (gRPC profile only). */
  grpcCode?: number;
}

export interface Transport {
  profile: "http-json" | "grpc";
  /** One client operation by its HTTP/JSON method and path. */
  req(method: string, path: string, body?: unknown, token?: string): Promise<Resp>;
  /** Discovery: `GET /.well-known/avp`, or `GetHostInfo` (SPEC 11.7, 10.3). */
  discovery(): Promise<Resp>;
  close(): void;
}

/** The HTTP/JSON status of each SPEC 10.4 code. */
export const AVP_STATUS: Record<string, number> = {
  bad_request: 400,
  unauthorized: 401,
  forbidden: 403,
  policy_denied: 403,
  not_hosted: 403,
  not_found: 404,
  duplicate_repo: 409,
  too_many_heads: 409,
  manifest_conflict: 409,
  too_large: 413,
  missing_parents: 422,
  quota_exceeded: 429,
};

/** The gRPC status code of each SPEC 10.4 code (SPEC 10.3). */
export const GRPC_CODE: Record<string, number> = {
  bad_request: 3, // INVALID_ARGUMENT
  unauthorized: 16, // UNAUTHENTICATED
  forbidden: 7, // PERMISSION_DENIED
  policy_denied: 7,
  not_hosted: 7,
  not_found: 5, // NOT_FOUND
  duplicate_repo: 6, // ALREADY_EXISTS
  too_many_heads: 9, // FAILED_PRECONDITION
  manifest_conflict: 9,
  missing_parents: 9,
  quota_exceeded: 8, // RESOURCE_EXHAUSTED
  too_large: 8,
};

/** The HTTP status a gRPC status code stands for when its message is not a SPEC 10.4 code. */
function fromGrpc(code: number): number {
  switch (code) {
    case 3:
      return 400;
    case 16:
      return 401;
    case 7:
      return 403;
    case 5:
      return 404;
    case 6:
    case 9:
      return 409;
    case 8:
      return 429;
    case 14:
      return 503;
    default:
      return 500;
  }
}

/** Today's HTTP/JSON request: the body as JSON (or as given when it is a string), the bearer token. */
export function httpTransport(base: string, timeoutMs: number): Transport {
  const root = base.replace(/\/$/, "");
  const req = async (method: string, path: string, body?: unknown, token?: string): Promise<Resp> => {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (token !== undefined) headers.Authorization = `Bearer ${token}`;
    const res = await fetch(`${root}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
      // A host that never answers fails the run (the abort throws) instead of hanging it.
      signal: AbortSignal.timeout(timeoutMs),
    });
    const text = await res.text();
    let parsed: any = undefined;
    try {
      parsed = text ? JSON.parse(text) : undefined;
    } catch {
      parsed = undefined;
    }
    return { status: res.status, body: parsed, text };
  };
  return {
    profile: "http-json",
    req,
    discovery: () => req("GET", "/.well-known/avp"),
    close: () => {},
  };
}

/** An RPC and its request message for one HTTP/JSON client path, or why there is none. */
function rpcFor(method: string, path: string, body: unknown): { rpc: string; message: Record<string, unknown> } {
  if (typeof body === "string") throw new Error(`no gRPC form: ${method} ${path} with a non-JSON body`);
  const message = (body ?? {}) as Record<string, unknown>;
  if (method === "GET" && path === "/.well-known/avp") return { rpc: "GetHostInfo", message: {} };
  if (method !== "POST") throw new Error(`no gRPC form: ${method} ${path}`);
  switch (path) {
    case "/api/auth/keypair/challenge":
      return { rpc: "Challenge", message };
    case "/api/auth/keypair/token":
      return { rpc: "Token", message };
    case "/v1/repos":
      return { rpc: "CreateRepo", message };
    case "/v1/prepare-join":
      return { rpc: "PrepareJoin", message };
  }
  const m = /^\/v1\/repos\/([^/]+)\/(pull|push|manifest|leave)$/.exec(path);
  if (!m) throw new Error(`no gRPC form: ${method} ${path}`);
  const repoId = decodeURIComponent(m[1]);
  switch (m[2]) {
    case "pull":
      // gRPC-only addressing field: the HTTP path segment (SPEC 10.3).
      return { rpc: "Pull", message: { ...message, repoId } };
    case "push":
      return { rpc: "Push", message };
    case "manifest":
      return { rpc: "PublishManifest", message };
    default:
      return { rpc: "Leave", message };
  }
}

/** Drops `null` (absent) message fields, as an HTTP/JSON body leaves them out. */
function dropNulls(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(dropNulls);
  if (v === null || typeof v !== "object") return v;
  const out: Record<string, unknown> = {};
  for (const [k, x] of Object.entries(v)) if (x !== null) out[k] = dropNulls(x);
  return out;
}

/**
 * The gRPC profile against `target` (`grpc://host:port` or `grpcs://host:port`), with the proto
 * loaded from proto/avp.proto at runtime.
 */
export async function grpcTransport(target: string, timeoutMs: number): Promise<Transport> {
  const grpc = await import("@grpc/grpc-js");
  const loader = await import("@grpc/proto-loader");
  const m = /^(grpcs?):\/\/([^/]+)\/?$/.exec(target);
  if (!m) throw new Error(`a gRPC target is grpc://host:port or grpcs://host:port, got ${target}`);
  const credentials = m[1] === "grpcs" ? grpc.credentials.createSsl() : grpc.credentials.createInsecure();
  const here = dirname(fileURLToPath(import.meta.url));
  const definition = loader.loadSync(join(here, "..", "proto", "avp.proto"), {
    keepCase: false,
    longs: Number,
    defaults: true,
    arrays: true,
    oneofs: true,
  });
  const pkg = grpc.loadPackageDefinition(definition) as any;
  const client = new pkg.avp.Vault(m[2], credentials);

  const call = (rpc: string, message: Record<string, unknown>, token?: string): Promise<Resp> =>
    new Promise((resolve) => {
      const metadata = new grpc.Metadata();
      if (token !== undefined) metadata.set("authorization", `Bearer ${token}`);
      client[rpc](message, metadata, { deadline: Date.now() + timeoutMs }, (err: any, reply: unknown) => {
        if (!err) {
          const body = dropNulls(reply);
          resolve({ status: 200, body, text: JSON.stringify(body) });
          return;
        }
        const code: string = typeof err.details === "string" ? err.details : "";
        const detailValue = err.metadata?.get?.("avp-error-detail")?.[0];
        const body: Record<string, unknown> = { error: code, code };
        if (detailValue !== undefined) body.detail = String(detailValue);
        resolve({ status: AVP_STATUS[code] ?? fromGrpc(err.code), body, text: JSON.stringify(body), grpcCode: err.code });
      });
    });

  return {
    profile: "grpc",
    req: async (method, path, body, token) => {
      const { rpc, message } = rpcFor(method, path, body);
      return call(rpc, message, token);
    },
    discovery: () => call("GetHostInfo", {}),
    close: () => client.close(),
  };
}

/** The `--profile` flag: `http-json` (default) or `grpc`. */
export function profileFlag(argv: string[]): "http-json" | "grpc" {
  const i = argv.indexOf("--profile");
  const value = i === -1 ? "http-json" : argv[i + 1];
  if (value !== "http-json" && value !== "grpc") throw new Error(`--profile must be http-json or grpc, got ${value}`);
  return value;
}
