#!/usr/bin/env bash
# Start one to three AVP reference hosts on loopback, run a command against them, then stop them.
#
#   bash harness/run-hosts.sh KIND [KIND [KIND]] -- COMMAND [ARG...]
#
# KIND is `rust` or `java`. Hosts A, B and C listen on http://127.0.0.1:19201, :19202 and :19203 with
# AVP_BIND=127.0.0.1, AVP_TEST_CONTROL=1, a fixed distinct AVP_HOST_SEED each, and AVP_PEERS naming every
# other host, which is the setup multihost.ts expects (A and B peer with each other, C with both). The
# script builds the host kinds it needs, starts them, polls GET /.well-known/avp on each (up to 30 s),
# checks that each startup line says it listens on its 127.0.0.1 address, and then runs COMMAND from the
# repository root with AVP_SERVER_URL set to host A and, when present, AVP_SERVER_URL_B and
# AVP_SERVER_URL_C set to hosts B and C. It stops every host on exit and exits with COMMAND's status.
#
# Every `rust` host also serves the gRPC client profile (SPEC 10.3) with AVP_GRPC_PORT 19211, 19212 or
# 19213 (A, B, C). curl cannot call GetHostInfo, so for a rust host the script also waits for the
# startup line `grpc on 127.0.0.1:<port>` and exports AVP_GRPC_URL, AVP_GRPC_URL_B and AVP_GRPC_URL_C
# (grpc://127.0.0.1:1921N) for the rust hosts only. The java host serves HTTP/JSON only.
#
# Environment: AVP_HOSTS_LOG_DIR (where host logs go; default a new temporary directory), JAVA_HOME (the
# JDK to build and run the Java host with; default `javac` and `java` on PATH), CARGO_TARGET_DIR (honored
# when locating the Rust host binary). Host logs are printed when a host fails to start or COMMAND fails.
#
# Run from any directory; the script locates the repository from its own path. It needs bash, curl, bun,
# and the toolchain of each host kind requested.

set -euo pipefail

usage() {
  echo "usage: bash harness/run-hosts.sh KIND [KIND [KIND]] -- COMMAND [ARG...]   (KIND: rust | java)" >&2
  exit 2
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMES=(A B C)
PORTS=(19201 19202 19203)
GRPC_PORTS=(19211 19212 19213)
SEEDS=(
  a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1
  b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
  c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3
)
POLL_TRIES=150 # 150 x 0.2 s = 30 s

kinds=()
while [ $# -gt 0 ] && [ "$1" != "--" ]; do
  case "$1" in
    rust | java) kinds+=("$1") ;;
    *) usage ;;
  esac
  shift
done
[ $# -gt 0 ] || usage
shift
[ $# -gt 0 ] || usage
[ ${#kinds[@]} -ge 1 ] && [ ${#kinds[@]} -le 3 ] || usage
count=${#kinds[@]}

JAVAC=javac
JAVA=java
if [ -n "${JAVA_HOME:-}" ]; then
  JAVAC="$JAVA_HOME/bin/javac"
  JAVA="$JAVA_HOME/bin/java"
fi
LOG_DIR="${AVP_HOSTS_LOG_DIR:-$(mktemp -d)}"
mkdir -p "$LOG_DIR"

# Build first, then start the binaries, so a cold build never eats into the startup poll.
rust_exe=""
java_build="$ROOT/examples/java/server/build"
for kind in $(printf '%s\n' "${kinds[@]}" | sort -u); do
  case "$kind" in
    rust)
      echo "building the rust host"
      cargo build --quiet --manifest-path "$ROOT/examples/rust/server/Cargo.toml"
      rust_exe="${CARGO_TARGET_DIR:-$ROOT/examples/rust/server/target}/debug/avp-reference-server"
      [ -f "$rust_exe.exe" ] && rust_exe="$rust_exe.exe"
      [ -f "$rust_exe" ] || { echo "rust host binary not found at $rust_exe" >&2; exit 1; }
      ;;
    java)
      echo "building the java host"
      (cd "$ROOT/examples/java/server" && "$JAVAC" -d build ../avp/*.java *.java)
      ;;
  esac
done

# Each host's public key, derived from its seed with the harness's vector-tested crypto.
keys=($(cd "$ROOT/harness" && AVP_SEEDS="${SEEDS[*]:0:count}" bun -e '
import { ed25519PublicRaw, importEd25519Private } from "./crypto.ts";
for (const seed of (process.env.AVP_SEEDS ?? "").split(" ")) {
  console.log(ed25519PublicRaw(importEd25519Private(Buffer.from(seed, "hex"))).toString("base64"));
}'))
[ ${#keys[@]} -eq "$count" ] || { echo "could not derive the host keys" >&2; exit 1; }

pids=()
dump_logs() {
  for i in $(seq 0 $((count - 1))); do
    local log="$LOG_DIR/host-${NAMES[$i]}.log"
    [ -f "$log" ] || continue
    echo "----- host ${NAMES[$i]} (${kinds[$i]}) log: $log"
    cat "$log"
  done
}
stop_hosts() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
}
trap stop_hosts EXIT

for i in $(seq 0 $((count - 1))); do
  peers=""
  for j in $(seq 0 $((count - 1))); do
    [ "$i" -eq "$j" ] && continue
    peers="${peers:+$peers,}${keys[$j]}@http://127.0.0.1:${PORTS[$j]}"
  done
  log="$LOG_DIR/host-${NAMES[$i]}.log"
  case "${kinds[$i]}" in
    rust)
      PORT=${PORTS[$i]} AVP_GRPC_PORT=${GRPC_PORTS[$i]} AVP_BIND=127.0.0.1 AVP_HOST_SEED=${SEEDS[$i]} \
        AVP_PEERS="$peers" AVP_TEST_CONTROL=1 "$rust_exe" >"$log" 2>&1 &
      ;;
    java)
      PORT=${PORTS[$i]} AVP_BIND=127.0.0.1 AVP_HOST_SEED=${SEEDS[$i]} AVP_PEERS="$peers" AVP_TEST_CONTROL=1 \
        "$JAVA" -cp "$java_build" Server >"$log" 2>&1 &
      ;;
  esac
  pids+=($!)
done

# Wait until each host serves discovery and has logged that it listens on its loopback address.
for i in $(seq 0 $((count - 1))); do
  url="http://127.0.0.1:${PORTS[$i]}"
  log="$LOG_DIR/host-${NAMES[$i]}.log"
  ready=""
  for _ in $(seq 1 "$POLL_TRIES"); do
    if ! kill -0 "${pids[$i]}" 2>/dev/null; then
      echo "host ${NAMES[$i]} (${kinds[$i]}) exited during startup" >&2
      dump_logs >&2
      exit 1
    fi
    if curl -fsS "$url/.well-known/avp" >/dev/null 2>&1 && grep -qF "listening on $url," "$log"; then
      # A rust host also logs its gRPC listener once it is bound.
      if [ "${kinds[$i]}" != rust ] || grep -qF "grpc on 127.0.0.1:${GRPC_PORTS[$i]}" "$log"; then
        ready=1
        break
      fi
    fi
    sleep 0.2
  done
  if [ -z "$ready" ]; then
    echo "host ${NAMES[$i]} (${kinds[$i]}) did not serve $url/.well-known/avp and log 'listening on $url' (rust: and 'grpc on 127.0.0.1:${GRPC_PORTS[$i]}') within 30 s" >&2
    dump_logs >&2
    exit 1
  fi
  echo "host ${NAMES[$i]} (${kinds[$i]}): $(grep -F "listening on $url," "$log")"
  if [ "${kinds[$i]}" = rust ]; then
    echo "host ${NAMES[$i]} (${kinds[$i]}): $(grep -F "grpc on 127.0.0.1:${GRPC_PORTS[$i]}" "$log")"
  fi
done

export AVP_SERVER_URL="http://127.0.0.1:${PORTS[0]}"
unset AVP_SERVER_URL_B AVP_SERVER_URL_C
[ "$count" -ge 2 ] && export AVP_SERVER_URL_B="http://127.0.0.1:${PORTS[1]}"
[ "$count" -ge 3 ] && export AVP_SERVER_URL_C="http://127.0.0.1:${PORTS[2]}"
# gRPC targets for the rust hosts only; a java host serves HTTP/JSON only.
unset AVP_GRPC_URL AVP_GRPC_URL_B AVP_GRPC_URL_C
GRPC_VARS=(AVP_GRPC_URL AVP_GRPC_URL_B AVP_GRPC_URL_C)
for i in $(seq 0 $((count - 1))); do
  if [ "${kinds[$i]}" = rust ]; then
    export "${GRPC_VARS[$i]}=grpc://127.0.0.1:${GRPC_PORTS[$i]}"
  fi
done

status=0
(cd "$ROOT" && "$@") || status=$?
if [ "$status" -ne 0 ]; then
  echo "command exited with status $status" >&2
  dump_logs >&2
fi
exit "$status"
