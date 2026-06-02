/*
 * Micro reference server for the Alt Vault Protocol (AVP), HTTP/JSON profile.
 *
 * It implements the whole wire contract against an in-memory store so an implementer can point a client
 * at something real. It is intentionally tiny and NOT production code: state lives in memory and is lost
 * on restart, there is no TLS, and the bearer token is an opaque random string mapped to a member id in
 * this same process (a real deployment mints a JWT verifiable via JWKS, as the spec describes). What it
 * does honour is the part that matters: it is zero-knowledge. It stores only the manifest, the encrypted
 * envelope, the per-member wrapped keys, public keys, and counters that clients send, and decrypts
 * nothing. Field shapes follow ../../schema/avp.schema.json.
 *
 * Single file, no dependencies: com.sun.net.httpserver.HttpServer plus the JDK's built-in Ed25519
 * (java.security) and a tiny hand-rolled JSON parser/serializer.
 *
 * Run on JDK 17+ with the single-file source launcher:
 *
 *     java Server.java          # listens on http://localhost:8787 (set PORT to change)
 *
 * SPDX-License-Identifier: MIT
 */

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Micro reference server for the Alt Vault Protocol (AVP), HTTP/JSON profile.
 *
 * <p>This class implements the entire wire contract against an in-memory store so that an implementer
 * can point a client at something real. It is intentionally tiny and is <strong>not</strong> production
 * code: all state lives in memory and is lost on restart, there is no TLS, and the bearer token is an
 * opaque random string mapped to a member id within this same process (a real deployment mints a JWT
 * verifiable via JWKS, as the spec describes).
 *
 * <p>What it does honour is the part that matters: it is zero-knowledge. It stores only the manifest, the
 * encrypted envelope, the per-member wrapped keys, public keys, and the version/epoch counters that
 * clients send, and it decrypts nothing. The only cryptography it performs is verifying the Ed25519
 * challenge signature over the raw nonce bytes. Field shapes follow {@code ../../schema/avp.schema.json}.
 *
 * <p>The implementation is a single file with no dependencies: it uses
 * {@link com.sun.net.httpserver.HttpServer} plus the JDK's built-in Ed25519 provider ({@code java.security})
 * and a tiny hand-rolled JSON parser/serializer.
 *
 * <p>Run on JDK 17+ with the single-file source launcher:
 *
 * <pre>{@code
 *     java Server.java          // listens on http://localhost:8787 (set PORT to change)
 * }</pre>
 */
public final class Server {

    // ─── In-memory state ────────────────────────────────────────────────────
    //
    // A repo holds exactly what clients send and nothing the server can decrypt: the manifest (public
    // metadata + per-member wrapped keys + public keys), and the current encrypted envelope.

    /** repoId -> stored repo (manifest + current envelope). */
    private final Map<String, StoredRepo> repos = new ConcurrentHashMap<>();
    /** nonce (base64) -> challenge (the pubkey it was issued for + its expiry). Single-use. */
    private final Map<String, Challenge> nonces = new ConcurrentHashMap<>();
    /** opaque bearer token -> member id (the base64 Ed25519 public key). */
    private final Map<String, String> tokens = new ConcurrentHashMap<>();

    /** How long an issued challenge nonce remains redeemable before it expires. */
    private static final long NONCE_TTL_MS = 2 * 60 * 1000L;
    /** How long a minted bearer token remains valid (advisory; this server never garbage-collects). */
    private static final long TOKEN_TTL_MS = 60 * 60 * 1000L;

    private final SecureRandom random = new SecureRandom();
    private final Base64.Encoder b64 = Base64.getEncoder();          // standard alphabet, padded
    private final Base64.Encoder b64url = Base64.getUrlEncoder().withoutPadding();
    private final Base64.Decoder b64decode = Base64.getDecoder();

    /**
     * The server-side state for a single repo: the manifest plus its current encrypted envelope.
     *
     * <p>The manifest is held as the parsed JSON object exactly as the client sent it. The server mutates
     * only the version/epoch counters and the member roster; it never touches any wrapped-key or
     * ciphertext bytes.
     */
    private static final class StoredRepo {
        /** The repo manifest: public metadata, the member roster, and the version/epoch counters. */
        Map<String, Object> manifest;
        /** The current encrypted envelope (opaque ciphertext the server never decrypts). */
        Object envelope;

        /**
         * Creates a stored repo.
         *
         * @param manifest the repo manifest as parsed from the client request
         * @param envelope the initial encrypted envelope, or {@code null} if none was supplied
         */
        StoredRepo(Map<String, Object> manifest, Object envelope) {
            this.manifest = manifest;
            this.envelope = envelope;
        }
    }

    /**
     * A single-use authentication challenge, bound to the public key it was issued for.
     *
     * @param publicKey the base64 Ed25519 public key the challenge was issued for
     * @param expiresAt the wall-clock time (epoch millis) after which the nonce is no longer redeemable
     */
    private record Challenge(String publicKey, long expiresAt) {}

    // ─── Crypto: verify an Ed25519 signature over raw bytes (SPEC section 3) ──

    /**
     * Wraps a raw 32-byte Ed25519 public key into a {@link PublicKey} the JDK provider can use.
     *
     * <p>The JDK's {@code KeyFactory} expects an X.509 {@code SubjectPublicKeyInfo} (SPKI) encoding, so
     * this prepends the fixed Ed25519 SPKI header to the raw key bytes before decoding.
     *
     * @param rawBase64 the raw 32-byte Ed25519 public key, base64-encoded (standard alphabet)
     * @return the corresponding {@link PublicKey}
     * @throws Exception if the input is not valid base64 or the bytes are not a valid Ed25519 key
     */
    private PublicKey ed25519PublicKeyObject(String rawBase64) throws Exception {
        // SubjectPublicKeyInfo prefix for an Ed25519 key, then the raw 32-byte key.
        byte[] prefix = hexToBytes("302a300506032b6570032100");
        byte[] raw = b64decode.decode(rawBase64);
        byte[] der = new byte[prefix.length + raw.length];
        System.arraycopy(prefix, 0, der, 0, prefix.length);
        System.arraycopy(raw, 0, der, prefix.length, raw.length);
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
    }

    /**
     * Verifies an Ed25519 signature over the given message bytes.
     *
     * <p>Any failure (malformed key, malformed signature, or a signature that does not match) is reported
     * as a plain {@code false} rather than an exception, so callers can treat verification as a simple
     * predicate.
     *
     * @param publicKeyBase64 the signer's raw Ed25519 public key, base64-encoded
     * @param message the exact message bytes that were signed
     * @param signatureBase64 the candidate signature, base64-encoded
     * @return {@code true} if the signature is valid for the message and key, {@code false} otherwise
     */
    private boolean verifyEd25519(String publicKeyBase64, byte[] message, String signatureBase64) {
        try {
            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(ed25519PublicKeyObject(publicKeyBase64));
            sig.update(message);
            return sig.verify(b64decode.decode(signatureBase64));
        } catch (Exception e) {
            return false;
        }
    }

    // ─── Request handling ────────────────────────────────────────────────────

    /**
     * Dispatches a single HTTP request to the matching AVP operation and writes the response.
     *
     * <p>The two {@code /api/auth/keypair/*} endpoints are unauthenticated and implement the challenge ->
     * token flow. Every other route requires a valid bearer token; the caller's member id is resolved
     * from it and, for repo-scoped routes, checked for membership before the operation runs. Routing is
     * performed against the <em>raw</em> request path because base64 member ids contain {@code + / =},
     * which must survive into the path segment for this server to decode them itself.
     *
     * @param ex the HTTP exchange to read the request from and write the response to
     * @throws IOException if reading the request body fails
     */
    private void route(HttpExchange ex) throws IOException {
        String method = ex.getRequestMethod();
        // Route on the RAW path: getPath() would percent-decode for us, but base64 member ids contain
        // '+' '/' '=' which must survive into the segment so we can decode them ourselves (matching
        // decodeURIComponent semantics — not URLDecoder, which turns '+' into a space).
        String path = ex.getRequestURI().getRawPath();

        // ── Auth: challenge -> token ──
        if (method.equals("POST") && path.equals("/api/auth/keypair/challenge")) {
            Map<String, Object> body = readJsonObject(ex);
            byte[] raw = new byte[32];
            random.nextBytes(raw);
            String nonce = b64.encodeToString(raw);
            nonces.put(nonce, new Challenge(str(body.get("ed25519PublicKey")), now() + NONCE_TTL_MS));
            send(ex, 200, Map.of("nonce", nonce));
            return;
        }

        if (method.equals("POST") && path.equals("/api/auth/keypair/token")) {
            Map<String, Object> body = readJsonObject(ex);
            String nonce = str(body.get("nonce"));
            String pub = str(body.get("ed25519PublicKey"));
            String signature = str(body.get("signature"));
            Challenge challenge = nonces.remove(nonce); // single-use
            if (challenge == null || !challenge.publicKey().equals(pub) || challenge.expiresAt() < now()) {
                send(ex, 401, Map.of("error", "invalid or expired nonce"));
                return;
            }
            if (!verifyEd25519(pub, b64decode.decode(nonce), signature)) {
                send(ex, 401, Map.of("error", "bad signature"));
                return;
            }
            byte[] tokenBytes = new byte[32];
            random.nextBytes(tokenBytes);
            String token = b64url.encodeToString(tokenBytes);
            tokens.put(token, pub);
            send(ex, 200, orderedMap("token", token, "expiresAt", now() + TOKEN_TTL_MS));
            return;
        }

        // ── Everything below requires a bearer token ──
        String caller = callerId(ex);
        if (caller == null) {
            send(ex, 401, Map.of("error", "missing or unknown bearer token"));
            return;
        }

        // createRepo
        if (method.equals("POST") && path.equals("/v1/repos")) {
            Map<String, Object> body = readJsonObject(ex);
            @SuppressWarnings("unchecked")
            Map<String, Object> manifest = (Map<String, Object>) body.get("manifest");
            List<Object> members = membersOf(manifest);
            if (members.size() != 1 || !caller.equals(memberId(members.get(0)))) {
                send(ex, 403, Map.of("error", "creator must be the sole member"));
                return;
            }
            String repoId = str(manifest.get("repoId"));
            if (repos.containsKey(repoId)) {
                send(ex, 409, Map.of("error", "repo already exists"));
                return;
            }
            repos.put(repoId, new StoredRepo(manifest, body.get("initialEnvelope")));
            send(ex, 200, manifest);
            return;
        }

        // routes under /v1/repos/{repoId}/...
        Matcher opMatch = OP_PATH.matcher(path);
        Matcher memberMatch = MEMBER_PATH.matcher(path);
        String repoIdRaw = null;
        String op = null;
        String memberIdRaw = null;
        if (opMatch.matches()) {
            repoIdRaw = opMatch.group(1);
            op = opMatch.group(2);
        } else if (memberMatch.matches()) {
            repoIdRaw = memberMatch.group(1);
            memberIdRaw = memberMatch.group(2);
        }
        if (repoIdRaw == null) {
            send(ex, 404, Map.of("error", "no such route"));
            return;
        }
        String repoId = urlDecode(repoIdRaw);
        StoredRepo stored = repos.get(repoId);
        if (stored == null) {
            send(ex, 404, Map.of("error", "repo not found"));
            return;
        }
        if (!isMember(stored.manifest, caller)) {
            send(ex, 403, Map.of("error", "caller is not a member"));
            return;
        }

        if (method.equals("POST") && "pull".equals(op)) {
            Map<String, Object> body = readJsonObject(ex);
            long current = asLong(stored.manifest.get("payloadVersion"));
            if (asLong(body.get("knownPayloadVersion")) == current) {
                send(ex, 200, orderedMap("manifest", stored.manifest, "envelope", null, "unchanged", true));
            } else {
                send(ex, 200, orderedMap("manifest", stored.manifest, "envelope", stored.envelope, "unchanged", false));
            }
            return;
        }

        if (method.equals("POST") && "push".equals(op)) {
            Map<String, Object> body = readJsonObject(ex);
            long current = asLong(stored.manifest.get("payloadVersion"));
            if (asLong(body.get("expectedPayloadVersion")) != current) {
                send(ex, 200, orderedMap(
                        "accepted", false,
                        "conflict", true,
                        "payloadVersion", current,
                        "keyEpoch", asLong(stored.manifest.get("keyEpoch"))));
                return;
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> envelope = (Map<String, Object>) body.get("envelope");
            stored.envelope = envelope;
            stored.manifest.put("payloadVersion", asLong(envelope.get("payloadVersion")));
            stored.manifest.put("keyEpoch", asLong(envelope.get("keyEpoch")));
            Object rotated = body.get("rotatedMembers");
            if (rotated instanceof List) {
                stored.manifest.put("members", rotated);
            }
            send(ex, 200, orderedMap(
                    "accepted", true,
                    "conflict", false,
                    "payloadVersion", asLong(stored.manifest.get("payloadVersion")),
                    "keyEpoch", asLong(stored.manifest.get("keyEpoch"))));
            return;
        }

        if (method.equals("POST") && "add-member".equals(op)) {
            Map<String, Object> body = readJsonObject(ex);
            Object member = body.get("member");
            if (!isMember(stored.manifest, memberId(member))) {
                membersOf(stored.manifest).add(member);
            }
            send(ex, 200, stored.manifest);
            return;
        }

        if (method.equals("POST") && "remove-member".equals(op)) {
            Map<String, Object> body = readJsonObject(ex);
            @SuppressWarnings("unchecked")
            Map<String, Object> rotatedEnvelope = (Map<String, Object>) body.get("rotatedEnvelope");
            stored.manifest.put("members", body.get("rewrappedMembers"));
            stored.envelope = rotatedEnvelope;
            stored.manifest.put("keyEpoch", asLong(body.get("newKeyEpoch")));
            stored.manifest.put("payloadVersion", asLong(rotatedEnvelope.get("payloadVersion")));
            send(ex, 200, stored.manifest);
            return;
        }

        if (method.equals("GET") && memberIdRaw != null) {
            String wanted = urlDecode(memberIdRaw);
            for (Object m : membersOf(stored.manifest)) {
                if (wanted.equals(memberId(m))) {
                    send(ex, 200, m);
                    return;
                }
            }
            send(ex, 404, Map.of("error", "member not found"));
            return;
        }

        send(ex, 404, Map.of("error", "no such route"));
    }

    /** Matches a repo operation route, capturing the repo id (group 1) and the operation name (group 2). */
    private static final Pattern OP_PATH =
            Pattern.compile("^/v1/repos/([^/]+)/(pull|push|add-member|remove-member)$");
    /** Matches a single-member fetch route, capturing the repo id (group 1) and the member id (group 2). */
    private static final Pattern MEMBER_PATH =
            Pattern.compile("^/v1/repos/([^/]+)/member/([^/]+)$");

    /**
     * Resolves the caller's member id from the request's {@code Authorization: Bearer} header.
     *
     * @param ex the HTTP exchange whose request headers are inspected
     * @return the caller's member id (base64 Ed25519 public key), or {@code null} if the header is absent,
     *     malformed, or carries an unknown token
     */
    private String callerId(HttpExchange ex) {
        String header = ex.getRequestHeaders().getFirst("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            return null;
        }
        return tokens.get(header.substring("Bearer ".length()));
    }

    /**
     * Tests whether the given member id appears in a manifest's roster.
     *
     * @param manifest the repo manifest to inspect
     * @param memberId the candidate member id (base64 Ed25519 public key)
     * @return {@code true} if a member with that id is on the roster, {@code false} otherwise
     */
    private boolean isMember(Map<String, Object> manifest, String memberId) {
        for (Object m : membersOf(manifest)) {
            if (memberId.equals(memberId(m))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns the live member roster of a manifest.
     *
     * <p>The returned list is the manifest's own backing list, so mutating it (for example to add a
     * member) updates the manifest in place.
     *
     * @param manifest the repo manifest
     * @return the list of member entries
     */
    @SuppressWarnings("unchecked")
    private static List<Object> membersOf(Map<String, Object> manifest) {
        return (List<Object>) manifest.get("members");
    }

    /**
     * Extracts the member id (its base64 Ed25519 public key) from a member entry.
     *
     * @param member a member entry object (a JSON object as parsed into a map)
     * @return the member's {@code ed25519PublicKey} value
     */
    @SuppressWarnings("unchecked")
    private static String memberId(Object member) {
        return str(((Map<String, Object>) member).get("ed25519PublicKey"));
    }

    /** Drops all repos, nonces, and tokens. Exposed package-private so tests can start from a clean slate. */
    void resetState() {
        repos.clear();
        nonces.clear();
        tokens.clear();
    }

    /**
     * Creates and starts the HTTP server on the given port.
     *
     * <p>A single catch-all context routes every request through {@link #route(HttpExchange)}; any
     * exception escaping a handler is turned into a {@code 400} JSON error response so a buggy request can
     * never wedge the server.
     *
     * @param port the TCP port to bind, or {@code 0} to let the OS pick an ephemeral free port
     * @return the started {@link HttpServer} (its bound address reveals the actual port)
     * @throws IOException if the server cannot bind the requested port
     */
    HttpServer start(int port) throws IOException {
        HttpServer http = HttpServer.create(new InetSocketAddress(port), 0);
        http.createContext("/", ex -> {
            try (ex) {
                route(ex);
            } catch (Exception e) {
                send(ex, 400, orderedMap("error", "bad request", "detail", String.valueOf(e)));
            }
        });
        http.start();
        return http;
    }

    /**
     * Program entry point: starts the reference server and blocks (the HTTP server runs its own threads).
     *
     * <p>The listen port defaults to {@code 8787} and can be overridden with the {@code PORT} environment
     * variable.
     *
     * @param args ignored
     * @throws IOException if the server cannot bind its port
     */
    public static void main(String[] args) throws IOException {
        int port = 8787;
        String env = System.getenv("PORT");
        if (env != null && !env.isBlank()) {
            port = Integer.parseInt(env.trim());
        }
        new Server().start(port);
        System.out.println("AVP reference server (in-memory) listening on http://localhost:" + port);
    }

    // ─── HTTP helpers ─────────────────────────────────────────────────────────

    /**
     * Serializes {@code body} to JSON and writes it as the response with the given status code.
     *
     * <p>If the client has already disconnected the write is silently dropped; a reference server has
     * nothing useful to do about a half-closed connection.
     *
     * @param ex the HTTP exchange to respond on
     * @param status the HTTP status code to send
     * @param body the response body, serialized via {@link Json#write(Object)}
     */
    private static void send(HttpExchange ex, int status, Object body) {
        try {
            byte[] bytes = Json.write(body).getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(status, bytes.length);
            ex.getResponseBody().write(bytes);
        } catch (IOException e) {
            // The client went away mid-response; nothing useful to do in a reference server.
        }
    }

    /**
     * Reads the request body and parses it as a JSON object.
     *
     * <p>An empty body, or a body whose top-level JSON value is not an object, yields an empty map rather
     * than an error, which keeps the route handlers simple.
     *
     * @param ex the HTTP exchange whose request body is read
     * @return the parsed object as a map (empty if the body is blank or not an object)
     * @throws IOException if reading the request body fails
     */
    private static Map<String, Object> readJsonObject(HttpExchange ex) throws IOException {
        String raw = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        if (raw.isBlank()) {
            return new LinkedHashMap<>();
        }
        Object parsed = Json.parse(raw);
        if (parsed instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> m = (Map<String, Object>) parsed;
            return m;
        }
        return new LinkedHashMap<>();
    }

    /**
     * Percent-decodes a single URI path segment with {@code decodeUriComponent} semantics: only
     * {@code %XX} escapes are decoded, and a literal {@code '+'} stays a {@code '+'} (it is NOT a space).
     * This matters because base64 member ids contain {@code + / =}, so {@link URLDecoder} (form decoding)
     * would corrupt them by turning {@code '+'} into a space.
     */
    private static String urlDecode(String s) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '%' && i + 2 < s.length()) {
                out.write(Integer.parseInt(s.substring(i + 1, i + 3), 16));
                i += 2;
            } else {
                out.write(c);
            }
        }
        return out.toString(StandardCharsets.UTF_8);
    }

    /**
     * Returns the current wall-clock time.
     *
     * @return the current time in epoch milliseconds
     */
    private static long now() {
        return System.currentTimeMillis();
    }

    /**
     * Coerces an arbitrary value to its string form, preserving {@code null}.
     *
     * @param o the value to stringify, possibly {@code null}
     * @return {@code null} if {@code o} is {@code null}, otherwise {@code String.valueOf(o)}
     */
    private static String str(Object o) {
        return o == null ? null : String.valueOf(o);
    }

    /**
     * Coerces a parsed JSON value to a {@code long}.
     *
     * <p>The spec's counters are int64, but a value may arrive as a {@link Number} (from JSON parsing) or
     * as a numeric {@link String}; both are accepted.
     *
     * @param o the value to interpret, expected to be a {@link Number} or numeric {@link String}
     * @return the value as a {@code long}
     * @throws IllegalArgumentException if {@code o} is neither a number nor a numeric string
     * @throws NumberFormatException if {@code o} is a string that does not parse as a {@code long}
     */
    private static long asLong(Object o) {
        if (o instanceof Number n) {
            return n.longValue();
        }
        if (o instanceof String s) {
            return Long.parseLong(s);
        }
        throw new IllegalArgumentException("expected a number, got " + o);
    }

    /**
     * Builds an insertion-ordered map from alternating key/value arguments.
     *
     * <p>Using a {@link LinkedHashMap} keeps JSON fields serialized in a stable, readable order.
     *
     * @param kv alternating {@code String} keys and arbitrary values ({@code key0, value0, key1, value1, ...})
     * @return a {@link LinkedHashMap} populated in argument order
     */
    private static Map<String, Object> orderedMap(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            m.put((String) kv[i], kv[i + 1]);
        }
        return m;
    }

    /**
     * Decodes a hexadecimal string into its raw bytes.
     *
     * @param hex an even-length string of hexadecimal digits
     * @return the decoded bytes (half as many bytes as input characters)
     */
    private static byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    // ─── Minimal JSON (no dependencies) ───────────────────────────────────────
    //
    // Just enough JSON to move the contract's message shapes over the wire: objects become LinkedHashMap,
    // arrays become ArrayList, numbers that are integral become Long (the spec's counters are int64),
    // others Double. This is a reference server, not a JSON library.

    static final class Json {

        /**
         * Parses a JSON document into Java values.
         *
         * <p>Objects become {@link LinkedHashMap}, arrays become {@link ArrayList}, integral numbers
         * become {@link Long} (the spec's counters are int64), non-integral numbers become {@link Double},
         * strings/booleans map to {@link String}/{@link Boolean}, and {@code null} maps to {@code null}.
         *
         * @param text the JSON document to parse
         * @return the parsed value
         * @throws IllegalArgumentException if the text is not well-formed JSON or has trailing content
         */
        static Object parse(String text) {
            Parser p = new Parser(text);
            Object value = p.value();
            p.skipWhitespace();
            if (!p.atEnd()) {
                throw new IllegalArgumentException("trailing content at index " + p.pos);
            }
            return value;
        }

        /**
         * Serializes a Java value to a compact JSON string.
         *
         * @param value the value to serialize ({@link Map}, {@link List}, {@link String}, {@link Number},
         *     {@link Boolean}, or {@code null})
         * @return the JSON text
         * @throws IllegalArgumentException if {@code value} (or a nested value) is of a type this minimal
         *     serializer cannot represent
         */
        static String write(Object value) {
            StringBuilder sb = new StringBuilder();
            writeValue(sb, value);
            return sb.toString();
        }

        /**
         * Appends the JSON form of a single value to {@code sb}, recursing into maps and lists.
         *
         * @param sb the buffer to append to
         * @param value the value to serialize
         * @throws IllegalArgumentException if {@code value} is of an unsupported type
         */
        private static void writeValue(StringBuilder sb, Object value) {
            if (value == null) {
                sb.append("null");
            } else if (value instanceof String s) {
                writeString(sb, s);
            } else if (value instanceof Boolean || value instanceof Long || value instanceof Integer) {
                sb.append(value);
            } else if (value instanceof Double d) {
                // Emit integral doubles without a trailing ".0" so versions/epochs stay clean.
                if (d == Math.floor(d) && !d.isInfinite()) {
                    sb.append(d.longValue());
                } else {
                    sb.append(d);
                }
            } else if (value instanceof Number n) {
                sb.append(n);
            } else if (value instanceof Map<?, ?> map) {
                sb.append('{');
                boolean first = true;
                for (Map.Entry<?, ?> e : map.entrySet()) {
                    if (!first) {
                        sb.append(',');
                    }
                    first = false;
                    writeString(sb, String.valueOf(e.getKey()));
                    sb.append(':');
                    writeValue(sb, e.getValue());
                }
                sb.append('}');
            } else if (value instanceof List<?> list) {
                sb.append('[');
                boolean first = true;
                for (Object item : list) {
                    if (!first) {
                        sb.append(',');
                    }
                    first = false;
                    writeValue(sb, item);
                }
                sb.append(']');
            } else {
                throw new IllegalArgumentException("cannot serialize " + value.getClass());
            }
        }

        /**
         * Appends a JSON string literal (quoted, with the required escapes) to {@code sb}.
         *
         * @param sb the buffer to append to
         * @param s the raw string to encode
         */
        private static void writeString(StringBuilder sb, String s) {
            sb.append('"');
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                switch (c) {
                    case '"' -> sb.append("\\\"");
                    case '\\' -> sb.append("\\\\");
                    case '\n' -> sb.append("\\n");
                    case '\r' -> sb.append("\\r");
                    case '\t' -> sb.append("\\t");
                    case '\b' -> sb.append("\\b");
                    case '\f' -> sb.append("\\f");
                    default -> {
                        if (c < 0x20) {
                            sb.append(String.format("\\u%04x", (int) c));
                        } else {
                            sb.append(c);
                        }
                    }
                }
            }
            sb.append('"');
        }

        /** A single-pass recursive-descent JSON parser over an in-memory string. */
        private static final class Parser {
            /** The full input being parsed. */
            private final String s;
            /** The index of the next character to consume. */
            private int pos;

            /**
             * Creates a parser positioned at the start of the given input.
             *
             * @param s the JSON text to parse
             */
            Parser(String s) {
                this.s = s;
            }

            /**
             * Reports whether the cursor has reached the end of the input.
             *
             * @return {@code true} if no characters remain
             */
            boolean atEnd() {
                return pos >= s.length();
            }

            /** Advances the cursor past any run of JSON whitespace (space, tab, newline, carriage return). */
            void skipWhitespace() {
                while (pos < s.length()) {
                    char c = s.charAt(pos);
                    if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                        pos++;
                    } else {
                        break;
                    }
                }
            }

            /**
             * Parses the next JSON value at the cursor, dispatching on its first character.
             *
             * @return the parsed value
             * @throws IllegalArgumentException if the input ends prematurely or is malformed
             */
            Object value() {
                skipWhitespace();
                if (atEnd()) {
                    throw new IllegalArgumentException("unexpected end of input");
                }
                char c = s.charAt(pos);
                return switch (c) {
                    case '{' -> object();
                    case '[' -> array();
                    case '"' -> string();
                    case 't', 'f' -> bool();
                    case 'n' -> nul();
                    default -> number();
                };
            }

            /**
             * Parses a JSON object, assuming the cursor is at the opening {@code '{'}.
             *
             * @return the object as an insertion-ordered map
             * @throws IllegalArgumentException if the object is malformed or unterminated
             */
            private Map<String, Object> object() {
                expect('{');
                Map<String, Object> map = new LinkedHashMap<>();
                skipWhitespace();
                if (peek() == '}') {
                    pos++;
                    return map;
                }
                while (true) {
                    skipWhitespace();
                    String key = string();
                    skipWhitespace();
                    expect(':');
                    map.put(key, value());
                    skipWhitespace();
                    char c = next();
                    if (c == '}') {
                        return map;
                    }
                    if (c != ',') {
                        throw new IllegalArgumentException("expected ',' or '}' at index " + (pos - 1));
                    }
                }
            }

            /**
             * Parses a JSON array, assuming the cursor is at the opening {@code '['}.
             *
             * @return the array as a list
             * @throws IllegalArgumentException if the array is malformed or unterminated
             */
            private List<Object> array() {
                expect('[');
                List<Object> list = new ArrayList<>();
                skipWhitespace();
                if (peek() == ']') {
                    pos++;
                    return list;
                }
                while (true) {
                    list.add(value());
                    skipWhitespace();
                    char c = next();
                    if (c == ']') {
                        return list;
                    }
                    if (c != ',') {
                        throw new IllegalArgumentException("expected ',' or ']' at index " + (pos - 1));
                    }
                }
            }

            /**
             * Parses a JSON string literal, assuming the cursor is at the opening quote.
             *
             * @return the decoded string with escapes resolved
             * @throws IllegalArgumentException if the string is unterminated or contains a bad escape
             */
            private String string() {
                expect('"');
                StringBuilder sb = new StringBuilder();
                while (true) {
                    char c = next();
                    if (c == '"') {
                        return sb.toString();
                    }
                    if (c == '\\') {
                        char esc = next();
                        switch (esc) {
                            case '"' -> sb.append('"');
                            case '\\' -> sb.append('\\');
                            case '/' -> sb.append('/');
                            case 'n' -> sb.append('\n');
                            case 'r' -> sb.append('\r');
                            case 't' -> sb.append('\t');
                            case 'b' -> sb.append('\b');
                            case 'f' -> sb.append('\f');
                            case 'u' -> {
                                String hex = s.substring(pos, pos + 4);
                                pos += 4;
                                sb.append((char) Integer.parseInt(hex, 16));
                            }
                            default -> throw new IllegalArgumentException("bad escape \\" + esc);
                        }
                    } else {
                        sb.append(c);
                    }
                }
            }

            /**
             * Parses a JSON number, consuming the run of numeric characters at the cursor.
             *
             * @return a {@link Long} for an integral token, otherwise a {@link Double}
             * @throws IllegalArgumentException if no numeric characters are present
             * @throws NumberFormatException if the token is not a valid number
             */
            private Object number() {
                int start = pos;
                while (pos < s.length()) {
                    char c = s.charAt(pos);
                    if ((c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E') {
                        pos++;
                    } else {
                        break;
                    }
                }
                String token = s.substring(start, pos);
                if (token.isEmpty()) {
                    throw new IllegalArgumentException("invalid number at index " + start);
                }
                if (token.indexOf('.') < 0 && token.indexOf('e') < 0 && token.indexOf('E') < 0) {
                    return Long.parseLong(token);
                }
                return Double.parseDouble(token);
            }

            /**
             * Parses a {@code true} or {@code false} literal at the cursor.
             *
             * @return {@link Boolean#TRUE} or {@link Boolean#FALSE}
             * @throws IllegalArgumentException if neither literal is present
             */
            private Boolean bool() {
                if (s.startsWith("true", pos)) {
                    pos += 4;
                    return Boolean.TRUE;
                }
                if (s.startsWith("false", pos)) {
                    pos += 5;
                    return Boolean.FALSE;
                }
                throw new IllegalArgumentException("invalid literal at index " + pos);
            }

            /**
             * Parses a {@code null} literal at the cursor.
             *
             * @return {@code null}
             * @throws IllegalArgumentException if the literal is not {@code null}
             */
            private Object nul() {
                if (s.startsWith("null", pos)) {
                    pos += 4;
                    return null;
                }
                throw new IllegalArgumentException("invalid literal at index " + pos);
            }

            /**
             * Returns the character at the cursor without consuming it.
             *
             * @return the current character
             * @throws IllegalArgumentException if the cursor is at end of input
             */
            private char peek() {
                if (atEnd()) {
                    throw new IllegalArgumentException("unexpected end of input");
                }
                return s.charAt(pos);
            }

            /**
             * Returns the character at the cursor and advances past it.
             *
             * @return the consumed character
             * @throws IllegalArgumentException if the cursor is at end of input
             */
            private char next() {
                if (atEnd()) {
                    throw new IllegalArgumentException("unexpected end of input");
                }
                return s.charAt(pos++);
            }

            /**
             * Consumes the next character, requiring it to equal {@code c}.
             *
             * @param c the character that must appear next
             * @throws IllegalArgumentException if the next character is not {@code c} (or input ended)
             */
            private void expect(char c) {
                char got = next();
                if (got != c) {
                    throw new IllegalArgumentException("expected '" + c + "' but got '" + got + "' at index " + (pos - 1));
                }
            }
        }
    }
}
