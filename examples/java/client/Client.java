/*
 * Micro reference client for the Alt Vault Protocol (AVP), HTTP/JSON profile.
 *
 * It drives the whole wire contract against a running server (the sibling ../server, or any other
 * conformant HTTP/JSON server) so an implementer can see the full lifecycle end to end: generate a real
 * Ed25519 keypair, run the challenge -> sign nonce -> token auth flow, create a repo, pull (known +
 * stale), push (accept + conflict paths), invite a second member, fetch that member's key, and have the
 * second member authenticate and pull. Each step prints a one-line transcript entry.
 *
 * It is intentionally tiny and NOT production code. Crucially, the envelope and wrapped-key crypto is
 * OUT OF SCOPE here: this client carries the alt payload as an opaque placeholder ciphertext and never
 * actually encrypts anything. A real client derives a per-repo data key, AES-256-GCM encrypts the alt
 * payload (binding repoId/payloadVersion/keyEpoch into the AAD), and wraps the data key to each member's
 * X25519 key. See SPEC sections 4-5 and the lol.trq.alts reference for that part. The only real crypto
 * here is the Ed25519 challenge signature, which IS part of the wire contract.
 *
 * Single file, no dependencies: java.net.http.HttpClient for HTTP, the JDK's built-in Ed25519
 * (java.security), and a tiny hand-rolled JSON parser/serializer (mirrors the one in ../server).
 *
 * Run on JDK 17+ with the single-file source launcher:
 *
 *     java Client.java          # drives the flow against http://localhost:8787
 *
 * Point it at a different server with the AVP_SERVER_URL environment variable (default
 * http://localhost:8787).
 *
 * SPDX-License-Identifier: MIT
 */

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Micro reference client for the Alt Vault Protocol (AVP), HTTP/JSON profile.
 *
 * <p>This class drives the entire wire contract against a running server so that an implementer can watch
 * every operation happen end to end. It mirrors the sibling TypeScript client
 * ({@code examples/typescript/client/src/client.ts}) step for step: it generates two local Ed25519
 * identities, authenticates the first, creates a repo, pulls at the known and a stale version, pushes a
 * new version, demonstrates the optimistic-concurrency conflict path, invites a second member, fetches
 * that member's key, and finally authenticates the second member and pulls.
 *
 * <p>It is intentionally tiny and is <strong>not</strong> production code. The envelope and wrapped-key
 * cryptography is <strong>out of scope</strong> here: the client carries the alt payload as an opaque
 * placeholder ciphertext and fills each member's wrapped data key with a labelled placeholder blob. That
 * round-trips identically through a zero-knowledge server, which never decrypts what it stores. The only
 * real cryptography is the Ed25519 challenge signature over the raw nonce bytes, which is genuinely part
 * of the wire contract. See SPEC sections 4-5 and the {@code lol.trq.alts} reference for the real
 * envelope crypto. Field shapes follow {@code ../../schema/avp.schema.json}.
 *
 * <p>The implementation is a single file with no dependencies: it uses {@link java.net.http.HttpClient}
 * for HTTP, the JDK's built-in Ed25519 provider ({@code java.security}), and a tiny hand-rolled JSON
 * parser/serializer (the {@link Json} nested class, mirroring the one in the reference server).
 *
 * <p>Run on JDK 17+ with the single-file source launcher:
 *
 * <pre>{@code
 *     java Client.java          // drives the flow against http://localhost:8787
 * }</pre>
 */
public final class Client {

    /** Identifier of the wrapping scheme this example advertises in manifests and wrapped keys. */
    private static final String SCHEME_ID = "X25519-HKDF-SHA256-AESGCM-v1";

    /** Base server URL from {@code AVP_SERVER_URL} (default localhost:8787), with any trailing slash trimmed. */
    private static final String BASE_URL = resolveBaseUrl();

    /** Shared HTTP client for every request the transcript issues. */
    private static final HttpClient HTTP = HttpClient.newHttpClient();
    /** Standard (padded) base64 encoder, matching the encoding the server expects for keys and blobs. */
    private static final Base64.Encoder B64 = Base64.getEncoder();
    /** Standard base64 decoder, used to recover the raw nonce bytes for signing. */
    private static final Base64.Decoder B64D = Base64.getDecoder();
    /** Source of randomness for the placeholder AES-GCM IVs (illustrative; no real encryption happens). */
    private static final SecureRandom RANDOM = new SecureRandom();

    /** Not instantiable: this class is a runnable entry point, not an object. */
    private Client() {}

    // ─── Identity (SPEC section 3) ────────────────────────────────────────────

    /**
     * A member identity: a real Ed25519 signing keypair plus a placeholder X25519 public key.
     *
     * <p>The raw 32-byte Ed25519 public key, base64-encoded, is the member id (SPEC section 2). The
     * X25519 key would be a real Curve25519 public key in a production client; here it is an opaque,
     * clearly-labelled placeholder, because this example performs no key wrapping.
     *
     * @param ed25519PublicKey the base64 raw 32-byte Ed25519 public key; this is the member id
     * @param x25519PublicKey a base64 placeholder X25519 public key (no real key agreement happens here)
     * @param privateKey the Ed25519 private key, used only to sign the auth challenge nonce
     */
    private record Identity(String ed25519PublicKey, String x25519PublicKey, PrivateKey privateKey) {}

    /**
     * Generates a fresh Ed25519 identity, extracting the raw 32-byte public key from its SPKI encoding.
     *
     * <p>The JDK exports an Ed25519 public key in {@code SubjectPublicKeyInfo} (SPKI) form, whose last 32
     * bytes are the raw key the protocol uses as the member id.
     *
     * @param label a human-readable name (e.g. {@code "alice"}) woven into the placeholder X25519 key so
     *     the transcript stays readable; it carries no cryptographic meaning
     * @return a new {@link Identity} with a real Ed25519 keypair and a placeholder X25519 public key
     * @throws Exception if the Ed25519 key generator is unavailable
     */
    private static Identity generateIdentity(String label) throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] spki = pair.getPublic().getEncoded();
        byte[] raw = new byte[32];
        System.arraycopy(spki, spki.length - 32, raw, 0, 32);
        // Placeholder, not a real X25519 key — clearly labelled so nobody mistakes it for key material.
        String x25519 = B64.encodeToString(("x25519-placeholder-" + label).getBytes(StandardCharsets.UTF_8));
        return new Identity(B64.encodeToString(raw), x25519, pair.getPrivate());
    }

    // ─── HTTP helper ──────────────────────────────────────────────────────────

    /**
     * Resolves the base server URL from {@code AVP_SERVER_URL}, falling back to {@code localhost:8787}.
     *
     * @return the base URL with any single trailing slash trimmed
     */
    private static String resolveBaseUrl() {
        String env = System.getenv("AVP_SERVER_URL");
        String url = (env == null || env.isBlank()) ? "http://localhost:8787" : env.trim();
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    /**
     * Sends a JSON request to the server and parses the JSON response, throwing on any non-2xx status so
     * the transcript fails loudly rather than silently mis-stepping.
     *
     * @param method the HTTP method ({@code "GET"}, {@code "POST"}, ...)
     * @param path the path appended to {@link #BASE_URL} (must start with {@code "/"})
     * @param body the value to JSON-encode as the request body, or {@code null} for a bodyless request
     *     (e.g. a GET)
     * @param token the bearer token to send as {@code Authorization: Bearer <token>}, or {@code null} for
     *     an unauthenticated call
     * @return the parsed response body (a {@link Map}, {@link List}, scalar, or {@code null}); an empty
     *     map when the response has no body
     * @throws Exception if the request cannot be sent, or the response status is not 2xx (the message
     *     includes the method, path, status, and body)
     */
    private static Object call(String method, String path, Object body, String token) throws Exception {
        HttpRequest.Builder req = HttpRequest.newBuilder(URI.create(BASE_URL + path))
                .header("Content-Type", "application/json");
        if (token != null) {
            req.header("Authorization", "Bearer " + token);
        }
        HttpRequest.BodyPublisher publisher = body == null
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(Json.write(body), StandardCharsets.UTF_8);
        req.method(method, publisher);

        HttpResponse<String> res = HTTP.send(req.build(), HttpResponse.BodyHandlers.ofString());
        if (res.statusCode() < 200 || res.statusCode() >= 300) {
            throw new RuntimeException(method + " " + path + " -> " + res.statusCode() + ": " + res.body());
        }
        String text = res.body();
        return (text == null || text.isBlank()) ? new LinkedHashMap<String, Object>() : Json.parse(text);
    }

    // ─── Auth flow: challenge -> sign nonce -> token (SPEC section 3) ──────────

    /**
     * Runs the keypair challenge flow and returns a bearer token for the given identity.
     *
     * <p>The client signs the <strong>raw nonce bytes</strong> (the bytes obtained by base64-decoding the
     * server's {@code nonce}), not the base64 text — this is the part conformant servers verify. Ed25519
     * signs the message directly with no pre-hash.
     *
     * @param identity the member identity whose private key signs the challenge nonce
     * @return a bearer token to authorize subsequent calls for this identity
     * @throws Exception if either auth leg returns a non-2xx status, or signing fails
     */
    private static String authenticate(Identity identity) throws Exception {
        Map<?, ?> challenge = (Map<?, ?>) call("POST", "/api/auth/keypair/challenge",
                Map.of("ed25519PublicKey", identity.ed25519PublicKey()), null);
        String nonce = (String) challenge.get("nonce");

        Signature sig = Signature.getInstance("Ed25519");
        sig.initSign(identity.privateKey());
        sig.update(B64D.decode(nonce));
        String signature = B64.encodeToString(sig.sign());

        Map<?, ?> auth = (Map<?, ?>) call("POST", "/api/auth/keypair/token", orderedMap(
                "ed25519PublicKey", identity.ed25519PublicKey(),
                "nonce", nonce,
                "signature", signature), null);
        return (String) auth.get("token");
    }

    // ─── Placeholder envelope + wrapped key (NOT real crypto) ──────────────────

    /**
     * Builds an opaque placeholder envelope. A real client AES-256-GCM-encrypts the alt payload and binds
     * {@code (repoId, payloadVersion, keyEpoch)} into the AAD (SPEC section 4). Here {@code ciphertext} is
     * just a base64 blob so the server has something to store; the server never decrypts it, which is the
     * whole point.
     *
     * @param repoId the repo the envelope belongs to
     * @param payloadVersion the payload version this envelope represents
     * @param keyEpoch the key epoch the (notional) payload was encrypted under
     * @return an {@code EncryptedEnvelope} map with a random IV and a labelled placeholder ciphertext
     */
    private static Map<String, Object> placeholderEnvelope(String repoId, long payloadVersion, long keyEpoch) {
        return orderedMap(
                "repoId", repoId,
                "payloadVersion", payloadVersion,
                "keyEpoch", keyEpoch,
                "iv", randomIv(),
                "ciphertext", b64("opaque-placeholder-payload-v" + payloadVersion));
    }

    /**
     * Builds an opaque placeholder wrapped data key for a member. A real client runs X25519 ECDH against
     * the member's X25519 key, derives an AES key via HKDF-SHA256, and AES-256-GCM-encrypts the repo data
     * key. Here it is a labelled placeholder; the server stores and serves it without ever being able to
     * read it.
     *
     * @param memberLabel a human-readable member name woven into the placeholder fields for transcript
     *     readability; it carries no cryptographic meaning
     * @return a {@code WrappedKey} map advertising {@link #SCHEME_ID} with a random IV and labelled
     *     placeholders
     */
    private static Map<String, Object> placeholderWrappedKey(String memberLabel) {
        return orderedMap(
                "schemeId", SCHEME_ID,
                "ephemeralPublicKey", b64("ephemeral-x25519-for-" + memberLabel),
                "iv", randomIv(),
                "ciphertext", b64("wrapped-data-key-for-" + memberLabel));
    }

    /**
     * Assembles a {@code MemberEntry} map from an identity at a given key epoch.
     *
     * @param identity the member whose public keys populate the entry
     * @param label the human-readable member name passed through to {@link #placeholderWrappedKey(String)}
     * @param keyEpoch the key epoch this entry's wrapped key belongs to
     * @return a member-entry map with a placeholder wrapped data key and a {@code null} key-binding signature
     */
    private static Map<String, Object> memberEntry(Identity identity, String label, long keyEpoch) {
        return orderedMap(
                "ed25519PublicKey", identity.ed25519PublicKey(),
                "x25519PublicKey", identity.x25519PublicKey(),
                "wrappedDataKey", placeholderWrappedKey(label),
                "keyEpoch", keyEpoch,
                "keyBindingSig", null);
    }

    // ─── Transcript ───────────────────────────────────────────────────────────

    /**
     * Drives the full AVP lifecycle end to end against a running server and prints a transcript.
     *
     * <p>The steps, in order: generate two local identities (alice, bob); authenticate alice; create a
     * repo with alice as sole member; pull at the known version (unchanged) and from version 0 (envelope
     * returned); push a new version; demonstrate the optimistic-concurrency conflict path with a stale
     * expected version; add bob as a member; fetch bob's stored key entry; then authenticate bob and have
     * him pull the shared repo.
     *
     * @param args ignored
     * @throws Exception if any server call returns a non-2xx status or a crypto/transport step fails;
     *     {@link #main(String[])} turns this into a non-zero exit code
     */
    private static void run(String[] args) throws Exception {
        System.out.println("AVP reference client -> " + BASE_URL);
        System.out.println("(Envelope/wrapped-key crypto is a placeholder; only the Ed25519 auth is real.)\n");

        // Two members, generated locally. alice creates the repo; bob joins later.
        Identity alice = generateIdentity("alice");
        Identity bob = generateIdentity("bob");
        step("members", "alice=" + truncate(alice.ed25519PublicKey()) + " bob=" + truncate(bob.ed25519PublicKey()));

        // 1. Authenticate alice (challenge -> sign nonce -> token).
        String aliceToken = authenticate(alice);
        step("auth", "alice token=" + truncate(aliceToken));

        // 2. createRepo — alice must be the sole member of the manifest she creates. A real repoId is
        // whatever the deploying client mints; we use a random UUID.
        String repoId = UUID.randomUUID().toString();
        Map<String, Object> initialEnvelope = placeholderEnvelope(repoId, 1, 0);
        Map<String, Object> manifest = orderedMap(
                "repoId", repoId,
                "schemeId", SCHEME_ID,
                "keyEpoch", 0L,
                "payloadVersion", 1L,
                "members", new ArrayList<>(List.of(memberEntry(alice, "alice", 0))));
        Map<?, ?> createdManifest = (Map<?, ?>) call("POST", "/v1/repos",
                orderedMap("manifest", manifest, "initialEnvelope", initialEnvelope), aliceToken);
        long createdVersion = asLong(createdManifest.get("payloadVersion"));
        step("createRepo", "repoId=" + createdManifest.get("repoId")
                + " members=" + ((List<?>) createdManifest.get("members")).size()
                + " v=" + createdVersion);

        // 3. pull at the version we already know — server reports unchanged and omits the envelope.
        String repoPath = "/v1/repos/" + urlEncode(repoId);
        Map<?, ?> pullSame = (Map<?, ?>) call("POST", repoPath + "/pull",
                orderedMap("repoId", repoId, "knownPayloadVersion", createdVersion), aliceToken);
        step("pull (known)", "unchanged=" + pullSame.get("unchanged")
                + " envelope=" + (pullSame.get("envelope") == null ? "null" : "present"));

        // 4. pull from version 0 — server returns the current envelope.
        Map<?, ?> pullFresh = (Map<?, ?>) call("POST", repoPath + "/pull",
                orderedMap("repoId", repoId, "knownPayloadVersion", 0L), aliceToken);
        step("pull (stale)", "unchanged=" + pullFresh.get("unchanged")
                + " envelope=" + (pullFresh.get("envelope") == null ? "null" : "present"));

        // 5. push a new payload version with optimistic concurrency on the current version.
        long nextVersion = createdVersion + 1;
        Map<?, ?> pushResult = (Map<?, ?>) call("POST", repoPath + "/push", orderedMap(
                "repoId", repoId,
                "envelope", placeholderEnvelope(repoId, nextVersion, 0),
                "expectedPayloadVersion", createdVersion), aliceToken);
        step("push", "accepted=" + pushResult.get("accepted")
                + " conflict=" + pushResult.get("conflict")
                + " v=" + asLong(pushResult.get("payloadVersion")));

        // 6. demonstrate the conflict path: pushing again at the now-stale expected version is rejected.
        Map<?, ?> conflict = (Map<?, ?>) call("POST", repoPath + "/push", orderedMap(
                "repoId", repoId,
                "envelope", placeholderEnvelope(repoId, nextVersion + 1, 0),
                "expectedPayloadVersion", createdVersion), aliceToken); // stale on purpose
        step("push (stale)", "accepted=" + conflict.get("accepted")
                + " conflict=" + conflict.get("conflict")
                + " serverV=" + asLong(conflict.get("payloadVersion")));

        // 7. addMember — alice (any member may invite, v1 policy) records bob's entry. In a real client
        // bob would publish his public keys via the join handshake (SPEC section 8.1) and alice would
        // wrap the data key to bob's X25519 key; here the wrapped key is a placeholder.
        Map<?, ?> withBob = (Map<?, ?>) call("POST", repoPath + "/add-member",
                orderedMap("repoId", repoId, "member", memberEntry(bob, "bob", 0)), aliceToken);
        step("addMember", "members=" + ((List<?>) withBob.get("members")).size() + " (added bob)");

        // 8. fetchMemberKey — look up bob's stored entry by member id. The id is base64, which can contain
        // + / =, so it MUST be URL-encoded in the path.
        Map<?, ?> bobEntry = (Map<?, ?>) call("GET",
                repoPath + "/member/" + urlEncode(bob.ed25519PublicKey()), null, aliceToken);
        step("fetchMemberKey", "bob x25519=" + truncate((String) bobEntry.get("x25519PublicKey"))
                + " epoch=" + asLong(bobEntry.get("keyEpoch")));

        // 9. bob authenticates with his own keypair and pulls the shared repo.
        String bobToken = authenticate(bob);
        Map<?, ?> bobPull = (Map<?, ?>) call("POST", repoPath + "/pull",
                orderedMap("repoId", repoId, "knownPayloadVersion", 0L), bobToken);
        Map<?, ?> bobManifest = (Map<?, ?>) bobPull.get("manifest");
        step("bob pull", "members=" + ((List<?>) bobManifest.get("members")).size()
                + " v=" + asLong(bobManifest.get("payloadVersion"))
                + " envelope=" + (bobPull.get("envelope") == null ? "null" : "present"));

        System.out.println("\nDone. Full lifecycle exercised against a zero-knowledge server.");
    }

    /**
     * Program entry point: runs the transcript and maps any failure to a non-zero exit code.
     *
     * <p>On failure it prints the error and a hint to start a server, then exits with status {@code 1}.
     *
     * @param args ignored
     */
    public static void main(String[] args) {
        try {
            run(args);
        } catch (Exception e) {
            System.err.println("\nClient failed: " + e.getMessage());
            System.err.println("Is a server running? Start one with `java Server.java` in ../server, "
                    + "or set AVP_SERVER_URL.");
            System.exit(1);
        }
    }

    // ─── Small helpers ──────────────────────────────────────────────────────────

    /**
     * Prints one transcript line with a padded step label so the output columns line up.
     *
     * @param label the short step name shown left-aligned in a fixed-width column
     * @param detail the free-form detail printed after the label
     */
    private static void step(String label, String detail) {
        System.out.printf("  %-16s %s%n", label, detail);
    }

    /**
     * Truncates a base64 string to a short, readable prefix for the transcript.
     *
     * @param value the value to abbreviate
     * @return the first 12 characters followed by an ellipsis, or the whole value if it is shorter
     */
    private static String truncate(String value) {
        return value.length() <= 12 ? value : value.substring(0, 12) + "…";
    }

    /**
     * Base64-encodes a UTF-8 string into a labelled placeholder blob.
     *
     * @param label the human-readable label to encode (never real key material)
     * @return the standard-alphabet base64 of {@code label}'s UTF-8 bytes
     */
    private static String b64(String label) {
        return B64.encodeToString(label.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Generates a fresh base64 placeholder AES-GCM IV (12 random bytes).
     *
     * <p>No encryption happens in this example; the IV exists only so the envelope/wrapped-key shapes are
     * well-formed for the server to store.
     *
     * @return 12 random bytes, standard-alphabet base64-encoded
     */
    private static String randomIv() {
        byte[] iv = new byte[12];
        RANDOM.nextBytes(iv);
        return B64.encodeToString(iv);
    }

    /**
     * Percent-encodes a single URI path segment with {@code encodeURIComponent} semantics, so a base64
     * member id or repo id survives intact in the path.
     *
     * <p>{@link java.net.URLEncoder} performs form encoding (it turns a space into {@code '+'} and encodes
     * {@code '/'}, but leaves {@code '+'} alone), which would corrupt base64 ids. This encodes every byte
     * that is not an RFC 3986 unreserved character, matching what the reference server's decoder expects.
     *
     * @param segment the raw path segment to encode
     * @return the percent-encoded segment, safe to splice into a URL path
     */
    private static String urlEncode(String segment) {
        StringBuilder out = new StringBuilder(segment.length());
        for (byte b : segment.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xFF;
            boolean unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_' || c == '.' || c == '~';
            if (unreserved) {
                out.append((char) c);
            } else {
                out.append('%').append(String.format("%02X", c));
            }
        }
        return out.toString();
    }

    /**
     * Coerces a parsed JSON value to a {@code long}, accepting either a {@link Number} or a numeric string.
     *
     * @param o the value to interpret (the spec's counters are int64)
     * @return the value as a {@code long}
     * @throws IllegalArgumentException if {@code o} is neither a number nor a numeric string
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
     * <p>A {@link LinkedHashMap} keeps the JSON fields serialized in a stable, readable order.
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

    // ─── Minimal JSON (no dependencies) ───────────────────────────────────────
    //
    // Just enough JSON to move the contract's message shapes over the wire: objects become LinkedHashMap,
    // arrays become ArrayList, integral numbers become Long (the spec's counters are int64), others
    // Double. This mirrors the parser/serializer in ../server/Server.java; it is not a JSON library.

    /**
     * A tiny, dependency-free JSON parser and serializer covering exactly the AVP message shapes.
     *
     * <p>Objects become {@link LinkedHashMap}, arrays become {@link ArrayList}, integral numbers become
     * {@link Long} (the spec's counters are int64), non-integral numbers become {@link Double}, and
     * strings/booleans/{@code null} map to their Java equivalents. It mirrors the JSON helper in the
     * reference server so the two examples stay symmetric; it is not a general-purpose JSON library.
     */
    static final class Json {

        /** Not instantiable: all behavior is exposed through static methods. */
        private Json() {}

        /**
         * Parses a JSON document into Java values.
         *
         * @param text the JSON document to parse
         * @return the parsed value ({@link Map}, {@link List}, {@link String}, {@link Long}, {@link Double},
         *     {@link Boolean}, or {@code null})
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
         * @throws IllegalArgumentException if {@code value} (or a nested value) is of an unsupported type
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
                    throw new IllegalArgumentException(
                            "expected '" + c + "' but got '" + got + "' at index " + (pos - 1));
                }
            }
        }
    }
}
