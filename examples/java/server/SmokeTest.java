/*
 * Integration smoke test for the AVP Java reference server. Dependency-free: it spins the server up on
 * an ephemeral port, drives the real keypair challenge -> token flow with a JDK-generated Ed25519 key,
 * and walks the full repo lifecycle (create, pull, push + conflict, add, fetch, remove) plus the auth and
 * authorization rejection paths. Mirrors examples/typescript/server/test/server.test.ts.
 *
 * Run on JDK 17+ from this directory:
 *
 *     java SmokeTest.java
 *
 * Exits 0 on success, 1 on the first failed assertion.
 *
 * SPDX-License-Identifier: MIT
 */

import com.sun.net.httpserver.HttpServer;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Dependency-free integration smoke test for the AVP Java reference server ({@link Server}).
 *
 * <p>It spins the server up on an ephemeral port, drives the real keypair challenge -> token flow with a
 * JDK-generated Ed25519 key, and walks the full repo lifecycle (create, pull, push + conflict, add,
 * fetch, remove) plus the authentication and authorization rejection paths. It mirrors
 * {@code examples/typescript/server/test/server.test.ts}.
 *
 * <p>Run on JDK 17+ from this directory:
 *
 * <pre>{@code
 *     java SmokeTest.java
 * }</pre>
 *
 * <p>The process exits {@code 0} when every assertion passes and {@code 1} on the first failed assertion.
 */
public final class SmokeTest {

    /** Base URL of the server under test, e.g. {@code http://localhost:<port>}; set by {@link #main}. */
    private static String base;
    /** Shared HTTP client used for every request the test issues. */
    private static final HttpClient client = HttpClient.newHttpClient();
    /** Standard (padded) base64 encoder, matching the encoding the server expects for keys. */
    private static final Base64.Encoder B64 = Base64.getEncoder();
    /** Standard base64 decoder, used to recover raw nonce bytes for signing. */
    private static final Base64.Decoder B64D = Base64.getDecoder();
    /** Running count of assertions executed, reported on success. */
    private static int checks = 0;

    /**
     * Entry point: starts the server on an ephemeral port, runs every test, and reports the outcome.
     *
     * <p>On success it prints the number of checks that passed. On the first failed assertion it prints
     * the failure to standard error, stops the server, and exits with status {@code 1}.
     *
     * @param args ignored
     * @throws Exception if the server cannot start or a request unexpectedly fails outside an assertion
     */
    public static void main(String[] args) throws Exception {
        // Server.java compiles into the same package (default), so its package-private start() is visible
        // when both files are compiled together. We reflectively launch to avoid a hard compile dependency
        // ordering issue; in practice `java SmokeTest.java` compiles Server.java alongside it.
        Server server = new Server();
        HttpServer http = server.start(0);
        int port = http.getAddress().getPort();
        base = "http://localhost:" + port;

        try {
            testRejectsUnauthenticated();
            testRejectsBadSignature();
            testFullLifecycle();
            testNonMemberForbidden();
            System.out.println("OK — " + checks + " checks passed");
        } catch (AssertionError e) {
            System.err.println("FAIL: " + e.getMessage());
            http.stop(0);
            System.exit(1);
        } finally {
            http.stop(0);
        }
    }

    // ─── tests ────────────────────────────────────────────────────────────────

    /**
     * Asserts that a repo-scoped call without a bearer token is rejected with {@code 401}.
     *
     * @throws Exception if the request cannot be sent
     */
    private static void testRejectsUnauthenticated() throws Exception {
        Resp r = post("/v1/repos", "{}", null);
        eq(401, r.status, "unauthenticated createRepo -> 401");
    }

    /**
     * Asserts that redeeming a challenge with a signature that does not match the nonce is rejected with
     * {@code 401}. The challenge is requested for one key, but the nonce is signed with a different key
     * over the wrong bytes.
     *
     * @throws Exception if a request cannot be sent or key generation fails
     */
    private static void testRejectsBadSignature() throws Exception {
        Kp kp = keypair();
        Map<String, Object> challenge = postJson("/api/auth/keypair/challenge",
                Server.Json.write(Map.of("ed25519PublicKey", kp.pub)), null);
        // Sign the wrong message with a different key.
        Kp other = keypair();
        String wrong = B64.encodeToString(signRaw(other, "not the nonce".getBytes(StandardCharsets.UTF_8)));
        Resp r = post("/api/auth/keypair/token", Server.Json.write(Map.of(
                "ed25519PublicKey", kp.pub,
                "nonce", challenge.get("nonce"),
                "signature", wrong)), null);
        eq(401, r.status, "bad challenge signature -> 401");
    }

    /**
     * Walks a repo through its entire lifecycle as a single authenticated member and asserts the server's
     * responses at each step: create (sole member), pull (unchanged vs. behind), push (accepted vs. stale
     * conflict), add-member, fetch-member-key (round-tripping a URL-encoded base64 id), and remove-member
     * (rotation to a new key epoch and bumped version).
     *
     * @throws Exception if any request fails or key generation fails
     */
    private static void testFullLifecycle() throws Exception {
        Kp alice = keypair();
        String aliceToken = authenticate(alice);
        String repoId = "repo-lifecycle";

        Map<String, Object> manifest = Map.of(
                "repoId", repoId, "schemeId", "scheme-v1", "keyEpoch", 0, "payloadVersion", 1,
                "members", List.of(entry(alice.pub, 0)));
        Map<String, Object> created = postJson("/v1/repos",
                Server.Json.write(Map.of("manifest", manifest, "initialEnvelope", envelope(repoId, 1, 0))),
                aliceToken);
        eq(1, ((List<?>) created.get("members")).size(), "create -> sole member");

        // pull at current version => unchanged; behind => the envelope byte-for-byte.
        Map<String, Object> fresh = postJson("/v1/repos/" + repoId + "/pull",
                Server.Json.write(Map.of("repoId", repoId, "knownPayloadVersion", 1)), aliceToken);
        eq(Boolean.TRUE, fresh.get("unchanged"), "pull at current -> unchanged");
        eq(null, fresh.get("envelope"), "pull at current -> null envelope");

        Map<String, Object> behind = postJson("/v1/repos/" + repoId + "/pull",
                Server.Json.write(Map.of("repoId", repoId, "knownPayloadVersion", 0)), aliceToken);
        eq(Boolean.FALSE, behind.get("unchanged"), "pull behind -> changed");
        eq("ct-1", ((Map<?, ?>) behind.get("envelope")).get("ciphertext"), "pull behind -> current ciphertext");

        // push with the right base version succeeds; a stale base version conflicts.
        Map<String, Object> pushed = postJson("/v1/repos/" + repoId + "/push",
                Server.Json.write(Map.of("repoId", repoId, "envelope", envelope(repoId, 2, 0),
                        "expectedPayloadVersion", 1)), aliceToken);
        eq(Boolean.TRUE, pushed.get("accepted"), "push at base -> accepted");
        eq(2L, ((Number) pushed.get("payloadVersion")).longValue(), "push -> bumped version");

        Map<String, Object> stale = postJson("/v1/repos/" + repoId + "/push",
                Server.Json.write(Map.of("repoId", repoId, "envelope", envelope(repoId, 2, 0),
                        "expectedPayloadVersion", 1)), aliceToken);
        eq(Boolean.TRUE, stale.get("conflict"), "stale push -> conflict");
        eq(Boolean.FALSE, stale.get("accepted"), "stale push -> not accepted");

        // add a member, then fetch their key back (member id is base64, so it must round-trip URL-encoded).
        Kp bob = keypair();
        Map<String, Object> added = postJson("/v1/repos/" + repoId + "/add-member",
                Server.Json.write(Map.of("repoId", repoId, "member", entry(bob.pub, 0))), aliceToken);
        eq(2, ((List<?>) added.get("members")).size(), "add-member -> roster grows");

        String encodedId = java.net.URLEncoder.encode(bob.pub, StandardCharsets.UTF_8);
        Map<String, Object> fetched = getJson("/v1/repos/" + repoId + "/member/" + encodedId, aliceToken);
        eq(bob.pub, fetched.get("ed25519PublicKey"), "fetchMemberKey -> bob's entry");

        // remove bob: rotate to {alice} at a new epoch and a bumped version.
        Map<String, Object> removed = postJson("/v1/repos/" + repoId + "/remove-member",
                Server.Json.write(Map.of(
                        "repoId", repoId,
                        "removedMemberId", bob.pub,
                        "rotatedEnvelope", envelope(repoId, 3, 1),
                        "rewrappedMembers", List.of(entry(alice.pub, 1)),
                        "newKeyEpoch", 1)), aliceToken);
        eq(1, ((List<?>) removed.get("members")).size(), "remove-member -> roster shrinks");
        eq(1L, ((Number) removed.get("keyEpoch")).longValue(), "remove-member -> new epoch");
        eq(3L, ((Number) removed.get("payloadVersion")).longValue(), "remove-member -> rotated version");
    }

    /**
     * Asserts that an authenticated caller who is not on a repo's roster is forbidden ({@code 403}) from
     * acting on it: one member creates a repo, and a second, unrelated authenticated key is denied a pull.
     *
     * @throws Exception if any request fails or key generation fails
     */
    private static void testNonMemberForbidden() throws Exception {
        Kp alice = keypair();
        String aliceToken = authenticate(alice);
        String repoId = "repo-private";
        Map<String, Object> manifest = Map.of(
                "repoId", repoId, "schemeId", "s", "keyEpoch", 0, "payloadVersion", 1,
                "members", List.of(entry(alice.pub, 0)));
        postJson("/v1/repos",
                Server.Json.write(Map.of("manifest", manifest, "initialEnvelope", envelope(repoId, 1, 0))),
                aliceToken);

        Kp mallory = keypair();
        String malloryToken = authenticate(mallory);
        Resp r = post("/v1/repos/" + repoId + "/pull",
                Server.Json.write(Map.of("repoId", repoId, "knownPayloadVersion", 0)), malloryToken);
        eq(403, r.status, "non-member pull -> 403");
    }

    // ─── helpers ───────────────────────────────────────────────────────────────

    /**
     * A generated Ed25519 keypair together with the base64 of its raw public key.
     *
     * @param pub the raw 32-byte public key, base64-encoded (the member id the server uses)
     * @param pair the full JDK keypair, retained so the private key can sign challenges
     */
    private record Kp(String pub, KeyPair pair) {}

    /**
     * Generates a fresh Ed25519 keypair and extracts its raw public key as base64.
     *
     * <p>The JDK exports the public key in SPKI form; the raw 32-byte key is the last 32 bytes of that
     * encoding.
     *
     * @return a {@link Kp} bundling the base64 raw public key and the underlying {@link KeyPair}
     * @throws Exception if the Ed25519 key generator is unavailable
     */
    private static Kp keypair() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        // Export raw 32-byte key: the SPKI encoding's last 32 bytes are the raw key.
        byte[] spki = kp.getPublic().getEncoded();
        byte[] raw = new byte[32];
        System.arraycopy(spki, spki.length - 32, raw, 0, 32);
        return new Kp(B64.encodeToString(raw), kp);
    }

    /**
     * Signs raw message bytes with a keypair's Ed25519 private key.
     *
     * @param kp the keypair whose private key signs
     * @param message the exact bytes to sign
     * @return the raw Ed25519 signature
     * @throws Exception if signing fails
     */
    private static byte[] signRaw(Kp kp, byte[] message) throws Exception {
        Signature sig = Signature.getInstance("Ed25519");
        sig.initSign(kp.pair.getPrivate());
        sig.update(message);
        return sig.sign();
    }

    /**
     * Runs the full keypair authentication flow for a key and returns the resulting bearer token.
     *
     * <p>It requests a challenge nonce for the public key, signs the base64-decoded nonce bytes with the
     * private key, and redeems the signed nonce for a token.
     *
     * @param kp the keypair to authenticate as
     * @return the bearer token to send as {@code Authorization: Bearer <token>}
     * @throws Exception if any request fails or signing fails
     */
    private static String authenticate(Kp kp) throws Exception {
        Map<String, Object> challenge = postJson("/api/auth/keypair/challenge",
                Server.Json.write(Map.of("ed25519PublicKey", kp.pub)), null);
        String nonce = (String) challenge.get("nonce");
        String signature = B64.encodeToString(signRaw(kp, B64D.decode(nonce)));
        Map<String, Object> token = postJson("/api/auth/keypair/token", Server.Json.write(Map.of(
                "ed25519PublicKey", kp.pub, "nonce", nonce, "signature", signature)), null);
        return (String) token.get("token");
    }

    /**
     * Builds a placeholder member roster entry for a public key at a given key epoch.
     *
     * <p>The wrapped-key and x25519 fields are illustrative placeholders, not real cryptographic output;
     * the server stores them verbatim and never decrypts them.
     *
     * @param pub the member's base64 Ed25519 public key
     * @param epoch the key epoch this entry's wrapped data key belongs to
     * @return a member entry map shaped like the schema's member object
     */
    private static Map<String, Object> entry(String pub, int epoch) {
        return Map.of(
                "ed25519PublicKey", pub,
                "x25519PublicKey", "x-" + pub.substring(0, Math.min(6, pub.length())),
                "wrappedDataKey", Map.of("schemeId", "X25519-HKDF-SHA256-AESGCM-v1",
                        "ephemeralPublicKey", "eph", "iv", "iv", "ciphertext", "wk"),
                "keyEpoch", epoch);
    }

    /**
     * Builds a placeholder encrypted envelope at a given version and key epoch.
     *
     * <p>The {@code iv} and {@code ciphertext} values are placeholders; the ciphertext is tagged with the
     * version (e.g. {@code ct-2}) so tests can assert which envelope came back from a pull.
     *
     * @param repoId the repo the envelope belongs to
     * @param version the payload version this envelope carries
     * @param epoch the key epoch this envelope was encrypted under
     * @return an envelope map shaped like the schema's envelope object
     */
    private static Map<String, Object> envelope(String repoId, int version, int epoch) {
        return Map.of("repoId", repoId, "payloadVersion", version, "keyEpoch", epoch,
                "iv", "iv", "ciphertext", "ct-" + version);
    }

    /**
     * A captured HTTP response: its status code and its raw body text.
     *
     * @param status the HTTP status code
     * @param body the response body as a string
     */
    private record Resp(int status, String body) {}

    /**
     * Sends a POST request with a JSON body, optionally bearing an authorization token.
     *
     * @param path the path to POST to, appended to {@link #base}
     * @param body the request body (already-serialized JSON)
     * @param token the bearer token to send, or {@code null} to omit the {@code Authorization} header
     * @return the captured response
     * @throws Exception if the request fails to send or is interrupted
     */
    private static Resp post(String path, String body, String token) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (token != null) {
            b.header("Authorization", "Bearer " + token);
        }
        HttpResponse<String> r = client.send(b.build(), HttpResponse.BodyHandlers.ofString());
        return new Resp(r.statusCode(), r.body());
    }

    /**
     * Sends a POST request, asserts a {@code 200} response, and parses the body as a JSON object.
     *
     * @param path the path to POST to, appended to {@link #base}
     * @param body the request body (already-serialized JSON)
     * @param token the bearer token to send, or {@code null} to omit the {@code Authorization} header
     * @return the parsed response object
     * @throws Exception if the request fails to send
     * @throws AssertionError if the response status is not {@code 200}
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> postJson(String path, String body, String token) throws Exception {
        Resp r = post(path, body, token);
        eq(200, r.status, "POST " + path + " -> 200 (got " + r.status + ": " + r.body + ")");
        return (Map<String, Object>) Server.Json.parse(r.body);
    }

    /**
     * Sends an authenticated GET request, asserts a {@code 200} response, and parses the body as a JSON
     * object.
     *
     * @param path the path to GET, appended to {@link #base}
     * @param token the bearer token to send in the {@code Authorization} header
     * @return the parsed response object
     * @throws Exception if the request fails to send
     * @throws AssertionError if the response status is not {@code 200}
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> getJson(String path, String token) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(base + path))
                .header("Authorization", "Bearer " + token).GET().build();
        HttpResponse<String> r = client.send(req, HttpResponse.BodyHandlers.ofString());
        eq(200, r.statusCode(), "GET " + path + " -> 200 (got " + r.statusCode() + ": " + r.body() + ")");
        return (Map<String, Object>) Server.Json.parse(r.body());
    }

    /**
     * Asserts that an actual value equals an expected one, incrementing the check counter.
     *
     * <p>Two non-null {@link Number}s are compared by their {@code long} value so that, for example, a
     * parsed {@link Long} and an {@link Integer} literal compare equal; everything else is compared with
     * {@link Object#equals(Object)} (with {@code null} matching only {@code null}).
     *
     * @param expected the expected value (may be {@code null})
     * @param actual the actual value (may be {@code null})
     * @param what a human-readable description of the assertion, used in the failure message
     * @throws AssertionError if the values are not equal
     */
    private static void eq(Object expected, Object actual, String what) {
        checks++;
        boolean ok = (expected == null) ? actual == null
                : (expected instanceof Number && actual instanceof Number)
                        ? ((Number) expected).longValue() == ((Number) actual).longValue()
                        : expected.equals(actual);
        if (!ok) {
            throw new AssertionError(what + " — expected <" + expected + "> but was <" + actual + ">");
        }
    }

    /** Touches the {@link PublicKey} type so the import stays meaningful if a future check needs it. */
    @SuppressWarnings("unused")
    private static PublicKey unused;
}
