/*
 * In-memory AVP 0.5 reference host, HTTP/JSON profile: the client-facing API and the host routes of
 * host-to-host replication.
 *
 * SPDX-License-Identifier: MIT
 */

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * The AVP 0.5 reference host (SPEC 3.3, 6 to 10, 12), in memory, over the HTTP/JSON profile.
 *
 * <p>The host is a thin layer over the shared {@code avp} sources: each request is read up to the size
 * limit ({@code 413}), routed ({@code 404}), authenticated ({@code 401}), decoded ({@code 400}), checked
 * against the repository ({@code 404 not_found}, {@code 403 not_hosted}) and the caller identity each
 * operation requires (SPEC 10.1, {@code 403 forbidden}), and handed to {@link AvpRules.RepoView}, which
 * makes every SPEC 6 and 7 decision. An engine verdict maps to the SPEC 10.4 status table. An accepted
 * client write is queued for the repository's other hosts ({@link Replication}).
 *
 * <p>The host routes of the reference host-to-host profile (SPEC 9.3) answer {@code 503} while
 * replication is paused by the test control, then check the host request signature ({@code 401}), and
 * the repository: {@code 404 not_found} if not held, {@code 403 not_hosted} if this host's winning tip
 * does not list it, {@code 403 forbidden} if that tip does not list the calling peer (SPEC 9.2). {@code
 * offer} checks the received tip after validating the items.
 *
 * <p>It is zero-knowledge: it stores only manifest states, commits (ciphertext), and leave requests,
 * never a data key, decrypts nothing, and never logs a request body. No handler lets an exception escape
 * on any input: every failure is an error body. Illustrative reference code, not production: state lives
 * in memory and there is no TLS.
 *
 * <p>Build and run from this directory: {@code javac -d build ../avp/*.java *.java} then {@code java -cp
 * build Server}. Environment: {@code PORT} (default 8787), {@code AVP_BIND} (default 0.0.0.0), {@code
 * AVP_HOST_SEED} (64 hex digits, else a random host key), {@code AVP_PEERS} ({@code <base64 hostKey>@<http
 * base url>,...}), and {@code AVP_TEST_CONTROL=1} for the test control route.
 */
public final class Server {

    /** The default port of the binary ({@code PORT} overrides it). */
    public static final int DEFAULT_PORT = 8787;

    /**
     * The default listen address of the binary ({@code AVP_BIND} overrides it): every interface, which
     * container and CI runs rely on.
     */
    public static final String DEFAULT_BIND = "0.0.0.0";

    /** A dotted-quad IPv4 literal, each part 0 to 255 without a leading zero. */
    private static final String IPV4_PART = "(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])";

    /** How long an acceptance from {@code prepareJoin} stays valid (SPEC 8.2: 15 minutes). */
    static final long ACCEPTANCE_TTL_MS = 15 * 60 * 1000L;

    /** How long a challenge nonce stays valid (SPEC 3.3: RECOMMENDED at most 2 minutes). */
    static final long CHALLENGE_TTL_MS = 2 * 60 * 1000L;

    /** How long a minted token stays valid (SPEC 3.3: tokens SHOULD be short-lived). */
    static final long TOKEN_TTL_MS = 15 * 60 * 1000L;

    /** The protocol version in discovery (SPEC 11.7). */
    private static final String VERSION = "0.5";

    /** The threads that serve requests. */
    private static final int WORKERS = 8;

    /** The state of each running server, for {@link #host(HttpServer)}, {@link #stop(HttpServer)}. */
    private static final Map<HttpServer, Host> HOSTS = new ConcurrentHashMap<>();

    private Server() {}

    // ─── Configuration ──────────────────────────────────────────────────────────────────

    /**
     * The deployment limits of SPEC 12.1, each answered with the terminal error SPEC 12.1 names. Mutable so
     * that tests can lower a limit; the host reads it under its lock.
     */
    public static final class Limits {
        /** Largest request body in bytes; a larger one is {@code 413 too_large}. */
        int maxBodyBytes = 4 * 1024 * 1024;
        /** Most members a manifest state may list; more is {@code 429 quota_exceeded}. */
        int maxMembers = 500;
        /** Most repositories one owner key may have on this host; more is {@code 429 quota_exceeded}. */
        int maxReposPerOwner = 1000;
        /** Most repositories this host holds in all, by createRepo and replication. */
        int maxRepos = 10_000;
        /** Most outstanding challenges in all; at the cap the oldest is evicted. */
        int maxChallenges = 10_000;
        /** Most outstanding challenges for one key; more is {@code 429 quota_exceeded}. */
        int maxChallengesPerKey = 16;
        /** Most live bearer tokens in all; at the cap the oldest is evicted. */
        int maxTokens = 100_000;
        /** Most live bearer tokens for one key; more is {@code 429 quota_exceeded}. */
        int maxTokensPerKey = 32;
        /** Most recorded unexpired acceptances (SPEC 8.2) in all; at the cap the oldest is evicted. */
        int maxPendingJoins = 10_000;
        /** Most recorded unexpired acceptances for one member key; more is {@code 429 quota_exceeded}. */
        int maxPendingJoinsPerKey = 64;
        /** The head bound for client writes (SPEC 7.4); more is {@code 409 too_many_heads}. */
        int headBound = 16;

        /** The default limits. */
        public Limits() {}

        Limits copy() {
            Limits l = new Limits();
            l.maxBodyBytes = maxBodyBytes;
            l.maxMembers = maxMembers;
            l.maxReposPerOwner = maxReposPerOwner;
            l.maxRepos = maxRepos;
            l.maxChallenges = maxChallenges;
            l.maxChallengesPerKey = maxChallengesPerKey;
            l.maxTokens = maxTokens;
            l.maxTokensPerKey = maxTokensPerKey;
            l.maxPendingJoins = maxPendingJoins;
            l.maxPendingJoinsPerKey = maxPendingJoinsPerKey;
            l.headBound = headBound;
            return l;
        }
    }

    /**
     * How to start a host.
     *
     * @param bindHost the address to listen on ({@code AVP_BIND} in the binary, default {@code 0.0.0.0})
     * @param hostSeed the 32-byte Ed25519 seed of the host key
     * @param peers the static peer list (SPEC 9.3)
     * @param limits the deployment limits, copied at start
     * @param replication the replication settings
     */
    public record ServerConfig(
            String bindHost, byte[] hostSeed, Replication.Peers peers, Limits limits, Replication.Config replication) {
        /** Copies the seed. */
        public ServerConfig {
            hostSeed = hostSeed.clone();
        }
    }

    // ─── Host state ─────────────────────────────────────────────────────────────────────

    /**
     * Everything one host process holds. The request handlers and the replication workers share it under
     * one lock ({@link #lock()}); nobody holds that lock across an outbound host call.
     */
    static final class Host {
        /** This host's Ed25519 seed; it signs acceptances and host requests. */
        final byte[] seed;
        /** This host's public host key. */
        final byte[] hostKey;
        /** The replication settings. */
        final Replication.Config replication;

        private final ReentrantLock mutex = new ReentrantLock();
        /** Wakes the replication workers; it waits on {@link #mutex}. */
        final Condition wake = mutex.newCondition();
        /** Set by a test to model a broken state: every handler then fails with {@code 500}. */
        private volatile boolean poisoned;

        /** The deployment limits. */
        Limits limits;
        /** Added to the system clock. Zero in the binary; tests move it to expire challenges and tokens. */
        long clockOffsetMs;
        /**
         * When set, the host's clock reads this instant instead of the system clock (plus {@link
         * #clockOffsetMs}). Unset in the binary; tests freeze the clock to pin exact time bounds.
         */
        Long fixedNowMs;
        /** Each repository's engine view, by repoId. */
        final Map<String, AvpRules.RepoView> repos = new HashMap<>();
        /** {@link #joinKey(String, byte[])} of each acceptance this host issued, to its expiresAt. */
        final Map<String, Long> pendingJoin = new HashMap<>();
        /** The accepted client writes waiting to be offered to the repository's other hosts. */
        final Replication.Outbox outbox = new Replication.Outbox();
        /** Outstanding challenges and live tokens. */
        final Auth auth = new Auth();
        /** The peer list the host routes authenticate against. */
        Replication.Peers peers = Replication.Peers.none();
        /** Set by the test control: no outbound host traffic, inbound host routes answer {@code 503}. */
        boolean paused;
        /** Bumped when replication is unpaused, so every worker sweeps at once. */
        long kick;
        /** {@code (peer, repoId)} pairs to catch up from, queued by incomplete offers. */
        final ArrayDeque<Replication.Catchup> catchups = new ArrayDeque<>();
        /** Engine applications of received items, for tests and diagnostics. */
        long engineApplications;

        /** The running replication workers; guarded by {@code this}. */
        private Replication.Running running;
        /** The request threads. */
        private ExecutorService pool;

        Host(ServerConfig cfg) throws AvpException {
            this.seed = cfg.hostSeed();
            this.hostKey = AvpCrypto.ed25519Public(seed);
            this.replication = cfg.replication();
            this.limits = cfg.limits().copy();
        }

        /**
         * Takes the state lock.
         *
         * @throws IllegalStateException if the state is poisoned (a test hook)
         */
        void lock() {
            mutex.lock();
            if (poisoned) {
                mutex.unlock();
                throw new IllegalStateException("state lock poisoned");
            }
        }

        /** Releases the state lock. */
        void unlock() {
            mutex.unlock();
        }

        /** Takes the lock whatever the poison flag, for shutdown. */
        void lockForShutdown() {
            mutex.lock();
        }

        /** Marks the state broken, like a poisoned lock: every later request answers {@code 500}. */
        void poison() {
            poisoned = true;
        }

        /** The host's current time in epoch milliseconds. */
        long nowMs() {
            Long fixed = fixedNowMs;
            return saturatingAdd(fixed == null ? System.currentTimeMillis() : fixed, clockOffsetMs);
        }

        /** What the store holds (repositories, acceptances, outbox), for a full rendering in tests. */
        Map<String, Object> storeParts() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("repos", repos);
            m.put("pendingJoin", pendingJoin);
            m.put("outbox", outbox);
            return m;
        }

        /** How many repositories on this host have {@code owner} as their owner key. */
        int reposOwnedBy(byte[] owner) {
            int n = 0;
            for (AvpRules.RepoView v : repos.values()) {
                Optional<AvpManifest.SignedManifest> t = v.tip();
                if (t.isPresent() && Arrays.equals(t.get().state().ownerKey(), owner)) {
                    n++;
                }
            }
            return n;
        }

        /**
         * Records an issued acceptance after dropping expired ones; at the total cap the one that expires
         * first is evicted.
         *
         * @return {@code false}, recording nothing, when the member already holds its share
         */
        boolean recordAcceptance(String repoId, byte[] member, long expiresAt, long now) {
            pendingJoin.values().removeIf(exp -> exp <= now);
            String key = joinKey(repoId, member);
            if (!pendingJoin.containsKey(key)) {
                String suffix = "|" + AvpEncoding.base64(member);
                long held = pendingJoin.keySet().stream()
                        .filter(k -> k.endsWith(suffix))
                        .count();
                if (limits.maxPendingJoins == 0 || held >= limits.maxPendingJoinsPerKey) {
                    return false;
                }
                while (pendingJoin.size() >= limits.maxPendingJoins) {
                    String oldest = null;
                    long min = Long.MAX_VALUE;
                    for (Map.Entry<String, Long> e : pendingJoin.entrySet()) {
                        if (oldest == null || e.getValue() < min) {
                            oldest = e.getKey();
                            min = e.getValue();
                        }
                    }
                    if (oldest == null) {
                        break;
                    }
                    pendingJoin.remove(oldest);
                }
            }
            pendingJoin.put(key, expiresAt);
            return true;
        }
    }

    /**
     * The key of a recorded acceptance: the repoId and the base64 member key.
     *
     * @param repoId the repository
     * @param member the member key
     * @return the key in {@link Host#pendingJoin}
     */
    static String joinKey(String repoId, byte[] member) {
        return repoId + "|" + AvpEncoding.base64(member);
    }

    // ─── Host-issued authentication (SPEC 3.3) ──────────────────────────────────────────

    /**
     * Challenges and bearer tokens (SPEC 3.3). A challenge is 32 CSPRNG bytes for one key, single-use,
     * valid for {@link #CHALLENGE_TTL_MS}; a token is 32 random bytes (base64url), valid only here for
     * {@link #TOKEN_TTL_MS}. Neither secret is stored: both tables are keyed by the SHA-256 digest of the
     * secret, so a lookup compares digests and its timing says nothing about the secret. The challenge's
     * bound key is compared in constant time. Each table has a per-key cap ({@code 429}) and a total cap at
     * which the entry that expires first is evicted.
     */
    static final class Auth {
        private record Entry(byte[] key, long expiresAt) {}

        private final Map<String, Entry> challenges = new HashMap<>();
        private final Map<String, Entry> tokens = new HashMap<>();

        private static String digest(byte[] secret) {
            return AvpEncoding.base64(AvpCrypto.sha256(secret));
        }

        private static boolean makeRoom(Map<String, Entry> map, byte[] key, long now, int total, int perKey) {
            map.values().removeIf(e -> e.expiresAt() <= now);
            long mine = map.values().stream()
                    .filter(e -> Arrays.equals(e.key(), key))
                    .count();
            if (total == 0 || mine >= perKey) {
                return false;
            }
            while (map.size() >= total) {
                String oldest = null;
                long min = Long.MAX_VALUE;
                for (Map.Entry<String, Entry> e : map.entrySet()) {
                    if (oldest == null || e.getValue().expiresAt() < min) {
                        oldest = e.getKey();
                        min = e.getValue().expiresAt();
                    }
                }
                if (oldest == null) {
                    break;
                }
                map.remove(oldest);
            }
            return true;
        }

        /** A fresh nonce for {@code key}, or {@code null} when the key holds its share of challenges. */
        byte[] challenge(byte[] key, long now, Limits l) {
            if (!makeRoom(challenges, key, now, l.maxChallenges, l.maxChallengesPerKey)) {
                return null;
            }
            byte[] nonce = AvpCrypto.randomBytes(32);
            challenges.put(digest(nonce), new Entry(key.clone(), saturatingAdd(now, CHALLENGE_TTL_MS)));
            return nonce;
        }

        /**
         * Redeems a signed challenge for a token whose subject is {@code key}. The nonce is consumed
         * whatever the outcome.
         */
        Map<String, Object> token(byte[] key, byte[] nonce, byte[] signature, long now, Limits l) throws ApiError {
            Entry challenge = challenges.remove(digest(nonce));
            if (challenge == null
                    || challenge.expiresAt() <= now
                    || !AvpCrypto.constantTimeEquals(challenge.key(), key)
                    || !AvpCrypto.ed25519Verify(key, nonce, signature)) {
                throw ApiError.unauthorized(
                        "challenge nonce unknown, used, expired, or not issued for this key, or bad signature");
            }
            if (!makeRoom(tokens, key, now, l.maxTokens, l.maxTokensPerKey)) {
                throw ApiError.quota("too many live tokens for this key");
            }
            String token = AvpEncoding.base64Url(AvpCrypto.randomBytes(32));
            long expiresAt = saturatingAdd(now, TOKEN_TTL_MS);
            tokens.put(digest(token.getBytes(StandardCharsets.UTF_8)), new Entry(key.clone(), expiresAt));
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("expiresAt", expiresAt);
            o.put("token", token);
            return o;
        }

        /** The subject of a live token issued here, or {@code null}. */
        byte[] subject(String token, long now) {
            Entry e = tokens.get(digest(token.getBytes(StandardCharsets.UTF_8)));
            return e == null || e.expiresAt() <= now ? null : e.key();
        }
    }

    static long saturatingAdd(long a, long b) {
        long sum = a + b;
        if (((a ^ sum) & (b ^ sum)) < 0) {
            return b < 0 ? Long.MIN_VALUE : Long.MAX_VALUE;
        }
        return sum;
    }

    // ─── Errors ─────────────────────────────────────────────────────────────────────────

    /** An error answer: the status, the SPEC 10.4 {@code code}, a message, and an optional detail. */
    static final class ApiError extends Exception {
        private static final long serialVersionUID = 1L;

        final int status;
        final String code;
        final String detail;
        final Long retryAfterS;

        ApiError(int status, String code, String message, String detail, Long retryAfterS) {
            super(message, null, false, false);
            this.status = status;
            this.code = code;
            this.detail = detail;
            this.retryAfterS = retryAfterS;
        }

        static ApiError of(int status, String code, String message) {
            return new ApiError(status, code, message, null, null);
        }

        static ApiError badRequest(String message) {
            return of(400, AvpRules.BAD_REQUEST, message);
        }

        static ApiError unauthorized(String message) {
            return of(401, "unauthorized", message);
        }

        static ApiError forbidden(String message) {
            return of(403, AvpRules.FORBIDDEN, message);
        }

        static ApiError notFound(String message) {
            return of(404, "not_found", message);
        }

        static ApiError quota(String message) {
            return of(429, "quota_exceeded", message);
        }

        static ApiError tooLarge() {
            return of(413, "too_large", "request body too large");
        }

        /** {@code 503} while replication is paused by the test control (SPEC 9.3); no SPEC code. */
        static ApiError paused() {
            return new ApiError(503, null, "replication is paused", null, null);
        }

        /** A failure that is not the caller's fault. */
        static ApiError internal() {
            return new ApiError(500, null, "internal error", null, null);
        }

        /** The SPEC 10.4 answer for an engine verdict. */
        static ApiError reject(String code) {
            return switch (code) {
                case AvpRules.BAD_REQUEST -> of(400, code, "malformed or invalid item");
                case AvpRules.FORBIDDEN -> of(403, code, "not allowed by the repository's manifest");
                case AvpRules.NOT_HOSTED -> of(403, code, "this host is not in the manifest's hosts");
                case AvpRules.TOO_MANY_HEADS -> of(409, code, "too many heads; merge first");
                case AvpRules.MANIFEST_CONFLICT -> of(409, code, "manifest state is not the tip + 1");
                case AvpRules.MISSING_PARENTS -> of(422, code, "unknown parent, manifest state, or frontier commit");
                default -> of(400, AvpRules.BAD_REQUEST, "rejected");
            };
        }

        /** {@code 422 missing_parents} with {@code detail} listing the ids, base64, joined by commas. */
        static ApiError missing(List<byte[]> ids) {
            ApiError base = reject(AvpRules.MISSING_PARENTS);
            if (ids.isEmpty()) {
                return base;
            }
            List<String> parts = new ArrayList<>();
            for (byte[] id : ids) {
                parts.add(AvpEncoding.base64(id));
            }
            return new ApiError(base.status, base.code, base.getMessage(), String.join(",", parts), null);
        }

        Map<String, Object> body() {
            // The keys in the order the Rust host writes them (sorted).
            Map<String, Object> o = new LinkedHashMap<>();
            if (code != null) {
                o.put("code", code);
            }
            if (detail != null) {
                o.put("detail", detail);
            }
            o.put("error", getMessage());
            return o;
        }
    }

    // ─── Decoding ───────────────────────────────────────────────────────────────────────

    private interface Decoder<T> {
        T run() throws AvpException;
    }

    /** Runs a decoder; any malformed value, missing field, wrong type, or bad base64 is {@code 400}. */
    static <T> T decode(Decoder<T> d) throws ApiError {
        try {
            return d.run();
        } catch (AvpException | RuntimeException e) {
            throw ApiError.badRequest("malformed body: " + e.getMessage());
        }
    }

    /** Parses a JSON object body that may hold only {@code fields}. */
    static Map<String, Object> strict(byte[] body, String... fields) throws ApiError {
        Map<String, Object> o = decode(() -> AvpJson.object(AvpJson.parse(body), "body"));
        Set<String> allowed = Set.of(fields);
        for (String k : o.keySet()) {
            if (!allowed.contains(k)) {
                throw ApiError.badRequest("malformed body: unknown field `" + k + "`");
            }
        }
        return o;
    }

    /** An optional field: absent and {@code null} both mean none. */
    static Object optional(Map<String, Object> o, String key) {
        return o.get(key);
    }

    static byte[] key32(Map<String, Object> o, String key) throws AvpException {
        return AvpEncoding.fromBase64(AvpJson.string(o, key), 32);
    }

    // ─── Starting and stopping ──────────────────────────────────────────────────────────

    /**
     * Binds {@code port} and serves the client-facing API and the host routes, and starts replication with
     * {@code cfg.peers()}.
     *
     * @param port the port, or {@code 0} for one the OS chooses (read it from the returned server)
     * @param cfg the configuration
     * @return the running server
     * @throws IOException if the port cannot be bound
     */
    public static HttpServer start(int port, ServerConfig cfg) throws IOException {
        Host host;
        try {
            host = new Host(cfg);
        } catch (AvpException e) {
            throw new IOException("bad host seed", e);
        }
        HttpServer http = HttpServer.create(new InetSocketAddress(cfg.bindHost(), port), 64);
        http.createContext("/", ex -> exchange(ex, host));
        AtomicInteger n = new AtomicInteger();
        host.pool = Executors.newFixedThreadPool(WORKERS, r -> {
            Thread t = new Thread(r, "avp-worker-" + n.getAndIncrement());
            t.setDaemon(true);
            return t;
        });
        http.setExecutor(host.pool);
        http.start();
        HOSTS.put(http, host);
        peerWith(http, cfg.peers());
        return http;
    }

    /**
     * The state of a running server, for in-process tests.
     *
     * @param http a server from {@link #start(int, ServerConfig)}
     * @return its state
     */
    static Host host(HttpServer http) {
        Host h = HOSTS.get(http);
        if (h == null) {
            throw new IllegalArgumentException("not a running AVP host");
        }
        return h;
    }

    /**
     * Installs {@code peers} as the host's peer list and (re)starts one replication worker per peer.
     *
     * @param http a running server
     * @param peers the new peer list; empty stops replication
     */
    static void peerWith(HttpServer http, Replication.Peers peers) {
        Host h = host(http);
        synchronized (h) {
            if (h.running != null) {
                h.running.close();
            }
            h.running = Replication.run(h, peers);
        }
    }

    /**
     * Stops replication, the listener, and the request threads.
     *
     * @param http a running server; a stopped one is ignored
     */
    static void stop(HttpServer http) {
        Host h = HOSTS.remove(http);
        if (h == null) {
            return;
        }
        synchronized (h) {
            if (h.running != null) {
                h.running.close();
                h.running = null;
            }
        }
        http.stop(0);
        h.pool.shutdownNow();
    }

    /**
     * Parses {@code AVP_HOST_SEED}: exactly 64 hex digits (spaces around them ignored), the 32-byte Ed25519
     * seed of the host key.
     *
     * @param hex the text
     * @return the seed
     * @throws IllegalArgumentException naming the problem
     */
    static byte[] parseHostSeed(String hex) {
        String text = hex.trim();
        if (text.length() != 64 || !text.chars().allMatch(c -> c < 128)) {
            throw new IllegalArgumentException("AVP_HOST_SEED must be 64 hex digits (32 bytes)");
        }
        byte[] out = new byte[32];
        for (int i = 0; i < 32; i++) {
            int hi = hexDigit(text.charAt(2 * i));
            int lo = hexDigit(text.charAt(2 * i + 1));
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("AVP_HOST_SEED has a non-hex digit");
            }
            out[i] = (byte) (hi << 4 | lo);
        }
        return out;
    }

    /**
     * Parses {@code AVP_BIND}: the IP address the binary listens on. Only an IPv4 or IPv6 literal is taken
     * (a host name or an address with a port is refused), so parsing never does a name lookup.
     *
     * @param text the text, or {@code null} when unset for {@link #DEFAULT_BIND}
     * @return the address in its numeric form
     * @throws IllegalArgumentException naming the variable
     */
    static String parseBind(String text) {
        String t = text == null ? DEFAULT_BIND : text.trim();
        boolean v4 = t.matches(IPV4_PART + "(?:\\." + IPV4_PART + "){3}");
        boolean v6 = t.contains(":") && t.matches("[0-9A-Fa-f:.]+");
        if (v4 || v6) {
            try {
                return InetAddress.getByName(t).getHostAddress();
            } catch (UnknownHostException e) {
                // Not a valid literal: refused below.
            }
        }
        throw new IllegalArgumentException("AVP_BIND must be an IP address, for example 127.0.0.1");
    }

    private static int hexDigit(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        return -1;
    }

    /**
     * The binary: listens on {@code $AVP_BIND:$PORT} (default {@code 0.0.0.0:8787}) and replicates with
     * {@code AVP_PEERS}. A bad value exits with code 1 and a message.
     *
     * @param args ignored
     */
    public static void main(String[] args) {
        int port = DEFAULT_PORT;
        String portText = System.getenv("PORT");
        if (portText != null) {
            try {
                port = Integer.parseInt(portText.trim());
            } catch (NumberFormatException e) {
                port = -1;
            }
            if (port < 0 || port > 65535) {
                System.err.println("PORT must be a port number");
                System.exit(1);
            }
        }
        String bind;
        try {
            bind = parseBind(System.getenv("AVP_BIND"));
        } catch (IllegalArgumentException e) {
            System.err.println(e.getMessage());
            System.exit(1);
            return;
        }
        byte[] seed;
        String seedText = System.getenv("AVP_HOST_SEED");
        try {
            seed = seedText == null ? AvpCrypto.randomBytes(32) : parseHostSeed(seedText);
        } catch (IllegalArgumentException e) {
            System.err.println(e.getMessage());
            System.exit(1);
            return;
        }
        Replication.Peers peers;
        try {
            String peersText = System.getenv("AVP_PEERS");
            peers = Replication.Peers.fromEnv(peersText == null ? "" : peersText);
        } catch (AvpException e) {
            System.err.println(e.getMessage());
            System.exit(1);
            return;
        }
        String control = System.getenv("AVP_TEST_CONTROL");
        Replication.Config d = Replication.Config.defaults();
        Replication.Config config = new Replication.Config(
                d.sweepIntervalMs(),
                d.requestTimeoutMs(),
                d.maxResponseBytes(),
                control != null && control.trim().equals("1"));
        HttpServer http;
        try {
            http = start(port, new ServerConfig(bind, seed, peers, new Limits(), config));
        } catch (IOException e) {
            System.err.println("cannot listen on " + bind + " port " + port + ": " + e.getMessage());
            System.exit(1);
            return;
        }
        Host h = host(http);
        InetAddress bound = http.getAddress().getAddress();
        String shown = bound instanceof Inet6Address ? "[" + bound.getHostAddress() + "]" : bound.getHostAddress();
        System.out.println("AVP 0.5 reference host listening on http://" + shown + ":"
                + http.getAddress().getPort()
                + ", host key " + AvpEncoding.base64(h.hostKey) + ", " + peers.size() + " peer(s)");
    }

    // ─── One exchange ───────────────────────────────────────────────────────────────────

    /** A request read off the wire. */
    private record Incoming(
            String method,
            String path,
            String authorization,
            String hostKey,
            String hostTime,
            String hostSig,
            byte[] body) {}

    /** Handles one request end to end; every outcome is a response, never an escaped exception. */
    private static void exchange(HttpExchange ex, Host host) {
        int status;
        Object value;
        Long retryAfter = null;
        try {
            try {
                value = handle(read(ex, host), host);
                status = 200;
            } catch (ApiError e) {
                status = e.status;
                value = e.body();
                retryAfter = e.retryAfterS;
            }
        } catch (RuntimeException e) {
            // A broken state or a bug, not the caller's fault. Nothing about the request is logged.
            status = 500;
            value = Map.of("error", "internal error");
            retryAfter = null;
        }
        byte[] bytes;
        try {
            bytes = AvpJson.writeUtf8(value);
        } catch (RuntimeException e) {
            status = 500;
            bytes = "{\"error\":\"internal error\"}".getBytes(StandardCharsets.UTF_8);
        }
        try {
            ex.getResponseHeaders().set("Content-Type", "application/json");
            if (retryAfter != null) {
                ex.getResponseHeaders().set("Retry-After", Long.toString(retryAfter));
            }
            ex.sendResponseHeaders(status, bytes.length);
            try (OutputStream out = ex.getResponseBody()) {
                out.write(bytes);
            }
        } catch (IOException e) {
            // A client that hung up is not an error for the host.
        } finally {
            ex.close();
        }
    }

    /** Reads the request line, the headers it needs, and the body up to the size limit. */
    private static Incoming read(HttpExchange ex, Host host) throws ApiError {
        int max;
        host.lock();
        try {
            max = host.limits.maxBodyBytes;
        } finally {
            host.unlock();
        }
        String length = ex.getRequestHeaders().getFirst("Content-Length");
        if (length != null) {
            try {
                if (Long.parseLong(length.trim()) > max) {
                    throw ApiError.tooLarge();
                }
            } catch (NumberFormatException e) {
                throw ApiError.badRequest("bad Content-Length");
            }
        }
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        try (InputStream in = ex.getRequestBody()) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                body.write(buf, 0, n);
                if (body.size() > max) {
                    throw ApiError.tooLarge();
                }
            }
        } catch (IOException e) {
            throw ApiError.badRequest("unreadable request body");
        }
        String path = ex.getRequestURI().getRawPath();
        var h = ex.getRequestHeaders();
        return new Incoming(
                ex.getRequestMethod(),
                path == null ? "" : path,
                h.getFirst("Authorization"),
                h.getFirst(Replication.HEADER_KEY),
                h.getFirst(Replication.HEADER_TIME),
                h.getFirst(Replication.HEADER_SIGNATURE),
                body.toByteArray());
    }

    // ─── Routing ────────────────────────────────────────────────────────────────────────

    private enum Kind {
        DISCOVERY,
        CHALLENGE,
        TOKEN,
        CREATE_REPO,
        PREPARE_JOIN,
        REPO,
        HOST,
        TEST_CONTROL
    }

    private record Route(Kind kind, String repoId, String op) {}

    private static Route parseRoute(String method, String path) throws ApiError {
        if (method.equals("GET") && path.equals("/.well-known/avp")) {
            return new Route(Kind.DISCOVERY, null, null);
        }
        if (!method.equals("POST")) {
            throw ApiError.notFound("no such route");
        }
        switch (path) {
            case "/api/auth/keypair/challenge":
                return new Route(Kind.CHALLENGE, null, null);
            case "/api/auth/keypair/token":
                return new Route(Kind.TOKEN, null, null);
            case "/v1/repos":
                return new Route(Kind.CREATE_REPO, null, null);
            case "/v1/prepare-join":
                return new Route(Kind.PREPARE_JOIN, null, null);
            case "/v1/test/replication":
                return new Route(Kind.TEST_CONTROL, null, null);
            default:
                break;
        }
        String hostPrefix = "/v1/host/repos/";
        if (path.startsWith(hostPrefix)) {
            String[] parts = splitOnce(path.substring(hostPrefix.length()));
            if (parts == null || !Set.of("heads", "fetch", "offer").contains(parts[1])) {
                throw ApiError.notFound("no such route");
            }
            return new Route(Kind.HOST, percentDecode(parts[0]), parts[1]);
        }
        String repoPrefix = "/v1/repos/";
        if (!path.startsWith(repoPrefix)) {
            throw ApiError.notFound("no such route");
        }
        String[] parts = splitOnce(path.substring(repoPrefix.length()));
        if (parts == null || !Set.of("pull", "push", "manifest", "leave").contains(parts[1])) {
            throw ApiError.notFound("no such route");
        }
        // The host routes on the escaped path and decodes the segment (SPEC 10.2, 12.4).
        return new Route(Kind.REPO, percentDecode(parts[0]), parts[1]);
    }

    private static String[] splitOnce(String rest) {
        int slash = rest.indexOf('/');
        return slash < 0 ? null : new String[] {rest.substring(0, slash), rest.substring(slash + 1)};
    }

    /** Decodes one percent-encoded path segment; a bad escape or a non-UTF-8 result is {@code 400}. */
    static String percentDecode(String segment) throws ApiError {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int i = 0;
        while (i < segment.length()) {
            char c = segment.charAt(i);
            if (c == '%') {
                if (i + 2 >= segment.length()) {
                    throw ApiError.badRequest("bad percent-encoding in path");
                }
                int hi = hexDigit(segment.charAt(i + 1));
                int lo = hexDigit(segment.charAt(i + 2));
                if (hi < 0 || lo < 0) {
                    throw ApiError.badRequest("bad percent-encoding in path");
                }
                out.write(hi << 4 | lo);
                i += 3;
            } else {
                byte[] b = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
                out.write(b, 0, b.length);
                i++;
            }
        }
        try {
            return StandardCharsets.UTF_8
                    .newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(out.toByteArray()))
                    .toString();
        } catch (CharacterCodingException e) {
            throw ApiError.badRequest("bad percent-encoding in path");
        }
    }

    private static Object handle(Incoming req, Host host) throws ApiError {
        Route route = parseRoute(req.method(), req.path());
        if (route.kind() == Kind.HOST && route.op().equals("offer")) {
            // An offer of a first copy is validated outside the state lock (SPEC 9.2).
            return hostOffer(host, req, route.repoId());
        }
        host.lock();
        try {
            byte[] body = req.body();
            switch (route.kind()) {
                case DISCOVERY:
                    return discovery(host);
                case CHALLENGE:
                    return challenge(host, body);
                case TOKEN:
                    return token(host, body);
                case CREATE_REPO:
                    return createRepo(host, authenticate(host, req.authorization()), body);
                case PREPARE_JOIN:
                    return prepareJoin(host, authenticate(host, req.authorization()), body);
                case REPO: {
                    byte[] caller = authenticate(host, req.authorization());
                    return switch (route.op()) {
                        case "pull" -> pull(host, caller, route.repoId(), body);
                        case "push" -> push(host, caller, route.repoId(), body);
                        case "manifest" -> publishManifest(host, caller, route.repoId(), body);
                        default -> leave(host, caller, route.repoId(), body);
                    };
                }
                case HOST: {
                    if (host.paused) {
                        throw ApiError.paused();
                    }
                    // SPEC 9.3: signed over the method, the path as sent, and the exact body bytes.
                    byte[] peer = Replication.authenticate(
                            host, req.method(), req.path(), body, req.hostKey(), req.hostTime(), req.hostSig());
                    if (peer == null) {
                        throw ApiError.unauthorized("bad host request signature");
                    }
                    return route.op().equals("heads")
                            ? hostHeads(host, peer, route.repoId(), body)
                            : hostFetch(host, peer, route.repoId(), body);
                }
                case TEST_CONTROL:
                    return testControl(host, body);
                default:
                    throw ApiError.notFound("no such route");
            }
        } finally {
            host.unlock();
        }
    }

    /** The token subject of {@code Authorization: Bearer <token>}; anything else is {@code 401}. */
    private static byte[] authenticate(Host host, String authorization) throws ApiError {
        if (authorization == null) {
            throw ApiError.unauthorized("missing bearer token");
        }
        int space = authorization.indexOf(' ');
        if (space < 0 || !authorization.substring(0, space).equalsIgnoreCase("bearer")) {
            throw ApiError.unauthorized("missing bearer token");
        }
        byte[] subject = host.auth.subject(authorization.substring(space + 1).trim(), host.nowMs());
        if (subject == null) {
            throw ApiError.unauthorized("unknown or expired bearer token");
        }
        return subject;
    }

    // ─── Discovery and authentication (SPEC 11.7, 3.3) ──────────────────────────────────

    private static Object discovery(Host host) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("hostKey", AvpEncoding.base64(host.hostKey));
        o.put("profiles", List.of("http-json"));
        o.put("version", VERSION);
        return o;
    }

    private static Object challenge(Host host, byte[] body) throws ApiError {
        Map<String, Object> o = strict(body, "ed25519PublicKey");
        byte[] key = decode(() -> key32(o, "ed25519PublicKey"));
        byte[] nonce = host.auth.challenge(key, host.nowMs(), host.limits);
        if (nonce == null) {
            throw new ApiError(
                    429,
                    "quota_exceeded",
                    "too many outstanding challenges for this key",
                    null,
                    CHALLENGE_TTL_MS / 1000);
        }
        return Map.of("nonce", AvpEncoding.base64(nonce));
    }

    private static Object token(Host host, byte[] body) throws ApiError {
        Map<String, Object> o = strict(body, "ed25519PublicKey", "nonce", "signature");
        byte[] key = decode(() -> key32(o, "ed25519PublicKey"));
        byte[] nonce = decode(() -> AvpEncoding.fromBase64(AvpJson.string(o, "nonce")));
        byte[] signature = decode(() -> AvpEncoding.fromBase64(AvpJson.string(o, "signature"), 64));
        return host.auth.token(key, nonce, signature, host.nowMs(), host.limits);
    }

    // ─── createRepo and prepareJoin (SPEC 8.2) ──────────────────────────────────────────

    private static Object createRepo(Host host, byte[] caller, byte[] body) throws ApiError {
        Map<String, Object> o = strict(body, "manifest", "commit");
        AvpManifest.SignedManifest manifest =
                decode(() -> AvpManifest.signedManifestFromJson(AvpJson.required(o, "manifest")));
        AvpCommit.Commit commit = decode(() -> AvpCommit.fromJson(AvpJson.required(o, "commit")));
        AvpManifest.ManifestState s = manifest.state();
        // SPEC 8.2: the authenticated caller MUST equal the genesis ownerKey.
        if (!Arrays.equals(s.ownerKey(), caller)) {
            throw ApiError.forbidden("caller is not the genesis ownerKey");
        }
        // createRepo carries the genesis state (SPEC 6.2, 10.1); any other seq is malformed.
        if (s.manifestSeq() != 1) {
            throw ApiError.badRequest("createRepo needs the genesis state (manifestSeq 1)");
        }
        if (s.members().size() > host.limits.maxMembers) {
            throw ApiError.quota("member limit exceeded");
        }
        // Validate first, on a fresh view: structure, owner signature, repoId recomputation, genesis and
        // first-commit rules, and the hosted check (SPEC 6, 8.2). Only a valid genesis can collide with a
        // held repoId, so a forged one never learns whether that id exists here. The genesis state and its
        // first commit are accepted together or not at all (SPEC 8.2).
        AvpRules.RepoView view = new AvpRules.RepoView(host.hostKey, host.limits.headBound);
        Optional<String> verdict = view.applyManifest(manifest, Optional.of(commit), AvpRules.Via.PUSH);
        if (verdict.isPresent()) {
            throw ApiError.reject(verdict.get());
        }
        AvpManifest.SignedManifest tip = view.tip().orElseThrow(ApiError::internal);
        String repoId = tip.state().repoId();
        if (host.repos.containsKey(repoId)) {
            throw ApiError.of(409, "duplicate_repo", "repository already exists");
        }
        if (host.reposOwnedBy(caller) >= host.limits.maxReposPerOwner) {
            throw ApiError.quota("repository quota for this owner key exceeded");
        }
        if (host.repos.size() >= host.limits.maxRepos) {
            throw ApiError.quota("repository quota of this host exceeded");
        }
        host.repos.put(repoId, view);
        Replication.queueOffer(host, new Replication.Outgoing(repoId, List.of(tip), List.of(commit), List.of()));
        return AvpManifest.toJson(tip);
    }

    /** Whether {@code id} is 22 characters of base64url-nopad over 16 bytes (SPEC 4.2, 12.4). */
    private static boolean isRepoId(String id) {
        if (id.length() != 22) {
            return false;
        }
        try {
            return AvpEncoding.fromBase64Url(id).length == 16;
        } catch (AvpException e) {
            return false;
        }
    }

    private static Object prepareJoin(Host host, byte[] caller, byte[] body) throws ApiError {
        Map<String, Object> o = strict(body, "repoId", "memberKey");
        String repoId = decode(() -> AvpJson.string(o, "repoId"));
        byte[] memberKey = decode(() -> key32(o, "memberKey"));
        if (!isRepoId(repoId)) {
            throw ApiError.badRequest("repoId is not a 22-character base64url id");
        }
        // SPEC 8.2: the authenticated caller MUST equal memberKey.
        if (!Arrays.equals(memberKey, caller)) {
            throw ApiError.forbidden("caller is not memberKey");
        }
        long now = host.nowMs();
        long expiresAt = saturatingAdd(now, ACCEPTANCE_TTL_MS);
        AvpTokens.Acceptance acceptance;
        try {
            acceptance = AvpTokens.signAcceptance(repoId, memberKey, expiresAt, host.seed);
        } catch (AvpException e) {
            throw ApiError.internal();
        }
        if (!host.recordAcceptance(repoId, memberKey, expiresAt, now)) {
            throw ApiError.quota("too many outstanding acceptances for this key");
        }
        return AvpTokens.toJson(acceptance);
    }

    // ─── Repository operations (SPEC 10.1) ──────────────────────────────────────────────

    /**
     * The repository's view: {@code 404 not_found} if not held, {@code 403 not_hosted} if its winning tip
     * does not list this host (SPEC 8.6, 10.1).
     */
    private static AvpRules.RepoView hosted(Host host, String repoId) throws ApiError {
        AvpRules.RepoView view = host.repos.get(repoId);
        if (view == null) {
            throw ApiError.notFound("repository not found");
        }
        if (!view.tipListsHost()) {
            throw ApiError.reject(AvpRules.NOT_HOSTED);
        }
        return view;
    }

    private static AvpManifest.SignedManifest tip(AvpRules.RepoView view) throws ApiError {
        return view.tip().orElseThrow(() -> ApiError.notFound("repository not found"));
    }

    private static List<Object> manifestsJson(List<AvpManifest.SignedManifest> ms) {
        List<Object> out = new ArrayList<>();
        for (AvpManifest.SignedManifest m : ms) {
            out.add(AvpManifest.toJson(m));
        }
        return out;
    }

    private static List<Object> commitsJson(List<AvpCommit.Commit> cs) {
        List<Object> out = new ArrayList<>();
        for (AvpCommit.Commit c : cs) {
            out.add(AvpCommit.toJson(c));
        }
        return out;
    }

    private static List<Object> leavesJson(List<AvpTokens.LeaveRequest> ls) {
        List<Object> out = new ArrayList<>();
        for (AvpTokens.LeaveRequest l : ls) {
            out.add(AvpTokens.toJson(l));
        }
        return out;
    }

    static List<Object> idsJson(List<byte[]> ids) {
        List<Object> out = new ArrayList<>();
        for (byte[] id : ids) {
            out.add(AvpEncoding.base64(id));
        }
        return out;
    }

    private static Object pull(Host host, byte[] caller, String repoId, byte[] body) throws ApiError {
        Map<String, Object> o = strict(body, "sinceManifestSeq", "knownHeads");
        long since = decode(() -> AvpJson.integer(o, "sinceManifestSeq"));
        List<byte[]> known = decode(() -> AvpManifest.ids(o, "knownHeads"));
        AvpRules.RepoView view = hosted(host, repoId);
        // SPEC 10.1: the caller is a member of the tip.
        if (!tip(view).state().hasMember(caller)) {
            throw ApiError.forbidden("caller is not a member of the tip");
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("manifests", manifestsJson(view.manifestsSince(since)));
        out.put("heads", commitsJson(view.commitsSince(known)));
        out.put("leaves", leavesJson(view.leaves()));
        return out;
    }

    private static Object push(Host host, byte[] caller, String repoId, byte[] body) throws ApiError {
        Map<String, Object> o = strict(body, "commit");
        AvpCommit.Commit commit = decode(() -> AvpCommit.fromJson(AvpJson.required(o, "commit")));
        AvpRules.RepoView view = hosted(host, repoId);
        // SPEC 7.1 order: the commit matches the repository and its id and signature verify (400) before
        // the caller check (403).
        if (!commit.repoId().equals(repoId) || !AvpCommit.verify(commit)) {
            throw ApiError.reject(AvpRules.BAD_REQUEST);
        }
        // SPEC 7.1, 10.1: the caller is the author; the engine checks the author is a member of the tip.
        if (!Arrays.equals(commit.author(), caller)) {
            throw ApiError.forbidden("caller is not the commit's author");
        }
        Optional<String> verdict = view.applyCommit(commit, AvpRules.Via.PUSH);
        if (verdict.isPresent()) {
            throw verdict.get().equals(AvpRules.MISSING_PARENTS)
                    ? ApiError.missing(view.missingFor(commit))
                    : ApiError.reject(verdict.get());
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("accepted", true);
        out.put("heads", idsJson(view.heads()));
        Replication.queueOffer(host, new Replication.Outgoing(repoId, List.of(), List.of(commit), List.of()));
        return out;
    }

    private static Object publishManifest(Host host, byte[] caller, String repoId, byte[] body) throws ApiError {
        Map<String, Object> o = strict(body, "manifest", "commit");
        AvpManifest.SignedManifest manifest =
                decode(() -> AvpManifest.signedManifestFromJson(AvpJson.required(o, "manifest")));
        Object commitJson = optional(o, "commit");
        Optional<AvpCommit.Commit> commit =
                commitJson == null ? Optional.empty() : Optional.of(decode(() -> AvpCommit.fromJson(commitJson)));
        AvpRules.RepoView view = hosted(host, repoId);
        // SPEC 10.1: the caller is ownerKey.
        AvpManifest.SignedManifest current = tip(view);
        if (!Arrays.equals(current.state().ownerKey(), caller)) {
            throw ApiError.forbidden("caller is not the ownerKey");
        }
        if (manifest.state().members().size() > host.limits.maxMembers) {
            throw ApiError.quota("member limit exceeded");
        }
        byte[] submitted;
        try {
            submitted = AvpManifest.hash(manifest);
        } catch (AvpException e) {
            submitted = null;
        }
        long tipEpoch = current.state().keyEpoch();
        Optional<String> verdict = view.applyManifest(manifest, commit, AvpRules.Via.PUSH);
        if (verdict.isEmpty()) {
            Object answer = AvpManifest.toJson(tip(view));
            Replication.queueOffer(
                    host,
                    new Replication.Outgoing(
                            repoId, List.of(manifest), commit.map(List::of).orElse(List.of()), List.of()));
            return answer;
        }
        String code = verdict.get();
        if (code.equals(AvpRules.NOT_HOSTED)) {
            // SPEC 6.1 rule 6, 8.6: the state passed every other rule. The host keeps it (its winning tip
            // then no longer lists this host), with only its rotation commit when it raises the epoch: a
            // carried non-rotation commit is not kept, since the offer path skips the caller check and the
            // head bound. It is not offered to peers.
            boolean raising = tipEpoch != Long.MAX_VALUE
                    && tipEpoch + 1 == manifest.state().keyEpoch();
            view.applyManifest(manifest, raising ? commit : Optional.empty(), AvpRules.Via.OFFER);
            throw ApiError.reject(AvpRules.NOT_HOSTED);
        }
        if (code.equals(AvpRules.MISSING_PARENTS)) {
            // The engine rolled the state back, so missingFor also names the state this request carries; it
            // is not missing (the commit was checked against it), so only the ids the host lacks are listed.
            List<byte[]> ids = new ArrayList<>();
            if (commit.isPresent()) {
                for (byte[] id : view.missingFor(commit.get())) {
                    if (submitted == null || !Arrays.equals(id, submitted)) {
                        ids.add(id);
                    }
                }
            }
            throw ApiError.missing(ids);
        }
        throw ApiError.reject(code);
    }

    private static Object leave(Host host, byte[] caller, String repoId, byte[] body) throws ApiError {
        AvpTokens.LeaveRequest request = decode(() -> AvpTokens.leaveFromJson(AvpJson.parse(body)));
        AvpRules.RepoView view = hosted(host, repoId);
        // SPEC 8.4 order: the signature verifies and repoId matches (400), then the caller is memberKey, and
        // memberKey is a member of the tip and not the owner (403, the engine).
        if (!request.repoId().equals(repoId) || !AvpTokens.verifyLeave(request)) {
            throw ApiError.reject(AvpRules.BAD_REQUEST);
        }
        if (!Arrays.equals(request.memberKey(), caller)) {
            throw ApiError.forbidden("caller is not the leaving member");
        }
        Optional<String> verdict = view.applyLeave(request, AvpRules.Via.PUSH);
        if (verdict.isPresent()) {
            throw ApiError.reject(verdict.get());
        }
        Replication.queueOffer(host, new Replication.Outgoing(repoId, List.of(), List.of(), List.of(request)));
        return new LinkedHashMap<String, Object>();
    }

    // ─── Host routes (SPEC 9.1 to 9.3) and the test control ─────────────────────────────

    /** A body repoId must name the path's repository; the field may be left out (SPEC 9.3). */
    private static void sameRepo(Map<String, Object> o, String repoId) throws ApiError {
        Object id = optional(o, "repoId");
        if (id != null && !(id instanceof String s && s.equals(repoId))) {
            throw ApiError.badRequest("body repoId does not match the path");
        }
    }

    /**
     * The view a peer may read: {@code 404 not_found} if not held, {@code 403 not_hosted} if this host's
     * winning tip does not list it, {@code 403 forbidden} if that tip does not list the peer (SPEC 9.2).
     */
    private static AvpRules.RepoView served(Host host, String repoId, byte[] peer) throws ApiError {
        AvpRules.RepoView view = host.repos.get(repoId);
        if (view == null) {
            throw ApiError.notFound("repository not found");
        }
        if (!view.tipListsHost()) {
            throw ApiError.reject(AvpRules.NOT_HOSTED);
        }
        if (view.tip().map(t -> !t.state().hasHost(peer)).orElse(true)) {
            throw ApiError.forbidden("the calling host is not in the repository's hosts");
        }
        return view;
    }

    /** {@code heads} (SPEC 9.1): the verified tip and the head ids; held and pending commits are not heads. */
    private static Object hostHeads(Host host, byte[] peer, String repoId, byte[] body) throws ApiError {
        Map<String, Object> o = strict(body, "repoId");
        sameRepo(o, repoId);
        AvpRules.RepoView view = served(host, repoId, peer);
        AvpManifest.SignedManifest t = tip(view);
        Map<String, Object> tipJson = new LinkedHashMap<>();
        tipJson.put("manifestSeq", t.state().manifestSeq());
        try {
            tipJson.put("manifestHash", AvpEncoding.base64(AvpManifest.hash(t)));
        } catch (AvpException e) {
            throw ApiError.internal();
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("manifestTip", tipJson);
        out.put("heads", idsJson(view.heads()));
        return out;
    }

    /**
     * {@code fetch} (SPEC 9.1): for a manifest hash (winning or verified losing), that state and every
     * state before it, ascending, with the rotation commit of each epoch-raising state among them even
     * while held; for a commit id, that commit if accepted or a rotation commit; every pending leave
     * request. Unknown ids, other held commits, and pending commits are left out.
     */
    private static Object hostFetch(Host host, byte[] peer, String repoId, byte[] body) throws ApiError {
        Map<String, Object> o = strict(body, "repoId", "ids");
        sameRepo(o, repoId);
        List<byte[]> ids = decode(() -> AvpManifest.ids(o, "ids"));
        if (ids.size() > Replication.MAX_ITEMS) {
            throw ApiError.badRequest("too many ids");
        }
        AvpRules.RepoView view = served(host, repoId, peer);
        List<AvpManifest.SignedManifest> manifests = new ArrayList<>();
        List<AvpCommit.Commit> commits = new ArrayList<>();
        Set<String> seenStates = new HashSet<>();
        Set<String> seenCommits = new HashSet<>();
        for (byte[] id : ids) {
            Optional<List<AvpManifest.SignedManifest>> chain = view.chainTo(id);
            if (chain.isPresent()) {
                for (AvpManifest.SignedManifest m : chain.get()) {
                    byte[] h;
                    try {
                        h = AvpManifest.hash(m);
                    } catch (AvpException e) {
                        throw ApiError.internal();
                    }
                    if (!seenStates.add(AvpEncoding.base64(h))) {
                        continue;
                    }
                    Optional<AvpCommit.Commit> rc = view.rotationCommit(h);
                    if (rc.isPresent()
                            && seenCommits.add(AvpEncoding.base64(rc.get().commitId()))) {
                        commits.add(rc.get());
                    }
                    manifests.add(m);
                }
            } else {
                Optional<AvpCommit.Commit> c = view.fetchCommit(id);
                if (c.isPresent() && seenCommits.add(AvpEncoding.base64(c.get().commitId()))) {
                    commits.add(c.get());
                }
            }
        }
        manifests.sort((a, b) -> Long.compare(a.state().manifestSeq(), b.state().manifestSeq()));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("manifests", manifestsJson(manifests));
        out.put("commits", commitsJson(commits));
        out.put("leaves", leavesJson(view.leaves()));
        return out;
    }

    /**
     * {@code offer} (SPEC 9.1, 9.2), with the 503 and signature checks of every host route. A held
     * repository refuses a peer its tip does not list ({@code 403 forbidden}). The items are validated on a
     * trial copy and the received tip decides: {@code 403 not_hosted} if it does not list this host (a held
     * repository keeps the validated states), {@code 403 forbidden} for a first copy whose tip does not list
     * the sender, {@code 429 quota_exceeded} for a first copy over the repository caps, and otherwise the
     * per-item answer. An incomplete offer also queues a catch-up from the sender.
     *
     * <p>A held repository is updated under the state lock. A first copy is private until admitted, so it
     * is validated outside the lock, which is then taken again only to admit it (re-checking that the
     * repository is still not held, and the caps); if another path stored the repository meanwhile, the
     * offer is applied to it as to a held repository.
     */
    private static Object hostOffer(Host host, Incoming req, String repoId) throws ApiError {
        byte[] body = req.body();
        host.lock();
        boolean locked = true;
        try {
            if (host.paused) {
                throw ApiError.paused();
            }
            byte[] peer = Replication.authenticate(
                    host, req.method(), req.path(), body, req.hostKey(), req.hostTime(), req.hostSig());
            if (peer == null) {
                throw ApiError.unauthorized("bad host request signature");
            }
            Map<String, Object> o = strict(body, "repoId", "manifests", "commits", "leaves");
            sameRepo(o, repoId);
            Replication.Items items = decode(() -> Replication.itemsFromJson(o));
            if (!items.bounded()) {
                throw ApiError.badRequest("too many items");
            }
            Boolean listed = senderListed(host, repoId, peer);
            Replication.Received got;
            if (Boolean.FALSE.equals(listed)) {
                throw ApiError.forbidden("the calling host is not in the repository's hosts");
            } else if (Boolean.TRUE.equals(listed)) {
                got = Replication.receive(host, repoId, peer, items, Long.MAX_VALUE);
            } else {
                AvpRules.RepoView fresh = new AvpRules.RepoView(host.hostKey, host.limits.headBound);
                host.unlock();
                locked = false;
                Replication.Kept kept = Replication.applyKept(fresh, repoId, items, false, Long.MAX_VALUE);
                host.lock();
                locked = true;
                host.engineApplications += kept.applied().applications;
                // The test control may have paused the host meanwhile (SPEC 9.3).
                if (host.paused) {
                    throw ApiError.paused();
                }
                Boolean again = senderListed(host, repoId, peer);
                if (Boolean.FALSE.equals(again)) {
                    throw ApiError.forbidden("the calling host is not in the repository's hosts");
                } else if (Boolean.TRUE.equals(again)) {
                    got = Replication.receive(host, repoId, peer, items, Long.MAX_VALUE);
                } else if (kept.applied().hasGap()) {
                    got = new Replication.Received(Replication.Admitted.INCOMPLETE, kept.applied());
                } else {
                    got = new Replication.Received(
                            Replication.admitFirstCopy(host, repoId, peer, kept.view()), kept.applied());
                }
            }
            if (got.applied().incomplete || got.admitted() == Replication.Admitted.INCOMPLETE) {
                Replication.queueCatchup(host, peer, repoId);
            }
            return switch (got.admitted()) {
                case HOSTED, INCOMPLETE -> got.applied().reply();
                case NOT_HOSTED -> throw ApiError.reject(AvpRules.NOT_HOSTED);
                case FORBIDDEN -> throw ApiError.forbidden("the sending host is not in the repository's hosts");
                case QUOTA -> throw ApiError.quota("repository quota exceeded");
            };
        } finally {
            if (locked) {
                host.unlock();
            }
        }
    }

    /** Whether the held repository's tip lists {@code peer}; {@code null} when the repository is not held. */
    private static Boolean senderListed(Host host, String repoId, byte[] peer) {
        AvpRules.RepoView view = host.repos.get(repoId);
        if (view == null) {
            return null;
        }
        return view.tip().map(t -> t.state().hasHost(peer)).orElse(false);
    }

    /** {@code POST /v1/test/replication { paused }} (SPEC 9.3), only with {@code AVP_TEST_CONTROL=1}. */
    private static Object testControl(Host host, byte[] body) throws ApiError {
        if (!host.replication.testControl()) {
            throw ApiError.notFound("no such route");
        }
        Map<String, Object> o = strict(body, "paused");
        boolean paused = decode(() -> AvpJson.bool(o, "paused"));
        host.paused = paused;
        if (!paused) {
            host.kick++;
        }
        host.wake.signalAll();
        return Map.of("paused", paused);
    }
}
