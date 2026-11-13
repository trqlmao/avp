/*
 * AVP 0.5 reference client, HTTP/JSON profile: one member device's copy of one repository, over the
 * shared Java avp sources.
 *
 * SPDX-License-Identifier: MIT
 */

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BiConsumer;
import java.util.function.Predicate;

/**
 * One member device's copy of one repository, synced through its home host (SPEC 5 to 8, 10, 11).
 *
 * <p>The client never trusts a host's acceptance (SPEC 7.5). It keeps its own verified manifest chain
 * ({@link Chain}), pins its highest verified state and refuses a rollback (SPEC 6.4), checks every pulled
 * commit itself, merges every head it can read and pushes the merge (SPEC 5), leaves an unreadable head
 * alone (SPEC 7.5), retains every epoch's data key so it can merge old-epoch heads forward, and strips
 * {@code refreshToken} and {@code expiresAt} unless the signed policy is {@code true} (SPEC 5.1). The owner
 * operations of SPEC 8 (invite, remove, policy, leave processing) build and sign new states here.
 *
 * <p>Every host answer is untrusted input: no unchecked exception escapes on one, and a state or commit
 * that fails a check is discarded rather than used. No secret (the phrase, its entropy or seed, a private
 * key, a data key, a plaintext) is ever sent to a host.
 *
 * <p>The class is shaped for a game-client library: it holds no static mutable state, and every operation
 * that talks to a host returns a {@link CompletableFuture} that completes on the vault's executor (a new
 * virtual thread per operation unless the caller supplies one). A failed future completes with a {@link
 * CompletionException} whose cause is a {@link ClientException}. Operations on one vault run one at a time,
 * in the order they start. Illustrative reference code, not production: keys live in memory, nothing is
 * persisted, and there is no TLS.
 */
public final class Vault implements AutoCloseable {

    /** The largest host answer the client reads (16 MiB); a larger one is a transport error. */
    public static final int MAX_RESPONSE_BYTES = 16 * 1024 * 1024;

    /** How often a write is retried on {@code 422 missing_parents}, the only retryable error (SPEC 10.4). */
    static final int MISSING_PARENTS_RETRIES = 40;

    /** The pause between tries while a host fetches missing parents from its peers. */
    static final long RETRY_PAUSE_MS = 100;

    /** How often an owner rebuilds a publication on {@code 409 manifest_conflict} (SPEC 6.3). */
    static final int CONFLICT_RETRIES = 3;

    /** A token is renewed this long before it expires. */
    static final long TOKEN_SLACK_MS = 30_000;

    /** The timeout of one HTTP exchange. */
    static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

    private final ReentrantLock lock = new ReentrantLock();
    private final Executor executor;
    private final HostClient host;
    private final Member me;
    private Chain chain;
    /** Every data key this device has held, by keyEpoch, so it can read old-epoch heads (SPEC 7.5). */
    private final Map<Long, byte[]> retained = new HashMap<>();

    private Map<String, Object> local = emptyPayload();
    private final AvpPayload.Hlc hlc = new AvpPayload.Hlc();
    private List<byte[]> heads = new ArrayList<>();
    private List<byte[]> unreadable = new ArrayList<>();
    private List<Map<String, Object>> incoming = new ArrayList<>();
    /** The ancestry this device learned of each verified commit, by base64 id. */
    private final Map<String, Seen> seen = new HashMap<>();

    private List<AvpTokens.LeaveRequest> leaves = new ArrayList<>();
    private boolean left;

    private record Seen(byte[] author, List<byte[]> parents) {}

    private Vault(HostClient host, Member me, Chain chain, Executor executor) {
        this.host = host;
        this.me = me;
        this.chain = chain;
        this.executor = executor;
    }

    // ─── Errors ─────────────────────────────────────────────────────────────────────────────

    /** Every failure of the client, categorized by {@link Kind}. Messages never carry secret material. */
    public static final class ClientException extends Exception {

        private static final long serialVersionUID = 1L;

        /** The category of a failure. */
        public enum Kind {
            /** The host could not be reached, the connection failed, or the answer was too large. */
            TRANSPORT,
            /** The host answered with a non-2xx status and, usually, the SPEC 10.4 error body. */
            HOST,
            /** A host answer that does not decode as the route's response. */
            BAD_RESPONSE,
            /** A construction of the shared avp sources failed. */
            AVP,
            /** A manifest state failed a SPEC 6 check and was not used. */
            STATE_REJECTED,
            /** A commit failed a SPEC 7.5 check and was discarded. */
            COMMIT_REJECTED,
            /** An invite token failed the SPEC 8.2 owner verification. */
            INVITE_REFUSED,
            /** The host's discovery key is not the key the client expected (SPEC 3.3, 11.7). */
            HOST_KEY_MISMATCH,
            /** The operation needs a role this device does not have (owner, member). */
            NOT_PERMITTED,
            /** No data key is held for the epoch. */
            NO_KEY,
            /** This member left the repository and no longer syncs (SPEC 8.4). */
            LEFT,
            /** The owner did not confirm the device link code (SPEC 11.6). */
            LINK_NOT_CONFIRMED,
            /** The genesis owner key does not match the repo locator's fingerprint (SPEC 11.2). */
            OWNER_MISMATCH,
            /** A step of the worked flow did not end as expected. */
            FLOW
        }

        private final Kind kind;
        private final int status;
        private final String code;

        /**
         * A failure of the given kind.
         *
         * @param kind the category
         * @param message a description free of secret material
         */
        public ClientException(Kind kind, String message) {
            this(kind, message, 0, null, null);
        }

        /**
         * A failure of the given kind with its cause.
         *
         * @param kind the category
         * @param message a description free of secret material
         * @param cause the underlying failure
         */
        public ClientException(Kind kind, String message, Throwable cause) {
            this(kind, message, 0, null, cause);
        }

        private ClientException(Kind kind, String message, int status, String code, Throwable cause) {
            super(message, cause);
            this.kind = kind;
            this.status = status;
            this.code = code;
        }

        static ClientException host(int status, String code, String message) {
            String text = "host answered " + status + " " + (code == null ? "(no code)" : code) + ": " + message;
            return new ClientException(Kind.HOST, text, status, code, null);
        }

        static ClientException avp(AvpException e) {
            return new ClientException(Kind.AVP, e.getMessage(), e);
        }

        /**
         * The category of the failure.
         *
         * @return the kind
         */
        public Kind kind() {
            return kind;
        }

        /**
         * The HTTP status of a {@link Kind#HOST} failure.
         *
         * @return the status, or {@code 0} for any other kind
         */
        public int status() {
            return status;
        }

        /**
         * The host's machine error code ({@code forbidden}, {@code manifest_conflict}, ...), when this is a
         * host answer that carries one (SPEC 10.4).
         *
         * @return the code, or empty
         */
        public Optional<String> code() {
            return Optional.ofNullable(code);
        }
    }

    // ─── Async plumbing ─────────────────────────────────────────────────────────────────────

    /** A blocking step that fails with the client's exception. */
    @FunctionalInterface
    interface Op<T> {
        T run() throws ClientException;
    }

    /**
     * The default executor: one new virtual thread per operation. A stateless method, so the class holds
     * no executor of its own and nothing needs shutting down.
     *
     * @param task the operation
     */
    static void virtualThread(Runnable task) {
        Thread.ofVirtual().name("avp-client").start(task);
    }

    static <T> CompletableFuture<T> async(Executor executor, Op<T> op) {
        return CompletableFuture.supplyAsync(
                () -> {
                    try {
                        return op.run();
                    } catch (ClientException e) {
                        throw new CompletionException(e);
                    }
                },
                executor);
    }

    /** Runs {@code op} on this vault's executor, one operation at a time. */
    private <T> CompletableFuture<T> locked(Op<T> op) {
        return async(executor, () -> {
            lock.lock();
            try {
                return op.run();
            } finally {
                lock.unlock();
            }
        });
    }

    /** Reads local state under the vault lock. */
    private <T> T read(java.util.function.Supplier<T> f) {
        lock.lock();
        try {
            return f.get();
        } finally {
            lock.unlock();
        }
    }

    /**
     * The client's wall clock in epoch milliseconds.
     *
     * @return the current time
     */
    public static long nowMs() {
        return System.currentTimeMillis();
    }

    private static long saturatingAdd(long a, long b) {
        long r = a + b;
        return ((a ^ r) & (b ^ r)) < 0 ? (a < 0 ? Long.MIN_VALUE : Long.MAX_VALUE) : r;
    }

    private static boolean ctEq(byte[] a, byte[] b) {
        return AvpCrypto.constantTimeEquals(a, b);
    }

    private static String b64(byte[] b) {
        return AvpEncoding.base64(b);
    }

    // ─── Member identity ────────────────────────────────────────────────────────────────────

    /**
     * A member identity: a per-device Ed25519 and X25519 key pair (SPEC 3.2). The owner is the member whose
     * keys derive from the phrase ({@link #fromOwner(AvpOwner.OwnerKeys)}).
     */
    public static final class Member {
        private final byte[] signingSeed;
        private final byte[] ed25519Public;
        private final byte[] x25519Private;
        private final byte[] x25519Public;

        private Member(byte[] signingSeed, byte[] ed25519Public, byte[] x25519Private, byte[] x25519Public) {
            this.signingSeed = signingSeed.clone();
            this.ed25519Public = ed25519Public.clone();
            this.x25519Private = x25519Private.clone();
            this.x25519Public = x25519Public.clone();
        }

        /**
         * A fresh member identity from the CSPRNG.
         *
         * @return the identity
         * @throws ClientException of kind {@link ClientException.Kind#AVP} if a key cannot be derived
         */
        public static Member generate() throws ClientException {
            byte[] seed = AvpCrypto.randomBytes(32);
            byte[] x = AvpCrypto.randomBytes(32);
            try {
                return new Member(seed, AvpCrypto.ed25519Public(seed), x, AvpCrypto.x25519Public(x));
            } catch (AvpException e) {
                throw ClientException.avp(e);
            }
        }

        /**
         * The owner's member identity (SPEC 3.1: the owner is one member entry).
         *
         * @param owner the owner keys
         * @return the identity
         */
        public static Member fromOwner(AvpOwner.OwnerKeys owner) {
            return new Member(owner.ed25519Seed(), owner.ed25519Public(), owner.x25519Private(), owner.x25519Public());
        }

        /**
         * The Ed25519 public key, the member id.
         *
         * @return a copy of the 32-byte key
         */
        public byte[] ed25519Public() {
            return ed25519Public.clone();
        }

        /**
         * The X25519 public key the data key is wrapped to.
         *
         * @return a copy of the 32-byte key
         */
        public byte[] x25519Public() {
            return x25519Public.clone();
        }

        /**
         * The Ed25519 seed. A secret: it never leaves the device.
         *
         * @return a copy of the 32-byte seed
         */
        public byte[] signingSeed() {
            return signingSeed.clone();
        }

        /**
         * The X25519 private key. A secret: it never leaves the device.
         *
         * @return a copy of the 32-byte scalar
         */
        public byte[] x25519Private() {
            return x25519Private.clone();
        }

        /**
         * The member id written into stamps ({@code by}): the base64 Ed25519 public key.
         *
         * @return the id
         */
        public String id() {
            return b64(ed25519Public);
        }

        /**
         * The key fingerprint to show and compare (SPEC 3.2).
         *
         * @return {@code xxxx-xxxx-xxxx-xxxx}
         */
        public String fingerprint() {
            return AvpTokens.keyFingerprint(ed25519Public, x25519Public);
        }

        /** The member id only; never a private key. */
        @Override
        public String toString() {
            return "Member[" + id() + "]";
        }
    }

    // ─── Owner identity and device linking (SPEC 3.1, 11.6) ─────────────────────────────────

    /**
     * An owner identity: the BIP39 entropy and the owner keys derived from it (SPEC 3.1). It is a secret: the
     * client shows the phrase once at creation and never sends the phrase, the entropy, the seed, or a
     * private key to a host.
     */
    public static final class OwnerIdentity {
        private final byte[] entropy;
        private final AvpOwner.OwnerKeys keys;

        private OwnerIdentity(byte[] entropy, AvpOwner.OwnerKeys keys) {
            this.entropy = entropy.clone();
            this.keys = keys;
        }

        /**
         * A new identity from 32 bytes of CSPRNG entropy.
         *
         * @return the identity
         * @throws ClientException of kind {@link ClientException.Kind#AVP} if the derivation fails
         */
        public static OwnerIdentity generate() throws ClientException {
            return fromEntropy(AvpCrypto.randomBytes(32));
        }

        /**
         * The identity of a 24-word phrase.
         *
         * @param phrase the mnemonic
         * @return the identity
         * @throws ClientException of kind {@link ClientException.Kind#AVP} if the phrase is not 24 words of
         *     the English list or fails the checksum (SPEC 3.1)
         */
        public static OwnerIdentity fromMnemonic(String phrase) throws ClientException {
            try {
                return fromEntropy(AvpOwner.mnemonicToEntropy(phrase));
            } catch (AvpException e) {
                throw ClientException.avp(e);
            }
        }

        /**
         * The identity of 32 bytes of entropy: the mnemonic, its seed, then the owner keys.
         *
         * @param entropy the entropy
         * @return the identity
         * @throws ClientException of kind {@link ClientException.Kind#AVP} if the entropy is not 32 bytes
         */
        public static OwnerIdentity fromEntropy(byte[] entropy) throws ClientException {
            try {
                return new OwnerIdentity(entropy, AvpOwner.fromEntropy(entropy));
            } catch (AvpException e) {
                throw ClientException.avp(e);
            }
        }

        /**
         * The 32 bytes of mnemonic entropy; a device link grant carries exactly these (SPEC 11.6).
         *
         * @return a copy
         */
        public byte[] entropy() {
            return entropy.clone();
        }

        /**
         * The owner Ed25519 and X25519 keys.
         *
         * @return the keys
         */
        public AvpOwner.OwnerKeys keys() {
            return keys;
        }

        /**
         * The 24-word phrase. A client shows it once, at creation (SPEC 3.1).
         *
         * @return the phrase
         * @throws ClientException of kind {@link ClientException.Kind#AVP} if the wordlist cannot be read
         */
        public String mnemonic() throws ClientException {
            try {
                return AvpOwner.entropyToMnemonic(entropy);
            } catch (AvpException e) {
                throw ClientException.avp(e);
            }
        }

        /** The owner key only; never the phrase or a private key. */
        @Override
        public String toString() {
            return "OwnerIdentity[" + b64(keys.ed25519Public()) + "]";
        }
    }

    /**
     * The new device's side of an owner device link (SPEC 11.6 steps 1 and 4), and the existing device's
     * side in {@link #approve(byte[], AvpTokens.LinkRequest, Predicate)}.
     */
    public static final class LinkSession {
        private final byte[] ephemeral;
        private final AvpTokens.LinkRequest request;
        private boolean finished;

        private LinkSession(byte[] ephemeral, AvpTokens.LinkRequest request) {
            this.ephemeral = ephemeral;
            this.request = request;
        }

        /**
         * A fresh ephemeral X25519 key pair and its link request.
         *
         * @return the session
         * @throws ClientException of kind {@link ClientException.Kind#AVP} if the key cannot be derived
         */
        public static LinkSession start() throws ClientException {
            byte[] e = AvpCrypto.randomBytes(32);
            try {
                return new LinkSession(e, new AvpTokens.LinkRequest(AvpCrypto.x25519Public(e)));
            } catch (AvpException ex) {
                throw ClientException.avp(ex);
            }
        }

        /**
         * The link request to show, as a token, out of band.
         *
         * @return the request
         */
        public AvpTokens.LinkRequest request() {
            return request;
        }

        /**
         * The 6-digit confirmation code this device shows.
         *
         * @return the code
         * @throws ClientException of kind {@link ClientException.Kind#AVP} if it cannot be computed
         */
        public String confirmationCode() throws ClientException {
            try {
                return AvpTokens.linkConfirmationCode(request.ephemeralPublicKey());
            } catch (AvpException e) {
                throw ClientException.avp(e);
            }
        }

        /**
         * Opens a grant with the ephemeral key, which is then discarded, and derives the identity: the same
         * phrase and owner keys as the granting device. A session finishes once.
         *
         * @param grant the link grant
         * @return the owner identity
         * @throws ClientException of kind {@link ClientException.Kind#AVP} if the grant does not unwrap under
         *     {@code avp/owner-link/v1} with this session's key (a grant for another device, a tampered
         *     grant, another label), and of kind {@link ClientException.Kind#NOT_PERMITTED} if the session
         *     already finished
         */
        public synchronized OwnerIdentity finish(AvpTokens.LinkGrant grant) throws ClientException {
            if (finished) {
                throw new ClientException(ClientException.Kind.NOT_PERMITTED, "this link session already finished");
            }
            try {
                byte[] entropy = AvpTokens.openLinkGrant(grant, ephemeral);
                finished = true;
                Arrays.fill(ephemeral, (byte) 0);
                return OwnerIdentity.fromEntropy(entropy);
            } catch (AvpException e) {
                throw ClientException.avp(e);
            }
        }

        /**
         * The existing device's side (SPEC 11.6 steps 2 and 3): computes the request's confirmation code,
         * shows it to the owner through {@code confirm}, and only if the owner confirms that it matches the
         * code on the new device, wraps the entropy to the request's ephemeral key.
         *
         * @param entropy the owner's 32-byte mnemonic entropy
         * @param request the new device's link request
         * @param confirm shows the code and answers whether the owner confirmed it
         * @return the link grant
         * @throws ClientException of kind {@link ClientException.Kind#LINK_NOT_CONFIRMED} if {@code confirm}
         *     answers {@code false}, and of kind {@link ClientException.Kind#AVP} if the wrap fails
         */
        public static AvpTokens.LinkGrant approve(
                byte[] entropy, AvpTokens.LinkRequest request, Predicate<String> confirm) throws ClientException {
            try {
                String code = AvpTokens.linkConfirmationCode(request.ephemeralPublicKey());
                if (!confirm.test(code)) {
                    throw new ClientException(
                            ClientException.Kind.LINK_NOT_CONFIRMED, "the link confirmation code was not confirmed");
                }
                return AvpTokens.sealLinkGrant(entropy, request.ephemeralPublicKey());
            } catch (AvpException e) {
                throw ClientException.avp(e);
            }
        }
    }

    // ─── Transport ──────────────────────────────────────────────────────────────────────────

    /**
     * A connection to one host, matched by its host key (SPEC 3.3, 11.7).
     *
     * <p>It caches the bearer token that host minted and presents it only to that host. Every answer is read
     * up to {@link #MAX_RESPONSE_BYTES} (a larger one is a transport error) and decoded as untrusted input;
     * a non-JSON error body (SPEC 10.4 allows a bare {@code 400}) is reported by status alone.
     */
    public static final class HostClient implements AutoCloseable {
        private final String base;
        private final String locator;
        private final byte[] key;
        private final HttpClient http;
        private final Executor executor;
        private final ReentrantLock tokenLock = new ReentrantLock();
        private Token token;

        private record Token(byte[] subject, String value, long expiresAt) {}

        private record Answer(int status, byte[] body) {}

        private HostClient(String base, String locator, byte[] key, HttpClient http, Executor executor) {
            this.base = base;
            this.locator = locator;
            this.key = key;
            this.http = http;
            this.executor = executor;
        }

        /**
         * Connects to the host at {@code url} ({@code http://host:port}) and learns its host key from {@code
         * GET /.well-known/avp} (SPEC 11.7). Operations of this connection run on new virtual threads.
         *
         * @param url the host's base URL
         * @return the connection; fails with {@link ClientException.Kind#TRANSPORT} if the host cannot be
         *     reached, {@link ClientException.Kind#HOST} or {@link ClientException.Kind#BAD_RESPONSE} if
         *     discovery does not answer with a host key
         */
        public static CompletableFuture<HostClient> connect(String url) {
            return connect(url, Vault::virtualThread);
        }

        /**
         * {@link #connect(String)} with the executor this connection's operations run on.
         *
         * @param url the host's base URL
         * @param executor runs each blocking operation
         * @return the connection
         */
        public static CompletableFuture<HostClient> connect(String url, Executor executor) {
            return async(executor, () -> connectNow(url, executor));
        }

        /**
         * Connects to {@code url} and requires its discovery key to be {@code expected} (a key from a token or
         * a manifest's {@code hosts}; hosts are matched by key, never by locator alone, SPEC 11.7).
         *
         * @param url the host's base URL
         * @param expected the expected 32-byte host key
         * @return the connection; fails as {@link #connect(String)}, and with {@link
         *     ClientException.Kind#HOST_KEY_MISMATCH} for another key
         */
        public static CompletableFuture<HostClient> connectExpecting(String url, byte[] expected) {
            byte[] want = expected.clone();
            Executor ex = Vault::virtualThread;
            return async(ex, () -> {
                HostClient h = connectNow(url, ex);
                if (!ctEq(h.key, want)) {
                    h.close();
                    throw new ClientException(
                            ClientException.Kind.HOST_KEY_MISMATCH, "host key does not match the expected key");
                }
                return h;
            });
        }

        static HostClient connectNow(String url, Executor executor) throws ClientException {
            String base = url;
            while (base.endsWith("/")) {
                base = base.substring(0, base.length() - 1);
            }
            String locator = base.startsWith("http://")
                    ? base.substring("http://".length())
                    : base.startsWith("https://") ? base.substring("https://".length()) : base;
            HttpClient http = HttpClient.newBuilder()
                    .version(HttpClient.Version.HTTP_1_1)
                    .connectTimeout(REQUEST_TIMEOUT)
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build();
            try {
                Answer a = call(http, base, "/.well-known/avp", null, null);
                if (a.status() != 200) {
                    throw hostError(a);
                }
                byte[] key;
                try {
                    key = AvpManifest.key32(AvpJson.object(AvpJson.parse(a.body()), "discovery"), "hostKey");
                } catch (AvpException e) {
                    throw badResponse("discovery: " + e.getMessage(), e);
                }
                return new HostClient(base, locator, key, http, executor);
            } catch (ClientException e) {
                http.close();
                throw e;
            }
        }

        /**
         * The host key.
         *
         * @return a copy of the 32-byte key
         */
        public byte[] key() {
            return key.clone();
        }

        /**
         * The locator ({@code host:port}) this client dials.
         *
         * @return the locator
         */
        public String locator() {
            return locator;
        }

        /** Closes the HTTP client; the connection is unusable afterwards. */
        @Override
        public void close() {
            http.close();
        }

        /** One HTTP exchange: the status and the body, read up to the size limit. */
        private static Answer call(HttpClient http, String base, String path, byte[] body, String bearer)
                throws ClientException {
            HttpRequest request;
            try {
                HttpRequest.Builder b =
                        HttpRequest.newBuilder(URI.create(base + path)).timeout(REQUEST_TIMEOUT);
                if (body == null) {
                    b.GET();
                } else {
                    b.POST(HttpRequest.BodyPublishers.ofByteArray(body)).header("Content-Type", "application/json");
                    if (bearer != null) {
                        b.header("Authorization", "Bearer " + bearer);
                    }
                }
                request = b.build();
            } catch (IllegalArgumentException | IllegalStateException e) {
                // A malformed URL from the caller, or a token from the host that is not a header value.
                throw new ClientException(ClientException.Kind.TRANSPORT, "cannot build the request", e);
            }
            try {
                HttpResponse<InputStream> r = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
                try (InputStream in = r.body()) {
                    byte[] bytes = in.readNBytes(MAX_RESPONSE_BYTES + 1);
                    if (bytes.length > MAX_RESPONSE_BYTES) {
                        throw new ClientException(ClientException.Kind.TRANSPORT, "host answer larger than 16 MiB");
                    }
                    return new Answer(r.statusCode(), bytes);
                }
            } catch (IOException | IllegalArgumentException e) {
                throw new ClientException(ClientException.Kind.TRANSPORT, "transport: " + e, e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new ClientException(ClientException.Kind.TRANSPORT, "interrupted", e);
            }
        }

        /** An unauthenticated JSON POST whose 200 answer is a JSON object. */
        private Map<String, Object> postOpen(String path, Map<String, Object> body) throws ClientException {
            Answer a = call(http, base, path, AvpJson.writeUtf8(body), null);
            if (a.status() != 200) {
                throw hostError(a);
            }
            return object(a.body(), path);
        }

        /** A bearer token for {@code me}, from the cache or from the challenge flow (SPEC 3.3). */
        private String token(Member me) throws ClientException {
            tokenLock.lock();
            try {
                byte[] subject = me.ed25519Public;
                if (token != null
                        && ctEq(token.subject(), subject)
                        && token.expiresAt() > saturatingAdd(nowMs(), TOKEN_SLACK_MS)) {
                    return token.value();
                }
                Map<String, Object> ch = new LinkedHashMap<>();
                ch.put("ed25519PublicKey", b64(subject));
                Map<String, Object> answer = postOpen("/api/auth/keypair/challenge", ch);
                Map<String, Object> tb = new LinkedHashMap<>();
                try {
                    String nonce = AvpJson.string(answer, "nonce");
                    // The client signs the raw nonce bytes.
                    byte[] raw = AvpEncoding.fromBase64(nonce);
                    tb.put("ed25519PublicKey", b64(subject));
                    tb.put("nonce", nonce);
                    tb.put("signature", b64(AvpCrypto.ed25519Sign(me.signingSeed, raw)));
                } catch (AvpException e) {
                    throw badResponse("challenge: " + e.getMessage(), e);
                }
                Map<String, Object> minted = postOpen("/api/auth/keypair/token", tb);
                try {
                    token = new Token(subject, AvpJson.string(minted, "token"), AvpJson.integer(minted, "expiresAt"));
                } catch (AvpException e) {
                    throw badResponse("token: " + e.getMessage(), e);
                }
                return token.value();
            } finally {
                tokenLock.unlock();
            }
        }

        /**
         * An authenticated JSON POST as {@code me}; a 401 drops the cached token and retries once.
         *
         * @return the parsed 200 answer
         */
        Object post(Member me, String path, Map<String, Object> body) throws ClientException {
            byte[] bytes = AvpJson.writeUtf8(body);
            boolean fresh = false;
            while (true) {
                String t = token(me);
                Answer a = call(http, base, path, bytes, t);
                if (a.status() == 200) {
                    try {
                        return AvpJson.parse(a.body());
                    } catch (AvpException e) {
                        throw badResponse(path + ": " + e.getMessage(), e);
                    }
                }
                if (a.status() == 401 && !fresh) {
                    tokenLock.lock();
                    try {
                        token = null;
                    } finally {
                        tokenLock.unlock();
                    }
                    fresh = true;
                    continue;
                }
                throw hostError(a);
            }
        }

        /**
         * Pushes one commit as {@code me} (SPEC 10.1 {@code push}), retrying {@code 422 missing_parents} while
         * the host fetches the parents from its peers.
         *
         * @param me the author
         * @param repoId the repository
         * @param commit the commit
         * @return the host's heads after the push; fails with {@link ClientException.Kind#HOST} if the host
         *     refuses (a {@code missing_parents} that outlasts the retries included)
         */
        public CompletableFuture<List<byte[]>> push(Member me, String repoId, AvpCommit.Commit commit) {
            return async(executor, () -> pushNow(me, repoId, commit));
        }

        List<byte[]> pushNow(Member me, String repoId, AvpCommit.Commit commit) throws ClientException {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("commit", AvpCommit.toJson(commit));
            Object answer = retryMissingParents(() -> post(me, repoPath(repoId, "push"), body));
            try {
                List<byte[]> out = new ArrayList<>();
                for (Object id : AvpJson.array(AvpJson.required(AvpJson.object(answer, "push"), "heads"), "heads")) {
                    out.add(AvpEncoding.fromBase64(AvpJson.string(id, "head"), 32));
                }
                return out;
            } catch (AvpException e) {
                throw badResponse("push: " + e.getMessage(), e);
            }
        }
    }

    /** Runs {@code op} again while the host answers {@code 422 missing_parents}, up to the retry bound. */
    static <T> T retryMissingParents(Op<T> op) throws ClientException {
        int tries = 0;
        while (true) {
            try {
                return op.run();
            } catch (ClientException e) {
                if (!e.code().equals(Optional.of("missing_parents")) || tries >= MISSING_PARENTS_RETRIES) {
                    throw e;
                }
                tries++;
                try {
                    Thread.sleep(RETRY_PAUSE_MS);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new ClientException(ClientException.Kind.TRANSPORT, "interrupted", ie);
                }
            }
        }
    }

    private static ClientException badResponse(String message, Throwable cause) {
        return new ClientException(ClientException.Kind.BAD_RESPONSE, "malformed host answer: " + message, cause);
    }

    private static Map<String, Object> object(byte[] body, String what) throws ClientException {
        try {
            return AvpJson.object(AvpJson.parse(body), what);
        } catch (AvpException e) {
            throw badResponse(what + ": " + e.getMessage(), e);
        }
    }

    /**
     * The SPEC 10.4 error of a non-2xx answer: the {@code code} is kept, the message is never parsed. A body
     * that is not the JSON error object (a bare {@code 400}) leaves only the status.
     */
    private static ClientException hostError(HostClient.Answer a) {
        String code = null;
        String message = "";
        try {
            if (AvpJson.parse(a.body()) instanceof Map<?, ?> m) {
                if (m.get("code") instanceof String c) {
                    code = c;
                }
                if (m.get("error") instanceof String err) {
                    message = err;
                }
            }
        } catch (AvpException e) {
            // Not a JSON body: report the status alone (SPEC 10.4 allows a bare 400).
        }
        return ClientException.host(a.status(), code, message);
    }

    /** The path of a repository route, repoId percent-encoded as a path segment (SPEC 10.2). */
    static String repoPath(String repoId, String op) {
        StringBuilder seg = new StringBuilder();
        for (byte b : repoId.getBytes(StandardCharsets.UTF_8)) {
            char c = (char) (b & 0xff);
            boolean unreserved = (c >= 'a' && c <= 'z')
                    || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9')
                    || c == '-'
                    || c == '_'
                    || c == '.'
                    || c == '~';
            if (unreserved) {
                seg.append(c);
            } else {
                seg.append(String.format("%%%02X", b & 0xff));
            }
        }
        return "/v1/repos/" + seg + "/" + op;
    }

    // ─── Manifest chain verification (SPEC 6) ───────────────────────────────────────────────

    private static boolean distinct(List<byte[]> ids) {
        Set<ByteBuffer> seenIds = new HashSet<>();
        for (byte[] id : ids) {
            if (!seenIds.add(ByteBuffer.wrap(id))) {
                return false;
            }
        }
        return true;
    }

    /**
     * SPEC 6.1 rule 1: counters in range, the variable-length binary fields at their lengths, no repeated
     * key. Fixed-length fields are already enforced by the decoder.
     */
    private static boolean shapeOk(AvpManifest.ManifestState s) {
        if (s.manifestSeq() < 1 || s.keyEpoch() < 0) {
            return false;
        }
        int prevLen = s.manifestSeq() == 1 ? 0 : 32;
        int nonceLen = s.manifestSeq() == 1 ? 16 : 0;
        if (s.prevManifestHash().length != prevLen || s.genesisNonce().length != nonceLen) {
            return false;
        }
        for (AvpManifest.MemberEntry m : s.members()) {
            if (m.keyEpoch() < 0 || m.wrappedDataKey().ciphertext().length != 48) {
                return false;
            }
        }
        for (AvpManifest.Removal r : s.removals()) {
            if (!distinct(r.frontier())) {
                return false;
            }
        }
        return distinct(s.hosts().stream().map(AvpManifest.HostRef::hostKey).toList())
                && distinct(s.members().stream()
                        .map(AvpManifest.MemberEntry::ed25519PublicKey)
                        .toList())
                && distinct(s.removals().stream()
                        .map(AvpManifest.Removal::memberKey)
                        .toList());
    }

    /** SPEC 6.2: the genesis state, with repoId recomputed from ownerKey and genesisNonce. */
    private static boolean genesisOk(AvpManifest.ManifestState s) {
        if (s.genesisNonce().length != 16 || s.members().size() != 1) {
            return false;
        }
        AvpManifest.MemberEntry only = s.members().get(0);
        try {
            return s.prevManifestHash().length == 0
                    && s.keyEpoch() == 0
                    && s.removals().isEmpty()
                    && Arrays.equals(only.ed25519PublicKey(), s.ownerKey())
                    && AvpManifest.deriveRepoId(s.ownerKey(), s.genesisNonce()).equals(s.repoId());
        } catch (AvpException e) {
            return false;
        }
    }

    private static List<String> sortedIds(List<byte[]> ids) {
        List<String> out = new ArrayList<>();
        for (byte[] id : ids) {
            out.add(AvpEncoding.hex(id));
        }
        Collections.sort(out);
        return out;
    }

    /** SPEC 6.1 rule 5: the content rules, and against the previous state when there is one. */
    private static boolean contentOk(AvpManifest.ManifestState s, AvpManifest.ManifestState prev) {
        long own = s.members().stream()
                .filter(m -> Arrays.equals(m.ed25519PublicKey(), s.ownerKey()))
                .count();
        boolean membersOk = s.members().stream()
                .allMatch(m -> m.keyEpoch() == s.keyEpoch()
                        && s.hasHost(m.homeHostKey())
                        && s.removalOf(m.ed25519PublicKey()).isEmpty());
        boolean removalsOk =
                s.removals().stream().allMatch(r -> r.removedAtSeq() >= 2 && r.removedAtSeq() <= s.manifestSeq());
        if (s.hosts().isEmpty() || own != 1 || !membersOk || !removalsOk) {
            return false;
        }
        if (prev == null) {
            return true;
        }
        boolean canRotate = prev.keyEpoch() < Long.MAX_VALUE;
        boolean rotatedEpoch = canRotate && s.keyEpoch() == prev.keyEpoch() + 1;
        if (!s.repoId().equals(prev.repoId())
                || !Arrays.equals(s.ownerKey(), prev.ownerKey())
                || !s.schemeId().equals(prev.schemeId())
                || s.genesisNonce().length != 0
                || (s.keyEpoch() != prev.keyEpoch() && !rotatedEpoch)) {
            return false;
        }
        // Removals are cumulative and unchanged.
        boolean kept = prev.removals().stream()
                .allMatch(r -> s.removalOf(r.memberKey())
                        .filter(same -> same.removedAtSeq() == r.removedAtSeq()
                                && sortedIds(same.frontier()).equals(sortedIds(r.frontier())))
                        .isPresent());
        List<AvpManifest.Removal> added = s.removals().stream()
                .filter(r -> prev.removalOf(r.memberKey()).isEmpty())
                .toList();
        boolean addedOk =
                added.stream().allMatch(r -> r.removedAtSeq() == s.manifestSeq() && prev.hasMember(r.memberKey()));
        // Every member that disappears is removed, and never the owner.
        boolean droppedOk = prev.members().stream()
                .allMatch(m -> s.hasMember(m.ed25519PublicKey())
                        || (!Arrays.equals(m.ed25519PublicKey(), s.ownerKey())
                                && added.stream().anyMatch(r -> Arrays.equals(r.memberKey(), m.ed25519PublicKey()))));
        boolean rotated = added.isEmpty() || rotatedEpoch;
        return kept && addedOk && droppedOk && rotated;
    }

    /**
     * Validates one state by SPEC 6.1 rules 1 to 5 (rule 6, the hosted check, is a host rule), against {@code
     * prev} (the state at {@code manifestSeq - 1} on the client's chain) or, when {@code prev} is {@code
     * null}, as a genesis state (SPEC 6.2).
     *
     * @param m the state
     * @param prev the previous state, or {@code null} for a genesis state
     * @return the state's {@code manifestHash}
     * @throws ClientException of kind {@link ClientException.Kind#STATE_REJECTED} naming the first rule that
     *     fails
     */
    public static byte[] validateState(AvpManifest.SignedManifest m, AvpManifest.SignedManifest prev)
            throws ClientException {
        AvpManifest.ManifestState s = m.state();
        boolean encodes;
        try {
            AvpManifest.encode(s);
            encodes = true;
        } catch (AvpException e) {
            encodes = false;
        }
        if (!shapeOk(s) || !encodes) {
            throw rejected("malformed state");
        }
        if (!AvpManifest.verify(m)) {
            throw rejected("owner signature does not verify");
        }
        if (prev == null) {
            if (s.manifestSeq() != 1 || !genesisOk(s)) {
                throw rejected("not a valid genesis state");
            }
        } else if (!AvpManifest.linksTo(m, prev)) {
            throw rejected("does not link to the previous state");
        }
        if (!contentOk(s, prev == null ? null : prev.state())) {
            throw rejected("content rules");
        }
        try {
            return AvpManifest.hash(m);
        } catch (AvpException e) {
            throw ClientException.avp(e);
        }
    }

    private static ClientException rejected(String why) {
        return new ClientException(ClientException.Kind.STATE_REJECTED, "manifest state rejected: " + why);
    }

    private static ClientException discarded(String why) {
        return new ClientException(ClientException.Kind.COMMIT_REJECTED, "commit discarded: " + why);
    }

    /**
     * The client's verified manifest chain, from genesis to the pinned tip (SPEC 6.4).
     *
     * <p>Every state on it passed {@link #validateState(AvpManifest.SignedManifest, AvpManifest.SignedManifest)}
     * against its predecessor, so the chain is never empty and its genesis fixes {@code repoId} and {@code
     * ownerKey}.
     */
    public static final class Chain {
        private final List<AvpManifest.SignedManifest> states;
        private final List<byte[]> hashes;

        private Chain(List<AvpManifest.SignedManifest> states, List<byte[]> hashes) {
            this.states = states;
            this.hashes = hashes;
        }

        static Chain genesis(AvpManifest.SignedManifest m) throws ClientException {
            byte[] h = validateState(m, null);
            List<AvpManifest.SignedManifest> s = new ArrayList<>();
            s.add(m);
            List<byte[]> hs = new ArrayList<>();
            hs.add(h);
            return new Chain(s, hs);
        }

        /**
         * Builds a chain from states in ascending seq, validating each one.
         *
         * @param states the states, genesis first
         * @return the chain
         * @throws ClientException of kind {@link ClientException.Kind#STATE_REJECTED} if the list is empty or
         *     any state fails
         */
        public static Chain fromStates(List<AvpManifest.SignedManifest> states) throws ClientException {
            if (states.isEmpty()) {
                throw rejected("empty chain");
            }
            Chain c = genesis(states.get(0));
            for (AvpManifest.SignedManifest m : states.subList(1, states.size())) {
                c.extend(m);
            }
            return c;
        }

        /** The longest valid prefix of a list, and the number of states after it that were discarded. */
        private record Prefix(Chain chain, int discarded) {}

        static Prefix prefix(List<AvpManifest.SignedManifest> states) {
            if (states.isEmpty()) {
                return new Prefix(null, 0);
            }
            Chain c;
            try {
                c = genesis(states.get(0));
            } catch (ClientException e) {
                return new Prefix(null, states.size());
            }
            for (int i = 1; i < states.size(); i++) {
                try {
                    c.extend(states.get(i));
                } catch (ClientException e) {
                    return new Prefix(c, states.size() - i);
                }
            }
            return new Prefix(c, 0);
        }

        /** Appends the state after the tip, if it validates against the tip. */
        void extend(AvpManifest.SignedManifest m) throws ClientException {
            byte[] h = validateState(m, tip());
            states.add(m);
            hashes.add(h);
        }

        Chain copy() {
            return new Chain(new ArrayList<>(states), new ArrayList<>(hashes));
        }

        int size() {
            return states.size();
        }

        /**
         * The states, genesis first.
         *
         * @return a read-only copy
         */
        public List<AvpManifest.SignedManifest> states() {
            return List.copyOf(states);
        }

        /**
         * The pinned tip: the highest verified state.
         *
         * @return the tip
         */
        public AvpManifest.SignedManifest tip() {
            return states.get(states.size() - 1);
        }

        /**
         * The {@code manifestHash} of the tip.
         *
         * @return a copy of the 32-byte hash
         */
        public byte[] tipHash() {
            return hashes.get(hashes.size() - 1).clone();
        }

        /**
         * The repository id fixed by genesis.
         *
         * @return the repoId
         */
        public String repoId() {
            return tip().state().repoId();
        }

        private int index(long seq) {
            return seq >= 1 && seq - 1 < states.size() ? (int) (seq - 1) : -1;
        }

        /** The index of the first state that differs from {@code other}'s, or -1 if one is a prefix. */
        int fork(Chain other) {
            int n = Math.min(hashes.size(), other.hashes.size());
            for (int i = 0; i < n; i++) {
                if (!ctEq(hashes.get(i), other.hashes.get(i))) {
                    return i;
                }
            }
            return -1;
        }

        /**
         * SPEC 6.4 with the 6.5 exception: {@code other} is adopted if it contains the pinned state, or if it
         * diverges at a fork point at or below the pin (never at genesis, which fixes the repository) and its
         * state there has the bytewise-lower {@code manifestHash}.
         */
        boolean accepts(Chain other) {
            int i = fork(other);
            if (i < 0) {
                return other.size() >= size();
            }
            return i > 0 && AvpEncoding.compare(other.hashes.get(i), hashes.get(i)) < 0;
        }

        /**
         * The client checks of SPEC 7.5 for one pulled commit, against this chain.
         *
         * <ol>
         *   <li>The commit is for this repository, lists no parent twice, {@code commitId} recomputes, and
         *       {@code authorSignature} verifies.
         *   <li>Removal cutoff: a head by a removed member passes only if its id is in the removal's frontier
         *       (removals are cumulative, so the tip holds them all).
         *   <li>Membership: if {@code (manifestSeq, manifestHash)} is the state on this chain at that seq, the
         *       author is a member of it and {@code keyEpoch} is its epoch; otherwise the author is a member of
         *       some state at or after the cited seq whose epoch is the commit's.
         * </ol>
         *
         * @param c the commit
         * @throws ClientException of kind {@link ClientException.Kind#COMMIT_REJECTED} naming the check that
         *     fails
         */
        public void verifyCommit(AvpCommit.Commit c) throws ClientException {
            boolean shape =
                    c.ciphertext().length >= 16 && c.manifestSeq() >= 1 && c.keyEpoch() >= 0 && distinct(c.parents());
            if (!c.repoId().equals(repoId()) || !shape) {
                throw discarded("malformed or another repository");
            }
            if (!AvpCommit.verify(c)) {
                throw discarded("id or author signature does not verify");
            }
            Optional<AvpManifest.Removal> removal = tip().state().removalOf(c.author());
            if (removal.isPresent() && removal.get().frontier().stream().noneMatch(id -> ctEq(id, c.commitId()))) {
                throw discarded("removed author outside the frontier");
            }
            Predicate<AvpManifest.SignedManifest> memberAt =
                    m -> m.state().hasMember(c.author()) && m.state().keyEpoch() == c.keyEpoch();
            int i = index(c.manifestSeq());
            boolean ok;
            if (i >= 0 && ctEq(hashes.get(i), c.manifestHash())) {
                ok = memberAt.test(states.get(i));
            } else {
                ok = states.stream()
                        .filter(m -> m.state().manifestSeq() >= c.manifestSeq())
                        .anyMatch(memberAt);
            }
            if (!ok) {
                throw discarded("author is not a member at the commit's epoch");
            }
        }
    }

    // ─── Payload edits ──────────────────────────────────────────────────────────────────────

    private static Map<String, Object> emptyPayload() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("v", 2L);
        p.put("accounts", new TreeMap<String, Object>());
        return p;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> child(Map<String, Object> parent, String key) {
        if (parent.get(key) instanceof Map<?, ?> m) {
            return (Map<String, Object>) m;
        }
        Map<String, Object> fresh = new TreeMap<>();
        parent.put(key, fresh);
        return fresh;
    }

    private static Map<String, Object> account(Map<String, Object> payload, String uuid) {
        Map<String, Object> a = child(child(payload, "accounts"), uuid);
        child(a, "fields");
        child(a, "bans");
        return a;
    }

    /**
     * Sets one field of an account with {@code stamp} (SPEC 5 writes), creating the account if needed.
     *
     * @param payload a mutable payload tree, as {@link #write(BiConsumer)} hands it out
     * @param uuid the account
     * @param name the field name
     * @param value the JSON value
     * @param stamp the stamp {@code { at, n, by }}, from {@link AvpPayload.Hlc#tick(long, String)}
     */
    public static void setField(
            Map<String, Object> payload, String uuid, String name, Object value, Map<String, Object> stamp) {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("value", value);
        f.put("at", stamp.get("at"));
        f.put("n", stamp.get("n"));
        f.put("by", stamp.get("by"));
        child(account(payload, uuid), "fields").put(name, f);
    }

    /**
     * Deletes an account by setting its deletion marker to {@code stamp}; its fields stay (SPEC 5).
     *
     * @param payload a mutable payload tree
     * @param uuid the account
     * @param stamp the stamp {@code { at, n, by }}
     */
    public static void deleteAccount(Map<String, Object> payload, String uuid, Map<String, Object> stamp) {
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("at", stamp.get("at"));
        d.put("n", stamp.get("n"));
        d.put("by", stamp.get("by"));
        account(payload, uuid).put("deleted", d);
    }

    /** A deep, normalized copy of a payload: encoded and parsed back, so it is checked to be payload v2. */
    private static Map<String, Object> normalize(Map<String, Object> payload) throws ClientException {
        byte[] bytes;
        try {
            bytes = AvpPayload.encode(payload);
        } catch (IllegalArgumentException e) {
            throw new ClientException(ClientException.Kind.AVP, "the payload holds a value that is not JSON", e);
        }
        try {
            return AvpPayload.parse(bytes);
        } catch (AvpException e) {
            throw ClientException.avp(e);
        }
    }

    private static Map<String, Object> strip(Map<String, Object> payload) throws ClientException {
        try {
            return AvpPayload.stripRefresh(payload);
        } catch (AvpException e) {
            throw ClientException.avp(e);
        }
    }

    // ─── Pull report ────────────────────────────────────────────────────────────────────────

    /**
     * What one pull found.
     *
     * @param newStates states added to the verified chain
     * @param discardedStates pulled states that failed SPEC 6.1 and were discarded, with every state after
     *     them
     * @param rejectedChain the host served a chain that does not contain the pinned state and does not win
     *     the tie rule (SPEC 6.4): it was rejected and the pin did not move
     * @param readableHeads verified heads this device read
     * @param unreadableHeads verified heads this device cannot read (no key for the epoch, a payload that
     *     does not decrypt or is not {@code v: 2}); left for another member (SPEC 7.5)
     * @param discardedCommits heads that failed SPEC 7.5 and were discarded (never merged, never a parent)
     * @param malformedItems pulled items that did not decode at all
     * @param leaves valid pending leave requests
     * @param mergeCommit the merge commit pushed after this pull, if it merged more than one head (SPEC 5)
     */
    public record PullReport(
            int newStates,
            int discardedStates,
            boolean rejectedChain,
            List<byte[]> readableHeads,
            List<byte[]> unreadableHeads,
            List<byte[]> discardedCommits,
            int malformedItems,
            int leaves,
            Optional<byte[]> mergeCommit) {
        /** Copies the lists. */
        public PullReport {
            readableHeads = List.copyOf(readableHeads);
            unreadableHeads = List.copyOf(unreadableHeads);
            discardedCommits = List.copyOf(discardedCommits);
        }
    }

    /** The mutable report while a pull runs. */
    private static final class Report {
        int newStates;
        int discardedStates;
        boolean rejectedChain;
        final List<byte[]> readable = new ArrayList<>();
        final List<byte[]> unreadable = new ArrayList<>();
        final List<byte[]> discardedCommits = new ArrayList<>();
        int malformed;
        int leaves;

        PullReport build(Optional<byte[]> merge) {
            return new PullReport(
                    newStates,
                    discardedStates,
                    rejectedChain,
                    readable,
                    unreadable,
                    discardedCommits,
                    malformed,
                    leaves,
                    merge);
        }
    }

    /** A pull answer, each item decoded on its own so one malformed item does not hide the rest. */
    private record PullAnswer(
            List<AvpManifest.SignedManifest> manifests,
            List<AvpCommit.Commit> heads,
            List<AvpTokens.LeaveRequest> leaves,
            int malformed) {}

    @FunctionalInterface
    private interface Decoder<T> {
        T decode(Object json) throws AvpException;
    }

    private static <T> List<T> items(Map<String, Object> answer, String key, Decoder<T> d, int[] malformed)
            throws ClientException {
        List<Object> list;
        try {
            list = AvpJson.array(AvpJson.required(answer, key), key);
        } catch (AvpException e) {
            throw badResponse("pull answer has no " + key + " list", e);
        }
        List<T> out = new ArrayList<>();
        for (Object item : list) {
            try {
                out.add(d.decode(item));
            } catch (AvpException e) {
                malformed[0]++;
            }
        }
        return out;
    }

    private static PullAnswer pullRaw(HostClient host, Member me, String repoId, long since) throws ClientException {
        // knownHeads stays empty: the answer then lists every current head, which is how the client learns
        // which of the heads it merged are still heads.
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("sinceManifestSeq", since);
        body.put("knownHeads", List.of());
        Map<String, Object> answer;
        try {
            answer = AvpJson.object(host.post(me, repoPath(repoId, "pull"), body), "pull");
        } catch (AvpException e) {
            throw badResponse("pull: " + e.getMessage(), e);
        }
        int[] malformed = {0};
        List<AvpManifest.SignedManifest> manifests =
                items(answer, "manifests", AvpManifest::signedManifestFromJson, malformed);
        List<AvpCommit.Commit> commits = items(answer, "heads", AvpCommit::fromJson, malformed);
        List<AvpTokens.LeaveRequest> leaves = items(answer, "leaves", AvpTokens::leaveFromJson, malformed);
        return new PullAnswer(manifests, commits, leaves, malformed[0]);
    }

    // ─── Opening a vault ────────────────────────────────────────────────────────────────────

    /**
     * Creates a repository on the owner's home host (SPEC 8.2 initial host): a random genesis nonce, a fresh
     * epoch-0 data key wrapped to the owner, the genesis state listing {@code host}, and an empty first
     * commit, sent together with {@code createRepo}. The vault's operations run on the host connection's
     * executor ({@link HostClient#connect(String, Executor)}).
     *
     * @param host the owner's home host
     * @param owner the owner keys
     * @return the vault; fails with {@link ClientException.Kind#HOST} if the host refuses and {@link
     *     ClientException.Kind#TRANSPORT} if it cannot be reached
     */
    public static CompletableFuture<Vault> create(HostClient host, AvpOwner.OwnerKeys owner) {
        return async(host.executor, () -> createNow(host, owner, host.executor));
    }

    private static Vault createNow(HostClient host, AvpOwner.OwnerKeys owner, Executor executor)
            throws ClientException {
        Member me = Member.fromOwner(owner);
        byte[] ownerKey = owner.ed25519Public();
        byte[] nonce = AvpCrypto.randomBytes(16);
        byte[] dataKey = AvpCrypto.randomBytes(32);
        try {
            String repoId = AvpManifest.deriveRepoId(ownerKey, nonce);
            AvpManifest.ManifestState state = new AvpManifest.ManifestState(
                    repoId,
                    1,
                    new byte[0],
                    ownerKey,
                    nonce,
                    AvpCrypto.SCHEME_ID,
                    0,
                    false,
                    List.of(new AvpManifest.HostRef(host.key, host.locator)),
                    List.of(new AvpManifest.MemberEntry(
                            ownerKey,
                            owner.x25519Public(),
                            AvpCrypto.wrap(owner.x25519Public(), dataKey, AvpCrypto.WRAP_INFO),
                            0,
                            host.key)),
                    List.of());
            AvpManifest.SignedManifest genesis = AvpManifest.sign(state, owner.ed25519Seed());
            Chain chain = Chain.genesis(genesis);
            AvpCommit.Header header = new AvpCommit.Header(repoId, List.of(), 1, chain.tipHash(), 0);
            AvpCommit.Commit first =
                    AvpCommit.seal(dataKey, header, AvpPayload.encode(emptyPayload()), owner.ed25519Seed());
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("manifest", AvpManifest.toJson(genesis));
            body.put("commit", AvpCommit.toJson(first));
            host.post(me, "/v1/repos", body);
            Vault v = new Vault(host, me, chain, executor);
            v.retained.put(0L, dataKey);
            v.record(first);
            v.heads = new ArrayList<>(List.of(first.commitId()));
            return v;
        } catch (AvpException e) {
            throw ClientException.avp(e);
        }
    }

    /**
     * Opens a repository this device is a member of from its home host: pulls the whole chain, verifies it
     * from genesis, unwraps every data key it was given, and reads and merges the heads. The vault's
     * operations run on the host connection's executor.
     *
     * @param host the member's home host
     * @param me this device's member identity
     * @param repoId the repository
     * @return the vault; fails with {@link ClientException.Kind#HOST} if the host does not serve it ({@code
     *     404}, {@code 403} for a non-member), {@link ClientException.Kind#STATE_REJECTED} if the chain does
     *     not verify or is another repository, and {@link ClientException.Kind#NOT_PERMITTED} if the verified
     *     tip does not list this member
     */
    public static CompletableFuture<Vault> open(HostClient host, Member me, String repoId) {
        return async(host.executor, () -> openChecked(host, me, repoId, c -> {}, host.executor));
    }

    /**
     * Joins a repository after the owner's invite (SPEC 8.1): {@link #open(HostClient, Member, String)} from
     * the joiner's home host, plus the SPEC 11.2 check that the genesis {@code ownerKey} matches the
     * locator's {@code ownerFingerprint}.
     *
     * @param host the joiner's home host
     * @param me the joiner's member identity
     * @param locator the owner's repo locator
     * @return the vault; fails as {@link #open(HostClient, Member, String)}, and with {@link
     *     ClientException.Kind#OWNER_MISMATCH} for another owner key
     */
    public static CompletableFuture<Vault> join(HostClient host, Member me, AvpTokens.RepoLocator locator) {
        String expected = locator.ownerFingerprint();
        Executor ex = host.executor;
        return async(
                ex,
                () -> openChecked(
                        host,
                        me,
                        locator.repoId(),
                        c -> {
                            byte[] genesisOwner = c.states.get(0).state().ownerKey();
                            byte[] actual =
                                    AvpTokens.ownerFingerprint(genesisOwner).getBytes(StandardCharsets.UTF_8);
                            if (!ctEq(actual, expected.getBytes(StandardCharsets.UTF_8))) {
                                throw new ClientException(
                                        ClientException.Kind.OWNER_MISMATCH,
                                        "the repository's owner key does not match the locator's fingerprint");
                            }
                        },
                        ex));
    }

    @FunctionalInterface
    private interface ChainCheck {
        void check(Chain c) throws ClientException;
    }

    private static Vault openChecked(HostClient host, Member me, String repoId, ChainCheck check, Executor ex)
            throws ClientException {
        PullAnswer answer = pullRaw(host, me, repoId, 0);
        Chain chain = Chain.prefix(answer.manifests()).chain();
        if (chain == null) {
            throw rejected("no valid genesis state");
        }
        if (!chain.repoId().equals(repoId)) {
            throw rejected("the chain is another repository");
        }
        check.check(chain);
        if (!chain.tip().state().hasMember(me.ed25519Public)) {
            throw new ClientException(
                    ClientException.Kind.NOT_PERMITTED, "this device is not a member of the verified tip");
        }
        Vault v = new Vault(host, me, chain, ex);
        v.adoptKeys(0);
        Report report = new Report();
        v.takeHeads(answer.heads(), report);
        v.takeLeaves(answer.leaves(), report);
        v.mergeHeadsNow();
        return v;
    }

    // ─── Accessors ──────────────────────────────────────────────────────────────────────────

    /**
     * The repository id.
     *
     * @return the repoId
     */
    public String repoId() {
        return read(() -> chain.repoId());
    }

    /**
     * The verified chain.
     *
     * @return a copy
     */
    public Chain chain() {
        return read(() -> chain.copy());
    }

    /**
     * The pinned tip state.
     *
     * @return the tip
     */
    public AvpManifest.SignedManifest tip() {
        return read(() -> chain.tip());
    }

    /**
     * The {@code manifestHash} of the pinned tip.
     *
     * @return a copy of the hash
     */
    public byte[] tipHash() {
        return read(() -> chain.tipHash());
    }

    /**
     * The local payload: the merge of every head this device has read, stripped by policy.
     *
     * @return a deep, mutable copy
     */
    public Map<String, Object> payload() {
        return read(() -> deepCopy(local));
    }

    /**
     * The readable heads the local payload covers; the parents of the next write.
     *
     * @return a copy
     */
    public List<byte[]> heads() {
        return read(() -> copyIds(heads));
    }

    /**
     * The verified heads this device could not read at the last pull.
     *
     * @return a copy
     */
    public List<byte[]> unreadableHeads() {
        return read(() -> copyIds(unreadable));
    }

    /**
     * The hybrid logical clock.
     *
     * @return a copy of its state
     */
    public AvpPayload.Hlc hlc() {
        return read(() -> new AvpPayload.Hlc(hlc.at(), hlc.n()));
    }

    /**
     * This device's member identity.
     *
     * @return the identity
     */
    public Member member() {
        return me;
    }

    /**
     * The valid pending leave requests of the last pull.
     *
     * @return a copy
     */
    public List<AvpTokens.LeaveRequest> leaves() {
        return read(() -> List.copyOf(leaves));
    }

    /**
     * Every data key this device has held, by {@code keyEpoch}, retained so it can read and merge old-epoch
     * heads forward after a rotation (SPEC 7.5 SHOULD). Secrets: they never leave the device.
     *
     * @return a copy
     */
    public Map<Long, byte[]> retainedEpochKeys() {
        return read(() -> {
            Map<Long, byte[]> out = new TreeMap<>();
            retained.forEach((k, v) -> out.put(k, v.clone()));
            return out;
        });
    }

    /**
     * The home host connection.
     *
     * @return the connection
     */
    public HostClient host() {
        return host;
    }

    /**
     * A repo locator naming this device's host as the owner's home host (SPEC 11.2).
     *
     * @return the locator
     * @throws ClientException of kind {@link ClientException.Kind#NOT_PERMITTED} unless this device is the
     *     owner
     */
    public AvpTokens.RepoLocator locator() throws ClientException {
        lock.lock();
        try {
            requireOwner();
            return new AvpTokens.RepoLocator(
                    chain.repoId(),
                    host.key,
                    host.locator,
                    AvpTokens.ownerFingerprint(chain.tip().state().ownerKey()));
        } finally {
            lock.unlock();
        }
    }

    /** Closes the home host connection. */
    @Override
    public void close() {
        host.close();
    }

    /** Shows the repository and sync position only; never a key or a plaintext. */
    @Override
    public String toString() {
        return read(() -> "Vault[repoId=" + chain.repoId() + ", manifestSeq="
                + chain.tip().state().manifestSeq() + ", heads=" + heads.size() + ", left=" + left + "]");
    }

    private static List<byte[]> copyIds(List<byte[]> ids) {
        List<byte[]> out = new ArrayList<>();
        for (byte[] id : ids) {
            out.add(id.clone());
        }
        return out;
    }

    /** A structural deep copy of a JSON tree: maps and lists copied, leaves shared (they are immutable). */
    private static Map<String, Object> deepCopy(Map<String, Object> payload) {
        Map<String, Object> out = new LinkedHashMap<>();
        payload.forEach((k, v) -> out.put(k, copyTree(v)));
        return out;
    }

    private static Object copyTree(Object v) {
        if (v instanceof Map<?, ?> m) {
            Map<String, Object> out = m instanceof TreeMap<?, ?> ? new TreeMap<>() : new LinkedHashMap<>();
            m.forEach((k, x) -> out.put(String.valueOf(k), copyTree(x)));
            return out;
        }
        if (v instanceof List<?> l) {
            List<Object> out = new ArrayList<>();
            l.forEach(x -> out.add(copyTree(x)));
            return out;
        }
        return v;
    }

    private boolean shareRefresh() {
        // SPEC 5.1 fail closed: on only when the latest verified state says true.
        return chain.tip().state().shareRefreshTokens();
    }

    private boolean isOwner() {
        return ctEq(chain.tip().state().ownerKey(), me.ed25519Public);
    }

    private void requireOwner() throws ClientException {
        if (!isOwner()) {
            throw new ClientException(ClientException.Kind.NOT_PERMITTED, "only the owner changes the manifest");
        }
    }

    private void requireSyncing() throws ClientException {
        if (left) {
            throw new ClientException(ClientException.Kind.LEFT, "this member left the repository and no longer syncs");
        }
    }

    // ─── Pull ───────────────────────────────────────────────────────────────────────────────

    /**
     * Pulls from the home host and merges (SPEC 5, 6.4, 7.5, 10.1): verifies every new state and pins the
     * highest, checks every head, reads the heads it can, and pushes a merge commit when more than one head
     * is readable.
     *
     * <p>The request always sends {@code knownHeads: []}, so the host answers with every current head: that
     * is how the client learns which heads it merged are still heads, at the cost of downloading every head
     * body on each pull. Answers are read up to 16 MiB. An unreadable head or a discarded state or commit is
     * not a failure (see the report).
     *
     * @return the report; fails with {@link ClientException.Kind#LEFT} after {@link #leave()}, and with
     *     {@link ClientException.Kind#HOST} or {@link ClientException.Kind#TRANSPORT} if the host does not
     *     answer
     */
    public CompletableFuture<PullReport> pull() {
        return locked(this::pullNow);
    }

    private PullReport pullNow() throws ClientException {
        Report report = fetch();
        return report.build(mergeHeadsNow());
    }

    /** The pull without the merge push. */
    private Report fetch() throws ClientException {
        requireSyncing();
        String repoId = chain.repoId();
        PullAnswer answer = pullRaw(host, me, repoId, chain.tip().state().manifestSeq());
        Report report = new Report();
        report.malformed = answer.malformed();
        boolean linked = answer.manifests().isEmpty()
                || AvpManifest.linksTo(answer.manifests().get(0), chain.tip());
        if (linked) {
            int before = chain.size();
            List<AvpManifest.SignedManifest> ms = answer.manifests();
            for (int i = 0; i < ms.size(); i++) {
                try {
                    chain.extend(ms.get(i));
                } catch (ClientException e) {
                    report.discardedStates = ms.size() - i;
                    break;
                }
            }
            report.newStates = chain.size() - before;
            adoptKeys(before);
        } else {
            // SPEC 6.4: the first state does not link to the pin; pull the whole chain and decide.
            answer = pullRaw(host, me, repoId, 0);
            report.malformed += answer.malformed();
            Chain.Prefix p = Chain.prefix(answer.manifests());
            report.discardedStates = p.discarded();
            Chain candidate = p.chain();
            if (candidate != null && chain.accepts(candidate)) {
                int fork = chain.fork(candidate);
                int from = fork < 0 ? chain.size() : fork;
                report.newStates = Math.max(0, candidate.size() - from);
                chain = candidate;
                adoptKeys(from);
            } else {
                report.rejectedChain = true;
            }
        }
        if (!shareRefresh()) {
            local = strip(local);
        }
        takeHeads(answer.heads(), report);
        takeLeaves(answer.leaves(), report);
        return report;
    }

    /** Unwraps this member's data key from every chain state from index {@code from} on. */
    private void adoptKeys(int from) {
        int start = Math.min(Math.max(from, 0), chain.size());
        for (AvpManifest.SignedManifest m : chain.states.subList(start, chain.size())) {
            for (AvpManifest.MemberEntry e : m.state().members()) {
                if (!Arrays.equals(e.ed25519PublicKey(), me.ed25519Public)) {
                    continue;
                }
                try {
                    byte[] key = AvpCrypto.unwrap(me.x25519Private, e.wrappedDataKey(), AvpCrypto.WRAP_INFO);
                    if (key.length == 32) {
                        retained.put(m.state().keyEpoch(), key);
                    }
                } catch (AvpException ex) {
                    // A wrap this device cannot open gives no key for that epoch; its heads stay unreadable.
                }
            }
        }
    }

    private void record(AvpCommit.Commit c) {
        seen.put(b64(c.commitId()), new Seen(c.author(), c.parents()));
    }

    /** Checks every pulled head (SPEC 7.5), then sorts the valid ones into readable and unreadable. */
    private void takeHeads(List<AvpCommit.Commit> pulled, Report report) {
        heads = new ArrayList<>();
        unreadable = new ArrayList<>();
        incoming = new ArrayList<>();
        Set<String> once = new HashSet<>();
        for (AvpCommit.Commit c : pulled) {
            // Verify before de-duplicating, so a forgery that claims a real head's id cannot shadow the real
            // head.
            try {
                chain.verifyCommit(c);
            } catch (ClientException e) {
                report.discardedCommits.add(c.commitId());
                continue;
            }
            if (!once.add(b64(c.commitId()))) {
                continue;
            }
            record(c);
            Map<String, Object> p = readCommit(c);
            if (p != null) {
                heads.add(c.commitId());
                incoming.add(p);
                report.readable.add(c.commitId());
            } else {
                unreadable.add(c.commitId());
                report.unreadable.add(c.commitId());
            }
        }
    }

    /**
     * Decrypts a verified commit with the retained key of its epoch; {@code null} if this device cannot read
     * it. Strips on read when the policy is not true (SPEC 5.1).
     */
    private Map<String, Object> readCommit(AvpCommit.Commit c) {
        byte[] key = retained.get(c.keyEpoch());
        if (key == null) {
            return null;
        }
        try {
            Map<String, Object> p = AvpPayload.parse(AvpCommit.open(c, key));
            return shareRefresh() ? p : AvpPayload.stripRefresh(p);
        } catch (AvpException e) {
            return null;
        }
    }

    /** Keeps the leave requests that verify for a current, non-owner member (SPEC 8.4). */
    private void takeLeaves(List<AvpTokens.LeaveRequest> pulled, Report report) {
        AvpManifest.ManifestState s = chain.tip().state();
        List<AvpTokens.LeaveRequest> keep = new ArrayList<>();
        for (AvpTokens.LeaveRequest l : pulled) {
            if (AvpTokens.verifyLeave(l)
                    && l.repoId().equals(s.repoId())
                    && s.hasMember(l.memberKey())
                    && !Arrays.equals(l.memberKey(), s.ownerKey())) {
                keep.add(l);
            }
        }
        leaves = keep;
        report.leaves = keep.size();
    }

    /** Merges the payloads read at the last pull into the local payload, after observing their stamps. */
    private void absorb() throws ClientException {
        List<Map<String, Object>> in = incoming;
        incoming = new ArrayList<>();
        try {
            for (Map<String, Object> p : in) {
                hlc.observeAll(p);
            }
            List<Map<String, Object>> all = new ArrayList<>();
            all.add(local);
            all.addAll(in);
            Map<String, Object> merged = AvpPayload.merge(all);
            local = shareRefresh() ? merged : AvpPayload.stripRefresh(merged);
        } catch (AvpException e) {
            throw ClientException.avp(e);
        }
    }

    /**
     * Merges every readable head into the local payload and, when more than one head is readable, pushes the
     * merge commit whose parents are exactly those heads (SPEC 5). Unreadable heads are skipped: never
     * merged, never parents (SPEC 7.5).
     *
     * @return the merge commit id, or empty when there was nothing to merge; fails with {@link
     *     ClientException.Kind#LEFT} after {@link #leave()}, and with the push's failures
     */
    public CompletableFuture<Optional<byte[]>> mergeHeads() {
        return locked(this::mergeHeadsNow);
    }

    private Optional<byte[]> mergeHeadsNow() throws ClientException {
        requireSyncing();
        absorb();
        if (heads.size() < 2) {
            return Optional.empty();
        }
        return Optional.of(commitPayload(copyIds(heads), local));
    }

    // ─── Write ──────────────────────────────────────────────────────────────────────────────

    /**
     * One edit (SPEC 5): {@code edit} changes a copy of the local payload, taking its stamps from the clock
     * with {@link AvpPayload.Hlc#tick(long, String)} after every stamp seen has been observed. The result is
     * checked to be payload v2, stripped by policy (SPEC 5.1), encrypted under the current epoch with the
     * readable heads as parents, and pushed.
     *
     * @param edit changes the payload (with {@link #setField} and {@link #deleteAccount}) and ticks the clock
     * @return the new commit id; fails with {@link ClientException.Kind#LEFT} after {@link #leave()}, {@link
     *     ClientException.Kind#NO_KEY} without the current epoch's key, and {@link ClientException.Kind#HOST}
     *     if the host refuses the push
     */
    public CompletableFuture<byte[]> write(BiConsumer<Map<String, Object>, AvpPayload.Hlc> edit) {
        return locked(() -> writeNow(edit));
    }

    private byte[] writeNow(BiConsumer<Map<String, Object>, AvpPayload.Hlc> edit) throws ClientException {
        requireSyncing();
        absorb();
        try {
            hlc.observeAll(local);
        } catch (AvpException e) {
            throw ClientException.avp(e);
        }
        Map<String, Object> next = normalize(local);
        edit.accept(next, hlc);
        next = normalize(next);
        if (!shareRefresh()) {
            next = strip(next);
        }
        byte[] id = commitPayload(copyIds(heads), next);
        local = next;
        return id;
    }

    /** Seals {@code payload} under the tip's epoch, citing the tip, and pushes it. */
    private byte[] commitPayload(List<byte[]> parents, Map<String, Object> payload) throws ClientException {
        AvpManifest.ManifestState tip = chain.tip().state();
        long epoch = tip.keyEpoch();
        byte[] key = retained.get(epoch);
        if (key == null) {
            throw new ClientException(ClientException.Kind.NO_KEY, "no data key for epoch " + epoch);
        }
        AvpCommit.Header header =
                new AvpCommit.Header(tip.repoId(), parents, tip.manifestSeq(), chain.tipHash(), epoch);
        Map<String, Object> plain = shareRefresh() ? payload : strip(payload);
        AvpCommit.Commit c;
        try {
            c = AvpCommit.seal(key, header, AvpPayload.encode(plain), me.signingSeed);
        } catch (AvpException e) {
            throw ClientException.avp(e);
        }
        host.pushNow(me, tip.repoId(), c);
        record(c);
        heads = new ArrayList<>(List.of(c.commitId()));
        return c.commitId();
    }

    // ─── Owner operations (SPEC 8) ──────────────────────────────────────────────────────────

    /** A mutable copy of the tip state, the next state an owner operation builds. */
    private static final class Next {
        final AvpManifest.ManifestState base;
        final long seq;
        final byte[] prev;
        long keyEpoch;
        boolean share;
        final List<AvpManifest.HostRef> hosts;
        List<AvpManifest.MemberEntry> members;
        final List<AvpManifest.Removal> removals;

        Next(AvpManifest.ManifestState base, long seq, byte[] prev) {
            this.base = base;
            this.seq = seq;
            this.prev = prev;
            this.keyEpoch = base.keyEpoch();
            this.share = base.shareRefreshTokens();
            this.hosts = new ArrayList<>(base.hosts());
            this.members = new ArrayList<>(base.members());
            this.removals = new ArrayList<>(base.removals());
        }

        AvpManifest.ManifestState build() {
            return new AvpManifest.ManifestState(
                    base.repoId(),
                    seq,
                    prev,
                    base.ownerKey(),
                    new byte[0],
                    base.schemeId(),
                    keyEpoch,
                    share,
                    hosts,
                    members,
                    removals);
        }
    }

    @FunctionalInterface
    private interface Change {
        void apply(Next n) throws ClientException;
    }

    /** The next state after the tip, changed by {@code f} and signed by the owner. */
    private AvpManifest.SignedManifest signNext(Change f) throws ClientException {
        AvpManifest.ManifestState tip = chain.tip().state();
        if (tip.manifestSeq() == Long.MAX_VALUE) {
            throw rejected("manifestSeq overflow");
        }
        Next n = new Next(tip, tip.manifestSeq() + 1, chain.tipHash());
        f.apply(n);
        try {
            return AvpManifest.sign(n.build(), me.signingSeed);
        } catch (AvpException e) {
            throw ClientException.avp(e);
        }
    }

    /**
     * Publishes a signed next state (with its commit) and, once the host accepts it, pins it. The state is
     * validated against the tip first, so the owner never publishes what a client rejects.
     */
    private void publish(AvpManifest.SignedManifest signed, AvpCommit.Commit commit) throws ClientException {
        Chain next = chain.copy();
        next.extend(signed);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("manifest", AvpManifest.toJson(signed));
        if (commit != null) {
            body.put("commit", AvpCommit.toJson(commit));
        }
        String path = repoPath(chain.repoId(), "manifest");
        retryMissingParents(() -> host.post(me, path, body));
        int from = chain.size();
        chain = next;
        adoptKeys(from);
        if (!shareRefresh()) {
            local = strip(local);
        }
    }

    /** Runs {@code attempt} again after a pull when the host answers {@code 409 manifest_conflict}. */
    private <T> T retryConflict(Op<T> attempt) throws ClientException {
        int tries = 0;
        while (true) {
            try {
                return attempt.run();
            } catch (ClientException e) {
                if (!e.code().equals(Optional.of("manifest_conflict")) || tries >= CONFLICT_RETRIES) {
                    throw e;
                }
                tries++;
            }
        }
    }

    /**
     * Invites a member from an invite token (SPEC 8.1, 8.2). The token's acceptance must verify under its
     * {@code hostKey}, name this repository and the token's Ed25519 key, name the token's home host, and not
     * have expired. The current data key is wrapped to exactly the token's X25519 key, never to a key served
     * by a host, and the home host is added to {@code hosts} if missing.
     *
     * @param token the joiner's invite token
     * @return completes when the new state is published; fails with {@link
     *     ClientException.Kind#INVITE_REFUSED} for a token that fails verification, a current member, or a
     *     removed key, {@link ClientException.Kind#NOT_PERMITTED} unless this device is the owner, and the
     *     publication's failures
     */
    public CompletableFuture<Void> invite(AvpTokens.InviteToken token) {
        return locked(() -> {
            inviteNow(token);
            return null;
        });
    }

    private void inviteNow(AvpTokens.InviteToken token) throws ClientException {
        requireOwner();
        if (!AvpTokens.verifyInvite(token, chain.repoId(), nowMs())) {
            throw new ClientException(
                    ClientException.Kind.INVITE_REFUSED,
                    "invite refused: the acceptance does not verify for this repository, member, and home host");
        }
        retryConflict(() -> {
            pullNow();
            AvpManifest.ManifestState s = chain.tip().state();
            if (s.hasMember(token.ed25519PublicKey())) {
                throw new ClientException(ClientException.Kind.INVITE_REFUSED, "invite refused: already a member");
            }
            if (s.removalOf(token.ed25519PublicKey()).isPresent()) {
                throw new ClientException(
                        ClientException.Kind.INVITE_REFUSED, "invite refused: a removed key is never a member again");
            }
            long epoch = s.keyEpoch();
            byte[] key = retained.get(epoch);
            if (key == null) {
                throw new ClientException(ClientException.Kind.NO_KEY, "no data key for epoch " + epoch);
            }
            AvpManifest.MemberEntry entry;
            try {
                entry = new AvpManifest.MemberEntry(
                        token.ed25519PublicKey(),
                        token.x25519PublicKey(),
                        AvpCrypto.wrap(token.x25519PublicKey(), key, AvpCrypto.WRAP_INFO),
                        epoch,
                        token.homeHostKey());
            } catch (AvpException e) {
                throw ClientException.avp(e);
            }
            AvpManifest.SignedManifest signed = signNext(n -> {
                n.members.add(entry);
                if (n.hosts.stream().noneMatch(h -> Arrays.equals(h.hostKey(), token.homeHostKey()))) {
                    n.hosts.add(new AvpManifest.HostRef(token.homeHostKey(), token.homeHostLocator()));
                }
            });
            publish(signed, null);
            return null;
        });
    }

    /**
     * Removes a member (SPEC 8.3) in one {@code publishManifest}: pulls and merges every readable head,
     * generates the next epoch's data key and wraps it to every remaining member, drops the member with a
     * removal whose frontier is every merged head plus every verified commit by the member that is not an
     * ancestor of one, and carries the rotation commit (the merged state under the new epoch, parents the
     * merged heads, citing the new state) with the state.
     *
     * @param member the member's 32-byte Ed25519 key
     * @return completes when the state is published; fails with {@link ClientException.Kind#NOT_PERMITTED}
     *     unless this device is the owner, for the owner key, or for a key that is not a member, and the
     *     pull's and the publication's failures
     */
    public CompletableFuture<Void> remove(byte[] member) {
        byte[] key = member.clone();
        return locked(() -> {
            removeNow(key);
            return null;
        });
    }

    private void removeNow(byte[] member) throws ClientException {
        requireOwner();
        if (Arrays.equals(member, me.ed25519Public)) {
            throw new ClientException(ClientException.Kind.NOT_PERMITTED, "the owner is never removed");
        }
        retryConflict(() -> {
            fetch();
            absorb();
            AvpManifest.ManifestState tip = chain.tip().state();
            if (!tip.hasMember(member)) {
                throw new ClientException(ClientException.Kind.NOT_PERMITTED, "not a member");
            }
            if (tip.keyEpoch() == Long.MAX_VALUE) {
                throw rejected("keyEpoch overflow");
            }
            long epoch = tip.keyEpoch() + 1;
            byte[] newKey = AvpCrypto.randomBytes(32);
            List<AvpManifest.MemberEntry> members = new ArrayList<>();
            try {
                for (AvpManifest.MemberEntry m : tip.members()) {
                    if (!Arrays.equals(m.ed25519PublicKey(), member)) {
                        members.add(new AvpManifest.MemberEntry(
                                m.ed25519PublicKey(),
                                m.x25519PublicKey(),
                                AvpCrypto.wrap(m.x25519PublicKey(), newKey, AvpCrypto.WRAP_INFO),
                                epoch,
                                m.homeHostKey()));
                    }
                }
            } catch (AvpException e) {
                throw ClientException.avp(e);
            }
            List<byte[]> parents = copyIds(heads);
            List<byte[]> frontier = frontier(member, parents);
            AvpManifest.SignedManifest signed = signNext(n -> {
                n.keyEpoch = epoch;
                n.members = members;
                n.removals.add(new AvpManifest.Removal(member, n.seq, frontier));
            });
            Map<String, Object> payload = signed.state().shareRefreshTokens() ? local : strip(local);
            AvpCommit.Commit rotation;
            try {
                AvpCommit.Header header = new AvpCommit.Header(
                        signed.state().repoId(),
                        parents,
                        signed.state().manifestSeq(),
                        AvpManifest.hash(signed),
                        epoch);
                rotation = AvpCommit.seal(newKey, header, AvpPayload.encode(payload), me.signingSeed);
            } catch (AvpException e) {
                throw ClientException.avp(e);
            }
            publish(signed, rotation);
            retained.put(epoch, newKey);
            record(rotation);
            heads = new ArrayList<>(List.of(rotation.commitId()));
            leaves = new ArrayList<>(leaves);
            leaves.removeIf(l -> Arrays.equals(l.memberKey(), member));
            return null;
        });
    }

    /**
     * The removal frontier (SPEC 8.3): the merged heads, plus every verified commit by {@code member} that is
     * not one of them or an ancestor of one, sorted.
     */
    private List<byte[]> frontier(byte[] member, List<byte[]> mergedHeads) {
        Set<String> ancestors = new HashSet<>();
        ArrayDeque<String> stack = new ArrayDeque<>();
        for (byte[] h : mergedHeads) {
            stack.push(b64(h));
        }
        while (!stack.isEmpty()) {
            Seen s = seen.get(stack.pop());
            if (s == null) {
                continue;
            }
            for (byte[] p : s.parents()) {
                if (ancestors.add(b64(p))) {
                    stack.push(b64(p));
                }
            }
        }
        List<byte[]> out = copyIds(mergedHeads);
        Set<String> listed = new HashSet<>();
        for (byte[] h : mergedHeads) {
            listed.add(b64(h));
        }
        for (Map.Entry<String, Seen> e : seen.entrySet()) {
            if (Arrays.equals(e.getValue().author(), member)
                    && !ancestors.contains(e.getKey())
                    && listed.add(e.getKey())) {
                try {
                    out.add(AvpEncoding.fromBase64(e.getKey()));
                } catch (AvpException ex) {
                    // Keys of seen are this class's own base64 of 32-byte ids; they always decode.
                }
            }
        }
        out.sort(AvpEncoding::compare);
        return out;
    }

    /**
     * Sets the refresh-token policy (SPEC 5.1, 8.5): a new owner-signed state, no commit.
     *
     * @param on whether members share refresh tokens
     * @return completes when the state is published; fails with {@link ClientException.Kind#NOT_PERMITTED}
     *     unless this device is the owner, and the publication's failures
     */
    public CompletableFuture<Void> setShareRefreshTokens(boolean on) {
        return locked(() -> {
            requireOwner();
            retryConflict(() -> {
                pullNow();
                publish(signNext(n -> n.share = on), null);
                return null;
            });
            return null;
        });
    }

    /**
     * Leaves the repository (SPEC 8.4): sends a signed leave request and stops syncing at once; every later
     * pull and write fails with {@link ClientException.Kind#LEFT}.
     *
     * @return completes when the host stored the request; fails with {@link
     *     ClientException.Kind#NOT_PERMITTED} for the owner, and with the host's failures
     */
    public CompletableFuture<Void> leave() {
        return locked(() -> {
            requireSyncing();
            if (isOwner()) {
                throw new ClientException(ClientException.Kind.NOT_PERMITTED, "the owner cannot leave");
            }
            AvpTokens.LeaveRequest request;
            try {
                request = AvpTokens.signLeave(chain.repoId(), nowMs(), me.signingSeed);
            } catch (AvpException e) {
                throw ClientException.avp(e);
            }
            host.post(me, repoPath(chain.repoId(), "leave"), AvpTokens.toJson(request));
            left = true;
            heads = new ArrayList<>();
            incoming = new ArrayList<>();
            return null;
        });
    }

    /**
     * Processes pending leave requests (SPEC 8.4): pulls, then removes each leaving member that is still a
     * member, one removal each.
     *
     * @return the removed keys; fails with {@link ClientException.Kind#NOT_PERMITTED} unless this device is
     *     the owner, and with the pull's and the removals' failures
     */
    public CompletableFuture<List<byte[]>> processLeaves() {
        return locked(() -> {
            requireOwner();
            pullNow();
            List<byte[]> pending = new ArrayList<>();
            for (AvpTokens.LeaveRequest l : leaves) {
                pending.add(l.memberKey());
            }
            List<byte[]> removed = new ArrayList<>();
            for (byte[] key : pending) {
                if (chain.tip().state().hasMember(key)) {
                    removeNow(key);
                    removed.add(key);
                }
            }
            return removed;
        });
    }

    /**
     * The joiner's step 2 of SPEC 8.1: asks its home host to carry {@code repoId} ({@code prepareJoin}, SPEC
     * 8.2), checks the acceptance the host signed, and builds the invite token for the owner.
     *
     * @param host the joiner's home host
     * @param me the joiner's member identity
     * @param repoId the repository from the owner's repo locator
     * @return the invite token; fails with {@link ClientException.Kind#HOST} if the host refuses to carry
     *     the repository, and {@link ClientException.Kind#BAD_RESPONSE} if the acceptance does not verify
     *     under the host's key or names another repository or member
     */
    public static CompletableFuture<AvpTokens.InviteToken> prepareJoin(HostClient host, Member me, String repoId) {
        return async(host.executor, () -> {
            byte[] memberKey = me.ed25519Public;
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("repoId", repoId);
            body.put("memberKey", b64(memberKey));
            AvpTokens.Acceptance a;
            try {
                a = AvpTokens.acceptanceFromJson(host.post(me, "/v1/prepare-join", body));
            } catch (AvpException e) {
                throw badResponse("prepare-join: " + e.getMessage(), e);
            }
            boolean ok = AvpTokens.verifyAcceptance(a, host.key)
                    && ctEq(a.hostKey(), host.key)
                    && a.repoId().equals(repoId)
                    && ctEq(a.memberKey(), memberKey);
            if (!ok) {
                throw badResponse("the acceptance does not verify", null);
            }
            return new AvpTokens.InviteToken(memberKey, me.x25519Public, host.key, host.locator, a);
        });
    }
}
