/*
 * Client tests against real in-process Java reference hosts, one per test of the Rust client's
 * tests/flow.rs, with the same assertions.
 *
 * SPDX-License-Identifier: MIT
 */

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.lang.reflect.RecordComponent;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

/**
 * The Java client's tests: every test of {@code examples/rust/client/tests/flow.rs}, named after it.
 *
 * <p>Every item is real: owner, member, and host keys are generated, manifests are owner-signed, commits
 * are author-signed and encrypted, and the host is the real Java reference host ({@link Server}). Where a
 * test needs a host to misbehave (a forged manifest, a rollback, a commit the host would never serve), it
 * puts a malicious in-process proxy between the client and an honest host: the proxy forwards every
 * request unchanged, records every request body, and can rewrite the JSON answer of a {@code pull}. That is
 * the "malicious stub host" of the SPEC 7.5 premise: the client never trusts a host's acceptance.
 *
 * <p>Run from this directory: {@code javac -d build ../avp/*.java ../server/Server.java
 * ../server/Replication.java *.java && java -cp build ClientTest [name ...]}. Prints {@code ok <name>} per
 * test and exits 0 only if every test passed.
 */
final class ClientTest {

    private static final String U1 = "00000000-0000-4000-8000-000000000001";
    private static final String U2 = "00000000-0000-4000-8000-000000000002";

    private ClientTest() {}

    /** One test body, with the resources it starts registered on {@code t}. */
    @FunctionalInterface
    private interface Body {
        void run(T t) throws Exception;
    }

    private record Case(String name, Body body) {}

    /**
     * Runs the tests named on the command line, or all of them.
     *
     * @param args test names to run; none runs every test
     */
    public static void main(String[] args) {
        List<Case> cases = List.of(
                new Case("owner_create_and_reopen_from_mnemonic", ClientTest::ownerCreateAndReopenFromMnemonic),
                new Case("invite_requires_valid_acceptance", ClientTest::inviteRequiresValidAcceptance),
                new Case("concurrent_writes_merge_per_field", ClientTest::concurrentWritesMergePerField),
                new Case("delete_then_edit_revives_after_merge", ClientTest::deleteThenEditRevivesAfterMerge),
                new Case("remove_rotates_and_cuts_off", ClientTest::removeRotatesAndCutsOff),
                new Case("leave_processed_by_owner", ClientTest::leaveProcessedByOwner),
                new Case("skips_unreadable_head", ClientTest::skipsUnreadableHead),
                new Case("linked_device_shows_same_mnemonic", ClientTest::linkedDeviceShowsSameMnemonic),
                new Case("refresh_tokens_stripped_when_policy_false", ClientTest::refreshTokensStrippedWhenPolicyFalse),
                new Case(
                        "pulled_manifest_with_bad_owner_signature_is_discarded",
                        ClientTest::pulledManifestWithBadOwnerSignatureIsDiscarded),
                new Case("pulled_manifest_rollback_is_rejected", ClientTest::pulledManifestRollbackIsRejected),
                new Case(
                        "pulled_commit_failing_client_checks_is_discarded",
                        ClientTest::pulledCommitFailingClientChecksIsDiscarded),
                new Case("commit_checks_follow_the_client_chain", ClientTest::commitChecksFollowTheClientChain),
                new Case(
                        "invite_refuses_acceptance_from_another_host_key",
                        ClientTest::inviteRefusesAcceptanceFromAnotherHostKey),
                new Case("client_never_sends_secrets_or_plaintext", ClientTest::clientNeverSendsSecretsOrPlaintext),
                new Case(
                        "owner_signed_states_breaking_chain_rules_are_discarded",
                        ClientTest::ownerSignedStatesBreakingChainRulesAreDiscarded),
                new Case("open_rejects_an_invalid_genesis", ClientTest::openRejectsAnInvalidGenesis),
                new Case("competing_genesis_is_never_adopted", ClientTest::competingGenesisIsNeverAdopted),
                new Case("join_checks_the_owner_fingerprint", ClientTest::joinChecksTheOwnerFingerprint),
                new Case("invalid_leave_requests_are_ignored", ClientTest::invalidLeaveRequestsAreIgnored),
                new Case(
                        "frontier_lists_seen_commits_not_known_as_ancestors",
                        ClientTest::frontierListsSeenCommitsNotKnownAsAncestors),
                new Case(
                        "forged_commit_with_a_real_id_does_not_shadow_it",
                        ClientTest::forgedCommitWithARealIdDoesNotShadowIt),
                new Case(
                        "commit_with_duplicate_parents_is_discarded",
                        ClientTest::commitWithDuplicateParentsIsDiscarded),
                new Case(
                        "host_errors_without_a_json_body_are_reported_by_status",
                        ClientTest::hostErrorsWithoutAJsonBodyAreReportedByStatus),
                new Case("connect_expecting_matches_the_host_key", ClientTest::connectExpectingMatchesTheHostKey),
                new Case(
                        "owner_and_member_pinned_on_a_losing_same_seq_state_recover",
                        ClientTest::ownerAndMemberPinnedOnALosingSameSeqStateRecover),
                new Case("stale_pin_recovery_is_bounded", ClientTest::stalePinRecoveryIsBounded),
                new Case("worked_flow_one_host", ClientTest::workedFlowOneHost),
                new Case("worked_flow_two_peered_hosts", ClientTest::workedFlowTwoPeeredHosts));
        List<String> wanted = List.of(args);
        int passed = 0;
        int failed = 0;
        for (Case c : cases) {
            if (!wanted.isEmpty() && !wanted.contains(c.name())) {
                continue;
            }
            T t = new T();
            try {
                c.body().run(t);
                System.out.println("ok " + c.name());
                passed++;
            } catch (Throwable e) {
                System.out.println("FAIL " + c.name() + ": " + e);
                e.printStackTrace(System.out);
                failed++;
            } finally {
                t.close();
            }
        }
        System.out.println("ClientTest: " + passed + " passed, " + failed + " failed");
        System.exit(failed == 0 && passed > 0 ? 0 : 1);
    }

    // ─── Harness: in-process hosts, proxies, and what one test started ──────────────────────

    /** A running Java reference host. */
    private static final class Node {
        final byte[] seed = AvpCrypto.randomBytes(32);
        final HttpServer http;
        final Server.Host st;

        Node() throws IOException {
            this(false);
        }

        /** A host whose test control ({@code POST /v1/test/replication}) is on when {@code testControl}. */
        Node(boolean testControl) throws IOException {
            this.http = Server.start(
                    0,
                    new Server.ServerConfig(
                            "127.0.0.1",
                            seed,
                            Replication.Peers.none(),
                            new Server.Limits(),
                            new Replication.Config(100, 2000, 16L * 1024 * 1024, testControl)));
            this.st = Server.host(http);
        }

        int port() {
            return http.getAddress().getPort();
        }

        String url() {
            return "http://127.0.0.1:" + port();
        }

        String addr() {
            return "127.0.0.1:" + port();
        }

        byte[] key() {
            return st.hostKey.clone();
        }

        byte[] signing() {
            return seed.clone();
        }

        String entry() {
            return AvpEncoding.base64(key()) + "@" + url();
        }

        <R> Optional<R> view(String repo, Function<AvpRules.RepoView, R> f) {
            st.lock();
            try {
                AvpRules.RepoView v = st.repos.get(repo);
                return v == null ? Optional.empty() : Optional.ofNullable(f.apply(v));
            } finally {
                st.unlock();
            }
        }

        long tipSeq(String repo) {
            return view(repo, v -> v.tip().map(m -> m.state().manifestSeq()).orElse(0L))
                    .orElse(0L);
        }

        List<byte[]> heads(String repo) {
            return view(repo, AvpRules.RepoView::heads).orElse(List.of());
        }

        AvpCommit.Commit commit(String repo, byte[] id) {
            return view(repo, v -> v.fetchCommit(id).orElse(null))
                    .orElseThrow(() -> new AssertionError("the host holds the commit"));
        }

        int repoCount() {
            st.lock();
            try {
                return st.repos.size();
            } finally {
                st.unlock();
            }
        }

        void stop() {
            Server.stop(http);
        }
    }

    /** Rewrites a {@code 200} JSON answer: the request path, the parsed request body, the parsed answer. */
    @FunctionalInterface
    private interface Tamper {
        void apply(String path, Object request, Map<String, Object> answer) throws Exception;
    }

    /** Rewrites the answer of a {@code pull}: the parsed request body and the parsed answer. */
    @FunctionalInterface
    private interface PullTamper {
        void apply(Map<String, Object> request, Map<String, Object> answer) throws Exception;
    }

    private record Logged(String path, byte[] body) {}

    /**
     * Answers the next {@code budget} requests whose path ends with {@code suffix} with a SPEC 10.4 error,
     * without forwarding them; later ones are forwarded again.
     */
    private static final class Deny {
        final String suffix;
        final int status;
        final String code;
        int budget;

        Deny(String suffix, int status, String code, int budget) {
            this.suffix = suffix;
            this.status = status;
            this.code = code;
            this.budget = budget;
        }

        synchronized boolean take(String path) {
            if (budget > 0 && path.endsWith(suffix)) {
                budget--;
                return true;
            }
            return false;
        }
    }

    /**
     * Forwards every request to an honest host unchanged, records {@code (path, body)} of each, and lets
     * the test rewrite the JSON answer of a {@code 200} reply.
     */
    private static final class Proxy {
        final HttpServer server;
        final String upstream;
        final HttpClient http = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        final List<Logged> log = new ArrayList<>();
        final AtomicReference<Tamper> tamper = new AtomicReference<>();
        final AtomicReference<Deny> deny = new AtomicReference<>();

        Proxy(Node upstream) throws IOException {
            this.upstream = upstream.url();
            this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 64);
            server.createContext("/", this::handle);
            server.setExecutor(Executors.newFixedThreadPool(4, r -> {
                Thread th = new Thread(r, "client-test-proxy");
                th.setDaemon(true);
                return th;
            }));
            server.start();
        }

        private void handle(HttpExchange ex) throws IOException {
            try (ex) {
                byte[] body;
                try (InputStream in = ex.getRequestBody()) {
                    body = in.readAllBytes();
                }
                String path = ex.getRequestURI().getRawPath();
                String auth = ex.getRequestHeaders().getFirst("Authorization");
                synchronized (log) {
                    log.add(new Logged(path, body));
                }
                Deny d = deny.get();
                if (d != null && d.take(path)) {
                    byte[] err = AvpJson.writeUtf8(Map.of("error", "denied by the test proxy", "code", d.code));
                    ex.sendResponseHeaders(d.status, err.length);
                    try (OutputStream out = ex.getResponseBody()) {
                        out.write(err);
                    }
                    return;
                }
                HttpRequest.Builder b =
                        HttpRequest.newBuilder(URI.create(upstream + path)).timeout(Duration.ofSeconds(30));
                if (ex.getRequestMethod().equals("GET")) {
                    b.GET();
                } else {
                    b.POST(HttpRequest.BodyPublishers.ofByteArray(body)).header("Content-Type", "application/json");
                    if (auth != null) {
                        b.header("Authorization", auth);
                    }
                }
                int status;
                byte[] bytes;
                try {
                    HttpResponse<byte[]> r = http.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
                    status = r.statusCode();
                    bytes = r.body();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException(e);
                }
                Tamper f = tamper.get();
                if (status == 200 && f != null) {
                    Object request = null;
                    try {
                        request = AvpJson.parse(body);
                    } catch (AvpException e) {
                        // A body that is not JSON (a GET): the tamper sees null.
                    }
                    try {
                        Map<String, Object> answer = AvpJson.object(AvpJson.parse(bytes), "answer");
                        f.apply(path, request, answer);
                        bytes = AvpJson.writeUtf8(answer);
                    } catch (Exception e) {
                        throw new IOException("tamper failed", e);
                    }
                }
                ex.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
                try (OutputStream out = ex.getResponseBody()) {
                    out.write(bytes);
                }
            }
        }

        String url() {
            return "http://127.0.0.1:" + server.getAddress().getPort();
        }

        void onPull(PullTamper f) {
            tamper.set((path, req, ans) -> {
                if (path.endsWith("/pull")) {
                    f.apply(AvpJson.object(req, "pull request"), ans);
                }
            });
        }

        void honest() {
            tamper.set(null);
        }

        /** Answers the next {@code budget} requests to a path ending with {@code suffix} with an error. */
        void deny(String suffix, int status, String code, int budget) {
            deny.set(new Deny(suffix, status, code, budget));
        }

        List<String> paths() {
            synchronized (log) {
                return log.stream().map(Logged::path).toList();
            }
        }

        List<byte[]> bodies() {
            synchronized (log) {
                return log.stream().map(Logged::body).toList();
            }
        }

        int requestCount() {
            synchronized (log) {
                return log.size();
            }
        }

        void stop() {
            server.stop(0);
            http.close();
        }
    }

    /** What one test started; everything is stopped when the test ends. */
    private static final class T implements AutoCloseable {
        private final List<Node> nodes = new ArrayList<>();
        private final List<Proxy> proxies = new ArrayList<>();
        private final List<AutoCloseable> clients = new ArrayList<>();

        Node node() throws IOException {
            return node(false);
        }

        Node node(boolean testControl) throws IOException {
            Node n = new Node(testControl);
            nodes.add(n);
            return n;
        }

        /** Two hosts peered with each other ({@code AVP_PEERS} built from their keys and addresses). */
        Node[] peeredPair() throws Exception {
            return peeredPair(false);
        }

        /** Two peered hosts, with the test control on when {@code testControl}. */
        Node[] peeredPair(boolean testControl) throws Exception {
            Node a = node(testControl);
            Node b = node(testControl);
            Server.peerWith(a.http, Replication.Peers.fromEnv(b.entry()));
            Server.peerWith(b.http, Replication.Peers.fromEnv(a.entry()));
            return new Node[] {a, b};
        }

        Proxy proxy(Node upstream) throws IOException {
            Proxy p = new Proxy(upstream);
            proxies.add(p);
            return p;
        }

        Vault.HostClient host(String url) throws Vault.ClientException {
            Vault.HostClient h = await(Vault.HostClient.connect(url));
            clients.add(h);
            return h;
        }

        Owned ownerVault(String url) throws Vault.ClientException {
            Vault.OwnerIdentity id = Vault.OwnerIdentity.generate();
            Vault v = await(Vault.create(host(url), id.keys()));
            return new Owned(id, v);
        }

        Vault open(String url, Vault.Member me, String repo) throws Vault.ClientException {
            return await(Vault.open(host(url), me, repo));
        }

        /** A new member homed on {@code homeUrl}, invited by {@code owner} from a real prepareJoin acceptance. */
        Vault inviteMember(Vault owner, String homeUrl) throws Exception {
            Vault.Member me = Vault.Member.generate();
            Vault.HostClient home = host(homeUrl);
            AvpTokens.InviteToken token = await(Vault.prepareJoin(home, me, owner.repoId()));
            await(owner.invite(token));
            AvpTokens.RepoLocator locator = owner.locator();
            eventually("the joiner's home host holds the repository", () -> {
                try {
                    await(Vault.join(host(homeUrl), me, locator));
                    return true;
                } catch (Vault.ClientException e) {
                    return false;
                }
            });
            return await(Vault.join(home, me, locator));
        }

        @Override
        public void close() {
            for (AutoCloseable c : clients) {
                try {
                    c.close();
                } catch (Exception e) {
                    // Closing a client after its test cannot fail the test.
                }
            }
            proxies.forEach(Proxy::stop);
            nodes.forEach(Node::stop);
        }
    }

    private record Owned(Vault.OwnerIdentity id, Vault vault) {}

    // ─── Helpers ────────────────────────────────────────────────────────────────────────────

    /** Waits for a future; a failure is rethrown as the client's exception. */
    private static <R> R await(CompletableFuture<R> f) throws Vault.ClientException {
        try {
            return f.join();
        } catch (CompletionException e) {
            if (e.getCause() instanceof Vault.ClientException ce) {
                throw ce;
            }
            throw e;
        }
    }

    @FunctionalInterface
    private interface Check {
        boolean test() throws Exception;
    }

    @FunctionalInterface
    private interface Action {
        Object run() throws Exception;
    }

    private static void eventually(String what, Check f) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos();
        while (System.nanoTime() < deadline) {
            if (f.test()) {
                return;
            }
            Thread.sleep(50);
        }
        throw new AssertionError("not reached within 20 s: " + what);
    }

    /** The client exception {@code a} fails with. */
    private static Vault.ClientException thrown(Action a) throws Exception {
        Object v;
        try {
            v = a.run();
        } catch (Vault.ClientException e) {
            return e;
        }
        throw new AssertionError("expected a client error, got " + v);
    }

    /** The host's machine code of the error {@code a} fails with ({@code none} for another error). */
    private static String hostCode(Action a) throws Exception {
        return thrown(a).code().orElse("none");
    }

    private static void isTrue(boolean cond, String what) {
        if (!cond) {
            throw new AssertionError(what);
        }
    }

    private static void eq(Object actual, Object expected, String what) {
        boolean same = actual instanceof byte[] x && expected instanceof byte[] y
                ? Arrays.equals(x, y)
                : Objects.equals(actual, expected);
        if (!same) {
            throw new AssertionError(what + ": expected " + show(expected) + ", got " + show(actual));
        }
    }

    private static String show(Object o) {
        return o instanceof byte[] b ? AvpEncoding.base64(b) : String.valueOf(o);
    }

    private static String b64(byte[] b) {
        return AvpEncoding.base64(b);
    }

    private static byte[] unb64(Object s) throws AvpException {
        return AvpEncoding.fromBase64(AvpJson.string(s, "base64"));
    }

    /** Ids as base64, in order. */
    private static List<String> ids(List<byte[]> ids) {
        return ids.stream().map(AvpEncoding::base64).toList();
    }

    private static List<String> ids(byte[]... ids) {
        return ids(List.of(ids));
    }

    /** Ids as base64, sorted: a set comparison. */
    private static List<String> sorted(List<byte[]> ids) {
        return ids(ids).stream().sorted().toList();
    }

    private static List<String> sorted(byte[]... ids) {
        return sorted(List.of(ids));
    }

    private static boolean contains(List<byte[]> ids, byte[] id) {
        return ids.stream().anyMatch(x -> Arrays.equals(x, id));
    }

    /** One edit: one tick, the same stamp on every field set (SPEC 5). Fields are name, value pairs. */
    private static Map<String, Object> set(Vault v, String uuid, long now, Object... fields)
            throws Vault.ClientException {
        String by = v.member().id();
        AtomicReference<Map<String, Object>> stamp = new AtomicReference<>();
        await(v.write((p, hlc) -> {
            Map<String, Object> s = hlc.tick(now, by);
            for (int k = 0; k < fields.length; k += 2) {
                Vault.setField(p, uuid, (String) fields[k], fields[k + 1], s);
            }
            stamp.set(s);
        }));
        return stamp.get();
    }

    private static Map<String, Object> stamp(long at, long n, String by) {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("at", at);
        s.put("n", n);
        s.put("by", by);
        return s;
    }

    /** Orders two stamps by {@code (at, n, by)} (SPEC 5). */
    private static int order(Map<String, Object> a, Map<String, Object> b) throws AvpException {
        int c = Long.compare(AvpJson.integer(a, "at"), AvpJson.integer(b, "at"));
        if (c == 0) {
            c = Long.compare(AvpJson.integer(a, "n"), AvpJson.integer(b, "n"));
        }
        if (c == 0) {
            c = Arrays.compareUnsigned(
                    AvpJson.string(a, "by").getBytes(StandardCharsets.UTF_8),
                    AvpJson.string(b, "by").getBytes(StandardCharsets.UTF_8));
        }
        return c;
    }

    private static Map<String, Object> account(Map<String, Object> p, String uuid) throws AvpException {
        return AvpJson.object(AvpJson.object(p.get("accounts"), "accounts").get(uuid), uuid);
    }

    private static boolean hasAccount(Map<String, Object> p, String uuid) throws AvpException {
        return AvpJson.object(p.get("accounts"), "accounts").containsKey(uuid);
    }

    private static Map<String, Object> fields(Map<String, Object> p, String uuid) throws AvpException {
        return AvpJson.object(account(p, uuid).get("fields"), "fields");
    }

    private static boolean hasField(Map<String, Object> p, String uuid, String name) throws AvpException {
        return hasAccount(p, uuid) && fields(p, uuid).containsKey(name);
    }

    /** A field's value; the field must exist. */
    private static Object value(Map<String, Object> p, String uuid, String name) throws AvpException {
        isTrue(hasField(p, uuid, name), "field " + uuid + "/" + name + " is present");
        return AvpJson.object(fields(p, uuid).get(name), name).get("value");
    }

    private static boolean isDeleted(Map<String, Object> p, String uuid) throws AvpException {
        return AvpPayload.isDeleted(account(p, uuid));
    }

    private static Map<String, Object> decrypt(AvpCommit.Commit c, byte[] key) throws AvpException {
        return AvpPayload.parse(AvpCommit.open(c, key));
    }

    /** A forged commit sealed with real keys, so only the client's own checks can stop it. */
    private static AvpCommit.Commit forge(byte[] key, AvpCommit.Header header, String uuid, byte[] authorSeed)
            throws AvpException {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("v", 2L);
        p.put("accounts", new TreeMap<String, Object>());
        Map<String, Object> s =
                stamp(Vault.nowMs() + 1_000_000, 0, AvpEncoding.base64(AvpCrypto.ed25519Public(authorSeed)));
        Vault.setField(p, uuid, "username", "forged", s);
        return AvpCommit.seal(key, header, AvpPayload.encode(p), authorSeed);
    }

    private static AvpCommit.Header headerAt(Vault v, List<byte[]> parents, long seq, byte[] hash, long epoch) {
        return new AvpCommit.Header(v.repoId(), parents, seq, hash, epoch);
    }

    private static AvpCommit.Commit withParents(AvpCommit.Commit c, List<byte[]> parents) {
        return new AvpCommit.Commit(
                c.repoId(),
                c.commitId(),
                parents,
                c.manifestSeq(),
                c.manifestHash(),
                c.keyEpoch(),
                c.author(),
                c.iv(),
                c.ciphertext(),
                c.authorSignature());
    }

    private static AvpCommit.Commit withSignature(AvpCommit.Commit c, byte[] signature) {
        return new AvpCommit.Commit(
                c.repoId(),
                c.commitId(),
                c.parents(),
                c.manifestSeq(),
                c.manifestHash(),
                c.keyEpoch(),
                c.author(),
                c.iv(),
                c.ciphertext(),
                signature);
    }

    /** A mutable copy of a manifest state, to build test states from. */
    private static final class Draft {
        String repoId;
        long seq;
        byte[] prev;
        byte[] owner;
        byte[] nonce;
        String scheme;
        long epoch;
        boolean share;
        List<AvpManifest.HostRef> hosts;
        List<AvpManifest.MemberEntry> members;
        List<AvpManifest.Removal> removals;

        Draft(AvpManifest.ManifestState s) {
            repoId = s.repoId();
            seq = s.manifestSeq();
            prev = s.prevManifestHash();
            owner = s.ownerKey();
            nonce = s.genesisNonce();
            scheme = s.schemeId();
            epoch = s.keyEpoch();
            share = s.shareRefreshTokens();
            hosts = new ArrayList<>(s.hosts());
            members = new ArrayList<>(s.members());
            removals = new ArrayList<>(s.removals());
        }

        AvpManifest.ManifestState build() {
            return new AvpManifest.ManifestState(
                    repoId, seq, prev, owner, nonce, scheme, epoch, share, hosts, members, removals);
        }

        AvpManifest.SignedManifest sign(byte[] ownerSeed) throws AvpException {
            return AvpManifest.sign(build(), ownerSeed);
        }
    }

    private static List<Object> json(List<AvpManifest.SignedManifest> states) {
        List<Object> out = new ArrayList<>();
        for (AvpManifest.SignedManifest m : states) {
            out.add(AvpManifest.toJson(m));
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> list(Map<String, Object> o, String key) throws AvpException {
        Object v = o.get(key);
        if (v instanceof List<?> l) {
            return (List<Object>) l;
        }
        throw new AvpException(AvpException.Kind.BAD_ENCODING, key + " is not a list");
    }

    private static Object deepCopy(Object json) throws AvpException {
        return AvpJson.parse(AvpJson.write(json));
    }

    /** Makes the proxy serve {@code chain ++ extra} to a pull from seq 0 and {@code extra} to any other. */
    private static void serveStates(
            Proxy proxy, List<AvpManifest.SignedManifest> chain, List<AvpManifest.SignedManifest> extra) {
        List<AvpManifest.SignedManifest> all = new ArrayList<>(chain);
        all.addAll(extra);
        List<Object> full = json(all);
        List<Object> tail = json(extra);
        proxy.onPull((req, ans) ->
                ans.put("manifests", deepCopy(Long.valueOf(0).equals(req.get("sinceManifestSeq")) ? full : tail)));
    }

    private static AvpManifest.MemberEntry entry(AvpManifest.ManifestState s, byte[] key) {
        return s.members().stream()
                .filter(m -> Arrays.equals(m.ed25519PublicKey(), key))
                .findFirst()
                .orElseThrow(() -> new AssertionError("member listed"));
    }

    private static boolean containsBytes(byte[] hay, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= hay.length; i++) {
            for (int k = 0; k < needle.length; k++) {
                if (hay[i + k] != needle[k]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    /** A full rendering of a host object graph: every byte array as {@code x<hex>}, every field reached. */
    private static String dump(Object o) {
        StringBuilder sb = new StringBuilder();
        dump(o, sb, new IdentityHashMap<>());
        return sb.toString();
    }

    private static void dump(Object o, StringBuilder sb, IdentityHashMap<Object, Boolean> seen) {
        if (o == null) {
            sb.append("null");
        } else if (o instanceof byte[] b) {
            sb.append("x").append(AvpEncoding.hex(b));
        } else if (o instanceof String || o instanceof Number || o instanceof Boolean || o instanceof Enum<?>) {
            sb.append('"').append(o).append('"');
        } else if (seen.containsKey(o)) {
            sb.append("<cycle>");
        } else {
            seen.put(o, Boolean.TRUE);
            if (o instanceof Map<?, ?> m) {
                sb.append('{');
                for (Map.Entry<?, ?> e : m.entrySet()) {
                    dump(e.getKey(), sb, seen);
                    sb.append('=');
                    dump(e.getValue(), sb, seen);
                    sb.append(',');
                }
                sb.append('}');
            } else if (o instanceof Collection<?> c) {
                sb.append('[');
                for (Object x : c) {
                    dump(x, sb, seen);
                    sb.append(',');
                }
                sb.append(']');
            } else if (o instanceof Optional<?> opt) {
                dump(opt.orElse(null), sb, seen);
            } else if (o.getClass().isRecord()) {
                sb.append(o.getClass().getSimpleName()).append('{');
                for (RecordComponent rc : o.getClass().getRecordComponents()) {
                    sb.append(rc.getName()).append('=');
                    try {
                        rc.getAccessor().setAccessible(true);
                        dump(rc.getAccessor().invoke(o), sb, seen);
                    } catch (ReflectiveOperationException e) {
                        throw new IllegalStateException(e);
                    }
                    sb.append(',');
                }
                sb.append('}');
            } else if (o.getClass().getName().startsWith("java.")) {
                sb.append(o);
            } else {
                sb.append(o.getClass().getSimpleName()).append('{');
                for (Class<?> c = o.getClass(); c != null && c != Object.class; c = c.getSuperclass()) {
                    for (Field f : c.getDeclaredFields()) {
                        if (Modifier.isStatic(f.getModifiers())) {
                            continue;
                        }
                        f.setAccessible(true);
                        sb.append(f.getName()).append('=');
                        try {
                            dump(f.get(o), sb, seen);
                        } catch (IllegalAccessException e) {
                            throw new IllegalStateException(e);
                        }
                        sb.append(',');
                    }
                }
                sb.append('}');
            }
            seen.remove(o);
        }
    }

    /** The bytes as text, if they are well-formed UTF-8. */
    private static Optional<String> utf8(byte[] raw) {
        try {
            return Optional.of(StandardCharsets.UTF_8
                    .newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(raw))
                    .toString());
        } catch (CharacterCodingException e) {
            return Optional.empty();
        }
    }

    // ─── The nine named tests ───────────────────────────────────────────────────────────────

    /**
     * SPEC 3.1, 4.2, 6.2: the phrase is the identity. A vault created from a fresh phrase is reopened on a new
     * device from the phrase alone; a different phrase is not a member; a malformed phrase is rejected.
     */
    private static void ownerCreateAndReopenFromMnemonic(T t) throws Exception {
        Node a = t.node();
        Owned o = t.ownerVault(a.url());
        Vault.OwnerIdentity id = o.id();
        Vault v = o.vault();
        String phrase = id.mnemonic();
        eq(phrase.split(" ").length, 24, "24 words (SPEC 3.1)");

        AvpManifest.SignedManifest genesis = v.chain().states().get(0);
        AvpManifest.ManifestState s = genesis.state();
        eq(s.manifestSeq(), 1L, "manifestSeq");
        eq(s.keyEpoch(), 0L, "keyEpoch");
        eq(s.prevManifestHash().length, 0, "prevManifestHash empty");
        eq(s.ownerKey(), id.keys().ed25519Public(), "ownerKey");
        eq(s.genesisNonce().length, 16, "genesisNonce is 16 bytes");
        eq(s.repoId(), AvpManifest.deriveRepoId(s.ownerKey(), s.genesisNonce()), "repoId (SPEC 4.2)");
        eq(s.repoId().length(), 22, "repoId length");
        eq(s.hosts().size(), 1, "one host");
        eq(s.hosts().get(0).hostKey(), a.key(), "host key");
        eq(s.hosts().get(0).locator(), a.addr(), "host locator");
        eq(s.members().size(), 1, "genesis has exactly the owner (SPEC 6.2)");
        isTrue(!s.shareRefreshTokens(), "policy defaults to false (SPEC 5.1)");
        isTrue(AvpManifest.verify(genesis), "genesis verifies");
        eq(a.tipSeq(v.repoId()), 1L, "host tip");

        set(v, U1, Vault.nowMs(), "username", "alice-alt", "accessToken", "at-1");
        String repo = v.repoId();
        v.close();

        // A new device with only the phrase derives the same keys and reads the vault.
        Vault.OwnerIdentity again = Vault.OwnerIdentity.fromMnemonic(phrase);
        eq(again.entropy(), id.entropy(), "entropy");
        eq(again.keys().ed25519Public(), id.keys().ed25519Public(), "owner key");
        eq(again.keys().x25519Public(), id.keys().x25519Public(), "owner x25519 key");
        Vault reopened = t.open(a.url(), Vault.Member.fromOwner(again.keys()), repo);
        eq(value(reopened.payload(), U1, "username"), "alice-alt", "username");
        eq(value(reopened.payload(), U1, "accessToken"), "at-1", "accessToken");
        eq(reopened.retainedEpochKeys().size(), 1, "one epoch key");

        // Another phrase is another identity: not a member (SPEC 10.1).
        Vault.OwnerIdentity other = Vault.OwnerIdentity.generate();
        eq(hostCode(() -> t.open(a.url(), Vault.Member.fromOwner(other.keys()), repo)), "forbidden", "stranger");

        // SPEC 3.1: reject a phrase that is not exactly 24 words or has an unknown word.
        String[] words = phrase.split(" ");
        String shortPhrase = String.join(" ", Arrays.copyOf(words, 23));
        thrown(() -> Vault.OwnerIdentity.fromMnemonic(shortPhrase));
        words[0] = "notaword";
        String unknown = String.join(" ", words);
        thrown(() -> Vault.OwnerIdentity.fromMnemonic(unknown));
    }

    /**
     * SPEC 8.1, 8.2: the owner adds a member only from an invite token whose acceptance verifies, and wraps
     * the data key to exactly the token's X25519 key.
     */
    private static void inviteRequiresValidAcceptance(T t) throws Exception {
        Node a = t.node();
        Vault owner = t.ownerVault(a.url()).vault();
        String repo = owner.repoId();
        set(owner, U1, Vault.nowMs(), "username", "shared");

        Vault.Member bob = Vault.Member.generate();
        Vault.HostClient home = t.host(a.url());
        AvpTokens.InviteToken good = await(Vault.prepareJoin(home, bob, repo));
        eq(good.acceptance().hostKey(), a.key(), "acceptance host key");
        eq(good.homeHostKey(), a.key(), "home host key");
        eq(good.acceptance().memberKey(), bob.ed25519Public(), "acceptance member key");
        // The token is out-of-band text and round-trips (SPEC 11.1).
        String text = AvpTokens.encode(AvpTokens.toJson(good));
        AvpTokens.InviteToken decoded = AvpTokens.inviteTokenFromJson(AvpTokens.decode(text));
        eq(AvpJson.write(AvpTokens.toJson(decoded)), AvpJson.write(AvpTokens.toJson(good)), "token round trip");

        byte[] hostSeed = a.signing();
        String otherRepo = AvpEncoding.base64Url(AvpCrypto.randomBytes(16));
        Map<String, AvpTokens.InviteToken> bad = new LinkedHashMap<>();
        // The acceptance names another repository.
        bad.put(
                "other repoId",
                new AvpTokens.InviteToken(
                        good.ed25519PublicKey(),
                        good.x25519PublicKey(),
                        good.homeHostKey(),
                        good.homeHostLocator(),
                        AvpTokens.signAcceptance(otherRepo, bob.ed25519Public(), Vault.nowMs() + 600_000, hostSeed)));
        // The acceptance is for another member key than the token's.
        bad.put(
                "memberKey mismatch",
                new AvpTokens.InviteToken(
                        Vault.Member.generate().ed25519Public(),
                        good.x25519PublicKey(),
                        good.homeHostKey(),
                        good.homeHostLocator(),
                        good.acceptance()));
        // The token's home host is not the host that accepted.
        bad.put(
                "homeHostKey mismatch",
                new AvpTokens.InviteToken(
                        good.ed25519PublicKey(),
                        good.x25519PublicKey(),
                        AvpCrypto.randomBytes(32),
                        good.homeHostLocator(),
                        good.acceptance()));
        // Expired (signed by the real host key, expiresAt in the past).
        bad.put(
                "expired",
                new AvpTokens.InviteToken(
                        good.ed25519PublicKey(),
                        good.x25519PublicKey(),
                        good.homeHostKey(),
                        good.homeHostLocator(),
                        AvpTokens.signAcceptance(repo, bob.ed25519Public(), Vault.nowMs() - 1, hostSeed)));
        // Tampered signature.
        AvpTokens.Acceptance ga = good.acceptance();
        byte[] sig = ga.signature().clone();
        sig[0] ^= 1;
        bad.put(
                "bad signature",
                new AvpTokens.InviteToken(
                        good.ed25519PublicKey(),
                        good.x25519PublicKey(),
                        good.homeHostKey(),
                        good.homeHostLocator(),
                        new AvpTokens.Acceptance(ga.repoId(), ga.memberKey(), ga.hostKey(), ga.expiresAt(), sig)));

        for (Map.Entry<String, AvpTokens.InviteToken> e : bad.entrySet()) {
            Vault.ClientException r = thrown(() -> await(owner.invite(e.getValue())));
            eq(r.kind(), Vault.ClientException.Kind.INVITE_REFUSED, e.getKey());
            eq(a.tipSeq(repo), 1L, e.getKey() + ": nothing published");
            eq(owner.tip().state().manifestSeq(), 1L, e.getKey());
        }

        await(owner.invite(good));
        eq(a.tipSeq(repo), 2L, "published");
        AvpManifest.ManifestState s = owner.tip().state();
        AvpManifest.MemberEntry entry = entry(s, bob.ed25519Public());
        eq(entry.x25519PublicKey(), good.x25519PublicKey(), "wrapped to the token's key");
        eq(entry.homeHostKey(), a.key(), "home host");
        eq(entry.keyEpoch(), s.keyEpoch(), "epoch");
        // Wrapped to exactly the token's X25519 key: bob's private key opens it to the data key.
        byte[] dk = AvpCrypto.unwrap(bob.x25519Private(), entry.wrappedDataKey(), AvpCrypto.WRAP_INFO);
        eq(dk, owner.retainedEpochKeys().get(0L), "data key");

        Vault joined = await(Vault.join(home, bob, owner.locator()));
        eq(value(joined.payload(), U1, "username"), "shared", "bob reads");
    }

    /**
     * SPEC 5: concurrent writes to different fields of one account both survive the merge; on the same
     * field the greater stamp wins; the merge commit names exactly the merged heads; the merging client
     * observes every stamp before its next tick.
     */
    private static void concurrentWritesMergePerField(T t) throws Exception {
        Node a = t.node();
        Vault owner = t.ownerVault(a.url()).vault();
        String repo = owner.repoId();
        long now = Vault.nowMs() + 10_000;
        set(owner, U1, now, "username", "u0", "accessToken", "t0", "lastUsed", 1L);
        Vault bob = t.inviteMember(owner, a.url());
        await(owner.pull());

        // Both write from the same head, without pulling in between.
        Map<String, Object> sOwner = set(owner, U1, now + 10, "username", "owner-name", "lastUsed", 100L);
        Map<String, Object> sBob = set(bob, U1, now + 20, "accessToken", "bob-token", "lastUsed", 200L);
        isTrue(order(sBob, sOwner) > 0, "bob's stamp is greater");
        byte[] oh = owner.heads().get(0);
        byte[] bh = bob.heads().get(0);
        eq(sorted(a.heads(repo)), sorted(oh, bh), "two heads at the host");

        Vault.PullReport report = await(owner.pull());
        byte[] merge = report.mergeCommit()
                .orElseThrow(() -> new AssertionError("two readable heads are merged and pushed (SPEC 5)"));
        eq(ids(owner.heads()), ids(merge), "the owner's head");
        eq(ids(a.heads(repo)), ids(merge), "the host's head");
        AvpCommit.Commit mc = a.commit(repo, merge);
        eq(sorted(mc.parents()), sorted(oh, bh), "parents are exactly the merged heads");
        eq(mc.author(), owner.member().ed25519Public(), "author");

        Map<String, Object> p = owner.payload();
        eq(value(p, U1, "username"), "owner-name", "username");
        eq(value(p, U1, "accessToken"), "bob-token", "accessToken");
        eq(value(p, U1, "lastUsed"), 200L, "same field: greatest stamp wins");
        eq(decrypt(mc, owner.retainedEpochKeys().get(0L)), p, "the merge commit carries the merge");

        // HLC: bob's stamp was observed, so the next write is greater even with an older wall clock.
        isTrue(owner.hlc().at() >= AvpJson.integer(sBob, "at"), "observed bob's stamp");
        Map<String, Object> next = set(owner, U2, now, "username", "later");
        isTrue(order(next, sBob) > 0, next + " > " + sBob);

        await(bob.pull());
        eq(value(bob.payload(), U1, "username"), "owner-name", "bob username");
        eq(value(bob.payload(), U1, "accessToken"), "bob-token", "bob accessToken");
        eq(bob.payload(), owner.payload(), "both converge");
    }

    /** SPEC 5: an edit after a deletion brings the account back; a deletion after the edit removes it. */
    private static void deleteThenEditRevivesAfterMerge(T t) throws Exception {
        Node a = t.node();
        Vault owner = t.ownerVault(a.url()).vault();
        long now = Vault.nowMs() + 10_000;
        set(owner, U1, now, "username", "u0");
        Vault bob = t.inviteMember(owner, a.url());
        await(owner.pull());

        String by = owner.member().id();
        await(owner.write((p, hlc) -> Vault.deleteAccount(p, U1, hlc.tick(now + 10, by))));
        isTrue(isDeleted(owner.payload(), U1), "deleted");
        set(bob, U1, now + 20, "username", "edited");

        await(owner.pull());
        Map<String, Object> acc = account(owner.payload(), U1);
        isTrue(acc.get("deleted") != null, "the marker stays");
        isTrue(!isDeleted(owner.payload(), U1), "the later edit revives the account");
        eq(value(owner.payload(), U1, "username"), "edited", "username");

        // A deletion after the edit removes it again, for everyone.
        await(owner.write((p, hlc) -> Vault.deleteAccount(p, U1, hlc.tick(now, by))));
        isTrue(isDeleted(owner.payload(), U1), "deleted again");
        await(bob.pull());
        isTrue(isDeleted(bob.payload(), U1), "deleted for bob");
        eq(bob.payload(), owner.payload(), "both converge");
    }

    /**
     * SPEC 8.3, 7.3: removal rotates the key, rewraps to the remaining members, sets the frontier from the
     * merged heads, and publishes the rotation commit with the state in one publishManifest.
     */
    private static void removeRotatesAndCutsOff(T t) throws Exception {
        Node a = t.node();
        Proxy proxy = t.proxy(a);
        Vault owner = t.ownerVault(proxy.url()).vault();
        String repo = owner.repoId();
        set(owner, U1, Vault.nowMs(), "username", "u0");
        Vault bob = t.inviteMember(owner, a.url());
        Vault carol = t.inviteMember(owner, a.url());
        // Two concurrent heads, one by bob and one by carol: the removal merges both straight into the
        // rotation commit, so its frontier is both heads, by any author (SPEC 7.3, 8.3).
        set(bob, U2, Vault.nowMs(), "username", "bob-wrote");
        set(carol, U1, Vault.nowMs(), "accessToken", "carol-wrote");
        byte[] b1 = bob.heads().get(0);
        byte[] c1 = carol.heads().get(0);
        List<String> merged = sorted(b1, c1);
        eq(sorted(a.heads(repo)), merged, "two heads");
        AvpManifest.SignedManifest before = owner.tip();
        byte[] oldKey = owner.retainedEpochKeys().get(0L);

        int mark = proxy.requestCount();
        await(owner.remove(bob.member().ed25519Public()));
        List<String> during = proxy.paths().subList(mark, proxy.requestCount());
        List<String> publishes =
                during.stream().filter(p -> p.endsWith("/manifest")).toList();
        eq(publishes.size(), 1, "one publishManifest: " + during);
        isTrue(during.stream().noneMatch(p -> p.endsWith("/push")), "no separate push: " + during);
        int at = mark + during.indexOf(publishes.get(0));
        Map<String, Object> body = AvpJson.object(AvpJson.parse(proxy.bodies().get(at)), "body");
        isTrue(
                body.get("manifest") instanceof Map<?, ?> && body.get("commit") instanceof Map<?, ?>,
                "state and rotation commit together");

        AvpManifest.SignedManifest tip = owner.tip();
        AvpManifest.ManifestState s = tip.state();
        eq(s.manifestSeq(), before.state().manifestSeq() + 1, "seq + 1");
        eq(s.keyEpoch(), 1L, "epoch + 1");
        isTrue(!s.hasMember(bob.member().ed25519Public()), "bob dropped");
        AvpManifest.Removal removal =
                s.removalOf(bob.member().ed25519Public()).orElseThrow(() -> new AssertionError("removal"));
        eq(removal.removedAtSeq(), s.manifestSeq(), "removedAtSeq");
        eq(sorted(removal.frontier()), merged, "frontier = the heads merged into the rotation commit");
        byte[] newKey = owner.retainedEpochKeys().get(1L);
        isTrue(!Arrays.equals(newKey, oldKey), "a new key");
        eq(owner.retainedEpochKeys().get(0L), oldKey, "the old epoch key is retained");
        for (AvpManifest.MemberEntry m : s.members()) {
            eq(m.keyEpoch(), 1L, "member epoch");
        }
        AvpManifest.MemberEntry carolEntry = entry(s, carol.member().ed25519Public());
        eq(
                AvpCrypto.unwrap(carol.member().x25519Private(), carolEntry.wrappedDataKey(), AvpCrypto.WRAP_INFO),
                newKey,
                "carol's wrap");

        // The host recorded the rotation commit with the state (SPEC 8.3).
        byte[] h = AvpManifest.hash(tip);
        AvpCommit.Commit rc = a.view(repo, v -> v.rotationCommit(h).orElse(null))
                .orElseThrow(() -> new AssertionError("rotation commit recorded"));
        eq(rc.manifestSeq(), s.manifestSeq(), "rotation seq");
        eq(rc.manifestHash(), h, "rotation hash");
        eq(rc.keyEpoch(), 1L, "rotation epoch");
        eq(rc.author(), s.ownerKey(), "rotation author");
        eq(sorted(rc.parents()), merged, "parents = the merged heads");
        eq(ids(a.heads(repo)), ids(rc.commitId()), "the host's head");
        Map<String, Object> carried = decrypt(rc, newKey);
        eq(value(carried, U2, "username"), "bob-wrote", "carries the merged state");
        eq(value(carried, U1, "accessToken"), "carol-wrote", "carries carol's write");

        // Carol gets the new key and the carried state.
        await(carol.pull());
        eq(carol.retainedEpochKeys().get(1L), newKey, "carol's new key");
        eq(value(carol.payload(), U2, "username"), "bob-wrote", "carol reads");

        // Bob is cut off: no pull, and no backdated write citing his old state (SPEC 7.3).
        eq(hostCode(() -> await(bob.pull())), "forbidden", "bob pulls");
        eq(hostCode(() -> await(bob.write((p, hlc) -> {}))), "forbidden", "bob writes");
    }

    /**
     * SPEC 8.4: a leaving member signs a leave request and stops syncing; the owner processes it as a
     * removal the next time it is online.
     */
    private static void leaveProcessedByOwner(T t) throws Exception {
        Node a = t.node();
        Vault owner = t.ownerVault(a.url()).vault();
        String repo = owner.repoId();
        Proxy proxy = t.proxy(a);
        Vault bob = t.inviteMember(owner, proxy.url());
        byte[] bobKey = bob.member().ed25519Public();
        long seq = owner.tip().state().manifestSeq();

        await(bob.leave());
        int afterLeave = proxy.requestCount();
        isTrue(proxy.paths().stream().anyMatch(p -> p.endsWith("/leave")), "a leave request was sent");
        eq(thrown(() -> await(bob.pull())).kind(), Vault.ClientException.Kind.LEFT, "pull after leave");
        eq(thrown(() -> await(bob.write((p, hlc) -> {}))).kind(), Vault.ClientException.Kind.LEFT, "write");
        eq(proxy.requestCount(), afterLeave, "a member that left sends nothing more");

        Vault.PullReport report = await(owner.pull());
        eq(report.leaves(), 1, "one leave");
        eq(owner.leaves().size(), 1, "one pending leave");
        eq(owner.leaves().get(0).memberKey(), bobKey, "bob's leave");
        List<byte[]> removed = await(owner.processLeaves());
        eq(ids(removed), ids(bobKey), "bob removed");
        AvpManifest.ManifestState s = owner.tip().state();
        eq(s.manifestSeq(), seq + 1, "seq");
        eq(s.keyEpoch(), 1L, "processed by removal, with rotation");
        isTrue(!s.hasMember(bobKey), "not a member");
        isTrue(s.removalOf(bobKey).isPresent(), "removal");
        eq(a.tipSeq(repo), seq + 1, "host tip");

        // The host dropped the leave once a state removed the member.
        eq(await(owner.pull()).leaves(), 0, "leave dropped");
        isTrue(await(owner.processLeaves()).isEmpty(), "nothing to process");
    }

    /**
     * SPEC 7.5, Review Focus 4: bob joined at epoch 1 sees a head written under epoch 0. He cannot read it,
     * so he leaves it without error and never names it as a parent; the owner, who retained the epoch-0
     * key, merges it forward.
     */
    private static void skipsUnreadableHead(T t) throws Exception {
        Node a = t.node();
        Vault owner = t.ownerVault(a.url()).vault();
        String repo = owner.repoId();
        set(owner, U1, Vault.nowMs(), "username", "u0");
        Vault carol = t.inviteMember(owner, a.url());
        Vault dave = t.inviteMember(owner, a.url());
        await(carol.pull());

        await(owner.remove(dave.member().ed25519Public()));
        eq(owner.tip().state().keyEpoch(), 1L, "rotated");
        Vault bob = t.inviteMember(owner, a.url());
        isTrue(!bob.retainedEpochKeys().containsKey(0L), "bob never held the epoch-0 key");

        // Carol has not pulled since the rotation: she writes under epoch 0, citing the old state.
        set(carol, U2, Vault.nowMs(), "username", "carol-epoch0");
        byte[] c = carol.heads().get(0);
        eq(a.commit(repo, c).keyEpoch(), 0L, "carol wrote under epoch 0");
        eq(a.heads(repo).size(), 2, "two heads");

        Vault.PullReport report = await(bob.pull());
        eq(ids(report.unreadableHeads()), ids(c), "unreadable");
        isTrue(report.discardedCommits().isEmpty(), "it is valid, only unreadable");
        isTrue(report.mergeCommit().isEmpty(), "one readable head: nothing to merge");
        eq(ids(bob.unreadableHeads()), ids(c), "unreadable heads");
        isTrue(!contains(bob.heads(), c), "not a head of bob's");
        isTrue(!hasField(bob.payload(), U2, "username"), "not merged");

        set(bob, U1, Vault.nowMs(), "lastUsedBy", "bob");
        AvpCommit.Commit bw = a.commit(repo, bob.heads().get(0));
        isTrue(!contains(bw.parents(), c), "an unreadable head is never a parent");
        isTrue(contains(a.heads(repo), c), "the head is left for another member, not dropped");

        // The owner holds the epoch-0 key and merges the old head forward under epoch 1.
        report = await(owner.pull());
        byte[] m = report.mergeCommit().orElseThrow(() -> new AssertionError("the owner reads both heads and merges"));
        AvpCommit.Commit mc = a.commit(repo, m);
        eq(mc.keyEpoch(), 1L, "merged under epoch 1");
        isTrue(contains(mc.parents(), c), "merged the old head");
        eq(value(owner.payload(), U2, "username"), "carol-epoch0", "owner reads it");

        await(bob.pull());
        isTrue(bob.unreadableHeads().isEmpty(), "nothing unreadable");
        eq(value(bob.payload(), U2, "username"), "carol-epoch0", "bob reads it now");
    }

    /**
     * SPEC 11.6: device linking. Both devices show the same confirmation code, the grant carries the
     * entropy under avp/owner-link/v1, and the new device regenerates the same phrase; a grant for another
     * ephemeral key does not open.
     */
    private static void linkedDeviceShowsSameMnemonic(T t) throws Exception {
        Node a = t.node();
        Owned o = t.ownerVault(a.url());
        Vault.OwnerIdentity id = o.id();
        set(o.vault(), U1, Vault.nowMs(), "username", "linked");
        String repo = o.vault().repoId();

        Vault.LinkSession session = Vault.LinkSession.start();
        String codeNew = session.confirmationCode();
        eq(codeNew.length(), 6, "six digits");
        isTrue(codeNew.chars().allMatch(ch -> ch >= '0' && ch <= '9'), "digits only");
        // The request travels out of band as a token.
        String text = AvpTokens.encode(AvpTokens.toJson(session.request()));
        AvpTokens.LinkRequest request = AvpTokens.linkRequestFromJson(AvpTokens.decode(text));

        // The existing device refuses to continue unless the owner confirms the code.
        eq(
                thrown(() -> Vault.LinkSession.approve(id.entropy(), request, code -> false))
                        .kind(),
                Vault.ClientException.Kind.LINK_NOT_CONFIRMED,
                "not confirmed");

        String[] shown = new String[1];
        AvpTokens.LinkGrant grant = Vault.LinkSession.approve(id.entropy(), request, code -> {
            shown[0] = code;
            return code.equals(codeNew);
        });
        eq(shown[0], codeNew, "both devices show the same code");
        grant = AvpTokens.linkGrantFromJson(AvpTokens.decode(AvpTokens.encode(AvpTokens.toJson(grant))));
        Vault.OwnerIdentity linked = session.finish(grant);
        eq(linked.mnemonic(), id.mnemonic(), "the same 24-word phrase");
        eq(linked.keys().ed25519Public(), id.keys().ed25519Public(), "the same owner key");

        Vault opened = t.open(a.url(), Vault.Member.fromOwner(linked.keys()), repo);
        eq(value(opened.payload(), U1, "username"), "linked", "the linked device reads");

        // A grant made for another device's ephemeral key does not open here.
        Vault.LinkSession other = Vault.LinkSession.start();
        AvpTokens.LinkGrant stray = Vault.LinkSession.approve(id.entropy(), other.request(), code -> true);
        Vault.LinkSession mine = Vault.LinkSession.start();
        thrown(() -> mine.finish(stray));
    }

    /**
     * SPEC 5.1, Review Focus 5: with the policy not true, refreshToken and expiresAt are stripped with their
     * stamps on write and on read, including from a head written while the policy was on.
     */
    private static void refreshTokensStrippedWhenPolicyFalse(T t) throws Exception {
        Node a = t.node();
        Vault owner = t.ownerVault(a.url()).vault();
        String repo = owner.repoId();
        Vault bob = t.inviteMember(owner, a.url());
        byte[] key0 = owner.retainedEpochKeys().get(0L);

        // Write side: the owner's own payload never carries them.
        set(owner, U1, Vault.nowMs(), "accessToken", "at", "refreshToken", "rt", "expiresAt", 123L);
        Map<String, Object> written = decrypt(a.commit(repo, owner.heads().get(0)), key0);
        Map<String, Object> f = fields(written, U1);
        isTrue(f.containsKey("accessToken"), "accessToken kept");
        isTrue(!f.containsKey("refreshToken") && !f.containsKey("expiresAt"), "stripped on write");
        isTrue(!fields(owner.payload(), U1).containsKey("refreshToken"), "not in the local payload");

        // Read side: a modified build pushes a payload with a refresh token; every client drops it.
        await(bob.pull());
        Map<String, Object> p = bob.payload();
        Map<String, Object> st = stamp(Vault.nowMs() + 5_000, 0, bob.member().id());
        Vault.setField(p, U2, "refreshToken", "rogue-rt", st);
        Vault.setField(p, U2, "expiresAt", 999L, st);
        Vault.setField(p, U2, "username", "rogue", st);
        AvpManifest.SignedManifest tip = bob.tip();
        AvpCommit.Commit rogue = AvpCommit.seal(
                key0,
                headerAt(bob, bob.heads(), tip.state().manifestSeq(), AvpManifest.hash(tip), 0),
                AvpPayload.encode(p),
                bob.member().signingSeed());
        await(bob.host().push(bob.member(), repo, rogue));
        await(owner.pull());
        Map<String, Object> acc = fields(owner.payload(), U2);
        eq(value(owner.payload(), U2, "username"), "rogue", "the rest is merged");
        isTrue(!acc.containsKey("refreshToken") && !acc.containsKey("expiresAt"), "stripped on read");

        // Policy on: the field is kept and shared.
        await(owner.setShareRefreshTokens(true));
        isTrue(owner.tip().state().shareRefreshTokens(), "policy on");
        set(owner, U1, Vault.nowMs(), "refreshToken", "rt2", "expiresAt", 456L);
        byte[] on = owner.heads().get(0);
        eq(value(owner.payload(), U1, "refreshToken"), "rt2", "kept while on");
        await(bob.pull());
        eq(value(bob.payload(), U1, "refreshToken"), "rt2", "shared while on");
        Map<String, Object> carried = decrypt(a.commit(repo, on), key0);
        isTrue(fields(carried, U1).containsKey("refreshToken"), "the head carries it");

        // Policy back off: the head written while on still carries the field, and the merged result has
        // neither field, stamps included.
        await(owner.setShareRefreshTokens(false));
        await(bob.pull());
        eq(ids(a.heads(repo)), ids(on), "the head still carries refreshToken");
        f = fields(bob.payload(), U1);
        isTrue(!f.containsKey("refreshToken") && !f.containsKey("expiresAt"), "stripped from a merged-in head");
        set(bob, U1, Vault.nowMs(), "lastUsed", 7L);
        Map<String, Object> next = decrypt(a.commit(repo, bob.heads().get(0)), key0);
        isTrue(!fields(next, U1).containsKey("refreshToken"), "no refreshToken written");
        isTrue(!fields(next, U1).containsKey("expiresAt"), "no expiresAt written");
    }

    // ─── Client checks against a malicious host (SPEC 6, 7.5) ───────────────────────────────

    /**
     * SPEC 6.1 rule 2, 5.1: a pulled state whose owner signature does not verify, or whose content was
     * rewritten under the original signature, is discarded; the pin and the policy do not move.
     */
    private static void pulledManifestWithBadOwnerSignatureIsDiscarded(T t) throws Exception {
        Node a = t.node();
        Owned o = t.ownerVault(a.url());
        Vault dev1 = o.vault();
        String repo = dev1.repoId();
        Proxy proxy = t.proxy(a);
        Vault dev2 = t.open(proxy.url(), Vault.Member.fromOwner(o.id().keys()), repo);
        await(dev1.setShareRefreshTokens(true));

        proxy.onPull((req, ans) -> {
            for (Object m : list(ans, "manifests")) {
                Map<String, Object> mo = AvpJson.object(m, "manifest");
                if (Long.valueOf(2)
                        .equals(AvpJson.object(mo.get("state"), "state").get("manifestSeq"))) {
                    byte[] raw = unb64(mo.get("ownerSignature"));
                    raw[5] ^= 0x40;
                    mo.put("ownerSignature", b64(raw));
                }
            }
        });
        Vault.PullReport r = await(dev2.pull());
        eq(r.discardedStates(), 1, "discarded");
        eq(dev2.tip().state().manifestSeq(), 1L, "pin stays");
        isTrue(!dev2.tip().state().shareRefreshTokens(), "policy stays");

        // A rewritten field under the original signature fails the same way.
        proxy.onPull((req, ans) -> {
            for (Object m : list(ans, "manifests")) {
                Map<String, Object> state =
                        AvpJson.object(AvpJson.object(m, "manifest").get("state"), "state");
                if (Long.valueOf(2).equals(state.get("manifestSeq"))) {
                    state.put("keyEpoch", 1L);
                }
            }
        });
        r = await(dev2.pull());
        eq(r.discardedStates(), 1, "discarded rewrite");
        eq(dev2.tip().state().manifestSeq(), 1L, "pin stays");

        proxy.honest();
        r = await(dev2.pull());
        eq(r.discardedStates(), 0, "nothing discarded");
        eq(dev2.tip().state().manifestSeq(), 2L, "adopted");
        isTrue(dev2.tip().state().shareRefreshTokens(), "policy on");
    }

    /**
     * SPEC 6.4: the client pins its highest verified state and rejects a chain that does not contain it (a
     * genuine but shorter, owner-signed prefix), except a diverged chain that wins the tie rule at a fork
     * point at or below the pin (SPEC 6.5), to which it re-pins even at a lower seq.
     */
    private static void pulledManifestRollbackIsRejected(T t) throws Exception {
        Node a = t.node();
        Owned o = t.ownerVault(a.url());
        Vault dev1 = o.vault();
        String repo = dev1.repoId();
        await(dev1.setShareRefreshTokens(true));
        await(dev1.setShareRefreshTokens(false));
        Proxy proxy = t.proxy(a);
        Vault dev2 = t.open(proxy.url(), Vault.Member.fromOwner(o.id().keys()), repo);
        List<AvpManifest.SignedManifest> chain = dev2.chain().states();
        eq(chain.size(), 3, "three states");
        byte[] pinned = dev2.tipHash();

        // Rollback: the host serves only the first two states.
        List<Object> prefix = json(chain.subList(0, 2));
        proxy.onPull((req, ans) -> ans.put("manifests", deepCopy(prefix)));
        Vault.PullReport r = await(dev2.pull());
        isTrue(r.rejectedChain(), "rollback rejected");
        eq(dev2.tip().state().manifestSeq(), 3L, "pin seq");
        eq(dev2.tipHash(), pinned, "pin hash");

        // A diverged seq 2 signed by the owner: rejected if it loses the tie rule, adopted if it wins.
        byte[] real2 = AvpManifest.hash(chain.get(1));
        AvpManifest.SignedManifest lower = null;
        AvpManifest.SignedManifest higher = null;
        for (int i = 0; lower == null || higher == null; i++) {
            Draft d = new Draft(chain.get(1).state());
            AvpManifest.HostRef h0 = d.hosts.get(0);
            d.hosts.set(0, new AvpManifest.HostRef(h0.hostKey(), "v" + i + ".vault.example:443"));
            AvpManifest.SignedManifest m = d.sign(o.id().keys().ed25519Seed());
            if (AvpEncoding.compare(AvpManifest.hash(m), real2) < 0) {
                lower = lower == null ? m : lower;
            } else {
                higher = higher == null ? m : higher;
            }
        }

        List<Object> losing = json(List.of(chain.get(0), higher));
        proxy.onPull((req, ans) -> ans.put("manifests", deepCopy(losing)));
        r = await(dev2.pull());
        isTrue(r.rejectedChain(), "a diverged chain that loses the tie rule is a rollback");
        eq(dev2.tipHash(), pinned, "pin stays");

        List<Object> winning = json(List.of(chain.get(0), lower));
        proxy.onPull((req, ans) -> ans.put("manifests", deepCopy(winning)));
        r = await(dev2.pull());
        isTrue(!r.rejectedChain(), "adopted");
        eq(dev2.tip().state().manifestSeq(), 2L, "re-pinned to the winning tip below the old pin");
        eq(dev2.tipHash(), AvpManifest.hash(lower), "winning tip");
    }

    /**
     * SPEC 7.5: the client checks every pulled commit itself. A bad signature, an author who is not a member
     * at the commit's epoch, an epoch mismatch, a removed author outside the frontier, and a commit citing a
     * state not on the chain by a non-member are discarded: never merged and never named as a parent,
     * although every one is sealed under a key the client holds.
     */
    private static void pulledCommitFailingClientChecksIsDiscarded(T t) throws Exception {
        Node a = t.node();
        Proxy proxy = t.proxy(a);
        Vault owner = t.ownerVault(proxy.url()).vault();
        set(owner, U1, Vault.nowMs(), "username", "u0");
        Vault bob = t.inviteMember(owner, a.url());
        Vault dave = t.inviteMember(owner, a.url());
        await(dave.pull());
        AvpManifest.SignedManifest daveState = dave.tip();
        await(owner.remove(dave.member().ed25519Public()));
        List<byte[]> frontier = owner.tip()
                .state()
                .removalOf(dave.member().ed25519Public())
                .orElseThrow(() -> new AssertionError("removal"))
                .frontier();
        byte[] k0 = owner.retainedEpochKeys().get(0L);
        byte[] k1 = owner.retainedEpochKeys().get(1L);
        AvpManifest.SignedManifest tip = owner.tip();
        long seq = tip.state().manifestSeq();
        byte[] hash = AvpManifest.hash(tip);
        List<byte[]> parents = owner.heads();
        byte[] outsider = AvpCrypto.randomBytes(32);

        AvpCommit.Commit badSig = forge(
                k1,
                headerAt(owner, parents, seq, hash, 1),
                "forged-bad-sig",
                bob.member().signingSeed());
        byte[] sig = badSig.authorSignature().clone();
        sig[0] ^= 1;
        List<AvpCommit.Commit> forged = List.of(
                withSignature(badSig, sig),
                forge(k1, headerAt(owner, parents, seq, hash, 1), "forged-outsider", outsider),
                forge(
                        k0,
                        headerAt(owner, parents, seq, hash, 0),
                        "forged-epoch",
                        bob.member().signingSeed()),
                forge(
                        k0,
                        headerAt(owner, frontier, daveState.state().manifestSeq(), AvpManifest.hash(daveState), 0),
                        "forged-removed",
                        dave.member().signingSeed()),
                forge(k0, headerAt(owner, parents, 1, AvpCrypto.randomBytes(32), 0), "forged-off-chain", outsider));
        List<byte[]> forgedIds = forged.stream().map(AvpCommit.Commit::commitId).toList();
        List<Object> extra = new ArrayList<>();
        for (AvpCommit.Commit c : forged) {
            extra.add(AvpCommit.toJson(c));
        }
        proxy.onPull((req, ans) -> list(ans, "heads").addAll(AvpJson.array(deepCopy(extra), "extra")));

        Vault.PullReport r = await(owner.pull());
        eq(sorted(r.discardedCommits()), sorted(forgedIds), "all forged commits discarded");
        isTrue(r.mergeCommit().isEmpty(), "nothing forged is merged");
        eq(ids(owner.heads()), ids(parents), "heads unchanged");
        for (String uuid :
                List.of("forged-bad-sig", "forged-outsider", "forged-epoch", "forged-removed", "forged-off-chain")) {
            isTrue(!hasAccount(owner.payload(), uuid), uuid + " merged");
        }
        proxy.honest();
        set(owner, U2, Vault.nowMs(), "username", "after");
        AvpCommit.Commit w = a.commit(owner.repoId(), owner.heads().get(0));
        isTrue(w.parents().stream().noneMatch(p -> contains(forgedIds, p)), "a discarded commit is never a parent");
    }

    /**
     * SPEC 7.5 rule 3, the not-on-chain branch: a commit citing a (seq, hash) that is not on the client's
     * chain passes only if its author is a member, at the commit's epoch, of a state at or after the cited
     * seq; and a removed author's head passes only when its id is in the frontier.
     */
    private static void commitChecksFollowTheClientChain(T t) throws Exception {
        Node a = t.node();
        Vault owner = t.ownerVault(a.url()).vault();
        Vault bob = t.inviteMember(owner, a.url());
        Vault dave = t.inviteMember(owner, a.url());
        set(dave, U2, Vault.nowMs(), "username", "dave");
        await(owner.remove(dave.member().ed25519Public()));
        Vault.Chain chain = Vault.Chain.fromStates(owner.chain().states());
        byte[] k0 = owner.retainedEpochKeys().get(0L);
        byte[] k1 = owner.retainedEpochKeys().get(1L);
        AvpManifest.SignedManifest tip = owner.tip();
        byte[] fake = AvpCrypto.randomBytes(32);
        byte[] outsider = AvpCrypto.randomBytes(32);
        byte[] bobSeed = bob.member().signingSeed();

        // Not on the chain, but bob is a member at epoch 0 of a state at or after seq 1: passes.
        chain.verifyCommit(forge(k0, headerAt(owner, List.of(), 1, fake, 0), "x", bobSeed));
        // Same, at an epoch no such state has.
        AvpCommit.Commit epoch7 = forge(k0, headerAt(owner, List.of(), 1, fake, 7), "x", bobSeed);
        thrown(() -> {
            chain.verifyCommit(epoch7);
            return null;
        });
        // Only states at or after the cited seq count. The chain is genesis (1), +bob (2), +dave (3), and
        // the removal of dave at epoch 1 (4). Citing seq 4 off the chain, bob passes at epoch 1, but not at
        // epoch 0: he was a member at epoch 0 only in states before seq 4. Java only: the Rust test cites
        // seq 1 alone, where every state qualifies.
        eq(tip.state().manifestSeq(), 4L, "the chain this case assumes");
        chain.verifyCommit(forge(k1, headerAt(owner, List.of(), 4, fake, 1), "x", bobSeed));
        AvpCommit.Commit before = forge(k0, headerAt(owner, List.of(), 4, fake, 0), "x", bobSeed);
        eq(
                thrown(() -> {
                            chain.verifyCommit(before);
                            return null;
                        })
                        .kind(),
                Vault.ClientException.Kind.COMMIT_REJECTED,
                "a member at the epoch only before the cited seq");
        // Not a member of any state.
        AvpCommit.Commit stranger = forge(k0, headerAt(owner, List.of(), 1, fake, 0), "x", outsider);
        thrown(() -> {
            chain.verifyCommit(stranger);
            return null;
        });
        // On the chain: the cited state itself must list the author at that epoch.
        AvpCommit.Commit genesisCite = forge(
                k1,
                headerAt(owner, List.of(), 1, AvpManifest.hash(chain.states().get(0)), 0),
                "x",
                bobSeed);
        eq(
                thrown(() -> {
                            chain.verifyCommit(genesisCite);
                            return null;
                        })
                        .kind(),
                Vault.ClientException.Kind.COMMIT_REJECTED,
                "bob is not a member of the genesis state");
        chain.verifyCommit(forge(
                k1, headerAt(owner, List.of(), tip.state().manifestSeq(), AvpManifest.hash(tip), 1), "x", bobSeed));
        // A removed author: only a frontier id passes; any other head fails, whatever it cites.
        List<byte[]> frontier = tip.state()
                .removalOf(dave.member().ed25519Public())
                .orElseThrow(() -> new AssertionError("removal"))
                .frontier();
        AvpCommit.Commit any = forge(
                k0, headerAt(owner, frontier, 3, fake, 0), "x", dave.member().signingSeed());
        thrown(() -> {
            chain.verifyCommit(any);
            return null;
        });
        AvpCommit.Commit honest = a.commit(owner.repoId(), frontier.get(0));
        eq(honest.author(), dave.member().ed25519Public(), "dave's write was the merged head");
        chain.verifyCommit(honest);
    }

    /** SPEC 8.2: an acceptance signed by another host key than the token's home host is refused. */
    private static void inviteRefusesAcceptanceFromAnotherHostKey(T t) throws Exception {
        Node a = t.node();
        Node b = t.node();
        Vault owner = t.ownerVault(a.url()).vault();
        String repo = owner.repoId();
        Vault.Member bob = Vault.Member.generate();

        // A real acceptance from host B in a token that claims host A as the home host.
        AvpTokens.InviteToken fromB = await(Vault.prepareJoin(t.host(b.url()), bob, repo));
        AvpTokens.InviteToken claimsA = new AvpTokens.InviteToken(
                fromB.ed25519PublicKey(), fromB.x25519PublicKey(), a.key(), a.addr(), fromB.acceptance());
        eq(
                thrown(() -> await(owner.invite(claimsA))).kind(),
                Vault.ClientException.Kind.INVITE_REFUSED,
                "B's acceptance claiming A");

        // An acceptance that names host A but is signed with host B's key.
        AvpTokens.InviteToken fromA = await(Vault.prepareJoin(t.host(a.url()), bob, repo));
        AvpTokens.Acceptance ac = fromA.acceptance();
        AvpTokens.Acceptance signedByB =
                AvpTokens.signAcceptance(ac.repoId(), ac.memberKey(), ac.expiresAt(), b.signing());
        AvpTokens.Acceptance forged = new AvpTokens.Acceptance(
                signedByB.repoId(), signedByB.memberKey(), a.key(), signedByB.expiresAt(), signedByB.signature());
        AvpTokens.InviteToken forgedToken = new AvpTokens.InviteToken(
                fromA.ed25519PublicKey(),
                fromA.x25519PublicKey(),
                fromA.homeHostKey(),
                fromA.homeHostLocator(),
                forged);
        eq(
                thrown(() -> await(owner.invite(forgedToken))).kind(),
                Vault.ClientException.Kind.INVITE_REFUSED,
                "signed by B, naming A");
        eq(a.tipSeq(repo), 1L, "nothing published");
    }

    /**
     * SPEC 3.1, 3.3, CLAUDE.md zero-knowledge: no request body the clients send, and nothing the host stores,
     * contains a plaintext, a data key, the phrase, its entropy or seed, or a private key.
     */
    private static void clientNeverSendsSecretsOrPlaintext(T t) throws Exception {
        Node a = t.node();
        Proxy pa = t.proxy(a);
        Proxy pb = t.proxy(a);
        Owned o = t.ownerVault(pa.url());
        Vault.OwnerIdentity id = o.id();
        Vault owner = o.vault();
        String repo = owner.repoId();
        await(owner.setShareRefreshTokens(true));
        set(
                owner,
                U1,
                Vault.nowMs(),
                "username",
                "plain-username-7f3a",
                "accessToken",
                "plain-access-token-7f3a",
                "refreshToken",
                "plain-refresh-token-7f3a");
        Vault bob = t.inviteMember(owner, pb.url());
        set(bob, U2, Vault.nowMs(), "username", "plain-bob-alt-7f3a");
        await(owner.pull());
        await(bob.pull());
        Vault carol = t.inviteMember(owner, pb.url());
        await(owner.remove(bob.member().ed25519Public()));
        await(carol.pull());
        await(carol.leave());
        await(owner.processLeaves());
        Vault.LinkSession session = Vault.LinkSession.start();
        AvpTokens.LinkGrant grant = Vault.LinkSession.approve(id.entropy(), session.request(), code -> true);
        Vault.OwnerIdentity linked = session.finish(grant);
        t.open(pa.url(), Vault.Member.fromOwner(linked.keys()), repo);

        String phrase = id.mnemonic();
        byte[] seed = AvpOwner.mnemonicToSeed(phrase, "");
        Map<String, byte[]> secrets = new LinkedHashMap<>();
        secrets.put("mnemonic", phrase.getBytes(StandardCharsets.UTF_8));
        secrets.put(
                "first words",
                String.join(" ", Arrays.copyOf(phrase.split(" "), 3)).getBytes(StandardCharsets.UTF_8));
        secrets.put("entropy", id.entropy());
        secrets.put("seed", seed);
        secrets.put("owner ed25519 seed", id.keys().ed25519Seed());
        secrets.put("owner x25519", id.keys().x25519Private());
        for (Map.Entry<String, Vault> e : Map.of("bob", bob, "carol", carol).entrySet()) {
            secrets.put(e.getKey() + " ed25519 seed", e.getValue().member().signingSeed());
            secrets.put(e.getKey() + " x25519", e.getValue().member().x25519Private());
        }
        for (Map.Entry<Long, byte[]> e : owner.retainedEpochKeys().entrySet()) {
            secrets.put("data key " + e.getKey(), e.getValue());
        }
        for (String text : List.of(
                "plain-username-7f3a", "plain-access-token-7f3a", "plain-refresh-token-7f3a", "plain-bob-alt-7f3a")) {
            secrets.put(text, text.getBytes(StandardCharsets.UTF_8));
        }
        // Each secret in every encoding a body could carry it in.
        Map<String, byte[]> needles = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> e : secrets.entrySet()) {
            byte[] raw = e.getValue();
            needles.put(e.getKey() + " raw", raw);
            needles.put(e.getKey() + " base64", AvpEncoding.base64(raw).getBytes(StandardCharsets.UTF_8));
            needles.put(e.getKey() + " base64url", AvpEncoding.base64Url(raw).getBytes(StandardCharsets.UTF_8));
            needles.put(e.getKey() + " hex", AvpEncoding.hex(raw).getBytes(StandardCharsets.UTF_8));
        }

        List<byte[]> bodies = new ArrayList<>(pa.bodies());
        bodies.addAll(pb.bodies());
        isTrue(bodies.size() > 20, "the flow went through the proxies");
        for (byte[] body : bodies) {
            for (Map.Entry<String, byte[]> n : needles.entrySet()) {
                isTrue(!containsBytes(body, n.getValue()), "a request body carries the " + n.getKey());
            }
        }

        // Everything the host stores: the engine view rendered in full (every byte array as hex) and the
        // served JSON.
        String dump = a.view(repo, ClientTest::dump).orElseThrow();
        String served = a.view(repo, v -> {
                    List<Object> ms = new ArrayList<>();
                    for (AvpManifest.SignedManifest m : v.manifestsSince(0)) {
                        ms.add(AvpManifest.toJson(m));
                    }
                    List<Object> cs = new ArrayList<>();
                    for (AvpCommit.Commit c : v.commitsSince(List.of())) {
                        cs.add(AvpCommit.toJson(c));
                    }
                    return AvpJson.write(ms) + AvpJson.write(cs);
                })
                .orElseThrow();
        AvpCommit.Commit head = a.commit(repo, a.heads(repo).get(0));
        isTrue(dump.contains(AvpEncoding.hex(head.ciphertext())), "the dump renders stored bytes");
        for (Map.Entry<String, byte[]> e : secrets.entrySet()) {
            byte[] raw = e.getValue();
            isTrue(!dump.contains(AvpEncoding.hex(raw)), "the host stores the " + e.getKey());
            Optional<String> text = utf8(raw);
            isTrue(text.isEmpty() || !dump.contains(text.get()), "the host stores the " + e.getKey() + " as text");
            isTrue(!served.contains(AvpEncoding.base64(raw)), "the host serves the " + e.getKey());
        }
    }

    /**
     * SPEC 6.1 rules 1, 4, 5: states signed with the real owner key that break a structure, link, or content
     * rule are discarded by the client itself; the pin does not move. A valid next state is then adopted
     * through the same path.
     */
    private static void ownerSignedStatesBreakingChainRulesAreDiscarded(T t) throws Exception {
        Node a = t.node();
        Owned o = t.ownerVault(a.url());
        Vault dev1 = o.vault();
        Vault bob = t.inviteMember(dev1, a.url());
        String repo = dev1.repoId();
        Proxy proxy = t.proxy(a);
        Vault dev2 = t.open(proxy.url(), Vault.Member.fromOwner(o.id().keys()), repo);
        List<AvpManifest.SignedManifest> chain = dev2.chain().states();
        AvpManifest.SignedManifest tip = dev2.tip();
        byte[] pin = dev2.tipHash();
        byte[] bobKey = bob.member().ed25519Public();
        AvpManifest.MemberEntry bobEntry = entry(tip.state(), bobKey);
        byte[] ownerSeed = o.id().keys().ed25519Seed();

        Map<String, AvpManifest.SignedManifest> cases = new LinkedHashMap<>();
        Draft s = next(tip, pin);
        s.prev = AvpCrypto.randomBytes(32);
        cases.put("wrong prevManifestHash (6.3)", s.sign(ownerSeed));
        s = next(tip, pin);
        s.members.removeIf(m -> Arrays.equals(m.ed25519PublicKey(), bobKey));
        s.removals.add(new AvpManifest.Removal(bobKey, s.seq, List.of()));
        cases.put("removal without an epoch bump (6.1 rule 5)", s.sign(ownerSeed));
        s = next(tip, pin);
        s.members.removeIf(m -> Arrays.equals(m.ed25519PublicKey(), bobKey));
        cases.put("member dropped without a removal (6.1 rule 5)", s.sign(ownerSeed));
        s = next(tip, pin);
        s.members.add(newcomer(bobEntry, AvpCrypto.randomBytes(32), 48));
        cases.put("homeHostKey not in hosts (6.1 rule 5)", s.sign(ownerSeed));
        s = next(tip, pin);
        s.members.add(newcomer(bobEntry, a.key(), 47));
        cases.put("47-byte wrapped ciphertext (6.1 rule 1)", s.sign(ownerSeed));
        // A state listing a member twice cannot be encoded, so no signature over it exists; the owner's
        // signature over the same state without the duplicate is attached.
        s = next(tip, pin);
        byte[] signature = s.sign(ownerSeed).ownerSignature();
        s.members.add(bobEntry);
        cases.put("duplicate members (4.2, 6.1 rule 1)", new AvpManifest.SignedManifest(s.build(), signature));

        for (Map.Entry<String, AvpManifest.SignedManifest> e : cases.entrySet()) {
            serveStates(proxy, chain, List.of(e.getValue()));
            Vault.PullReport r = await(dev2.pull());
            eq(r.discardedStates(), 1, e.getKey());
            eq(r.newStates(), 0, e.getKey());
            eq(dev2.tipHash(), pin, e.getKey() + ": the pin does not move");
        }

        s = next(tip, pin);
        s.share = true;
        AvpManifest.SignedManifest good = s.sign(ownerSeed);
        serveStates(proxy, chain, List.of(good));
        Vault.PullReport r = await(dev2.pull());
        eq(r.discardedStates(), 0, "valid state: discarded");
        eq(r.newStates(), 1, "valid state: new");
        eq(dev2.tipHash(), AvpManifest.hash(good), "adopted");
    }

    private static Draft next(AvpManifest.SignedManifest tip, byte[] pin) {
        Draft d = new Draft(tip.state());
        d.seq += 1;
        d.prev = pin.clone();
        return d;
    }

    private static AvpManifest.MemberEntry newcomer(AvpManifest.MemberEntry like, byte[] home, int ctLen)
            throws Vault.ClientException {
        AvpManifest.WrappedKey w = like.wrappedDataKey();
        return new AvpManifest.MemberEntry(
                Vault.Member.generate().ed25519Public(),
                like.x25519PublicKey(),
                new AvpManifest.WrappedKey(
                        w.schemeId(), w.ephemeralPublicKey(), w.iv(), Arrays.copyOf(w.ciphertext(), ctLen)),
                like.keyEpoch(),
                home);
    }

    /**
     * SPEC 6.2: open refuses a genesis whose repoId does not recompute from ownerKey and genesisNonce, and a
     * genesis with more than the owner, although both carry the owner's signature.
     */
    private static void openRejectsAnInvalidGenesis(T t) throws Exception {
        Node a = t.node();
        Owned o = t.ownerVault(a.url());
        String repo = o.vault().repoId();
        Proxy proxy = t.proxy(a);
        AvpManifest.SignedManifest g = o.vault().chain().states().get(0);
        byte[] ownerSeed = o.id().keys().ed25519Seed();

        Draft d = new Draft(g.state());
        d.nonce = AvpCrypto.randomBytes(16);
        AvpManifest.SignedManifest wrongId = d.sign(ownerSeed);
        d = new Draft(g.state());
        AvpManifest.MemberEntry m0 = d.members.get(0);
        d.members.add(new AvpManifest.MemberEntry(
                Vault.Member.generate().ed25519Public(),
                m0.x25519PublicKey(),
                m0.wrappedDataKey(),
                m0.keyEpoch(),
                m0.homeHostKey()));
        AvpManifest.SignedManifest twoMembers = d.sign(ownerSeed);

        Map<String, AvpManifest.SignedManifest> cases = new LinkedHashMap<>();
        cases.put("repoId does not recompute", wrongId);
        cases.put("two members", twoMembers);
        for (Map.Entry<String, AvpManifest.SignedManifest> e : cases.entrySet()) {
            serveStates(proxy, List.of(), List.of(e.getValue()));
            Vault.ClientException r = thrown(() -> t.open(proxy.url(), Vault.Member.fromOwner(o.id().keys()), repo));
            eq(r.kind(), Vault.ClientException.Kind.STATE_REJECTED, e.getKey() + ": " + r);
        }
        proxy.honest();
        t.open(proxy.url(), Vault.Member.fromOwner(o.id().keys()), repo);
    }

    /**
     * SPEC 6.4, 6.2: genesis fixes the repository, so a competing owner-signed genesis for the same repoId is
     * never adopted, even with a lower manifestHash (the tie rule is not applied at seq 1).
     */
    private static void competingGenesisIsNeverAdopted(T t) throws Exception {
        Node a = t.node();
        Owned o = t.ownerVault(a.url());
        String repo = o.vault().repoId();
        Proxy proxy = t.proxy(a);
        Vault dev2 = t.open(proxy.url(), Vault.Member.fromOwner(o.id().keys()), repo);
        byte[] real = dev2.tipHash();
        AvpManifest.SignedManifest lower = null;
        for (int i = 0; lower == null; i++) {
            Draft d = new Draft(o.vault().chain().states().get(0).state());
            AvpManifest.HostRef h0 = d.hosts.get(0);
            d.hosts.set(0, new AvpManifest.HostRef(h0.hostKey(), "g" + i + ".vault.example:443"));
            AvpManifest.SignedManifest m = d.sign(o.id().keys().ed25519Seed());
            if (AvpEncoding.compare(AvpManifest.hash(m), real) < 0) {
                lower = m;
            }
        }
        eq(lower.state().repoId(), repo, "a valid genesis of the same repoId");

        serveStates(proxy, List.of(), List.of(lower));
        Vault.PullReport r = await(dev2.pull());
        isTrue(r.rejectedChain(), "rejected");
        eq(dev2.tipHash(), real, "pin stays");
    }

    /** SPEC 11.2: the joiner checks that the genesis ownerKey matches the locator's fingerprint. */
    private static void joinChecksTheOwnerFingerprint(T t) throws Exception {
        Node a = t.node();
        Vault owner = t.ownerVault(a.url()).vault();
        Vault.Member bob = Vault.Member.generate();
        Vault.HostClient home = t.host(a.url());
        AvpTokens.InviteToken token = await(Vault.prepareJoin(home, bob, owner.repoId()));
        await(owner.invite(token));
        AvpTokens.RepoLocator real = owner.locator();
        AvpTokens.RepoLocator locator = new AvpTokens.RepoLocator(
                real.repoId(),
                real.hostKey(),
                real.hostLocator(),
                AvpTokens.ownerFingerprint(AvpCrypto.randomBytes(32)));
        Vault.ClientException r = thrown(() -> await(Vault.join(t.host(a.url()), bob, locator)));
        eq(r.kind(), Vault.ClientException.Kind.OWNER_MISMATCH, String.valueOf(r));
        await(Vault.join(home, bob, owner.locator()));
    }

    /**
     * SPEC 8.4: the owner acts only on leave requests that verify under memberKey, name this repository, and
     * come from a current member who is not the owner.
     */
    private static void invalidLeaveRequestsAreIgnored(T t) throws Exception {
        Node a = t.node();
        Proxy proxy = t.proxy(a);
        Owned o = t.ownerVault(proxy.url());
        Vault owner = o.vault();
        String repo = owner.repoId();
        Vault bob = t.inviteMember(owner, a.url());
        long seq = owner.tip().state().manifestSeq();
        byte[] bobSeed = bob.member().signingSeed();

        AvpTokens.LeaveRequest real = AvpTokens.signLeave(repo, Vault.nowMs(), bobSeed);
        byte[] sig = real.signature().clone();
        sig[0] ^= 1;
        List<AvpTokens.LeaveRequest> bad = List.of(
                new AvpTokens.LeaveRequest(real.repoId(), real.memberKey(), real.at(), sig),
                AvpTokens.signLeave(repo, Vault.nowMs(), AvpCrypto.randomBytes(32)),
                AvpTokens.signLeave(repo, Vault.nowMs(), o.id().keys().ed25519Seed()),
                AvpTokens.signLeave(AvpEncoding.base64Url(AvpCrypto.randomBytes(16)), Vault.nowMs(), bobSeed));
        List<Object> injected = new ArrayList<>();
        for (AvpTokens.LeaveRequest l : bad) {
            injected.add(AvpTokens.toJson(l));
        }
        proxy.onPull((req, ans) -> ans.put("leaves", deepCopy(injected)));
        Vault.PullReport r = await(owner.pull());
        eq(r.leaves(), 0, "no valid leave");
        isTrue(owner.leaves().isEmpty(), "none pending");
        isTrue(await(owner.processLeaves()).isEmpty(), "nobody is removed");
        eq(owner.tip().state().manifestSeq(), seq, "client seq");
        eq(a.tipSeq(repo), seq, "host seq");

        // The same path carries a valid request.
        List<Object> good = List.of(AvpTokens.toJson(AvpTokens.signLeave(repo, Vault.nowMs(), bobSeed)));
        proxy.onPull((req, ans) -> ans.put("leaves", deepCopy(good)));
        eq(await(owner.pull()).leaves(), 1, "the valid leave counts");
    }

    /**
     * SPEC 8.3: the frontier also lists every verified commit by the removed member that the owner cannot
     * show to be an ancestor of a merged head. Here the owner saw bob's b1 as a head; the merged head is
     * carol's c, whose parent b2 the owner never saw, so b1 is listed too.
     */
    private static void frontierListsSeenCommitsNotKnownAsAncestors(T t) throws Exception {
        Node a = t.node();
        Vault owner = t.ownerVault(a.url()).vault();
        String repo = owner.repoId();
        Vault bob = t.inviteMember(owner, a.url());
        Vault carol = t.inviteMember(owner, a.url());
        set(bob, U1, Vault.nowMs(), "username", "b1");
        byte[] b1 = bob.heads().get(0);
        await(owner.pull());
        eq(ids(owner.heads()), ids(b1), "the owner saw b1");
        set(bob, U1, Vault.nowMs(), "username", "b2");
        await(carol.pull());
        set(carol, U2, Vault.nowMs(), "username", "c");
        byte[] c = carol.heads().get(0);
        eq(ids(a.heads(repo)), ids(c), "c is the only head");

        await(owner.remove(bob.member().ed25519Public()));
        AvpManifest.Removal removal = owner.tip()
                .state()
                .removalOf(bob.member().ed25519Public())
                .orElseThrow(() -> new AssertionError("removal"));
        eq(sorted(removal.frontier()), sorted(c, b1), "frontier");
        eq(a.tipSeq(repo), owner.tip().state().manifestSeq(), "the host accepted it");
    }

    /**
     * SPEC 7.5: a forged head that claims the id of a real head does not shadow it; ids are de-duplicated
     * only among commits that verify.
     */
    private static void forgedCommitWithARealIdDoesNotShadowIt(T t) throws Exception {
        Node a = t.node();
        Proxy proxy = t.proxy(a);
        Vault owner = t.ownerVault(proxy.url()).vault();
        Vault bob = t.inviteMember(owner, a.url());
        set(bob, U2, Vault.nowMs(), "username", "bob-real");
        byte[] real = bob.heads().get(0);
        proxy.onPull((req, ans) -> {
            List<Object> heads = list(ans, "heads");
            Map<String, Object> forged = AvpJson.object(deepCopy(heads.get(0)), "head");
            byte[] sig = unb64(forged.get("authorSignature"));
            sig[0] ^= 1;
            forged.put("authorSignature", b64(sig));
            heads.add(0, forged);
        });
        Vault.PullReport r = await(owner.pull());
        eq(ids(r.discardedCommits()), ids(real), "the forgery is discarded");
        eq(ids(r.readableHeads()), ids(real), "the real head is still read");
        eq(ids(owner.heads()), ids(real), "heads");
        eq(value(owner.payload(), U2, "username"), "bob-real", "merged");
    }

    /** SPEC 4.3, 7.5: a commit listing the same parent twice is malformed and discarded. */
    private static void commitWithDuplicateParentsIsDiscarded(T t) throws Exception {
        Node a = t.node();
        Vault owner = t.ownerVault(a.url()).vault();
        set(owner, U1, Vault.nowMs(), "username", "u0");
        Vault.Chain chain = Vault.Chain.fromStates(owner.chain().states());
        AvpManifest.SignedManifest tip = owner.tip();
        byte[] p = owner.heads().get(0);
        byte[] key = owner.retainedEpochKeys().get(0L);
        AvpCommit.Commit ok = forge(
                key,
                headerAt(owner, List.of(p), 1, AvpManifest.hash(tip), 0),
                "x",
                owner.member().signingSeed());
        chain.verifyCommit(ok);
        AvpCommit.Commit dup = withParents(ok, List.of(p, p));
        eq(
                thrown(() -> {
                            chain.verifyCommit(dup);
                            return null;
                        })
                        .kind(),
                Vault.ClientException.Kind.COMMIT_REJECTED,
                "duplicate parents");
    }

    /**
     * SPEC 10.4 (owner decision D5): a host may answer a bare {@code 400} without the JSON error object, and
     * any answer is untrusted. A non-JSON error body is a host error with its status and no code; a 200
     * answer that is not JSON is a malformed answer. Neither escapes as an unchecked exception. Java only:
     * the Rust client has no matching test.
     */
    private static void hostErrorsWithoutAJsonBodyAreReportedByStatus(T t) throws Exception {
        AtomicReference<String> mode = new AtomicReference<>("bare-400");
        HttpServer stub = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 16);
        byte[] hostKey = AvpCrypto.ed25519Public(AvpCrypto.randomBytes(32));
        stub.createContext("/", ex -> {
            try (ex) {
                ex.getRequestBody().readAllBytes();
                String path = ex.getRequestURI().getRawPath();
                int status;
                byte[] body;
                if (path.equals("/.well-known/avp")) {
                    status = 200;
                    body = AvpJson.writeUtf8(Map.of("version", "0.5", "hostKey", b64(hostKey)));
                } else if (mode.get().equals("bare-400")) {
                    status = 400;
                    body = "<html><body>Bad Request</body></html>".getBytes(StandardCharsets.UTF_8);
                } else {
                    status = 200;
                    body = "not json".getBytes(StandardCharsets.UTF_8);
                }
                ex.sendResponseHeaders(status, body.length);
                try (OutputStream out = ex.getResponseBody()) {
                    out.write(body);
                }
            }
        });
        stub.start();
        try {
            String url = "http://127.0.0.1:" + stub.getAddress().getPort();
            Vault.HostClient h = t.host(url);
            eq(h.key(), hostKey, "discovery");
            Vault.Member me = Vault.Member.generate();
            String repo = AvpEncoding.base64Url(AvpCrypto.randomBytes(16));

            Vault.ClientException bare = thrown(() -> await(Vault.prepareJoin(h, me, repo)));
            eq(bare.kind(), Vault.ClientException.Kind.HOST, "a bare 400 is a host error");
            eq(bare.status(), 400, "status");
            isTrue(bare.code().isEmpty(), "no code without a JSON body");
            Vault.ClientException open = thrown(() -> await(Vault.open(h, me, repo)));
            eq(open.status(), 400, "open: status only");

            mode.set("not-json");
            Vault.ClientException garbled = thrown(() -> await(Vault.prepareJoin(h, me, repo)));
            eq(garbled.kind(), Vault.ClientException.Kind.BAD_RESPONSE, "a 200 that is not JSON");
        } finally {
            stub.stop(0);
        }
    }

    /**
     * SPEC 3.3, 11.7: a client matches a host by key, never by locator alone. Connecting to host A while
     * expecting host B's key (a key from a token or a manifest's hosts) fails; expecting A's own key
     * succeeds.
     */
    private static void connectExpectingMatchesTheHostKey(T t) throws Exception {
        Node a = t.node();
        Node b = t.node();
        Vault.ClientException r = thrown(() -> await(Vault.HostClient.connectExpecting(a.url(), b.key())));
        eq(r.kind(), Vault.ClientException.Kind.HOST_KEY_MISMATCH, "A's address with B's key: " + r);
        Vault.HostClient h = await(Vault.HostClient.connectExpecting(a.url(), a.key()));
        try {
            eq(h.key(), a.key(), "the matched key");
            eq(h.locator(), a.addr(), "the locator");
        } finally {
            h.close();
        }
    }

    // ─── Stale pin on a same-seq state that lost the tie rule (SPEC 6.3, 6.4, 6.5) ───────────

    /**
     * Two peered hosts that converged on Y, a seq 4 that beat the seq 4 X that owner device 1 and the member
     * bob are pinned on. Y removes carol, so it raises the epoch to 1.
     */
    private record Diverged(
            Node a, Node b, Proxy proxy, String repo, Vault dev1, Vault bob, byte[] x, byte[] y, byte[] yKey) {}

    /** Pauses or resumes all host-to-host traffic through the test control (SPEC 9.3). */
    private static void pause(Node n, boolean paused) throws Exception {
        try (HttpClient http = HttpClient.newHttpClient()) {
            HttpRequest req = HttpRequest.newBuilder(URI.create(n.url() + "/v1/test/replication"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(AvpJson.writeUtf8(Map.of("paused", paused))))
                    .build();
            HttpResponse<byte[]> r = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
            eq(r.statusCode(), 200, "test control");
        }
    }

    private static Optional<String> tipHash(Node n, String repo) {
        return n.view(
                repo,
                v -> v.tip()
                        .map(m -> {
                            try {
                                return b64(AvpManifest.hash(m));
                            } catch (AvpException e) {
                                throw new AssertionError(e);
                            }
                        })
                        .orElse(null));
    }

    private static Diverged divergedOnY(T t) throws Exception {
        Node[] pair = t.peeredPair(true);
        Node a = pair[0];
        Node b = pair[1];
        // Owner device 1 and bob sync with host A through a proxy that counts their requests.
        Proxy proxy = t.proxy(a);
        Owned o = t.ownerVault(proxy.url());
        Vault dev1 = o.vault();
        String repo = dev1.repoId();
        Vault bob = t.inviteMember(dev1, proxy.url());
        Vault carol = t.inviteMember(dev1, b.url());
        eq(dev1.tip().state().manifestSeq(), 3L, "seq 2 adds bob, seq 3 adds carol and host B");
        AvpManifest.SignedManifest s3 = dev1.tip();
        byte[] s3h = AvpManifest.hash(s3);
        eventually("B holds seq 3", () -> tipHash(b, repo).equals(Optional.of(b64(s3h))));

        // The hosts cannot reach each other while the owner's two devices each publish a seq 4.
        pause(a, true);
        pause(b, true);
        // 1. Device 1 publishes X at seq 4 on A (policy on, no epoch change); bob pins it.
        await(dev1.setShareRefreshTokens(true));
        byte[] x = dev1.tipHash();
        eq(dev1.tip().state().manifestSeq(), 4L, "X is seq 4");
        await(bob.pull());
        eq(bob.tipHash(), x, "bob pins X");

        // 2. Device 2, offline from device 1, publishes Y at seq 4 on B: it removes carol, so it raises the
        // epoch and carries its rotation commit (SPEC 8.3). The new data key is fresh randomness, so
        // re-drawing it picks which hash is lower; Y must have the lower manifestHash.
        List<byte[]> heads = new ArrayList<>(b.heads(repo));
        heads.sort(AvpEncoding::compare);
        byte[] carolKey = carol.member().ed25519Public();
        byte[] seed = o.id().keys().ed25519Seed();
        AvpManifest.SignedManifest y;
        byte[] yKey;
        while (true) {
            byte[] key = AvpCrypto.randomBytes(32);
            Draft d = new Draft(s3.state());
            d.seq = 4;
            d.prev = s3h;
            d.nonce = new byte[0];
            d.epoch = 1;
            List<AvpManifest.MemberEntry> members = new ArrayList<>();
            for (AvpManifest.MemberEntry m : d.members) {
                if (Arrays.equals(m.ed25519PublicKey(), carolKey)) {
                    continue;
                }
                members.add(new AvpManifest.MemberEntry(
                        m.ed25519PublicKey(),
                        m.x25519PublicKey(),
                        AvpCrypto.wrap(m.x25519PublicKey(), key, AvpCrypto.WRAP_INFO),
                        1,
                        m.homeHostKey()));
            }
            d.members = members;
            d.removals.add(new AvpManifest.Removal(carolKey, 4, heads));
            AvpManifest.SignedManifest m = d.sign(seed);
            if (AvpEncoding.compare(AvpManifest.hash(m), x) < 0) {
                y = m;
                yKey = key;
                break;
            }
        }
        byte[] yh = AvpManifest.hash(y);
        Map<String, Object> empty = new LinkedHashMap<>();
        empty.put("v", 2L);
        empty.put("accounts", new TreeMap<String, Object>());
        AvpCommit.Commit rotation =
                AvpCommit.seal(yKey, new AvpCommit.Header(repo, heads, 4, yh, 1), AvpPayload.encode(empty), seed);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("manifest", AvpManifest.toJson(y));
        body.put("commit", AvpCommit.toJson(rotation));
        t.host(b.url()).post(Vault.Member.fromOwner(o.id().keys()), "/v1/repos/" + repo + "/manifest", body);

        // 3. The hosts converge on Y, the lower manifestHash (SPEC 6.5).
        pause(a, false);
        pause(b, false);
        Optional<String> want = Optional.of(b64(yh));
        eventually(
                "both hosts hold Y as their tip",
                () -> tipHash(a, repo).equals(want) && tipHash(b, repo).equals(want));
        List<String> rot = ids(rotation.commitId());
        eventually(
                "both hosts hold Y's rotation commit as the head",
                () -> ids(a.heads(repo)).equals(rot) && ids(b.heads(repo)).equals(rot));
        return new Diverged(a, b, proxy, repo, dev1, bob, x, yh, yKey);
    }

    /** The requests since {@code mark} whose path ends with {@code suffix}. */
    private static long countSince(Proxy p, int mark, String suffix) {
        List<String> paths = p.paths();
        return paths.subList(mark, paths.size()).stream()
                .filter(s -> s.endsWith(suffix))
                .count();
    }

    /** The {@code pull} requests since {@code mark} that asked for the whole chain ({@code sinceManifestSeq = 0}). */
    private static long fullPullsSince(Proxy p, int mark) throws AvpException {
        List<String> paths = p.paths();
        List<byte[]> bodies = p.bodies();
        long n = 0;
        for (int i = mark; i < paths.size(); i++) {
            if (paths.get(i).endsWith("/pull")
                    && AvpJson.object(AvpJson.parse(bodies.get(i)), "pull")
                            .get("sinceManifestSeq")
                            .equals(0L)) {
                n++;
            }
        }
        return n;
    }

    /**
     * SPEC 6.3, 6.4, 6.5: an owner device pinned on X, a same-seq state that lost the tie rule, gets an empty
     * pull (nothing is above its pin). Its next owner operation meets {@code 409 manifest_conflict}, re-pulls
     * from seq 0, adopts the winning chain through Y, and succeeds on Y. A member pinned on X meets {@code 403
     * forbidden} on its push (it cites X under epoch 0, and Y raised the epoch), re-pulls from seq 0, recovers
     * the epoch 1 key from Y, and pushes under epoch 1.
     */
    private static void ownerAndMemberPinnedOnALosingSameSeqStateRecover(T t) throws Exception {
        Diverged d = divergedOnY(t);
        Proxy proxy = d.proxy();
        String repo = d.repo();

        // Nothing has a seq above the pin, so a plain pull cannot show the loss.
        Vault.PullReport r = await(d.dev1().pull());
        eq(r.newStates(), 0, "no new state");
        isTrue(!r.rejectedChain(), "no rejected chain");
        eq(d.dev1().tipHash(), d.x(), "still pinned on X");

        // 4. Device 1's next owner operation succeeds on Y.
        int mark = proxy.requestCount();
        await(d.dev1().setShareRefreshTokens(true));
        eq(countSince(proxy, mark, "/manifest"), 2L, "one 409, then one rebuilt publication");
        eq(fullPullsSince(proxy, mark), 1L, "one re-pull from seq 0");
        AvpManifest.SignedManifest tip = d.dev1().tip();
        eq(tip.state().manifestSeq(), 5L, "seq 5");
        eq(tip.state().prevManifestHash(), d.y(), "seq 5 links to Y");
        eq(AvpManifest.hash(d.dev1().chain().states().get(3)), d.y(), "Y replaced X on the device's chain");
        isTrue(tip.state().shareRefreshTokens(), "policy on");
        eq(tip.state().keyEpoch(), 1L, "epoch 1");
        eq(d.dev1().retainedEpochKeys().get(1L), d.yKey(), "the owner holds Y's epoch key");
        byte[] s5 = d.dev1().tipHash();
        eq(tipHash(d.a(), repo), Optional.of(b64(s5)), "A's tip is seq 5");
        eventually("B reaches seq 5", () -> tipHash(d.b(), repo).equals(Optional.of(b64(s5))));

        // 5. The member pinned on X recovers Y's epoch and can push.
        eq(d.bob().tipHash(), d.x(), "bob is still pinned on X");
        mark = proxy.requestCount();
        set(d.bob(), U1, Vault.nowMs(), "username", "bob-after");
        eq(countSince(proxy, mark, "/push"), 2L, "one 403, then one rebuilt push");
        eq(fullPullsSince(proxy, mark), 1L, "one re-pull from seq 0");
        eq(d.bob().tipHash(), s5, "bob re-pinned to the winning tip");
        eq(d.bob().retainedEpochKeys().get(1L), d.yKey(), "bob recovered the epoch 1 key");
        byte[] head = d.bob().heads().get(0);
        eq(ids(d.a().heads(repo)), ids(head), "bob's commit is the head");
        AvpCommit.Commit c = d.a().commit(repo, head);
        eq(c.manifestSeq(), 5L, "cites seq 5");
        eq(c.manifestHash(), s5, "cites the winning tip");
        eq(c.keyEpoch(), 1L, "under epoch 1");
        eq(value(decrypt(c, d.yKey()), U1, "username"), "bob-after", "bob's write");
    }

    /**
     * SPEC 6.3, 6.4: the stale pin recovery is bounded. When the host keeps answering {@code 409
     * manifest_conflict} (or {@code 403 forbidden}), the operation fails after one re-pull from seq 0 and one
     * retry, with no loop, although the host would accept a later try.
     */
    private static void stalePinRecoveryIsBounded(T t) throws Exception {
        Diverged d = divergedOnY(t);
        Proxy proxy = d.proxy();

        proxy.deny("/manifest", 409, "manifest_conflict", 3);
        int mark = proxy.requestCount();
        eq(hostCode(() -> await(d.dev1().setShareRefreshTokens(true))), "manifest_conflict", "409");
        eq(countSince(proxy, mark, "/manifest"), 2L, "one publication and one retry");
        eq(fullPullsSince(proxy, mark), 1L, "one re-pull from seq 0");
        eq(tipHash(d.a(), d.repo()), Optional.of(b64(d.y())), "nothing was published");

        proxy.deny("/push", 403, "forbidden", 3);
        mark = proxy.requestCount();
        String by = d.bob().member().id();
        eq(
                hostCode(() -> await(d.bob().write((p, hlc) -> {
                    Map<String, Object> s = hlc.tick(Vault.nowMs(), by);
                    Vault.setField(p, U1, "username", "bob-after", s);
                }))),
                "forbidden",
                "403");
        eq(countSince(proxy, mark, "/push"), 2L, "one push and one retry");
        eq(fullPullsSince(proxy, mark), 1L, "one re-pull from seq 0");
        eq(d.bob().tipHash(), d.y(), "the re-pull moved bob's pin to Y");
    }

    // ─── The worked flow ────────────────────────────────────────────────────────────────────

    private static void workedFlowOneHost(T t) throws Exception {
        Node a = t.node();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Client.run(a.url(), null, new PrintStream(out, true, StandardCharsets.UTF_8));
        String text = out.toString(StandardCharsets.UTF_8);
        for (String step : List.of("create", "invite", "merge", "leave", "link")) {
            isTrue(text.contains(step), "missing step " + step + ": " + text);
        }
    }

    private static void workedFlowTwoPeeredHosts(T t) throws Exception {
        Node[] pair = t.peeredPair();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Client.run(pair[0].url(), pair[1].url(), new PrintStream(out, true, StandardCharsets.UTF_8));
        eq(pair[1].repoCount(), 1, "bob's home host B carries the repository");
    }
}
