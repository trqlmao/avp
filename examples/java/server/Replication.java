/*
 * Host-to-host replication (SPEC 9) over the reference signed HTTP/JSON profile (SPEC 9.3).
 *
 * SPDX-License-Identifier: MIT
 */

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.time.Duration;
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
import java.util.TreeSet;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Host-to-host replication (SPEC 9) over the reference signed HTTP/JSON profile (SPEC 9.3).
 *
 * <ul>
 *   <li>{@link Peers} is the static peer list from {@code AVP_PEERS}. Only these keys may call the host
 *       routes; every host request carries {@code AVP-Host-Key}, {@code AVP-Host-Time}, and {@code
 *       AVP-Host-Signature}, an Ed25519 signature over {@link #requestMessage}. The receiver checks it over
 *       the exact path and body bytes it received and allows 60 seconds of clock skew.
 *   <li>{@link #run} starts one worker thread per peer, so a dead or slow peer delays only its own worker.
 *       A worker offers each accepted client write in the {@link Outbox} to its peer when the repository's
 *       tip lists both hosts, catches up from the peer when an offer from it was incomplete, and sweeps
 *       every held repository whose winning tip lists the peer at startup and every sweep interval
 *       ({@code heads}, then {@code fetch} for what this host lacks, SPEC 9.2). A peer that is not listed
 *       gets no request for the repository at all (SPEC 9.3).
 *   <li>Every item a peer sends, by {@code offer} or in a {@code fetch} answer, goes through the engine
 *       with {@link AvpRules.Via#OFFER} on a trial copy of the repository's view (SPEC 9: validated
 *       whatever the transport). The validated received tip then decides what is kept (SPEC 6.1 rule 6,
 *       8.6, 9.2): a first copy is stored only if its tip lists this host and the sender; a held repository
 *       keeps the validated states even when the received tip drops this host, which then stops serving it.
 * </ul>
 *
 * <p>The state lock is never held across an outbound call: a worker reads what to send under the lock,
 * releases it, calls the peer with a timeout and a response size limit, and applies the answer under the
 * lock again. Peer answers are untrusted input: their size, list lengths, the number of catch-up rounds,
 * and the engine work of one catch-up are bounded. This is a port of the Rust reference host's {@code
 * replication.rs}; the constants and bounds are the same.
 */
final class Replication {

    /** The domain tag of the host request signature (SPEC 9.3). */
    static final String HOST_REQ_TAG = "avp/host-req/v1";

    /** The largest allowed difference between {@code AVP-Host-Time} and the receiver's clock. */
    static final long MAX_SKEW_MS = 60_000;

    /** The header carrying the sender's host key, base64. */
    static final String HEADER_KEY = "AVP-Host-Key";

    /** The header carrying the sender's time in epoch milliseconds, decimal. */
    static final String HEADER_TIME = "AVP-Host-Time";

    /** The header carrying the request signature, base64. */
    static final String HEADER_SIGNATURE = "AVP-Host-Signature";

    /** Most entries kept in the outbox; the oldest is dropped beyond it (the sweep repairs the gap). */
    static final int OUTBOX_CAP = 1024;

    /** Most catch-up requests queued for all peers. */
    static final int CATCHUP_CAP = 1024;

    /** Most items in one list of an offer or a fetch answer, and most ids in a heads answer or a fetch. */
    static final int MAX_ITEMS = 4096;

    /** Most {@code fetch} rounds of one catch-up. */
    static final int MAX_ROUNDS = 64;

    /** Most ids one catch-up requests in all. */
    static final int MAX_REQUESTED = 4096;

    /** The most rotation-commit candidates tried for one epoch-raising state. */
    static final int MAX_CANDIDATES = 8;

    /**
     * The most engine applications one catch-up may make in all its rounds: two full batches' worth of
     * {@link #budget}. It limits a peer that keeps the catch-up going, not the length of an honest history.
     */
    static final long CATCHUP_BUDGET = 2L * (3L * MAX_ITEMS + 64);

    private Replication() {}

    private static String k(byte[] id) {
        return AvpEncoding.base64(id);
    }

    private static byte[] unk(String id) {
        return java.util.Base64.getDecoder().decode(id);
    }

    // ─── Configuration ──────────────────────────────────────────────────────────────────

    /**
     * One peer host from {@code AVP_PEERS}.
     *
     * @param key the peer's Ed25519 host key
     * @param url the peer's base URL, {@code http://...}, without a trailing {@code /}
     */
    record Peer(byte[] key, String url) {
        /** Copies the key. */
        Peer {
            key = key.clone();
        }
    }

    /** The static peer list (SPEC 9.3): the only host keys that may call the host routes. */
    static final class Peers {
        private final List<Peer> list;

        private Peers(List<Peer> list) {
            this.list = List.copyOf(list);
        }

        /** The empty list. */
        static Peers none() {
            return new Peers(List.of());
        }

        /**
         * Parses {@code AVP_PEERS}: a comma-separated list of {@code <base64 hostKey>@<http base url>}.
         * Blank text gives an empty list; spaces around entries are ignored and trailing {@code /} of the
         * URL are dropped.
         *
         * @param text the variable's value
         * @return the peers
         * @throws AvpException naming the entry if it has no {@code @}, the key is not 32 bytes of standard
         *     base64, the URL is not a plain {@code http://} URL with a host (this profile has no TLS) or
         *     holds whitespace, a query, or a fragment, or a key appears twice
         */
        static Peers fromEnv(String text) throws AvpException {
            List<Peer> list = new ArrayList<>();
            String[] entries = text.split(",", -1);
            for (int n = 0; n < entries.length; n++) {
                String entry = entries[n].trim();
                if (entry.isEmpty()) {
                    continue;
                }
                String where = "AVP_PEERS entry " + (n + 1) + ": ";
                int at = entry.indexOf('@');
                if (at < 0) {
                    throw new AvpException(AvpException.Kind.BAD_ENCODING, where + "expected <base64 hostKey>@<url>");
                }
                byte[] key;
                try {
                    key = AvpEncoding.fromBase64(entry.substring(0, at).trim(), 32);
                } catch (AvpException e) {
                    throw new AvpException(
                            AvpException.Kind.BAD_ENCODING, where + "host key is not 32 bytes of base64");
                }
                String url = entry.substring(at + 1).trim();
                while (url.endsWith("/")) {
                    url = url.substring(0, url.length() - 1);
                }
                if (!url.startsWith("http://")) {
                    throw new AvpException(AvpException.Kind.BAD_ENCODING, where + "url must start with http://");
                }
                String rest = url.substring("http://".length());
                if (rest.isEmpty() || rest.startsWith("/")) {
                    throw new AvpException(AvpException.Kind.BAD_ENCODING, where + "url has no host");
                }
                if (url.chars().anyMatch(c -> Character.isWhitespace(c) || c == '?' || c == '#')) {
                    throw new AvpException(
                            AvpException.Kind.BAD_ENCODING, where + "url contains whitespace, a query, or a fragment");
                }
                for (Peer p : list) {
                    if (Arrays.equals(p.key(), key)) {
                        throw new AvpException(AvpException.Kind.BAD_ENCODING, where + "host key appears twice");
                    }
                }
                list.add(new Peer(key, url));
            }
            return new Peers(list);
        }

        /** The number of peers. */
        int size() {
            return list.size();
        }

        /** Whether the list is empty. */
        boolean isEmpty() {
            return list.isEmpty();
        }

        /** Whether {@code key} is a peer. */
        boolean contains(byte[] key) {
            return list.stream().anyMatch(p -> Arrays.equals(p.key(), key));
        }

        /** The peers in configuration order. */
        List<Peer> list() {
            return list;
        }
    }

    /**
     * Replication settings. The binary uses {@link #defaults()}; tests shorten the intervals.
     *
     * @param sweepIntervalMs how often each peer is swept ({@code heads}, then {@code fetch}); SPEC 9.3:
     *     every 5 seconds
     * @param requestTimeoutMs the whole-request timeout of an outbound host call, connection included
     * @param maxResponseBytes the largest peer response body read; a larger one is dropped unparsed
     * @param testControl whether {@code POST /v1/test/replication} exists ({@code AVP_TEST_CONTROL=1})
     */
    record Config(long sweepIntervalMs, long requestTimeoutMs, long maxResponseBytes, boolean testControl) {
        /** The binary's settings: 5 s sweeps, 10 s requests, 16 MiB answers, no test control. */
        static Config defaults() {
            return new Config(5_000, 10_000, 16L * 1024 * 1024, false);
        }
    }

    // ─── Shared runtime state (inside the host, under its lock) ─────────────────────────

    /**
     * One accepted write to offer to the repository's other hosts (SPEC 9.2).
     *
     * @param repoId the repository
     * @param manifests manifest states (an epoch-raising state travels with its rotation commit)
     * @param commits commits
     * @param leaves leave requests
     */
    record Outgoing(
            String repoId,
            List<AvpManifest.SignedManifest> manifests,
            List<AvpCommit.Commit> commits,
            List<AvpTokens.LeaveRequest> leaves) {
        /** Copies the lists. */
        Outgoing {
            manifests = List.copyOf(manifests);
            commits = List.copyOf(commits);
            leaves = List.copyOf(leaves);
        }
    }

    /**
     * The accepted client writes waiting to be offered, numbered so each peer worker keeps its own cursor.
     * Beyond {@link #OUTBOX_CAP} entries the oldest is dropped, and the periodic sweep brings a peer that
     * missed it up to date.
     */
    static final class Outbox {
        private record Numbered(long n, Outgoing item) {}

        private long next;
        private final ArrayDeque<Numbered> items = new ArrayDeque<>();

        /** Queues one write. */
        void push(Outgoing item) {
            next++;
            items.addLast(new Numbered(next, item));
            while (items.size() > OUTBOX_CAP) {
                items.removeFirst();
            }
        }

        /** The queued writes, oldest first. */
        List<Outgoing> entries() {
            return items.stream().map(Numbered::item).toList();
        }

        /** The entries after {@code cursor}, and the number of the last one. */
        private Map.Entry<List<Outgoing>, Long> after(long cursor) {
            long last = cursor;
            List<Outgoing> out = new ArrayList<>();
            for (Numbered e : items) {
                if (e.n() > cursor) {
                    last = e.n();
                    out.add(e.item());
                }
            }
            return Map.entry(out, last);
        }
    }

    /**
     * A queued catch-up of {@code repoId} from {@code peer}.
     *
     * @param peer the peer's host key
     * @param repoId the repository
     */
    record Catchup(byte[] peer, String repoId) {}

    /** Queues an accepted client write for the peers and wakes the workers; the caller holds the lock. */
    static void queueOffer(Server.Host host, Outgoing item) {
        host.outbox.push(item);
        host.wake.signalAll();
    }

    /** Queues a catch-up of {@code repoId} from {@code peer} and wakes the workers; the caller holds the lock. */
    static void queueCatchup(Server.Host host, byte[] peer, String repoId) {
        for (Catchup c : host.catchups) {
            if (Arrays.equals(c.peer(), peer) && c.repoId().equals(repoId)) {
                return;
            }
        }
        if (host.catchups.size() >= CATCHUP_CAP) {
            host.catchups.removeFirst();
        }
        host.catchups.addLast(new Catchup(peer.clone(), repoId));
        host.wake.signalAll();
    }

    // ─── Host request signature (SPEC 9.3) ──────────────────────────────────────────────

    /**
     * The signed message of a host request: {@code CE(tag "avp/host-req/v1", str(method), str(path),
     * bytes(SHA-256(body)), i64(time))}.
     *
     * @param method the uppercase HTTP method
     * @param path the request path exactly as sent, without the query
     * @param body the exact body bytes
     * @param time the {@code AVP-Host-Time} value
     * @return the message bytes
     * @throws AvpException not reachable for in-memory requests
     */
    static byte[] requestMessage(String method, String path, byte[] body, long time) throws AvpException {
        return AvpEncoding.tag(HOST_REQ_TAG)
                .str(method)
                .str(path)
                .bytes(AvpCrypto.sha256(body))
                .i64(time)
                .finish();
    }

    /** {@code AVP-Host-Time} as SPEC 9.3 states it: decimal digits with an optional leading {@code -}. */
    private static Long decimal(String text) {
        String digits = text.startsWith("-") ? text.substring(1) : text;
        if (digits.isEmpty() || !digits.chars().allMatch(c -> c >= '0' && c <= '9')) {
            return null;
        }
        try {
            return Long.parseLong(text);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * The sender's key if the request is from a configured peer, is signed over exactly this method, path,
     * and body, and is within the skew window; {@code null} (answered {@code 401}) otherwise. The caller
     * holds the lock.
     */
    static byte[] authenticate(
            Server.Host host,
            String method,
            String path,
            byte[] body,
            String keyText,
            String timeText,
            String sigText) {
        if (keyText == null || timeText == null || sigText == null) {
            return null;
        }
        byte[] key;
        byte[] signature;
        try {
            key = AvpEncoding.fromBase64(keyText, 32);
            signature = AvpEncoding.fromBase64(sigText, 64);
        } catch (AvpException e) {
            return null;
        }
        Long time = decimal(timeText);
        if (time == null || !host.peers.contains(key)) {
            return null;
        }
        long now = host.nowMs();
        long skew;
        try {
            skew = Math.abs(Math.subtractExact(now, time));
        } catch (ArithmeticException e) {
            return null;
        }
        if (skew < 0 || skew > MAX_SKEW_MS) {
            return null;
        }
        try {
            return AvpCrypto.ed25519Verify(key, requestMessage(method, path, body, time), signature) ? key : null;
        } catch (AvpException e) {
            return null;
        }
    }

    // ─── Item lists (schema/avp.schema.json) ────────────────────────────────────────────

    /**
     * The item lists of an {@code offer} body or a {@code fetch} answer.
     *
     * @param manifests manifest states
     * @param commits commits
     * @param leaves leave requests
     */
    record Items(
            List<AvpManifest.SignedManifest> manifests,
            List<AvpCommit.Commit> commits,
            List<AvpTokens.LeaveRequest> leaves) {
        /** Copies the lists. */
        Items {
            manifests = List.copyOf(manifests);
            commits = List.copyOf(commits);
            leaves = List.copyOf(leaves);
        }

        static Items empty() {
            return new Items(List.of(), List.of(), List.of());
        }

        /** Whether every list is within {@link #MAX_ITEMS}. */
        boolean bounded() {
            return manifests.size() <= MAX_ITEMS && commits.size() <= MAX_ITEMS && leaves.size() <= MAX_ITEMS;
        }
    }

    /**
     * Decodes the three item lists of an object; unknown fields are left to the caller (a request body is
     * strict, a peer answer tolerant).
     */
    static Items itemsFromJson(Map<String, Object> o) throws AvpException {
        List<AvpManifest.SignedManifest> ms = new ArrayList<>();
        for (Object m : AvpJson.array(AvpJson.required(o, "manifests"), "manifests")) {
            ms.add(AvpManifest.signedManifestFromJson(m));
        }
        List<AvpCommit.Commit> cs = new ArrayList<>();
        for (Object c : AvpJson.array(AvpJson.required(o, "commits"), "commits")) {
            cs.add(AvpCommit.fromJson(c));
        }
        List<AvpTokens.LeaveRequest> ls = new ArrayList<>();
        for (Object l : AvpJson.array(AvpJson.required(o, "leaves"), "leaves")) {
            ls.add(AvpTokens.leaveFromJson(l));
        }
        return new Items(ms, cs, ls);
    }

    private static Map<String, Object> itemsJson(String repoId, Items items) {
        Map<String, Object> o = new LinkedHashMap<>();
        if (repoId != null) {
            o.put("repoId", repoId);
        }
        List<Object> ms = new ArrayList<>();
        for (AvpManifest.SignedManifest m : items.manifests()) {
            ms.add(AvpManifest.toJson(m));
        }
        List<Object> cs = new ArrayList<>();
        for (AvpCommit.Commit c : items.commits()) {
            cs.add(AvpCommit.toJson(c));
        }
        List<Object> ls = new ArrayList<>();
        for (AvpTokens.LeaveRequest l : items.leaves()) {
            ls.add(AvpTokens.toJson(l));
        }
        o.put("manifests", ms);
        o.put("commits", cs);
        o.put("leaves", ls);
        return o;
    }

    // ─── Applying received items (SPEC 9.1, 9.2) ────────────────────────────────────────

    /**
     * An id the engine rejected, with the code it would give a client.
     *
     * @param id the manifest hash or commit id
     * @param code the SPEC 10.4 code
     */
    record Rejected(byte[] id, String code) {}

    /** The per-item outcome of applying received items to a view. */
    static final class Applied {
        /** Manifest hashes and commit ids the engine accepted. */
        List<byte[]> accepted = new ArrayList<>();
        /** Ids the engine rejected, with their codes. */
        final List<Rejected> rejected = new ArrayList<>();
        /**
         * States not applied yet: their previous state is unknown, or they raise the epoch and their
         * rotation commit still misses something. A catch-up carries them into its next round.
         */
        List<AvpManifest.SignedManifest> deferred = new ArrayList<>();
        /** Commits not applied yet for the same reasons, rotation commits of deferred states included. */
        List<AvpCommit.Commit> waiting = new ArrayList<>();
        /** Whether the sender may hold what this host lacks ({@code missing_parents} or {@code manifest_conflict}). */
        boolean incomplete;
        /** The engine applications this took. */
        long applications;
        /** Whether the engine-work budget ran out with items still to try. */
        boolean exhausted;

        void reject(byte[] id, String code) {
            if (code.equals(AvpRules.MISSING_PARENTS) || code.equals(AvpRules.MANIFEST_CONFLICT)) {
                incomplete = true;
            }
            rejected.add(new Rejected(id, code));
        }

        /** Whether some state could not be placed on a chain yet: the received tip is not known. */
        boolean hasGap() {
            return !deferred.isEmpty();
        }

        /** The {@code OfferResponse} body. */
        Map<String, Object> reply() {
            List<Object> rej = new ArrayList<>();
            for (Rejected r : rejected) {
                Map<String, Object> o = new LinkedHashMap<>();
                o.put("id", k(r.id()));
                o.put("code", r.code());
                rej.add(o);
            }
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("accepted", Server.idsJson(accepted));
            o.put("rejected", rej);
            return o;
        }
    }

    private static byte[] hashOf(AvpManifest.SignedManifest m) {
        try {
            return AvpManifest.hash(m);
        } catch (AvpException | RuntimeException e) {
            return null;
        }
    }

    private static byte[] prevHash(AvpManifest.SignedManifest m) {
        byte[] p = m.state().prevManifestHash();
        return p.length == 32 ? p : null;
    }

    private static boolean isNext(Long prev, long epoch) {
        return prev != null && prev != Long.MAX_VALUE && prev + 1 == epoch;
    }

    /** The keyEpoch of the state {@code m} links to, if the view holds it. */
    private static Long prevEpoch(AvpRules.RepoView view, AvpManifest.SignedManifest m) {
        byte[] prev = prevHash(m);
        if (prev == null) {
            return null;
        }
        return view.manifest(prev).map(p -> p.state().keyEpoch()).orElse(null);
    }

    /**
     * Whether {@code c} has the shape of the rotation commit of the state {@code m} whose hash is {@code
     * hash} (SPEC 8.3): it cites that state and its epoch and is authored by the owner.
     */
    private static boolean isRotationFor(AvpCommit.Commit c, AvpManifest.SignedManifest m, byte[] hash) {
        return Arrays.equals(c.manifestHash(), hash)
                && c.manifestSeq() == m.state().manifestSeq()
                && Arrays.equals(c.author(), m.state().ownerKey())
                && c.keyEpoch() == m.state().keyEpoch();
    }

    /** A received state with its hash. */
    private record Pending(byte[] hash, String key, AvpManifest.SignedManifest m) {}

    /**
     * The most engine applications one {@link #applyItems} call may make for {@code items} received items:
     * about two per item for an honest batch in any order, three with room to spare.
     */
    private static long budget(int items) {
        return 3L * items + 64;
    }

    /** One received item in the worklist. */
    private record Task(boolean state, int index) {}

    /** The worklist of {@link #applyItems}: what to try next, and who waits on which id. */
    private static final class Worklist {
        private final ArrayDeque<Task> queue = new ArrayDeque<>();
        private final Set<Task> queued = new HashSet<>();
        private final Map<String, List<Task>> waiters = new HashMap<>();

        void push(Task w) {
            if (queued.add(w)) {
                queue.addLast(w);
            }
        }

        Task pop() {
            Task w = queue.pollFirst();
            if (w != null) {
                queued.remove(w);
            }
            return w;
        }

        /** {@code w} is retried when an item with one of {@code ids} settles. */
        void await(Task w, List<byte[]> ids) {
            for (byte[] id : ids) {
                waiters.computeIfAbsent(k(id), x -> new ArrayList<>()).add(w);
            }
        }

        /** The item with {@code id} settled: every item waiting on it is tried again. */
        void wake(byte[] id) {
            List<Task> ws = waiters.remove(k(id));
            if (ws != null) {
                for (Task w : ws) {
                    push(w);
                }
            }
        }
    }

    private static boolean allParentsAccepted(AvpRules.RepoView view, AvpCommit.Commit c) {
        for (byte[] q : c.parents()) {
            if (view.status(q).orElse(null) != AvpRules.CommitStatus.ACCEPTED) {
                return false;
            }
        }
        return true;
    }

    /**
     * Applies received items to {@code view} with {@link AvpRules.Via#OFFER} in the dependency order of
     * SPEC 9.1, whatever order the sender used: a commit after the state it cites and after its parents,
     * each epoch-raising state with its rotation commit as one atomic pair, leave requests last (a failing
     * one is dropped).
     *
     * <p>Every item is tried once (states by ascending manifestSeq, then commits parents first). One that
     * cannot apply yet waits on the ids it misses and is tried again only when an item with one of those
     * ids settles, so the engine work is linear in the items, and it is also capped by {@link #budget}. A
     * commit that can never apply in this batch is not tried at all. An epoch-raising state tries each
     * commit shaped like its rotation commit (only verified ones, at most {@link #MAX_CANDIDATES}, those
     * whose parents are all accepted first) until one pairs with it, so a decoy does not block the pair.
     *
     * <p>What is left is reported ({@code missing_parents} for a waiting pair and commit, {@code
     * manifest_conflict} for a state with an unknown previous state) and returned in {@link
     * Applied#deferred} and {@link Applied#waiting}. {@code cap} lowers the budget further. With {@code
     * statesOnly}, only states and their rotation commits are applied. Nothing here trusts the sender.
     */
    static Applied applyItems(AvpRules.RepoView view, String repoId, Items items, boolean statesOnly, long cap) {
        Applied out = new Applied();
        Set<String> seen = new HashSet<>();
        List<Pending> states = new ArrayList<>();
        for (AvpManifest.SignedManifest m : items.manifests()) {
            byte[] hash = hashOf(m);
            if (hash == null) {
                // A state whose canonical bytes cannot be built has no id to report; it is dropped.
                continue;
            }
            if (!seen.add(k(hash))) {
                continue;
            }
            if (!m.state().repoId().equals(repoId)) {
                out.reject(hash, AvpRules.BAD_REQUEST);
                continue;
            }
            states.add(new Pending(hash, k(hash), m));
        }
        states.sort((a, b) ->
                Long.compare(a.m().state().manifestSeq(), b.m().state().manifestSeq()));
        List<AvpCommit.Commit> commits = parentsFirst(items.commits());
        long limit = Math.min(budget(states.size() + commits.size()), cap);

        Map<String, Integer> stateAt = new HashMap<>();
        for (int i = 0; i < states.size(); i++) {
            stateAt.put(states.get(i).key(), i);
        }
        Map<String, Integer> commitAt = new HashMap<>();
        for (int i = 0; i < commits.size(); i++) {
            commitAt.put(k(commits.get(i).commitId()), i);
        }

        // Rotation-commit candidates of each state, and the state a candidate is reserved for. A candidate
        // must verify: only the owner can make one, so a listed peer cannot fill the cut with decoys. Before
        // the cut, candidates whose parents are all accepted come first, then those whose parents are all
        // held or offered, then the rest; the sender's order decides only among equals.
        List<List<Integer>> candidates = new ArrayList<>();
        for (int i = 0; i < states.size(); i++) {
            candidates.add(new ArrayList<>());
        }
        Integer[] reserved = new Integer[commits.size()];
        for (int ci = 0; ci < commits.size(); ci++) {
            AvpCommit.Commit c = commits.get(ci);
            Integer si = stateAt.get(k(c.manifestHash()));
            if (si != null) {
                Pending p = states.get(si);
                // Only a state after the genesis with a raised epoch can have a rotation commit.
                boolean mayRaise =
                        p.m().state().manifestSeq() > 1 && p.m().state().keyEpoch() > 0;
                if (mayRaise && isRotationFor(c, p.m(), p.hash()) && AvpCommit.verify(c)) {
                    candidates.get(si).add(ci);
                }
            }
        }
        for (int si = 0; si < candidates.size(); si++) {
            List<Integer> list = candidates.get(si);
            list.sort((x, y) ->
                    Integer.compare(rank(view, commits.get(x), commitAt), rank(view, commits.get(y), commitAt)));
            while (list.size() > MAX_CANDIDATES) {
                list.remove(list.size() - 1);
            }
            for (int ci : list) {
                reserved[ci] = si;
            }
        }

        // States behind a gap no item of this batch fills, in ascending seq.
        boolean[] gap = new boolean[states.size()];
        for (int si = 0; si < states.size(); si++) {
            Pending p = states.get(si);
            byte[] prev = prevHash(p.m());
            boolean filled = p.m().state().manifestSeq() == 1;
            if (!filled && prev != null) {
                Integer j = stateAt.get(k(prev));
                filled = view.manifest(prev).isPresent() || (j != null && j < si && !gap[j]);
            }
            gap[si] = !filled;
        }

        // Commits that cannot apply in this batch whatever happens: never tried. `blocked` marks the states
        // that cannot settle in this batch.
        boolean[] blocked = gap.clone();
        boolean[] hopeless = hopelessGiven(view, commits, stateAt, commitAt, blocked);
        // An epoch-raising state whose rotation candidates all cannot apply here waits for its rotation
        // commit, so it cannot settle in this batch either, nor can a state after it on its chain, nor a
        // commit citing one of them. A few rounds reach a fixed point in practice.
        for (int round = 0; round < 8; round++) {
            boolean changed = false;
            for (int si = 0; si < states.size(); si++) {
                Pending p = states.get(si);
                if (blocked[si] || view.manifest(p.hash()).isPresent()) {
                    continue;
                }
                byte[] prev = prevHash(p.m());
                Integer prevAt = prev == null ? null : stateAt.get(k(prev));
                boolean prevHeld = prev != null && view.manifest(prev).isPresent();
                boolean afterBlocked = !prevHeld && prevAt != null && prevAt < si && blocked[prevAt];
                Long pe = null;
                if (prev != null) {
                    pe = view.manifest(prev)
                            .map(m -> m.state().keyEpoch())
                            .orElse(
                                    prevAt == null
                                            ? null
                                            : states.get(prevAt).m().state().keyEpoch());
                }
                boolean raising = p.m().state().manifestSeq() > 1
                        && isNext(pe, p.m().state().keyEpoch());
                List<Integer> cands = candidates.get(si);
                boolean allHopeless = true;
                for (int ci : cands) {
                    allHopeless &= hopeless[ci];
                }
                boolean stuck = raising && !cands.isEmpty() && allHopeless;
                if (afterBlocked || stuck) {
                    blocked[si] = true;
                    changed = true;
                }
            }
            if (!changed) {
                break;
            }
            hopeless = hopelessGiven(view, commits, stateAt, commitAt, blocked);
        }
        final boolean[] hopelessFinal = hopeless;

        boolean[] stateDone = new boolean[states.size()];
        boolean[] commitDone = new boolean[commits.size()];
        Worklist work = new Worklist();
        for (int si = 0; si < states.size(); si++) {
            work.push(new Task(true, si));
        }
        if (!statesOnly) {
            for (int ci = 0; ci < commits.size(); ci++) {
                if (!hopelessFinal[ci] && reserved[ci] == null) {
                    work.push(new Task(false, ci));
                }
            }
        }
        boolean exhausted = false;

        loop:
        for (Task w = work.pop(); w != null; w = work.pop()) {
            if (out.applications >= limit) {
                exhausted = true;
                break;
            }
            if (!w.state()) {
                int ci = w.index();
                AvpCommit.Commit c = commits.get(ci);
                if (commitDone[ci] || reserved[ci] != null) {
                    continue;
                }
                out.applications++;
                Optional<String> r = view.applyCommit(c, AvpRules.Via.OFFER);
                if (r.isPresent() && r.get().equals(AvpRules.MISSING_PARENTS)) {
                    work.await(w, view.missingFor(c));
                } else {
                    if (r.isEmpty()) {
                        out.accepted.add(c.commitId());
                    } else {
                        out.reject(c.commitId(), r.get());
                    }
                    commitDone[ci] = true;
                    work.wake(c.commitId());
                }
                continue;
            }
            int si = w.index();
            Pending p = states.get(si);
            if (stateDone[si]) {
                continue;
            }
            List<Integer> cands = new ArrayList<>(candidates.get(si));
            if (view.isWinning(p.hash())) {
                // Already on the chain: accepted again with no change. Its rotation commit, if offered, is
                // applied as an ordinary commit and accepted again the same way.
                out.accepted.add(p.hash());
                stateDone[si] = true;
                release(reserved, work, cands, statesOnly, hopelessFinal);
                work.wake(p.hash());
                continue;
            }
            boolean genesis = p.m().state().manifestSeq() == 1;
            Long pe = prevEpoch(view, p.m());
            boolean raising;
            if (pe != null) {
                raising = isNext(pe, p.m().state().keyEpoch());
            } else if (genesis) {
                raising = false;
            } else {
                // A gap: wait for the previous state.
                byte[] prev = prevHash(p.m());
                if (prev != null) {
                    work.await(w, List.of(prev));
                }
                continue;
            }
            List<Integer> live = new ArrayList<>();
            if (raising) {
                for (int ci : cands) {
                    if (!commitDone[ci] && !hopelessFinal[ci]) {
                        live.add(ci);
                    }
                }
            }
            // A candidate whose parents are all held goes first.
            live.sort((x, y) -> Boolean.compare(
                    !allParentsAccepted(view, commits.get(x)), !allParentsAccepted(view, commits.get(y))));
            if (live.isEmpty() && raising && cands.stream().anyMatch(ci -> !commitDone[ci])) {
                // Its rotation commit is offered but cannot apply in this batch: the pair waits for the next
                // catch-up round.
                continue;
            }
            if (live.isEmpty()) {
                out.applications++;
                Optional<String> r = view.applyManifest(p.m(), Optional.empty(), AvpRules.Via.OFFER);
                if (r.isEmpty()) {
                    out.accepted.add(p.hash());
                } else {
                    out.reject(p.hash(), r.get());
                }
                stateDone[si] = true;
                release(reserved, work, cands, statesOnly, hopelessFinal);
                work.wake(p.hash());
                continue;
            }
            List<byte[]> missing = new ArrayList<>();
            Integer outcomeCi = null;
            Optional<String> outcome = null;
            // The first candidate that failed for a reason of its own, kept in case none pairs.
            Integer failedCi = null;
            String failedCode = null;
            for (int ci : live) {
                if (out.applications >= limit) {
                    exhausted = true;
                    break;
                }
                AvpCommit.Commit c = commits.get(ci);
                out.applications++;
                Optional<String> r = view.applyManifest(p.m(), Optional.of(c), AvpRules.Via.OFFER);
                if (r.isPresent() && r.get().equals(AvpRules.MISSING_PARENTS)) {
                    for (byte[] id : view.missingFor(c)) {
                        if (!Arrays.equals(id, p.hash())) {
                            missing.add(id);
                        }
                    }
                } else if (r.isPresent() && !r.get().equals(AvpRules.MANIFEST_CONFLICT)) {
                    // This candidate cannot be the rotation commit, or the state itself is invalid: another
                    // candidate may still pair with the state.
                    if (failedCi == null) {
                        failedCi = ci;
                        failedCode = r.get();
                    }
                } else if (r.isPresent()
                        && view.manifest(p.hash()).isPresent()
                        && !view.rotationCommit(p.hash())
                                .map(x -> Arrays.equals(x.commitId(), c.commitId()))
                                .orElse(false)) {
                    // A verified losing state the engine kept without this candidate as its rotation
                    // commit: a later candidate may be the real one (SPEC 8.3 keeps it with the state).
                    if (failedCi == null) {
                        failedCi = ci;
                        failedCode = AvpRules.MANIFEST_CONFLICT;
                    }
                } else {
                    // Accepted, or a verified losing state kept with this candidate as its held rotation
                    // commit: settled.
                    outcomeCi = ci;
                    outcome = r;
                    break;
                }
            }
            if (outcomeCi == null && missing.isEmpty() && !exhausted && failedCi != null) {
                outcomeCi = failedCi;
                outcome = Optional.of(failedCode);
            }
            if (outcomeCi != null) {
                byte[] id = commits.get(outcomeCi).commitId();
                if (outcome.isEmpty()) {
                    out.accepted.add(p.hash());
                    out.accepted.add(id);
                } else {
                    // Both items of a rejected pair carry the same code (SPEC 9.1).
                    out.reject(p.hash(), outcome.get());
                    out.reject(id, outcome.get());
                }
                commitDone[outcomeCi] = true;
                stateDone[si] = true;
                List<Integer> others = new ArrayList<>();
                for (int o : cands) {
                    if (o != outcomeCi) {
                        others.add(o);
                    }
                }
                release(reserved, work, others, statesOnly, hopelessFinal);
                work.wake(p.hash());
                work.wake(id);
            } else if (exhausted) {
                break loop;
            } else {
                work.await(w, missing);
            }
        }
        out.exhausted = exhausted;

        // Report what is left, and return it for the next catch-up round.
        Set<String> reported = new HashSet<>();
        List<AvpManifest.SignedManifest> deferred = new ArrayList<>();
        for (int si = 0; si < states.size(); si++) {
            if (stateDone[si]) {
                continue;
            }
            Pending p = states.get(si);
            String code = p.m().state().manifestSeq() == 1 || prevEpoch(view, p.m()) != null
                    ? AvpRules.MISSING_PARENTS
                    : AvpRules.MANIFEST_CONFLICT;
            out.reject(p.hash(), code);
            for (int ci : candidates.get(si)) {
                if (!commitDone[ci]) {
                    byte[] id = commits.get(ci).commitId();
                    out.reject(id, code);
                    reported.add(k(id));
                    break;
                }
            }
            deferred.add(p.m());
        }
        List<AvpCommit.Commit> waiting = new ArrayList<>();
        for (int ci = 0; ci < commits.size(); ci++) {
            if (commitDone[ci]) {
                continue;
            }
            AvpCommit.Commit c = commits.get(ci);
            if (!statesOnly && !reported.contains(k(c.commitId()))) {
                out.reject(c.commitId(), AvpRules.MISSING_PARENTS);
            }
            waiting.add(c);
        }
        if (!statesOnly) {
            for (AvpTokens.LeaveRequest l : items.leaves()) {
                // A failing leave request is dropped (SPEC 9.1).
                view.applyLeave(l, AvpRules.Via.OFFER);
            }
        }
        out.deferred = deferred;
        out.waiting = waiting;
        return out;
    }

    /** The rank of a rotation candidate: 0 if all parents are accepted, 1 if all held or offered, else 2. */
    private static int rank(AvpRules.RepoView view, AvpCommit.Commit c, Map<String, Integer> commitAt) {
        if (allParentsAccepted(view, c)) {
            return 0;
        }
        for (byte[] q : c.parents()) {
            if (view.status(q).isEmpty() && !commitAt.containsKey(k(q))) {
                return 2;
            }
        }
        return 1;
    }

    /** Releases the candidates of a settled state as ordinary commits. */
    private static void release(
            Integer[] reserved, Worklist work, List<Integer> cands, boolean statesOnly, boolean[] hopeless) {
        for (int ci : cands) {
            reserved[ci] = null;
            if (!statesOnly && !hopeless[ci]) {
                work.push(new Task(false, ci));
            }
        }
    }

    /** Which commits cannot apply in this batch, given the states that cannot settle in it. */
    private static boolean[] hopelessGiven(
            AvpRules.RepoView view,
            List<AvpCommit.Commit> commits,
            Map<String, Integer> stateAt,
            Map<String, Integer> commitAt,
            boolean[] blocked) {
        boolean[] hopeless = new boolean[commits.size()];
        for (int ci = 0; ci < commits.size(); ci++) {
            AvpCommit.Commit c = commits.get(ci);
            Integer si = stateAt.get(k(c.manifestHash()));
            boolean cited = view.manifest(c.manifestHash()).isPresent() || (si != null && !blocked[si]);
            boolean parents = true;
            for (byte[] p : c.parents()) {
                Integer j = commitAt.get(k(p));
                if (!(view.status(p).isPresent() || (j != null && j < ci && !hopeless[j]))) {
                    parents = false;
                    break;
                }
            }
            hopeless[ci] = !(cited && parents);
        }
        return hopeless;
    }

    /**
     * Orders commits so that a commit comes after every parent in the same batch (Kahn's algorithm over the
     * claimed ids). Duplicates are dropped. Commits left in a claimed cycle, which valid ids cannot form, go
     * last; the engine rejects them.
     */
    static List<AvpCommit.Commit> parentsFirst(List<AvpCommit.Commit> commits) {
        Map<String, Integer> index = new HashMap<>();
        List<AvpCommit.Commit> unique = new ArrayList<>();
        for (AvpCommit.Commit c : commits) {
            if (index.putIfAbsent(k(c.commitId()), unique.size()) == null) {
                unique.add(c);
            }
        }
        int[] waitingOn = new int[unique.size()];
        List<List<Integer>> children = new ArrayList<>();
        for (int i = 0; i < unique.size(); i++) {
            children.add(new ArrayList<>());
        }
        for (int i = 0; i < unique.size(); i++) {
            for (byte[] p : unique.get(i).parents()) {
                Integer j = index.get(k(p));
                if (j != null) {
                    waitingOn[i]++;
                    children.get(j).add(i);
                }
            }
        }
        ArrayDeque<Integer> ready = new ArrayDeque<>();
        for (int i = 0; i < unique.size(); i++) {
            if (waitingOn[i] == 0) {
                ready.add(i);
            }
        }
        List<AvpCommit.Commit> order = new ArrayList<>();
        boolean[] placed = new boolean[unique.size()];
        while (!ready.isEmpty()) {
            int i = ready.poll();
            order.add(unique.get(i));
            placed[i] = true;
            for (int ch : children.get(i)) {
                if (--waitingOn[ch] == 0) {
                    ready.add(ch);
                }
            }
        }
        for (int i = 0; i < unique.size(); i++) {
            if (!placed[i]) {
                order.add(unique.get(i));
            }
        }
        return order;
    }

    /**
     * A trial view with the outcome of applying items to it.
     *
     * @param view the view, holding only what the engine accepted or must store
     * @param applied the per-item outcome
     */
    record Kept(AvpRules.RepoView view, Applied applied) {}

    /**
     * Applies {@code items} to a copy of {@code base} and returns it with the per-item outcome, keeping only
     * what the engine accepted or must store.
     *
     * <p>A listed peer must not be able to grow a repository with items the engine refuses: a rejected
     * commit is stored with that status, and the header of a commit that misses a parent is kept for
     * ancestry (SPEC 7.3). So when an offered commit ends neither accepted, held, nor pending, the copy is
     * rebuilt from {@code base} with the states, the leave requests, and only the commits that ended
     * accepted, held, or pending. When a dropped commit's header was what decided a kept one in the trial,
     * the answer reports its stored status instead, so the answer always matches what is stored.
     */
    static Kept applyKept(AvpRules.RepoView base, String repoId, Items items, boolean statesOnly, long cap) {
        AvpRules.RepoView trial = base.copy();
        Applied applied = applyItems(trial, repoId, items, statesOnly, cap);
        List<AvpCommit.Commit> keptCommits = new ArrayList<>();
        boolean all = true;
        for (AvpCommit.Commit c : items.commits()) {
            AvpRules.CommitStatus s = trial.status(c.commitId()).orElse(null);
            if (s == AvpRules.CommitStatus.ACCEPTED
                    || s == AvpRules.CommitStatus.HELD
                    || s == AvpRules.CommitStatus.PENDING) {
                keptCommits.add(c);
            } else {
                all = false;
            }
        }
        if (all) {
            return new Kept(trial, applied);
        }
        AvpRules.RepoView clean = base.copy();
        applied.applications += applyItems(
                        clean,
                        repoId,
                        new Items(items.manifests(), keptCommits, items.leaves()),
                        statesOnly,
                        Long.MAX_VALUE)
                .applications;
        // The answer reports what is stored. A commit the trial accepted only thanks to a header the rebuild
        // left out is reported with the code its stored status gives, and waits for a retry.
        List<byte[]> stored = new ArrayList<>();
        List<byte[]> moved = new ArrayList<>();
        for (byte[] id : applied.accepted) {
            if (clean.manifest(id).isPresent() || clean.status(id).orElse(null) == AvpRules.CommitStatus.ACCEPTED) {
                stored.add(id);
            } else {
                moved.add(id);
            }
        }
        applied.accepted = stored;
        for (byte[] id : moved) {
            AvpRules.CommitStatus s = clean.status(id).orElse(null);
            String code = s == AvpRules.CommitStatus.HELD || s == AvpRules.CommitStatus.REJECTED
                    ? AvpRules.FORBIDDEN
                    : AvpRules.MISSING_PARENTS;
            applied.reject(id, code);
            for (AvpCommit.Commit c : keptCommits) {
                if (Arrays.equals(c.commitId(), id)) {
                    applied.waiting.add(c);
                    break;
                }
            }
        }
        return new Kept(clean, applied);
    }

    /** What happened to a trial view after the received-tip check (SPEC 9.2). */
    enum Admitted {
        /** Stored; the tip lists this host. */
        HOSTED,
        /**
         * The received tip does not list this host: a held repository kept the validated states and is now
         * not hosted; a first copy stored nothing.
         */
        NOT_HOSTED,
        /** A first copy whose received tip does not list the sender: nothing stored. */
        FORBIDDEN,
        /** A first copy over the per-owner or store-wide repository cap: nothing stored. */
        QUOTA,
        /** A first copy whose received tip is not known yet: nothing stored; the catch-up decides. */
        INCOMPLETE
    }

    /**
     * The decision on a validated first copy (SPEC 9.2): stored only if its received tip lists this host and
     * the sender and the repository caps allow it. The caller holds the lock.
     */
    static Admitted admitFirstCopy(Server.Host host, String repoId, byte[] sender, AvpRules.RepoView trial) {
        Optional<AvpManifest.SignedManifest> tip = trial.tip();
        if (tip.isEmpty()) {
            return Admitted.INCOMPLETE;
        }
        if (!tip.get().state().repoId().equals(repoId) || !trial.tipListsHost()) {
            return Admitted.NOT_HOSTED;
        }
        if (!tip.get().state().hasHost(sender)) {
            return Admitted.FORBIDDEN;
        }
        byte[] owner = tip.get().state().ownerKey();
        if (host.repos.size() >= host.limits.maxRepos || host.reposOwnedBy(owner) >= host.limits.maxReposPerOwner) {
            return Admitted.QUOTA;
        }
        host.repos.put(repoId, trial);
        return Admitted.HOSTED;
    }

    /**
     * The outcome of {@link #receive}.
     *
     * @param admitted what was kept
     * @param applied the per-item outcome
     */
    record Received(Admitted admitted, Applied applied) {}

    /**
     * Applies {@code items} from {@code sender} to a trial copy of {@code repoId} (or a new view for a first
     * copy), checks the validated received tip, and installs what SPEC 6.1 rule 6, 8.6, and 9.2 allow. A
     * first copy is all or nothing; a held repository always gets the result, but when the received tip does
     * not list this host only the validated states with their rotation commits are kept. The caller holds
     * the lock.
     */
    static Received receive(Server.Host host, String repoId, byte[] sender, Items items, long cap) {
        AvpRules.RepoView base = host.repos.get(repoId);
        if (base == null) {
            AvpRules.RepoView fresh = new AvpRules.RepoView(host.hostKey, host.limits.headBound);
            Kept kept = applyKept(fresh, repoId, items, false, cap);
            host.engineApplications += kept.applied().applications;
            if (kept.applied().hasGap()) {
                return new Received(Admitted.INCOMPLETE, kept.applied());
            }
            return new Received(admitFirstCopy(host, repoId, sender, kept.view()), kept.applied());
        }
        Kept kept = applyKept(base, repoId, items, false, cap);
        host.engineApplications += kept.applied().applications;
        if (kept.view().tipListsHost()) {
            host.repos.put(repoId, kept.view());
            return new Received(Admitted.HOSTED, kept.applied());
        }
        // Held, and the received tip drops this host: keep the validated states (each epoch-raising one with
        // its rotation commit), not the other items (SPEC 8.6, 9.2).
        Items states = new Items(items.manifests(), items.commits(), List.of());
        Kept onlyStates = applyKept(base, repoId, states, true, Long.MAX_VALUE);
        host.repos.put(repoId, onlyStates.view());
        return new Received(Admitted.NOT_HOSTED, kept.applied());
    }

    // ─── The peer workers ───────────────────────────────────────────────────────────────

    /** The running replication: one worker thread per peer. {@link #close()} stops and joins them. */
    static final class Running implements AutoCloseable {
        private final Server.Host host;
        private final AtomicBoolean stop;
        private final List<Thread> threads;
        private final HttpClient client;

        private Running(Server.Host host, AtomicBoolean stop, List<Thread> threads, HttpClient client) {
            this.host = host;
            this.stop = stop;
            this.threads = threads;
            this.client = client;
        }

        @Override
        public void close() {
            stop.set(true);
            // Signal under the lock so no worker misses it between its check and its wait.
            host.lockForShutdown();
            try {
                host.wake.signalAll();
            } finally {
                host.unlock();
            }
            for (Thread t : threads) {
                t.interrupt();
            }
            for (Thread t : threads) {
                try {
                    t.join(host.replication.requestTimeoutMs() + 5_000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            client.shutdownNow();
        }
    }

    /**
     * Installs {@code peers} as the host's peer list and starts one worker thread per peer other than this
     * host. Each worker sweeps its peer at once (the startup replication of SPEC 9.3), then on every
     * accepted write and every sweep interval.
     */
    static Running run(Server.Host host, Peers peers) {
        host.lockForShutdown();
        try {
            host.peers = peers;
        } finally {
            host.unlock();
        }
        Config cfg = host.replication;
        HttpClient client = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.NEVER)
                .proxy(HttpClient.Builder.NO_PROXY)
                .connectTimeout(Duration.ofMillis(cfg.requestTimeoutMs()))
                .build();
        AtomicBoolean stop = new AtomicBoolean(false);
        List<Thread> threads = new ArrayList<>();
        int i = 0;
        for (Peer peer : peers.list()) {
            if (Arrays.equals(peer.key(), host.hostKey)) {
                continue;
            }
            Worker w = new Worker(host, peer, client, stop);
            Thread t = new Thread(w, "avp-peer-" + i++);
            t.setDaemon(true);
            t.start();
            threads.add(t);
        }
        return new Running(host, stop, threads, client);
    }

    /** A response body read with a size limit; completes with {@code null} when the body is too large. */
    private static final class Limited implements HttpResponse.BodySubscriber<byte[]> {
        private final long max;
        private final ByteArrayOutputStream buf = new ByteArrayOutputStream();
        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private Flow.Subscription sub;

        Limited(long max) {
            this.max = max;
        }

        @Override
        public CompletionStage<byte[]> getBody() {
            return result;
        }

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            sub = subscription;
            subscription.request(Long.MAX_VALUE);
        }

        @Override
        public void onNext(List<ByteBuffer> items) {
            if (result.isDone()) {
                return;
            }
            for (ByteBuffer b : items) {
                if (buf.size() + (long) b.remaining() > max) {
                    result.complete(null);
                    sub.cancel();
                    return;
                }
                byte[] chunk = new byte[b.remaining()];
                b.get(chunk);
                buf.writeBytes(chunk);
            }
        }

        @Override
        public void onError(Throwable throwable) {
            result.completeExceptionally(throwable);
        }

        @Override
        public void onComplete() {
            result.complete(buf.toByteArray());
        }
    }

    /** A peer's answer to {@code heads}. */
    private record HeadsReply(long seq, byte[] hash, List<byte[]> heads) {}

    /** The work one wake-up of a worker found. */
    private record Work(List<Outgoing> offers, List<String> repos) {}

    /** One peer's worker. */
    private static final class Worker implements Runnable {
        private final Server.Host host;
        private final Peer peer;
        private final HttpClient client;
        private final AtomicBoolean stop;
        private long cursor;
        private Long seenKick;
        private long nextSweep = System.nanoTime();

        Worker(Server.Host host, Peer peer, HttpClient client, AtomicBoolean stop) {
            this.host = host;
            this.peer = peer;
            this.client = client;
            this.stop = stop;
        }

        private boolean stopping() {
            return stop.get() || Thread.currentThread().isInterrupted();
        }

        @Override
        public void run() {
            try {
                for (Work work = nextWork(); work != null; work = nextWork()) {
                    for (Outgoing item : work.offers()) {
                        if (stopping()) {
                            return;
                        }
                        offer(item);
                    }
                    for (String repoId : work.repos()) {
                        if (stopping()) {
                            return;
                        }
                        catchUp(repoId);
                    }
                }
            } catch (IllegalStateException e) {
                // A poisoned state ends the worker, like a poisoned lock in the Rust host.
            }
        }

        /** Waits under the state lock until there is something to do, and takes it; {@code null} ends the worker. */
        private Work nextWork() {
            host.lock();
            try {
                while (true) {
                    if (stopping()) {
                        return null;
                    }
                    long now = System.nanoTime();
                    if (!host.paused) {
                        if (seenKick == null || seenKick != host.kick) {
                            seenKick = host.kick;
                            nextSweep = now;
                        }
                        Map.Entry<List<Outgoing>, Long> queued = host.outbox.after(cursor);
                        cursor = queued.getValue();
                        List<Outgoing> offers = new ArrayList<>();
                        for (Outgoing o : queued.getKey()) {
                            AvpRules.RepoView v = host.repos.get(o.repoId());
                            if (v != null
                                    && v.tipListsHost()
                                    && v.tip()
                                            .map(t -> t.state().hasHost(peer.key()))
                                            .orElse(false)) {
                                offers.add(o);
                            }
                        }
                        List<String> repos = new ArrayList<>();
                        host.catchups.removeIf(c -> {
                            if (Arrays.equals(c.peer(), peer.key())) {
                                repos.add(c.repoId());
                                return true;
                            }
                            return false;
                        });
                        if (now - nextSweep >= 0) {
                            // SPEC 9.3: only the repositories whose winning tip lists this peer, so a peer
                            // that is not listed never learns which repoIds this host holds.
                            TreeSet<String> listed = new TreeSet<>();
                            host.repos.forEach((r, v) -> {
                                if (v.tip()
                                        .map(t -> t.state().hasHost(peer.key()))
                                        .orElse(false)) {
                                    listed.add(r);
                                }
                            });
                            repos.addAll(listed);
                            nextSweep = now + TimeUnit.MILLISECONDS.toNanos(host.replication.sweepIntervalMs());
                        }
                        List<String> unique = new ArrayList<>(new java.util.LinkedHashSet<>(repos));
                        if (!offers.isEmpty() || !unique.isEmpty()) {
                            return new Work(offers, unique);
                        }
                    }
                    long waitNs = host.paused
                            ? TimeUnit.MILLISECONDS.toNanos(host.replication.sweepIntervalMs())
                            : nextSweep - now;
                    try {
                        host.wake.awaitNanos(Math.max(waitNs, TimeUnit.MILLISECONDS.toNanos(1)));
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return null;
                    }
                }
            } finally {
                host.unlock();
            }
        }

        /** One signed {@code POST} to the peer: its status and body, or {@code null} on any failure. */
        private Map.Entry<Integer, byte[]> call(String path, byte[] body) {
            long time;
            host.lock();
            try {
                if (host.paused) {
                    return null;
                }
                time = host.nowMs();
            } finally {
                host.unlock();
            }
            long timeout = host.replication.requestTimeoutMs();
            CompletableFuture<HttpResponse<byte[]>> future = null;
            try {
                byte[] signature = AvpCrypto.ed25519Sign(host.seed, requestMessage("POST", path, body, time));
                HttpRequest req = HttpRequest.newBuilder(URI.create(peer.url() + path))
                        .timeout(Duration.ofMillis(timeout))
                        .header(HEADER_KEY, k(host.hostKey))
                        .header(HEADER_TIME, Long.toString(time))
                        .header(HEADER_SIGNATURE, k(signature))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                        .build();
                long max = host.replication.maxResponseBytes();
                future = client.sendAsync(req, info -> new Limited(max));
                HttpResponse<byte[]> resp = future.get(timeout, TimeUnit.MILLISECONDS);
                return resp.body() == null ? null : Map.entry(resp.statusCode(), resp.body());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return null;
            } catch (TimeoutException | ExecutionException | AvpException | RuntimeException e) {
                if (future != null) {
                    future.cancel(true);
                }
                return null;
            }
        }

        /** A signed JSON call whose {@code 200} answer is a JSON object; anything else is {@code null}. */
        private Map<String, Object> postJson(String path, Object body) {
            Map.Entry<Integer, byte[]> got = call(path, AvpJson.writeUtf8(body));
            if (got == null || got.getKey() != 200) {
                return null;
            }
            try {
                return AvpJson.object(AvpJson.parse(got.getValue()), "answer");
            } catch (AvpException | RuntimeException e) {
                return null;
            }
        }

        /** Offers one accepted write; a peer that lacks something catches up from this host itself. */
        private void offer(Outgoing item) {
            postJson(
                    hostPath(item.repoId(), "offer"),
                    itemsJson(item.repoId(), new Items(item.manifests(), item.commits(), item.leaves())));
        }

        /** Decodes a {@code heads} answer tolerantly: unknown fields are ignored. */
        private static HeadsReply heads(Map<String, Object> o) {
            if (o == null) {
                return null;
            }
            try {
                Map<String, Object> tip = AvpJson.object(AvpJson.required(o, "manifestTip"), "manifestTip");
                long seq = AvpJson.integer(tip, "manifestSeq");
                byte[] hash = AvpEncoding.fromBase64(AvpJson.string(tip, "manifestHash"), 32);
                return new HeadsReply(seq, hash, AvpManifest.ids(o, "heads"));
            } catch (AvpException | RuntimeException e) {
                return null;
            }
        }

        /**
         * Catch-up from the peer (SPEC 9.2): {@code heads}, then {@code fetch} for the tip state and the
         * heads this host lacks, then, round after round, for what the carried items still miss, at most
         * {@link #MAX_ROUNDS} rounds, {@link #MAX_REQUESTED} ids, and {@link #CATCHUP_BUDGET} engine
         * applications. A held repository goes through {@link #receive} under the lock; a first copy is built
         * outside the lock on one trial view kept across the rounds and decided once at the end by {@link
         * #admitFirstCopy}. A peer that refuses or answers badly ends the catch-up of this repository only.
         */
        private void catchUp(String repoId) {
            Map<String, Object> headsBody = new LinkedHashMap<>();
            headsBody.put("repoId", repoId);
            HeadsReply heads = heads(postJson(hostPath(repoId, "heads"), headsBody));
            if (heads == null || heads.seq() < 1 || heads.heads().size() > MAX_ITEMS) {
                return;
            }
            List<byte[]> want = new ArrayList<>();
            AvpRules.RepoView firstCopy;
            host.lock();
            try {
                AvpRules.RepoView view = host.repos.get(repoId);
                if (view == null || view.manifest(heads.hash()).isEmpty()) {
                    want.add(heads.hash());
                }
                Set<String> wanted = new HashSet<>();
                wanted.add(k(heads.hash()));
                for (byte[] h : heads.heads()) {
                    if ((view == null || view.status(h).isEmpty()) && wanted.add(k(h))) {
                        want.add(h);
                    }
                }
                firstCopy = view == null ? new AvpRules.RepoView(host.hostKey, host.limits.headBound) : null;
            } finally {
                host.unlock();
            }
            Set<String> requested = new HashSet<>();
            Carried carried = new Carried();
            long left = CATCHUP_BUDGET;
            boolean again = false;
            for (int round = 0; round < MAX_ROUNDS; round++) {
                if (stopping() || left == 0) {
                    break;
                }
                // The first round fetches even with nothing wanted: a fetch also returns the pending leave
                // requests (SPEC 9.1).
                boolean fetching = round == 0 || !want.isEmpty();
                if (!fetching && !again) {
                    break;
                }
                Items items;
                if (fetching) {
                    for (byte[] id : want) {
                        requested.add(k(id));
                    }
                    Map<String, Object> body = new LinkedHashMap<>();
                    body.put("repoId", repoId);
                    body.put("ids", Server.idsJson(want));
                    want = new ArrayList<>();
                    Map<String, Object> answer = postJson(hostPath(repoId, "fetch"), body);
                    if (answer == null) {
                        break;
                    }
                    try {
                        items = itemsFromJson(answer);
                    } catch (AvpException | RuntimeException e) {
                        break;
                    }
                    if (!items.bounded()) {
                        break;
                    }
                } else {
                    items = Items.empty();
                }
                // Carried and fetched together stay within one batch.
                carried.trim(Math.max(
                        0,
                        MAX_ITEMS - (items.manifests().size() + items.commits().size())));
                boolean held;
                host.lock();
                try {
                    // A sweep of a peer in step brings only known leave requests: nothing to apply.
                    AvpRules.RepoView v = host.repos.get(repoId);
                    boolean nothingNew = items.manifests().isEmpty()
                            && items.commits().isEmpty()
                            && carried.isEmpty()
                            && v != null
                            && items.leaves().stream().allMatch(l -> containsLeave(v.leaves(), l));
                    if (nothingNew) {
                        return;
                    }
                    held = v != null;
                } finally {
                    host.unlock();
                }
                Applied applied;
                if (held) {
                    // Another path may have stored the repository meanwhile: it is held now.
                    firstCopy = null;
                    host.lock();
                    try {
                        AvpRules.RepoView v = host.repos.get(repoId);
                        if (v == null) {
                            return;
                        }
                        Items batch = carried.batch(v, items);
                        applied = receive(host, repoId, peer.key(), batch, left).applied();
                        AvpRules.RepoView after = host.repos.get(repoId);
                        if (after == null) {
                            return;
                        }
                        carried.after(after, applied, round);
                        want = carried.want(after, requested);
                    } finally {
                        host.unlock();
                    }
                } else {
                    AvpRules.RepoView base =
                            firstCopy != null ? firstCopy : new AvpRules.RepoView(host.hostKey, host.limits.headBound);
                    Items batch = carried.batch(base, items);
                    Kept kept = applyKept(base, repoId, batch, false, left);
                    applied = kept.applied();
                    host.lock();
                    try {
                        host.engineApplications += applied.applications;
                    } finally {
                        host.unlock();
                    }
                    carried.after(kept.view(), applied, round);
                    want = carried.want(kept.view(), requested);
                    firstCopy = kept.view();
                }
                left = Math.max(0, left - applied.applications);
                again = applied.exhausted;
            }
            // A first copy is decided once, on the validated received tip, and only without a gap.
            if (firstCopy != null && carried.states.isEmpty()) {
                host.lock();
                try {
                    if (!host.repos.containsKey(repoId)) {
                        admitFirstCopy(host, repoId, peer.key(), firstCopy);
                    }
                } finally {
                    host.unlock();
                }
            }
        }
    }

    private static boolean sameLeave(AvpTokens.LeaveRequest a, AvpTokens.LeaveRequest b) {
        return a.repoId().equals(b.repoId())
                && Arrays.equals(a.memberKey(), b.memberKey())
                && a.at() == b.at()
                && Arrays.equals(a.signature(), b.signature());
    }

    private static boolean containsLeave(List<AvpTokens.LeaveRequest> list, AvpTokens.LeaveRequest l) {
        return list.stream().anyMatch(x -> sameLeave(x, l));
    }

    /** The path of a host route for {@code repoId}, percent-encoding anything outside the unreserved set. */
    static String hostPath(String repoId, String op) {
        StringBuilder seg = new StringBuilder();
        for (byte b : repoId.getBytes(java.nio.charset.StandardCharsets.UTF_8)) {
            int c = b & 0xff;
            boolean unreserved = (c >= 'A' && c <= 'Z')
                    || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9')
                    || c == '-'
                    || c == '_'
                    || c == '.'
                    || c == '~';
            if (unreserved) {
                seg.append((char) c);
            } else {
                seg.append(String.format("%%%02X", c));
            }
        }
        return "/v1/host/repos/" + seg + "/" + op;
    }

    // ─── What a catch-up carries between rounds ─────────────────────────────────────────

    /** One carried item: the ids it waits on and the round it was first carried in. */
    private static final class Carry<T> {
        final T item;
        final String id;
        final List<String> deps;
        final int since;

        Carry(T item, String id, List<String> deps, int since) {
            this.item = item;
            this.id = id;
            this.deps = deps;
            this.since = since;
        }
    }

    /** What a catch-up carries from one round to the next. */
    private static final class Carried {
        List<Carry<AvpManifest.SignedManifest>> states = new ArrayList<>();
        List<Carry<AvpCommit.Commit>> commits = new ArrayList<>();
        /** The first round of each carried item put back into this round's batch. */
        Map<String, Integer> taken = new HashMap<>();

        boolean isEmpty() {
            return states.isEmpty() && commits.isEmpty();
        }

        private Set<String> ids() {
            Set<String> out = new HashSet<>();
            for (Carry<?> c : states) {
                out.add(c.id);
            }
            for (Carry<?> c : commits) {
                out.add(c.id);
            }
            return out;
        }

        /** Keeps at most {@code room} carried items, dropping those carried longest first. */
        void trim(int room) {
            int total = states.size() + commits.size();
            if (total <= room) {
                return;
            }
            List<Integer> ages = new ArrayList<>();
            for (Carry<?> c : states) {
                ages.add(c.since);
            }
            for (Carry<?> c : commits) {
                ages.add(c.since);
            }
            ages.sort(null);
            int excess = total - room;
            int cut = ages.get(Math.max(0, excess - 1));
            int[] dropAtCut = {0};
            for (int i = 0; i < excess; i++) {
                if (ages.get(i) == cut) {
                    dropAtCut[0]++;
                }
            }
            java.util.function.IntPredicate keep = since -> {
                if (since < cut) {
                    return false;
                }
                if (since == cut && dropAtCut[0] > 0) {
                    dropAtCut[0]--;
                    return false;
                }
                return true;
            };
            states.removeIf(c -> !keep.test(c.since));
            commits.removeIf(c -> !keep.test(c.since));
        }

        /**
         * The batch of a round: the fetched items, and the carried items whose wait is over (an id they wait
         * on arrived in this round or is now known in {@code view}, or belongs to another carried item tried
         * again). The others stay carried without being tried.
         */
        Items batch(AvpRules.RepoView view, Items items) {
            Set<String> carriedIds = ids();
            Set<String> arrived = new HashSet<>();
            for (AvpManifest.SignedManifest m : items.manifests()) {
                byte[] h = hashOf(m);
                if (h != null && !carriedIds.contains(k(h))) {
                    arrived.add(k(h));
                }
            }
            for (AvpCommit.Commit c : items.commits()) {
                if (!carriedIds.contains(k(c.commitId()))) {
                    arrived.add(k(c.commitId()));
                }
            }
            // Which carried items wait on each id: {isState ? 1 : 0, index}.
            Map<String, List<int[]>> waitingOn = new HashMap<>();
            for (int i = 0; i < states.size(); i++) {
                for (String d : states.get(i).deps) {
                    waitingOn.computeIfAbsent(d, x -> new ArrayList<>()).add(new int[] {1, i});
                }
            }
            for (int i = 0; i < commits.size(); i++) {
                for (String d : commits.get(i).deps) {
                    waitingOn.computeIfAbsent(d, x -> new ArrayList<>()).add(new int[] {0, i});
                }
            }
            boolean[] takeState = new boolean[states.size()];
            boolean[] takeCommit = new boolean[commits.size()];
            ArrayDeque<String> queue = new ArrayDeque<>();
            for (String d : waitingOn.keySet()) {
                if (arrived.contains(d) || known(view, d)) {
                    queue.add(d);
                }
            }
            while (!queue.isEmpty()) {
                String d = queue.poll();
                List<int[]> ws = waitingOn.remove(d);
                if (ws == null) {
                    continue;
                }
                for (int[] w : ws) {
                    boolean isState = w[0] == 1;
                    boolean[] flags = isState ? takeState : takeCommit;
                    String id = isState ? states.get(w[1]).id : commits.get(w[1]).id;
                    if (!flags[w[1]]) {
                        flags[w[1]] = true;
                        if (arrived.add(id)) {
                            queue.add(id);
                        }
                    }
                }
            }
            List<AvpManifest.SignedManifest> ms = new ArrayList<>(items.manifests());
            List<AvpCommit.Commit> cs = new ArrayList<>(items.commits());
            List<Carry<AvpManifest.SignedManifest>> keptStates = new ArrayList<>();
            for (int i = 0; i < states.size(); i++) {
                Carry<AvpManifest.SignedManifest> c = states.get(i);
                if (takeState[i]) {
                    ms.add(c.item);
                    taken.put(c.id, c.since);
                } else {
                    keptStates.add(c);
                }
            }
            List<Carry<AvpCommit.Commit>> keptCommits = new ArrayList<>();
            for (int i = 0; i < commits.size(); i++) {
                Carry<AvpCommit.Commit> c = commits.get(i);
                if (takeCommit[i]) {
                    cs.add(c.item);
                    taken.put(c.id, c.since);
                } else {
                    keptCommits.add(c);
                }
            }
            states = keptStates;
            commits = keptCommits;
            return new Items(ms, cs, items.leaves());
        }

        /**
         * Adds what a round left to the carried items, with the ids each waits on in {@code view}; an item
         * carried before keeps its first round. An item that waits on nothing it can name is dropped.
         */
        void after(AvpRules.RepoView view, Applied applied, int round) {
            Set<String> present = ids();
            Map<String, Integer> since = taken;
            taken = new HashMap<>();
            for (AvpManifest.SignedManifest m : applied.deferred) {
                byte[] hash = hashOf(m);
                if (hash == null || present.contains(k(hash))) {
                    continue;
                }
                byte[] prev = prevHash(m);
                List<String> deps;
                if (prev != null
                        && m.state().manifestSeq() > 1
                        && view.manifest(prev).isEmpty()) {
                    deps = List.of(k(prev));
                } else {
                    TreeSet<String> d = new TreeSet<>();
                    for (AvpCommit.Commit c : applied.waiting) {
                        if (isRotationFor(c, m, hash)) {
                            for (byte[] id : view.missingFor(c)) {
                                if (!Arrays.equals(id, hash)) {
                                    d.add(k(id));
                                }
                            }
                        }
                    }
                    deps = new ArrayList<>(d);
                }
                states.add(new Carry<>(m, k(hash), deps, since.getOrDefault(k(hash), round)));
            }
            for (AvpCommit.Commit c : applied.waiting) {
                String id = k(c.commitId());
                if (present.contains(id)) {
                    continue;
                }
                List<String> deps = new ArrayList<>();
                for (byte[] d : view.missingFor(c)) {
                    deps.add(k(d));
                }
                commits.add(new Carry<>(c, id, deps, since.getOrDefault(id, round)));
            }
            states.removeIf(c -> c.deps.isEmpty());
            commits.removeIf(c -> c.deps.isEmpty());
        }

        /**
         * The ids the next round fetches: what the carried items wait on, without what is carried or known
         * already, ids already requested, or more than {@link #MAX_REQUESTED} in all.
         */
        List<byte[]> want(AvpRules.RepoView view, Set<String> requested) {
            Set<String> carriedIds = ids();
            List<byte[]> next = new ArrayList<>();
            Set<String> seen = new HashSet<>();
            List<String> deps = new ArrayList<>();
            for (Carry<?> c : states) {
                deps.addAll(c.deps);
            }
            for (Carry<?> c : commits) {
                deps.addAll(c.deps);
            }
            for (String d : deps) {
                if (requested.size() + next.size() >= MAX_REQUESTED) {
                    break;
                }
                if (carriedIds.contains(d) || requested.contains(d) || known(view, d)) {
                    continue;
                }
                if (seen.add(d)) {
                    next.add(unk(d));
                }
            }
            return next;
        }

        private static boolean known(AvpRules.RepoView view, String id) {
            byte[] b = unk(id);
            return view.manifest(b).isPresent() || view.status(b).isPresent();
        }
    }
}
