/*
 * Host acceptance rules (SPEC 6, 7, 8.3, 8.4): one host's view of one repository.
 *
 * SPDX-License-Identifier: MIT
 */

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The host rules engine (SPEC 6, 7, 8.3, 8.4) and its verdicts.
 *
 * <p>{@link RepoView} models the decisions, not the transport. It mirrors the TypeScript reference
 * engine ({@code examples/conformance/src/rules.ts}) and the Rust one ({@code
 * examples/rust/avp/src/rules.rs}) and is checked against {@code vectors/acceptance.json}. A verdict
 * is an {@code Optional<String>}: empty means accepted, otherwise it holds the SPEC 10.4 code ({@link
 * #BAD_REQUEST}, {@link #FORBIDDEN}, {@link #NOT_HOSTED}, {@link #TOO_MANY_HEADS}, {@link
 * #MANIFEST_CONFLICT}, or {@link #MISSING_PARENTS}). {@code duplicate_repo} and {@code not_found} are
 * host-level answers given before the engine runs, so the engine never returns them.
 */
public final class AvpRules {

    /** {@code 400 bad_request}: malformed, a bad signature, an id that does not recompute. */
    public static final String BAD_REQUEST = "bad_request";

    /** {@code 403 forbidden}: not a member, after the removal cutoff, an epoch mismatch, a held commit. */
    public static final String FORBIDDEN = "forbidden";

    /** {@code 403 not_hosted}: this host is not in the manifest's {@code hosts}. */
    public static final String NOT_HOSTED = "not_hosted";

    /** {@code 409 too_many_heads}: the push would leave more heads than the bound. */
    public static final String TOO_MANY_HEADS = "too_many_heads";

    /** {@code 409 manifest_conflict}: not tip + 1, a previous hash mismatch, or a losing state. */
    public static final String MANIFEST_CONFLICT = "manifest_conflict";

    /** {@code 422 missing_parents}: a parent, a cited manifest state, or a frontier commit is unknown. */
    public static final String MISSING_PARENTS = "missing_parents";

    private static final Optional<String> OK = Optional.empty();

    private AvpRules() {}

    /** The path an item arrived on. */
    public enum Via {
        /**
         * A client write ({@code push}, {@code createRepo}, {@code publishManifest}, {@code leave}).
         * The host has already authenticated the caller and passes the item only when the caller is
         * the commit's author (the owner for a manifest and the commit carried with it, {@code
         * memberKey} for a leave). The engine then checks that the author is a member of the tip
         * (SPEC 7.1) and applies the head bound (SPEC 7.4); a manifest must be at tip + 1 (SPEC 6.3)
         * and list this host (SPEC 6.1 rule 6).
         */
        PUSH,
        /**
         * An item of a peer host's replication {@code offer} (SPEC 9.1): no caller check and no head
         * bound, and diverged states meet the tie rule (SPEC 6.5). A state is not rejected for not
         * listing this host: rule 6 applies to the tip of the chain being received, which the host
         * checks before it applies the offer (SPEC 6.1, 9.2).
         */
        OFFER
    }

    /** The status of a stored commit. */
    public enum CommitStatus {
        /** Accepted: a head unless an accepted commit names it as a parent. */
        ACCEPTED,
        /** Held until an owner device decides (SPEC 6.5): not a head, not served, not offered. */
        HELD,
        /**
         * Stored but undecided: its removal cutoff waits on a frontier commit header it lacks (SPEC
         * 7.3). Neither a head nor held.
         */
        PENDING,
        /** Rejected or dropped (SPEC 6.5, 7.3, 7.4). */
        REJECTED
    }

    /** The classification of one commit by the membership, cutoff, and parent rules. */
    private enum Classification {
        ACCEPTED,
        HELD,
        REJECTED,
        MISSING,
        TOO_MANY
    }

    /** The SPEC 6.5 verdict for a commit citing a verified losing state. */
    private enum Losing {
        ACCEPTED,
        HELD,
        REJECTED,
        UNDECIDED
    }

    /** The SPEC 7.3 removal cutoff outcome. */
    private enum Cut {
        OK,
        FAIL,
        UNDECIDED
    }

    /** A verified state with its hash, the hash's map key, and its seq. */
    private record StateRec(AvpManifest.SignedManifest m, byte[] hash, String key, long seq) {
        AvpManifest.ManifestState state() {
            return m.state();
        }
    }

    /** One stored commit as seen at the start of a re-check pass. */
    private record Snap(String id, CommitStatus status, AvpCommit.Commit c) {}

    /** The outcome of a cutoff walk: whether the commit is covered, and the unknown headers met. */
    private record Walk(boolean covered, List<String> unknown) {}

    /** Everything a view holds; copied to make an operation atomic. Every value held is immutable. */
    private static final class Store {
        /** The winning chain; {@code chain.get(i)} has {@code manifestSeq} {@code i + 1}. */
        final List<StateRec> chain;
        /** Every verified state, winning or losing, by manifest hash. */
        final Map<String, StateRec> states;
        /** Manifest hash of each epoch-raising state to its rotation commit id. */
        final Map<String, String> rotation;
        /** Commit ids in the order they were first stored. */
        final List<String> order;
        /** Every stored commit. */
        final Map<String, AvpCommit.Commit> commits;
        /** The status of every stored commit. */
        final Map<String, CommitStatus> status;
        /** The parents of every commit whose id recomputes and whose signature verifies (SPEC 7.3). */
        final Map<String, List<String>> headers;
        /** The latest leave request per member, sorted by member key. */
        final List<AvpTokens.LeaveRequest> leaves;

        Store() {
            this(
                    new ArrayList<>(),
                    new HashMap<>(),
                    new HashMap<>(),
                    new ArrayList<>(),
                    new HashMap<>(),
                    new HashMap<>(),
                    new HashMap<>(),
                    new ArrayList<>());
        }

        private Store(
                List<StateRec> chain,
                Map<String, StateRec> states,
                Map<String, String> rotation,
                List<String> order,
                Map<String, AvpCommit.Commit> commits,
                Map<String, CommitStatus> status,
                Map<String, List<String>> headers,
                List<AvpTokens.LeaveRequest> leaves) {
            this.chain = chain;
            this.states = states;
            this.rotation = rotation;
            this.order = order;
            this.commits = commits;
            this.status = status;
            this.headers = headers;
            this.leaves = leaves;
        }

        Store copy() {
            return new Store(
                    new ArrayList<>(chain),
                    new HashMap<>(states),
                    new HashMap<>(rotation),
                    new ArrayList<>(order),
                    new HashMap<>(commits),
                    new HashMap<>(status),
                    new HashMap<>(headers),
                    new ArrayList<>(leaves));
        }
    }

    // ─── Shape and content rules ──────────────────────────────────────────────────────

    private static String key(byte[] b) {
        return AvpEncoding.base64(b);
    }

    private static Optional<String> fail(String code) {
        return Optional.of(code);
    }

    /** True when no two byte strings are equal. */
    private static boolean distinct(List<byte[]> ids) {
        Set<String> seen = new HashSet<>();
        for (byte[] id : ids) {
            if (!seen.add(key(id))) {
                return false;
            }
        }
        return true;
    }

    private static boolean len(byte[] b, int n) {
        return b.length == n;
    }

    /**
     * SPEC 6.1 rule 1: every binary field has its length, the counters are in range, and no list
     * repeats a key. The decoders already check the fixed lengths; the engine checks them again so a
     * state built in code gets the same verdict.
     */
    private static boolean manifestShapeOk(AvpManifest.SignedManifest m) {
        AvpManifest.ManifestState s = m.state();
        if (s.manifestSeq() < 1 || s.keyEpoch() < 0 || !len(s.ownerKey(), 32) || !len(m.ownerSignature(), 64)) {
            return false;
        }
        boolean genesis = s.manifestSeq() == 1;
        if (!len(s.prevManifestHash(), genesis ? 0 : 32) || !len(s.genesisNonce(), genesis ? 16 : 0)) {
            return false;
        }
        List<byte[]> hosts = new ArrayList<>();
        for (AvpManifest.HostRef h : s.hosts()) {
            if (!len(h.hostKey(), 32)) {
                return false;
            }
            hosts.add(h.hostKey());
        }
        List<byte[]> members = new ArrayList<>();
        for (AvpManifest.MemberEntry x : s.members()) {
            AvpManifest.WrappedKey wk = x.wrappedDataKey();
            boolean ok = x.keyEpoch() >= 0
                    && len(x.ed25519PublicKey(), 32)
                    && len(x.x25519PublicKey(), 32)
                    && len(x.homeHostKey(), 32)
                    && len(wk.ephemeralPublicKey(), 32)
                    && len(wk.iv(), 12)
                    && len(wk.ciphertext(), 48);
            if (!ok) {
                return false;
            }
            members.add(x.ed25519PublicKey());
        }
        List<byte[]> removed = new ArrayList<>();
        for (AvpManifest.Removal r : s.removals()) {
            if (r.removedAtSeq() < 0 || !len(r.memberKey(), 32) || !distinct(r.frontier())) {
                return false;
            }
            for (byte[] id : r.frontier()) {
                if (!len(id, 32)) {
                    return false;
                }
            }
            removed.add(r.memberKey());
        }
        return distinct(hosts) && distinct(members) && distinct(removed);
    }

    /**
     * SPEC 7.1: the binary fields have their lengths, the counters are in range, the ciphertext holds
     * at least the GCM tag, and no parent appears twice.
     */
    private static boolean commitShapeOk(AvpCommit.Commit c) {
        if (!len(c.commitId(), 32)
                || !len(c.manifestHash(), 32)
                || !len(c.author(), 32)
                || !len(c.iv(), 12)
                || !len(c.authorSignature(), 64)) {
            return false;
        }
        for (byte[] p : c.parents()) {
            if (!len(p, 32)) {
                return false;
            }
        }
        return c.ciphertext().length >= 16 && c.manifestSeq() >= 1 && c.keyEpoch() >= 0 && distinct(c.parents());
    }

    /** SPEC 6.2: the genesis state. */
    private static boolean genesisOk(AvpManifest.ManifestState s) {
        if (s.prevManifestHash().length != 0
                || s.keyEpoch() != 0
                || !s.removals().isEmpty()) {
            return false;
        }
        if (s.genesisNonce().length != 16 || s.members().size() != 1) {
            return false;
        }
        if (!Arrays.equals(s.members().get(0).ed25519PublicKey(), s.ownerKey())) {
            return false;
        }
        try {
            return AvpManifest.deriveRepoId(s.ownerKey(), s.genesisNonce()).equals(s.repoId());
        } catch (AvpException e) {
            return false;
        }
    }

    private static boolean sameFrontier(List<byte[]> a, List<byte[]> b) {
        List<String> x = new ArrayList<>();
        for (byte[] id : a) {
            x.add(key(id));
        }
        List<String> y = new ArrayList<>();
        for (byte[] id : b) {
            y.add(key(id));
        }
        x.sort(null);
        y.sort(null);
        return x.equals(y);
    }

    /** Whether {@code epoch} is {@code prev + 1}, without overflow. */
    private static boolean isNext(long prev, long epoch) {
        return prev != Long.MAX_VALUE && prev + 1 == epoch;
    }

    /** SPEC 6.1 rule 5: the content rules, against the previous state when {@code prev} is given. */
    private static boolean contentOk(AvpManifest.ManifestState s, AvpManifest.ManifestState prev) {
        if (s.hosts().isEmpty()) {
            return false;
        }
        long owners = s.members().stream()
                .filter(x -> Arrays.equals(x.ed25519PublicKey(), s.ownerKey()))
                .count();
        if (owners != 1) {
            return false;
        }
        for (AvpManifest.MemberEntry x : s.members()) {
            if (x.keyEpoch() != s.keyEpoch() || !s.hasHost(x.homeHostKey())) {
                return false;
            }
            if (s.removalOf(x.ed25519PublicKey()).isPresent()) {
                return false;
            }
        }
        for (AvpManifest.Removal r : s.removals()) {
            if (r.removedAtSeq() < 2 || r.removedAtSeq() > s.manifestSeq()) {
                return false;
            }
        }
        if (prev == null) {
            return true;
        }

        if (!s.repoId().equals(prev.repoId())
                || !Arrays.equals(s.ownerKey(), prev.ownerKey())
                || !s.schemeId().equals(prev.schemeId())
                || s.genesisNonce().length != 0) {
            return false;
        }
        if (s.keyEpoch() != prev.keyEpoch() && !isNext(prev.keyEpoch(), s.keyEpoch())) {
            return false;
        }
        for (AvpManifest.Removal r : prev.removals()) {
            Optional<AvpManifest.Removal> same = s.removalOf(r.memberKey());
            if (same.isEmpty()
                    || same.get().removedAtSeq() != r.removedAtSeq()
                    || !sameFrontier(same.get().frontier(), r.frontier())) {
                return false;
            }
        }
        Set<String> added = new HashSet<>();
        for (AvpManifest.Removal r : s.removals()) {
            if (prev.removalOf(r.memberKey()).isEmpty()) {
                if (r.removedAtSeq() != s.manifestSeq() || !prev.hasMember(r.memberKey())) {
                    return false;
                }
                added.add(key(r.memberKey()));
            }
        }
        for (AvpManifest.MemberEntry x : prev.members()) {
            if (s.hasMember(x.ed25519PublicKey())) {
                continue;
            }
            if (Arrays.equals(x.ed25519PublicKey(), s.ownerKey()) || !added.contains(key(x.ed25519PublicKey()))) {
                return false;
            }
        }
        return added.isEmpty() || isNext(prev.keyEpoch(), s.keyEpoch());
    }

    // ─── The view ─────────────────────────────────────────────────────────────────────

    /**
     * One host's view of one repository.
     *
     * <p>Construct it with the host's own Ed25519 key, apply items in arrival order, and read {@link
     * #heads()}, {@link #held()}, and {@link #tip()}. Every {@code apply} method is atomic: an item
     * that is rejected changes nothing, except that a state that loses the tie rule but verifies is
     * retained as a verified losing state (SPEC 6.5), a rejected or held commit keeps its status, and
     * the verified header of a commit applied alone stays known for ancestry (SPEC 7.3) when a rule
     * after the caller check refuses it. A commit whose caller is refused, and a state refused
     * together with its commit, leave no header behind. Every input is
     * attacker-controlled: no {@code apply} method throws; every failure is a verdict code. The view
     * stores its own copies of the records it is given and returns copies from its readers, so no
     * caller can change its state through a record's arrays. A view is not thread safe; a host
     * serializes access to it.
     *
     * <p>Host implementers: on the {@link Via#OFFER} path this engine applies no per-state hosted
     * check, so it will adopt a whole repository whose states never list this host. The host MUST
     * therefore apply an offer (with its catch-up) to a trial copy of the view ({@link #copy()}) and
     * check the validated resulting tip with {@link #tipListsHost()} (the received tip of SPEC 9.2).
     * If the host did not hold the repository and that tip does not list it, it MUST discard the
     * trial copy and answer {@code 403 not_hosted} (a first copy is all or nothing). If it held the
     * repository, it MUST keep the trial copy and answer {@code 403 not_hosted} when that tip does
     * not list it (SPEC 8.6). A client publish this engine answers {@link #NOT_HOSTED} passed every
     * other rule; when the host already holds the repository it MUST keep the state by applying it
     * again with {@link Via#OFFER} together with its rotation commit only (with no commit when the
     * epoch is unchanged), never with a carried non-rotation commit, because the offer path skips the
     * client caller check and the head bound. A {@code createRepo} genesis answered {@code
     * not_hosted} stores nothing. Serving and client writes are gated on {@link #tipListsHost()}
     * (SPEC 8.6, 10.1); there is no separate not-hosted marker. The host answers {@code 409
     * duplicate_repo} for a {@code createRepo} of a repository it holds and {@code 404 not_found} for
     * any operation on one it does not hold before it consults the engine, and it fetches what {@link
     * #missingFor(AvpCommit.Commit)} names after a {@link #MISSING_PARENTS} verdict.
     */
    public static final class RepoView {
        private final byte[] hostKey;
        private final int headBound;
        private Store st;

        /**
         * A view for the host whose Ed25519 host key is {@code hostKey}, with the head bound for
         * client writes (SPEC 7.4, RECOMMENDED 16).
         *
         * @param hostKey this host's 32-byte key
         * @param headBound the most heads a client write may leave
         */
        public RepoView(byte[] hostKey, int headBound) {
            this(hostKey.clone(), headBound, new Store());
        }

        private RepoView(byte[] hostKey, int headBound, Store st) {
            this.hostKey = hostKey;
            this.headBound = headBound;
            this.st = st;
        }

        /**
         * An independent copy of this view, for applying an offer to a trial copy (SPEC 9.2).
         *
         * @return the copy
         */
        public RepoView copy() {
            return new RepoView(hostKey, headBound, st.copy());
        }

        // ─── Defensive copies: the store holds records that no caller can reach ───────

        private static AvpCommit.Commit copyOf(AvpCommit.Commit c) {
            // The record constructor clones every array and id list.
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
                    c.authorSignature());
        }

        private static AvpTokens.LeaveRequest copyOf(AvpTokens.LeaveRequest l) {
            return new AvpTokens.LeaveRequest(l.repoId(), l.memberKey(), l.at(), l.signature());
        }

        private static AvpManifest.SignedManifest copyOf(AvpManifest.SignedManifest m) {
            AvpManifest.ManifestState s = m.state();
            List<AvpManifest.HostRef> hosts = new ArrayList<>();
            for (AvpManifest.HostRef h : s.hosts()) {
                hosts.add(new AvpManifest.HostRef(h.hostKey(), h.locator()));
            }
            List<AvpManifest.MemberEntry> members = new ArrayList<>();
            for (AvpManifest.MemberEntry x : s.members()) {
                AvpManifest.WrappedKey wk = x.wrappedDataKey();
                members.add(new AvpManifest.MemberEntry(
                        x.ed25519PublicKey(),
                        x.x25519PublicKey(),
                        new AvpManifest.WrappedKey(wk.schemeId(), wk.ephemeralPublicKey(), wk.iv(), wk.ciphertext()),
                        x.keyEpoch(),
                        x.homeHostKey()));
            }
            List<AvpManifest.Removal> removals = new ArrayList<>();
            for (AvpManifest.Removal r : s.removals()) {
                removals.add(new AvpManifest.Removal(r.memberKey(), r.removedAtSeq(), r.frontier()));
            }
            AvpManifest.ManifestState state = new AvpManifest.ManifestState(
                    s.repoId(),
                    s.manifestSeq(),
                    s.prevManifestHash(),
                    s.ownerKey(),
                    s.genesisNonce(),
                    s.schemeId(),
                    s.keyEpoch(),
                    s.shareRefreshTokens(),
                    hosts,
                    members,
                    removals);
            return new AvpManifest.SignedManifest(state, m.ownerSignature());
        }

        // ─── Applying items ───────────────────────────────────────────────────────────

        /**
         * Applies a client publish of a manifest state with no commit: {@link
         * #applyManifest(AvpManifest.SignedManifest, Optional, Via)} with no commit and {@link
         * Via#PUSH}.
         *
         * @param m the signed manifest
         * @return empty if accepted, otherwise the SPEC 6 code of the first rule that fails
         */
        public Optional<String> applyManifest(AvpManifest.SignedManifest m) {
            return applyManifest(m, Optional.empty(), Via.PUSH);
        }

        /**
         * Applies a signed manifest state (SPEC 6) together with the commit published with it: the
         * first commit at genesis ({@code createRepo}, SPEC 8.2), the rotation commit of an
         * epoch-raising state (SPEC 8.3), or an optional commit that cites any other state. The state
         * and its commit are applied together or not at all, and the rotation commit of each adopted
         * epoch-raising state is recorded ({@link #rotationCommit(byte[])}).
         *
         * @param m the signed manifest
         * @param commit the commit published with it, if any
         * @param via the path it arrived on
         * @return empty if accepted, otherwise the code of the first rule that fails: SPEC 6.1 in
         *     order for the state, then SPEC 7 for the commit
         */
        public Optional<String> applyManifest(
                AvpManifest.SignedManifest m, Optional<AvpCommit.Commit> commit, Via via) {
            Store snap = st.copy();
            try {
                return state(copyOf(m), commit.map(RepoView::copyOf), via);
            } catch (AvpException | RuntimeException e) {
                // A state or commit that cannot be encoded is malformed; nothing of it is kept.
                restore(snap);
                return fail(BAD_REQUEST);
            }
        }

        /**
         * Applies a client push of one commit: {@link #applyCommit(AvpCommit.Commit, Via)} with
         * {@link Via#PUSH}.
         *
         * @param c the commit
         * @return empty if accepted, otherwise the SPEC 7 code of the first rule that fails
         */
        public Optional<String> applyCommit(AvpCommit.Commit c) {
            return applyCommit(c, Via.PUSH);
        }

        /**
         * Applies one commit (SPEC 7): a client push, or a commit of a peer's offer. A commit the view
         * already accepted is accepted again with no change.
         *
         * @param c the commit
         * @param via the path it arrived on
         * @return empty if accepted, otherwise the SPEC 7 code of the first rule that fails: {@link
         *     #FORBIDDEN} for a held commit, and {@link #MISSING_PARENTS} when a parent, the cited
         *     state, or a frontier header is unknown (see {@link #missingFor(AvpCommit.Commit)})
         */
        public Optional<String> applyCommit(AvpCommit.Commit c, Via via) {
            Store snap = st.copy();
            try {
                return oneCommit(copyOf(c), via, false);
            } catch (RuntimeException e) {
                // Not reachable by design (every rule is total); kept so that no unchecked exception
                // escapes on attacker input. The operation is undone and the item refused.
                restore(snap);
                return fail(BAD_REQUEST);
            }
        }

        /**
         * Applies a client's leave request: {@link #applyLeave(AvpTokens.LeaveRequest, Via)} with
         * {@link Via#PUSH}.
         *
         * @param l the leave request
         * @return empty if accepted, otherwise the SPEC 8.4 code
         */
        public Optional<String> applyLeave(AvpTokens.LeaveRequest l) {
            return applyLeave(l, Via.PUSH);
        }

        /**
         * Applies a signed leave request (SPEC 8.4) and keeps the latest one per member. Replication
         * skips only the caller check, which the host makes before a push reaches the engine, so both
         * paths apply the same rules. A state that removes the member drops its request.
         *
         * @param l the leave request
         * @param via the path it arrived on
         * @return empty if accepted; {@link #BAD_REQUEST} if the signature does not verify or the
         *     repoId does not match; {@link #FORBIDDEN} if the member is not a member of the tip or is
         *     the owner
         */
        public Optional<String> applyLeave(AvpTokens.LeaveRequest l, Via via) {
            Store snap = st.copy();
            try {
                return oneLeave(copyOf(l));
            } catch (RuntimeException e) {
                // Not reachable by design (every rule is total); kept so that no unchecked exception
                // escapes on attacker input. The operation is undone and the item refused.
                st = snap;
                return fail(BAD_REQUEST);
            }
        }

        private Optional<String> oneLeave(AvpTokens.LeaveRequest l) {
            if (!AvpTokens.verifyLeave(l)) {
                return fail(BAD_REQUEST);
            }
            StateRec tip = tipRec();
            if (tip == null || !l.repoId().equals(tip.state().repoId())) {
                return fail(BAD_REQUEST);
            }
            AvpManifest.ManifestState s = tip.state();
            if (!s.hasMember(l.memberKey()) || Arrays.equals(l.memberKey(), s.ownerKey())) {
                return fail(FORBIDDEN);
            }
            for (int k = 0; k <= st.leaves.size(); k++) {
                int cmp = k == st.leaves.size()
                        ? 1
                        : AvpEncoding.compare(st.leaves.get(k).memberKey(), l.memberKey());
                if (cmp == 0) {
                    if (l.at() > st.leaves.get(k).at()) {
                        st.leaves.set(k, l);
                    }
                    return OK;
                }
                if (cmp > 0) {
                    st.leaves.add(k, l);
                    return OK;
                }
            }
            return OK;
        }

        // ─── Reading the view ─────────────────────────────────────────────────────────

        /**
         * The accepted commits with no accepted child.
         *
         * @return the head ids, sorted as unsigned bytes
         */
        public List<byte[]> heads() {
            return sortedIds(headIds());
        }

        /**
         * The held commits (SPEC 6.5).
         *
         * @return the held ids, sorted as unsigned bytes
         */
        public List<byte[]> held() {
            return withStatus(CommitStatus.HELD);
        }

        /**
         * The stored commits whose removal cutoff cannot be decided yet (SPEC 7.3).
         *
         * @return the pending ids, sorted as unsigned bytes
         */
        public List<byte[]> pending() {
            return withStatus(CommitStatus.PENDING);
        }

        /**
         * The tip of the winning chain.
         *
         * @return the tip, or empty before genesis
         */
        public Optional<AvpManifest.SignedManifest> tip() {
            StateRec t = tipRec();
            return t == null ? Optional.empty() : Optional.of(copyOf(t.m()));
        }

        /**
         * Whether the tip of the winning chain lists this host. A host does not serve a repository
         * whose tip does not list it (SPEC 8.6, 10.1). States before the tip may not list it when the
         * host got its first copy by replication (SPEC 6.1 rule 6, 9.2).
         *
         * @return whether the tip lists this host; {@code false} before genesis
         */
        public boolean tipListsHost() {
            StateRec t = tipRec();
            return t != null && t.state().hasHost(hostKey);
        }

        /**
         * The head commits whose ids are not in {@code known}: the {@code heads} of a pull (SPEC
         * 10.1).
         *
         * @param known the head ids the client already has
         * @return the commits, sorted by id
         */
        public List<AvpCommit.Commit> commitsSince(List<byte[]> known) {
            Set<String> skip = new HashSet<>();
            for (byte[] id : known) {
                skip.add(key(id));
            }
            List<AvpCommit.Commit> out = new ArrayList<>();
            for (byte[] id : heads()) {
                if (!skip.contains(key(id))) {
                    out.add(copyOf(st.commits.get(key(id))));
                }
            }
            return out;
        }

        /**
         * The winning chain's states with {@code manifestSeq} greater than {@code seq}, ascending: the
         * {@code manifests} of a pull (SPEC 10.1).
         *
         * @param seq the client's {@code sinceManifestSeq}
         * @return the states
         */
        public List<AvpManifest.SignedManifest> manifestsSince(long seq) {
            List<AvpManifest.SignedManifest> out = new ArrayList<>();
            for (StateRec r : st.chain) {
                if (r.seq() > seq) {
                    out.add(copyOf(r.m()));
                }
            }
            return out;
        }

        /**
         * The pending leave requests (SPEC 8.4), one per member.
         *
         * @return the requests, sorted by member key
         */
        public List<AvpTokens.LeaveRequest> leaves() {
            return st.leaves.stream().map(RepoView::copyOf).toList();
        }

        /**
         * The status of a stored commit.
         *
         * @param id the commit id
         * @return the status, or empty if the view does not store the commit
         */
        public Optional<CommitStatus> status(byte[] id) {
            return Optional.ofNullable(st.status.get(key(id)));
        }

        /**
         * A verified state, on the winning chain or a verified losing state (SPEC 6.5), by hash.
         *
         * @param hash the manifest hash
         * @return the state, or empty if the view holds no such verified state
         */
        public Optional<AvpManifest.SignedManifest> manifest(byte[] hash) {
            StateRec r = st.states.get(key(hash));
            return r == null ? Optional.empty() : Optional.of(copyOf(r.m()));
        }

        /**
         * Whether the state with this hash is on the winning chain.
         *
         * @param hash the manifest hash
         * @return whether it is a winning-chain state
         */
        public boolean isWinning(byte[] hash) {
            StateRec r = st.states.get(key(hash));
            return r != null && winning(r);
        }

        /**
         * The state with this hash and every state before it on its chain, ascending by {@code
         * manifestSeq}: the {@code manifests} of a replication {@code fetch} by manifest hash (SPEC
         * 9.1). Works for winning-chain states and verified losing states alike.
         *
         * @param hash the manifest hash
         * @return the chain, or empty if the view holds no such state
         */
        public Optional<List<AvpManifest.SignedManifest>> chainTo(byte[] hash) {
            List<AvpManifest.SignedManifest> out = new ArrayList<>();
            StateRec cur = st.states.get(key(hash));
            while (cur != null) {
                out.add(0, copyOf(cur.m()));
                if (cur.seq() <= 1) {
                    return Optional.of(out);
                }
                cur = st.states.get(key(cur.state().prevManifestHash()));
            }
            return Optional.empty();
        }

        /**
         * The rotation commit recorded with an epoch-raising state (SPEC 8.3), even while it is held.
         *
         * @param hash the manifest hash of the state
         * @return the rotation commit, or empty if none is recorded
         */
        public Optional<AvpCommit.Commit> rotationCommit(byte[] hash) {
            String id = st.rotation.get(key(hash));
            return id == null
                    ? Optional.empty()
                    : Optional.ofNullable(st.commits.get(id)).map(RepoView::copyOf);
        }

        /**
         * A commit a replication {@code fetch} serves by id (SPEC 9.1): an accepted commit, or a
         * rotation commit whatever its status. Other held, pending, and rejected commits are not
         * served.
         *
         * @param id the commit id
         * @return the commit, or empty if it is not served
         */
        public Optional<AvpCommit.Commit> fetchCommit(byte[] id) {
            String k = key(id);
            AvpCommit.Commit c = st.commits.get(k);
            if (c == null) {
                return Optional.empty();
            }
            boolean rotation = st.rotation.containsValue(k);
            return st.status.get(k) == CommitStatus.ACCEPTED || rotation ? Optional.of(copyOf(c)) : Optional.empty();
        }

        /**
         * The ids a {@code missing_parents} answer for {@code c} names (SPEC 7.2, 7.3, 7.4): the cited
         * manifest hash when the view holds no such state, each parent it does not hold, and each
         * frontier commit whose header it lacks for the removal cutoff of {@code c} or of a pending
         * parent. The host fetches these from its peers (SPEC 9.2).
         *
         * @param c the commit
         * @return the missing ids, without duplicates
         */
        public List<byte[]> missingFor(AvpCommit.Commit c) {
            List<String> out = new ArrayList<>();
            StateRec bound = st.states.get(key(c.manifestHash()));
            if (bound == null || bound.seq() != c.manifestSeq()) {
                addOnce(out, key(c.manifestHash()));
            }
            StateRec tip = tipRec();
            if (tip != null) {
                for (String id : cutoffWalk(c, tip).unknown()) {
                    addOnce(out, id);
                }
            }
            for (byte[] p : c.parents()) {
                String pk = key(p);
                AvpCommit.Commit pc = st.commits.get(pk);
                if (pc == null) {
                    addOnce(out, pk);
                } else if (st.status.get(pk) == CommitStatus.PENDING && tip != null) {
                    for (String id : cutoffWalk(pc, tip).unknown()) {
                        addOnce(out, id);
                    }
                }
            }
            List<byte[]> ids = new ArrayList<>();
            for (String id : out) {
                ids.add(fromKey(id));
            }
            return ids;
        }

        private static void addOnce(List<String> out, String id) {
            if (!out.contains(id)) {
                out.add(id);
            }
        }

        // ─── Store ────────────────────────────────────────────────────────────────────

        private static byte[] fromKey(String k) {
            return java.util.Base64.getDecoder().decode(k);
        }

        private static List<byte[]> sortedIds(List<String> keys) {
            List<byte[]> out = new ArrayList<>();
            for (String k : keys) {
                out.add(fromKey(k));
            }
            out.sort(AvpEncoding::compare);
            return out;
        }

        /**
         * Undoes a rejected operation completely, the headers it learned included: a rejected item
         * changes nothing, as on the offer path, where a rejected commit is not kept at all.
         */
        private void restore(Store snap) {
            st = snap;
        }

        private StateRec tipRec() {
            return st.chain.isEmpty() ? null : st.chain.get(st.chain.size() - 1);
        }

        private StateRec chainAt(long seq) {
            if (seq < 1 || seq - 1 >= st.chain.size()) {
                return null;
            }
            return st.chain.get((int) (seq - 1));
        }

        private boolean winning(StateRec r) {
            StateRec w = chainAt(r.seq());
            return w != null && w.key().equals(r.key());
        }

        private CommitStatus statusOf(String id) {
            return st.status.get(id);
        }

        private void setStatus(String id, CommitStatus status) {
            if (st.status.containsKey(id)) {
                st.status.put(id, status);
            }
        }

        private void insertCommit(AvpCommit.Commit c, CommitStatus status) {
            String id = key(c.commitId());
            if (st.commits.put(id, c) == null) {
                st.order.add(id);
            }
            st.status.put(id, status);
        }

        /** The stored commits in first-stored order with their status at this moment. */
        private List<Snap> snapshot() {
            List<Snap> out = new ArrayList<>(st.order.size());
            for (String id : st.order) {
                out.add(new Snap(id, st.status.get(id), st.commits.get(id)));
            }
            return out;
        }

        /** The status of each parent; {@code null} for a parent the view does not store. */
        private List<CommitStatus> parentStatuses(AvpCommit.Commit c) {
            List<CommitStatus> out = new ArrayList<>();
            for (byte[] p : c.parents()) {
                out.add(statusOf(key(p)));
            }
            return out;
        }

        private List<byte[]> withStatus(CommitStatus status) {
            List<String> out = new ArrayList<>();
            for (Map.Entry<String, CommitStatus> e : st.status.entrySet()) {
                if (e.getValue() == status) {
                    out.add(e.getKey());
                }
            }
            return sortedIds(out);
        }

        private List<String> headIds() {
            Set<String> parents = new HashSet<>();
            List<String> accepted = new ArrayList<>();
            for (Map.Entry<String, CommitStatus> e : st.status.entrySet()) {
                if (e.getValue() == CommitStatus.ACCEPTED) {
                    accepted.add(e.getKey());
                    for (byte[] p : st.commits.get(e.getKey()).parents()) {
                        parents.add(key(p));
                    }
                }
            }
            List<String> out = new ArrayList<>();
            for (String id : accepted) {
                if (!parents.contains(id)) {
                    out.add(id);
                }
            }
            return out;
        }

        // ─── Manifest states (SPEC 6, 8.3) ────────────────────────────────────────────

        private Optional<String> state(AvpManifest.SignedManifest m, Optional<AvpCommit.Commit> commit, Via via)
                throws AvpException {
            // Rule 1, structure; rule 2, owner signature.
            if (!manifestShapeOk(m) || !AvpManifest.verify(m)) {
                return fail(BAD_REQUEST);
            }
            byte[] hash = AvpManifest.hash(m);
            long seq = m.state().manifestSeq();
            StateRec rec = new StateRec(m, hash, key(hash), seq);
            AvpManifest.ManifestState s = rec.state();

            if (seq == 1) {
                // createRepo carries the genesis and its first commit together (SPEC 8.2); without
                // the commit the client request is malformed.
                if (via == Via.PUSH && commit.isEmpty()) {
                    return fail(BAD_REQUEST);
                }
                // Rule 3, genesis.
                if (!genesisOk(s)) {
                    return fail(BAD_REQUEST);
                }
                if (!st.chain.isEmpty()) {
                    // Host level, not an engine verdict: a host answers createRepo for a repoId it
                    // already holds with 409 duplicate_repo (SPEC 8.2, 12.3) before consulting the
                    // engine. The answer below is a placeholder that no acceptance.json scenario pins.
                    boolean same = st.chain.get(0).key().equals(rec.key());
                    return same && via == Via.OFFER && commit.isEmpty() ? OK : fail(MANIFEST_CONFLICT);
                }
                if (!contentOk(s, null)) {
                    return fail(BAD_REQUEST);
                }
                // Rule 6, hosted, on a client write. By replication it applies to the tip of the
                // chain being received, which the host checks before it applies any item (SPEC 6.1,
                // 9.2).
                if (via == Via.PUSH && !s.hasHost(hostKey)) {
                    return fail(NOT_HOSTED);
                }
                return adopt(rec, null, commit, via);
            }

            // Rule 4, chain link.
            StateRec tip = tipRec();
            if (tip == null) {
                return fail(MANIFEST_CONFLICT);
            }
            StateRec prev = st.states.get(key(s.prevManifestHash()));
            if (prev == null || prev.seq() != seq - 1) {
                return fail(MANIFEST_CONFLICT);
            }
            StateRec known = st.states.get(rec.key());
            if (known != null) {
                boolean win = winning(known);
                if (win || via == Via.PUSH) {
                    // A retry of a state already on the chain: idempotent by replication, a conflict
                    // on publish (SPEC 12.3). A retained losing state offered again is evaluated again.
                    return win && via == Via.OFFER && commit.isEmpty() ? OK : fail(MANIFEST_CONFLICT);
                }
            }
            boolean content = contentOk(s, prev.state());
            if (via == Via.PUSH && !prev.key().equals(tip.key())) {
                // Still rule 4: a client publish is accepted only at tip + 1 linked to the tip (SPEC
                // 6.3), and it fails here before the content rule; the tie rule is for states that
                // arrive by replication. A state that also passes rule 5 is kept as a verified losing
                // state (SPEC 6.5).
                if (content) {
                    retainLosing(rec, prev, commit);
                }
                return fail(MANIFEST_CONFLICT);
            }
            // Rule 5, content.
            if (!content) {
                return fail(BAD_REQUEST);
            }
            if (!winning(prev)) {
                // Extends a losing chain: verified and retained, never adopted (SPEC 6.5).
                retainLosing(rec, prev, commit);
                return fail(MANIFEST_CONFLICT);
            }
            StateRec at = chainAt(seq);
            if (at != null && AvpEncoding.compare(hash, at.hash()) > 0) {
                // Diverged and loses the tie rule: retained as a verified losing state (SPEC 6.5).
                retainLosing(rec, prev, commit);
                return fail(MANIFEST_CONFLICT);
            }
            // Appends to the tip, or wins the tie rule at its seq (lower manifestHash). Rule 6 as above.
            if (via == Via.PUSH && !s.hasHost(hostKey)) {
                return fail(NOT_HOSTED);
            }
            return adopt(rec, prev, commit, via);
        }

        private void retainLosing(StateRec rec, StateRec prev, Optional<AvpCommit.Commit> commit) {
            st.states.put(rec.key(), rec);
            boolean raising = isNext(prev.state().keyEpoch(), rec.state().keyEpoch());
            if (commit.isEmpty()) {
                return;
            }
            AvpCommit.Commit c = commit.get();
            if (!raising || !rotationShapeOk(rec, c) || !AvpCommit.verify(c)) {
                return;
            }
            // The rotation commit of a losing epoch-raising state is kept with it, held (SPEC 8.3).
            String id = key(c.commitId());
            if (!st.commits.containsKey(id)) {
                insertCommit(c, CommitStatus.HELD);
            }
            st.rotation.put(rec.key(), id);
            recordHeader(c);
        }

        /**
         * Records a verified commit header. A new one can complete the ancestry an undecided cutoff was
         * waiting for (SPEC 7.3), so every path that learns a header re-runs the cutoff re-check.
         */
        private void recordHeader(AvpCommit.Commit c) {
            String id = key(c.commitId());
            if (st.headers.containsKey(id)) {
                return;
            }
            List<String> parents = new ArrayList<>();
            for (byte[] p : c.parents()) {
                parents.add(key(p));
            }
            st.headers.put(id, List.copyOf(parents));
            recheckCutoffs();
            propagate();
        }

        /** SPEC 8.2 and 8.3: the commit published with a genesis or epoch-raising state. */
        private static boolean rotationShapeOk(StateRec rec, AvpCommit.Commit c) {
            AvpManifest.ManifestState s = rec.state();
            return commitShapeOk(c)
                    && c.manifestSeq() == s.manifestSeq()
                    && Arrays.equals(c.manifestHash(), rec.hash())
                    && c.keyEpoch() == s.keyEpoch()
                    && Arrays.equals(c.author(), s.ownerKey())
                    && (s.manifestSeq() != 1 || c.parents().isEmpty());
        }

        private static boolean citesState(StateRec rec, AvpCommit.Commit c) {
            return commitShapeOk(c) && c.manifestSeq() == rec.seq() && Arrays.equals(c.manifestHash(), rec.hash());
        }

        /**
         * Adopts a state onto the winning chain together with its commit, or changes nothing (SPEC
         * 8.2, 8.3).
         */
        private Optional<String> adopt(StateRec rec, StateRec prev, Optional<AvpCommit.Commit> commit, Via via)
                throws AvpException {
            Store snap = st.copy();
            Optional<String> v = adoptUnchecked(rec, prev, commit, via);
            if (v.isPresent()) {
                restore(snap);
            }
            return v;
        }

        private Optional<String> adoptUnchecked(StateRec rec, StateRec prev, Optional<AvpCommit.Commit> commit, Via via)
                throws AvpException {
            AvpManifest.ManifestState s = rec.state();
            boolean raising = prev != null && isNext(prev.state().keyEpoch(), s.keyEpoch());
            if (raising && commit.isEmpty()) {
                return fail(BAD_REQUEST);
            }
            if (commit.isPresent()) {
                // The genesis commit and a rotation commit have a fixed shape (SPEC 8.2, 8.3); any
                // other commit published with a state is validated as a push that cites the new state.
                boolean shaped =
                        raising || prev == null ? rotationShapeOk(rec, commit.get()) : citesState(rec, commit.get());
                if (!shaped) {
                    return fail(BAD_REQUEST);
                }
            }

            // The state at seq goes at chain[seq - 1]; its predecessor is on the chain, so the chain
            // already holds at least seq - 1 states.
            long index = rec.seq() - 1;
            if (index < 0 || index > st.chain.size()) {
                return fail(BAD_REQUEST);
            }
            boolean switching = st.chain.size() > index;
            st.states.put(rec.key(), rec);
            while (st.chain.size() > index) {
                st.chain.remove(st.chain.size() - 1);
            }
            st.chain.add(rec);

            if (switching) {
                recheckAccepted(rec.seq());
            }
            recheckCutoffs();
            for (AvpManifest.Removal r : s.removals()) {
                st.leaves.removeIf(l -> Arrays.equals(l.memberKey(), r.memberKey()));
            }
            recheckHeld();
            propagate();

            if (commit.isPresent()) {
                AvpCommit.Commit c = commit.get();
                Optional<String> v = oneCommit(c, via, true);
                if (v.isPresent()) {
                    return v;
                }
                if (raising) {
                    st.rotation.put(rec.key(), key(c.commitId()));
                }
            }
            return OK;
        }

        // ─── Commits (SPEC 7, 6.5) ────────────────────────────────────────────────────

        private Optional<String> oneCommit(AvpCommit.Commit c, Via via, boolean carried) {
            if (!commitShapeOk(c)) {
                return fail(BAD_REQUEST);
            }
            // Host level, not an engine verdict: a host answers 404 not_found for a repository it does
            // not hold (SPEC 10.1) before consulting the engine. The answer below is a placeholder
            // that no acceptance.json scenario pins.
            StateRec tip = tipRec();
            if (tip == null) {
                return fail(MISSING_PARENTS);
            }
            if (!c.repoId().equals(tip.state().repoId()) || !AvpCommit.verify(c)) {
                return fail(BAD_REQUEST);
            }
            String id = key(c.commitId());

            // Caller check on the client routes: the caller is the author (the owner for a carried
            // commit) and is a member of the tip. It runs before the header is recorded, so a caller
            // the host refuses leaves nothing behind.
            if (via == Via.PUSH) {
                if (carried && !Arrays.equals(c.author(), tip.state().ownerKey())) {
                    return fail(FORBIDDEN);
                }
                if (!tip.state().hasMember(c.author())) {
                    return fail(FORBIDDEN);
                }
            }
            recordHeader(c);

            CommitStatus existing = statusOf(id);
            if (existing != null) {
                return switch (existing) {
                    case ACCEPTED -> OK;
                    // Undecided cutoff: retryable once the missing frontier commit arrives (SPEC 7.3).
                    case PENDING -> fail(MISSING_PARENTS);
                    case HELD, REJECTED -> fail(FORBIDDEN);
                };
            }

            return switch (classify(c, via == Via.PUSH)) {
                case MISSING -> fail(MISSING_PARENTS);
                case TOO_MANY -> fail(TOO_MANY_HEADS);
                case REJECTED -> {
                    insertCommit(c, CommitStatus.REJECTED);
                    yield fail(FORBIDDEN);
                }
                case HELD -> {
                    insertCommit(c, CommitStatus.HELD);
                    yield fail(FORBIDDEN);
                }
                case ACCEPTED -> {
                    insertCommit(c, CommitStatus.ACCEPTED);
                    yield OK;
                }
            };
        }

        /** SPEC 7.2 to 7.4 (and 6.5 for a commit citing a losing state). */
        private Classification classify(AvpCommit.Commit c, boolean applyBound) {
            StateRec tip = tipRec();
            if (tip == null) {
                return Classification.MISSING;
            }
            // 7.2 manifest binding: the (seq, hash) pair must name a verified state this host holds.
            StateRec bound = st.states.get(key(c.manifestHash()));
            if (bound == null || bound.seq() != c.manifestSeq()) {
                return Classification.MISSING;
            }

            boolean held = false;
            if (winning(bound)) {
                if (!bound.state().hasMember(c.author())
                        || c.keyEpoch() != bound.state().keyEpoch()) {
                    return Classification.REJECTED;
                }
                switch (cutoff(c, tip)) {
                    case FAIL -> {
                        return Classification.REJECTED;
                    }
                    case UNDECIDED -> {
                        return Classification.MISSING;
                    }
                    case OK -> {}
                }
            } else {
                switch (losingVerdict(c, tip)) {
                    case UNDECIDED -> {
                        return Classification.MISSING;
                    }
                    case REJECTED -> {
                        return Classification.REJECTED;
                    }
                    case HELD -> held = true;
                    case ACCEPTED -> {}
                }
            }

            // 7.4 parents.
            List<CommitStatus> parents = parentStatuses(c);
            if (parents.contains(CommitStatus.REJECTED)) {
                return Classification.REJECTED;
            }
            // A pending parent is not accepted and is waiting on a missing frontier commit: retryable.
            if (parents.contains(null) || parents.contains(CommitStatus.PENDING)) {
                return Classification.MISSING;
            }
            if (parents.contains(CommitStatus.HELD)) {
                held = true;
            }

            if (held) {
                return Classification.HELD;
            }
            if (applyBound) {
                Set<String> heads = new HashSet<>(headIds());
                long named =
                        c.parents().stream().filter(p -> heads.contains(key(p))).count();
                if (heads.size() - named + 1 > headBound) {
                    return Classification.TOO_MANY;
                }
            }
            return Classification.ACCEPTED;
        }

        /**
         * SPEC 6.5: a commit citing a verified losing state, re-checked against the winning chain. The
         * removal cutoff takes precedence; then accept if the winning state at that seq lists the
         * author at the commit's epoch; then the drop test; otherwise held.
         */
        private Losing losingVerdict(AvpCommit.Commit c, StateRec tip) {
            switch (cutoff(c, tip)) {
                case FAIL -> {
                    return Losing.REJECTED;
                }
                case UNDECIDED -> {
                    return Losing.UNDECIDED;
                }
                case OK -> {}
            }
            StateRec w = chainAt(c.manifestSeq());
            if (w != null && w.state().hasMember(c.author()) && w.state().keyEpoch() == c.keyEpoch()) {
                return Losing.ACCEPTED;
            }
            if (dropTest(c, tip)) {
                return Losing.REJECTED;
            }
            return Losing.HELD;
        }

        /**
         * SPEC 6.5 drop test: the tip's epoch passed the commit's, or the author was removed and the
         * commit is not covered by the frontier. A cutoff that cannot be decided yet is not a drop
         * (SPEC 7.3 says only that the host MUST NOT accept such a commit).
         */
        private boolean dropTest(AvpCommit.Commit c, StateRec tip) {
            return tip.state().keyEpoch() > c.keyEpoch() || cutoff(c, tip) == Cut.FAIL;
        }

        /**
         * Walks the removal cutoff of {@code c} against the tip's removals (SPEC 7.3): a commit by a
         * removed author is valid only if its id is in the frontier or it is an ancestor of a frontier
         * commit, ancestry following the parents of every verified header. Returns whether {@code c}
         * is covered and the ids on the way whose headers are unknown.
         */
        private Walk cutoffWalk(AvpCommit.Commit c, StateRec tip) {
            Optional<AvpManifest.Removal> r = tip.state().removalOf(c.author());
            if (r.isEmpty()) {
                return new Walk(true, List.of());
            }
            String target = key(c.commitId());
            List<String> stack = new ArrayList<>();
            for (byte[] id : r.get().frontier()) {
                stack.add(key(id));
            }
            if (stack.contains(target)) {
                return new Walk(true, List.of());
            }
            Set<String> seen = new HashSet<>(stack);
            List<String> unknown = new ArrayList<>();
            while (!stack.isEmpty()) {
                String h = stack.remove(stack.size() - 1);
                List<String> parents = st.headers.get(h);
                if (parents == null) {
                    unknown.add(h);
                    continue;
                }
                for (String p : parents) {
                    if (p.equals(target)) {
                        return new Walk(true, List.of());
                    }
                    if (seen.add(p)) {
                        stack.add(p);
                    }
                }
            }
            return new Walk(false, unknown);
        }

        private Cut cutoff(AvpCommit.Commit c, StateRec tip) {
            Walk w = cutoffWalk(c, tip);
            if (w.covered()) {
                return Cut.OK;
            }
            return w.unknown().isEmpty() ? Cut.FAIL : Cut.UNDECIDED;
        }

        private boolean cutoffOk(AvpCommit.Commit c) {
            StateRec tip = tipRec();
            return tip != null && cutoff(c, tip) == Cut.OK;
        }

        // ─── Re-checks after a new winning state or a new header ──────────────────────

        /** SPEC 6.5: after a switch, every accepted commit citing a state from the fork point on. */
        private void recheckAccepted(long forkSeq) {
            StateRec tip = tipRec();
            if (tip == null) {
                return;
            }
            for (Snap sn : snapshot()) {
                if (sn.status() != CommitStatus.ACCEPTED || sn.c().manifestSeq() < forkSeq) {
                    continue;
                }
                StateRec bound = st.states.get(key(sn.c().manifestHash()));
                if (bound == null || winning(bound)) {
                    continue;
                }
                switch (losingVerdict(sn.c(), tip)) {
                    case REJECTED -> setStatus(sn.id(), CommitStatus.REJECTED);
                    case HELD -> setStatus(sn.id(), CommitStatus.HELD);
                    case UNDECIDED -> setStatus(sn.id(), CommitStatus.PENDING);
                    case ACCEPTED -> {}
                }
            }
        }

        /**
         * SPEC 7.3, run on each new winning state and each new verified header: every stored commit by
         * a removed member is checked against the tip's cutoff. One that fails is dropped; an accepted
         * one that cannot be decided leaves the heads as pending; a pending one that is now covered is
         * decided again. A held commit stays held unless it fails.
         */
        private void recheckCutoffs() {
            StateRec tip = tipRec();
            if (tip == null) {
                return;
            }
            for (Snap sn : snapshot()) {
                if (sn.status() == CommitStatus.REJECTED) {
                    continue;
                }
                Cut cut = cutoff(sn.c(), tip);
                if (cut == Cut.FAIL) {
                    setStatus(sn.id(), CommitStatus.REJECTED);
                } else if (cut == Cut.UNDECIDED && sn.status() == CommitStatus.ACCEPTED) {
                    setStatus(sn.id(), CommitStatus.PENDING);
                } else if (cut == Cut.OK && sn.status() == CommitStatus.PENDING) {
                    setStatus(sn.id(), decidePending(sn.c()));
                }
            }
        }

        /**
         * The status of a pending commit whose own cutoff is now decided as covered. A commit citing a
         * verified losing state goes through the rest of the SPEC 6.5 re-check (winning state at its
         * seq, drop test, hold), as at its first classification; then its parents decide as in SPEC
         * 7.4.
         */
        private CommitStatus decidePending(AvpCommit.Commit c) {
            StateRec tip = tipRec();
            if (tip == null) {
                return CommitStatus.PENDING;
            }
            CommitStatus status = CommitStatus.ACCEPTED;
            StateRec bound = st.states.get(key(c.manifestHash()));
            if (bound != null && !winning(bound)) {
                switch (losingVerdict(c, tip)) {
                    case UNDECIDED -> {
                        return CommitStatus.PENDING;
                    }
                    case REJECTED -> {
                        return CommitStatus.REJECTED;
                    }
                    case HELD -> status = CommitStatus.HELD;
                    case ACCEPTED -> {}
                }
            }
            List<CommitStatus> parents = parentStatuses(c);
            if (parents.contains(CommitStatus.REJECTED)) {
                return CommitStatus.REJECTED;
            }
            if (parents.contains(null) || parents.contains(CommitStatus.PENDING)) {
                return CommitStatus.PENDING;
            }
            if (parents.contains(CommitStatus.HELD)) {
                return CommitStatus.HELD;
            }
            return status;
        }

        /**
         * SPEC 6.5 deciding a held commit, against the new tip: dropped if it meets the drop test,
         * accepted if the tip lists its author at its epoch, held otherwise. A held descendant waits
         * for its held ancestors and is then re-checked in turn.
         */
        private void recheckHeld() {
            StateRec tip = tipRec();
            if (tip == null) {
                return;
            }
            while (true) {
                boolean changed = false;
                propagate();
                for (Snap sn : snapshot()) {
                    if (sn.status() != CommitStatus.HELD) {
                        continue;
                    }
                    boolean parentsAccepted = true;
                    for (CommitStatus p : parentStatuses(sn.c())) {
                        if (p != CommitStatus.ACCEPTED) {
                            parentsAccepted = false;
                        }
                    }
                    if (!parentsAccepted) {
                        continue;
                    }
                    if (dropTest(sn.c(), tip)) {
                        setStatus(sn.id(), CommitStatus.REJECTED);
                        changed = true;
                    } else if (cutoff(sn.c(), tip) == Cut.OK
                            && tip.state().hasMember(sn.c().author())
                            && tip.state().keyEpoch() == sn.c().keyEpoch()) {
                        setStatus(sn.id(), CommitStatus.ACCEPTED);
                        changed = true;
                    }
                }
                if (!changed) {
                    return;
                }
            }
        }

        /**
         * A commit with a rejected parent is rejected; an accepted commit with a held parent is held,
         * and one with a pending parent is pending; a pending commit whose parents are decided is
         * decided again.
         */
        private void propagate() {
            while (true) {
                boolean changed = false;
                for (Snap sn : snapshot()) {
                    if (sn.status() == CommitStatus.REJECTED) {
                        continue;
                    }
                    List<CommitStatus> parents = parentStatuses(sn.c());
                    if (parents.contains(CommitStatus.REJECTED)) {
                        setStatus(sn.id(), CommitStatus.REJECTED);
                        changed = true;
                    } else if (sn.status() == CommitStatus.ACCEPTED && parents.contains(CommitStatus.HELD)) {
                        setStatus(sn.id(), CommitStatus.HELD);
                        changed = true;
                    } else if (sn.status() == CommitStatus.ACCEPTED && parents.contains(CommitStatus.PENDING)) {
                        setStatus(sn.id(), CommitStatus.PENDING);
                        changed = true;
                    } else if (sn.status() == CommitStatus.PENDING
                            && !parents.contains(CommitStatus.PENDING)
                            && cutoffOk(sn.c())) {
                        // Waiting only on its parent: decided again, with the full re-check, once the
                        // parent is.
                        CommitStatus next = decidePending(sn.c());
                        if (next != CommitStatus.PENDING) {
                            setStatus(sn.id(), next);
                            changed = true;
                        }
                    }
                }
                if (!changed) {
                    return;
                }
            }
        }
    }
}
