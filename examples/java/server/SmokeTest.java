/*
 * Black-box tests of the Java reference host: the client-facing API (SPEC 3.3, 6 to 8, 10, 11.7, 12) and
 * host-to-host replication (SPEC 6.1 rule 6, 6.5, 8.3, 8.6, 9, 10.1).
 *
 * SPDX-License-Identifier: MIT
 */

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.lang.reflect.RecordComponent;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.IntFunction;

/**
 * Integration tests of the Java reference host, one check per test of the Rust reference host's {@code
 * tests/api.rs} and {@code tests/replication.rs}, with the same names and assertions.
 *
 * <p>Each test starts hosts in-process on port 0 ({@link Server#start(int, Server.ServerConfig)}) and talks
 * to them over real HTTP. Every request body is built with the shared {@code avp} sources, with real keys
 * and signatures; the engine is the real {@link AvpRules.RepoView}. Expected statuses and codes are the
 * ones SPEC 10.4 names for each case. Replicating hosts sweep every 100 ms here (the default is 5 s), and
 * convergence is polled every 25 ms for at most 15 s.
 *
 * <p>Run from this directory: {@code javac -d build ../avp/*.java *.java && java -cp build SmokeTest}.
 * Each passing check prints {@code ok <name>}; the exit code is 0 only when every check passed.
 */
public final class SmokeTest {

    private static final long SWEEP_MS = 100;
    private static final long CONVERGE_MS = 15_000;
    private static final byte[] EMPTY_PAYLOAD = "{\"v\":2,\"accounts\":{}}".getBytes(StandardCharsets.UTF_8);

    /** Every host a test started, stopped when the test ends. */
    private static final List<Node> STARTED = new ArrayList<>();

    private SmokeTest() {}

    // ─── Runner ─────────────────────────────────────────────────────────────────────────

    private interface Check {
        void run() throws Exception;
    }

    /**
     * Runs every check and prints {@code ok <name>} for each that passes.
     *
     * @param args ignored
     */
    public static void main(String[] args) {
        Map<String, Check> checks = new LinkedHashMap<>();
        // tests/api.rs
        checks.put("create_pull_push_roundtrip", SmokeTest::createPullPushRoundtrip);
        checks.put("create_returns_the_genesis_state", SmokeTest::createReturnsTheGenesisState);
        checks.put("create_rejected_when_host_not_listed", SmokeTest::createRejectedWhenHostNotListed);
        checks.put("push_concurrent_gives_two_heads", SmokeTest::pushConcurrentGivesTwoHeads);
        checks.put("push_beyond_bound_is_too_many_heads", SmokeTest::pushBeyondBoundIsTooManyHeads);
        checks.put("publish_manifest_wrong_seq_is_conflict", SmokeTest::publishManifestWrongSeqIsConflict);
        checks.put("removed_member_push_forbidden", SmokeTest::removedMemberPushForbidden);
        checks.put("leave_is_served_in_pull", SmokeTest::leaveIsServedInPull);
        checks.put("prepare_join_acceptance_verifies", SmokeTest::prepareJoinAcceptanceVerifies);
        checks.put("token_required", SmokeTest::tokenRequired);
        checks.put("server_never_sees_plaintext", SmokeTest::serverNeverSeesPlaintext);
        checks.put("discovery_reports_version_profiles_and_host_key", SmokeTest::discoveryReports);
        checks.put("challenge_nonce_is_32_random_bytes", SmokeTest::challengeNonceIs32RandomBytes);
        checks.put("token_response_has_token_and_expiry", SmokeTest::tokenResponseHasTokenAndExpiry);
        checks.put("expired_challenge_is_unauthorized", SmokeTest::expiredChallengeIsUnauthorized);
        checks.put("reused_challenge_is_unauthorized", SmokeTest::reusedChallengeIsUnauthorized);
        checks.put("bad_challenge_signature_is_unauthorized", SmokeTest::badChallengeSignatureIsUnauthorized);
        checks.put("challenge_for_another_key_is_unauthorized", SmokeTest::challengeForAnotherKeyIsUnauthorized);
        checks.put("token_of_another_host_is_unauthorized", SmokeTest::tokenOfAnotherHostIsUnauthorized);
        checks.put("expired_token_is_unauthorized", SmokeTest::expiredTokenIsUnauthorized);
        checks.put("malformed_auth_bodies_are_bad_request", SmokeTest::malformedAuthBodiesAreBadRequest);
        checks.put("create_by_non_owner_is_forbidden", SmokeTest::createByNonOwnerIsForbidden);
        checks.put("publish_by_non_owner_is_forbidden", SmokeTest::publishByNonOwnerIsForbidden);
        checks.put("pull_by_non_member_is_forbidden", SmokeTest::pullByNonMemberIsForbidden);
        checks.put("push_by_non_author_is_forbidden", SmokeTest::pushByNonAuthorIsForbidden);
        checks.put("leave_for_another_member_is_forbidden", SmokeTest::leaveForAnotherMemberIsForbidden);
        checks.put("prepare_join_for_another_key_is_forbidden", SmokeTest::prepareJoinForAnotherKeyIsForbidden);
        checks.put("second_create_is_duplicate_repo", SmokeTest::secondCreateIsDuplicateRepo);
        checks.put("unknown_repo_is_not_found", SmokeTest::unknownRepoIsNotFound);
        checks.put("unknown_parent_is_missing_parents_with_detail", SmokeTest::unknownParentIsMissingParents);
        checks.put("malformed_bodies_are_bad_request", SmokeTest::malformedBodiesAreBadRequest);
        checks.put("percent_encoded_repo_id_routes", SmokeTest::percentEncodedRepoIdRoutes);
        checks.put("unknown_route_is_not_found", SmokeTest::unknownRouteIsNotFound);
        checks.put("oversize_body_is_too_large", SmokeTest::oversizeBodyIsTooLarge);
        checks.put("member_limit_is_quota_exceeded", SmokeTest::memberLimitIsQuotaExceeded);
        checks.put("repo_limit_per_owner_is_quota_exceeded", SmokeTest::repoLimitPerOwnerIsQuotaExceeded);
        checks.put("challenge_cap_per_key_is_quota_exceeded", SmokeTest::challengeCapPerKeyIsQuotaExceeded);
        checks.put("challenge_global_cap_evicts_the_oldest", SmokeTest::challengeGlobalCapEvictsTheOldest);
        checks.put("token_cap_per_key_is_quota_exceeded", SmokeTest::tokenCapPerKeyIsQuotaExceeded);
        checks.put("token_global_cap_evicts_the_oldest", SmokeTest::tokenGlobalCapEvictsTheOldest);
        checks.put("acceptance_cap_per_key_is_quota_exceeded", SmokeTest::acceptanceCapPerKeyIsQuotaExceeded);
        checks.put("acceptance_global_cap_evicts_the_oldest", SmokeTest::acceptanceGlobalCapEvictsTheOldest);
        checks.put(
                "publish_carried_commit_missing_parent_lists_only_that_parent",
                SmokeTest::publishCarriedCommitMissingParent);
        checks.put("publish_carried_commit_beyond_bound_is_too_many_heads", SmokeTest::publishCarriedCommitBeyondBound);
        checks.put("create_non_genesis_state_is_bad_request", SmokeTest::createNonGenesisStateIsBadRequest);
        checks.put("create_first_commit_rules_are_bad_request", SmokeTest::createFirstCommitRulesAreBadRequest);
        checks.put(
                "forged_colliding_genesis_is_bad_request_not_duplicate", SmokeTest::forgedCollidingGenesisIsBadRequest);
        checks.put("push_epoch_mismatch_is_forbidden", SmokeTest::pushEpochMismatchIsForbidden);
        checks.put("publish_dropping_this_host_is_not_hosted", SmokeTest::publishDroppingThisHostIsNotHosted);
        checks.put("leave_by_outsider_is_forbidden", SmokeTest::leaveByOutsiderIsForbidden);
        checks.put("pull_returns_states_after_since_in_ascending_order", SmokeTest::pullReturnsStatesInOrder);
        checks.put("poisoned_state_is_an_error_response", SmokeTest::poisonedStateIsAnErrorResponse);
        // tests/replication.rs
        checks.put("write_on_a_reaches_b", SmokeTest::writeOnAReachesB);
        checks.put("partition_then_heal_converges", SmokeTest::partitionThenHealConverges);
        checks.put("host_not_in_hosts_is_refused", SmokeTest::hostNotInHostsIsRefused);
        checks.put("bad_host_signature_rejected", SmokeTest::badHostSignatureRejected);
        checks.put("stale_timestamp_rejected", SmokeTest::staleTimestampRejected);
        checks.put("offer_revalidates", SmokeTest::offerRevalidates);
        checks.put("body_not_matching_signed_hash_rejected", SmokeTest::bodyNotMatchingSignedHashRejected);
        checks.put("path_not_matching_signed_path_rejected", SmokeTest::pathNotMatchingSignedPathRejected);
        checks.put("peers_from_env_parses_and_rejects", SmokeTest::peersFromEnvParsesAndRejects);
        checks.put("test_control_absent_without_flag", SmokeTest::testControlAbsentWithoutFlag);
        checks.put("paused_host_answers_503", SmokeTest::pausedHostAnswers503);
        checks.put("heads_and_fetch_answer_the_spec_shapes", SmokeTest::headsAndFetchAnswerTheSpecShapes);
        checks.put("newly_listed_host_bootstraps_by_replication", SmokeTest::newlyListedHostBootstraps);
        checks.put("rotation_reaches_b_atomically", SmokeTest::rotationReachesBAtomically);
        checks.put("epoch_raise_offer_needs_its_rotation_commit", SmokeTest::epochRaiseOfferNeedsItsRotationCommit);
        checks.put("diverged_owner_states_converge", SmokeTest::divergedOwnerStatesConverge);
        checks.put("leave_replicates", SmokeTest::leaveReplicates);
        checks.put("fetch_serves_losing_state_with_rotation_commit", SmokeTest::fetchServesLosingState);
        checks.put("held_and_pending_commits_are_not_served", SmokeTest::heldAndPendingCommitsAreNotServed);
        checks.put("dropped_by_replication_stops_serving_and_relisting_resumes", SmokeTest::droppedByReplicationStops);
        checks.put(
                "client_publish_dropping_host_keeps_state_and_stops_serving",
                SmokeTest::clientPublishDroppingHostKeepsState);
        checks.put("first_copy_with_unlisted_tip_stores_nothing", SmokeTest::firstCopyWithUnlistedTip);
        checks.put("first_copy_whose_tip_omits_the_sender_stores_nothing", SmokeTest::firstCopyOmittingTheSender);
        checks.put("first_copy_with_forged_listing_state_stores_nothing", SmokeTest::firstCopyWithForgedListing);
        checks.put("bad_peer_responses_do_not_stop_replication", SmokeTest::badPeerResponses);
        checks.put("sweep_repairs_rotation_after_missed_offers", SmokeTest::sweepRepairsRotation);
        checks.put("newly_listed_after_rotation_bootstraps", SmokeTest::newlyListedAfterRotationBootstraps);
        checks.put("first_copy_across_a_diverged_losing_branch", SmokeTest::firstCopyAcrossALosingBranch);
        checks.put("first_copy_with_a_gap_waits_for_the_catch_up", SmokeTest::firstCopyWithAGap);
        checks.put("first_copies_are_held_to_the_repository_quotas", SmokeTest::firstCopiesAreHeldToQuotas);
        checks.put("rejected_offers_do_not_grow_a_held_repository", SmokeTest::rejectedOffersDoNotGrow);
        checks.put("host_time_must_be_plain_decimal", SmokeTest::hostTimeMustBePlainDecimal);
        checks.put("host_route_reject_paths", SmokeTest::hostRouteRejectPaths);
        checks.put(
                "losing_raising_state_without_its_rotation_commit_is_retained", SmokeTest::losingRaisingStateRetained);
        checks.put("offer_work_is_linear_in_its_items", SmokeTest::offerWorkIsLinearInItsItems);
        checks.put("first_copy_bootstraps_across_40_rotations_with_pushes", SmokeTest::bootstrapsAcross40Rotations);
        checks.put("decoy_rotation_candidate_does_not_block_its_state", SmokeTest::decoyRotationCandidate);
        checks.put("offer_answer_matches_what_is_stored", SmokeTest::offerAnswerMatchesWhatIsStored);
        checks.put("losing_state_keeps_its_real_rotation_commit", SmokeTest::losingStateKeepsItsRotationCommit);
        checks.put("catch_up_work_does_not_grow_with_carried_rounds", SmokeTest::catchUpWorkDoesNotGrow);
        checks.put("carried_items_are_retried_only_when_their_wait_ends", SmokeTest::carriedItemsRetried);
        checks.put("eight_decoys_before_the_rotation_commit_do_not_block_it", SmokeTest::eightDecoys);
        // Java-only checks of the HTTP layer.
        checks.put("bad_utf8_percent_escape_is_bad_request", SmokeTest::badUtf8PercentEscapeIsBadRequest);

        int failed = 0;
        for (Map.Entry<String, Check> e : checks.entrySet()) {
            try {
                e.getValue().run();
                System.out.println("ok " + e.getKey());
            } catch (Throwable t) {
                failed++;
                System.out.println("FAIL " + e.getKey() + ": " + t);
                t.printStackTrace(System.out);
            } finally {
                stopEveryHost();
            }
        }
        System.out.println((checks.size() - failed) + " passed, " + failed + " failed, " + checks.size() + " checks");
        System.exit(failed == 0 ? 0 : 1);
    }

    private static void stopEveryHost() {
        for (Node n : STARTED) {
            n.stop();
        }
        STARTED.clear();
    }

    // ─── Assertions ─────────────────────────────────────────────────────────────────────

    private static void eq(Object actual, Object expected, String what) {
        if (!java.util.Objects.equals(actual, expected)) {
            throw new AssertionError(what + ": expected " + expected + " but was " + actual);
        }
    }

    private static void isTrue(boolean ok, String what) {
        if (!ok) {
            throw new AssertionError(what);
        }
    }

    /** The SPEC 10.4 error object: {@code error} is a string, {@code code} is the expected machine code. */
    private static void assertError(Reply r, int status, String code) {
        eq(r.status, status, "status of " + r.body);
        isTrue(r.at("error") instanceof String, "error message present: " + r.body);
        eq(r.at("code"), code, "code of " + r.body);
    }

    private static void eventually(String what, Check f) throws Exception {
        long deadline = System.currentTimeMillis() + CONVERGE_MS;
        while (System.currentTimeMillis() < deadline) {
            try {
                f.run();
                return;
            } catch (AssertionError e) {
                // Not converged yet.
            }
            Thread.sleep(25);
        }
        throw new AssertionError("not reached within " + CONVERGE_MS + " ms: " + what);
    }

    private static void eventuallyTrue(String what, java.util.function.BooleanSupplier f) throws Exception {
        eventually(what, () -> isTrue(f.getAsBoolean(), what));
    }

    // ─── JSON helpers ───────────────────────────────────────────────────────────────────

    /** A JSON tree normalized through the shared writer and parser, so trees compare by value. */
    private static Object j(Object tree) {
        try {
            return AvpJson.parse(AvpJson.write(tree));
        } catch (AvpException e) {
            throw new IllegalStateException(e);
        }
    }

    private static Map<String, Object> obj(Object... kv) {
        Map<String, Object> o = new LinkedHashMap<>();
        for (int k = 0; k < kv.length; k += 2) {
            o.put((String) kv[k], kv[k + 1]);
        }
        return o;
    }

    private static List<Object> list(Object... items) {
        return new ArrayList<>(Arrays.asList(items));
    }

    private static Object mj(AvpManifest.SignedManifest m) {
        return j(AvpManifest.toJson(m));
    }

    private static Object cj(AvpCommit.Commit c) {
        return j(AvpCommit.toJson(c));
    }

    private static Object lj(AvpTokens.LeaveRequest l) {
        return j(AvpTokens.toJson(l));
    }

    private static String b64(byte[] b) {
        return AvpEncoding.base64(b);
    }

    private static byte[] unb64(Object s) throws AvpException {
        return AvpEncoding.fromBase64((String) s);
    }

    private static List<Object> ids(byte[]... v) {
        List<Object> out = new ArrayList<>();
        for (byte[] id : v) {
            out.add(b64(id));
        }
        return out;
    }

    private static List<Object> idList(List<byte[]> v) {
        return ids(v.toArray(new byte[0][]));
    }

    private static List<String> b64s(byte[]... v) {
        List<String> out = new ArrayList<>();
        for (byte[] id : v) {
            out.add(b64(id));
        }
        return out;
    }

    private static List<String> sortedB64(byte[]... v) {
        List<byte[]> l = new ArrayList<>(Arrays.asList(v));
        l.sort(AvpEncoding::compare);
        return b64s(l.toArray(new byte[0][]));
    }

    private static Set<String> b64Set(byte[]... v) {
        return new HashSet<>(b64s(v));
    }

    private static Set<String> idSet(Object v) {
        Set<String> out = new HashSet<>();
        for (Object x : (List<?>) v) {
            out.add((String) x);
        }
        return out;
    }

    /** The {@code rejected} list of an offer answer as {@code id|code} strings. */
    private static Set<String> rejected(Reply r) {
        Set<String> out = new HashSet<>();
        for (Object x : (List<?>) r.at("rejected")) {
            Map<?, ?> m = (Map<?, ?>) x;
            out.add(m.get("id") + "|" + m.get("code"));
        }
        return out;
    }

    private static String pair(byte[] id, String code) {
        return b64(id) + "|" + code;
    }

    // ─── Keys and fixtures ──────────────────────────────────────────────────────────────

    private static byte[] seed() {
        return AvpCrypto.randomBytes(32);
    }

    private static byte[] pk(byte[] seed) {
        try {
            return AvpCrypto.ed25519Public(seed);
        } catch (AvpException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] sign(byte[] seed, byte[] message) {
        try {
            return AvpCrypto.ed25519Sign(seed, message);
        } catch (AvpException e) {
            throw new IllegalStateException(e);
        }
    }

    private static long nowMs() {
        return System.currentTimeMillis();
    }

    private static byte[] hash(AvpManifest.SignedManifest m) {
        try {
            return AvpManifest.hash(m);
        } catch (AvpException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String h(AvpManifest.SignedManifest m) {
        return b64(hash(m));
    }

    private static byte[] flip(byte[] b, int at) {
        byte[] out = b.clone();
        out[at] ^= 1;
        return out;
    }

    private static AvpCommit.Commit withSignature(AvpCommit.Commit c, byte[] sig) {
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
                sig);
    }

    private static AvpCommit.Commit withRepoId(AvpCommit.Commit c, String repoId) {
        return new AvpCommit.Commit(
                repoId,
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

    /** A member device: an Ed25519 seed and an X25519 key pair. */
    private static final class Device {
        final byte[] seed;
        final byte[] xPrivate;

        Device() {
            this(SmokeTest.seed());
        }

        Device(byte[] seed) {
            this.seed = seed;
            this.xPrivate = AvpCrypto.randomBytes(32);
        }

        byte[] key() {
            return pk(seed);
        }

        AvpManifest.MemberEntry entry(byte[] dataKey, long epoch, byte[] home) throws AvpException {
            byte[] xPublic = AvpCrypto.x25519Public(xPrivate);
            return new AvpManifest.MemberEntry(
                    key(), xPublic, AvpCrypto.wrap(xPublic, dataKey, AvpCrypto.WRAP_INFO), epoch, home);
        }
    }

    /** A manifest state being edited. */
    private static final class S {
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

        static S of(AvpManifest.ManifestState s) {
            S o = new S();
            o.repoId = s.repoId();
            o.seq = s.manifestSeq();
            o.prev = s.prevManifestHash();
            o.owner = s.ownerKey();
            o.nonce = s.genesisNonce();
            o.scheme = s.schemeId();
            o.epoch = s.keyEpoch();
            o.share = s.shareRefreshTokens();
            o.hosts = new ArrayList<>(s.hosts());
            o.members = new ArrayList<>(s.members());
            o.removals = new ArrayList<>(s.removals());
            return o;
        }

        AvpManifest.ManifestState build() {
            return new AvpManifest.ManifestState(
                    repoId, seq, prev, owner, nonce, scheme, epoch, share, hosts, members, removals);
        }

        AvpManifest.SignedManifest sign(byte[] ownerSeed) throws AvpException {
            return AvpManifest.sign(build(), ownerSeed);
        }

        /** Keeps only the host with {@code key}. */
        void keepHost(byte[] key) {
            hosts.removeIf(x -> !Arrays.equals(x.hostKey(), key));
        }

        void addHost(byte[] key, String locator) {
            hosts.add(new AvpManifest.HostRef(key, locator));
        }

        void relocate(int at, String locator) {
            hosts.set(at, new AvpManifest.HostRef(hosts.get(at).hostKey(), locator));
        }
    }

    private interface Edit {
        void apply(S s) throws AvpException;
    }

    private static AvpManifest.SignedManifest nextOf(AvpManifest.SignedManifest tip, byte[] ownerSeed, Edit f)
            throws AvpException {
        S s = S.of(tip.state());
        s.seq += 1;
        s.prev = hash(tip);
        s.nonce = new byte[0];
        f.apply(s);
        return s.sign(ownerSeed);
    }

    private static AvpCommit.Commit commitOn(
            AvpManifest.SignedManifest cites, byte[] dataKey, byte[] authorSeed, List<byte[]> parents, byte[] text)
            throws AvpException {
        AvpCommit.Header header = new AvpCommit.Header(
                cites.state().repoId(),
                parents,
                cites.state().manifestSeq(),
                hash(cites),
                cites.state().keyEpoch());
        return AvpCommit.seal(dataKey, header, text, authorSeed);
    }

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    /** A repository as its owner's client sees it. */
    private static final class Repo {
        Device owner;
        byte[] dataKey;
        AvpManifest.SignedManifest genesis;
        AvpManifest.SignedManifest tip;
        AvpCommit.Commit root;

        String id() {
            return tip.state().repoId();
        }

        String path(String op) {
            return "/v1/repos/" + id() + "/" + op;
        }

        AvpManifest.SignedManifest next(Edit f) throws AvpException {
            return nextOf(tip, owner.seed, f);
        }

        AvpCommit.Commit commit(byte[] authorSeed, List<byte[]> parents, byte[] text) throws AvpException {
            return commitOn(tip, dataKey, authorSeed, parents, text);
        }
    }

    /** The genesis state of a new repository listing {@code hosts}, with the owner homed on {@code home}. */
    private static Repo genesis(byte[] home, byte[]... hosts) throws AvpException {
        Repo r = new Repo();
        r.owner = new Device();
        r.dataKey = AvpCrypto.randomBytes(32);
        byte[] nonce = AvpCrypto.randomBytes(16);
        List<AvpManifest.HostRef> refs = new ArrayList<>();
        for (int i = 0; i < hosts.length; i++) {
            refs.add(new AvpManifest.HostRef(hosts[i], "h" + i + ".vault.example"));
        }
        AvpManifest.ManifestState state = new AvpManifest.ManifestState(
                AvpManifest.deriveRepoId(r.owner.key(), nonce),
                1,
                new byte[0],
                r.owner.key(),
                nonce,
                AvpCrypto.SCHEME_ID,
                0,
                false,
                refs,
                List.of(r.owner.entry(r.dataKey, 0, home)),
                List.of());
        r.tip = AvpManifest.sign(state, r.owner.seed);
        r.genesis = r.tip;
        r.root = commitOn(r.tip, r.dataKey, r.owner.seed, List.of(), EMPTY_PAYLOAD);
        return r;
    }

    /** The api tests' genesis: the owner is homed on the first host. */
    private static Repo apiGenesis(byte[]... hosts) throws AvpException {
        return genesis(hosts[0], hosts);
    }

    private static Object createBody(Repo repo) {
        return obj("manifest", AvpManifest.toJson(repo.tip), "commit", AvpCommit.toJson(repo.root));
    }

    private static AvpTokens.LeaveRequest leaveRequest(Repo repo, byte[] memberSeed) throws AvpException {
        return AvpTokens.signLeave(repo.id(), nowMs(), memberSeed);
    }

    /**
     * An epoch-raising state on {@code repo}'s tip that keeps {@code members} (owner first), optionally
     * removing one with a frontier, and its rotation commit with {@code parents} (SPEC 8.3).
     */
    private record Rotation(AvpManifest.SignedManifest state, AvpCommit.Commit commit, byte[] dataKey) {}

    private static Rotation rotation(
            Repo repo, List<Device> members, Device removed, List<byte[]> frontier, List<byte[]> parents, byte[] home)
            throws AvpException {
        byte[] newKey = AvpCrypto.randomBytes(32);
        long epoch = repo.tip.state().keyEpoch() + 1;
        List<AvpManifest.MemberEntry> entries = new ArrayList<>();
        for (Device d : members) {
            entries.add(d.entry(newKey, epoch, home));
        }
        AvpManifest.SignedManifest state = repo.next(s -> {
            s.epoch = epoch;
            s.members = entries;
            if (removed != null) {
                s.removals.add(new AvpManifest.Removal(removed.key(), s.seq, frontier));
            }
        });
        AvpCommit.Commit commit = commitOn(state, newKey, repo.owner.seed, parents, bytes("rotation"));
        return new Rotation(state, commit, newKey);
    }

    /** The first of {@code make(0)}, {@code make(1)}, ... whose state hash has a first byte of at least 0x80. */
    private static <T> T upperHalf(IntFunctionX<T> make, Function<T, AvpManifest.SignedManifest> state)
            throws AvpException {
        for (int n = 0; n < 64; n++) {
            T t = make.apply(n);
            if ((hash(state.apply(t))[0] & 0xff) >= 0x80) {
                return t;
            }
        }
        throw new AssertionError("no upper-half variant found");
    }

    private interface IntFunctionX<T> {
        T apply(int n) throws AvpException;
    }

    /** A state on {@code repo}'s tip that wins the tie rule against {@code loser} (SPEC 6.5). */
    private static AvpManifest.SignedManifest winnerAgainst(Repo repo, AvpManifest.SignedManifest loser)
            throws AvpException {
        for (int n = 0; n < 256; n++) {
            int k = n;
            AvpManifest.SignedManifest w = repo.next(s -> s.relocate(0, "v" + k + ".vault.example"));
            if (AvpEncoding.compare(hash(w), hash(loser)) < 0) {
                return w;
            }
        }
        throw new AssertionError("no winning variant found");
    }

    /** A losing epoch-raising seq 2 with its rotation commit and data key, in the upper hash half. */
    private static Rotation losingRaise(Repo repo, byte[] home) throws AvpException {
        return upperHalf(
                n -> {
                    byte[] newKey = AvpCrypto.randomBytes(32);
                    AvpManifest.MemberEntry entry = repo.owner.entry(newKey, 1, home);
                    AvpManifest.SignedManifest state = repo.next(s -> {
                        s.epoch = 1;
                        s.members = new ArrayList<>(List.of(entry));
                        s.relocate(s.hosts.size() - 1, "l" + n + ".vault.example");
                    });
                    AvpCommit.Commit commit =
                            commitOn(state, newKey, repo.owner.seed, List.of(repo.root.commitId()), bytes("rotation"));
                    return new Rotation(state, commit, newKey);
                },
                Rotation::state);
    }

    // ─── Harness ────────────────────────────────────────────────────────────────────────

    /** One HTTP reply: the status, the raw body, and the parsed JSON body ({@code null} when empty). */
    private record Reply(int status, String body, Object json) {
        Object at(String key) {
            return json instanceof Map<?, ?> m ? m.get(key) : null;
        }
    }

    /** A running host. */
    private static final class Node {
        final byte[] seed;
        final HttpServer http;
        final Server.Host st;
        final List<String> bodies = new ArrayList<>();

        Node(Server.ServerConfig cfg) throws IOException {
            this.seed = cfg.hostSeed();
            this.http = Server.start(0, cfg);
            this.st = Server.host(http);
            STARTED.add(this);
        }

        byte[] key() {
            return pk(seed);
        }

        int port() {
            return http.getAddress().getPort();
        }

        String entry() {
            return b64(key()) + "@http://127.0.0.1:" + port();
        }

        void peerWith(String... entries) throws AvpException {
            Server.peerWith(http, Replication.Peers.fromEnv(String.join(",", entries)));
        }

        void unpeer() throws AvpException {
            Server.peerWith(http, Replication.Peers.fromEnv(""));
        }

        void stop() {
            Server.stop(http);
        }

        Reply raw(String method, String path, String token, byte[] body, String extra) throws IOException {
            StringBuilder head = new StringBuilder();
            head.append(method).append(' ').append(path).append(" HTTP/1.1\r\nHost: vault.example\r\n");
            head.append("Connection: close\r\n");
            if (!extra.contains("Transfer-Encoding")) {
                head.append("Content-Length: ").append(body.length).append("\r\n");
            }
            head.append("Content-Type: application/json\r\n").append(extra);
            if (token != null) {
                head.append("Authorization: Bearer ").append(token).append("\r\n");
            }
            head.append("\r\n");
            Reply r = rawCall(port(), head.toString(), body);
            synchronized (bodies) {
                bodies.add(r.body);
            }
            return r;
        }

        Reply post(String path, String token, Object body) throws IOException {
            return raw("POST", path, token, AvpJson.writeUtf8(body), "");
        }

        Reply get(String path) throws IOException {
            return raw("GET", path, null, new byte[0], "");
        }

        Reply hosted(String path, List<String[]> headers, byte[] body) throws IOException {
            StringBuilder extra = new StringBuilder();
            for (String[] hd : headers) {
                extra.append(hd[0]).append(": ").append(hd[1]).append("\r\n");
            }
            return raw("POST", path, null, body, extra.toString());
        }

        /** A signed host request from {@code peer} (SPEC 9.3), timestamped now. */
        Reply host(byte[] peer, String repo, String op, Object body) throws IOException {
            String path = hostPath(repo, op);
            byte[] b = AvpJson.writeUtf8(body);
            return hosted(path, hostHeaders(peer, "POST", path, b, nowMs()), b);
        }

        String challenge(byte[] key) throws IOException {
            Reply r = post("/api/auth/keypair/challenge", null, obj("ed25519PublicKey", b64(pk(key))));
            eq(r.status, 200, "challenge: " + r.body);
            return (String) r.at("nonce");
        }

        Reply redeem(byte[] key, String nonce, byte[] signature) throws IOException {
            return post(
                    "/api/auth/keypair/token",
                    null,
                    obj("ed25519PublicKey", b64(pk(key)), "nonce", nonce, "signature", b64(signature)));
        }

        /** The challenge and token flow of SPEC 3.3; returns the bearer token. */
        String login(byte[] key) throws Exception {
            String nonce = challenge(key);
            Reply r = redeem(key, nonce, sign(key, unb64(nonce)));
            eq(r.status, 200, "token: " + r.body);
            return (String) r.at("token");
        }

        void advanceClock(long ms) {
            st.lock();
            try {
                st.clockOffsetMs += ms;
            } finally {
                st.unlock();
            }
        }

        /** Freezes the host's clock at {@code ms} (epoch milliseconds), or lets it run again for {@code null}. */
        void freezeClock(Long ms) {
            st.lock();
            try {
                st.fixedNowMs = ms;
            } finally {
                st.unlock();
            }
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

        boolean holds(String repo) {
            return view(repo, v -> Boolean.TRUE).isPresent();
        }

        List<String> heads(String repo) {
            return view(repo, v -> b64s(v.heads().toArray(new byte[0][]))).orElse(List.of());
        }

        Optional<String> tipHash(String repo) {
            return view(repo, v -> v.tip().map(SmokeTest::h).orElse(null));
        }

        void pause(boolean paused) throws IOException {
            Reply r = post("/v1/test/replication", null, obj("paused", paused));
            eq(r.status, 200, "test control: " + r.body);
        }

        long engineApplications() {
            st.lock();
            try {
                return st.engineApplications;
            } finally {
                st.unlock();
            }
        }

        int repoCount() {
            st.lock();
            try {
                return st.repos.size();
            } finally {
                st.unlock();
            }
        }
    }

    /** The api tests' host: default settings, no peers. */
    private static Node start() throws IOException {
        return start(l -> {});
    }

    private static Node start(Consumer<Server.Limits> limits) throws IOException {
        Server.Limits l = new Server.Limits();
        limits.accept(l);
        return new Node(new Server.ServerConfig(
                "127.0.0.1", seed(), Replication.Peers.none(), l, Replication.Config.defaults()));
    }

    /** The replication tests' host: 100 ms sweeps, 1 s timeouts, 256 KiB answers, test control on. */
    private static Node node() throws IOException {
        return nodeCfg(true, l -> {});
    }

    private static Node nodeCfg(boolean testControl, Consumer<Server.Limits> limits) throws IOException {
        Server.Limits l = new Server.Limits();
        limits.accept(l);
        return new Node(new Server.ServerConfig(
                "127.0.0.1",
                seed(),
                Replication.Peers.none(),
                l,
                new Replication.Config(SWEEP_MS, 1000, 256 * 1024, testControl)));
    }

    /** Peers every node with every other one ({@code AVP_PEERS} built from their keys and addresses). */
    private static void link(Node... nodes) throws AvpException {
        for (Node n : nodes) {
            List<String> others = new ArrayList<>();
            for (Node o : nodes) {
                if (o != n) {
                    others.add(o.entry());
                }
            }
            n.peerWith(others.toArray(new String[0]));
        }
    }

    /** A test-held host key listed in a host's {@code AVP_PEERS} at an address nothing listens on. */
    private static final class FakePeer {
        final byte[] seed = SmokeTest.seed();

        byte[] key() {
            return pk(seed);
        }

        String entry() {
            return b64(key()) + "@http://127.0.0.1:9";
        }
    }

    /**
     * A test-held host key listed in a host's {@code AVP_PEERS} at an address where the test listens: it
     * records the path of every request it gets and answers {@code 403 forbidden}, as a host that does not
     * list the caller would.
     */
    private static final class RecordingPeer implements AutoCloseable {
        final byte[] seed = SmokeTest.seed();
        final List<String> paths = new ArrayList<>();
        final HttpServer http;

        RecordingPeer() throws IOException {
            http = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            http.createContext("/", ex -> {
                synchronized (paths) {
                    paths.add(ex.getRequestURI().getRawPath());
                }
                ex.getRequestBody().readAllBytes();
                byte[] answer = "{\"error\":\"forbidden\",\"code\":\"forbidden\"}".getBytes(StandardCharsets.UTF_8);
                ex.getResponseHeaders().set("Content-Type", "application/json");
                ex.sendResponseHeaders(403, answer.length);
                try (OutputStream out = ex.getResponseBody()) {
                    out.write(answer);
                }
            });
            http.start();
        }

        String entry() {
            return b64(pk(seed)) + "@http://127.0.0.1:" + http.getAddress().getPort();
        }

        List<String> paths() {
            synchronized (paths) {
                return new ArrayList<>(paths);
            }
        }

        @Override
        public void close() {
            http.stop(0);
        }
    }

    private record Faked(Node b, FakePeer p) {}

    /** A host peered only with a fake peer. */
    private static Faked nodeWithFake() throws Exception {
        Node b = node();
        FakePeer p = new FakePeer();
        b.peerWith(p.entry());
        return new Faked(b, p);
    }

    private static Reply rawCall(int port, String head, byte[] body) throws IOException {
        try (Socket s = new Socket("127.0.0.1", port)) {
            s.setSoTimeout(30_000);
            OutputStream out = s.getOutputStream();
            out.write(head.getBytes(StandardCharsets.ISO_8859_1));
            try {
                // The host may answer and close before reading an oversize body; a failed write is fine.
                out.write(body);
                out.flush();
            } catch (IOException e) {
                // Expected for an oversize body.
            }
            ByteArrayOutputStream got = new ByteArrayOutputStream();
            InputStream in = s.getInputStream();
            byte[] buf = new byte[65536];
            try {
                int n;
                while ((n = in.read(buf)) > 0) {
                    got.write(buf, 0, n);
                }
            } catch (IOException e) {
                // A reset after the answer is not an error for the test.
            }
            String text = got.toString(StandardCharsets.UTF_8);
            int split = text.indexOf("\r\n\r\n");
            if (split < 0) {
                throw new AssertionError("no header/body split in reply: " + text);
            }
            String headers = text.substring(0, split);
            String rest = text.substring(split + 4);
            if (headers.toLowerCase(java.util.Locale.ROOT).contains("transfer-encoding: chunked")) {
                rest = dechunk(rest);
            }
            int status = Integer.parseInt(headers.split("\r\n")[0].split(" ")[1]);
            Object json = null;
            if (!rest.isEmpty()) {
                try {
                    json = AvpJson.parse(rest);
                } catch (AvpException e) {
                    // Not JSON: only the JDK's own request-line rejection answers so; assertions on the
                    // body then fail on the missing fields.
                    json = null;
                }
            }
            return new Reply(status, rest, json);
        }
    }

    private static String dechunk(String rest) {
        StringBuilder out = new StringBuilder();
        while (true) {
            int nl = rest.indexOf("\r\n");
            if (nl < 0) {
                break;
            }
            int n = Integer.parseInt(rest.substring(0, nl).trim(), 16);
            if (n == 0) {
                break;
            }
            out.append(rest, nl + 2, nl + 2 + n);
            rest = rest.substring(nl + 4 + n);
        }
        return out.toString();
    }

    private static String hostPath(String repo, String op) {
        return "/v1/host/repos/" + repo + "/" + op;
    }

    /**
     * {@code AVP-Host-Signature} built here from the SPEC 9.3 layout, independently of the host: {@code
     * CE(tag "avp/host-req/v1", str(method), str(path), bytes(SHA-256(body)), i64(time))}.
     */
    private static String hostSignature(byte[] key, String method, String path, byte[] body, long time)
            throws AvpException {
        byte[] message = AvpEncoding.tag("avp/host-req/v1")
                .str(method)
                .str(path)
                .bytes(AvpCrypto.sha256(body))
                .i64(time)
                .finish();
        return b64(sign(key, message));
    }

    private static List<String[]> hostHeaders(byte[] key, String method, String path, byte[] body, long time) {
        try {
            List<String[]> h = new ArrayList<>();
            h.add(new String[] {"AVP-Host-Key", b64(pk(key))});
            h.add(new String[] {"AVP-Host-Time", Long.toString(time)});
            h.add(new String[] {"AVP-Host-Signature", hostSignature(key, method, path, body, time)});
            return h;
        } catch (AvpException e) {
            throw new IllegalStateException(e);
        }
    }

    private record Created(Repo repo, String token) {}

    /** Creates a repository on {@code host} and returns it with the owner's token. */
    private static Created created(Node host) throws Exception {
        Repo repo = apiGenesis(host.key());
        String token = host.login(repo.owner.seed);
        Reply r = host.post("/v1/repos", token, createBody(repo));
        eq(r.status, 200, "createRepo: " + r.body);
        return new Created(repo, token);
    }

    /** Creates {@code repo} on {@code node} through {@code createRepo} and returns the owner's token there. */
    private static String create(Node node, Repo repo) throws Exception {
        String token = node.login(repo.owner.seed);
        Reply r = node.post("/v1/repos", token, createBody(repo));
        eq(r.status, 200, "createRepo: " + r.body);
        return token;
    }

    /** Publishes a state that adds {@code who} as a member (SPEC 8.1). */
    private static void addMember(Node host, Repo repo, String token, Device who) throws Exception {
        AvpManifest.MemberEntry entry = who.entry(repo.dataKey, repo.tip.state().keyEpoch(), host.key());
        AvpManifest.SignedManifest next = repo.next(s -> s.members.add(entry));
        Reply r = host.post(repo.path("manifest"), token, obj("manifest", AvpManifest.toJson(next)));
        eq(r.status, 200, "publishManifest: " + r.body);
        repo.tip = next;
    }

    private static Reply publish(Node node, Repo repo, String token, AvpManifest.SignedManifest m, AvpCommit.Commit c)
            throws IOException {
        Map<String, Object> body = obj("manifest", AvpManifest.toJson(m));
        if (c != null) {
            body.put("commit", AvpCommit.toJson(c));
        }
        return node.post(repo.path("manifest"), token, body);
    }

    private static Reply push(Node host, Repo repo, String token, AvpCommit.Commit c) throws IOException {
        return host.post(repo.path("push"), token, obj("commit", AvpCommit.toJson(c)));
    }

    private static Reply pull(Node host, Repo repo, String token, long since, byte[]... known) throws IOException {
        return host.post(repo.path("pull"), token, obj("sinceManifestSeq", since, "knownHeads", ids(known)));
    }

    private static Reply pull(Node host, Repo repo, String token) throws IOException {
        return pull(host, repo, token, 0);
    }

    private static Object offer(
            String repo,
            List<AvpManifest.SignedManifest> manifests,
            List<AvpCommit.Commit> commits,
            List<AvpTokens.LeaveRequest> leaves) {
        List<Object> ms = new ArrayList<>();
        for (AvpManifest.SignedManifest m : manifests) {
            ms.add(AvpManifest.toJson(m));
        }
        List<Object> cs = new ArrayList<>();
        for (AvpCommit.Commit c : commits) {
            cs.add(AvpCommit.toJson(c));
        }
        List<Object> ls = new ArrayList<>();
        for (AvpTokens.LeaveRequest l : leaves) {
            ls.add(AvpTokens.toJson(l));
        }
        return obj("repoId", repo, "manifests", ms, "commits", cs, "leaves", ls);
    }

    private static Object fetchBody(String repo, byte[]... want) {
        return obj("repoId", repo, "ids", ids(want));
    }

    // ─── A full rendering of host state, for "nothing changed" and zero-knowledge checks ──

    /**
     * Renders an object graph in full: records by component, other objects by every declared field (read
     * reflectively), maps sorted by key, byte arrays as hex. It is the Java counterpart of the Rust
     * tests' {@code format!("{v:?}")} of a view or the store.
     */
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
                TreeMap<String, String> sorted = new TreeMap<>();
                for (Map.Entry<?, ?> e : m.entrySet()) {
                    StringBuilder v = new StringBuilder();
                    dump(e.getValue(), v, seen);
                    sorted.put(dump(e.getKey()), v.toString());
                }
                sb.append(sorted);
            } else if (o instanceof Set<?> set) {
                List<String> items = new ArrayList<>();
                for (Object x : set) {
                    items.add(dump(x));
                }
                items.sort(null);
                sb.append(items);
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

    private static String viewDump(Node n, String repo) {
        return n.view(repo, SmokeTest::dump).orElse("<none>");
    }

    // ═══ tests/api.rs ═══════════════════════════════════════════════════════════════════

    private static void createPullPushRoundtrip() throws Exception {
        Node host = start();
        Created cr = created(host);
        Repo repo = cr.repo();
        String token = cr.token();

        // Another owner's genesis: the caller is not its ownerKey.
        Reply r = host.post("/v1/repos", token, createBody(apiGenesis(host.key())));
        assertError(r, 403, "forbidden");

        r = pull(host, repo, token, 0);
        eq(r.status, 200, "pull");
        eq(r.json, j(obj("manifests", list(mj(repo.tip)), "heads", list(cj(repo.root)), "leaves", list())), "pull");

        AvpCommit.Commit child = repo.commit(repo.owner.seed, List.of(repo.root.commitId()), EMPTY_PAYLOAD);
        r = push(host, repo, token, child);
        eq(r.status, 200, "push");
        eq(r.json, j(obj("accepted", true, "heads", ids(child.commitId()))), "push answer");

        // A push of a commit the host already holds is accepted again with no change (SPEC 7, 12.3).
        r = push(host, repo, token, child);
        eq(r.json, j(obj("accepted", true, "heads", ids(child.commitId()))), "repeated push");

        r = pull(host, repo, token, 1, child.commitId());
        eq(r.json, j(obj("manifests", list(), "heads", list(), "leaves", list())), "pull in step");
        r = pull(host, repo, token, 1, repo.root.commitId());
        eq(r.at("heads"), list(cj(child)), "pull behind");
    }

    private static void createReturnsTheGenesisState() throws Exception {
        Node host = start();
        Repo repo = apiGenesis(host.key());
        String token = host.login(repo.owner.seed);
        Reply r = host.post("/v1/repos", token, createBody(repo));
        eq(r.status, 200, "status");
        eq(r.json, mj(repo.tip), "answer");
    }

    private static void createRejectedWhenHostNotListed() throws Exception {
        Node host = start();
        byte[] other = pk(seed());
        Repo repo = apiGenesis(other);
        String token = host.login(repo.owner.seed);
        assertError(host.post("/v1/repos", token, createBody(repo)), 403, "not_hosted");
        eq(host.repoCount(), 0, "nothing stored");
    }

    private static void pushConcurrentGivesTwoHeads() throws Exception {
        Node host = start();
        Created cr = created(host);
        Repo repo = cr.repo();
        AvpCommit.Commit a =
                repo.commit(repo.owner.seed, List.of(repo.root.commitId()), bytes("{\"v\":2,\"accounts\":{\"a\":1}}"));
        AvpCommit.Commit b =
                repo.commit(repo.owner.seed, List.of(repo.root.commitId()), bytes("{\"v\":2,\"accounts\":{\"b\":1}}"));
        eq(push(host, repo, cr.token(), a).status, 200, "push a");
        Reply r = push(host, repo, cr.token(), b);
        eq(r.status, 200, "push b");
        eq(r.json, j(obj("accepted", true, "heads", sortedB64(a.commitId(), b.commitId()))), "two heads");
        r = pull(host, repo, cr.token(), 1);
        eq(((List<?>) r.at("heads")).size(), 2, "pulled heads");
    }

    private static void pushBeyondBoundIsTooManyHeads() throws Exception {
        Node host = start();
        Created cr = created(host);
        Repo repo = cr.repo();
        List<byte[]> heads = new ArrayList<>();
        for (int i = 0; i < 16; i++) {
            AvpCommit.Commit c = repo.commit(repo.owner.seed, List.of(repo.root.commitId()), bytes("" + i));
            eq(push(host, repo, cr.token(), c).status, 200, "head " + i);
            heads.add(c.commitId());
        }
        // A 17th head would leave more than the bound of 16 (SPEC 7.4).
        AvpCommit.Commit c = repo.commit(repo.owner.seed, List.of(repo.root.commitId()), bytes("17"));
        assertError(push(host, repo, cr.token(), c), 409, "too_many_heads");
        // A merge at the bound reduces the heads and is accepted.
        AvpCommit.Commit merge = repo.commit(repo.owner.seed, heads, bytes("merge"));
        Reply r = push(host, repo, cr.token(), merge);
        eq(r.json, j(obj("accepted", true, "heads", ids(merge.commitId()))), "merge");
    }

    private static void publishManifestWrongSeqIsConflict() throws Exception {
        Node host = start();
        Created cr = created(host);
        Repo repo = cr.repo();
        String token = cr.token();
        Device bob = new Device();

        // seq 3 on a tip at seq 1.
        AvpManifest.SignedManifest skip = repo.next(s -> s.seq = 3);
        assertError(publish(host, repo, token, skip, null), 409, "manifest_conflict");

        addMember(host, repo, token, bob);
        eq(repo.tip.state().manifestSeq(), 2L, "seq");

        // A retry of the published state after success (SPEC 12.3).
        assertError(publish(host, repo, token, repo.tip, null), 409, "manifest_conflict");

        // seq 3 whose prevManifestHash is not the tip's.
        S s = S.of(repo.tip.state());
        s.seq = 3;
        byte[] sevens = new byte[32];
        Arrays.fill(sevens, (byte) 7);
        s.prev = sevens;
        s.share = true;
        assertError(publish(host, repo, token, s.sign(repo.owner.seed), null), 409, "manifest_conflict");

        // tip + 1 linked to the tip is accepted and answers the stored state.
        AvpManifest.SignedManifest ok = repo.next(x -> x.share = true);
        Reply r = publish(host, repo, token, ok, null);
        eq(r.status, 200, "status");
        eq(r.json, mj(ok), "answer");
    }

    private static void removedMemberPushForbidden() throws Exception {
        Node host = start();
        Created cr = created(host);
        Repo repo = cr.repo();
        String token = cr.token();
        Device bob = new Device();
        addMember(host, repo, token, bob);
        String bobToken = host.login(bob.seed);
        AvpCommit.Commit bobCommit = repo.commit(bob.seed, List.of(repo.root.commitId()), bytes("bob"));
        eq(push(host, repo, bobToken, bobCommit).status, 200, "bob pushes");
        AvpManifest.SignedManifest atSeq2 = repo.tip;
        byte[] oldKey = repo.dataKey;

        // The owner removes bob (SPEC 8.3): new epoch, removal with frontier, rotation commit.
        byte[] newKey = AvpCrypto.randomBytes(32);
        AvpManifest.MemberEntry ownerEntry = repo.owner.entry(newKey, 1, host.key());
        AvpManifest.SignedManifest removed = repo.next(s -> {
            s.epoch = 1;
            s.members = new ArrayList<>(List.of(ownerEntry));
            s.removals = new ArrayList<>(List.of(new AvpManifest.Removal(bob.key(), 3, List.of(bobCommit.commitId()))));
        });
        AvpCommit.Commit rotation =
                commitOn(removed, newKey, repo.owner.seed, List.of(bobCommit.commitId()), bytes("rot"));

        // An epoch-raising state without its rotation commit is bad_request (SPEC 8.3).
        assertError(publish(host, repo, token, removed, null), 400, "bad_request");
        Reply r = publish(host, repo, token, removed, rotation);
        eq(r.status, 200, "publish with rotation: " + r.body);
        repo.tip = removed;
        repo.dataKey = newKey;

        // Bob backdates a child of his frontier commit citing the old state and epoch: through the client
        // route the 403 comes from the caller check (SPEC 7.1).
        AvpCommit.Commit late = commitOn(atSeq2, oldKey, bob.seed, List.of(bobCommit.commitId()), bytes("late"));
        assertError(push(host, repo, bobToken, late), 403, "forbidden");
        // And he can no longer pull: not a member of the tip.
        assertError(pull(host, repo, bobToken, 0), 403, "forbidden");
        eq(pull(host, repo, token, 0).at("heads"), list(cj(rotation)), "heads");
    }

    private static void leaveIsServedInPull() throws Exception {
        Node host = start();
        Created cr = created(host);
        Repo repo = cr.repo();
        Device bob = new Device();
        addMember(host, repo, cr.token(), bob);
        String bobToken = host.login(bob.seed);
        AvpTokens.LeaveRequest leave = leaveRequest(repo, bob.seed);
        Reply r = host.post(repo.path("leave"), bobToken, AvpTokens.toJson(leave));
        eq(r.status, 200, "leave");
        eq(r.json, j(obj()), "leave answer");
        // leave is idempotent (SPEC 12.3).
        eq(host.post(repo.path("leave"), bobToken, AvpTokens.toJson(leave)).status, 200, "leave again");

        r = pull(host, repo, cr.token(), 2, repo.root.commitId());
        eq(r.json, j(obj("manifests", list(), "heads", list(), "leaves", list(lj(leave)))), "pull");
    }

    private static void prepareJoinAcceptanceVerifies() throws Exception {
        Node host = start();
        byte[] carol = seed();
        String token = host.login(carol);
        String repoId = apiGenesis(host.key()).id();
        long before = nowMs();
        Reply r = host.post("/v1/prepare-join", token, obj("repoId", repoId, "memberKey", b64(pk(carol))));
        long after = nowMs();
        eq(r.status, 200, "status: " + r.body);
        eq(((Map<?, ?>) r.json).keySet(), Set.of("repoId", "memberKey", "hostKey", "expiresAt", "signature"), "keys");

        Reply disco = host.get("/.well-known/avp");
        byte[] hostKey = AvpEncoding.fromBase64((String) disco.at("hostKey"), 32);
        AvpTokens.Acceptance acc = AvpTokens.acceptanceFromJson(r.json);
        eq(acc.repoId(), repoId, "repoId");
        eq(b64(acc.memberKey()), b64(pk(carol)), "memberKey");
        eq(b64(acc.hostKey()), b64(hostKey), "hostKey");

        // expiresAt = now + 15 min (SPEC 8.2: the reference hosts use 15 minutes).
        long fifteen = 15 * 60 * 1000;
        isTrue(acc.expiresAt() >= before + fifteen && acc.expiresAt() <= after + fifteen, "expiresAt");

        // The signature verifies under the discovery hostKey over the CE message of plan-header.md.
        byte[] message = AvpEncoding.tag("avp/accept/v1")
                .str(repoId)
                .bytes(pk(carol))
                .bytes(hostKey)
                .i64(acc.expiresAt())
                .finish();
        isTrue(AvpCrypto.ed25519Verify(hostKey, message, acc.signature()), "acceptance signature");

        // The host records the acceptance it issued (SPEC 8.2).
        host.st.lock();
        try {
            eq(host.st.pendingJoin.get(Server.joinKey(repoId, pk(carol))), acc.expiresAt(), "recorded");
        } finally {
            host.st.unlock();
        }
    }

    private static void tokenRequired() throws Exception {
        Node host = start();
        Created cr = created(host);
        Repo repo = cr.repo();
        AvpTokens.LeaveRequest leave = leaveRequest(repo, repo.owner.seed);
        List<Object[]> cases = List.of(
                new Object[] {"/v1/repos", createBody(apiGenesis(host.key()))},
                new Object[] {repo.path("pull"), obj("sinceManifestSeq", 0, "knownHeads", list())},
                new Object[] {repo.path("push"), obj("commit", AvpCommit.toJson(repo.root))},
                new Object[] {repo.path("manifest"), obj("manifest", AvpManifest.toJson(repo.tip))},
                new Object[] {repo.path("leave"), AvpTokens.toJson(leave)},
                new Object[] {"/v1/prepare-join", obj("repoId", repo.id(), "memberKey", b64(repo.owner.key()))});
        for (Object[] c : cases) {
            String path = (String) c[0];
            assertError(host.post(path, null, c[1]), 401, "unauthorized");
            assertError(host.post(path, "not-a-token", c[1]), 401, "unauthorized");
            Reply r = host.raw(
                    "POST", path, null, AvpJson.writeUtf8(c[1]), "Authorization: Basic " + cr.token() + "\r\n");
            assertError(r, 401, "unauthorized");
        }
        // The valid token still works.
        eq(pull(host, repo, cr.token(), 0).status, 200, "valid token");
    }

    private static void serverNeverSeesPlaintext() throws Exception {
        String marker = "PLAINTEXT-MARKER-alice-alt-7f3c9e1b";
        Node host = start();
        Created cr = created(host);
        Repo repo = cr.repo();
        Device bob = new Device();
        addMember(host, repo, cr.token(), bob);
        String bobToken = host.login(bob.seed);

        String plaintext = "{\"v\":2,\"accounts\":{\"u1\":{\"fields\":{\"username\":{\"value\":\"" + marker
                + "\",\"at\":1,\"n\":0,\"by\":\"alice\"}},\"bans\":{}}}}";
        AvpCommit.Commit c = repo.commit(repo.owner.seed, List.of(repo.root.commitId()), bytes(plaintext));
        eq(new String(AvpCommit.open(c, repo.dataKey), StandardCharsets.UTF_8), plaintext, "sealed the marker");
        eq(push(host, repo, cr.token(), c).status, 200, "push");
        Reply r = pull(host, repo, bobToken, 0);
        eq(r.status, 200, "pull");
        AvpTokens.LeaveRequest leave = leaveRequest(repo, bob.seed);
        eq(host.post(repo.path("leave"), bobToken, AvpTokens.toJson(leave)).status, 200, "leave");

        // Every response body: no marker as text, and every served ciphertext lacks the marker bytes.
        synchronized (host.bodies) {
            for (String body : host.bodies) {
                isTrue(!body.contains(marker), "response body leaks the plaintext");
            }
        }
        String markerHex = AvpEncoding.hex(bytes(marker));
        for (Object head : (List<?>) r.at("heads")) {
            byte[] ct = unb64(((Map<?, ?>) head).get("ciphertext"));
            isTrue(!AvpEncoding.hex(ct).contains(markerHex), "served ciphertext holds the marker");
        }

        // Everything the store holds, rendered in full: neither the marker (as text or as bytes) nor any
        // data key is in it.
        host.st.lock();
        String rendered;
        try {
            rendered = dump(host.st.storeParts());
        } finally {
            host.st.unlock();
        }
        isTrue(rendered.contains(AvpEncoding.hex(c.ciphertext())), "the dump renders stored bytes");
        isTrue(!rendered.contains(marker), "store holds the marker text");
        isTrue(!rendered.contains(markerHex), "store holds the marker bytes");
        isTrue(!rendered.contains(AvpEncoding.hex(repo.dataKey)), "the host never holds a data key");
    }

    private static void discoveryReports() throws Exception {
        byte[] fixedSeed = new byte[32];
        Arrays.fill(fixedSeed, (byte) 0x11);
        Node host = start();
        Reply r = host.get("/.well-known/avp");
        eq(r.status, 200, "status");
        eq(r.json, j(obj("version", "0.5", "profiles", list("http-json"), "hostKey", b64(host.key()))), "body");

        // AVP_HOST_SEED (hex, 32 bytes) fixes the host identity.
        eq(b64(Server.parseHostSeed("11".repeat(32))), b64(fixedSeed), "parsed seed");
        for (String bad : List.of("11", "zz".repeat(32))) {
            try {
                Server.parseHostSeed(bad);
                throw new AssertionError("accepted seed " + bad);
            } catch (IllegalArgumentException e) {
                // Expected.
            }
        }
        Server.ServerConfig cfg = new Server.ServerConfig(
                "127.0.0.1", fixedSeed, Replication.Peers.none(), new Server.Limits(), Replication.Config.defaults());
        Node fixed = new Node(cfg);
        eq(fixed.get("/.well-known/avp").at("hostKey"), b64(pk(fixedSeed)), "fixed host key");
    }

    private static void challengeNonceIs32RandomBytes() throws Exception {
        Node host = start();
        byte[] key = seed();
        byte[] a = unb64(host.challenge(key));
        byte[] b = unb64(host.challenge(key));
        isTrue(a.length >= 32 && b.length >= 32, "length");
        isTrue(!Arrays.equals(a, b), "distinct");
    }

    private static void tokenResponseHasTokenAndExpiry() throws Exception {
        Node host = start();
        byte[] key = seed();
        String nonce = host.challenge(key);
        Reply r = host.redeem(key, nonce, sign(key, unb64(nonce)));
        eq(r.status, 200, "status");
        eq(((Map<?, ?>) r.json).keySet(), Set.of("token", "expiresAt"), "keys");
        isTrue((Long) r.at("expiresAt") > nowMs(), "expiry in the future");
    }

    private static void expiredChallengeIsUnauthorized() throws Exception {
        Node host = start();
        byte[] key = seed();
        String nonce = host.challenge(key);
        // The challenge TTL is 2 minutes (SPEC 3.3 RECOMMENDED at most 2 minutes).
        host.advanceClock(2 * 60 * 1000 + 1);
        assertError(host.redeem(key, nonce, sign(key, unb64(nonce))), 401, "unauthorized");
    }

    private static void reusedChallengeIsUnauthorized() throws Exception {
        Node host = start();
        byte[] key = seed();
        String nonce = host.challenge(key);
        byte[] sig = sign(key, unb64(nonce));
        eq(host.redeem(key, nonce, sig).status, 200, "first use");
        assertError(host.redeem(key, nonce, sig), 401, "unauthorized");
    }

    private static void badChallengeSignatureIsUnauthorized() throws Exception {
        Node host = start();
        byte[] key = seed();
        String nonce = host.challenge(key);
        // Signing the base64 text instead of the raw nonce bytes.
        assertError(host.redeem(key, nonce, sign(key, bytes(nonce))), 401, "unauthorized");
        // A failed attempt consumes the nonce: it is single-use.
        assertError(host.redeem(key, nonce, sign(key, unb64(nonce))), 401, "unauthorized");
        // A signature by another key.
        String nonce2 = host.challenge(key);
        assertError(host.redeem(key, nonce2, sign(seed(), unb64(nonce2))), 401, "unauthorized");
        // A nonce the host never issued.
        String fake = b64(AvpCrypto.randomBytes(32));
        assertError(host.redeem(key, fake, sign(key, unb64(fake))), 401, "unauthorized");
    }

    private static void challengeForAnotherKeyIsUnauthorized() throws Exception {
        Node host = start();
        byte[] alice = seed();
        byte[] mallory = seed();
        String nonce = host.challenge(alice);
        // Mallory signs alice's nonce correctly with her own key: not issued for that key.
        assertError(host.redeem(mallory, nonce, sign(mallory, unb64(nonce))), 401, "unauthorized");
    }

    private static void tokenOfAnotherHostIsUnauthorized() throws Exception {
        Node a = start();
        Node b = start();
        Created cr = created(a);
        String tokenB = b.login(cr.repo().owner.seed);
        assertError(pull(a, cr.repo(), tokenB, 0), 401, "unauthorized");
    }

    private static void expiredTokenIsUnauthorized() throws Exception {
        Node host = start();
        Created cr = created(host);
        host.advanceClock(15 * 60 * 1000 + 1);
        assertError(pull(host, cr.repo(), cr.token(), 0), 401, "unauthorized");
    }

    private static void malformedAuthBodiesAreBadRequest() throws Exception {
        Node host = start();
        assertError(host.post("/api/auth/keypair/challenge", null, obj("ed25519PublicKey", "%%%")), 400, "bad_request");
        assertError(
                host.post("/api/auth/keypair/challenge", null, obj("ed25519PublicKey", b64(filled(31, 1)))),
                400,
                "bad_request");
        assertError(
                host.post("/api/auth/keypair/token", null, obj("ed25519PublicKey", b64(filled(32, 1)))),
                400,
                "bad_request");
        assertError(host.raw("POST", "/api/auth/keypair/challenge", null, bytes("{not json"), ""), 400, "bad_request");
    }

    private static byte[] filled(int len, int value) {
        byte[] b = new byte[len];
        Arrays.fill(b, (byte) value);
        return b;
    }

    private static void createByNonOwnerIsForbidden() throws Exception {
        Node host = start();
        Repo repo = apiGenesis(host.key());
        String mallory = host.login(seed());
        assertError(host.post("/v1/repos", mallory, createBody(repo)), 403, "forbidden");
        eq(host.repoCount(), 0, "nothing stored");
    }

    private static void publishByNonOwnerIsForbidden() throws Exception {
        Node host = start();
        Created cr = created(host);
        Repo repo = cr.repo();
        Device bob = new Device();
        addMember(host, repo, cr.token(), bob);
        String bobToken = host.login(bob.seed);
        AvpManifest.SignedManifest next = repo.next(s -> s.share = true);
        assertError(publish(host, repo, bobToken, next, null), 403, "forbidden");
        String outsider = host.login(seed());
        assertError(publish(host, repo, outsider, next, null), 403, "forbidden");
    }

    private static void pullByNonMemberIsForbidden() throws Exception {
        Node host = start();
        Created cr = created(host);
        String outsider = host.login(seed());
        assertError(pull(host, cr.repo(), outsider, 0), 403, "forbidden");
    }

    private static void pushByNonAuthorIsForbidden() throws Exception {
        Node host = start();
        Created cr = created(host);
        Repo repo = cr.repo();
        Device bob = new Device();
        addMember(host, repo, cr.token(), bob);
        AvpCommit.Commit bobCommit = repo.commit(bob.seed, List.of(repo.root.commitId()), bytes("bob"));
        // The owner, a member, pushes a commit authored by bob.
        assertError(push(host, repo, cr.token(), bobCommit), 403, "forbidden");
        // A non-member pushes their own commit.
        Device carol = new Device();
        String carolToken = host.login(carol.seed);
        AvpCommit.Commit c = repo.commit(carol.seed, List.of(repo.root.commitId()), bytes("carol"));
        assertError(push(host, repo, carolToken, c), 403, "forbidden");
        eq(pull(host, repo, cr.token(), 0).at("heads"), list(cj(repo.root)), "heads unchanged");
    }

    private static void leaveForAnotherMemberIsForbidden() throws Exception {
        Node host = start();
        Created cr = created(host);
        Repo repo = cr.repo();
        Device bob = new Device();
        Device carol = new Device();
        addMember(host, repo, cr.token(), bob);
        addMember(host, repo, cr.token(), carol);
        String carolToken = host.login(carol.seed);
        AvpTokens.LeaveRequest bobs = leaveRequest(repo, bob.seed);
        assertError(host.post(repo.path("leave"), carolToken, AvpTokens.toJson(bobs)), 403, "forbidden");
        // The owner cannot leave (SPEC 8.4).
        AvpTokens.LeaveRequest owners = leaveRequest(repo, repo.owner.seed);
        assertError(host.post(repo.path("leave"), cr.token(), AvpTokens.toJson(owners)), 403, "forbidden");
        // A leave request whose signature does not verify.
        AvpTokens.LeaveRequest good = leaveRequest(repo, carol.seed);
        AvpTokens.LeaveRequest forged =
                new AvpTokens.LeaveRequest(good.repoId(), good.memberKey(), good.at() + 1, good.signature());
        assertError(host.post(repo.path("leave"), carolToken, AvpTokens.toJson(forged)), 400, "bad_request");
        eq(pull(host, repo, cr.token(), 0).at("leaves"), list(), "no leaves");
    }

    private static void prepareJoinForAnotherKeyIsForbidden() throws Exception {
        Node host = start();
        byte[] carol = seed();
        String mallory = host.login(seed());
        Reply r = host.post(
                "/v1/prepare-join",
                mallory,
                obj("repoId", apiGenesis(host.key()).id(), "memberKey", b64(pk(carol))));
        assertError(r, 403, "forbidden");
        host.st.lock();
        try {
            isTrue(host.st.pendingJoin.isEmpty(), "nothing recorded");
        } finally {
            host.st.unlock();
        }
    }

    private static void secondCreateIsDuplicateRepo() throws Exception {
        Node host = start();
        Created cr = created(host);
        assertError(host.post("/v1/repos", cr.token(), createBody(cr.repo())), 409, "duplicate_repo");
    }

    private static void unknownRepoIsNotFound() throws Exception {
        Node host = start();
        Created cr = created(host);
        Repo other = apiGenesis(host.key());
        AvpTokens.LeaveRequest leave = leaveRequest(other, other.owner.seed);
        Map<String, Object> cases = new LinkedHashMap<>();
        cases.put("pull", obj("sinceManifestSeq", 0, "knownHeads", list()));
        cases.put("push", obj("commit", AvpCommit.toJson(other.root)));
        cases.put("manifest", obj("manifest", AvpManifest.toJson(other.tip)));
        cases.put("leave", AvpTokens.toJson(leave));
        for (Map.Entry<String, Object> e : cases.entrySet()) {
            assertError(host.post(other.path(e.getKey()), cr.token(), e.getValue()), 404, "not_found");
        }
    }

    private static void unknownParentIsMissingParents() throws Exception {
        Node host = start();
        Created cr = created(host);
        Repo repo = cr.repo();
        byte[] p1 = AvpCrypto.randomBytes(32);
        byte[] p2 = AvpCrypto.randomBytes(32);
        AvpCommit.Commit c = repo.commit(repo.owner.seed, List.of(p1, p2), bytes("orphan"));
        Reply r = push(host, repo, cr.token(), c);
        assertError(r, 422, "missing_parents");
        eq(new HashSet<>(Arrays.asList(((String) r.at("detail")).split(","))), b64Set(p1, p2), "detail");

        // A cited manifest state the host does not hold is named by its hash (SPEC 7.2).
        AvpManifest.SignedManifest unknown = repo.next(s -> s.share = true);
        AvpCommit.Commit c2 =
                commitOn(unknown, repo.dataKey, repo.owner.seed, List.of(repo.root.commitId()), bytes("x"));
        r = push(host, repo, cr.token(), c2);
        assertError(r, 422, "missing_parents");
        eq(r.at("detail"), h(unknown), "detail names the state");
    }

    private static void malformedBodiesAreBadRequest() throws Exception {
        Node host = start();
        Created cr = created(host);
        Repo repo = cr.repo();
        String token = cr.token();
        List<String> bad = List.of("{not json", "[]", "{\"commit\":{}}", "{\"sinceManifestSeq\":0}");
        for (String body : bad) {
            for (String path : List.of(
                    repo.path("push"),
                    repo.path("pull"),
                    repo.path("manifest"),
                    repo.path("leave"),
                    "/v1/repos",
                    "/v1/prepare-join")) {
                assertError(host.raw("POST", path, token, bytes(body), ""), 400, "bad_request");
            }
        }
        // Bad base64 in an id list, and an id of the wrong length.
        assertError(
                host.post(repo.path("pull"), token, obj("sinceManifestSeq", 0, "knownHeads", list("%%%"))),
                400,
                "bad_request");
        assertError(
                host.post(repo.path("pull"), token, obj("sinceManifestSeq", 0, "knownHeads", list(b64(filled(31, 1))))),
                400,
                "bad_request");
        // A commit whose signature does not verify.
        AvpCommit.Commit c = repo.commit(repo.owner.seed, List.of(repo.root.commitId()), bytes("x"));
        assertError(push(host, repo, token, withSignature(c, flip(c.authorSignature(), 0))), 400, "bad_request");
        // A commit for another repository.
        Repo other = apiGenesis(host.key());
        assertError(push(host, repo, token, withRepoId(other.root, repo.id())), 400, "bad_request");
        // A repoId in prepareJoin that is not a 22-character base64url id (SPEC 12.4).
        assertError(
                host.post(
                        "/v1/prepare-join", token, obj("repoId", "not-a-repo-id", "memberKey", b64(repo.owner.key()))),
                400,
                "bad_request");
        // A path segment with a bad percent escape. The JDK HTTP server refuses this request line before
        // any handler runs (it is not a valid URI), so the status is 400 but the body is the JDK's.
        eq(host.raw("POST", "/v1/repos/%zz/pull", token, bytes("{}"), "").status, 400, "bad escape status");
        // A genesis whose repoId does not recompute.
        Repo g = apiGenesis(host.key());
        S s = S.of(g.tip.state());
        s.repoId = AvpManifest.deriveRepoId(g.owner.key(), AvpCrypto.randomBytes(16));
        g.tip = s.sign(g.owner.seed);
        String t = host.login(g.owner.seed);
        assertError(host.post("/v1/repos", t, createBody(g)), 400, "bad_request");
    }

    private static void badUtf8PercentEscapeIsBadRequest() throws Exception {
        // A well-formed escape that the JDK server passes through but that decodes to bad UTF-8 reaches the
        // host's own decoder: 400 bad_request (SPEC 10.2, 12.4).
        Node host = start();
        Created cr = created(host);
        assertError(host.raw("POST", "/v1/repos/%C3%28/pull", cr.token(), bytes("{}"), ""), 400, "bad_request");
    }

    private static void percentEncodedRepoIdRoutes() throws Exception {
        Node host = start();
        Created cr = created(host);
        StringBuilder encoded = new StringBuilder();
        for (byte b : bytes(cr.repo().id())) {
            encoded.append(String.format("%%%02X", b));
        }
        Reply r = host.post(
                "/v1/repos/" + encoded + "/pull", cr.token(), obj("sinceManifestSeq", 1, "knownHeads", list()));
        eq(r.status, 200, "status: " + r.body);
    }

    private static void unknownRouteIsNotFound() throws Exception {
        Node host = start();
        assertError(host.get("/v1/nothing"), 404, "not_found");
        assertError(host.get("/v1/repos"), 404, "not_found");
    }

    private static void oversizeBodyIsTooLarge() throws Exception {
        Node host = start();
        Created cr = created(host);
        host.st.lock();
        try {
            host.st.limits.maxBodyBytes = 1024;
        } finally {
            host.st.unlock();
        }
        byte[] big = new byte[4096];
        Arrays.fill(big, (byte) ' ');
        assertError(host.raw("POST", cr.repo().path("push"), cr.token(), big, ""), 413, "too_large");
        // Without Content-Length (chunked), the bounded read still stops at the limit.
        ByteArrayOutputStream chunked = new ByteArrayOutputStream();
        chunked.write(bytes(Integer.toHexString(big.length) + "\r\n"));
        chunked.write(big);
        chunked.write(bytes("\r\n0\r\n\r\n"));
        Reply r = host.raw(
                "POST", cr.repo().path("push"), cr.token(), chunked.toByteArray(), "Transfer-Encoding: chunked\r\n");
        assertError(r, 413, "too_large");
    }

    private static void memberLimitIsQuotaExceeded() throws Exception {
        Node host = start(l -> l.maxMembers = 2);
        Created cr = created(host);
        Repo repo = cr.repo();
        addMember(host, repo, cr.token(), new Device());
        AvpManifest.MemberEntry third = new Device().entry(repo.dataKey, 0, host.key());
        AvpManifest.SignedManifest next = repo.next(s -> s.members.add(third));
        assertError(publish(host, repo, cr.token(), next, null), 429, "quota_exceeded");
    }

    /** A second repository of {@code first}'s owner key, listing {@code hosts}. */
    private static Repo sameOwner(Repo first, byte[] home, byte[]... hosts) throws AvpException {
        Repo second = genesis(home, hosts);
        byte[] nonce = AvpCrypto.randomBytes(16);
        S s = S.of(first.genesis.state());
        s.nonce = nonce;
        s.repoId = AvpManifest.deriveRepoId(first.owner.key(), nonce);
        s.members = new ArrayList<>(List.of(first.owner.entry(second.dataKey, 0, home)));
        s.hosts = new ArrayList<>(second.genesis.state().hosts());
        second.owner = new Device(first.owner.seed);
        second.genesis = s.sign(first.owner.seed);
        second.tip = second.genesis;
        second.root = commitOn(second.genesis, second.dataKey, first.owner.seed, List.of(), EMPTY_PAYLOAD);
        return second;
    }

    private static void repoLimitPerOwnerIsQuotaExceeded() throws Exception {
        Node host = start(l -> l.maxReposPerOwner = 1);
        Created cr = created(host);
        Repo second = sameOwner(cr.repo(), host.key(), host.key());
        assertError(host.post("/v1/repos", cr.token(), createBody(second)), 429, "quota_exceeded");
    }

    private static void challengeCapPerKeyIsQuotaExceeded() throws Exception {
        Node host = start(l -> l.maxChallengesPerKey = 2);
        byte[] key = seed();
        host.challenge(key);
        host.challenge(key);
        Reply r = host.post("/api/auth/keypair/challenge", null, obj("ed25519PublicKey", b64(pk(key))));
        assertError(r, 429, "quota_exceeded");
        eq(r.status, 429, "status");
        // Another key is not affected by this key's cap.
        host.challenge(seed());
        // Expired challenges free their slots.
        host.advanceClock(2 * 60 * 1000 + 1);
        host.challenge(key);
    }

    private static void challengeGlobalCapEvictsTheOldest() throws Exception {
        // One caller filling the global table cannot lock out the next caller: the oldest challenge is
        // evicted instead of answering 429.
        Node host = start(l -> l.maxChallenges = 2);
        byte[] a = seed();
        byte[] b = seed();
        byte[] c = seed();
        String na = host.challenge(a);
        host.advanceClock(1);
        String nb = host.challenge(b);
        host.advanceClock(1);
        String nc = host.challenge(c);
        assertError(host.redeem(a, na, sign(a, unb64(na))), 401, "unauthorized");
        eq(host.redeem(b, nb, sign(b, unb64(nb))).status, 200, "b");
        eq(host.redeem(c, nc, sign(c, unb64(nc))).status, 200, "c");
    }

    private static void tokenCapPerKeyIsQuotaExceeded() throws Exception {
        Node host = start(l -> l.maxTokensPerKey = 2);
        byte[] key = seed();
        host.login(key);
        host.login(key);
        String nonce = host.challenge(key);
        assertError(host.redeem(key, nonce, sign(key, unb64(nonce))), 429, "quota_exceeded");
        // Another key still logs in.
        host.login(seed());
    }

    private static void tokenGlobalCapEvictsTheOldest() throws Exception {
        Node host = start(l -> l.maxTokens = 2);
        Created r1 = created(host);
        host.advanceClock(1);
        Created r2 = created(host);
        host.advanceClock(1);
        Created r3 = created(host);
        assertError(pull(host, r1.repo(), r1.token(), 0), 401, "unauthorized");
        eq(pull(host, r2.repo(), r2.token(), 0).status, 200, "r2");
        eq(pull(host, r3.repo(), r3.token(), 0).status, 200, "r3");
    }

    private static Reply prepare(Node host, byte[] key, String token) throws Exception {
        return host.post(
                "/v1/prepare-join", token, obj("repoId", apiGenesis(host.key()).id(), "memberKey", b64(pk(key))));
    }

    private static void acceptanceCapPerKeyIsQuotaExceeded() throws Exception {
        Node host = start(l -> l.maxPendingJoinsPerKey = 2);
        byte[] carol = seed();
        String token = host.login(carol);
        eq(prepare(host, carol, token).status, 200, "first");
        eq(prepare(host, carol, token).status, 200, "second");
        assertError(prepare(host, carol, token), 429, "quota_exceeded");
        byte[] bob = seed();
        String bobToken = host.login(bob);
        eq(prepare(host, bob, bobToken).status, 200, "another key is not affected");
    }

    private static void acceptanceGlobalCapEvictsTheOldest() throws Exception {
        Node host = start(l -> l.maxPendingJoins = 2);
        List<String> issued = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            byte[] k = seed();
            String t = host.login(k);
            Reply r = prepare(host, k, t);
            eq(r.status, 200, "prepare");
            issued.add(Server.joinKey((String) r.at("repoId"), pk(k)));
            host.advanceClock(1);
        }
        host.st.lock();
        try {
            eq(host.st.pendingJoin.size(), 2, "size");
            isTrue(!host.st.pendingJoin.containsKey(issued.get(0)), "the oldest acceptance is evicted");
            isTrue(host.st.pendingJoin.containsKey(issued.get(1)), "second kept");
            isTrue(host.st.pendingJoin.containsKey(issued.get(2)), "third kept");
        } finally {
            host.st.unlock();
        }
    }

    private static AvpCommit.Commit sealed(byte[] key, AvpCommit.Header header, byte[] dataKey) throws AvpException {
        return AvpCommit.seal(dataKey, header, EMPTY_PAYLOAD, key);
    }

    private static void publishCarriedCommitMissingParent() throws Exception {
        Node host = start();
        Created cr = created(host);
        Repo repo = cr.repo();
        AvpManifest.SignedManifest next = repo.next(s -> s.share = true);
        byte[] unknown = AvpCrypto.randomBytes(32);
        AvpCommit.Commit c = commitOn(next, repo.dataKey, repo.owner.seed, List.of(unknown), bytes("x"));
        Reply r = publish(host, repo, cr.token(), next, c);
        assertError(r, 422, "missing_parents");
        eq(r.at("detail"), b64(unknown), "detail");
        // Nothing was adopted.
        eq(pull(host, repo, cr.token(), 0).at("manifests"), list(mj(repo.tip)), "tip unchanged");
    }

    private static void publishCarriedCommitBeyondBound() throws Exception {
        Node host = start();
        Created cr = created(host);
        Repo repo = cr.repo();
        for (int i = 0; i < 16; i++) {
            AvpCommit.Commit c = repo.commit(repo.owner.seed, List.of(repo.root.commitId()), bytes("" + i));
            eq(push(host, repo, cr.token(), c).status, 200, "head " + i);
        }
        AvpManifest.SignedManifest next = repo.next(s -> s.share = true);
        AvpCommit.Commit c = commitOn(next, repo.dataKey, repo.owner.seed, List.of(repo.root.commitId()), bytes("17"));
        assertError(publish(host, repo, cr.token(), next, c), 409, "too_many_heads");
    }

    private static void createNonGenesisStateIsBadRequest() throws Exception {
        Node host = start();
        Repo repo = apiGenesis(host.key());
        String token = host.login(repo.owner.seed);
        AvpManifest.SignedManifest seq2 = repo.next(s -> s.share = true);
        AvpCommit.Commit c = commitOn(seq2, repo.dataKey, repo.owner.seed, List.of(), EMPTY_PAYLOAD);
        Reply r =
                host.post("/v1/repos", token, obj("manifest", AvpManifest.toJson(seq2), "commit", AvpCommit.toJson(c)));
        assertError(r, 400, "bad_request");
    }

    private static void createFirstCommitRulesAreBadRequest() throws Exception {
        Node host = start();
        Repo repo = apiGenesis(host.key());
        String token = host.login(repo.owner.seed);
        AvpManifest.SignedManifest g = repo.tip;
        byte[] gh = hash(g);
        byte[] owner = repo.owner.seed;
        byte[] dk = repo.dataKey;
        Map<String, AvpCommit.Commit> cases = new LinkedHashMap<>();
        cases.put("has a parent", sealed(owner, new AvpCommit.Header(repo.id(), List.of(filled(32, 5)), 1, gh, 0), dk));
        cases.put(
                "wrong manifest hash",
                sealed(owner, new AvpCommit.Header(repo.id(), List.of(), 1, filled(32, 6), 0), dk));
        cases.put("wrong seq", sealed(owner, new AvpCommit.Header(repo.id(), List.of(), 2, gh, 0), dk));
        cases.put("author not owner", sealed(seed(), new AvpCommit.Header(repo.id(), List.of(), 1, gh, 0), dk));
        cases.put("keyEpoch not 0", sealed(owner, new AvpCommit.Header(repo.id(), List.of(), 1, gh, 1), dk));
        for (Map.Entry<String, AvpCommit.Commit> e : cases.entrySet()) {
            Reply r = host.post(
                    "/v1/repos",
                    token,
                    obj("manifest", AvpManifest.toJson(g), "commit", AvpCommit.toJson(e.getValue())));
            eq(r.status, 400, e.getKey() + ": " + r.body);
            eq(r.at("code"), "bad_request", e.getKey());
        }
        assertError(host.post("/v1/repos", token, obj("manifest", AvpManifest.toJson(g))), 400, "bad_request");
        eq(host.repoCount(), 0, "nothing stored");
    }

    private static void forgedCollidingGenesisIsBadRequest() throws Exception {
        Node host = start();
        Created cr = created(host);
        Repo repo = cr.repo();
        // Mallory reuses the existing repoId under her own owner key: the repoId does not recompute.
        Repo mallory = apiGenesis(host.key());
        S s = S.of(mallory.tip.state());
        s.repoId = repo.id();
        AvpManifest.SignedManifest forged = s.sign(mallory.owner.seed);
        AvpCommit.Commit c = commitOn(forged, mallory.dataKey, mallory.owner.seed, List.of(), EMPTY_PAYLOAD);
        String t = host.login(mallory.owner.seed);
        Reply r = host.post("/v1/repos", t, obj("manifest", AvpManifest.toJson(forged), "commit", AvpCommit.toJson(c)));
        assertError(r, 400, "bad_request");
        // The same genesis with a bad owner signature.
        AvpManifest.SignedManifest badSig =
                new AvpManifest.SignedManifest(repo.tip.state(), flip(repo.tip.ownerSignature(), 0));
        String t2 = host.login(repo.owner.seed);
        r = host.post(
                "/v1/repos", t2, obj("manifest", AvpManifest.toJson(badSig), "commit", AvpCommit.toJson(repo.root)));
        assertError(r, 400, "bad_request");
    }

    private static void pushEpochMismatchIsForbidden() throws Exception {
        Node host = start();
        Created cr = created(host);
        Repo repo = cr.repo();
        AvpCommit.Header header = new AvpCommit.Header(repo.id(), List.of(repo.root.commitId()), 1, hash(repo.tip), 1);
        assertError(push(host, repo, cr.token(), sealed(repo.owner.seed, header, repo.dataKey)), 403, "forbidden");
    }

    private static void publishDroppingThisHostIsNotHosted() throws Exception {
        Node host = start();
        byte[] other = pk(seed());
        // The owner's home is the other host, so a state listing only it passes the content rules.
        Repo repo = apiGenesis(other, host.key());
        String token = host.login(repo.owner.seed);
        eq(host.post("/v1/repos", token, createBody(repo)).status, 200, "create");
        AvpManifest.SignedManifest next = repo.next(s -> s.keepHost(other));
        assertError(publish(host, repo, token, next, null), 403, "not_hosted");
    }

    private static void leaveByOutsiderIsForbidden() throws Exception {
        Node host = start();
        Created cr = created(host);
        byte[] outsider = seed();
        String t = host.login(outsider);
        AvpTokens.LeaveRequest own = leaveRequest(cr.repo(), outsider);
        assertError(host.post(cr.repo().path("leave"), t, AvpTokens.toJson(own)), 403, "forbidden");
    }

    private static void pullReturnsStatesInOrder() throws Exception {
        Node host = start();
        Created cr = created(host);
        Repo repo = cr.repo();
        addMember(host, repo, cr.token(), new Device());
        AvpManifest.SignedManifest seq2 = repo.tip;
        addMember(host, repo, cr.token(), new Device());
        AvpManifest.SignedManifest seq3 = repo.tip;
        eq(pull(host, repo, cr.token(), 1).at("manifests"), list(mj(seq2), mj(seq3)), "after 1");
        eq(pull(host, repo, cr.token(), 3).at("manifests"), list(), "after 3");
    }

    private static void poisonedStateIsAnErrorResponse() throws Exception {
        // The Java counterpart of a poisoned Rust mutex: a broken state makes every handler fail, and the
        // failure is a 500 error body, never an escaped exception or a dropped connection.
        Node host = start();
        host.st.poison();
        Reply r = host.get("/.well-known/avp");
        eq(r.status, 500, "status");
        isTrue(r.at("error") instanceof String, "error body");
        // The server survived: a second request is answered too.
        eq(host.get("/.well-known/avp").status, 500, "second request");
    }

    // ═══ tests/replication.rs ═══════════════════════════════════════════════════════════

    private static void writeOnAReachesB() throws Exception {
        Node a = node();
        Node b = node();
        link(a, b);
        Repo repo = genesis(a.key(), a.key(), b.key());
        String token = create(a, repo);
        String id = repo.id();

        // createRepo is offered to B, which takes its first copy from the genesis (SPEC 9.2).
        eventually("B holds the genesis", () -> eq(b.tipHash(id), Optional.of(h(repo.genesis)), "tip"));
        eventually("B has the first commit", () -> eq(b.heads(id), b64s(repo.root.commitId()), "heads"));

        AvpCommit.Commit c1 = repo.commit(repo.owner.seed, List.of(repo.root.commitId()), bytes("one"));
        eq(push(a, repo, token, c1).status, 200, "push");
        eventually("B has the pushed commit", () -> eq(b.heads(id), b64s(c1.commitId()), "heads"));

        // B serves it to a client: the owner pulls from B.
        String tb = b.login(repo.owner.seed);
        Reply r = pull(b, repo, tb);
        eq(r.status, 200, "pull: " + r.body);
        eq(r.at("heads"), list(cj(c1)), "heads");
        eq(r.at("manifests"), list(mj(repo.genesis)), "manifests");

        // A manifest state replicates too.
        AvpManifest.SignedManifest s2 = repo.next(s -> s.share = true);
        eq(publish(a, repo, token, s2, null).status, 200, "publish");
        repo.tip = s2;
        eventually("B has seq 2", () -> eq(b.tipHash(id), Optional.of(h(s2)), "tip"));
    }

    private static void partitionThenHealConverges() throws Exception {
        Node a = node();
        Node b = node();
        link(a, b);
        Repo repo = genesis(a.key(), a.key(), b.key());
        String ta = create(a, repo);
        String id = repo.id();
        eventually("B holds the repository", () -> eq(b.heads(id), b64s(repo.root.commitId()), "heads"));
        String tb = b.login(repo.owner.seed);

        a.pause(true);
        b.pause(true);
        AvpCommit.Commit ca = repo.commit(repo.owner.seed, List.of(repo.root.commitId()), bytes("on a"));
        AvpCommit.Commit cb = repo.commit(repo.owner.seed, List.of(repo.root.commitId()), bytes("on b"));
        eq(push(a, repo, ta, ca).status, 200, "push a");
        eq(push(b, repo, tb, cb).status, 200, "push b");
        // Paused: no host traffic for several sweep intervals.
        Thread.sleep(SWEEP_MS * 6);
        eq(a.heads(id), b64s(ca.commitId()), "a heads while paused");
        eq(b.heads(id), b64s(cb.commitId()), "b heads while paused");

        a.pause(false);
        b.pause(false);
        List<String> both = sortedB64(ca.commitId(), cb.commitId());
        eventually("A and B report the same two heads", () -> {
            eq(a.heads(id), both, "a");
            eq(b.heads(id), both, "b");
        });
    }

    private static void hostNotInHostsIsRefused() throws Exception {
        // Deviation from the Task 11 brief (SPEC wins): a peer whose key is not in the repository's hosts
        // in the serving host's tip gets 403 forbidden on heads, fetch, and offer (SPEC 9.2, openapi.yaml).
        Node a = node();
        Node b = node();
        Node c = node();
        link(a, b, c);
        try (RecordingPeer d = new RecordingPeer()) {
            // D is in A's static peer list (AVP_PEERS) but not in the repository's hosts.
            a.peerWith(b.entry(), c.entry(), d.entry());
            Repo repo = genesis(a.key(), a.key(), b.key());
            create(a, repo);
            String id = repo.id();
            eventuallyTrue("B holds the repository", () -> b.holds(id));

            assertError(a.host(c.seed, id, "heads", obj("repoId", id)), 403, "forbidden");
            assertError(a.host(c.seed, id, "fetch", fetchBody(id, hash(repo.genesis))), 403, "forbidden");
            assertError(
                    a.host(c.seed, id, "offer", offer(id, List.of(), List.of(repo.root), List.of())), 403, "forbidden");

            // A never offers the repository to C, and C never takes it.
            Thread.sleep(SWEEP_MS * 6);
            isTrue(!c.holds(id), "C does not hold it");

            // Positive control: a second repository that does list D. A offers it to D and sweeps it, so the
            // recorder is reachable and records A's requests.
            Repo listed = genesis(a.key(), a.key(), pk(d.seed));
            create(a, listed);
            String listedId = listed.id();
            eventuallyTrue("D gets requests for the repository that lists it", () -> {
                List<String> got = d.paths();
                return got.contains(hostPath(listedId, "offer")) && got.contains(hostPath(listedId, "heads"));
            });
            Thread.sleep(SWEEP_MS * 3);

            // SPEC 9.2 and 9.3: A sends heads, fetch, and offer for a repository only to the peers in its
            // hosts. D is in A's AVP_PEERS but not in the first repository's hosts, so it gets no request for
            // it at all, sweep included, and never learns its repoId.
            List<String> got = d.paths();
            String prefix = "/v1/host/repos/" + id + "/";
            for (String p : got) {
                isTrue(!p.startsWith(prefix), "A sent D a request for a repository that does not list it: " + got);
            }
        }
    }

    private static void badHostSignatureRejected() throws Exception {
        Faked f = nodeWithFake();
        Node b = f.b();
        FakePeer p = f.p();
        Repo repo = genesis(b.key(), b.key(), p.key());
        create(b, repo);
        String id = repo.id();
        String path = hostPath(id, "heads");
        byte[] body = AvpJson.writeUtf8(obj("repoId", id));
        long now = nowMs();

        // Control: a correct signature is accepted.
        Reply r = b.hosted(path, hostHeaders(p.seed, "POST", path, body, now), body);
        eq(r.status, 200, "control: " + r.body);

        // Signed by another key under the peer's key header.
        List<String[]> hd = hostHeaders(p.seed, "POST", path, body, now);
        hd.get(2)[1] = hostSignature(seed(), "POST", path, body, now);
        assertError(b.hosted(path, hd, body), 401, "unauthorized");

        // Random signature bytes; signature over another time; not base64; wrong length.
        hd = hostHeaders(p.seed, "POST", path, body, now);
        hd.get(2)[1] = b64(AvpCrypto.randomBytes(64));
        assertError(b.hosted(path, hd, body), 401, "unauthorized");
        hd = hostHeaders(p.seed, "POST", path, body, now);
        hd.get(1)[1] = Long.toString(now + 1);
        assertError(b.hosted(path, hd, body), 401, "unauthorized");
        hd = hostHeaders(p.seed, "POST", path, body, now);
        hd.get(2)[1] = "not base64!";
        assertError(b.hosted(path, hd, body), 401, "unauthorized");
        hd = hostHeaders(p.seed, "POST", path, body, now);
        hd.get(2)[1] = b64(AvpCrypto.randomBytes(32));
        assertError(b.hosted(path, hd, body), 401, "unauthorized");

        // A correctly self-signed key that is not in the static peer list.
        assertError(b.hosted(path, hostHeaders(seed(), "POST", path, body, now), body), 401, "unauthorized");

        // Each header missing, a malformed key, a non-decimal time.
        for (int drop = 0; drop < 3; drop++) {
            hd = hostHeaders(p.seed, "POST", path, body, now);
            hd.remove(drop);
            assertError(b.hosted(path, hd, body), 401, "unauthorized");
        }
        hd = hostHeaders(p.seed, "POST", path, body, now);
        hd.get(0)[1] = b64(AvpCrypto.randomBytes(31));
        assertError(b.hosted(path, hd, body), 401, "unauthorized");
        hd = hostHeaders(p.seed, "POST", path, body, now);
        hd.get(1)[1] = "soon";
        assertError(b.hosted(path, hd, body), 401, "unauthorized");
    }

    private static void staleTimestampRejected() throws Exception {
        Faked f = nodeWithFake();
        Node b = f.b();
        FakePeer p = f.p();
        Repo repo = genesis(b.key(), b.key(), p.key());
        create(b, repo);
        String id = repo.id();
        String path = hostPath(id, "heads");
        byte[] body = AvpJson.writeUtf8(obj("repoId", id));

        // SPEC 9.3: |now - time| over 60 seconds is 401, in either direction.
        for (long skew : new long[] {-61_000, 61_000, -3_600_000}) {
            assertError(
                    b.hosted(path, hostHeaders(p.seed, "POST", path, body, nowMs() + skew), body), 401, "unauthorized");
        }
        // Within the window it is accepted.
        for (long skew : new long[] {-59_000, 59_000}) {
            eq(
                    b.hosted(path, hostHeaders(p.seed, "POST", path, body, nowMs() + skew), body).status,
                    200,
                    "skew " + skew);
        }
        // The bound itself, on a frozen clock: SPEC 9.3 rejects only when |now - time| exceeds 60 seconds, so
        // exactly 60 000 ms is accepted and 60 001 ms is refused, in either direction.
        long frozen = nowMs();
        b.freezeClock(frozen);
        try {
            for (long skew : new long[] {-60_000, 60_000}) {
                eq(
                        b.hosted(path, hostHeaders(p.seed, "POST", path, body, frozen + skew), body).status,
                        200,
                        "skew " + skew);
            }
            for (long skew : new long[] {-60_001, 60_001}) {
                assertError(
                        b.hosted(path, hostHeaders(p.seed, "POST", path, body, frozen + skew), body),
                        401,
                        "unauthorized");
            }
        } finally {
            b.freezeClock(null);
        }
    }

    private static void offerRevalidates() throws Exception {
        Node a = node();
        Node b = node();
        FakePeer p = new FakePeer();
        a.peerWith(b.entry());
        b.peerWith(a.entry(), p.entry());
        Repo repo = genesis(a.key(), a.key(), b.key(), p.key());
        create(a, repo);
        String id = repo.id();
        eventually("B holds the repository", () -> eq(b.heads(id), b64s(repo.root.commitId()), "heads"));

        // Commits A was tricked into storing: they go into A's outbox behind the engine's back, so A offers
        // them to B as if it had accepted them.
        AvpCommit.Commit good = repo.commit(repo.owner.seed, List.of(repo.root.commitId()), bytes("forged"));
        AvpCommit.Commit forged = withSignature(good, flip(good.authorSignature(), 0));
        Device stranger = new Device();
        AvpCommit.Commit outsider = repo.commit(stranger.seed, List.of(repo.root.commitId()), bytes("outsider"));
        // A valid commit travels in the same offer, so its arrival at B shows the offer was received.
        AvpCommit.Commit marker = repo.commit(repo.owner.seed, List.of(repo.root.commitId()), bytes("marker"));
        a.st.lock();
        try {
            a.st.outbox.push(new Replication.Outgoing(id, List.of(), List.of(forged, outsider, marker), List.of()));
        } finally {
            a.st.unlock();
        }

        // B validates each item with the engine (SPEC 9: whatever the transport): it accepts the valid commit
        // and rejects the other two, storing neither of them.
        eventually("B received the offer", () -> eq(b.heads(id), b64s(marker.commitId()), "heads"));
        eq(b.view(id, v -> v.status(forged.commitId())), Optional.of(Optional.empty()), "forged not stored");
        eq(b.view(id, v -> v.status(outsider.commitId())), Optional.of(Optional.empty()), "outsider not stored");

        // The per-item codes are the ones the engine gives a client (SPEC 9.1).
        AvpCommit.Commit orphan = repo.commit(repo.owner.seed, List.of(AvpCrypto.randomBytes(32)), bytes("orphan"));
        Reply r = b.host(p.seed, id, "offer", offer(id, List.of(), List.of(forged, outsider, orphan), List.of()));
        eq(r.status, 200, "offer: " + r.body);
        eq(r.at("accepted"), list(), "accepted");
        eq(
                rejected(r),
                Set.of(
                        pair(forged.commitId(), "bad_request"),
                        pair(outsider.commitId(), "forbidden"),
                        pair(orphan.commitId(), "missing_parents")),
                "rejected");
        eq(b.heads(id), b64s(marker.commitId()), "heads unchanged");
    }

    private static void bodyNotMatchingSignedHashRejected() throws Exception {
        Faked f = nodeWithFake();
        Node b = f.b();
        FakePeer p = f.p();
        Repo repo = genesis(b.key(), b.key(), p.key());
        create(b, repo);
        String id = repo.id();
        String path = hostPath(id, "fetch");
        byte[] signed = AvpJson.writeUtf8(fetchBody(id));
        byte[] sent = AvpJson.writeUtf8(fetchBody(id, hash(repo.genesis)));
        List<String[]> hd = hostHeaders(p.seed, "POST", path, signed, nowMs());
        assertError(b.hosted(path, hd, sent), 401, "unauthorized");
        // One extra byte of whitespace is a different body.
        byte[] spaced = Arrays.copyOf(signed, signed.length + 1);
        spaced[signed.length] = ' ';
        assertError(b.hosted(path, hd, spaced), 401, "unauthorized");
        // Control: the signed body itself is accepted, and the signature covers its hash.
        eq(b.hosted(path, hd, signed).status, 200, "signed body");
        Reply r = b.hosted(path, hostHeaders(p.seed, "POST", path, sent, nowMs()), sent);
        eq(r.status, 200, "sent body: " + r.body);
        eq(r.at("manifests"), list(mj(repo.genesis)), "manifests");
    }

    private static void pathNotMatchingSignedPathRejected() throws Exception {
        Faked f = nodeWithFake();
        Node b = f.b();
        FakePeer p = f.p();
        Repo repo = genesis(b.key(), b.key(), p.key());
        create(b, repo);
        Repo other = genesis(b.key(), b.key(), p.key());
        create(b, other);
        String id = repo.id();
        byte[] body = AvpJson.writeUtf8(obj("repoId", id));
        // Signed for fetch, sent to heads.
        List<String[]> hd = hostHeaders(p.seed, "POST", hostPath(id, "fetch"), body, nowMs());
        assertError(b.hosted(hostPath(id, "heads"), hd, body), 401, "unauthorized");
        // Signed for another repository, sent to this one.
        hd = hostHeaders(p.seed, "POST", hostPath(other.id(), "heads"), body, nowMs());
        assertError(b.hosted(hostPath(id, "heads"), hd, body), 401, "unauthorized");
        // Signed without the query, sent with one: the path is signed as sent.
        hd = hostHeaders(p.seed, "POST", hostPath(id, "heads"), body, nowMs());
        Reply r = b.hosted(hostPath(id, "heads") + "?x=1", hd, body);
        eq(r.status, 200, "query is not part of the signed path: " + r.body);
        // Signed with another method.
        hd = hostHeaders(p.seed, "GET", hostPath(id, "heads"), body, nowMs());
        assertError(b.hosted(hostPath(id, "heads"), hd, body), 401, "unauthorized");
    }

    private static void peersFromEnvParsesAndRejects() throws Exception {
        String k1 = b64(AvpCrypto.randomBytes(32));
        String k2 = b64(AvpCrypto.randomBytes(32));
        Replication.Peers peers = Replication.Peers.fromEnv(
                " " + k1 + "@http://a.vault.example:8787/ , " + k2 + "@http://127.0.0.1:9000");
        eq(peers.size(), 2, "size");
        isTrue(Replication.Peers.fromEnv("").isEmpty(), "empty");
        isTrue(Replication.Peers.fromEnv("  ").isEmpty(), "blank");
        for (String bad : List.of(
                k1,
                k1 + "@",
                "@http://a.vault.example",
                "not-base64@http://a.vault.example",
                b64(AvpCrypto.randomBytes(31)) + "@http://a.vault.example",
                k1 + "@https://a.vault.example",
                k1 + "@a.vault.example",
                k1 + "@http://",
                k1 + "@http://a.vault.example/x y",
                k1 + "@http://a.vault.example," + k1 + "@http://b.vault.example")) {
            try {
                Replication.Peers.fromEnv(bad);
                throw new AssertionError("accepted " + bad);
            } catch (AvpException e) {
                // Expected.
            }
        }
    }

    private static void testControlAbsentWithoutFlag() throws Exception {
        Node b = nodeCfg(false, l -> {});
        assertError(b.post("/v1/test/replication", null, obj("paused", true)), 404, "not_found");
    }

    private static void pausedHostAnswers503() throws Exception {
        Faked f = nodeWithFake();
        Node b = f.b();
        FakePeer p = f.p();
        Repo repo = genesis(b.key(), b.key(), p.key());
        create(b, repo);
        String id = repo.id();
        b.pause(true);
        for (String op : List.of("heads", "fetch", "offer")) {
            Object body =
                    switch (op) {
                        case "fetch" -> fetchBody(id);
                        case "offer" -> offer(id, List.of(), List.of(), List.of());
                        default -> obj("repoId", id);
                    };
            eq(b.host(p.seed, id, op, body).status, 503, op);
            // Even unsigned: paused answers before authentication.
            eq(b.post(hostPath(id, op), null, body).status, 503, op + " unsigned");
        }
        // Client routes keep working.
        String token = b.login(repo.owner.seed);
        eq(pull(b, repo, token).status, 200, "pull");
        b.pause(false);
        eq(b.host(p.seed, id, "heads", obj("repoId", id)).status, 200, "heads after unpause");
        // A malformed control body is 400.
        assertError(b.post("/v1/test/replication", null, obj("paused", "yes")), 400, "bad_request");
    }

    private static void headsAndFetchAnswerTheSpecShapes() throws Exception {
        Faked f = nodeWithFake();
        Node b = f.b();
        FakePeer p = f.p();
        Repo repo = genesis(b.key(), b.key(), p.key());
        String token = create(b, repo);
        String id = repo.id();
        Device bob = new Device();
        AvpManifest.MemberEntry entry = bob.entry(repo.dataKey, 0, b.key());
        AvpManifest.SignedManifest s2 = repo.next(s -> s.members.add(entry));
        eq(publish(b, repo, token, s2, null).status, 200, "publish s2");
        repo.tip = s2;
        Rotation rot = rotation(repo, List.of(repo.owner), bob, List.of(), List.of(repo.root.commitId()), b.key());
        eq(publish(b, repo, token, rot.state(), rot.commit()).status, 200, "publish s3");

        Reply r = b.host(p.seed, id, "heads", obj("repoId", id));
        eq(r.status, 200, "heads: " + r.body);
        eq(
                r.json,
                j(obj(
                        "manifestTip",
                        obj("manifestSeq", 3L, "manifestHash", h(rot.state())),
                        "heads",
                        ids(rot.commit().commitId()))),
                "heads answer");
        // The body repoId may be left out (SPEC 9.3 heads body is `{}`).
        eq(b.host(p.seed, id, "heads", obj()).status, 200, "heads without repoId");

        // fetch by the tip hash: the whole chain ascending, with the rotation commit of the epoch-raising
        // state; by a commit id: that commit; unknown ids are left out.
        r = b.host(
                p.seed, id, "fetch", fetchBody(id, hash(rot.state()), repo.root.commitId(), AvpCrypto.randomBytes(32)));
        eq(r.status, 200, "fetch: " + r.body);
        eq(r.at("manifests"), list(mj(repo.genesis), mj(s2), mj(rot.state())), "manifests");
        eq(new HashSet<>((List<?>) r.at("commits")), new HashSet<>(list(cj(rot.commit()), cj(repo.root))), "commits");
        eq(r.at("leaves"), list(), "leaves");

        // Unknown repository: 404; body repoId that differs from the path: 400.
        String unknown = genesis(b.key(), b.key()).id();
        assertError(b.host(p.seed, unknown, "heads", obj()), 404, "not_found");
        assertError(b.host(p.seed, id, "heads", obj("repoId", unknown)), 400, "bad_request");
        assertError(b.host(p.seed, id, "fetch", obj("repoId", id)), 400, "bad_request");
    }

    private static void newlyListedHostBootstraps() throws Exception {
        Node a = node();
        Node b = node();
        link(a, b);
        // The genesis lists only A: B is not offered it and does not hold it.
        Repo repo = genesis(a.key(), a.key());
        String token = create(a, repo);
        String id = repo.id();
        AvpCommit.Commit c1 = repo.commit(repo.owner.seed, List.of(repo.root.commitId()), bytes("one"));
        eq(push(a, repo, token, c1).status, 200, "push");
        Thread.sleep(SWEEP_MS * 4);
        isTrue(!b.holds(id), "B does not hold it");

        // The owner invites bob, homed on B, adding B to hosts in seq 2 (SPEC 8.1). B takes its first copy
        // by replication from A, from the genesis on, though the genesis does not list it.
        Device bob = new Device();
        AvpManifest.MemberEntry entry = bob.entry(repo.dataKey, 0, b.key());
        AvpManifest.SignedManifest s2 = repo.next(s -> {
            s.addHost(b.key(), "b.vault.example");
            s.members.add(entry);
        });
        eq(publish(a, repo, token, s2, null).status, 200, "publish");
        repo.tip = s2;
        eventually("B converges to A's tip and heads", () -> {
            eq(b.tipHash(id), Optional.of(h(s2)), "tip");
            eq(b.heads(id), a.heads(id), "heads");
        });
        eq(b.heads(id), b64s(c1.commitId()), "heads");
        eq(b.view(id, AvpRules.RepoView::tipListsHost), Optional.of(true), "hosted");

        // Bob pulls from his home host.
        String tb = b.login(bob.seed);
        Reply r = pull(b, repo, tb);
        eq(r.status, 200, "pull: " + r.body);
        eq(r.at("manifests"), list(mj(repo.genesis), mj(s2)), "manifests");
        eq(r.at("heads"), list(cj(c1)), "heads");
    }

    private static void rotationReachesBAtomically() throws Exception {
        Node a = node();
        Node b = node();
        link(a, b);
        Repo repo = genesis(a.key(), a.key(), b.key());
        String token = create(a, repo);
        String id = repo.id();
        Device bob = new Device();
        AvpManifest.MemberEntry entry = bob.entry(repo.dataKey, 0, a.key());
        AvpManifest.SignedManifest s2 = repo.next(s -> s.members.add(entry));
        eq(publish(a, repo, token, s2, null).status, 200, "publish");
        repo.tip = s2;
        String bobToken = a.login(bob.seed);
        AvpCommit.Commit bc = repo.commit(bob.seed, List.of(repo.root.commitId()), bytes("bob"));
        eq(push(a, repo, bobToken, bc).status, 200, "push");
        eventually("B has bob's commit", () -> eq(b.heads(id), b64s(bc.commitId()), "heads"));

        // Remove bob (SPEC 8.3): new epoch, frontier, rotation commit; published on A.
        Rotation rot =
                rotation(repo, List.of(repo.owner), bob, List.of(bc.commitId()), List.of(bc.commitId()), a.key());
        eq(publish(a, repo, token, rot.state(), rot.commit()).status, 200, "publish rotation");
        eventually("B adopted the rotation pair", () -> eq(b.tipHash(id), Optional.of(h(rot.state())), "tip"));
        // The state is never on B's chain without its rotation commit.
        eq(b.heads(id), b64s(rot.commit().commitId()), "heads");
        eq(
                b.view(id, v -> v.rotationCommit(hash(rot.state())).map(SmokeTest::cj)),
                Optional.of(Optional.of(cj(rot.commit()))),
                "rotation commit");
    }

    private static void epochRaiseOfferNeedsItsRotationCommit() throws Exception {
        Faked f = nodeWithFake();
        Node b = f.b();
        FakePeer p = f.p();
        Repo repo = genesis(b.key(), b.key(), p.key());
        create(b, repo);
        String id = repo.id();
        Rotation rot = rotation(repo, List.of(repo.owner), null, null, List.of(repo.root.commitId()), b.key());
        AvpManifest.SignedManifest s2 = rot.state();

        // Without its rotation commit: 400 bad_request for the state, nothing adopted (SPEC 8.3, 9.1).
        Reply r = b.host(p.seed, id, "offer", offer(id, List.of(s2), List.of(), List.of()));
        eq(r.status, 200, "offer: " + r.body);
        eq(rejected(r), Set.of(pair(hash(s2), "bad_request")), "rejected");
        eq(b.tipHash(id), Optional.of(h(repo.genesis)), "tip");

        // With a forged rotation commit: both items of the pair are rejected with the same code.
        AvpCommit.Commit bad = withSignature(rot.commit(), flip(rot.commit().authorSignature(), 5));
        r = b.host(p.seed, id, "offer", offer(id, List.of(s2), List.of(bad), List.of()));
        eq(rejected(r), Set.of(pair(hash(s2), "bad_request"), pair(bad.commitId(), "bad_request")), "rejected pair");
        eq(b.tipHash(id), Optional.of(h(repo.genesis)), "tip");
        eq(b.heads(id), b64s(repo.root.commitId()), "heads");

        // With it: both accepted together.
        r = b.host(p.seed, id, "offer", offer(id, List.of(s2), List.of(rot.commit()), List.of()));
        eq(r.status, 200, "offer: " + r.body);
        eq(idSet(r.at("accepted")), b64Set(hash(s2), rot.commit().commitId()), "accepted");
        eq(r.at("rejected"), list(), "rejected");
        eq(b.tipHash(id), Optional.of(h(s2)), "tip");
        eq(b.heads(id), b64s(rot.commit().commitId()), "heads");

        // Offered again, the pair is accepted again with no change (SPEC 7, 12.3).
        r = b.host(p.seed, id, "offer", offer(id, List.of(s2), List.of(rot.commit()), List.of()));
        eq(idSet(r.at("accepted")), b64Set(hash(s2), rot.commit().commitId()), "accepted again");
        eq(b.heads(id), b64s(rot.commit().commitId()), "heads");
    }

    private static void divergedOwnerStatesConverge() throws Exception {
        Node a = node();
        Node b = node();
        link(a, b);
        Repo repo = genesis(a.key(), a.key(), b.key());
        String ta = create(a, repo);
        String id = repo.id();
        eventually("B holds the repository", () -> eq(b.heads(id), b64s(repo.root.commitId()), "heads"));
        String tb = b.login(repo.owner.seed);

        // Two owner devices publish different seq 2 states while the hosts cannot reach each other.
        a.pause(true);
        b.pause(true);
        Device bob = new Device();
        AvpManifest.MemberEntry entry = bob.entry(repo.dataKey, 0, b.key());
        AvpManifest.SignedManifest x = repo.next(s -> s.share = true);
        AvpManifest.SignedManifest y = repo.next(s -> s.members.add(entry));
        eq(publish(a, repo, ta, x, null).status, 200, "publish x");
        eq(publish(b, repo, tb, y, null).status, 200, "publish y");
        // Each side writes a commit citing its own seq 2.
        AvpCommit.Commit cx = commitOn(x, repo.dataKey, repo.owner.seed, List.of(repo.root.commitId()), bytes("x"));
        AvpCommit.Commit cy = commitOn(y, repo.dataKey, repo.owner.seed, List.of(repo.root.commitId()), bytes("y"));
        eq(push(a, repo, ta, cx).status, 200, "push x");
        eq(push(b, repo, tb, cy).status, 200, "push y");

        a.pause(false);
        b.pause(false);
        boolean xWins = AvpEncoding.compare(hash(x), hash(y)) < 0;
        AvpManifest.SignedManifest win = xWins ? x : y;
        AvpManifest.SignedManifest lose = xWins ? y : x;
        eventually("both hosts hold the lower-hash tip", () -> {
            eq(a.tipHash(id), Optional.of(h(win)), "a");
            eq(b.tipHash(id), Optional.of(h(win)), "b");
        });
        // The owner is a member at epoch 0 in the winner, so the commit citing the losing state is accepted
        // after the re-check, not dropped (SPEC 6.5), and both hosts converge on both heads.
        List<String> both = sortedB64(cx.commitId(), cy.commitId());
        eventually("both hosts report both commits as heads", () -> {
            eq(a.heads(id), both, "a");
            eq(b.heads(id), both, "b");
        });
        // Both keep the losing state, verified, off the chain (SPEC 6.5).
        for (Node n : List.of(a, b)) {
            eq(n.view(id, v -> v.manifest(hash(lose)).isPresent()), Optional.of(true), "losing state kept");
            eq(n.view(id, v -> v.isWinning(hash(lose))), Optional.of(false), "losing state off the chain");
            eq(n.tipHash(id), Optional.of(h(win)), "tip");
        }
    }

    private static void leaveReplicates() throws Exception {
        Node a = node();
        Node b = node();
        link(a, b);
        Repo repo = genesis(a.key(), a.key(), b.key());
        String token = create(a, repo);
        String id = repo.id();
        Device bob = new Device();
        AvpManifest.MemberEntry entry = bob.entry(repo.dataKey, 0, a.key());
        AvpManifest.SignedManifest s2 = repo.next(s -> s.members.add(entry));
        eq(publish(a, repo, token, s2, null).status, 200, "publish");
        repo.tip = s2;
        eventually("B has seq 2", () -> eq(b.tipHash(id), Optional.of(h(s2)), "tip"));

        AvpTokens.LeaveRequest leave = leaveRequest(repo, bob.seed);
        String bobToken = a.login(bob.seed);
        Reply r = a.post(repo.path("leave"), bobToken, AvpTokens.toJson(leave));
        eq(r.status, 200, "leave: " + r.body);
        eventually(
                "B holds bob's leave request",
                () -> eq(
                        b.view(
                                id,
                                v -> j(v.leaves().stream()
                                        .map(AvpTokens::toJson)
                                        .toList())),
                        Optional.of(list(lj(leave))),
                        "leaves"));
        String tb = b.login(repo.owner.seed);
        eq(pull(b, repo, tb).at("leaves"), list(lj(leave)), "pulled leaves");
    }

    private static void fetchServesLosingState() throws Exception {
        Faked f = nodeWithFake();
        Node b = f.b();
        FakePeer p = f.p();
        Repo repo = genesis(b.key(), b.key(), p.key());
        String token = create(b, repo);
        String id = repo.id();

        // A losing epoch-raising seq 2 and its rotation commit; the winner is published first.
        Rotation lose = losingRaise(repo, b.key());
        AvpManifest.SignedManifest win = winnerAgainst(repo, lose.state());
        eq(publish(b, repo, token, win, null).status, 200, "publish winner");
        Reply r = b.host(p.seed, id, "offer", offer(id, List.of(lose.state()), List.of(lose.commit()), List.of()));
        eq(r.status, 200, "offer: " + r.body);
        eq(r.at("accepted"), list(), "accepted");
        eq(
                rejected(r),
                Set.of(
                        pair(hash(lose.state()), "manifest_conflict"),
                        pair(lose.commit().commitId(), "manifest_conflict")),
                "rejected");
        repo.tip = win;

        // SPEC 6.5, 9.1: served by hash with the chain before it and its rotation commit, though held.
        r = b.host(p.seed, id, "fetch", fetchBody(id, hash(lose.state())));
        eq(r.status, 200, "fetch: " + r.body);
        eq(r.at("manifests"), list(mj(repo.genesis), mj(lose.state())), "manifests");
        eq(r.at("commits"), list(cj(lose.commit())), "commits");
        // The rotation commit is served by id too, and is not a head.
        r = b.host(p.seed, id, "fetch", fetchBody(id, lose.commit().commitId()));
        eq(r.at("commits"), list(cj(lose.commit())), "commit by id");
        r = b.host(p.seed, id, "heads", obj("repoId", id));
        eq(
                r.json,
                j(obj(
                        "manifestTip",
                        obj("manifestSeq", 2L, "manifestHash", h(win)),
                        "heads",
                        ids(repo.root.commitId()))),
                "heads");
    }

    private static void heldAndPendingCommitsAreNotServed() throws Exception {
        Faked f = nodeWithFake();
        Node b = f.b();
        FakePeer p = f.p();
        Repo repo = genesis(b.key(), b.key(), p.key());
        String token = create(b, repo);
        String id = repo.id();

        // Held (SPEC 6.5): bob is a member only on the losing seq 2; his commit citing it is held.
        Device bob = new Device();
        AvpManifest.MemberEntry bobEntry = bob.entry(repo.dataKey, 0, b.key());
        AvpManifest.SignedManifest lose = upperHalf(
                n -> repo.next(s -> {
                    s.members.add(bobEntry);
                    s.relocate(s.hosts.size() - 1, "l" + n + ".vault.example");
                }),
                m -> m);
        AvpManifest.SignedManifest win = winnerAgainst(repo, lose);
        eq(publish(b, repo, token, win, null).status, 200, "publish winner");
        Reply r = b.host(p.seed, id, "offer", offer(id, List.of(lose), List.of(), List.of()));
        eq(rejected(r), Set.of(pair(hash(lose), "manifest_conflict")), "losing state");
        AvpCommit.Commit held = commitOn(lose, repo.dataKey, bob.seed, List.of(repo.root.commitId()), bytes("held"));
        r = b.host(p.seed, id, "offer", offer(id, List.of(), List.of(held), List.of()));
        eq(rejected(r), Set.of(pair(held.commitId(), "forbidden")), "held commit");
        eq(b.view(id, v -> idList(v.held())), Optional.of(ids(held.commitId())), "held list");
        r = b.host(p.seed, id, "fetch", fetchBody(id, held.commitId()));
        eq(r.at("commits"), list(), "held commit not served");
        r = b.host(p.seed, id, "heads", obj());
        eq(r.at("heads"), ids(repo.root.commitId()), "heads");
        repo.tip = win;

        // Pending (SPEC 7.3): carol's accepted commit becomes undecided when a removal names a frontier commit
        // whose header the host lacks.
        Device carol = new Device();
        AvpManifest.MemberEntry carolEntry = carol.entry(repo.dataKey, 0, b.key());
        AvpManifest.SignedManifest s3 = repo.next(s -> s.members.add(carolEntry));
        eq(publish(b, repo, token, s3, null).status, 200, "publish s3");
        repo.tip = s3;
        AvpCommit.Commit x = repo.commit(carol.seed, List.of(repo.root.commitId()), bytes("carol"));
        r = b.host(p.seed, id, "offer", offer(id, List.of(), List.of(x), List.of()));
        eq(idSet(r.at("accepted")), b64Set(x.commitId()), "carol accepted");
        byte[] unknownFrontier = AvpCrypto.randomBytes(32);
        Rotation rot = rotation(
                repo, List.of(repo.owner), carol, List.of(unknownFrontier), List.of(repo.root.commitId()), b.key());
        eq(publish(b, repo, token, rot.state(), rot.commit()).status, 200, "publish s4");
        eq(b.view(id, v -> idList(v.pending())), Optional.of(ids(x.commitId())), "pending");

        r = b.host(p.seed, id, "fetch", fetchBody(id, x.commitId()));
        eq(r.status, 200, "fetch: " + r.body);
        eq(r.at("commits"), list(), "pending commit not served");
        r = b.host(p.seed, id, "heads", obj());
        eq(r.at("heads"), ids(rot.commit().commitId()), "heads");
    }

    private static void droppedByReplicationStops() throws Exception {
        Faked f = nodeWithFake();
        Node b = f.b();
        FakePeer p = f.p();
        Repo repo = genesis(p.key(), p.key(), b.key());
        String token = create(b, repo);
        String id = repo.id();

        // A validated seq 2 that drops B: B keeps it and answers 403 not_hosted (SPEC 8.6, 9.2).
        AvpManifest.SignedManifest dropped = repo.next(s -> s.keepHost(p.key()));
        assertError(b.host(p.seed, id, "offer", offer(id, List.of(dropped), List.of(), List.of())), 403, "not_hosted");
        eq(b.tipHash(id), Optional.of(h(dropped)), "tip");
        eq(b.view(id, AvpRules.RepoView::tipListsHost), Optional.of(false), "not hosted");
        repo.tip = dropped;

        // Not hosted: every client operation and every peer route answers 403 not_hosted (SPEC 10.1).
        assertError(pull(b, repo, token), 403, "not_hosted");
        AvpCommit.Commit c = repo.commit(repo.owner.seed, List.of(repo.root.commitId()), bytes("late"));
        assertError(push(b, repo, token, c), 403, "not_hosted");
        AvpManifest.SignedManifest s3Unused = repo.next(s -> s.share = true);
        assertError(publish(b, repo, token, s3Unused, null), 403, "not_hosted");
        Device bob = new Device();
        assertError(
                b.post(repo.path("leave"), token, AvpTokens.toJson(leaveRequest(repo, bob.seed))), 403, "not_hosted");
        assertError(b.host(p.seed, id, "heads", obj()), 403, "not_hosted");
        assertError(b.host(p.seed, id, "fetch", fetchBody(id)), 403, "not_hosted");
        assertError(b.host(p.seed, id, "offer", offer(id, List.of(), List.of(c), List.of())), 403, "not_hosted");
        eq(b.view(id, v -> v.status(c.commitId())), Optional.of(Optional.empty()), "not stored");

        // A later replicated state that lists B again: hosted again (SPEC 8.6).
        AvpManifest.SignedManifest relisted = repo.next(s -> s.addHost(b.key(), "b.vault.example"));
        Reply r = b.host(p.seed, id, "offer", offer(id, List.of(relisted), List.of(), List.of()));
        eq(r.status, 200, "offer: " + r.body);
        eq(idSet(r.at("accepted")), b64Set(hash(relisted)), "accepted");
        repo.tip = relisted;
        r = pull(b, repo, token);
        eq(r.status, 200, "pull: " + r.body);
        eq(((List<?>) r.at("manifests")).size(), 3, "manifests");
        eq(b.host(p.seed, id, "heads", obj()).status, 200, "heads");
    }

    private static void clientPublishDroppingHostKeepsState() throws Exception {
        Faked f = nodeWithFake();
        Node b = f.b();
        FakePeer p = f.p();
        Repo repo = genesis(p.key(), p.key(), b.key());
        String token = create(b, repo);
        String id = repo.id();

        // The owner publishes through B a state that drops B, carrying a non-rotation commit.
        AvpManifest.SignedManifest dropped = repo.next(s -> s.keepHost(p.key()));
        AvpCommit.Commit carried =
                commitOn(dropped, repo.dataKey, repo.owner.seed, List.of(repo.root.commitId()), bytes("c"));
        assertError(publish(b, repo, token, dropped, carried), 403, "not_hosted");
        // B records the state (SPEC 8.6) but not the carried commit, and does not offer the state.
        eq(b.tipHash(id), Optional.of(h(dropped)), "tip");
        eq(b.view(id, v -> v.status(carried.commitId())), Optional.of(Optional.empty()), "carried not kept");
        b.st.lock();
        try {
            boolean offered = false;
            for (Replication.Outgoing o : b.st.outbox.entries()) {
                for (AvpManifest.SignedManifest m : o.manifests()) {
                    offered |= h(m).equals(h(dropped));
                }
            }
            isTrue(!offered, "a state that drops this host is not offered");
        } finally {
            b.st.unlock();
        }
        repo.tip = dropped;
        assertError(pull(b, repo, token), 403, "not_hosted");
        assertError(b.host(p.seed, id, "heads", obj()), 403, "not_hosted");

        // An epoch-raising state that drops B is kept with its rotation commit, atomically.
        Repo repo2 = genesis(p.key(), p.key(), b.key());
        String token2 = create(b, repo2);
        String id2 = repo2.id();
        Rotation r0 = rotation(repo2, List.of(repo2.owner), null, null, List.of(repo2.root.commitId()), p.key());
        S rs = S.of(r0.state().state());
        rs.keepHost(p.key());
        AvpManifest.SignedManifest raised = rs.sign(repo2.owner.seed);
        AvpCommit.Commit rot = AvpCommit.seal(
                AvpCrypto.randomBytes(32),
                new AvpCommit.Header(id2, r0.commit().parents(), 2, hash(raised), 1),
                bytes("rotation"),
                repo2.owner.seed);
        assertError(publish(b, repo2, token2, raised, rot), 403, "not_hosted");
        eq(b.tipHash(id2), Optional.of(h(raised)), "tip");
        eq(
                b.view(id2, v -> v.rotationCommit(hash(raised)).map(SmokeTest::cj)),
                Optional.of(Optional.of(cj(rot))),
                "rotation commit kept");
        repo2.tip = raised;
        assertError(pull(b, repo2, token2), 403, "not_hosted");
    }

    private static void firstCopyWithUnlistedTip() throws Exception {
        Faked f = nodeWithFake();
        Node b = f.b();
        FakePeer p = f.p();
        Repo repo = genesis(p.key(), p.key());
        String id = repo.id();

        // A valid repository whose received tip does not list B: 403 not_hosted, nothing stored.
        assertError(
                b.host(p.seed, id, "offer", offer(id, List.of(repo.genesis), List.of(repo.root), List.of())),
                403,
                "not_hosted");
        isTrue(!b.holds(id), "nothing stored");
        AvpManifest.SignedManifest s2 = repo.next(s -> s.share = true);
        assertError(
                b.host(p.seed, id, "offer", offer(id, List.of(repo.genesis, s2), List.of(repo.root), List.of())),
                403,
                "not_hosted");
        isTrue(!b.holds(id), "nothing stored");
        assertError(b.host(p.seed, id, "heads", obj()), 404, "not_found");

        // Control: the same genesis with a seq 2 that lists B is a first copy (SPEC 8.1, 9.2).
        AvpManifest.SignedManifest listing = repo.next(s -> s.addHost(b.key(), "b.vault.example"));
        Reply r = b.host(p.seed, id, "offer", offer(id, List.of(repo.genesis, listing), List.of(repo.root), List.of()));
        eq(r.status, 200, "offer: " + r.body);
        eq(idSet(r.at("accepted")), b64Set(hash(repo.genesis), hash(listing), repo.root.commitId()), "accepted");
        eq(b.tipHash(id), Optional.of(h(listing)), "tip");
        eq(b.heads(id), b64s(repo.root.commitId()), "heads");
    }

    private static void firstCopyOmittingTheSender() throws Exception {
        // SPEC 9.2: a host never takes a repository from a host its signed hosts do not list. B is peered
        // with P and Q; Q offers a valid repository that lists B and P but not Q.
        Node b = node();
        FakePeer p = new FakePeer();
        FakePeer q = new FakePeer();
        b.peerWith(p.entry(), q.entry());
        Repo repo = genesis(p.key(), p.key(), b.key());
        String id = repo.id();
        assertError(
                b.host(q.seed, id, "offer", offer(id, List.of(repo.genesis), List.of(repo.root), List.of())),
                403,
                "forbidden");
        isTrue(!b.holds(id), "nothing stored");
        // The same offer from P, which the tip lists, is a first copy.
        Reply r = b.host(p.seed, id, "offer", offer(id, List.of(repo.genesis), List.of(repo.root), List.of()));
        eq(r.status, 200, "offer: " + r.body);
        eq(b.heads(id), b64s(repo.root.commitId()), "heads");
    }

    private static void firstCopyWithForgedListing() throws Exception {
        Faked f = nodeWithFake();
        Node b = f.b();
        FakePeer p = f.p();
        Repo repo = genesis(p.key(), p.key());
        String id = repo.id();
        // A seq 2 claiming to list B, signed by a key that is not the owner.
        AvpManifest.SignedManifest forged = nextOf(repo.genesis, seed(), s -> s.addHost(b.key(), "b.vault.example"));
        assertError(
                b.host(p.seed, id, "offer", offer(id, List.of(repo.genesis, forged), List.of(repo.root), List.of())),
                403,
                "not_hosted");
        isTrue(!b.holds(id), "nothing stored");
        // States of another repository offered under this repoId are not taken either.
        Repo other = genesis(b.key(), b.key());
        Reply r = b.host(p.seed, id, "offer", offer(id, List.of(other.genesis), List.of(other.root), List.of()));
        eq(r.status, 200, "offer: " + r.body);
        isTrue(rejected(r).contains(pair(hash(other.genesis), "bad_request")), "wrong repo state rejected: " + r.body);
        isTrue(!b.holds(id), "nothing stored");
        isTrue(!b.holds(other.id()), "other not stored");
    }

    // ─── Robustness against peers (SPEC 9: peer responses are untrusted input) ──────────

    private static byte[] httpOk(String body) {
        byte[] b = bytes(body);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(bytes("HTTP/1.1 200 OK\r\nContent-Length: " + b.length + "\r\n\r\n"));
        out.writeBytes(b);
        return out.toByteArray();
    }

    /** A peer that answers in turn: not JSON, oversized, the wrong shape, 500, too slow, closed, valid. */
    private static Thread badPeer(
            ServerSocket listener,
            AtomicBoolean stop,
            AtomicInteger hits,
            AtomicInteger fetches,
            String headsAnswer,
            String fetchAnswer) {
        Thread t = new Thread(() -> {
            while (!stop.get()) {
                try (Socket s = listener.accept()) {
                    s.setSoTimeout(2000);
                    byte[] buf = new byte[8192];
                    int got = Math.max(0, s.getInputStream().read(buf));
                    String head = new String(buf, 0, got, StandardCharsets.ISO_8859_1);
                    OutputStream out = s.getOutputStream();
                    if (head.startsWith("POST /v1/host/repos/") && head.contains("/fetch ")) {
                        fetches.incrementAndGet();
                        out.write(httpOk(fetchAnswer));
                        continue;
                    }
                    int n = hits.getAndIncrement();
                    switch (n % 7) {
                        case 0 -> out.write(bytes("HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nnot json"));
                        case 1 -> {
                            byte[] body = new byte[300 * 1024];
                            Arrays.fill(body, (byte) '[');
                            out.write(bytes("HTTP/1.1 200 OK\r\nContent-Length: " + body.length + "\r\n\r\n"));
                            out.write(body);
                        }
                        case 2 ->
                            out.write(
                                    httpOk(
                                            "{\"manifestTip\":{\"manifestSeq\":-5,\"manifestHash\":\"AAAA\"},\"heads\":\"x\"}"));
                        case 3 -> out.write(bytes("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 2\r\n\r\n{}"));
                        case 4 -> {
                            Thread.sleep(1500);
                            out.write(httpOk("{}"));
                        }
                        case 5 -> {
                            // A closed connection with no answer.
                        }
                        default -> out.write(httpOk(headsAnswer));
                    }
                } catch (SocketTimeoutException e) {
                    // The accept timeout: re-check the stop flag.
                } catch (IOException e) {
                    // A client that hung up.
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        });
        t.setDaemon(true);
        t.start();
        return t;
    }

    private static void badPeerResponses() throws Exception {
        AtomicBoolean stop = new AtomicBoolean(false);
        AtomicInteger hits = new AtomicInteger();
        AtomicInteger fetches = new AtomicInteger();
        byte[] badKey = seed();
        Node a = node();
        Node b = node();
        Repo repo = genesis(b.key(), b.key(), a.key(), pk(badKey));
        String id = repo.id();
        // Items that would be stored if the bad peer's answers were trusted: a commit with a forged owner
        // signature and a stranger's validly signed commit, both advertised as heads.
        AvpCommit.Commit good = repo.commit(repo.owner.seed, List.of(repo.root.commitId()), bytes("forged"));
        AvpCommit.Commit forged = withSignature(good, flip(good.authorSignature(), 0));
        Device stranger = new Device();
        AvpCommit.Commit outsider = repo.commit(stranger.seed, List.of(repo.root.commitId()), bytes("outsider"));
        String headsAnswer = AvpJson.write(obj(
                "manifestTip",
                obj("manifestSeq", 1L, "manifestHash", h(repo.genesis)),
                "heads",
                ids(forged.commitId(), outsider.commitId()),
                "extra",
                "a field this host ignores in a peer answer"));
        String fetchAnswer = AvpJson.write(obj(
                "manifests",
                list(),
                "commits",
                list(AvpCommit.toJson(forged), AvpCommit.toJson(outsider)),
                "leaves",
                list(),
                "extra",
                1L));
        try (ServerSocket listener = new ServerSocket()) {
            listener.bind(new InetSocketAddress("127.0.0.1", 0));
            listener.setSoTimeout(50);
            Thread server = badPeer(listener, stop, hits, fetches, headsAnswer, fetchAnswer);
            a.peerWith(b.entry());
            b.peerWith(a.entry(), b64(pk(badKey)) + "@http://127.0.0.1:" + listener.getLocalPort());
            String token = create(b, repo);

            // B keeps sweeping the bad peer through two full rounds of bad answers, and client requests on B
            // stay fast while a call to the bad peer hangs: the state lock is never held across a call.
            long deadline = System.currentTimeMillis() + CONVERGE_MS;
            while (hits.get() < 14) {
                isTrue(System.currentTimeMillis() < deadline, "B stopped calling the bad peer");
                long t = System.nanoTime();
                eq(pull(b, repo, token).status, 200, "pull");
                isTrue((System.nanoTime() - t) / 1_000_000 < 1000, "a client request waited on a peer call");
                Thread.sleep(20);
            }
            // B decoded the valid heads answer despite its extra field and fetched the advertised heads, but
            // the engine stored neither commit: nothing from the bad peer was stored.
            eventuallyTrue("B fetched from the bad peer", () -> fetches.get() >= 1);
            String before = viewDump(b, id);
            Thread.sleep(SWEEP_MS * 4);
            eq(b.view(id, v -> v.status(forged.commitId())), Optional.of(Optional.empty()), "forged not stored");
            eq(b.view(id, v -> v.status(outsider.commitId())), Optional.of(Optional.empty()), "outsider not stored");
            eq(viewDump(b, id), before, "view unchanged");
            eq(b.tipHash(id), Optional.of(h(repo.genesis)), "tip");
            eq(b.heads(id), b64s(repo.root.commitId()), "heads");
            AvpCommit.Commit c = repo.commit(repo.owner.seed, List.of(repo.root.commitId()), bytes("after"));
            eq(push(b, repo, token, c).status, 200, "push");
            eventually("A has the commit written on B", () -> eq(a.heads(id), b64s(c.commitId()), "heads"));

            stop.set(true);
            b.stop();
            server.join(5000);
        }
    }

    // ─── Fix round 1: rotations by catch-up, first copies across rotations, quotas ──────

    private static void sweepRepairsRotation() throws Exception {
        Node a = node();
        Node b = node();
        link(a, b);
        Repo repo = genesis(a.key(), a.key(), b.key());
        String token = create(a, repo);
        String id = repo.id();
        eventually("B holds the repository", () -> eq(b.heads(id), b64s(repo.root.commitId()), "heads"));

        b.pause(true);
        AvpCommit.Commit x = repo.commit(repo.owner.seed, List.of(repo.root.commitId()), bytes("x"));
        eq(push(a, repo, token, x).status, 200, "push");
        Rotation rot = rotation(repo, List.of(repo.owner), null, null, List.of(x.commitId()), a.key());
        eq(publish(a, repo, token, rot.state(), rot.commit()).status, 200, "publish");
        repo.tip = rot.state();
        repo.dataKey = rot.dataKey();
        // A's offers of x and of the pair reach B while it is paused: answered 503 and lost.
        Thread.sleep(SWEEP_MS * 6);
        eq(b.tipHash(id), Optional.of(h(repo.genesis)), "tip while paused");
        b.pause(false);
        eventually("B reaches A's tip by the sweep", () -> eq(b.tipHash(id), Optional.of(h(rot.state())), "tip"));
        eventually("B has A's heads", () -> eq(b.heads(id), b64s(rot.commit().commitId()), "heads"));
        eq(
                b.view(id, v -> v.rotationCommit(hash(rot.state())).map(SmokeTest::cj)),
                Optional.of(Optional.of(cj(rot.commit()))),
                "rotation commit");
        eq(b.view(id, v -> v.status(x.commitId())), Optional.of(Optional.of(AvpRules.CommitStatus.ACCEPTED)), "x");
    }

    private static void newlyListedAfterRotationBootstraps() throws Exception {
        Node a = node();
        Node b = node();
        link(a, b);
        Repo repo = genesis(a.key(), a.key());
        String token = create(a, repo);
        String id = repo.id();
        Rotation rot = rotation(repo, List.of(repo.owner), null, null, List.of(repo.root.commitId()), a.key());
        eq(publish(a, repo, token, rot.state(), rot.commit()).status, 200, "publish rotation");
        repo.tip = rot.state();
        repo.dataKey = rot.dataKey();
        Device bob = new Device();
        AvpManifest.MemberEntry entry = bob.entry(repo.dataKey, 1, b.key());
        AvpManifest.SignedManifest s3 = repo.next(s -> {
            s.addHost(b.key(), "b.vault.example");
            s.members.add(entry);
        });
        eq(publish(a, repo, token, s3, null).status, 200, "publish s3");
        eventually("B bootstraps to A's tip and heads", () -> {
            eq(b.tipHash(id), Optional.of(h(s3)), "tip");
            eq(b.heads(id), b64s(rot.commit().commitId()), "heads");
        });
        eq(
                b.view(id, v -> v.rotationCommit(hash(rot.state())).map(SmokeTest::cj)),
                Optional.of(Optional.of(cj(rot.commit()))),
                "rotation commit");
    }

    private static void firstCopyAcrossALosingBranch() throws Exception {
        Faked f = nodeWithFake();
        Node b = f.b();
        FakePeer p = f.p();
        Repo repo = genesis(p.key(), p.key());
        String id = repo.id();
        Rotation lose = losingRaise(repo, p.key());
        AvpManifest.SignedManifest win = winnerAgainst(repo, lose.state());
        repo.tip = win;
        AvpManifest.SignedManifest s3 = repo.next(s -> s.addHost(b.key(), "b.vault.example"));
        // The items in an order that needs the dependency loop: the rotation commit before its parent, the
        // states out of order.
        Reply r = b.host(
                p.seed,
                id,
                "offer",
                offer(id, List.of(s3, lose.state(), repo.genesis, win), List.of(lose.commit(), repo.root), List.of()));
        eq(r.status, 200, "offer: " + r.body);
        eq(b.tipHash(id), Optional.of(h(s3)), "tip");
        eq(b.view(id, v -> v.isWinning(hash(win))), Optional.of(true), "winner on the chain");
        eq(
                b.view(id, v -> v.manifest(hash(lose.state())).isPresent() && !v.isWinning(hash(lose.state()))),
                Optional.of(true),
                "loser retained off the chain");
        eq(
                b.view(id, v -> v.status(lose.commit().commitId())),
                Optional.of(Optional.of(AvpRules.CommitStatus.HELD)),
                "losing rotation commit held");
        eq(b.heads(id), b64s(repo.root.commitId()), "heads");
        eq(idSet(r.at("accepted")), b64Set(hash(repo.genesis), hash(win), hash(s3), repo.root.commitId()), "accepted");
    }

    private static void firstCopyWithAGap() throws Exception {
        Faked f = nodeWithFake();
        Node b = f.b();
        FakePeer p = f.p();
        Repo repo = genesis(p.key(), p.key());
        String id = repo.id();
        repo.tip = repo.next(s -> s.share = true);
        AvpManifest.SignedManifest s3 = repo.next(s -> s.addHost(b.key(), "b.vault.example"));
        Reply r = b.host(p.seed, id, "offer", offer(id, List.of(repo.genesis, s3), List.of(repo.root), List.of()));
        eq(r.status, 200, "offer: " + r.body);
        isTrue(rejected(r).contains(pair(hash(s3), "manifest_conflict")), "gap reported: " + r.body);
        isTrue(!b.holds(id), "nothing stored");
    }

    private static void firstCopiesAreHeldToQuotas() throws Exception {
        Node b = nodeCfg(true, l -> {
            l.maxReposPerOwner = 1;
            l.maxRepos = 2;
        });
        FakePeer p = new FakePeer();
        b.peerWith(p.entry());
        Function<Repo, Reply> firstCopy = repo -> {
            try {
                String rid = repo.id();
                return b.host(p.seed, rid, "offer", offer(rid, List.of(repo.genesis), List.of(repo.root), List.of()));
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        };
        Repo r1 = genesis(p.key(), p.key(), b.key());
        eq(firstCopy.apply(r1).status, 200, "r1");
        eq(b.repoCount(), 1, "count");

        // Per owner: a second repository of the same owner key.
        Repo r2 = sameOwner(r1, p.key(), p.key(), b.key());
        assertError(firstCopy.apply(r2), 429, "quota_exceeded");
        isTrue(!b.holds(r2.id()), "r2 not stored");
        eq(b.repoCount(), 1, "count");

        // Store-wide: a second owner fits, a third does not.
        Repo r3 = genesis(p.key(), p.key(), b.key());
        eq(firstCopy.apply(r3).status, 200, "r3");
        eq(b.repoCount(), 2, "count");
        Repo r4 = genesis(p.key(), p.key(), b.key());
        assertError(firstCopy.apply(r4), 429, "quota_exceeded");
        isTrue(!b.holds(r4.id()), "r4 not stored");
        eq(b.repoCount(), 2, "count");
        // createRepo is held to the store-wide cap too.
        Repo r5 = genesis(b.key(), b.key());
        String token = b.login(r5.owner.seed);
        assertError(b.post("/v1/repos", token, createBody(r5)), 429, "quota_exceeded");
        eq(b.repoCount(), 2, "count");
    }

    private static void rejectedOffersDoNotGrow() throws Exception {
        Faked f = nodeWithFake();
        Node b = f.b();
        FakePeer p = f.p();
        Repo repo = genesis(b.key(), b.key(), p.key());
        create(b, repo);
        String id = repo.id();
        String before = viewDump(b, id);

        List<AvpCommit.Commit> strangers = new ArrayList<>();
        List<AvpCommit.Commit> orphans = new ArrayList<>();
        for (int i = 0; i < 64; i++) {
            strangers.add(repo.commit(seed(), List.of(repo.root.commitId()), bytes("s" + i)));
            orphans.add(repo.commit(repo.owner.seed, List.of(AvpCrypto.randomBytes(32)), bytes("o" + i)));
        }
        List<AvpCommit.Commit> all = new ArrayList<>(strangers);
        all.addAll(orphans);
        Reply r = b.host(p.seed, id, "offer", offer(id, List.of(), all, List.of()));
        eq(r.status, 200, "offer: " + r.body);
        eq(r.at("accepted"), list(), "accepted");
        Set<String> expected = new HashSet<>();
        for (AvpCommit.Commit c : strangers) {
            expected.add(pair(c.commitId(), "forbidden"));
        }
        for (AvpCommit.Commit c : orphans) {
            expected.add(pair(c.commitId(), "missing_parents"));
        }
        eq(rejected(r), expected, "rejected");
        eq(viewDump(b, id), before, "view unchanged");

        // A valid commit offered with them is kept, and only it.
        AvpCommit.Commit good = repo.commit(repo.owner.seed, List.of(repo.root.commitId()), bytes("good"));
        List<AvpCommit.Commit> withGood = new ArrayList<>(all);
        withGood.add(good);
        r = b.host(p.seed, id, "offer", offer(id, List.of(), withGood, List.of()));
        eq(idSet(r.at("accepted")), b64Set(good.commitId()), "accepted");
        eq(b.heads(id), b64s(good.commitId()), "heads");
        for (AvpCommit.Commit c : all) {
            eq(b.view(id, v -> v.status(c.commitId())), Optional.of(Optional.empty()), "not stored");
        }
    }

    private static void hostTimeMustBePlainDecimal() throws Exception {
        Faked f = nodeWithFake();
        Node b = f.b();
        FakePeer p = f.p();
        Repo repo = genesis(b.key(), b.key(), p.key());
        create(b, repo);
        String id = repo.id();
        String path = hostPath(id, "heads");
        byte[] body = AvpJson.writeUtf8(obj());
        long now = nowMs();
        for (String text : List.of("+" + now, now + ".0", now + "x", "0x" + Long.toHexString(now))) {
            List<String[]> hd = hostHeaders(p.seed, "POST", path, body, now);
            hd.get(1)[1] = text;
            assertError(b.hosted(path, hd, body), 401, "unauthorized");
        }
    }

    private static void hostRouteRejectPaths() throws Exception {
        Faked f = nodeWithFake();
        Node b = f.b();
        FakePeer p = f.p();
        Repo repo = genesis(b.key(), b.key(), p.key());
        String token = create(b, repo);
        String id = repo.id();

        // A body repoId that differs from the path.
        String other = genesis(b.key(), b.key()).id();
        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) offer(id, List.of(), List.of(), List.of());
        body.put("repoId", other);
        assertError(b.host(p.seed, id, "offer", body), 400, "bad_request");

        // Over the item bound: 4097 ids in a fetch, 4097 leave requests in an offer.
        byte[][] many = new byte[4097][];
        for (int i = 0; i < many.length; i++) {
            many[i] = AvpCrypto.randomBytes(32);
        }
        assertError(b.host(p.seed, id, "fetch", fetchBody(id, many)), 400, "bad_request");
        Device bob = new Device();
        Object leave = AvpTokens.toJson(leaveRequest(repo, bob.seed));
        List<Object> leaves = new ArrayList<>();
        for (int i = 0; i < 4097; i++) {
            leaves.add(leave);
        }
        assertError(
                b.host(
                        p.seed,
                        id,
                        "offer",
                        obj("repoId", id, "manifests", list(), "commits", list(), "leaves", leaves)),
                400,
                "bad_request");

        // An invalid leave request (bad signature) is dropped: not stored and not reported.
        AvpManifest.MemberEntry entry = bob.entry(repo.dataKey, 0, b.key());
        AvpManifest.SignedManifest s2 = repo.next(s -> s.members.add(entry));
        eq(publish(b, repo, token, s2, null).status, 200, "publish");
        repo.tip = s2;
        AvpTokens.LeaveRequest good = leaveRequest(repo, bob.seed);
        AvpTokens.LeaveRequest bad =
                new AvpTokens.LeaveRequest(good.repoId(), good.memberKey(), good.at(), flip(good.signature(), 0));
        Reply r = b.host(p.seed, id, "offer", offer(id, List.of(), List.of(), List.of(bad)));
        eq(r.status, 200, "offer: " + r.body);
        eq(r.json, j(obj("accepted", list(), "rejected", list())), "answer");
        eq(b.view(id, v -> v.leaves().size()), Optional.of(0), "no leaves");
    }

    private static void losingRaisingStateRetained() throws Exception {
        Faked f = nodeWithFake();
        Node b = f.b();
        FakePeer p = f.p();
        Repo repo = genesis(b.key(), b.key(), p.key());
        String token = create(b, repo);
        String id = repo.id();
        Rotation lose = losingRaise(repo, b.key());
        AvpManifest.SignedManifest win = winnerAgainst(repo, lose.state());
        eq(publish(b, repo, token, win, null).status, 200, "publish winner");
        Reply r = b.host(p.seed, id, "offer", offer(id, List.of(lose.state()), List.of(), List.of()));
        eq(r.status, 200, "offer: " + r.body);
        eq(rejected(r), Set.of(pair(hash(lose.state()), "manifest_conflict")), "rejected");
        eq(b.view(id, v -> v.manifest(hash(lose.state())).isPresent()), Optional.of(true), "retained");
        eq(b.view(id, v -> v.isWinning(hash(lose.state()))), Optional.of(false), "off the chain");
        repo.tip = win;
        eq(b.tipHash(id), Optional.of(h(win)), "tip");
        r = b.host(p.seed, id, "fetch", fetchBody(id, hash(lose.state())));
        eq(r.at("manifests"), list(mj(repo.genesis), mj(lose.state())), "manifests");
        eq(r.at("commits"), list(), "no rotation commit");
    }

    // ─── Fix round 2: bounded work, long histories, rotation candidates, honest replies ─

    private record History(List<AvpManifest.SignedManifest> states, List<AvpCommit.Commit> commits, byte[] head) {}

    /** {@code n} offline rotations on {@code repo}, each after a commit. */
    private static History interleavedRotations(Repo repo, int n, byte[] home) throws AvpException {
        List<AvpManifest.SignedManifest> states = new ArrayList<>();
        List<AvpCommit.Commit> commits = new ArrayList<>();
        byte[] head = repo.root.commitId();
        for (int i = 0; i < n; i++) {
            AvpCommit.Commit x = repo.commit(repo.owner.seed, List.of(head), bytes("x" + i));
            Rotation rot = rotation(repo, List.of(repo.owner), null, null, List.of(x.commitId()), home);
            commits.add(x);
            head = rot.commit().commitId();
            commits.add(rot.commit());
            states.add(rot.state());
            repo.tip = rot.state();
            repo.dataKey = rot.dataKey();
        }
        return new History(states, commits, head);
    }

    /** Commits that can never apply: {@code loose} with a random parent, and a chain whose first parent is random. */
    private static List<AvpCommit.Commit> orphans(Repo repo, int loose, int chain) throws AvpException {
        List<AvpCommit.Commit> out = new ArrayList<>();
        for (int i = 0; i < loose; i++) {
            out.add(commitOn(
                    repo.genesis,
                    AvpCrypto.randomBytes(32),
                    repo.owner.seed,
                    List.of(AvpCrypto.randomBytes(32)),
                    bytes("o" + i)));
        }
        byte[] parent = AvpCrypto.randomBytes(32);
        for (int i = 0; i < chain; i++) {
            AvpCommit.Commit c =
                    commitOn(repo.genesis, AvpCrypto.randomBytes(32), repo.owner.seed, List.of(parent), bytes("c" + i));
            parent = c.commitId();
            out.add(c);
        }
        return out;
    }

    private static void offerWorkIsLinearInItsItems() throws Exception {
        Faked f = nodeWithFake();
        Node b = f.b();
        FakePeer p = f.p();
        Repo repo = genesis(p.key(), p.key(), b.key());
        String id = repo.id();
        History hist = interleavedRotations(repo, 30, p.key());
        List<AvpCommit.Commit> junk = orphans(repo, 1000, 200);

        // A first copy: genesis, 30 rotations with their pushes, and the junk, children first.
        List<AvpManifest.SignedManifest> ms = new ArrayList<>(hist.states());
        java.util.Collections.reverse(ms);
        ms.add(repo.genesis);
        List<AvpCommit.Commit> cs = new ArrayList<>(junk);
        java.util.Collections.reverse(cs);
        List<AvpCommit.Commit> honestCommits = new ArrayList<>(hist.commits());
        java.util.Collections.reverse(honestCommits);
        cs.addAll(honestCommits);
        cs.add(repo.root);
        long items = ms.size() + cs.size();
        long before = b.engineApplications();
        Reply r = b.host(p.seed, id, "offer", offer(id, ms, cs, List.of()));
        long work = b.engineApplications() - before;
        eq(r.status, 200, "offer: " + r.body.substring(0, Math.min(300, r.body.length())));
        eq(b.tipHash(id), Optional.of(h(repo.tip)), "tip");
        eq(b.heads(id), b64s(hist.head()), "heads");
        isTrue(work <= 2 * items, work + " engine applications for " + items + " items");
        // The junk cannot apply here, so it is not even tried: the work is that of the honest items.
        long honest = hist.states().size() + hist.commits().size() + 2;
        isTrue(work <= 3 * honest, work + " engine applications for " + honest + " honest items");

        // The same junk against the held repository costs no more, nor do commits citing a state behind a
        // gap nothing fills (its previous state is never offered).
        AvpManifest.SignedManifest unpublished = repo.next(s -> s.share = true);
        AvpManifest.SignedManifest behindGap = nextOf(unpublished, repo.owner.seed, s -> {});
        List<AvpCommit.Commit> js = new ArrayList<>(junk);
        for (int i = 0; i < 300; i++) {
            js.add(commitOn(behindGap, repo.dataKey, repo.owner.seed, List.of(hist.head()), bytes("g" + i)));
        }
        before = b.engineApplications();
        r = b.host(p.seed, id, "offer", offer(id, List.of(behindGap), js, List.of()));
        work = b.engineApplications() - before;
        eq(r.status, 200, "offer");
        isTrue(work <= js.size(), work + " engine applications for " + js.size() + " items");
        isTrue(work <= 64, work + " engine applications for items that cannot apply");
        eq(b.heads(id), b64s(hist.head()), "heads");
    }

    private static void bootstrapsAcross40Rotations() throws Exception {
        Node a = node();
        Node b = node();
        link(a, b);
        Repo repo = genesis(a.key(), a.key());
        String token = create(a, repo);
        String id = repo.id();
        byte[] head = repo.root.commitId();
        for (int i = 0; i < 40; i++) {
            AvpCommit.Commit x = repo.commit(repo.owner.seed, List.of(head), bytes("x" + i));
            eq(push(a, repo, token, x).status, 200, "push " + i);
            Rotation rot = rotation(repo, List.of(repo.owner), null, null, List.of(x.commitId()), a.key());
            eq(publish(a, repo, token, rot.state(), rot.commit()).status, 200, "rotation " + i);
            repo.tip = rot.state();
            repo.dataKey = rot.dataKey();
            head = rot.commit().commitId();
        }
        AvpManifest.SignedManifest listing = repo.next(s -> s.addHost(b.key(), "b.vault.example"));
        eq(publish(a, repo, token, listing, null).status, 200, "listing");
        byte[] last = head;
        eventually("B bootstraps across 40 rotations", () -> {
            eq(b.tipHash(id), Optional.of(h(listing)), "tip");
            eq(b.heads(id), b64s(last), "heads");
        });
    }

    private static void decoyRotationCandidate() throws Exception {
        Faked f = nodeWithFake();
        Node b = f.b();
        FakePeer p = f.p();
        Repo repo = genesis(p.key(), p.key(), b.key());
        String id = repo.id();
        // The real rotation commit's parent is one level deeper than the decoys', so the decoys come first.
        AvpCommit.Commit x = repo.commit(repo.owner.seed, List.of(repo.root.commitId()), bytes("x"));
        Rotation rot = rotation(repo, List.of(repo.owner), null, null, List.of(x.commitId()), p.key());
        AvpManifest.SignedManifest s2 = rot.state();
        AvpCommit.Commit stranger = repo.commit(seed(), List.of(repo.root.commitId()), bytes("stranger"));
        AvpCommit.Commit rejectedParent =
                commitOn(s2, rot.dataKey(), repo.owner.seed, List.of(stranger.commitId()), bytes("decoy-1"));
        AvpCommit.Commit unknownParent =
                commitOn(s2, rot.dataKey(), repo.owner.seed, List.of(AvpCrypto.randomBytes(32)), bytes("decoy-2"));
        AvpCommit.Commit d3 =
                commitOn(s2, rot.dataKey(), repo.owner.seed, List.of(repo.root.commitId()), bytes("decoy-3"));
        AvpCommit.Commit forged = withSignature(d3, flip(d3.authorSignature(), 0));
        Reply r = b.host(
                p.seed,
                id,
                "offer",
                offer(
                        id,
                        List.of(repo.genesis, s2),
                        List.of(repo.root, stranger, x, forged, unknownParent, rejectedParent, rot.commit()),
                        List.of()));
        eq(r.status, 200, "offer: " + r.body);
        eq(b.tipHash(id), Optional.of(h(s2)), "tip");
        eq(
                b.view(id, v -> v.rotationCommit(hash(s2)).map(SmokeTest::cj)),
                Optional.of(Optional.of(cj(rot.commit()))),
                "rotation commit");
        eq(
                idSet(r.at("accepted")),
                b64Set(
                        hash(repo.genesis),
                        hash(s2),
                        repo.root.commitId(),
                        x.commitId(),
                        rot.commit().commitId()),
                "accepted");
        Set<String> rej = rejected(r);
        isTrue(rej.contains(pair(stranger.commitId(), "forbidden")), "stranger: " + r.body);
        isTrue(rej.contains(pair(rejectedParent.commitId(), "forbidden")), "rejected parent: " + r.body);
        isTrue(rej.contains(pair(unknownParent.commitId(), "missing_parents")), "unknown parent: " + r.body);
        isTrue(rej.contains(pair(forged.commitId(), "bad_request")), "forged: " + r.body);
        eq(b.heads(id), b64s(rot.commit().commitId()), "heads");
    }

    private static void offerAnswerMatchesWhatIsStored() throws Exception {
        Faked f = nodeWithFake();
        Node b = f.b();
        FakePeer p = f.p();
        Repo repo = genesis(b.key(), b.key(), p.key());
        String token = create(b, repo);
        String id = repo.id();
        Device carol = new Device();
        AvpManifest.MemberEntry entry = carol.entry(repo.dataKey, 0, b.key());
        AvpManifest.SignedManifest s2 = repo.next(s -> s.members.add(entry));
        eq(publish(b, repo, token, s2, null).status, 200, "publish");
        repo.tip = s2;
        AvpCommit.Commit x = repo.commit(carol.seed, List.of(repo.root.commitId()), bytes("x"));
        Reply r = b.host(p.seed, id, "offer", offer(id, List.of(), List.of(x), List.of()));
        eq(idSet(r.at("accepted")), b64Set(x.commitId()), "x accepted");
        // Removing carol with a frontier naming f, whose header this host lacks: x becomes pending. f also has
        // a parent the engine rejects (a stranger's commit), so f is tried but ends rejected and is not kept.
        AvpCommit.Commit stranger = repo.commit(seed(), List.of(repo.root.commitId()), bytes("stranger"));
        AvpCommit.Commit fc = repo.commit(carol.seed, List.of(x.commitId(), stranger.commitId()), bytes("f"));
        Rotation rot = rotation(
                repo, List.of(repo.owner), carol, List.of(fc.commitId()), List.of(repo.root.commitId()), b.key());
        eq(publish(b, repo, token, rot.state(), rot.commit()).status, 200, "publish rotation");
        eq(b.view(id, v -> idList(v.pending())), Optional.of(ids(x.commitId())), "pending");
        repo.tip = rot.state();
        repo.dataKey = rot.dataKey();
        // On the trial f's header covers x, so k (a child of x) is accepted there; the stored copy drops f
        // with its header, x stays pending, and k is not stored.
        AvpCommit.Commit k = repo.commit(repo.owner.seed, List.of(x.commitId()), bytes("k"));
        r = b.host(p.seed, id, "offer", offer(id, List.of(), List.of(stranger, fc, k), List.of()));
        eq(r.status, 200, "offer: " + r.body);
        for (Object a : (List<?>) r.at("accepted")) {
            byte[] accepted = unb64(a);
            eq(
                    b.view(id, v -> v.status(accepted)),
                    Optional.of(Optional.of(AvpRules.CommitStatus.ACCEPTED)),
                    "answer accepts " + a + " but it is not stored as accepted: " + r.body);
        }
        isTrue(rejected(r).contains(pair(fc.commitId(), "forbidden")), "f: " + r.body);
        isTrue(rejected(r).contains(pair(k.commitId(), "missing_parents")), "k: " + r.body);
        eq(b.view(id, v -> v.status(k.commitId())), Optional.of(Optional.empty()), "k not stored");
        eq(b.view(id, v -> idList(v.pending())), Optional.of(ids(x.commitId())), "x still pending");
    }

    private static void losingStateKeepsItsRotationCommit() throws Exception {
        Faked f = nodeWithFake();
        Node b = f.b();
        FakePeer p = f.p();
        Repo repo = genesis(b.key(), b.key(), p.key());
        String token = create(b, repo);
        String id = repo.id();
        Rotation lose = losingRaise(repo, b.key());
        AvpManifest.SignedManifest win = winnerAgainst(repo, lose.state());
        eq(publish(b, repo, token, win, null).status, 200, "publish winner");
        AvpCommit.Commit fc =
                commitOn(lose.state(), lose.dataKey(), repo.owner.seed, List.of(repo.root.commitId()), bytes("forged"));
        AvpCommit.Commit forged = withSignature(fc, flip(fc.authorSignature(), 0));
        Reply r = b.host(
                p.seed, id, "offer", offer(id, List.of(lose.state()), List.of(forged, lose.commit()), List.of()));
        eq(r.status, 200, "offer: " + r.body);
        // The answer pairs the losing state with its real rotation commit (SPEC 9.1: same code).
        eq(
                rejected(r),
                Set.of(
                        pair(hash(lose.state()), "manifest_conflict"),
                        pair(lose.commit().commitId(), "manifest_conflict"),
                        pair(forged.commitId(), "bad_request")),
                "rejected");
        eq(
                b.view(id, v -> v.rotationCommit(hash(lose.state())).map(SmokeTest::cj)),
                Optional.of(Optional.of(cj(lose.commit()))),
                "rotation commit");
        eq(
                b.view(id, v -> v.status(lose.commit().commitId())),
                Optional.of(Optional.of(AvpRules.CommitStatus.HELD)),
                "held");
        r = b.host(p.seed, id, "fetch", fetchBody(id, hash(lose.state())));
        eq(r.at("commits"), list(cj(lose.commit())), "served");
    }

    // ─── Fix round 3: what a catch-up carries between rounds ────────────────────────────

    private record Round(List<AvpManifest.SignedManifest> manifests, List<AvpCommit.Commit> commits) {}

    private record CatchUp(int rounds, long work, long fetched) {}

    /** A minimal HTTP peer: reads one request, answers with {@code answer(path)}, closes. Runs until stop. */
    private static Thread scriptedPeer(
            ServerSocket listener, AtomicBoolean stop, Function<String, Map.Entry<Integer, String>> answer) {
        Thread t = new Thread(() -> {
            while (!stop.get()) {
                try (Socket s = listener.accept()) {
                    s.setSoTimeout(2000);
                    InputStream in = s.getInputStream();
                    ByteArrayOutputStream buf = new ByteArrayOutputStream();
                    byte[] tmp = new byte[65536];
                    int need = -1;
                    int n;
                    while ((n = in.read(tmp)) > 0) {
                        buf.write(tmp, 0, n);
                        String text = buf.toString(StandardCharsets.ISO_8859_1);
                        if (need < 0) {
                            int p = text.indexOf("\r\n\r\n");
                            if (p >= 0) {
                                int len = 0;
                                for (String line : text.substring(0, p).split("\r\n")) {
                                    String l = line.toLowerCase(java.util.Locale.ROOT);
                                    if (l.startsWith("content-length:")) {
                                        len = Integer.parseInt(l.substring(15).trim());
                                    }
                                }
                                need = p + 4 + len;
                            }
                        }
                        if (need >= 0 && buf.size() >= need) {
                            break;
                        }
                    }
                    String first = buf.toString(StandardCharsets.ISO_8859_1).split("\r\n", 2)[0];
                    String[] parts = first.split(" ");
                    String path = parts.length > 1 ? parts[1] : "";
                    Map.Entry<Integer, String> reply = answer.apply(path);
                    byte[] body = bytes(reply.getValue());
                    String head =
                            "HTTP/1.1 " + reply.getKey() + " X\r\nContent-Type: application/json\r\nContent-Length: "
                                    + body.length + "\r\nConnection: close\r\n\r\n";
                    OutputStream out = s.getOutputStream();
                    out.write(bytes(head));
                    out.write(body);
                } catch (SocketTimeoutException e) {
                    // The accept timeout: re-check the stop flag.
                } catch (IOException e) {
                    // A client that hung up.
                }
            }
        });
        t.setDaemon(true);
        t.start();
        return t;
    }

    /**
     * Runs one catch-up of a repository on {@code b} from a scripted peer whose {@code heads} answers {@code
     * tip} once and whose {@code fetch} answers {@code round(n)} for the first {@code fetches} rounds.
     */
    private static CatchUp oneCatchUp(
            Node b, byte[] peer, long tipSeq, byte[] tipHash, int fetches, IntFunction<Round> round) throws Exception {
        AtomicBoolean stop = new AtomicBoolean(false);
        AtomicInteger headsServed = new AtomicInteger();
        AtomicInteger fetched = new AtomicInteger();
        AtomicInteger rounds = new AtomicInteger();
        Map.Entry<Integer, String> notFound = Map.entry(404, "{\"error\":\"x\",\"code\":\"not_found\"}");
        try (ServerSocket listener = new ServerSocket()) {
            listener.bind(new InetSocketAddress("127.0.0.1", 0));
            listener.setSoTimeout(50);
            Thread server = scriptedPeer(listener, stop, path -> {
                if (path.endsWith("/heads")) {
                    if (headsServed.getAndIncrement() > 0) {
                        return notFound;
                    }
                    return Map.entry(
                            200,
                            AvpJson.write(obj(
                                    "manifestTip",
                                    obj("manifestSeq", tipSeq, "manifestHash", b64(tipHash)),
                                    "heads",
                                    list())));
                }
                if (path.endsWith("/fetch")) {
                    int n = rounds.getAndIncrement();
                    if (n >= fetches) {
                        return notFound;
                    }
                    Round rd = round.apply(n);
                    fetched.addAndGet(rd.manifests().size() + rd.commits().size());
                    List<Object> ms = new ArrayList<>();
                    for (AvpManifest.SignedManifest m : rd.manifests()) {
                        ms.add(AvpManifest.toJson(m));
                    }
                    List<Object> cs = new ArrayList<>();
                    for (AvpCommit.Commit c : rd.commits()) {
                        cs.add(AvpCommit.toJson(c));
                    }
                    return Map.entry(200, AvpJson.write(obj("manifests", ms, "commits", cs, "leaves", list())));
                }
                return notFound;
            });
            long before = b.engineApplications();
            b.peerWith(b64(pk(peer)) + "@http://127.0.0.1:" + listener.getLocalPort());
            // Wait until the catch-up has stopped (no fetch and no engine work for a while), at most 60 s.
            long deadline = System.currentTimeMillis() + 60_000;
            long[] last = {rounds.get(), b.engineApplications()};
            while (true) {
                Thread.sleep(SWEEP_MS * 5);
                long[] now = {rounds.get(), b.engineApplications()};
                boolean still = now[0] == last[0] && now[1] == last[1] && now[0] >= 2;
                last = now;
                if (still || System.currentTimeMillis() > deadline) {
                    break;
                }
            }
            stop.set(true);
            b.unpeer();
            server.join(5000);
            return new CatchUp((int) Math.min(last[0], fetches), last[1] - before, fetched.get());
        }
    }

    private static void catchUpWorkDoesNotGrow() throws Exception {
        int perRound = 100;
        byte[] peer = seed();
        Node b = node();
        Repo repo = genesis(b.key(), b.key(), pk(peer));
        create(b, repo);
        Rotation rot = rotation(repo, List.of(repo.owner), null, null, List.of(AvpCrypto.randomBytes(32)), b.key());
        AvpManifest.SignedManifest s = rot.state();
        CatchUp cu = oneCatchUp(b, peer, 2, hash(s), 12, n -> {
            try {
                List<AvpCommit.Commit> commits = new ArrayList<>();
                commits.add(rot.commit());
                for (int i = 0; i < perRound; i++) {
                    commits.add(commitOn(
                            s, rot.dataKey(), seed(), List.of(repo.root.commitId()), bytes("j" + n + "-" + i)));
                }
                commits.add(commitOn(
                        repo.genesis,
                        repo.dataKey,
                        repo.owner.seed,
                        List.of(AvpCrypto.randomBytes(32)),
                        bytes("more")));
                return new Round(List.of(s), commits);
            } catch (AvpException e) {
                throw new IllegalStateException(e);
            }
        });
        System.out.println("  catch-up: " + cu.rounds() + " rounds, " + cu.work() + " engine applications for "
                + cu.fetched() + " fetched items");
        isTrue(cu.rounds() >= 2, "the catch-up fetched only " + cu.rounds() + " times");
        // Linear in what was fetched, not in rounds times what was carried.
        isTrue(cu.work() <= 2 * cu.fetched() + 256, cu.work() + " engine applications for " + cu.fetched() + " items");
        isTrue(cu.work() <= 2 * (3 * 4096 + 64), cu.work() + " engine applications in one catch-up");
        // None of the strangers' commits can apply in its batch, so none is tried: the pair's work, once a round.
        isTrue(cu.work() <= 4L * cu.rounds(), cu.work() + " engine applications for " + cu.rounds() + " rounds");
        eq(b.tipHash(repo.id()), Optional.of(h(repo.genesis)), "tip");
    }

    private static void carriedItemsRetried() throws Exception {
        int perRound = 100;
        byte[] peer = seed();
        Node b = node();
        Repo repo = genesis(b.key(), b.key(), pk(peer));
        String token = create(b, repo);
        Device carol = new Device();
        AvpManifest.MemberEntry entry = carol.entry(repo.dataKey, 0, b.key());
        AvpManifest.SignedManifest s2 = repo.next(s -> s.members.add(entry));
        eq(publish(b, repo, token, s2, null).status, 200, "publish");
        repo.tip = s2;
        Rotation rot = rotation(
                repo,
                List.of(repo.owner),
                carol,
                List.of(AvpCrypto.randomBytes(32)),
                List.of(repo.root.commitId()),
                b.key());
        eq(publish(b, repo, token, rot.state(), rot.commit()).status, 200, "publish rotation");
        byte[] dataKey = repo.dataKey;
        CatchUp cu = oneCatchUp(b, peer, 3, hash(rot.state()), 12, n -> {
            try {
                List<AvpCommit.Commit> commits = new ArrayList<>();
                for (int i = 0; i < perRound; i++) {
                    commits.add(
                            commitOn(s2, dataKey, carol.seed, List.of(repo.root.commitId()), bytes("c" + n + "-" + i)));
                }
                commits.add(commitOn(
                        repo.genesis, dataKey, repo.owner.seed, List.of(AvpCrypto.randomBytes(32)), bytes("more")));
                return new Round(List.of(), commits);
            } catch (AvpException e) {
                throw new IllegalStateException(e);
            }
        });
        System.out.println("  carried: " + cu.rounds() + " rounds, " + cu.work() + " engine applications for "
                + cu.fetched() + " fetched items");
        isTrue(cu.rounds() >= 4, "the catch-up fetched only " + cu.rounds() + " times");
        isTrue(cu.work() <= 2 * cu.fetched() + 256, cu.work() + " engine applications for " + cu.fetched() + " items");
        eq(b.heads(repo.id()), b64s(rot.commit().commitId()), "heads");
    }

    private static void eightDecoys() throws Exception {
        Faked f = nodeWithFake();
        Node b = f.b();
        FakePeer p = f.p();
        Repo repo = genesis(b.key(), b.key(), p.key());
        create(b, repo);
        String id = repo.id();
        Rotation rot = rotation(repo, List.of(repo.owner), null, null, List.of(repo.root.commitId()), b.key());
        List<AvpCommit.Commit> cs = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            AvpCommit.Commit c = commitOn(
                    rot.state(), rot.dataKey(), repo.owner.seed, List.of(repo.root.commitId()), bytes("d" + i));
            cs.add(withSignature(c, flip(c.authorSignature(), i)));
        }
        List<AvpCommit.Commit> decoys = List.copyOf(cs);
        cs.add(rot.commit());
        Reply r = b.host(p.seed, id, "offer", offer(id, List.of(rot.state()), cs, List.of()));
        eq(r.status, 200, "offer: " + r.body);
        eq(b.tipHash(id), Optional.of(h(rot.state())), "tip");
        eq(
                b.view(id, v -> v.rotationCommit(hash(rot.state())).map(SmokeTest::cj)),
                Optional.of(Optional.of(cj(rot.commit()))),
                "rotation commit");
        eq(idSet(r.at("accepted")), b64Set(hash(rot.state()), rot.commit().commitId()), "accepted");
        for (AvpCommit.Commit d : decoys) {
            isTrue(rejected(r).contains(pair(d.commitId(), "bad_request")), "decoy: " + r.body);
        }
    }
}
