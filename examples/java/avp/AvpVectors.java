/*
 * Conformance runner for the shared Java AVP sources.
 *
 * Runs every shared vector file in vectors/ (the RFC-anchored primitives, bip39-owner, manifest,
 * commit, federation, negative, merge, and acceptance), the focused reject checks below the rules
 * engine (decoder lengths, BIP39 rejects, malformed JSON), and the rules engine checks that mirror
 * the Rust reference tests. Every expected value is read from a vector file or written here from
 * the SPEC; none is produced by the code under test.
 *
 * Run from examples/java/avp:
 *
 *     javac -d build *.java && java -cp build AvpVectors
 *
 * SPDX-License-Identifier: MIT
 */

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Conformance runner: replays every shared vector file against the Java AVP sources.
 *
 * <p>Each individual assertion is one check. The run prints {@code N passed}, where N counts every
 * check that passed, then lists every failed check and exits with status 1 if any failed. A
 * section that throws an unexpected exception is one failed check and the run continues with the
 * next section or scenario.
 */
public final class AvpVectors {

    /** The verdict strings an {@code acceptance.json} step may expect (SPEC 10.4). */
    private static final Set<String> VERDICTS = Set.of(
            "ok", "bad_request", "forbidden", "not_hosted", "too_many_heads", "manifest_conflict", "missing_parents");

    private static final Path VECTORS = Path.of(System.getProperty("avp.vectors", "../../../vectors"));

    private static int passed;
    private static final List<String> FAILURES = new ArrayList<>();

    private AvpVectors() {}

    /** A check body that may throw. */
    @FunctionalInterface
    private interface Body {
        void run() throws Exception;
    }

    /**
     * Runs every vector file and check, prints the count of passed checks, and exits 1 on any failure.
     *
     * @param args ignored
     */
    public static void main(String[] args) {
        section("ce-writer", AvpVectors::ceWriter);
        section("hkdf", AvpVectors::hkdf);
        section("x25519", AvpVectors::x25519);
        section("ed25519", AvpVectors::ed25519);
        section("key-wrap", AvpVectors::keyWrap);
        section("bip39-owner", AvpVectors::bip39Owner);
        section("manifest", AvpVectors::manifest);
        section("manifest-wraps", AvpVectors::manifestWraps);
        section("commit", AvpVectors::commit);
        section("federation", AvpVectors::federation);
        section("negative", AvpVectors::negative);
        section("merge", AvpVectors::merge);
        section("hlc", AvpVectors::hlc);
        section("acceptance", AvpVectors::acceptance);
        section("rules-extra", AvpVectors::rulesExtra);
        section("decoder-lengths", AvpVectors::decoderLengths);
        section("token-rejects", AvpVectors::tokenRejects);
        section("bip39-rejects", AvpVectors::bip39Rejects);
        section("json", AvpVectors::json);
        section("strict-ed25519", AvpVectors::strictEd25519);
        section("defensive-copies", AvpVectors::defensiveCopies);

        System.out.println(passed + " passed");
        if (!FAILURES.isEmpty()) {
            for (String f : FAILURES) {
                System.out.println("FAIL " + f);
            }
            System.out.println(FAILURES.size() + " failed");
            System.exit(1);
        }
    }

    // ─── Harness ──────────────────────────────────────────────────────────────────────

    private static void section(String name, Body body) {
        try {
            body.run();
        } catch (Exception e) {
            FAILURES.add(name + ": unexpected " + e);
        }
    }

    private static void check(boolean ok, String what) {
        if (ok) {
            passed++;
        } else {
            FAILURES.add(what);
        }
    }

    private static void eq(Object want, Object got, String what) {
        boolean ok =
                (want instanceof byte[] w && got instanceof byte[] g) ? Arrays.equals(w, g) : Objects.equals(want, got);
        check(ok, what + ": want " + show(want) + ", got " + show(got));
    }

    private static String show(Object o) {
        String s = o instanceof byte[] b ? AvpEncoding.hex(b) : String.valueOf(o);
        return s.length() > 200 ? s.substring(0, 200) + "..." : s;
    }

    /** Checks that {@code body} fails with an {@link AvpException}, and with no unchecked exception. */
    private static void rejects(Body body, String what) {
        try {
            body.run();
            check(false, what + ": accepted");
        } catch (AvpException e) {
            check(true, what);
        } catch (Exception e) {
            check(false, what + ": unchecked " + e);
        }
    }

    /** Checks that {@code body} fails with an {@link AvpException} of the given kind. */
    private static void rejectsWith(AvpException.Kind kind, Body body, String what) {
        try {
            body.run();
            check(false, what + ": accepted");
        } catch (AvpException e) {
            eq(kind, e.kind(), what);
        } catch (Exception e) {
            check(false, what + ": unchecked " + e);
        }
    }

    private static Object load(String name) throws IOException, AvpException {
        return AvpJson.parse(Files.readString(VECTORS.resolve(name), StandardCharsets.UTF_8));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) {
        return (Map<String, Object>) o;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) {
        return (List<Object>) o;
    }

    private static String s(Map<String, Object> o, String key) {
        return (String) o.get(key);
    }

    private static long i(Map<String, Object> o, String key) {
        return (Long) o.get(key);
    }

    private static byte[] hx(String s) throws AvpException {
        return AvpEncoding.fromHex(s);
    }

    private static byte[] b64(String s) throws AvpException {
        return AvpEncoding.fromBase64(s);
    }

    private static byte[] sha256Label(String label) {
        return AvpCrypto.sha256(label.getBytes(StandardCharsets.UTF_8));
    }

    private static Map<String, Object> find(List<Object> items, String key, String value) {
        for (Object o : items) {
            if (value.equals(m(o).get(key))) {
                return m(o);
            }
        }
        throw new IllegalStateException("no item with " + key + " = " + value);
    }

    private static List<String> names(List<Object> cases) {
        List<String> out = new ArrayList<>();
        for (Object c : cases) {
            out.add(s(m(c), "name"));
        }
        return out;
    }

    private static List<String> sortedB64(List<byte[]> ids) {
        List<String> out = new ArrayList<>();
        for (byte[] id : ids) {
            out.add(AvpEncoding.base64(id));
        }
        out.sort(Comparator.naturalOrder());
        return out;
    }

    private static List<String> sortedStrings(Object list) {
        List<String> out = new ArrayList<>();
        for (Object o : l(list)) {
            out.add((String) o);
        }
        out.sort(Comparator.naturalOrder());
        return out;
    }

    // ─── CE writer (SPEC 4.1), expected bytes written by hand from the SPEC table ─────

    private static void ceWriter() throws Exception {
        eq("6176702f7800", AvpEncoding.hex(AvpEncoding.tag("avp/x").finish()), "ce tag");
        eq(
                "6176702f780000000003deadbe",
                AvpEncoding.hex(AvpEncoding.tag("avp/x")
                        .bytes(new byte[] {(byte) 0xde, (byte) 0xad, (byte) 0xbe})
                        .finish()),
                "ce bytes");
        eq(
                "7400" + "000000026162" + "0000000000000002" + "01" + "00000001" + "00000001ff",
                AvpEncoding.hex(AvpEncoding.tag("t")
                        .str("ab")
                        .i64(2)
                        .bool(true)
                        .count(1)
                        .bytes(new byte[] {(byte) 0xff})
                        .finish()),
                "ce items");
        String expected = String.join(
                "",
                "7400", // tag("t")
                "ffffffffffffffff", // i64(-1)
                "0000000100000002", // i64(2^32 + 2): a 32-bit truncation would give ...00000002
                "7fffffffffffffff", // i64(MAX)
                "8000000000000000", // i64(MIN)
                "00", // bool(false)
                "00000000", // count(0)
                "0000000361c3a9", // str("aé"): U+00E9 is c3 a9, so the length is 3
                "00000000", // bytes(empty)
                "7fffffff"); // count(Integer.MAX_VALUE)
        eq(
                expected,
                AvpEncoding.hex(AvpEncoding.tag("t")
                        .i64(-1)
                        .i64(4_294_967_298L)
                        .i64(Long.MAX_VALUE)
                        .i64(Long.MIN_VALUE)
                        .bool(false)
                        .count(0)
                        .str("a\u00e9")
                        .bytes(new byte[0])
                        .count(Integer.MAX_VALUE)
                        .finish()),
                "ce edge values");
        rejects(() -> AvpEncoding.tag("a\0b").finish(), "ce tag with 0x00");
        rejects(() -> AvpEncoding.tag("t").count(-1).finish(), "ce negative count");
    }

    // ─── RFC-anchored primitives ──────────────────────────────────────────────────────

    private static void hkdf() throws Exception {
        List<Object> cases = l(m(load("hkdf.json")).get("cases"));
        eq(2, cases.size(), "hkdf case count");
        for (Object o : cases) {
            Map<String, Object> c = m(o);
            byte[] ikm = hx(s(c, "ikmHex"));
            byte[] salt = hx(s(c, "saltHex"));
            byte[] info = hx(s(c, "infoHex"));
            eq(s(c, "prkHex"), AvpEncoding.hex(AvpCrypto.hkdfExtract(salt, ikm)), s(c, "name") + " prk");
            byte[] okm = AvpCrypto.hkdf(ikm, salt, info, (int) i(c, "length"));
            eq(s(c, "okmHex"), AvpEncoding.hex(okm), s(c, "name") + " okm");
        }
        rejects(() -> AvpCrypto.hkdf(new byte[1], new byte[0], new byte[0], 255 * 32 + 1), "hkdf length limit");
    }

    private static void x25519() throws Exception {
        List<Object> cases = l(m(load("x25519.json")).get("cases"));
        eq(3, cases.size(), "x25519 case count");
        for (Object o : cases) {
            Map<String, Object> c = m(o);
            byte[] out = AvpCrypto.x25519(hx(s(c, "scalarHex")), hx(s(c, "uCoordinateHex")));
            eq(s(c, "outputHex"), AvpEncoding.hex(out), s(c, "name"));
        }
    }

    private static void ed25519() throws Exception {
        List<Object> cases = l(m(load("ed25519.json")).get("cases"));
        eq(2, cases.size(), "ed25519 case count");
        for (Object o : cases) {
            Map<String, Object> c = m(o);
            String name = s(c, "name");
            byte[] seed = hx(s(c, "seedHex"));
            byte[] pub = AvpCrypto.ed25519Public(seed);
            eq(s(c, "publicKeyHex"), AvpEncoding.hex(pub), name + " public key");
            byte[] msg = hx(s(c, "messageHex"));
            byte[] sig = AvpCrypto.ed25519Sign(seed, msg);
            eq(s(c, "signatureHex"), AvpEncoding.hex(sig), name + " signature");
            check(AvpCrypto.ed25519Verify(pub, msg, sig), name + " verifies");
        }
    }

    private static void keyWrap() throws Exception {
        List<Object> cases = l(m(load("key-wrap.json")).get("cases"));
        eq(1, cases.size(), "key-wrap case count");
        for (Object o : cases) {
            Map<String, Object> c = m(o);
            byte[] recipient = b64(s(c, "recipientPrivateKeyB64"));
            eq(
                    s(c, "recipientPublicKeyB64"),
                    AvpEncoding.base64(AvpCrypto.x25519Public(recipient)),
                    "recipient public");
            AvpManifest.WrappedKey wk = AvpManifest.wrappedKeyFromJson(c.get("wrappedKey"));
            byte[] shared = AvpCrypto.x25519(recipient, wk.ephemeralPublicKey());
            eq(s(c, "sharedSecretHex"), AvpEncoding.hex(shared), "shared secret");
            eq(s(c, "info"), AvpCrypto.WRAP_INFO, "wrap info label");
            byte[] info = AvpCrypto.WRAP_INFO.getBytes(StandardCharsets.UTF_8);
            byte[] kek = AvpCrypto.hkdf(shared, wk.ephemeralPublicKey(), info, 32);
            eq(s(c, "kekHex"), AvpEncoding.hex(kek), "kek");
            byte[] dataKey = b64(s(c, "dataKeyB64"));
            eq(wk.ciphertext(), AvpCrypto.aesGcmSeal(kek, wk.iv(), dataKey, info), "re-sealed wrap");
            eq(dataKey, AvpCrypto.unwrap(recipient, wk, AvpCrypto.WRAP_INFO), "unwrap recovers the data key");
            eq(c.get("wrappedKey"), AvpManifest.toJson(wk), "wrapped key wire round trip");
            rejectsWith(
                    AvpException.Kind.CRYPTO,
                    () -> AvpCrypto.unwrap(recipient, wk, AvpCrypto.OWNER_LINK_INFO),
                    "a data key wrap does not open under the link label");
        }
    }

    // ─── bip39-owner.json (SPEC 3.1) ──────────────────────────────────────────────────

    private static void bip39Owner() throws Exception {
        byte[] words = Files.readAllBytes(VECTORS.resolve("bip39-english.txt"));
        eq(
                "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
                AvpEncoding.hex(AvpCrypto.sha256(words)),
                "wordlist sha256");

        Map<String, Object> file = m(load("bip39-owner.json"));
        Map<String, Object> anchors = m(file.get("anchors"));
        eq("TREZOR", s(anchors, "passphrase"), "anchor passphrase");
        List<Object> anchorCases = l(anchors.get("cases"));
        eq(3, anchorCases.size(), "anchor count");
        for (Object o : anchorCases) {
            Map<String, Object> a = m(o);
            byte[] entropy = hx(s(a, "entropyHex"));
            eq(s(a, "mnemonic"), AvpOwner.entropyToMnemonic(entropy), "anchor mnemonic");
            eq(entropy, AvpOwner.mnemonicToEntropy(s(a, "mnemonic")), "anchor entropy");
            eq(s(a, "seedHex"), AvpEncoding.hex(AvpOwner.mnemonicToSeed(s(a, "mnemonic"), "TREZOR")), "anchor seed");
        }

        List<Object> cases = l(file.get("cases"));
        eq(3, cases.size(), "bip39 case count");
        for (Object o : cases) {
            Map<String, Object> c = m(o);
            String name = s(c, "name");
            eq("", s(c, "passphrase"), name + " passphrase");
            byte[] entropy = hx(s(c, "entropyHex"));
            eq(s(c, "mnemonic"), AvpOwner.entropyToMnemonic(entropy), name + " mnemonic");
            eq(entropy, AvpOwner.mnemonicToEntropy(s(c, "mnemonic")), name + " entropy");
            byte[] seed = AvpOwner.mnemonicToSeed(s(c, "mnemonic"), "");
            eq(s(c, "seedHex"), AvpEncoding.hex(seed), name + " seed");
            AvpOwner.OwnerKeys keys = AvpOwner.fromSeed(seed);
            eq(s(c, "ed25519SeedHex"), AvpEncoding.hex(keys.ed25519Seed()), name + " ed25519 seed");
            eq(s(c, "ed25519PublicKeyHex"), AvpEncoding.hex(keys.ed25519Public()), name + " ownerKey");
            eq(s(c, "x25519PrivateHex"), AvpEncoding.hex(keys.x25519Private()), name + " x25519 private");
            eq(s(c, "x25519PublicKeyHex"), AvpEncoding.hex(keys.x25519Public()), name + " x25519 public");
            AvpOwner.OwnerKeys fromEntropy = AvpOwner.fromEntropy(entropy);
            eq(s(c, "ed25519PublicKeyHex"), AvpEncoding.hex(fromEntropy.ed25519Public()), name + " from entropy");
            check(!keys.toString().contains(s(c, "ed25519SeedHex")), name + " toString hides the seed");
        }
    }

    // ─── manifest.json (SPEC 4.1, 4.2) ────────────────────────────────────────────────

    private static void manifest() throws Exception {
        Map<String, Object> file = m(load("manifest.json"));
        Map<String, Object> seeds = m(file.get("seeds"));
        byte[] ownerSeed = hx(s(m(seeds.get("owner")), "ed25519SeedHex"));
        List<Object> cases = l(file.get("cases"));
        eq(List.of("genesis", "add-members", "remove-member", "policy-flip"), names(cases), "manifest case names");

        AvpManifest.SignedManifest prev = null;
        for (Object o : cases) {
            Map<String, Object> c = m(o);
            String name = s(c, "name");
            Object wire = c.get("signedManifest");
            AvpManifest.SignedManifest sm = AvpManifest.signedManifestFromJson(wire);
            Map<String, Object> expected = m(c.get("expected"));

            eq(s(expected, "stateHex"), AvpEncoding.hex(AvpManifest.encode(sm.state())), name + " S");
            AvpManifest.SignedManifest resigned = AvpManifest.sign(sm.state(), ownerSeed);
            eq(sm.ownerSignature(), resigned.ownerSignature(), name + " ownerSignature");
            check(AvpManifest.verify(sm), name + " verifies");
            eq(s(expected, "manifestHashHex"), AvpEncoding.hex(AvpManifest.hash(sm)), name + " manifestHash");
            eq(wire, AvpManifest.toJson(sm), name + " wire round trip");

            // The encoding sorts every list, so any input order gives the same bytes.
            AvpManifest.ManifestState st = sm.state();
            List<AvpManifest.HostRef> hosts = new ArrayList<>(st.hosts());
            java.util.Collections.reverse(hosts);
            List<AvpManifest.MemberEntry> members = new ArrayList<>(st.members());
            java.util.Collections.rotate(members, -1);
            List<AvpManifest.Removal> removals = new ArrayList<>();
            for (AvpManifest.Removal r : st.removals()) {
                List<byte[]> frontier = new ArrayList<>(r.frontier());
                java.util.Collections.reverse(frontier);
                removals.add(new AvpManifest.Removal(r.memberKey(), r.removedAtSeq(), frontier));
            }
            java.util.Collections.reverse(removals);
            AvpManifest.ManifestState shuffled = new AvpManifest.ManifestState(
                    st.repoId(),
                    st.manifestSeq(),
                    st.prevManifestHash(),
                    st.ownerKey(),
                    st.genesisNonce(),
                    st.schemeId(),
                    st.keyEpoch(),
                    st.shareRefreshTokens(),
                    hosts,
                    members,
                    removals);
            eq(s(expected, "stateHex"), AvpEncoding.hex(AvpManifest.encode(shuffled)), name + " order independent");

            if (st.manifestSeq() == 1) {
                eq(s(expected, "repoId"), AvpManifest.deriveRepoId(st.ownerKey(), st.genesisNonce()), name + " repoId");
                eq(s(expected, "repoId"), st.repoId(), name + " repoId field");
            }
            if (prev != null) {
                check(AvpManifest.linksTo(sm, prev), name + " links to the previous state");
            }
            prev = sm;
        }

        // A list that repeats a key is malformed (SPEC 4.2).
        AvpManifest.ManifestState g = AvpManifest.signedManifestFromJson(
                        m(l(file.get("cases")).get(0)).get("signedManifest"))
                .state();
        List<AvpManifest.HostRef> twice = new ArrayList<>(g.hosts());
        twice.add(g.hosts().get(0));
        AvpManifest.ManifestState dup = new AvpManifest.ManifestState(
                g.repoId(),
                g.manifestSeq(),
                g.prevManifestHash(),
                g.ownerKey(),
                g.genesisNonce(),
                g.schemeId(),
                g.keyEpoch(),
                g.shareRefreshTokens(),
                twice,
                g.members(),
                g.removals());
        rejectsWith(AvpException.Kind.BAD_ENCODING, () -> AvpManifest.encode(dup), "duplicate hostKey");
    }

    private static void manifestWraps() throws Exception {
        Map<String, Object> file = m(load("manifest.json"));
        Map<String, Object> seeds = m(file.get("seeds"));
        // label, ed25519 public key (base64), x25519 private key
        List<String[]> parties = new ArrayList<>();
        Map<String, Object> owner = m(seeds.get("owner"));
        parties.add(new String[] {"owner", s(owner, "ownerKey"), s(owner, "x25519PrivateHex")});
        for (Object o : l(seeds.get("members"))) {
            Map<String, Object> mm = m(o);
            parties.add(new String[] {s(mm, "label"), s(mm, "ed25519PublicKey"), s(mm, "x25519PrivateHex")});
        }
        int checked = 0;
        for (Object o : l(file.get("cases"))) {
            AvpManifest.SignedManifest sm = AvpManifest.signedManifestFromJson(m(o).get("signedManifest"));
            for (AvpManifest.MemberEntry member : sm.state().members()) {
                String id = AvpEncoding.base64(member.ed25519PublicKey());
                String[] party = parties.stream()
                        .filter(p -> p[1].equals(id))
                        .findFirst()
                        .orElseThrow();
                byte[] xPriv = hx(party[2]);
                eq(member.x25519PublicKey(), AvpCrypto.x25519Public(xPriv), party[0] + " x25519 public");
                byte[] expectedKey = null;
                for (Object k : l(seeds.get("dataKeys"))) {
                    if (i(m(k), "keyEpoch") == member.keyEpoch()) {
                        expectedKey = hx(s(m(k), "dataKeyHex"));
                    }
                }
                eq(
                        expectedKey,
                        AvpCrypto.unwrap(xPriv, member.wrappedDataKey(), AvpCrypto.WRAP_INFO),
                        party[0] + " unwraps the epoch key");
                byte[] eph = sha256Label("avp/vectors/wrap-ephemeral/" + member.keyEpoch() + "/" + party[0]);
                byte[] iv = Arrays.copyOf(sha256Label("avp/vectors/wrap-iv/" + member.keyEpoch() + "/" + party[0]), 12);
                AvpManifest.WrappedKey rewrapped =
                        AvpCrypto.wrapWith(member.x25519PublicKey(), expectedKey, AvpCrypto.WRAP_INFO, eph, iv);
                eq(
                        AvpManifest.toJson(member.wrappedDataKey()),
                        AvpManifest.toJson(rewrapped),
                        party[0] + " wrap reproduces");
                checked++;
            }
        }
        eq(1 + 4 + 3 + 3, checked, "wrapped keys checked");
    }

    // ─── commit.json (SPEC 4.3) ───────────────────────────────────────────────────────

    private static void commit() throws Exception {
        Map<String, Object> file = m(load("commit.json"));
        Map<String, Object> seeds = m(file.get("seeds"));
        byte[] dataKey = hx(s(seeds, "dataKeyHex"));
        byte[] iv = hx(s(seeds, "ivHex"));
        List<Object> cases = l(file.get("cases"));
        eq(List.of("root", "single-parent", "three-parent-merge"), names(cases), "commit case names");
        for (Object o : cases) {
            Map<String, Object> c = m(o);
            String name = s(c, "name");
            Object wire = c.get("commit");
            AvpCommit.Commit cm = AvpCommit.fromJson(wire);
            Map<String, Object> expected = m(c.get("expected"));
            eq(s(expected, "headerHex"), AvpEncoding.hex(AvpCommit.headerBytes(cm)), name + " header");
            eq(s(expected, "commitIdHex"), AvpEncoding.hex(AvpCommit.id(cm)), name + " id");
            eq(s(expected, "commitIdHex"), AvpEncoding.hex(cm.commitId()), name + " commitId field");
            byte[] aad = AvpCommit.aadV2(cm.repoId(), cm.keyEpoch(), cm.author(), cm.parents());
            eq(s(expected, "aadHex"), AvpEncoding.hex(aad), name + " aad");
            check(AvpCommit.verify(cm), name + " verifies");
            check(
                    AvpCrypto.ed25519Verify(cm.author(), AvpCommit.sigMessage(cm.commitId()), cm.authorSignature()),
                    name + " author signature over the sig message");
            byte[] plaintext = s(c, "plaintextUtf8").getBytes(StandardCharsets.UTF_8);
            eq(plaintext, AvpCommit.open(cm, dataKey), name + " open");

            byte[] authorSeed = hx(s(find(l(seeds.get("authors")), "label", s(c, "authorLabel")), "ed25519SeedHex"));
            AvpCommit.Header header =
                    new AvpCommit.Header(cm.repoId(), cm.parents(), cm.manifestSeq(), cm.manifestHash(), cm.keyEpoch());
            AvpCommit.Commit sealed = AvpCommit.sealWithIv(dataKey, header, plaintext, authorSeed, iv);
            eq(wire, AvpCommit.toJson(sealed), name + " sealed commit");
        }
    }

    // ─── federation.json (SPEC 11) ────────────────────────────────────────────────────

    /** Asserts the decode oracle, the canonical encoding, and the re-encoding of one token case. */
    private static void checkToken(Map<String, Object> t, Function<Map<String, Object>, Map<String, Object>> typed)
            throws Exception {
        String name = s(t, "name");
        eq(
                s(t, "canonicalJson"),
                new String(AvpEncoding.fromBase64Url(s(t, "base64url")), StandardCharsets.UTF_8),
                name + " base64url decodes to the canonical JSON");
        Map<String, Object> decoded = AvpTokens.decode(s(t, "base64url"));
        Map<String, Object> roundTrip = typed.apply(decoded);
        eq(t.get("decoded"), roundTrip, name + " decoded");
        eq(s(t, "canonicalJson"), AvpJson.write(roundTrip), name + " canonical JSON");
        eq(s(t, "base64url"), AvpTokens.encode(roundTrip), name + " base64url");

        // Any field order and whitespace decodes; a v other than 2 is rejected.
        List<String> fields = new ArrayList<>();
        for (Map.Entry<String, Object> e : m(t.get("decoded")).entrySet()) {
            fields.add(0, "\"" + e.getKey() + "\" : " + AvpJson.write(e.getValue()));
        }
        String reordered =
                AvpEncoding.base64Url(("{ " + String.join(" ,\n ", fields) + " }").getBytes(StandardCharsets.UTF_8));
        eq(t.get("decoded"), typed.apply(AvpTokens.decode(reordered)), name + " reordered");
        if (m(t.get("decoded")).containsKey("v")) {
            for (String v : List.of("1", "3", "\"2\"", "2.0")) {
                String bad = s(t, "canonicalJson")
                        .replaceFirst(Pattern.quote("\"v\":2"), Matcher.quoteReplacement("\"v\":" + v));
                String token = AvpEncoding.base64Url(bad.getBytes(StandardCharsets.UTF_8));
                check(typed.apply(AvpTokens.decode(token)) == null, name + " rejects v " + v);
            }
        }
    }

    /** Wraps a typed decoder: the decoded token back to its wire map, or {@code null} if it is rejected. */
    private static Function<Map<String, Object>, Map<String, Object>> typed(String schema) {
        return map -> {
            try {
                return switch (schema) {
                    case "InviteToken" -> AvpTokens.toJson(AvpTokens.inviteTokenFromJson(map));
                    case "RepoLocator" -> AvpTokens.toJson(AvpTokens.repoLocatorFromJson(map));
                    case "LinkRequest" -> AvpTokens.toJson(AvpTokens.linkRequestFromJson(map));
                    case "LinkGrant" -> AvpTokens.toJson(AvpTokens.linkGrantFromJson(map));
                    default -> throw new IllegalStateException("unknown token schema " + schema);
                };
            } catch (AvpException e) {
                return null;
            }
        };
    }

    private static void federation() throws Exception {
        Map<String, Object> file = m(load("federation.json"));
        Map<String, Object> mseeds = m(m(load("manifest.json")).get("seeds"));
        byte[] hostBSeed = hx(s(find(l(mseeds.get("hosts")), "label", "b"), "ed25519SeedHex"));

        List<Object> tokens = l(file.get("tokens"));
        eq(5, tokens.size(), "token count");
        for (Object o : tokens) {
            checkToken(m(o), typed(s(m(o), "schema")));
        }

        // Invite token and its acceptance (SPEC 11.3, 8.2).
        Map<String, Object> t = find(tokens, "name", "invite-token");
        AvpTokens.InviteToken invite = AvpTokens.inviteTokenFromJson(AvpTokens.decode(s(t, "base64url")));
        AvpTokens.Acceptance acc = invite.acceptance();
        eq(s(t, "acceptanceMessageHex"), AvpEncoding.hex(AvpTokens.acceptanceMessage(acc)), "acceptance message");
        check(AvpTokens.verifyAcceptance(acc), "acceptance verifies");
        AvpTokens.Acceptance resigned =
                AvpTokens.signAcceptance(acc.repoId(), acc.memberKey(), acc.expiresAt(), hostBSeed);
        eq(AvpTokens.toJson(acc), AvpTokens.toJson(resigned), "acceptance signature reproduces");
        check(AvpTokens.verifyInvite(invite, acc.repoId(), acc.expiresAt() - 1), "invite verifies before expiry");
        check(!AvpTokens.verifyInvite(invite, acc.repoId(), acc.expiresAt()), "an expired acceptance is rejected");
        check(
                !AvpTokens.verifyInvite(invite, "ndV4hcP0XHhIOjCt8XXhrg", acc.expiresAt() - 1),
                "another repoId is rejected");

        // Repo locators (SPEC 11.2).
        byte[] ownerKey = b64(s(m(m(file.get("fingerprints")).get("owner")), "ownerKey"));
        for (String name : List.of("repo-locator", "repo-locator-port")) {
            AvpTokens.RepoLocator loc =
                    AvpTokens.repoLocatorFromJson(AvpTokens.decode(s(find(tokens, "name", name), "base64url")));
            eq(AvpTokens.ownerFingerprint(ownerKey), loc.ownerFingerprint(), name + " owner fingerprint");
        }

        // Link request and grant (SPEC 11.6).
        AvpTokens.LinkRequest req =
                AvpTokens.linkRequestFromJson(AvpTokens.decode(s(find(tokens, "name", "link-request"), "base64url")));
        Map<String, Object> gt = find(tokens, "name", "link-grant");
        AvpTokens.LinkGrant grant = AvpTokens.linkGrantFromJson(AvpTokens.decode(s(gt, "base64url")));
        Map<String, Object> checker = m(gt.get("checker"));
        byte[] linkPriv = hx(s(checker, "linkEphemeralPrivateHex"));
        eq(req.ephemeralPublicKey(), AvpCrypto.x25519Public(linkPriv), "link ephemeral public key");
        byte[] entropy = hx(s(checker, "entropyHex"));
        eq(entropy, AvpTokens.openLinkGrant(grant, linkPriv), "link grant opens to the entropy");
        byte[] eph = sha256Label("avp/vectors/link-wrap-ephemeral");
        byte[] iv = Arrays.copyOf(sha256Label("avp/vectors/link-wrap-iv"), 12);
        AvpTokens.LinkGrant resealed = AvpTokens.sealLinkGrantWith(entropy, req.ephemeralPublicKey(), eph, iv);
        eq(AvpTokens.toJson(grant), AvpTokens.toJson(resealed), "link grant reproduces");
        rejectsWith(
                AvpException.Kind.CRYPTO,
                () -> AvpCrypto.unwrap(linkPriv, grant.wrap(), AvpCrypto.WRAP_INFO),
                "the data key label does not open a link grant");
        eq(entropy, AvpCrypto.unwrap(linkPriv, grant.wrap(), AvpCrypto.OWNER_LINK_INFO), "link label opens it");

        // Leave requests (SPEC 11.4).
        List<Object> leaves = l(file.get("leaves"));
        eq(2, leaves.size(), "leave count");
        String[] labels = {"alice", "bob"};
        for (int k = 0; k < leaves.size(); k++) {
            Map<String, Object> lv = m(leaves.get(k));
            AvpTokens.LeaveRequest leave = AvpTokens.leaveFromJson(lv.get("decoded"));
            eq(lv.get("decoded"), AvpTokens.toJson(leave), labels[k] + " leave wire round trip");
            eq(
                    s(lv, "signatureMessageHex"),
                    AvpEncoding.hex(AvpTokens.leaveMessage(leave)),
                    labels[k] + " leave message");
            check(AvpTokens.verifyLeave(leave), labels[k] + " leave verifies");
            byte[] seed = hx(s(find(l(mseeds.get("members")), "label", labels[k]), "ed25519SeedHex"));
            AvpTokens.LeaveRequest again = AvpTokens.signLeave(leave.repoId(), leave.at(), seed);
            eq(AvpTokens.toJson(leave), AvpTokens.toJson(again), labels[k] + " leave signature reproduces");
        }

        // Link confirmation codes (SPEC 11.6).
        List<Object> codes = l(file.get("linkCodes"));
        eq(2, codes.size(), "link code count");
        for (Object o : codes) {
            Map<String, Object> c = m(o);
            eq(s(c, "code"), AvpTokens.linkConfirmationCode(b64(s(c, "ephemeralPublicKey"))), s(c, "name") + " code");
        }

        // Fingerprints (SPEC 3.2, 11.2).
        Map<String, Object> fp = m(file.get("fingerprints"));
        for (Object o : l(fp.get("members"))) {
            Map<String, Object> mm = m(o);
            eq(
                    s(mm, "fingerprint"),
                    AvpTokens.keyFingerprint(b64(s(mm, "ed25519PublicKey")), b64(s(mm, "x25519PublicKey"))),
                    s(mm, "label") + " fingerprint");
        }
        eq(s(m(fp.get("owner")), "ownerFingerprint"), AvpTokens.ownerFingerprint(ownerKey), "owner fingerprint");

        // avp:// URIs (SPEC 11.2).
        List<Object> uris = l(file.get("uris"));
        eq(2, uris.size(), "uri count");
        for (Object o : uris) {
            Map<String, Object> u = m(o);
            AvpTokens.AvpUri parsed = AvpTokens.parseUri(s(u, "uri"));
            eq(s(u, "host"), parsed.hostLocator(), s(u, "name") + " host");
            eq(s(u, "repoId"), parsed.repoId(), s(u, "name") + " repoId");
            eq(s(u, "uri"), parsed.toString(), s(u, "name") + " format");
        }
        for (String bad : List.of(
                "http://a.vault.example/RBhoUI0PUSR7tD5HpFC9lA",
                "avp:///RBhoUI0PUSR7tD5HpFC9lA",
                "avp://a.vault.example/RBhoUI0PUSR7tD5HpFC9l",
                "avp://a.vault.example/RBhoUI0PUSR7tD5HpFC9l+",
                "avp://a.vault.example",
                "avp://a.vault.example/x/RBhoUI0PUSR7tD5HpFC9lA")) {
            rejects(() -> AvpTokens.parseUri(bad), "uri " + bad);
        }
    }

    // ─── negative.json (MUST reject, and each base MUST be accepted) ──────────────────

    /** Applies the case's operation; a decode failure throws, a failed verification answers false. */
    private static boolean accepted(Map<String, Object> c) throws Exception {
        switch (s(c, "op")) {
            case "ed25519-verify" -> {
                return AvpCrypto.ed25519Verify(
                        hx(s(c, "publicKeyHex")), hx(s(c, "messageHex")), hx(s(c, "signatureHex")));
            }
            case "key-unwrap" -> {
                AvpManifest.WrappedKey wk = new AvpManifest.WrappedKey(
                        AvpCrypto.SCHEME_ID,
                        b64(s(c, "ephemeralPublicKeyB64")),
                        b64(s(c, "ivB64")),
                        b64(s(c, "ciphertextB64")));
                byte[] recipient = b64(s(c, "recipientPrivateKeyB64"));
                return opens(() -> AvpCrypto.unwrap(recipient, wk, AvpCrypto.WRAP_INFO));
            }
            case "wrap-unwrap" -> {
                AvpManifest.WrappedKey wk = AvpManifest.wrappedKeyFromJson(c.get("wrap"));
                byte[] recipient = hx(s(c, "recipientPrivateKeyHex"));
                return opens(() -> AvpCrypto.unwrap(recipient, wk, s(c, "info")));
            }
            case "manifest-verify" -> {
                return AvpManifest.verify(AvpManifest.signedManifestFromJson(c.get("signedManifest")));
            }
            case "manifest-link" -> {
                AvpManifest.SignedManifest prev = AvpManifest.signedManifestFromJson(c.get("prev"));
                AvpManifest.SignedManifest next = AvpManifest.signedManifestFromJson(c.get("next"));
                // The mutation keeps the owner signature valid, so only the chain link can reject it.
                check(AvpManifest.verify(next), s(c, "name") + ": next is validly signed");
                return AvpManifest.linksTo(next, prev);
            }
            case "commit-verify" -> {
                return AvpCommit.verify(AvpCommit.fromJson(c.get("commit")));
            }
            case "payload-decrypt" -> {
                Map<String, Object> a = m(c.get("aad"));
                List<byte[]> parents = new ArrayList<>();
                for (Object p : l(a.get("parents"))) {
                    parents.add(b64((String) p));
                }
                byte[] aad = AvpCommit.aadV2(s(a, "repoId"), i(a, "keyEpoch"), b64(s(a, "author")), parents);
                byte[] key = hx(s(c, "dataKeyHex"));
                byte[] iv = b64(s(c, "ivB64"));
                byte[] ct = b64(s(c, "ciphertextB64"));
                return opens(() -> AvpCrypto.aesGcmOpen(key, iv, ct, aad));
            }
            case "acceptance-verify" -> {
                AvpTokens.Acceptance acc = AvpTokens.acceptanceFromJson(c.get("acceptance"));
                return AvpTokens.verifyAcceptance(acc, b64(s(c, "verifyHostKey")));
            }
            case "leave-verify" -> {
                return AvpTokens.verifyLeave(AvpTokens.leaveFromJson(c.get("leave")));
            }
            default -> throw new IllegalStateException("unknown negative op " + s(c, "op"));
        }
    }

    /** Whether a decryption or unwrap succeeds; only a cryptographic failure counts as a reject. */
    private static boolean opens(Body body) throws Exception {
        try {
            body.run();
            return true;
        } catch (AvpException e) {
            if (e.kind() != AvpException.Kind.CRYPTO) {
                throw e;
            }
            return false;
        }
    }

    private static void negative() throws Exception {
        List<Object> cases = l(m(load("negative.json")).get("cases"));
        // 23 cases plus the six strict Ed25519 rejects of SPEC 2.
        eq(29, cases.size(), "negative case count");
        int withBase = 0;
        for (Object o : cases) {
            Map<String, Object> c = m(o);
            String name = s(c, "name");
            try {
                eq("reject", s(c, "expect"), name + " expect");
                check(!accepted(c), name + " must be rejected");
                if (c.containsKey("base")) {
                    Map<String, Object> restored = new LinkedHashMap<>(c);
                    restored.putAll(m(c.get("base")));
                    check(accepted(restored), name + ": the unmutated base must be accepted");
                    withBase++;
                } else {
                    check(
                            List.of("key-unwrap", "ed25519-verify").contains(s(c, "op")),
                            name + ": every 0.5 case carries a base");
                }
            } catch (Exception e) {
                check(false, name + ": unexpected " + e);
            }
        }
        eq(15, withBase, "negative cases with a base");
    }

    // ─── merge.json (SPEC 5, 5.1) ─────────────────────────────────────────────────────

    private static <T> List<List<T>> permutations(List<T> xs) {
        List<List<T>> out = new ArrayList<>();
        if (xs.size() <= 1) {
            out.add(new ArrayList<>(xs));
            return out;
        }
        for (int k = 0; k < xs.size(); k++) {
            List<T> rest = new ArrayList<>(xs);
            T x = rest.remove(k);
            for (List<T> p : permutations(rest)) {
                p.add(0, x);
                out.add(p);
            }
        }
        return out;
    }

    private static Map<String, Object> finish(boolean strip, Map<String, Object> p) throws AvpException {
        return strip ? AvpPayload.stripRefresh(p) : p;
    }

    private static boolean hasField(Map<String, Object> p, String field) {
        for (Object a : m(p.get("accounts")).values()) {
            if (m(m(a).get("fields")).containsKey(field)) {
                return true;
            }
        }
        return false;
    }

    private static void merge() throws Exception {
        List<Object> cases = l(m(load("merge.json")).get("cases"));
        eq(9, cases.size(), "merge case count");
        for (Object o : cases) {
            Map<String, Object> c = m(o);
            String name = s(c, "name");
            boolean strip = Boolean.TRUE.equals(c.get("stripRefresh"));
            List<Map<String, Object>> inputs = new ArrayList<>();
            for (Object p : l(c.get("inputs"))) {
                inputs.add(m(p));
            }
            Map<String, Object> expected = m(c.get("expected"));
            check(inputs.size() >= 2, name + " has at least two inputs");
            // The normalized form of the hand-written expected payload is itself.
            eq(expected, AvpPayload.merge(List.of(expected)), name + " expected round trip");

            for (List<Map<String, Object>> perm : permutations(inputs)) {
                eq(expected, finish(strip, AvpPayload.merge(perm)), name + " permutation");
            }
            List<Map<String, Object>> withExpected = new ArrayList<>(inputs);
            withExpected.add(expected);
            for (Map<String, Object> input : withExpected) {
                eq(expected, finish(strip, AvpPayload.merge(List.of(expected, input))), name + " idempotent left");
                eq(expected, finish(strip, AvpPayload.merge(List.of(input, expected))), name + " idempotent right");
            }
            for (Map<String, Object> input : inputs) {
                eq(AvpPayload.merge(List.of(input)), AvpPayload.merge(List.of(input, input)), name + " self merge");
            }
            for (Map<String, Object> a : inputs) {
                for (Map<String, Object> b : inputs) {
                    for (Map<String, Object> d : inputs) {
                        Map<String, Object> left = AvpPayload.merge(List.of(AvpPayload.merge(List.of(a, b)), d));
                        Map<String, Object> right = AvpPayload.merge(List.of(a, AvpPayload.merge(List.of(b, d))));
                        eq(left, right, name + " associative");
                        eq(left, AvpPayload.merge(List.of(a, b, d)), name + " associative flat");
                    }
                }
            }

            Map<String, Object> merged = finish(strip, AvpPayload.merge(inputs));
            Map<String, Object> wantDeleted = m(c.get("expectedDeleted"));
            Map<String, Object> accounts = m(merged.get("accounts"));
            eq(
                    new java.util.TreeSet<>(wantDeleted.keySet()),
                    new java.util.TreeSet<>(accounts.keySet()),
                    name + " accounts");
            for (Map.Entry<String, Object> e : wantDeleted.entrySet()) {
                eq(e.getValue(), AvpPayload.isDeleted(m(accounts.get(e.getKey()))), name + " deleted " + e.getKey());
            }

            if (name.equals("strip-after-policy-off")) {
                check(strip, name + " strips");
                Map<String, Object> unstripped = AvpPayload.merge(inputs);
                for (String f : AvpPayload.REFRESH_FIELDS) {
                    check(inputs.stream().anyMatch(p -> hasField(p, f)), name + " an input carries " + f);
                    check(hasField(unstripped, f), name + " the unstripped merge carries " + f);
                    check(!hasField(AvpPayload.stripRefresh(unstripped), f), name + " the stripped merge drops " + f);
                    check(!hasField(expected, f), name + " expected has no " + f);
                }
            }
            if (name.equals("strip-then-deleted")) {
                String uuid = wantDeleted.keySet().iterator().next();
                Map<String, Object> unstripped = AvpPayload.merge(inputs);
                check(!AvpPayload.isDeleted(m(m(unstripped.get("accounts")).get(uuid))), name + " live before strip");
                Map<String, Object> stripped = AvpPayload.stripRefresh(unstripped);
                check(AvpPayload.isDeleted(m(m(stripped.get("accounts")).get(uuid))), name + " deleted after strip");
            }
        }

        // SPEC 5: deletion needs a strictly greater stamp, and a later ban stamp revives the account.
        Map<String, Object> acc = account("{\"deleted\":{\"at\":10,\"n\":0,\"by\":\"x\"},"
                + "\"fields\":{\"username\":{\"value\":\"u\",\"at\":10,\"n\":0,\"by\":\"x\"}},\"bans\":{}}");
        check(!AvpPayload.isDeleted(acc), "an equal stamp does not delete");
        acc = account("{\"deleted\":{\"at\":10,\"n\":1,\"by\":\"x\"},"
                + "\"fields\":{\"username\":{\"value\":\"u\",\"at\":10,\"n\":0,\"by\":\"x\"}},\"bans\":{}}");
        check(AvpPayload.isDeleted(acc), "a greater stamp deletes");
        acc = account("{\"deleted\":{\"at\":10,\"n\":0,\"by\":\"x\"},"
                + "\"fields\":{},\"bans\":{\"srv\":{\"value\":null,\"at\":11,\"n\":0,\"by\":\"x\"}}}");
        check(!AvpPayload.isDeleted(acc), "a later ban stamp revives the account");
        check(!AvpPayload.isDeleted(account("{\"fields\":{},\"bans\":{}}")), "no marker is not deleted");

        // SPEC 5: by compares by UTF-8 bytes; "Z" (0x5a) sorts before "a" (0x61).
        Map<String, Object> lower = payload("{\"v\":2,\"accounts\":{\"u\":{\"fields\":"
                + "{\"username\":{\"value\":\"lower\",\"at\":1,\"n\":0,\"by\":\"a\"}},\"bans\":{}}}}");
        Map<String, Object> upper = payload("{\"v\":2,\"accounts\":{\"u\":{\"fields\":"
                + "{\"username\":{\"value\":\"upper\",\"at\":1,\"n\":0,\"by\":\"Z\"}},\"bans\":{}}}}");
        Map<String, Object> won = AvpPayload.merge(List.of(lower, upper));
        eq(
                "lower",
                m(m(m(m(won.get("accounts")).get("u")).get("fields")).get("username"))
                        .get("value"),
                "by bytewise");
        // In UTF-8, U+FB01 is ef ac 81 and U+1F600 is f0 9f 98 80, so the emoji is greater by bytes; in
        // UTF-16 code units fb01 is greater than d83d, so a code unit compare would pick the ligature.
        Map<String, Object> lig = payload("{\"v\":2,\"accounts\":{\"u\":{\"fields\":"
                + "{\"username\":{\"value\":\"lig\",\"at\":1,\"n\":0,\"by\":\"\\ufb01\"}},\"bans\":{}}}}");
        Map<String, Object> emoji = payload("{\"v\":2,\"accounts\":{\"u\":{\"fields\":"
                + "{\"username\":{\"value\":\"emoji\",\"at\":1,\"n\":0,\"by\":\"\\ud83d\\ude00\"}},\"bans\":{}}}}");
        Map<String, Object> won2 = AvpPayload.merge(List.of(lig, emoji));
        eq(
                "emoji",
                m(m(m(m(won2.get("accounts")).get("u")).get("fields")).get("username"))
                        .get("value"),
                "by UTF-8 not UTF-16");

        // SPEC 5: a payload whose v is not 2 is unreadable.
        rejects(() -> AvpPayload.parse("{\"v\":1,\"accounts\":{}}".getBytes(StandardCharsets.UTF_8)), "payload v 1");
        rejects(() -> AvpPayload.parse("{\"accounts\":{}}".getBytes(StandardCharsets.UTF_8)), "payload without v");
        rejects(() -> AvpPayload.parse("{\"v\":2}".getBytes(StandardCharsets.UTF_8)), "payload without accounts");
        rejects(
                () -> AvpPayload.parse("{\"v\":2,\"accounts\":{\"u\":{\"fields\":{\"username\":{\"value\":1}}}}}"
                        .getBytes(StandardCharsets.UTF_8)),
                "field without a stamp");
        rejects(
                () -> AvpPayload.merge(List.of(m(AvpJson.parse("{\"v\":2,\"accounts\":[]}")))),
                "accounts not an object");
        Map<String, Object> empty = AvpPayload.parse("{\"v\":2,\"accounts\":{}}".getBytes(StandardCharsets.UTF_8));
        eq("{\"v\":2,\"accounts\":{}}", new String(AvpPayload.encode(empty), StandardCharsets.UTF_8), "empty payload");
    }

    private static Map<String, Object> account(String json) throws AvpException {
        return m(AvpJson.parse(json));
    }

    private static Map<String, Object> payload(String json) throws AvpException {
        return m(AvpJson.parse(json));
    }

    private static void hlc() throws Exception {
        List<Object> cases = l(m(load("merge.json")).get("hlc"));
        eq(3, cases.size(), "hlc case count");
        for (Object o : cases) {
            Map<String, Object> h = m(o);
            String name = s(h, "name");
            Map<String, Object> start = m(h.get("start"));
            AvpPayload.Hlc clock = new AvpPayload.Hlc(i(start, "at"), i(start, "n"));
            List<Object> steps = l(h.get("steps"));
            for (int k = 0; k < steps.size(); k++) {
                Map<String, Object> step = m(steps.get(k));
                Map<String, Object> want = m(step.get("expect"));
                switch (s(step, "op")) {
                    case "tick" -> {
                        Map<String, Object> st = clock.tick(i(step, "now"), "me");
                        eq(want.get("at"), st.get("at"), name + " step " + k + " tick at");
                        eq(want.get("n"), st.get("n"), name + " step " + k + " tick n");
                        eq("me", st.get("by"), name + " step " + k + " tick by");
                    }
                    case "observe" -> clock.observe(m(step.get("stamp")));
                    default -> check(false, name + " unknown hlc op " + s(step, "op"));
                }
                eq(want.get("at"), clock.at(), name + " step " + k + " at");
                eq(want.get("n"), clock.n(), name + " step " + k + " n");
            }
        }
        AvpPayload.Hlc max = new AvpPayload.Hlc(7, Long.MAX_VALUE);
        Map<String, Object> st = max.tick(0, "me");
        eq(8L, st.get("at"), "a saturated counter moves the clock to the next millisecond");
        eq(0L, st.get("n"), "and resets the counter");
    }

    // ─── acceptance.json (SPEC 6, 7, 8.3, 8.4, 9.1) ───────────────────────────────────

    private static AvpRules.Via via(Map<String, Object> step) {
        return switch (s(step, "via")) {
            case "push" -> AvpRules.Via.PUSH;
            case "offer" -> AvpRules.Via.OFFER;
            default -> throw new IllegalStateException("unknown via " + s(step, "via"));
        };
    }

    /**
     * Applies one step. A body that does not decode (for example a binary field of the wrong length)
     * is malformed, which a host answers with {@code bad_request} before the engine runs (SPEC 6.1
     * rule 1, 7.1, 10.4).
     */
    private static String apply(AvpRules.RepoView view, Map<String, Object> step) {
        Map<String, Object> item = m(step.get("item"));
        AvpRules.Via via = via(step);
        Optional<String> verdict;
        try {
            verdict = switch (s(step, "op")) {
                case "manifest" -> {
                    AvpManifest.SignedManifest sm = AvpManifest.signedManifestFromJson(item.get("manifest"));
                    Optional<AvpCommit.Commit> c = item.containsKey("commit")
                            ? Optional.of(AvpCommit.fromJson(item.get("commit")))
                            : Optional.empty();
                    yield view.applyManifest(sm, c, via);
                }
                case "commit" -> view.applyCommit(AvpCommit.fromJson(item), via);
                case "leave" -> view.applyLeave(AvpTokens.leaveFromJson(item), via);
                default -> throw new IllegalStateException("unknown op " + s(step, "op"));
            };
        } catch (AvpException e) {
            verdict = Optional.of("bad_request");
        }
        return verdict.orElse("ok");
    }

    private static void acceptance() throws Exception {
        List<Object> scenarios = l(m(load("acceptance.json")).get("scenarios"));
        eq(78, scenarios.size(), "scenario count");
        int steps = 0;
        for (Object o : scenarios) {
            Map<String, Object> sc = m(o);
            String name = s(sc, "name");
            try {
                AvpRules.RepoView view = new AvpRules.RepoView(b64(s(sc, "hostKey")), (int) i(sc, "headBound"));
                List<Object> list = l(sc.get("steps"));
                for (int k = 0; k < list.size(); k++) {
                    Map<String, Object> step = m(list.get(k));
                    String want = s(step, "expect");
                    check(VERDICTS.contains(want), name + ": step " + k + " expects a known verdict, not " + want);
                    String got = apply(view, step);
                    eq(
                            want,
                            got,
                            name + ": step " + k + " (" + s(step, "op") + " " + s(step, "label") + " via "
                                    + s(step, "via") + ")");
                    steps++;
                }
                eq(sortedStrings(sc.get("finalHeads")), sortedB64(view.heads()), name + ": final heads");
                eq(sortedStrings(sc.get("finalHeld")), sortedB64(view.held()), name + ": final held");
                Object tip = view.tip().isPresent()
                        ? AvpEncoding.base64(AvpManifest.hash(view.tip().get()))
                        : null;
                eq(sc.get("finalTip"), tip, name + ": final tip");
                if (sc.containsKey("finalLeaves")) {
                    List<String> want = new ArrayList<>();
                    for (Object lv : l(sc.get("finalLeaves"))) {
                        want.add(s(m(lv), "memberKey") + "@" + i(m(lv), "at"));
                    }
                    want.sort(Comparator.naturalOrder());
                    List<String> got = new ArrayList<>();
                    for (AvpTokens.LeaveRequest lv : view.leaves()) {
                        got.add(AvpEncoding.base64(lv.memberKey()) + "@" + lv.at());
                    }
                    got.sort(Comparator.naturalOrder());
                    eq(want, got, name + ": final leaves");
                }
            } catch (Exception e) {
                check(false, name + ": unexpected " + e);
            }
        }
        eq(360, steps, "acceptance steps replayed");
    }

    // ─── Rules engine checks beyond the scenarios (mirroring the Rust rules tests) ────

    private record Fixture(
            byte[] hostA,
            byte[] ownerSeed,
            AvpManifest.SignedManifest genesis,
            AvpCommit.Commit root,
            AvpManifest.MemberEntry alice,
            AvpManifest.MemberEntry carol) {}

    private static Fixture fixture() throws Exception {
        Map<String, Object> manifest = m(load("manifest.json"));
        Map<String, Object> commits = m(load("commit.json"));
        Map<String, Object> seeds = m(manifest.get("seeds"));
        byte[] ownerSeed = hx(s(m(seeds.get("owner")), "ed25519SeedHex"));
        List<Object> cases = l(manifest.get("cases"));
        AvpManifest.SignedManifest genesis =
                AvpManifest.signedManifestFromJson(m(cases.get(0)).get("signedManifest"));
        AvpManifest.SignedManifest add =
                AvpManifest.signedManifestFromJson(m(cases.get(1)).get("signedManifest"));
        AvpManifest.MemberEntry[] picked = new AvpManifest.MemberEntry[2];
        String[] labels = {"alice", "carol"};
        for (int k = 0; k < 2; k++) {
            byte[] key = b64(s(find(l(seeds.get("members")), "label", labels[k]), "ed25519PublicKey"));
            for (AvpManifest.MemberEntry me : add.state().members()) {
                if (Arrays.equals(me.ed25519PublicKey(), key)) {
                    picked[k] = me;
                }
            }
        }
        AvpCommit.Commit root =
                AvpCommit.fromJson(m(l(commits.get("cases")).get(0)).get("commit"));
        byte[] hostA = b64(s(m(l(seeds.get("hosts")).get(0)), "hostKey"));
        return new Fixture(hostA, ownerSeed, genesis, root, picked[0], picked[1]);
    }

    /** A seq 2 state on genesis that adds {@code member}. */
    private static AvpManifest.SignedManifest seq2(Fixture f, AvpManifest.MemberEntry member) throws Exception {
        AvpManifest.ManifestState g = f.genesis().state();
        List<AvpManifest.MemberEntry> members = new ArrayList<>(g.members());
        members.add(member);
        AvpManifest.ManifestState st = new AvpManifest.ManifestState(
                g.repoId(),
                2,
                AvpManifest.hash(f.genesis()),
                g.ownerKey(),
                new byte[0],
                g.schemeId(),
                g.keyEpoch(),
                g.shareRefreshTokens(),
                g.hosts(),
                members,
                g.removals());
        return AvpManifest.sign(st, f.ownerSeed());
    }

    private static AvpRules.RepoView started(Fixture f) {
        AvpRules.RepoView view = new AvpRules.RepoView(f.hostA(), 16);
        eq(
                Optional.empty(),
                view.applyManifest(f.genesis(), Optional.of(f.root()), AvpRules.Via.PUSH),
                "genesis applies");
        return view;
    }

    private static void rulesExtra() throws Exception {
        Fixture f = fixture();
        AvpManifest.SignedManifest x = seq2(f, f.alice());
        AvpManifest.SignedManifest y = seq2(f, f.carol());
        byte[] xh = AvpManifest.hash(x);
        byte[] yh = AvpManifest.hash(y);
        check(!Arrays.equals(xh, yh), "diverged states differ");
        boolean xLower = Arrays.compareUnsigned(xh, yh) < 0;
        byte[] lower = xLower ? xh : yh;
        byte[] loser = xLower ? yh : xh;

        // SPEC 6.5: both arrival orders converge on the bytewise-lower manifestHash.
        List<String> tips = new ArrayList<>();
        for (AvpManifest.SignedManifest[] order :
                List.of(new AvpManifest.SignedManifest[] {x, y}, new AvpManifest.SignedManifest[] {y, x})) {
            AvpRules.RepoView view = started(f);
            Optional<String> first = view.applyManifest(order[0], Optional.empty(), AvpRules.Via.OFFER);
            Optional<String> second = view.applyManifest(order[1], Optional.empty(), AvpRules.Via.OFFER);
            eq(Optional.empty(), first, "the first diverged state appends");
            boolean secondWins = Arrays.equals(AvpManifest.hash(order[1]), lower);
            eq(
                    secondWins ? Optional.empty() : Optional.of("manifest_conflict"),
                    second,
                    "the second meets the tie rule");
            byte[] tip = AvpManifest.hash(view.tip().orElseThrow());
            eq(lower, tip, "the bytewise-lower manifestHash wins");
            check(view.manifest(loser).isPresent(), "the loser is retained as a verified losing state");
            check(!view.isWinning(loser), "the loser is not on the winning chain");
            List<AvpManifest.SignedManifest> chain = view.chainTo(loser).orElseThrow();
            eq(2, chain.size(), "the loser's chain has two states");
            eq(AvpManifest.hash(f.genesis()), AvpManifest.hash(chain.get(0)), "the loser's chain starts at genesis");
            tips.add(AvpEncoding.base64(tip));
        }
        eq(tips.get(0), tips.get(1), "both orders converge on the same tip");

        // Review focus 1: a commit citing the losing state by a member of both is accepted after the
        // re-check (SPEC 6.5).
        AvpManifest.SignedManifest winner = xLower ? x : y;
        AvpManifest.SignedManifest losing = xLower ? y : x;
        AvpRules.RepoView view = started(f);
        eq(Optional.empty(), view.applyManifest(losing, Optional.empty(), AvpRules.Via.OFFER), "losing state first");
        AvpCommit.Header header = new AvpCommit.Header(
                losing.state().repoId(), List.of(f.root().commitId()), 2, AvpManifest.hash(losing), 0);
        byte[] dataKey = new byte[32];
        Arrays.fill(dataKey, (byte) 0x42);
        AvpCommit.Commit c = AvpCommit.seal(
                dataKey, header, "{\"v\":2,\"accounts\":{}}".getBytes(StandardCharsets.UTF_8), f.ownerSeed());
        eq(Optional.empty(), view.applyCommit(c), "owner commit on the losing state");
        eq(List.of(AvpEncoding.base64(c.commitId())), sortedB64(view.heads()), "the commit is the head");
        eq(
                Optional.empty(),
                view.applyManifest(winner, Optional.empty(), AvpRules.Via.OFFER),
                "the winner replaces it");
        eq(AvpManifest.hash(winner), AvpManifest.hash(view.tip().orElseThrow()), "the tip is the winner");
        eq(List.of(AvpEncoding.base64(c.commitId())), sortedB64(view.heads()), "still a head after the switch");
        check(view.held().isEmpty(), "nothing is held");
        eq(Optional.of(AvpRules.CommitStatus.ACCEPTED), view.status(c.commitId()), "the commit is accepted");

        // SPEC 7.2, 7.4: what a missing_parents answer names.
        AvpRules.RepoView v2 = started(f);
        byte[] unknownParent = new byte[32];
        Arrays.fill(unknownParent, (byte) 7);
        byte[] unknownState = new byte[32];
        Arrays.fill(unknownState, (byte) 9);
        AvpCommit.Commit p = AvpCommit.seal(
                dataKey,
                new AvpCommit.Header(
                        f.genesis().state().repoId(), List.of(unknownParent), 1, AvpManifest.hash(f.genesis()), 0),
                "{}".getBytes(StandardCharsets.UTF_8),
                f.ownerSeed());
        eq(Optional.of("missing_parents"), v2.applyCommit(p), "unknown parent");
        eq(List.of(AvpEncoding.base64(unknownParent)), sortedB64(v2.missingFor(p)), "missing names the parent");
        AvpCommit.Commit q = AvpCommit.seal(
                dataKey,
                new AvpCommit.Header(
                        f.genesis().state().repoId(), List.of(f.root().commitId()), 2, unknownState, 0),
                "{}".getBytes(StandardCharsets.UTF_8),
                f.ownerSeed());
        eq(Optional.of("missing_parents"), v2.applyCommit(q), "unknown cited state");
        eq(List.of(AvpEncoding.base64(unknownState)), sortedB64(v2.missingFor(q)), "missing names the state");

        // Pull and fetch views (SPEC 9.1, 10.1).
        AvpRules.RepoView v3 = new AvpRules.RepoView(f.hostA(), 16);
        check(v3.tip().isEmpty(), "no tip before genesis");
        check(v3.heads().isEmpty(), "no heads before genesis");
        check(!v3.tipListsHost(), "no tip lists the host before genesis");
        eq(Optional.empty(), v3.applyManifest(f.genesis(), Optional.of(f.root()), AvpRules.Via.PUSH), "genesis");
        eq(Optional.empty(), v3.applyManifest(x), "publish seq 2");
        String genesisHash = AvpEncoding.base64(AvpManifest.hash(f.genesis()));
        eq(List.of(genesisHash, AvpEncoding.base64(xh)), hashes(v3.manifestsSince(0)), "manifests since 0");
        eq(List.of(AvpEncoding.base64(xh)), hashes(v3.manifestsSince(1)), "manifests since 1");
        check(v3.manifestsSince(2).isEmpty(), "manifests since 2");
        eq(List.of(AvpEncoding.base64(f.root().commitId())), ids(v3.commitsSince(List.of())), "commits since nothing");
        check(v3.commitsSince(List.of(f.root().commitId())).isEmpty(), "commits since the root");
        eq(
                f.root().commitId(),
                v3.fetchCommit(f.root().commitId())
                        .map(AvpCommit.Commit::commitId)
                        .orElse(null),
                "fetch root");
        check(v3.fetchCommit(new byte[32]).isEmpty(), "fetch unknown");
        check(v3.tipListsHost(), "the tip lists the host");
        eq(Optional.of("manifest_conflict"), v3.applyManifest(x), "publishing the same state again conflicts");
        eq(
                Optional.empty(),
                v3.applyManifest(x, Optional.empty(), AvpRules.Via.OFFER),
                "offering it again is idempotent");

        // SPEC 8.4: a leave with a bad signature is bad_request and stores nothing.
        byte[] three = new byte[32];
        Arrays.fill(three, (byte) 3);
        AvpTokens.LeaveRequest bad =
                new AvpTokens.LeaveRequest(f.genesis().state().repoId(), three, 0, new byte[64]);
        eq(Optional.of("bad_request"), v3.applyLeave(bad), "malformed leave");
        check(v3.leaves().isEmpty(), "no leave stored");

        // SPEC 8.4: the host keeps the latest leave request per member, and refuses the owner's.
        String repoId = f.genesis().state().repoId();
        byte[] aliceSeed = hx(s(
                find(l(m(m(load("manifest.json")).get("seeds")).get("members")), "label", "alice"), "ed25519SeedHex"));
        eq(Optional.empty(), v3.applyLeave(AvpTokens.signLeave(repoId, 200, aliceSeed)), "alice leaves at 200");
        eq(Optional.empty(), v3.applyLeave(AvpTokens.signLeave(repoId, 100, aliceSeed)), "an older leave is accepted");
        eq(List.of(200L), v3.leaves().stream().map(AvpTokens.LeaveRequest::at).toList(), "the latest leave is kept");
        eq(Optional.empty(), v3.applyLeave(AvpTokens.signLeave(repoId, 300, aliceSeed)), "alice leaves again at 300");
        eq(List.of(300L), v3.leaves().stream().map(AvpTokens.LeaveRequest::at).toList(), "a later leave replaces it");
        eq(
                Optional.of("forbidden"),
                v3.applyLeave(AvpTokens.signLeave(repoId, 400, f.ownerSeed())),
                "the owner cannot leave");
        eq(
                Optional.of("bad_request"),
                v3.applyLeave(AvpTokens.signLeave("ndV4hcP0XHhIOjCt8XXhrg", 500, aliceSeed)),
                "another repoId");

        // SPEC 6.1 rule 6 by path.
        byte[] unlisted = new byte[32];
        Arrays.fill(unlisted, (byte) 0x55);
        check(!f.genesis().state().hasHost(unlisted), "the fixture does not list the host");
        AvpRules.RepoView pushed = new AvpRules.RepoView(unlisted, 16);
        eq(
                Optional.of("not_hosted"),
                pushed.applyManifest(f.genesis(), Optional.of(f.root()), AvpRules.Via.PUSH),
                "an unlisted genesis is not hosted on push");
        check(pushed.tip().isEmpty(), "a rejected client write stores nothing");
        AvpRules.RepoView offered = new AvpRules.RepoView(unlisted, 16);
        eq(
                Optional.empty(),
                offered.applyManifest(f.genesis(), Optional.of(f.root()), AvpRules.Via.OFFER),
                "an unlisted genesis is taken by offer");
        check(!offered.tipListsHost(), "the host layer refuses to serve this tip");

        // A trial copy is independent of the view it came from.
        AvpRules.RepoView trial = v3.copy();
        AvpManifest.SignedManifest y3 = seq3(f, x);
        eq(Optional.empty(), trial.applyManifest(y3), "the trial copy takes seq 3");
        eq(3L, trial.tip().orElseThrow().state().manifestSeq(), "the trial copy is at seq 3");
        eq(2L, v3.tip().orElseThrow().state().manifestSeq(), "the original stays at seq 2");

        // A commit with a duplicate parent is malformed (SPEC 4.3).
        AvpCommit.Commit dupParents = new AvpCommit.Commit(
                f.root().repoId(),
                f.root().commitId(),
                List.of(f.root().commitId(), f.root().commitId()),
                1,
                AvpManifest.hash(f.genesis()),
                0,
                f.root().author(),
                f.root().iv(),
                f.root().ciphertext(),
                f.root().authorSignature());
        eq(Optional.of("bad_request"), v3.applyCommit(dupParents), "duplicate parent ids");
        rejects(() -> AvpCommit.headerBytes(dupParents), "duplicate parent header");
    }

    /** A seq 3 state on {@code prev} that changes only the refresh-token policy. */
    private static AvpManifest.SignedManifest seq3(Fixture f, AvpManifest.SignedManifest prev) throws Exception {
        AvpManifest.ManifestState p = prev.state();
        AvpManifest.ManifestState st = new AvpManifest.ManifestState(
                p.repoId(),
                3,
                AvpManifest.hash(prev),
                p.ownerKey(),
                new byte[0],
                p.schemeId(),
                p.keyEpoch(),
                true,
                p.hosts(),
                p.members(),
                p.removals());
        return AvpManifest.sign(st, f.ownerSeed());
    }

    private static List<String> hashes(List<AvpManifest.SignedManifest> ms) throws AvpException {
        List<String> out = new ArrayList<>();
        for (AvpManifest.SignedManifest sm : ms) {
            out.add(AvpEncoding.base64(AvpManifest.hash(sm)));
        }
        return out;
    }

    private static List<String> ids(List<AvpCommit.Commit> cs) {
        List<String> out = new ArrayList<>();
        for (AvpCommit.Commit c : cs) {
            out.add(AvpEncoding.base64(c.commitId()));
        }
        return out;
    }

    // ─── Decoder length checks (SPEC 6.1 rule 1, 7.1) ─────────────────────────────────

    /** The base64 of {@code n} bytes of {@code 0x01}. */
    private static String bytesB64(int n) {
        byte[] b = new byte[n];
        Arrays.fill(b, (byte) 1);
        return AvpEncoding.base64(b);
    }

    /** A deep copy of a parsed JSON tree, so a mutation leaves the vector intact. */
    private static Object copy(Object o) {
        if (o instanceof Map<?, ?> mm) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : mm.entrySet()) {
                out.put((String) e.getKey(), copy(e.getValue()));
            }
            return out;
        }
        if (o instanceof List<?> ll) {
            List<Object> out = new ArrayList<>();
            for (Object x : ll) {
                out.add(copy(x));
            }
            return out;
        }
        return o;
    }

    /** Sets the value at a slash-separated path of object keys and array indexes. */
    @SuppressWarnings("unchecked")
    private static void put(Object root, String path, Object value) {
        String[] parts = path.split("/");
        Object cur = root;
        for (int k = 0; k < parts.length - 1; k++) {
            cur = cur instanceof List<?> ll ? ll.get(Integer.parseInt(parts[k])) : m(cur).get(parts[k]);
        }
        String last = parts[parts.length - 1];
        if (cur instanceof List<?> ll) {
            ((List<Object>) ll).set(Integer.parseInt(last), value);
        } else {
            m(cur).put(last, value);
        }
    }

    private static void decoderLengths() throws Exception {
        Object commitBase = m(l(m(load("commit.json")).get("cases")).get(1)).get("commit");
        AvpCommit.fromJson(commitBase);
        check(true, "commit base decodes");
        Object[][] commitMutations = {
            {"commitId", 31},
            {"commitId", 33},
            {"manifestHash", 31},
            {"author", 0},
            {"iv", 11},
            {"iv", 13},
            {"authorSignature", 63},
            {"authorSignature", 65},
            {"parents/0", 31}
        };
        for (Object[] mu : commitMutations) {
            Object c = copy(commitBase);
            put(c, (String) mu[0], bytesB64((Integer) mu[1]));
            rejects(() -> AvpCommit.fromJson(c), "commit " + mu[0] + " of " + mu[1] + " bytes");
        }
        Object notB64 = copy(commitBase);
        put(notB64, "iv", "not base64!");
        rejects(() -> AvpCommit.fromJson(notB64), "commit iv that is not base64");
        Object frac = copy(commitBase);
        put(frac, "manifestSeq", AvpJson.parse("1.5"));
        rejects(() -> AvpCommit.fromJson(frac), "a non-integer manifestSeq");
        Object str = copy(commitBase);
        put(str, "keyEpoch", "0");
        rejects(() -> AvpCommit.fromJson(str), "a string keyEpoch");
        Object missing = copy(commitBase);
        m(missing).remove("author");
        rejects(() -> AvpCommit.fromJson(missing), "a commit without author");
        Object huge = copy(commitBase);
        put(huge, "manifestSeq", AvpJson.parse("9223372036854775808"));
        rejects(() -> AvpCommit.fromJson(huge), "a manifestSeq beyond int64");
        rejects(() -> AvpCommit.fromJson(List.of()), "a commit that is not an object");

        Object manifestBase = m(l(m(load("manifest.json")).get("cases")).get(2)).get("signedManifest");
        AvpManifest.signedManifestFromJson(manifestBase);
        check(true, "manifest base decodes");
        Object[][] manifestMutations = {
            {"ownerSignature", 63},
            {"state/ownerKey", 31},
            {"state/hosts/0/hostKey", 33},
            {"state/members/0/ed25519PublicKey", 31},
            {"state/members/0/x25519PublicKey", 31},
            {"state/members/0/homeHostKey", 0},
            {"state/members/0/wrappedDataKey/ephemeralPublicKey", 31},
            {"state/members/0/wrappedDataKey/iv", 11},
            {"state/removals/0/memberKey", 31},
            {"state/removals/0/frontier/0", 31}
        };
        for (Object[] mu : manifestMutations) {
            Object sm = copy(manifestBase);
            put(sm, (String) mu[0], bytesB64((Integer) mu[1]));
            rejects(() -> AvpManifest.signedManifestFromJson(sm), "manifest " + mu[0] + " of " + mu[1] + " bytes");
        }
        Object nullNonce = copy(manifestBase);
        put(nullNonce, "state/genesisNonce", null);
        rejects(() -> AvpManifest.signedManifestFromJson(nullNonce), "a null genesisNonce");
        Object noOptional = copy(manifestBase);
        m(m(noOptional).get("state")).remove("shareRefreshTokens");
        check(
                !AvpManifest.signedManifestFromJson(noOptional).state().shareRefreshTokens(),
                "an absent shareRefreshTokens means false (SPEC 5.1)");

        Object wrap = m(l(m(load("key-wrap.json")).get("cases")).get(0)).get("wrappedKey");
        AvpManifest.wrappedKeyFromJson(wrap);
        check(true, "wrapped key base decodes");
        for (Object[] mu : new Object[][] {{"ephemeralPublicKey", 31}, {"iv", 13}}) {
            Object w = copy(wrap);
            put(w, (String) mu[0], bytesB64((Integer) mu[1]));
            rejects(() -> AvpManifest.wrappedKeyFromJson(w), "wrapped key " + mu[0]);
        }

        Object leave = m(l(m(load("federation.json")).get("leaves")).get(0)).get("decoded");
        AvpTokens.leaveFromJson(leave);
        check(true, "leave base decodes");
        for (Object[] mu : new Object[][] {{"memberKey", 31}, {"signature", 63}}) {
            Object lv = copy(leave);
            put(lv, (String) mu[0], bytesB64((Integer) mu[1]));
            rejects(() -> AvpTokens.leaveFromJson(lv), "leave " + mu[0]);
        }

        // Wire base64 is canonical standard base64 with padding (SPEC 2).
        rejects(() -> AvpEncoding.fromBase64("AQ"), "base64 without padding");
        rejects(() -> AvpEncoding.fromBase64("AR=="), "base64 with non-zero unused bits");
        rejects(() -> AvpEncoding.fromBase64("-_8="), "the url alphabet in standard base64");
        rejects(() -> AvpEncoding.fromBase64(" AQ=="), "base64 with whitespace");
        eq("01", AvpEncoding.hex(AvpEncoding.fromBase64("AQ==")), "canonical base64 decodes");
        rejects(
                () -> AvpEncoding.fromBase64(AvpEncoding.base64(new byte[31]), 32),
                "a 31-byte value where 32 are required");
        rejects(() -> AvpEncoding.fromHex("0"), "odd hex");
        rejects(() -> AvpEncoding.fromHex("zz"), "non-hex digits");
    }

    // ─── Token outer encoding (SPEC 11.1) ─────────────────────────────────────────────

    private static void tokenRejects() throws Exception {
        byte[] five = new byte[32];
        Arrays.fill(five, (byte) 5);
        String good = AvpEncoding.base64Url(("{\"v\":2,\"ephemeralPublicKey\":\"" + AvpEncoding.base64(five) + "\"}")
                .getBytes(StandardCharsets.UTF_8));
        eq(five, AvpTokens.linkRequestFromJson(AvpTokens.decode(good)).ephemeralPublicKey(), "a good link request");
        rejects(() -> AvpTokens.decode(good + "="), "a padded token");
        rejects(() -> AvpTokens.decode(good.substring(0, good.length() - 2) + "+/"), "the standard alphabet");
        rejects(
                () -> AvpTokens.decode(AvpEncoding.base64Url("not json".getBytes(StandardCharsets.UTF_8))),
                "a token that is not JSON");
        rejects(
                () -> AvpTokens.decode(AvpEncoding.base64Url("[2]".getBytes(StandardCharsets.UTF_8))),
                "a token that is not an object");
        rejects(
                () -> AvpTokens.linkRequestFromJson(
                        AvpTokens.decode(AvpEncoding.base64Url("{\"v\":2}".getBytes(StandardCharsets.UTF_8)))),
                "a missing field");
        String shortKey = AvpEncoding.base64Url(
                ("{\"v\":2,\"ephemeralPublicKey\":\"" + AvpEncoding.base64(Arrays.copyOf(five, 31)) + "\"}")
                        .getBytes(StandardCharsets.UTF_8));
        rejects(() -> AvpTokens.linkRequestFromJson(AvpTokens.decode(shortKey)), "a 31-byte key");
    }

    // ─── mnemonicToEntropy rejects (SPEC 3.1) ─────────────────────────────────────────

    private static void bip39Rejects() throws Exception {
        List<Object> anchors = l(m(m(load("bip39-owner.json")).get("anchors")).get("cases"));
        String valid = s(m(anchors.get(2)), "mnemonic");
        List<String> words = List.of(valid.split(" ", -1));
        eq(24, words.size(), "the anchor has 24 words");

        for (String phrase : List.of(
                String.join(" ", words.subList(0, 23)),
                valid + " abandon",
                // A valid 12-word BIP39 phrase (128 bits) is not an AVP phrase.
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "",
                valid + " ")) {
            rejectsWith(
                    AvpException.Kind.BAD_ENCODING,
                    () -> AvpOwner.mnemonicToEntropy(phrase),
                    "word count of " + phrase);
        }

        List<String> unknown = new ArrayList<>(words);
        unknown.set(5, "notaword");
        rejectsWith(
                AvpException.Kind.BAD_ENCODING,
                () -> AvpOwner.mnemonicToEntropy(String.join(" ", unknown)),
                "unknown word");
        // A doubled space is an empty word, which is not in the list.
        String doubled = String.join(" ", words.subList(0, 22)) + "  " + words.get(23);
        rejectsWith(AvpException.Kind.BAD_ENCODING, () -> AvpOwner.mnemonicToEntropy(doubled), "doubled space");
        // Case matters: the list is lowercase.
        rejectsWith(
                AvpException.Kind.BAD_ENCODING,
                () -> AvpOwner.mnemonicToEntropy(valid.replaceFirst("hamster", "Hamster")),
                "capitalized word");

        // 24 x "abandon" is all-zero entropy, whose checksum word is "art" (Trezor anchor 1), not "abandon".
        String zeros = String.join(" ", java.util.Collections.nCopies(24, "abandon"));
        rejectsWith(AvpException.Kind.BAD_CHECKSUM, () -> AvpOwner.mnemonicToEntropy(zeros), "all abandon");
        // 24 x "zoo" is all-ones entropy, whose checksum word is "vote" (Trezor anchor 2), not "zoo".
        String ones = String.join(" ", java.util.Collections.nCopies(24, "zoo"));
        rejectsWith(AvpException.Kind.BAD_CHECKSUM, () -> AvpOwner.mnemonicToEntropy(ones), "all zoo");

        rejects(() -> AvpOwner.entropyToMnemonic(new byte[16]), "16 bytes of entropy");
        rejects(() -> AvpOwner.fromSeed(new byte[32]), "a 32-byte seed");
    }

    // ─── AvpJson (strict parser and writer) ───────────────────────────────────────────

    private static void json() throws Exception {
        for (String bad : List.of(
                "",
                " ",
                "{",
                "{\"a\":1,}",
                "[1,]",
                "[1 2]",
                "{\"a\" 1}",
                "{a:1}",
                "{'a':1}",
                "01",
                "-",
                "1.",
                ".5",
                "1e",
                "+1",
                "NaN",
                "Infinity",
                "tru",
                "nul",
                "\"abc",
                "\"a\u0001b\"",
                "\"\\x\"",
                "\"\\u12\"",
                "\"\\ud800\"",
                "\"\\udc00\\ud800\"",
                "{\"a\":1,\"a\":2}",
                "{} {}",
                "[] x",
                "[" + "[".repeat(200) + "]".repeat(200) + "]")) {
            rejectsWith(AvpException.Kind.BAD_ENCODING, () -> AvpJson.parse(bad), "malformed JSON " + show(bad));
        }
        rejectsWith(
                AvpException.Kind.BAD_ENCODING,
                () -> AvpJson.parse(new byte[] {'"', (byte) 0xc3, '"'}),
                "invalid UTF-8 bytes");
        rejectsWith(
                AvpException.Kind.BAD_ENCODING,
                () -> AvpJson.parse(new byte[] {'"', (byte) 0xed, (byte) 0xa0, (byte) 0x80, '"'}),
                "UTF-8 encoded surrogate");

        // Values and the compact writer, expected forms written by hand from RFC 8259.
        eq(2L, AvpJson.parse("2"), "integer");
        eq(-9223372036854775808L, AvpJson.parse("-9223372036854775808"), "int64 min");
        eq(new java.math.BigInteger("9223372036854775808"), AvpJson.parse("9223372036854775808"), "beyond int64");
        eq(new java.math.BigDecimal("1.5e3"), AvpJson.parse("1.5e3"), "fraction and exponent");
        eq(
                "a\"\\/\b\f\n\r\t\u00e9\ud83d\ude00",
                AvpJson.parse("\"a\\\"\\\\\\/\\b\\f\\n\\r\\t\\u00e9\\ud83d\\ude00\""),
                "escapes");
        eq(true, AvpJson.parse(" true "), "true");
        eq(null, AvpJson.parse("null"), "null");
        Object tree = AvpJson.parse(" { \"b\" : [ 1 , { } , [ ] , null , false ] , \"a\" : \"x\" } ");
        eq("{\"b\":[1,{},[],null,false],\"a\":\"x\"}", AvpJson.write(tree), "field order is kept");
        eq(
                "\"a\\\"\\\\/\\b\\f\\n\\r\\t\\u0001\u00e9\"",
                AvpJson.write("a\"\\/\b\f\n\r\t\u0001\u00e9"),
                "string escapes");
        eq("[1.5E+3,9223372036854775808]", AvpJson.write(AvpJson.parse("[1.5e3,9223372036854775808]")), "big numbers");
        String deepest = "[".repeat(AvpJson.MAX_DEPTH) + "]".repeat(AvpJson.MAX_DEPTH);
        eq(deepest, AvpJson.write(AvpJson.parse(deepest)), "nesting at the depth bound");
        String tooDeep = "[".repeat(AvpJson.MAX_DEPTH + 1) + "]".repeat(AvpJson.MAX_DEPTH + 1);
        rejectsWith(AvpException.Kind.BAD_ENCODING, () -> AvpJson.parse(tooDeep), "nesting past the depth bound");
        Map<String, Object> ordered = new LinkedHashMap<>();
        ordered.put("z", 1L);
        ordered.put("a", List.of());
        eq("{\"z\":1,\"a\":[]}", AvpJson.write(ordered), "insertion order");
        rejects(() -> AvpJson.string(m(AvpJson.parse("{\"a\":1}")), "a"), "a number where a string is required");
        rejects(() -> AvpJson.integer(m(AvpJson.parse("{\"a\":\"1\"}")), "a"), "a string where an integer is required");
        rejects(() -> AvpJson.integer(m(AvpJson.parse("{}")), "a"), "a missing required field");

        // A number literal is at most MAX_NUMBER_LENGTH characters, which bounds BigInteger parsing.
        String longest = "1".repeat(AvpJson.MAX_NUMBER_LENGTH);
        eq(new java.math.BigInteger(longest), AvpJson.parse(longest), "a number at the length bound");
        rejectsWith(
                AvpException.Kind.BAD_ENCODING,
                () -> AvpJson.parse("1".repeat(AvpJson.MAX_NUMBER_LENGTH + 1)),
                "a number past the length bound");
        rejectsWith(
                AvpException.Kind.BAD_ENCODING,
                () -> AvpJson.parse("[0." + "1".repeat(AvpJson.MAX_NUMBER_LENGTH) + "]"),
                "a fraction past the length bound");
    }

    // ─── Strict Ed25519 verification (SPEC 2) ─────────────────────────────────────────

    /** The SPEC 2 small-order encodings, little-endian hex. */
    private static final List<String> SMALL_ORDER = List.of(
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");

    private static void strictEd25519() throws Exception {
        Map<String, Object> rfc = m(l(m(load("ed25519.json")).get("cases")).get(0));
        byte[] pub = hx(s(rfc, "publicKeyHex"));
        byte[] sig = hx(s(rfc, "signatureHex"));
        check(AvpCrypto.ed25519StrictInputsOk(pub, sig), "an RFC 8032 signature passes the pre-checks");

        byte[] sig0 = new byte[64];
        sig0[0] = 1; // R = identity, S = 0
        for (String enc : SMALL_ORDER) {
            byte[] key = hx(enc);
            check(!AvpCrypto.ed25519StrictInputsOk(key, sig), "small-order key " + enc);
            byte[] signed = key.clone();
            signed[31] |= (byte) 0x80; // the sign bit does not change the point's order
            check(!AvpCrypto.ed25519StrictInputsOk(signed, sig), "small-order key with the sign bit " + enc);
            byte[] r = sig.clone();
            System.arraycopy(key, 0, r, 0, 32);
            check(!AvpCrypto.ed25519StrictInputsOk(pub, r), "small-order R " + enc);
        }
        // y = p + 2 is non-canonical but not on the blocklist: the canonical check rejects it.
        byte[] nonCanonical = hx("ef" + "ff".repeat(30) + "7f");
        check(!AvpCrypto.ed25519StrictInputsOk(nonCanonical, sig), "a non-canonical key y = p + 2");
        byte[] rNonCanonical = sig.clone();
        System.arraycopy(nonCanonical, 0, rNonCanonical, 0, 32);
        check(!AvpCrypto.ed25519StrictInputsOk(pub, rNonCanonical), "a non-canonical R y = p + 2");
        // S = L is the smallest non-canonical S.
        byte[] sL = sig.clone();
        System.arraycopy(hx("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"), 0, sL, 32, 32);
        check(!AvpCrypto.ed25519StrictInputsOk(pub, sL), "S = L");
        byte[] sLm1 = sig.clone();
        System.arraycopy(hx("ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"), 0, sLm1, 32, 32);
        check(AvpCrypto.ed25519StrictInputsOk(pub, sLm1), "S = L - 1 is canonical");

        // The forged genesis of the review probe: ownerKey is the identity point, and the owner and
        // commit signatures are R = identity, S = 0. No private key exists, so it MUST be rejected.
        byte[] id = new byte[32];
        id[0] = 1;
        byte[] host = new byte[32];
        host[0] = 5;
        byte[] nonce = new byte[16];
        String repo = AvpManifest.deriveRepoId(id, nonce);
        AvpManifest.WrappedKey wk =
                new AvpManifest.WrappedKey(AvpCrypto.SCHEME_ID, new byte[32], new byte[12], new byte[48]);
        AvpManifest.MemberEntry me = new AvpManifest.MemberEntry(id, new byte[32], wk, 0, host);
        AvpManifest.ManifestState st = new AvpManifest.ManifestState(
                repo,
                1,
                new byte[0],
                id,
                nonce,
                AvpCrypto.SCHEME_ID,
                0,
                false,
                List.of(new AvpManifest.HostRef(host, "vault.example")),
                List.of(me),
                List.of());
        AvpManifest.SignedManifest forged = new AvpManifest.SignedManifest(st, sig0);
        check(!AvpManifest.verify(forged), "the forged genesis does not verify");
        byte[] mh = AvpManifest.hash(forged);
        AvpCommit.Commit unsigned =
                new AvpCommit.Commit(repo, new byte[32], List.of(), 1, mh, 0, id, new byte[12], new byte[16], sig0);
        AvpCommit.Commit c = new AvpCommit.Commit(
                repo, AvpCommit.id(unsigned), List.of(), 1, mh, 0, id, new byte[12], new byte[16], sig0);
        check(!AvpCommit.verify(c), "the forged commit does not verify");
        for (AvpRules.Via via : AvpRules.Via.values()) {
            AvpRules.RepoView view = new AvpRules.RepoView(host, 16);
            eq(
                    Optional.of("bad_request"),
                    view.applyManifest(forged, Optional.of(c), via),
                    "forged genesis via " + via);
            check(view.tip().isEmpty() && view.heads().isEmpty(), "the forged genesis stores nothing via " + via);
        }

        // A commit by the identity key in a real repository is malformed (its signature cannot verify).
        Fixture f = fixture();
        AvpRules.RepoView view = started(f);
        AvpCommit.Commit u = new AvpCommit.Commit(
                f.genesis().state().repoId(),
                new byte[32],
                List.of(f.root().commitId()),
                1,
                AvpManifest.hash(f.genesis()),
                0,
                id,
                new byte[12],
                new byte[16],
                sig0);
        AvpCommit.Commit byIdentity = new AvpCommit.Commit(
                u.repoId(), AvpCommit.id(u), u.parents(), 1, u.manifestHash(), 0, id, u.iv(), u.ciphertext(), sig0);
        eq(
                Optional.of("bad_request"),
                view.applyCommit(byIdentity, AvpRules.Via.OFFER),
                "an identity-key commit by offer");
        // Leave requests and acceptances go through the same verification.
        AvpTokens.LeaveRequest leave =
                new AvpTokens.LeaveRequest(f.genesis().state().repoId(), id, 1, sig0);
        check(!AvpTokens.verifyLeave(leave), "an identity-key leave does not verify");
        AvpTokens.Acceptance acc = new AvpTokens.Acceptance(f.genesis().state().repoId(), id, id, Long.MAX_VALUE, sig0);
        check(!AvpTokens.verifyAcceptance(acc), "an identity-key acceptance does not verify");
    }

    // ─── RepoView keeps its own copies ────────────────────────────────────────────────

    private static void defensiveCopies() throws Exception {
        Fixture f = fixture();
        AvpCommit.Commit root = AvpCommit.fromJson(AvpCommit.toJson(f.root()));
        AvpManifest.SignedManifest genesis = AvpManifest.signedManifestFromJson(AvpManifest.toJson(f.genesis()));
        AvpRules.RepoView view = new AvpRules.RepoView(f.hostA(), 16);
        eq(Optional.empty(), view.applyManifest(genesis, Optional.of(root), AvpRules.Via.PUSH), "genesis");
        byte[] rootId = f.root().commitId();
        byte[] genesisHash = AvpManifest.hash(f.genesis());

        // Changing the caller's records after applying them does not change the view.
        root.commitId()[0] ^= 1;
        root.ciphertext()[0] ^= 1;
        genesis.state().ownerKey()[0] ^= 1;
        genesis.ownerSignature()[0] ^= 1;
        eq(genesisHash, AvpManifest.hash(view.tip().orElseThrow()), "the stored tip is unchanged");
        check(view.fetchCommit(rootId).map(AvpCommit::verify).orElse(false), "the stored commit still verifies");

        // Changing a record a reader returned does not change the view either.
        view.tip().orElseThrow().ownerSignature()[0] ^= 1;
        view.fetchCommit(rootId).orElseThrow().ciphertext()[0] ^= 1;
        eq(
                genesisHash,
                AvpManifest.hash(view.tip().orElseThrow()),
                "the tip is unchanged after a reader's copy changed");
        check(
                view.fetchCommit(rootId).map(AvpCommit::verify).orElse(false),
                "the commit is unchanged after a reader's copy changed");
    }
}
