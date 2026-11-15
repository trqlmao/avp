/*
 * Manifest states (SPEC 4.2): the wire records, the canonical bytes S, the owner signature,
 * manifestHash, and the repoId derivation.
 *
 * SPDX-License-Identifier: MIT
 */

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Manifest states and their owner signature (SPEC 4.2).
 *
 * <p>The records hold raw bytes; their constructors copy every array and list they are given, and
 * their accessors return the record's own arrays, which callers must not modify. Records compare
 * byte arrays by identity, so compare two values by their wire form ({@code toJson}). The {@code
 * fromJson} decoders check every fixed binary length (SPEC 6.1 rule 1), which a host answers with
 * {@code 400 bad_request}; the rules engine checks the variable ones.
 */
public final class AvpManifest {

    private AvpManifest() {}

    /**
     * A host that replicates the repository (SPEC 3.3, 4.2).
     *
     * @param hostKey the 32-byte Ed25519 host key
     * @param locator the dialing hint, {@code host} or {@code host:port}
     */
    public record HostRef(byte[] hostKey, String locator) {
        /** Copies the key. */
        public HostRef {
            hostKey = hostKey.clone();
        }
    }

    /**
     * A secret wrapped to one recipient with the default wrap scheme (SPEC 4.4).
     *
     * @param schemeId the wrap scheme id
     * @param ephemeralPublicKey the 32-byte ephemeral X25519 public key
     * @param iv the 12-byte AES-GCM IV
     * @param ciphertext the wrapped secret with the 16-byte tag appended
     */
    public record WrappedKey(String schemeId, byte[] ephemeralPublicKey, byte[] iv, byte[] ciphertext) {
        /** Copies the arrays. */
        public WrappedKey {
            ephemeralPublicKey = ephemeralPublicKey.clone();
            iv = iv.clone();
            ciphertext = ciphertext.clone();
        }
    }

    /**
     * A member as the owner signed it (SPEC 4.2).
     *
     * @param ed25519PublicKey the member's 32-byte Ed25519 key, its member id
     * @param x25519PublicKey the member's 32-byte X25519 key
     * @param wrappedDataKey the data key of {@code keyEpoch} wrapped to {@code x25519PublicKey}
     * @param keyEpoch the epoch of the wrapped data key
     * @param homeHostKey the 32-byte host key of the member's home host
     */
    public record MemberEntry(
            byte[] ed25519PublicKey,
            byte[] x25519PublicKey,
            WrappedKey wrappedDataKey,
            long keyEpoch,
            byte[] homeHostKey) {
        /** Copies the keys. */
        public MemberEntry {
            ed25519PublicKey = ed25519PublicKey.clone();
            x25519PublicKey = x25519PublicKey.clone();
            homeHostKey = homeHostKey.clone();
        }
    }

    /**
     * A removed member and its signed removal cutoff (SPEC 4.2, 7.3).
     *
     * @param memberKey the removed member's 32-byte Ed25519 key
     * @param removedAtSeq the {@code manifestSeq} of the state that removed it
     * @param frontier the 32-byte commit ids of the cutoff
     */
    public record Removal(byte[] memberKey, long removedAtSeq, List<byte[]> frontier) {
        /** Copies the key and the ids. */
        public Removal {
            memberKey = memberKey.clone();
            frontier = copyIds(frontier);
        }
    }

    /**
     * One manifest state (SPEC 4.2).
     *
     * @param repoId the repository id
     * @param manifestSeq {@code 1} at genesis, {@code +1} per state
     * @param prevManifestHash the previous state's {@code manifestHash}; empty at seq 1
     * @param ownerKey the 32-byte owner Ed25519 key
     * @param genesisNonce 16 random bytes at seq 1; empty after
     * @param schemeId the wrap scheme id
     * @param keyEpoch the current data key epoch
     * @param shareRefreshTokens the refresh-token policy (SPEC 5.1)
     * @param hosts the hosts that replicate the repository
     * @param members the members, the owner included
     * @param removals every member ever removed, cumulative
     */
    public record ManifestState(
            String repoId,
            long manifestSeq,
            byte[] prevManifestHash,
            byte[] ownerKey,
            byte[] genesisNonce,
            String schemeId,
            long keyEpoch,
            boolean shareRefreshTokens,
            List<HostRef> hosts,
            List<MemberEntry> members,
            List<Removal> removals) {
        /** Copies the arrays and lists. */
        public ManifestState {
            prevManifestHash = prevManifestHash.clone();
            ownerKey = ownerKey.clone();
            genesisNonce = genesisNonce.clone();
            hosts = List.copyOf(hosts);
            members = List.copyOf(members);
            removals = List.copyOf(removals);
        }

        /**
         * Whether a key is a member of this state.
         *
         * @param key an Ed25519 public key
         * @return whether a member has that key
         */
        public boolean hasMember(byte[] key) {
            return members.stream().anyMatch(m -> Arrays.equals(m.ed25519PublicKey(), key));
        }

        /**
         * Whether a key is in this state's {@code hosts}.
         *
         * @param key a host key
         * @return whether a host has that key
         */
        public boolean hasHost(byte[] key) {
            return hosts.stream().anyMatch(h -> Arrays.equals(h.hostKey(), key));
        }

        /**
         * The removal of a key in this state.
         *
         * @param key an Ed25519 public key
         * @return the removal, or empty if the key was never removed
         */
        public Optional<Removal> removalOf(byte[] key) {
            return removals.stream()
                    .filter(r -> Arrays.equals(r.memberKey(), key))
                    .findFirst();
        }
    }

    /**
     * A manifest state with its owner signature (SPEC 4.2).
     *
     * @param state the state
     * @param ownerSignature the 64-byte {@code Ed25519-Sign(ownerKey, S)}
     */
    public record SignedManifest(ManifestState state, byte[] ownerSignature) {
        /** Copies the signature. */
        public SignedManifest {
            ownerSignature = ownerSignature.clone();
        }
    }

    static List<byte[]> copyIds(List<byte[]> ids) {
        List<byte[]> out = new ArrayList<>(ids.size());
        for (byte[] id : ids) {
            out.add(id.clone());
        }
        return List.copyOf(out);
    }

    // ─── Encoding, signature, hash (SPEC 4.2) ─────────────────────────────────────────

    /**
     * The canonical bytes {@code S} of a state (SPEC 4.2). Hosts are sorted by {@code hostKey},
     * members by {@code ed25519PublicKey}, removals by {@code memberKey}, and each frontier by commit
     * id, so the order of every wire list does not matter.
     *
     * @param s the state
     * @return {@code S}
     * @throws AvpException if a list holds the same key twice (SPEC 4.2 wire form)
     */
    public static byte[] encode(ManifestState s) throws AvpException {
        AvpEncoding w = AvpEncoding.tag("avp/manifest/v1")
                .str(s.repoId())
                .i64(s.manifestSeq())
                .bytes(s.prevManifestHash())
                .bytes(s.ownerKey())
                .bytes(s.genesisNonce())
                .str(s.schemeId())
                .i64(s.keyEpoch())
                .bool(s.shareRefreshTokens());

        List<HostRef> hosts = sortedBy(s.hosts(), HostRef::hostKey, "hostKey");
        w.count(hosts.size());
        for (HostRef h : hosts) {
            w.bytes(h.hostKey()).str(h.locator());
        }

        List<MemberEntry> members = sortedBy(s.members(), MemberEntry::ed25519PublicKey, "member ed25519PublicKey");
        w.count(members.size());
        for (MemberEntry m : members) {
            WrappedKey wk = m.wrappedDataKey();
            w.bytes(m.ed25519PublicKey())
                    .bytes(m.x25519PublicKey())
                    .str(wk.schemeId())
                    .bytes(wk.ephemeralPublicKey())
                    .bytes(wk.iv())
                    .bytes(wk.ciphertext())
                    .i64(m.keyEpoch())
                    .bytes(m.homeHostKey());
        }

        List<Removal> removals = sortedBy(s.removals(), Removal::memberKey, "removal memberKey");
        w.count(removals.size());
        for (Removal r : removals) {
            w.bytes(r.memberKey()).i64(r.removedAtSeq());
            List<byte[]> frontier = AvpEncoding.sortedUnique(r.frontier(), "frontier commit id");
            w.count(frontier.size());
            for (byte[] id : frontier) {
                w.bytes(id);
            }
        }
        return w.finish();
    }

    private static <T> List<T> sortedBy(List<T> items, java.util.function.Function<T, byte[]> key, String what)
            throws AvpException {
        List<T> out = new ArrayList<>(items);
        out.sort((a, b) -> AvpEncoding.compare(key.apply(a), key.apply(b)));
        for (int k = 1; k < out.size(); k++) {
            if (AvpEncoding.compare(key.apply(out.get(k - 1)), key.apply(out.get(k))) == 0) {
                throw AvpException.encoding("duplicate " + what);
            }
        }
        return out;
    }

    /**
     * Signs a state with the owner key: {@code ownerSignature = Ed25519-Sign(ownerKey, S)}. The
     * caller passes the seed whose public key is {@code ownerKey}; a state signed by another key
     * fails {@link #verify(SignedManifest)}.
     *
     * @param s the state
     * @param ownerSeed the owner's 32-byte Ed25519 seed
     * @return the signed manifest
     * @throws AvpException if the state does not encode or the seed has the wrong length
     */
    public static SignedManifest sign(ManifestState s, byte[] ownerSeed) throws AvpException {
        return new SignedManifest(s, AvpCrypto.ed25519Sign(ownerSeed, encode(s)));
    }

    /**
     * {@code manifestHash = SHA-256(S || ownerSignature)}, the raw 64-byte signature appended with no
     * length prefix (SPEC 4.2).
     *
     * @param m the signed manifest
     * @return the 32-byte hash
     * @throws AvpException if the state does not encode
     */
    public static byte[] hash(SignedManifest m) throws AvpException {
        return AvpCrypto.sha256(AvpCrypto.concat(encode(m.state()), m.ownerSignature()));
    }

    /**
     * Verifies the owner signature over {@code S} under {@code ownerKey} (SPEC 4.2, 6.1 rule 2).
     *
     * @param m the signed manifest
     * @return whether the state encodes and the signature verifies; never throws
     */
    public static boolean verify(SignedManifest m) {
        try {
            return AvpCrypto.ed25519Verify(m.state().ownerKey(), encode(m.state()), m.ownerSignature());
        } catch (AvpException e) {
            return false;
        }
    }

    /**
     * Whether a state links to {@code prev} (SPEC 6.3): its {@code manifestSeq} is {@code prev}'s
     * plus one and its {@code prevManifestHash} is {@code prev}'s {@code manifestHash}.
     *
     * @param next the later state
     * @param prev the earlier state
     * @return whether {@code next} links to {@code prev}; {@code false} if {@code prev} does not encode
     */
    public static boolean linksTo(SignedManifest next, SignedManifest prev) {
        long seq = prev.state().manifestSeq();
        if (seq == Long.MAX_VALUE || next.state().manifestSeq() != seq + 1) {
            return false;
        }
        try {
            return AvpCrypto.constantTimeEquals(next.state().prevManifestHash(), hash(prev));
        } catch (AvpException e) {
            return false;
        }
    }

    /**
     * The repository id (SPEC 4.2): {@code base64url-nopad(SHA-256(CE(tag "avp/repo-id/v1",
     * bytes(ownerKey), bytes(genesisNonce)))[0..16])}, 22 characters.
     *
     * @param ownerKey the 32-byte owner key
     * @param genesisNonce the 16-byte genesis nonce
     * @return the repoId
     * @throws AvpException if a length is wrong
     */
    public static String deriveRepoId(byte[] ownerKey, byte[] genesisNonce) throws AvpException {
        if (ownerKey.length != 32 || genesisNonce.length != 16) {
            throw AvpException.encoding("repoId needs a 32-byte owner key and a 16-byte nonce");
        }
        byte[] digest = AvpCrypto.sha256(AvpEncoding.tag("avp/repo-id/v1")
                .bytes(ownerKey)
                .bytes(genesisNonce)
                .finish());
        return AvpEncoding.base64Url(Arrays.copyOf(digest, 16));
    }

    // ─── Wire form (SPEC 10.2) ────────────────────────────────────────────────────────

    /**
     * Decodes a {@code SignedManifest} from its HTTP/JSON form. Unknown fields are ignored; an absent
     * {@code prevManifestHash} or {@code genesisNonce} is empty, an absent {@code shareRefreshTokens}
     * is {@code false} (SPEC 5.1), and absent {@code removals} are none.
     *
     * @param json the parsed JSON value
     * @return the signed manifest
     * @throws AvpException if a field is missing, has the wrong type, or a fixed binary field has the
     *     wrong length
     */
    public static SignedManifest signedManifestFromJson(Object json) throws AvpException {
        Map<String, Object> o = AvpJson.object(json, "SignedManifest");
        return new SignedManifest(
                manifestStateFromJson(AvpJson.required(o, "state")),
                AvpEncoding.fromBase64(AvpJson.string(o, "ownerSignature"), 64));
    }

    /**
     * Decodes a {@code ManifestState} from its HTTP/JSON form.
     *
     * @param json the parsed JSON value
     * @return the state
     * @throws AvpException as {@link #signedManifestFromJson(Object)}
     */
    public static ManifestState manifestStateFromJson(Object json) throws AvpException {
        Map<String, Object> o = AvpJson.object(json, "ManifestState");
        List<HostRef> hosts = new ArrayList<>();
        for (Object h : AvpJson.array(AvpJson.required(o, "hosts"), "hosts")) {
            Map<String, Object> ho = AvpJson.object(h, "HostRef");
            hosts.add(new HostRef(key32(ho, "hostKey"), AvpJson.string(ho, "locator")));
        }
        List<MemberEntry> members = new ArrayList<>();
        for (Object m : AvpJson.array(AvpJson.required(o, "members"), "members")) {
            Map<String, Object> mo = AvpJson.object(m, "MemberEntry");
            members.add(new MemberEntry(
                    key32(mo, "ed25519PublicKey"),
                    key32(mo, "x25519PublicKey"),
                    wrappedKeyFromJson(AvpJson.required(mo, "wrappedDataKey")),
                    AvpJson.integer(mo, "keyEpoch"),
                    key32(mo, "homeHostKey")));
        }
        List<Removal> removals = new ArrayList<>();
        for (Object r : AvpJson.array(AvpJson.optional(o, "removals").orElse(List.of()), "removals")) {
            Map<String, Object> ro = AvpJson.object(r, "Removal");
            removals.add(new Removal(key32(ro, "memberKey"), AvpJson.integer(ro, "removedAtSeq"), ids(ro, "frontier")));
        }
        return new ManifestState(
                AvpJson.string(o, "repoId"),
                AvpJson.integer(o, "manifestSeq"),
                optionalBytes(o, "prevManifestHash"),
                key32(o, "ownerKey"),
                optionalBytes(o, "genesisNonce"),
                AvpJson.string(o, "schemeId"),
                AvpJson.integer(o, "keyEpoch"),
                AvpJson.bool(AvpJson.optional(o, "shareRefreshTokens").orElse(Boolean.FALSE), "shareRefreshTokens"),
                hosts,
                members,
                removals);
    }

    /**
     * Decodes a {@code WrappedKey} from its HTTP/JSON form.
     *
     * @param json the parsed JSON value
     * @return the wrapped key
     * @throws AvpException if a field is missing, has the wrong type, or the ephemeral key or IV has
     *     the wrong length
     */
    public static WrappedKey wrappedKeyFromJson(Object json) throws AvpException {
        Map<String, Object> o = AvpJson.object(json, "WrappedKey");
        return new WrappedKey(
                AvpJson.string(o, "schemeId"),
                key32(o, "ephemeralPublicKey"),
                AvpEncoding.fromBase64(AvpJson.string(o, "iv"), 12),
                AvpEncoding.fromBase64(AvpJson.string(o, "ciphertext")));
    }

    /**
     * The HTTP/JSON form of a signed manifest, fields in the proto order.
     *
     * @param m the signed manifest
     * @return the JSON tree
     */
    public static Map<String, Object> toJson(SignedManifest m) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("state", toJson(m.state()));
        o.put("ownerSignature", AvpEncoding.base64(m.ownerSignature()));
        return o;
    }

    /**
     * The HTTP/JSON form of a manifest state, fields in the proto order and lists in their own order.
     *
     * @param s the state
     * @return the JSON tree
     */
    public static Map<String, Object> toJson(ManifestState s) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("repoId", s.repoId());
        o.put("manifestSeq", s.manifestSeq());
        o.put("prevManifestHash", AvpEncoding.base64(s.prevManifestHash()));
        o.put("ownerKey", AvpEncoding.base64(s.ownerKey()));
        o.put("genesisNonce", AvpEncoding.base64(s.genesisNonce()));
        o.put("schemeId", s.schemeId());
        o.put("keyEpoch", s.keyEpoch());
        o.put("shareRefreshTokens", s.shareRefreshTokens());
        List<Object> hosts = new ArrayList<>();
        for (HostRef h : s.hosts()) {
            Map<String, Object> ho = new LinkedHashMap<>();
            ho.put("hostKey", AvpEncoding.base64(h.hostKey()));
            ho.put("locator", h.locator());
            hosts.add(ho);
        }
        o.put("hosts", hosts);
        List<Object> members = new ArrayList<>();
        for (MemberEntry m : s.members()) {
            Map<String, Object> mo = new LinkedHashMap<>();
            mo.put("ed25519PublicKey", AvpEncoding.base64(m.ed25519PublicKey()));
            mo.put("x25519PublicKey", AvpEncoding.base64(m.x25519PublicKey()));
            mo.put("wrappedDataKey", toJson(m.wrappedDataKey()));
            mo.put("keyEpoch", m.keyEpoch());
            mo.put("homeHostKey", AvpEncoding.base64(m.homeHostKey()));
            members.add(mo);
        }
        o.put("members", members);
        List<Object> removals = new ArrayList<>();
        for (Removal r : s.removals()) {
            Map<String, Object> ro = new LinkedHashMap<>();
            ro.put("memberKey", AvpEncoding.base64(r.memberKey()));
            ro.put("removedAtSeq", r.removedAtSeq());
            ro.put("frontier", idsJson(r.frontier()));
            removals.add(ro);
        }
        o.put("removals", removals);
        return o;
    }

    /**
     * The HTTP/JSON form of a wrapped key.
     *
     * @param wk the wrapped key
     * @return the JSON tree
     */
    public static Map<String, Object> toJson(WrappedKey wk) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("schemeId", wk.schemeId());
        o.put("ephemeralPublicKey", AvpEncoding.base64(wk.ephemeralPublicKey()));
        o.put("iv", AvpEncoding.base64(wk.iv()));
        o.put("ciphertext", AvpEncoding.base64(wk.ciphertext()));
        return o;
    }

    static byte[] key32(Map<String, Object> o, String key) throws AvpException {
        return AvpEncoding.fromBase64(AvpJson.string(o, key), 32);
    }

    private static byte[] optionalBytes(Map<String, Object> o, String key) throws AvpException {
        Optional<Object> v = AvpJson.optional(o, key);
        return v.isEmpty() ? new byte[0] : AvpEncoding.fromBase64(AvpJson.string(v.get(), key));
    }

    /**
     * A required list of 32-byte ids.
     *
     * @param o the object
     * @param key the field name
     * @return the ids
     * @throws AvpException if the field is missing or an element is not 32 bytes of base64
     */
    static List<byte[]> ids(Map<String, Object> o, String key) throws AvpException {
        List<byte[]> out = new ArrayList<>();
        for (Object id : AvpJson.array(AvpJson.required(o, key), key)) {
            out.add(AvpEncoding.fromBase64(AvpJson.string(id, key), 32));
        }
        return out;
    }

    /**
     * The JSON form of a list of ids.
     *
     * @param ids the ids
     * @return the base64 strings
     */
    static List<Object> idsJson(List<byte[]> ids) {
        List<Object> out = new ArrayList<>();
        for (byte[] id : ids) {
            out.add(AvpEncoding.base64(id));
        }
        return out;
    }
}
