/*
 * Out-of-band tokens and addressing (SPEC 11): the invite token and host acceptance, the repo
 * locator and avp:// URI, device link request and grant, the leave request, and fingerprints.
 *
 * SPDX-License-Identifier: MIT
 */

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Tokens (SPEC 11).
 *
 * <p>A token is base64url-nopad over compact JSON with its fields in the SPEC order and {@code "v":
 * 2} (SPEC 11.1): {@link #encode(Map)} writes the map that a {@code toJson} method builds, in that
 * order, and {@link #decode(String)} reads any valid JSON object, so the typed {@code fromJson}
 * decoders accept any field order and whitespace, ignore unknown fields, and reject a {@code v}
 * other than the integer {@code 2} and a binary field of the wrong length.
 */
public final class AvpTokens {

    private AvpTokens() {}

    /**
     * A host's signed agreement to carry a repository for one joining member (SPEC 8.2, 11.3).
     *
     * @param repoId the repository
     * @param memberKey the joining member's 32-byte Ed25519 key
     * @param hostKey the accepting host's 32-byte key
     * @param expiresAt epoch milliseconds after which the acceptance is void
     * @param signature the host's 64-byte signature over {@link #acceptanceMessage(Acceptance)}
     */
    public record Acceptance(String repoId, byte[] memberKey, byte[] hostKey, long expiresAt, byte[] signature) {
        /** Copies the arrays. */
        public Acceptance {
            memberKey = memberKey.clone();
            hostKey = hostKey.clone();
            signature = signature.clone();
        }
    }

    /**
     * {@code InviteToken}, sent by the joiner to the owner (SPEC 11.3). Its {@code v} is always 2.
     *
     * @param ed25519PublicKey the joiner's 32-byte Ed25519 key
     * @param x25519PublicKey the joiner's 32-byte X25519 key, the only key the owner wraps to
     * @param homeHostKey the joiner's 32-byte home host key
     * @param homeHostLocator the joiner's home host locator
     * @param acceptance the home host's acceptance
     */
    public record InviteToken(
            byte[] ed25519PublicKey,
            byte[] x25519PublicKey,
            byte[] homeHostKey,
            String homeHostLocator,
            Acceptance acceptance) {
        /** Copies the keys. */
        public InviteToken {
            ed25519PublicKey = ed25519PublicKey.clone();
            x25519PublicKey = x25519PublicKey.clone();
            homeHostKey = homeHostKey.clone();
        }
    }

    /**
     * {@code RepoLocator}, sent by the owner to a joiner (SPEC 11.2). Its {@code v} is always 2.
     *
     * @param repoId the repository
     * @param hostKey the owner's 32-byte home host key
     * @param hostLocator the owner's home host locator
     * @param ownerFingerprint {@link #ownerFingerprint(byte[])} of the owner key
     */
    public record RepoLocator(String repoId, byte[] hostKey, String hostLocator, String ownerFingerprint) {
        /** Copies the key. */
        public RepoLocator {
            hostKey = hostKey.clone();
        }
    }

    /**
     * {@code LinkRequest}, shown by a new owner device (SPEC 11.6). Its {@code v} is always 2.
     *
     * @param ephemeralPublicKey the new device's 32-byte ephemeral X25519 public key
     */
    public record LinkRequest(byte[] ephemeralPublicKey) {
        /** Copies the key. */
        public LinkRequest {
            ephemeralPublicKey = ephemeralPublicKey.clone();
        }
    }

    /**
     * {@code LinkGrant}, returned by an existing owner device (SPEC 11.6). Its {@code v} is always 2.
     *
     * @param wrap the 32-byte mnemonic entropy wrapped under {@code avp/owner-link/v1}
     */
    public record LinkGrant(AvpManifest.WrappedKey wrap) {}

    /**
     * A member's signed request to leave a repository (SPEC 8.4, 11.4). Sent as a JSON body, not as a
     * base64url token.
     *
     * @param repoId the repository
     * @param memberKey the leaving member's 32-byte Ed25519 key
     * @param at the leaving client's time in epoch milliseconds
     * @param signature the member's 64-byte signature over {@link #leaveMessage(LeaveRequest)}
     */
    public record LeaveRequest(String repoId, byte[] memberKey, long at, byte[] signature) {
        /** Copies the arrays. */
        public LeaveRequest {
            memberKey = memberKey.clone();
            signature = signature.clone();
        }
    }

    /**
     * An {@code avp://<hostLocator>/<repoId>} locator URI (SPEC 11.2).
     *
     * @param hostLocator the host locator, {@code host} or {@code host:port}
     * @param repoId the 22-character repository id
     */
    public record AvpUri(String hostLocator, String repoId) {
        /**
         * The URI text.
         *
         * @return {@code avp://<hostLocator>/<repoId>}
         */
        @Override
        public String toString() {
            return "avp://" + hostLocator + "/" + repoId;
        }
    }

    // ─── Token encoding (SPEC 11.1) ───────────────────────────────────────────────────

    /**
     * Encodes a token: base64url-nopad over the compact JSON of {@code json}, fields in its iteration
     * order.
     *
     * @param json the token's JSON tree, as a {@code toJson} method builds it
     * @return the token text
     */
    public static String encode(Map<String, Object> json) {
        return AvpEncoding.base64Url(AvpJson.writeUtf8(json));
    }

    /**
     * Decodes a token's outer encoding: base64url-nopad over a JSON object.
     *
     * @param token the token text
     * @return the JSON object, for a typed {@code fromJson} decoder
     * @throws AvpException if the text is not canonical base64url-nopad or not a JSON object
     */
    public static Map<String, Object> decode(String token) throws AvpException {
        return AvpJson.object(AvpJson.parse(AvpEncoding.fromBase64Url(token)), "token");
    }

    private static void requireV2(Map<String, Object> o) throws AvpException {
        Object v = AvpJson.required(o, "v");
        if (!(v instanceof Long n) || n != 2) {
            throw AvpException.encoding("token v must be 2");
        }
    }

    private static Map<String, Object> v2() {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("v", 2L);
        return o;
    }

    // ─── Acceptance and invite (SPEC 8.2, 11.3) ───────────────────────────────────────

    /**
     * The signed message of an acceptance (SPEC 11.3): {@code CE(tag "avp/accept/v1", str(repoId),
     * bytes(memberKey), bytes(hostKey), i64(expiresAt))}.
     *
     * @param a the acceptance
     * @return the message
     * @throws AvpException never for a well-formed tag; the CE writer is fallible in general
     */
    public static byte[] acceptanceMessage(Acceptance a) throws AvpException {
        return AvpEncoding.tag("avp/accept/v1")
                .str(a.repoId())
                .bytes(a.memberKey())
                .bytes(a.hostKey())
                .i64(a.expiresAt())
                .finish();
    }

    /**
     * Signs an acceptance with a host key; the acceptance's {@code hostKey} is that seed's public key.
     *
     * @param repoId the repository
     * @param memberKey the joining member's Ed25519 key
     * @param expiresAt epoch milliseconds after which it is void
     * @param hostSeed the host's 32-byte Ed25519 seed
     * @return the signed acceptance
     * @throws AvpException if the seed has the wrong length
     */
    public static Acceptance signAcceptance(String repoId, byte[] memberKey, long expiresAt, byte[] hostSeed)
            throws AvpException {
        byte[] hostKey = AvpCrypto.ed25519Public(hostSeed);
        Acceptance unsigned = new Acceptance(repoId, memberKey, hostKey, expiresAt, new byte[64]);
        byte[] sig = AvpCrypto.ed25519Sign(hostSeed, acceptanceMessage(unsigned));
        return new Acceptance(repoId, memberKey, hostKey, expiresAt, sig);
    }

    /**
     * Verifies an acceptance under its own {@code hostKey}.
     *
     * @param a the acceptance
     * @return whether the signature verifies
     */
    public static boolean verifyAcceptance(Acceptance a) {
        return verifyAcceptance(a, a.hostKey());
    }

    /**
     * Verifies an acceptance under a given host key.
     *
     * @param a the acceptance
     * @param hostKey the host key to verify under
     * @return whether the signature verifies
     */
    public static boolean verifyAcceptance(Acceptance a, byte[] hostKey) {
        try {
            return AvpCrypto.ed25519Verify(hostKey, acceptanceMessage(a), a.signature());
        } catch (AvpException e) {
            return false;
        }
    }

    /**
     * The owner client's check before it adds a member or a host (SPEC 8.2): the acceptance verifies
     * under its {@code hostKey}, names {@code repoId}, names the token's Ed25519 key and home host
     * key, and expires after {@code nowMs}.
     *
     * @param t the invite token
     * @param repoId the repository the owner is adding the member to
     * @param nowMs the owner client's current time in epoch milliseconds
     * @return whether every condition holds
     */
    public static boolean verifyInvite(InviteToken t, String repoId, long nowMs) {
        Acceptance a = t.acceptance();
        return verifyAcceptance(a)
                && a.repoId().equals(repoId)
                && Arrays.equals(a.memberKey(), t.ed25519PublicKey())
                && Arrays.equals(a.hostKey(), t.homeHostKey())
                && a.expiresAt() > nowMs;
    }

    /**
     * Decodes an acceptance from its JSON form.
     *
     * @param json the parsed JSON value
     * @return the acceptance
     * @throws AvpException if a field is missing, has the wrong type, or a key or the signature has
     *     the wrong length
     */
    public static Acceptance acceptanceFromJson(Object json) throws AvpException {
        Map<String, Object> o = AvpJson.object(json, "Acceptance");
        return new Acceptance(
                AvpJson.string(o, "repoId"),
                AvpManifest.key32(o, "memberKey"),
                AvpManifest.key32(o, "hostKey"),
                AvpJson.integer(o, "expiresAt"),
                AvpEncoding.fromBase64(AvpJson.string(o, "signature"), 64));
    }

    /**
     * The JSON form of an acceptance, fields in the SPEC order.
     *
     * @param a the acceptance
     * @return the JSON tree
     */
    public static Map<String, Object> toJson(Acceptance a) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("repoId", a.repoId());
        o.put("memberKey", AvpEncoding.base64(a.memberKey()));
        o.put("hostKey", AvpEncoding.base64(a.hostKey()));
        o.put("expiresAt", a.expiresAt());
        o.put("signature", AvpEncoding.base64(a.signature()));
        return o;
    }

    /**
     * Decodes an invite token from its JSON form.
     *
     * @param json the parsed JSON value, for example from {@link #decode(String)}
     * @return the invite token
     * @throws AvpException if {@code v} is not 2, a field is missing or has the wrong type, or a key
     *     has the wrong length
     */
    public static InviteToken inviteTokenFromJson(Object json) throws AvpException {
        Map<String, Object> o = AvpJson.object(json, "InviteToken");
        requireV2(o);
        return new InviteToken(
                AvpManifest.key32(o, "ed25519PublicKey"),
                AvpManifest.key32(o, "x25519PublicKey"),
                AvpManifest.key32(o, "homeHostKey"),
                AvpJson.string(o, "homeHostLocator"),
                acceptanceFromJson(AvpJson.required(o, "acceptance")));
    }

    /**
     * The JSON form of an invite token, fields in the SPEC order.
     *
     * @param t the invite token
     * @return the JSON tree, for {@link #encode(Map)}
     */
    public static Map<String, Object> toJson(InviteToken t) {
        Map<String, Object> o = v2();
        o.put("ed25519PublicKey", AvpEncoding.base64(t.ed25519PublicKey()));
        o.put("x25519PublicKey", AvpEncoding.base64(t.x25519PublicKey()));
        o.put("homeHostKey", AvpEncoding.base64(t.homeHostKey()));
        o.put("homeHostLocator", t.homeHostLocator());
        o.put("acceptance", toJson(t.acceptance()));
        return o;
    }

    // ─── Repo locator (SPEC 11.2) ─────────────────────────────────────────────────────

    /**
     * Decodes a repo locator from its JSON form.
     *
     * @param json the parsed JSON value
     * @return the repo locator
     * @throws AvpException if {@code v} is not 2, a field is missing or has the wrong type, or the
     *     host key has the wrong length
     */
    public static RepoLocator repoLocatorFromJson(Object json) throws AvpException {
        Map<String, Object> o = AvpJson.object(json, "RepoLocator");
        requireV2(o);
        return new RepoLocator(
                AvpJson.string(o, "repoId"),
                AvpManifest.key32(o, "hostKey"),
                AvpJson.string(o, "hostLocator"),
                AvpJson.string(o, "ownerFingerprint"));
    }

    /**
     * The JSON form of a repo locator, fields in the SPEC order.
     *
     * @param r the repo locator
     * @return the JSON tree, for {@link #encode(Map)}
     */
    public static Map<String, Object> toJson(RepoLocator r) {
        Map<String, Object> o = v2();
        o.put("repoId", r.repoId());
        o.put("hostKey", AvpEncoding.base64(r.hostKey()));
        o.put("hostLocator", r.hostLocator());
        o.put("ownerFingerprint", r.ownerFingerprint());
        return o;
    }

    // ─── Device linking (SPEC 11.6) ───────────────────────────────────────────────────

    /**
     * Decodes a link request from its JSON form.
     *
     * @param json the parsed JSON value
     * @return the link request
     * @throws AvpException if {@code v} is not 2 or the key is missing or not 32 bytes
     */
    public static LinkRequest linkRequestFromJson(Object json) throws AvpException {
        Map<String, Object> o = AvpJson.object(json, "LinkRequest");
        requireV2(o);
        return new LinkRequest(AvpManifest.key32(o, "ephemeralPublicKey"));
    }

    /**
     * The JSON form of a link request, fields in the SPEC order.
     *
     * @param r the link request
     * @return the JSON tree, for {@link #encode(Map)}
     */
    public static Map<String, Object> toJson(LinkRequest r) {
        Map<String, Object> o = v2();
        o.put("ephemeralPublicKey", AvpEncoding.base64(r.ephemeralPublicKey()));
        return o;
    }

    /**
     * Decodes a link grant from its JSON form.
     *
     * @param json the parsed JSON value
     * @return the link grant
     * @throws AvpException if {@code v} is not 2 or the wrap is missing or malformed
     */
    public static LinkGrant linkGrantFromJson(Object json) throws AvpException {
        Map<String, Object> o = AvpJson.object(json, "LinkGrant");
        requireV2(o);
        return new LinkGrant(AvpManifest.wrappedKeyFromJson(AvpJson.required(o, "wrap")));
    }

    /**
     * The JSON form of a link grant, fields in the SPEC order.
     *
     * @param g the link grant
     * @return the JSON tree, for {@link #encode(Map)}
     */
    public static Map<String, Object> toJson(LinkGrant g) {
        Map<String, Object> o = v2();
        o.put("wrap", AvpManifest.toJson(g.wrap()));
        return o;
    }

    /**
     * The confirmation code of a link request (SPEC 11.6): the first 4 bytes of {@code
     * SHA-256(CE(tag "avp/link-code/v1", bytes(ephemeralPublicKey)))} as {@code u32BE}, modulo 1 000
     * 000, as 6 digits with leading zeros.
     *
     * @param ephemeralPublicKey the new device's ephemeral X25519 public key
     * @return the 6-digit code
     * @throws AvpException never for a well-formed tag; the CE writer is fallible in general
     */
    public static String linkConfirmationCode(byte[] ephemeralPublicKey) throws AvpException {
        byte[] d = AvpCrypto.sha256(
                AvpEncoding.tag("avp/link-code/v1").bytes(ephemeralPublicKey).finish());
        long u32 = ((d[0] & 0xffL) << 24) | ((d[1] & 0xffL) << 16) | ((d[2] & 0xffL) << 8) | (d[3] & 0xffL);
        return String.format("%06d", u32 % 1_000_000L);
    }

    /**
     * Wraps the 32-byte mnemonic entropy to a link request's ephemeral key under {@code
     * avp/owner-link/v1}, with a fresh random ephemeral key and IV.
     *
     * @param entropy the owner's 32-byte mnemonic entropy
     * @param ephemeralPublicKey the link request's ephemeral X25519 public key
     * @return the link grant
     * @throws AvpException if a length is wrong or the agreement fails
     */
    public static LinkGrant sealLinkGrant(byte[] entropy, byte[] ephemeralPublicKey) throws AvpException {
        return sealLinkGrantWith(entropy, ephemeralPublicKey, AvpCrypto.randomBytes(32), AvpCrypto.randomBytes(12));
    }

    /**
     * {@link #sealLinkGrant(byte[], byte[])} with a caller-chosen wrap ephemeral key and IV, for
     * reproducing the vectors. Real grants use {@link #sealLinkGrant(byte[], byte[])}.
     *
     * @param entropy the owner's 32-byte mnemonic entropy
     * @param ephemeralPublicKey the link request's ephemeral X25519 public key
     * @param wrapEphemeralPrivate the wrap's 32-byte ephemeral X25519 scalar
     * @param iv the 12-byte IV
     * @return the link grant
     * @throws AvpException if a length is wrong or the agreement fails
     */
    public static LinkGrant sealLinkGrantWith(
            byte[] entropy, byte[] ephemeralPublicKey, byte[] wrapEphemeralPrivate, byte[] iv) throws AvpException {
        if (entropy.length != 32) {
            throw AvpException.encoding("link grant entropy is 32 bytes");
        }
        return new LinkGrant(
                AvpCrypto.wrapWith(ephemeralPublicKey, entropy, AvpCrypto.OWNER_LINK_INFO, wrapEphemeralPrivate, iv));
    }

    /**
     * Unwraps a link grant with the new device's ephemeral private key under {@code
     * avp/owner-link/v1}. A grant that does not unwrap under that label is rejected (SPEC 11.6).
     *
     * @param grant the link grant
     * @param ephemeralPrivate the new device's 32-byte ephemeral X25519 scalar
     * @return the 32-byte mnemonic entropy
     * @throws AvpException of kind {@link AvpException.Kind#CRYPTO} if the grant does not unwrap, and
     *     of kind {@link AvpException.Kind#BAD_ENCODING} if the secret is not 32 bytes
     */
    public static byte[] openLinkGrant(LinkGrant grant, byte[] ephemeralPrivate) throws AvpException {
        byte[] secret = AvpCrypto.unwrap(ephemeralPrivate, grant.wrap(), AvpCrypto.OWNER_LINK_INFO);
        if (secret.length != 32) {
            throw AvpException.encoding("a link grant secret is 32 bytes");
        }
        return secret;
    }

    // ─── Leave request (SPEC 8.4, 11.4) ───────────────────────────────────────────────

    /**
     * The signed message of a leave request (SPEC 11.4): {@code CE(tag "avp/leave/v1", str(repoId),
     * bytes(memberKey), i64(at))}.
     *
     * @param l the leave request
     * @return the message
     * @throws AvpException never for a well-formed tag; the CE writer is fallible in general
     */
    public static byte[] leaveMessage(LeaveRequest l) throws AvpException {
        return AvpEncoding.tag("avp/leave/v1")
                .str(l.repoId())
                .bytes(l.memberKey())
                .i64(l.at())
                .finish();
    }

    /**
     * Signs a leave request with a member key; its {@code memberKey} is that seed's public key.
     *
     * @param repoId the repository
     * @param at the client's time in epoch milliseconds
     * @param memberSeed the member's 32-byte Ed25519 seed
     * @return the signed leave request
     * @throws AvpException if the seed has the wrong length
     */
    public static LeaveRequest signLeave(String repoId, long at, byte[] memberSeed) throws AvpException {
        byte[] memberKey = AvpCrypto.ed25519Public(memberSeed);
        LeaveRequest unsigned = new LeaveRequest(repoId, memberKey, at, new byte[64]);
        return new LeaveRequest(repoId, memberKey, at, AvpCrypto.ed25519Sign(memberSeed, leaveMessage(unsigned)));
    }

    /**
     * Verifies a leave request's signature under its {@code memberKey} (SPEC 8.4).
     *
     * @param l the leave request
     * @return whether the signature verifies
     */
    public static boolean verifyLeave(LeaveRequest l) {
        try {
            return AvpCrypto.ed25519Verify(l.memberKey(), leaveMessage(l), l.signature());
        } catch (AvpException e) {
            return false;
        }
    }

    /**
     * Decodes a leave request from its JSON body.
     *
     * @param json the parsed JSON value
     * @return the leave request
     * @throws AvpException if a field is missing, has the wrong type, or the key or signature has the
     *     wrong length
     */
    public static LeaveRequest leaveFromJson(Object json) throws AvpException {
        Map<String, Object> o = AvpJson.object(json, "LeaveRequest");
        return new LeaveRequest(
                AvpJson.string(o, "repoId"),
                AvpManifest.key32(o, "memberKey"),
                AvpJson.integer(o, "at"),
                AvpEncoding.fromBase64(AvpJson.string(o, "signature"), 64));
    }

    /**
     * The JSON body of a leave request, fields in the SPEC order.
     *
     * @param l the leave request
     * @return the JSON tree
     */
    public static Map<String, Object> toJson(LeaveRequest l) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("repoId", l.repoId());
        o.put("memberKey", AvpEncoding.base64(l.memberKey()));
        o.put("at", l.at());
        o.put("signature", AvpEncoding.base64(l.signature()));
        return o;
    }

    // ─── Fingerprints and URIs (SPEC 3.2, 11.2) ───────────────────────────────────────

    /**
     * The member key fingerprint (SPEC 3.2): {@code hex(SHA-256(ed25519 || x25519)[0..8])} as {@code
     * xxxx-xxxx-xxxx-xxxx}.
     *
     * @param ed25519Public the member's raw Ed25519 public key
     * @param x25519Public the member's raw X25519 public key
     * @return the fingerprint
     */
    public static String keyFingerprint(byte[] ed25519Public, byte[] x25519Public) {
        String h = AvpEncoding.hex(Arrays.copyOf(AvpCrypto.sha256(AvpCrypto.concat(ed25519Public, x25519Public)), 8));
        return h.substring(0, 4) + "-" + h.substring(4, 8) + "-" + h.substring(8, 12) + "-" + h.substring(12, 16);
    }

    /**
     * The owner fingerprint of a repo locator (SPEC 11.2): {@code hex(SHA-256(ownerKey)[0..8])}.
     *
     * @param ownerKey the owner's raw Ed25519 public key
     * @return 16 hex digits
     */
    public static String ownerFingerprint(byte[] ownerKey) {
        return AvpEncoding.hex(Arrays.copyOf(AvpCrypto.sha256(ownerKey), 8));
    }

    /**
     * Parses {@code avp://<hostLocator>/<repoId>} (SPEC 11.2).
     *
     * @param uri the URI text
     * @return the parsed URI
     * @throws AvpException if the scheme is not {@code avp://}, the locator is empty, or the repoId is
     *     not 22 base64url characters
     */
    public static AvpUri parseUri(String uri) throws AvpException {
        if (!uri.startsWith("avp://")) {
            throw AvpException.encoding("not an avp:// locator");
        }
        String rest = uri.substring("avp://".length());
        int slash = rest.indexOf('/');
        if (slash <= 0) {
            throw AvpException.encoding("not an avp:// locator");
        }
        String host = rest.substring(0, slash);
        String repo = rest.substring(slash + 1);
        if (repo.length() != 22) {
            throw AvpException.encoding("not an avp:// locator");
        }
        for (byte b : repo.getBytes(StandardCharsets.UTF_8)) {
            boolean ok =
                    (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '-' || b == '_';
            if (!ok) {
                throw AvpException.encoding("not an avp:// locator");
            }
        }
        return new AvpUri(host, repo);
    }
}
