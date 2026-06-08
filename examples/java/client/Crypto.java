/*
 * AVP cryptographic core for the Java reference client.
 *
 * Implements the real constructions from SPEC §4 and §9 end to end:
 *
 *   - AAD = UTF8(repoId) || 0x1F || int64BE(payloadVersion) || int64BE(keyEpoch)
 *   - HKDF-SHA256 (RFC 5869), hand-rolled from HmacSHA256 (JDK 21 has no JCE HKDF)
 *   - Payload AEAD: AES-256-GCM, 12-byte IV, 128-bit tag appended (JCE NoPadding)
 *   - Key wrap scheme X25519-HKDF-SHA256-AESGCM-v1:
 *       shared = X25519(ephPriv, recipientPub) [raw, unhashed]
 *       kek    = HKDF-SHA256(ikm=shared, salt=ephPubRaw, info="avp/rdk-wrap/v1", L=32)
 *       ct     = AES-256-GCM(kek, iv12, aad="avp/rdk-wrap/v1", plaintext=dataKey)
 *
 * Every construction is checked byte-for-byte against vectors/*.json by CryptoVectors.java.
 *
 * Single file, no dependencies: all crypto via java.security / javax.crypto.
 *
 * SPDX-License-Identifier: MIT
 */

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AVP cryptographic core: HKDF-SHA256, X25519 key wrapping, and AES-256-GCM payload encryption.
 *
 * <p>All methods are static. All byte fields on the wire are standard base64 with padding; helpers
 * {@link #b64Enc(byte[])} and {@link #b64Dec(String)} use {@link Base64#getEncoder()} /
 * {@link Base64#getDecoder()} throughout.
 */
public final class Crypto {

    /** The wrap scheme identifier advertised in every {@code WrappedKey} map. */
    public static final String SCHEME_ID = "X25519-HKDF-SHA256-AESGCM-v1";

    /** HKDF info and AES-GCM AAD for data-key wrapping. */
    private static final String WRAP_INFO = "avp/rdk-wrap/v1";

    /** AES-GCM authentication tag length: 128 bits. */
    private static final int GCM_TAG_BITS = 128;

    /** AES-GCM nonce length: 12 bytes. */
    private static final int IV_BYTES = 12;

    /** X25519 raw key length: 32 bytes. */
    private static final int X25519_KEY_BYTES = 32;

    // DER prefix for X25519 SubjectPublicKeyInfo (SPKI): 302a300506032b656e032100
    private static final byte[] X25519_SPKI_PREFIX = hexToBytes("302a300506032b656e032100");

    // DER prefix for X25519 PKCS8 private key: 302e020100300506032b656e04220420
    private static final byte[] X25519_PKCS8_PREFIX = hexToBytes("302e020100300506032b656e04220420");

    private static final Base64.Encoder B64E = Base64.getEncoder();
    private static final Base64.Decoder B64D = Base64.getDecoder();
    private static final SecureRandom RANDOM = new SecureRandom();

    /** Not instantiable. */
    private Crypto() {}

    // ─── AAD (SPEC §4) ────────────────────────────────────────────────────────

    /**
     * Builds the additional authenticated data for a payload envelope.
     *
     * <pre>AAD = UTF8(repoId) || 0x1F || int64BE(payloadVersion) || int64BE(keyEpoch)</pre>
     *
     * @param repoId the repository identifier
     * @param payloadVersion the payload version counter
     * @param keyEpoch the key epoch counter
     * @return the raw AAD bytes
     */
    public static byte[] buildAad(String repoId, long payloadVersion, long keyEpoch) {
        byte[] idBytes = repoId.getBytes(StandardCharsets.UTF_8);
        byte[] aad = new byte[idBytes.length + 1 + 8 + 8];
        int pos = 0;
        System.arraycopy(idBytes, 0, aad, pos, idBytes.length);
        pos += idBytes.length;
        aad[pos++] = 0x1F;
        writeLongBE(aad, pos, payloadVersion);
        pos += 8;
        writeLongBE(aad, pos, keyEpoch);
        return aad;
    }

    // ─── Key binding (SPEC §9) ────────────────────────────────────────────────

    /**
     * Returns the canonical key-binding message bytes.
     *
     * <pre>bindingMessage = UTF8(ed25519PublicKey + "|" + x25519PublicKey)</pre>
     *
     * @param ed25519PubB64 the raw 32-byte Ed25519 public key, standard base64
     * @param x25519PubB64 the raw 32-byte X25519 public key, standard base64
     * @return the UTF-8 bytes of the concatenated string
     */
    public static byte[] keyBindingMessage(String ed25519PubB64, String x25519PubB64) {
        return (ed25519PubB64 + "|" + x25519PubB64).getBytes(StandardCharsets.UTF_8);
    }

    // ─── HKDF-SHA256 (RFC 5869) ───────────────────────────────────────────────

    /**
     * Derives {@code length} bytes from {@code ikm} using HKDF-SHA256 (RFC 5869). An empty salt
     * is replaced by 32 zero bytes per RFC 5869 §2.2.
     *
     * @param ikm input key material
     * @param salt optional salt (may be empty or zero-length; replaced by zeroes per RFC 5869)
     * @param info context and application specific information
     * @param length desired output length in bytes
     * @return derived key material
     */
    public static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) {
        if (salt == null || salt.length == 0) {
            salt = new byte[32];
        }
        byte[] prk = hkdfExtract(salt, ikm);
        return hkdfExpand(prk, info, length);
    }

    /**
     * HKDF extract step: PRK = HMAC-SHA256(salt, ikm).
     *
     * @param salt the salt (must be non-empty after the empty-salt substitution above)
     * @param ikm the input key material
     * @return the pseudorandom key (PRK)
     */
    static byte[] hkdfExtract(byte[] salt, byte[] ikm) {
        return hmacSha256(salt, ikm);
    }

    /**
     * HKDF expand step: T(i) = HMAC(PRK, T(i-1) || info || i), output = first length bytes.
     *
     * @param prk the pseudorandom key from the extract step
     * @param info context info
     * @param length desired output length in bytes
     * @return derived key material of exactly {@code length} bytes
     */
    static byte[] hkdfExpand(byte[] prk, byte[] info, int length) {
        byte[] result = new byte[length];
        byte[] prev = new byte[0];
        int filled = 0;
        for (int counter = 1; filled < length; counter++) {
            // T(i) = HMAC-SHA256(PRK, T(i-1) || info || counter)
            byte[] data = new byte[prev.length + info.length + 1];
            System.arraycopy(prev, 0, data, 0, prev.length);
            System.arraycopy(info, 0, data, prev.length, info.length);
            data[data.length - 1] = (byte) counter;
            prev = hmacSha256(prk, data);
            int take = Math.min(prev.length, length - filled);
            System.arraycopy(prev, 0, result, filled, take);
            filled += take;
        }
        return result;
    }

    // ─── AES-256-GCM ─────────────────────────────────────────────────────────

    /**
     * AES-256-GCM seal: returns ciphertext with the 16-byte authentication tag appended.
     *
     * @param key 32-byte AES key
     * @param iv 12-byte nonce
     * @param plaintext data to encrypt
     * @param aad additional authenticated data
     * @return ciphertext || tag (GCM output from JCE doFinal)
     */
    public static byte[] aesgcmSeal(byte[] key, byte[] iv, byte[] plaintext, byte[] aad)
            throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
        cipher.updateAAD(aad);
        return cipher.doFinal(plaintext);
    }

    /**
     * AES-256-GCM open: decrypts and verifies tag. Throws on authentication failure.
     *
     * @param key 32-byte AES key
     * @param iv 12-byte nonce
     * @param ciphertextWithTag ciphertext || tag as returned by {@link #aesgcmSeal}
     * @param aad additional authenticated data
     * @return the plaintext
     */
    public static byte[] aesgcmOpen(byte[] key, byte[] iv, byte[] ciphertextWithTag, byte[] aad)
            throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
        cipher.updateAAD(aad);
        return cipher.doFinal(ciphertextWithTag);
    }

    // ─── Payload encrypt/decrypt (SPEC §4) ───────────────────────────────────

    /**
     * AES-256-GCM-encrypts a payload, binding {@code (repoId, payloadVersion, keyEpoch)} into the AAD.
     * A fresh 12-byte IV is generated per call.
     *
     * @param dataKey 32-byte symmetric data key
     * @param repoId the repository identifier
     * @param payloadVersion the payload version counter
     * @param keyEpoch the key epoch counter
     * @param plaintext the plaintext to encrypt
     * @return an {@code EncryptedEnvelope} map ready for JSON serialization
     */
    public static Map<String, Object> encryptPayload(
            byte[] dataKey, String repoId, long payloadVersion, long keyEpoch, byte[] plaintext)
            throws Exception {
        byte[] iv = new byte[IV_BYTES];
        RANDOM.nextBytes(iv);
        byte[] aad = buildAad(repoId, payloadVersion, keyEpoch);
        byte[] ct = aesgcmSeal(dataKey, iv, plaintext, aad);
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("repoId", repoId);
        env.put("payloadVersion", payloadVersion);
        env.put("keyEpoch", keyEpoch);
        env.put("iv", b64Enc(iv));
        env.put("ciphertext", b64Enc(ct));
        return env;
    }

    /**
     * Decrypts a payload envelope, rebuilding the AAD from the envelope's own counters.
     *
     * @param dataKey 32-byte symmetric data key
     * @param envelope an {@code EncryptedEnvelope} map (as parsed from JSON)
     * @return the plaintext bytes
     */
    public static byte[] decryptPayload(byte[] dataKey, Map<?, ?> envelope) throws Exception {
        String repoId = (String) envelope.get("repoId");
        long payloadVersion = asLong(envelope.get("payloadVersion"));
        long keyEpoch = asLong(envelope.get("keyEpoch"));
        byte[] iv = b64Dec((String) envelope.get("iv"));
        byte[] ct = b64Dec((String) envelope.get("ciphertext"));
        byte[] aad = buildAad(repoId, payloadVersion, keyEpoch);
        return aesgcmOpen(dataKey, iv, ct, aad);
    }

    // ─── Key wrap / unwrap (SPEC §4, X25519-HKDF-SHA256-AESGCM-v1) ──────────

    /**
     * Wraps a 32-byte data key to a recipient's X25519 public key.
     *
     * <p>Algorithm: generate ephemeral X25519; shared = X25519(ephPriv, recipientPub) [unhashed];
     * kek = HKDF-SHA256(shared, salt=ephPubRaw, info="avp/rdk-wrap/v1", L=32); ct = AES-256-GCM(kek,
     * iv, aad="avp/rdk-wrap/v1", dataKey).
     *
     * @param recipientX25519PubB64 the recipient's raw 32-byte X25519 public key, standard base64
     * @param dataKey the 32-byte data key to wrap
     * @return a {@code WrappedKey} map ready for JSON serialization
     */
    public static Map<String, Object> wrapDataKey(String recipientX25519PubB64, byte[] dataKey)
            throws Exception {
        // Decode recipient public key
        PublicKey recipientPub = x25519PublicFromRaw(b64Dec(recipientX25519PubB64));

        // Generate ephemeral X25519 keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH");
        kpg.initialize(NamedParameterSpec.X25519);
        KeyPair ephemeralPair = kpg.generateKeyPair();
        byte[] ephPubRaw = x25519PublicToRaw(ephemeralPair.getPublic());

        // X25519 key agreement (raw shared secret, unhashed)
        byte[] shared = x25519Agree(ephemeralPair.getPrivate(), recipientPub);

        // Derive KEK
        byte[] kek = hkdfSha256(shared, ephPubRaw, WRAP_INFO.getBytes(StandardCharsets.UTF_8), 32);

        // Encrypt data key
        byte[] iv = new byte[IV_BYTES];
        RANDOM.nextBytes(iv);
        byte[] ct = aesgcmSeal(kek, iv, dataKey, WRAP_INFO.getBytes(StandardCharsets.UTF_8));

        Map<String, Object> wk = new LinkedHashMap<>();
        wk.put("schemeId", SCHEME_ID);
        wk.put("ephemeralPublicKey", b64Enc(ephPubRaw));
        wk.put("iv", b64Enc(iv));
        wk.put("ciphertext", b64Enc(ct));
        return wk;
    }

    /**
     * Unwraps a data key using the recipient's X25519 private key.
     *
     * @param recipientPriv the recipient's X25519 {@link PrivateKey}
     * @param wrappedKey a {@code WrappedKey} map (as parsed from JSON)
     * @return the recovered 32-byte data key
     */
    public static byte[] unwrapDataKey(PrivateKey recipientPriv, Map<?, ?> wrappedKey)
            throws Exception {
        String schemeId = (String) wrappedKey.get("schemeId");
        if (!SCHEME_ID.equals(schemeId)) {
            throw new IllegalArgumentException("unsupported wrap scheme: " + schemeId);
        }
        byte[] ephPubRaw = b64Dec((String) wrappedKey.get("ephemeralPublicKey"));
        PublicKey ephPub = x25519PublicFromRaw(ephPubRaw);

        // Re-derive shared secret and KEK
        byte[] shared = x25519Agree(recipientPriv, ephPub);
        byte[] kek = hkdfSha256(shared, ephPubRaw, WRAP_INFO.getBytes(StandardCharsets.UTF_8), 32);

        byte[] iv = b64Dec((String) wrappedKey.get("iv"));
        byte[] ct = b64Dec((String) wrappedKey.get("ciphertext"));
        return aesgcmOpen(kek, iv, ct, WRAP_INFO.getBytes(StandardCharsets.UTF_8));
    }

    // ─── X25519 key helpers ───────────────────────────────────────────────────

    /**
     * Generates a fresh X25519 keypair.
     *
     * @return a new X25519 {@link KeyPair}
     */
    public static KeyPair generateX25519KeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH");
        kpg.initialize(NamedParameterSpec.X25519);
        return kpg.generateKeyPair();
    }

    /**
     * Wraps a raw 32-byte X25519 public key into a JCE {@link PublicKey} using the SPKI DER prefix.
     *
     * @param raw32 the raw 32-byte X25519 public key
     * @return the corresponding {@link PublicKey}
     */
    public static PublicKey x25519PublicFromRaw(byte[] raw32) throws Exception {
        byte[] der = concat(X25519_SPKI_PREFIX, raw32);
        return KeyFactory.getInstance("XDH").generatePublic(new X509EncodedKeySpec(der));
    }

    /**
     * Extracts the raw 32-byte X25519 public key from a JCE {@link PublicKey} SPKI encoding.
     *
     * <p>The JCE encodes an X25519 public key in SPKI form; the last 32 bytes are the raw key.
     *
     * @param pub the X25519 {@link PublicKey}
     * @return the raw 32-byte public key
     */
    public static byte[] x25519PublicToRaw(PublicKey pub) {
        byte[] spki = pub.getEncoded();
        return Arrays.copyOfRange(spki, spki.length - X25519_KEY_BYTES, spki.length);
    }

    /**
     * Wraps a raw 32-byte X25519 private scalar into a JCE {@link PrivateKey} using PKCS8 DER.
     *
     * @param raw32 the raw 32-byte X25519 scalar
     * @return the corresponding {@link PrivateKey}
     */
    public static PrivateKey x25519PrivateFromRaw(byte[] raw32) throws Exception {
        byte[] der = concat(X25519_PKCS8_PREFIX, raw32);
        return KeyFactory.getInstance("XDH").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    /**
     * Performs X25519 key agreement and returns the raw 32-byte shared secret (unhashed).
     *
     * @param priv the local private key
     * @param pub the remote public key
     * @return the 32-byte raw shared secret
     */
    public static byte[] x25519Agree(PrivateKey priv, PublicKey pub) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("XDH");
        ka.init(priv);
        ka.doPhase(pub, true);
        return ka.generateSecret();
    }

    // ─── Small helpers ────────────────────────────────────────────────────────

    /** Standard base64-encodes {@code b}. */
    public static String b64Enc(byte[] b) {
        return B64E.encodeToString(b);
    }

    /** Standard base64-decodes {@code s}. */
    public static byte[] b64Dec(String s) {
        return B64D.decode(s);
    }

    /**
     * Decodes a lowercase hex string into bytes.
     *
     * @param hex an even-length string of hex digits
     * @return the decoded bytes
     */
    public static byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    /**
     * Encodes bytes as lowercase hex.
     *
     * @param b the bytes to encode
     * @return the hex string
     */
    public static String hexEncode(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(String.format("%02x", x & 0xFF));
        }
        return sb.toString();
    }

    /** Concatenates two byte arrays. */
    static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    /** Computes HMAC-SHA256(key, data). */
    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("HmacSHA256 unavailable", e);
        }
    }

    /** Writes a signed 64-bit value as big-endian into {@code buf} at {@code offset}. */
    private static void writeLongBE(byte[] buf, int offset, long value) {
        for (int i = 7; i >= 0; i--) {
            buf[offset + i] = (byte) (value & 0xFF);
            value >>= 8;
        }
    }

    /** Coerces a parsed JSON value to {@code long}. */
    private static long asLong(Object o) {
        if (o instanceof Number n) {
            return n.longValue();
        }
        if (o instanceof String s) {
            return Long.parseLong(s);
        }
        throw new IllegalArgumentException("expected a number, got " + o);
    }
}
