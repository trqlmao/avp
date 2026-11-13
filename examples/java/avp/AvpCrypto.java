/*
 * Cryptographic primitives of AVP over the JDK's JCA providers (SPEC 2, 4.4).
 *
 * Ported from the vector-verified 0.4 reference client (Crypto.java): the same HKDF, AES-256-GCM,
 * and X25519 with the same SPKI/PKCS8 prefixes, plus Ed25519 from a raw seed and the wrap scheme
 * with its info label.
 *
 * SPDX-License-Identifier: MIT
 */

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.EdECPrivateKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * SHA-256, HKDF-SHA256, AES-256-GCM, X25519, Ed25519, and the default wrap scheme {@code
 * X25519-HKDF-SHA256-AESGCM-v1} (SPEC 4.4), all over raw byte encodings.
 *
 * <p>Keys are raw: a 32-byte X25519 scalar or u-coordinate (RFC 7748), a 32-byte Ed25519 seed or
 * public key and a 64-byte signature (RFC 8032), and a 32-byte AES key. Every failure on input is an
 * {@link AvpException}; {@link #ed25519Verify(byte[], byte[], byte[])} answers {@code false}
 * instead. A missing mandatory JDK algorithm is an environment fault and is reported as {@link
 * IllegalStateException}.
 */
public final class AvpCrypto {

    /** The only wrap scheme id of 0.5 (SPEC 4.4). */
    public static final String SCHEME_ID = "X25519-HKDF-SHA256-AESGCM-v1";

    /** The HKDF info and GCM AAD label of the data key wrap (SPEC 4.4). */
    public static final String WRAP_INFO = "avp/rdk-wrap/v1";

    /** The HKDF info and GCM AAD label of a device link grant (SPEC 11.6). */
    public static final String OWNER_LINK_INFO = "avp/owner-link/v1";

    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_TAG_BYTES = 16;
    private static final int HASH_LEN = 32;

    // DER prefixes of the raw keys (RFC 8410): X25519 and Ed25519 SubjectPublicKeyInfo and PKCS8.
    private static final byte[] X25519_SPKI_PREFIX = hexConstant("302a300506032b656e032100");
    private static final byte[] X25519_PKCS8_PREFIX = hexConstant("302e020100300506032b656e04220420");
    private static final byte[] ED25519_SPKI_PREFIX = hexConstant("302a300506032b6570032100");
    private static final byte[] ED25519_PKCS8_PREFIX = hexConstant("302e020100300506032b657004220420");

    /** The field prime of edwards25519, {@code 2^255 - 19}. */
    private static final BigInteger ED25519_P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));

    /** The prime order of the edwards25519 base point. */
    private static final BigInteger ED25519_L =
            BigInteger.ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));

    /**
     * The libsodium {@code has_small_order} blocklist: with the sign bit cleared, the eight small-order
     * points have five encodings ({@code y} = 0, 1, the two order-8 values, and {@code p - 1}), followed
     * by the non-canonical encodings {@code p} and {@code p + 1} of {@code y} = 0 and 1.
     */
    private static final byte[][] ED25519_SMALL_ORDER = {
        hexConstant("0000000000000000000000000000000000000000000000000000000000000000"),
        hexConstant("0100000000000000000000000000000000000000000000000000000000000000"),
        hexConstant("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
        hexConstant("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
        hexConstant("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hexConstant("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        hexConstant("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
    };

    /** The X25519 base point u = 9 (RFC 7748 4.1). */
    private static final byte[] X25519_BASE = basePoint();

    private static final SecureRandom RANDOM = new SecureRandom();

    private AvpCrypto() {}

    // ─── Hashes and HKDF ──────────────────────────────────────────────────────────────

    /**
     * SHA-256 (FIPS 180-4).
     *
     * @param data the input
     * @return the 32-byte digest
     */
    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is missing from this JDK", e);
        }
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 is missing from this JDK", e);
        }
    }

    /**
     * The HKDF-SHA256 extract step (RFC 5869 2.2): {@code PRK = HMAC-SHA256(salt, ikm)}, where an
     * empty salt is 32 zero bytes.
     *
     * @param salt the salt, possibly empty
     * @param ikm the input key material
     * @return the 32-byte pseudorandom key
     */
    public static byte[] hkdfExtract(byte[] salt, byte[] ikm) {
        return hmacSha256(salt.length == 0 ? new byte[HASH_LEN] : salt, ikm);
    }

    /**
     * HKDF-SHA256 (RFC 5869): extract with {@code salt}, then expand to {@code len} bytes with {@code
     * info}.
     *
     * @param ikm the input key material
     * @param salt the salt; empty means 32 zero bytes
     * @param info the context label
     * @param len the output length, at most 255 * 32
     * @return the output key material
     * @throws AvpException if {@code len} is negative or above the RFC 5869 limit
     */
    public static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int len) throws AvpException {
        if (len < 0 || len > 255 * HASH_LEN) {
            throw new AvpException(AvpException.Kind.CRYPTO, "HKDF output length out of range");
        }
        byte[] prk = hkdfExtract(salt, ikm);
        byte[] out = new byte[len];
        byte[] prev = new byte[0];
        int filled = 0;
        for (int counter = 1; filled < len; counter++) {
            byte[] block = new byte[prev.length + info.length + 1];
            System.arraycopy(prev, 0, block, 0, prev.length);
            System.arraycopy(info, 0, block, prev.length, info.length);
            block[block.length - 1] = (byte) counter;
            prev = hmacSha256(prk, block);
            int take = Math.min(prev.length, len - filled);
            System.arraycopy(prev, 0, out, filled, take);
            filled += take;
        }
        return out;
    }

    // ─── AES-256-GCM ──────────────────────────────────────────────────────────────────

    /**
     * AES-256-GCM encryption with a 12-byte IV; the 16-byte tag is appended to the ciphertext.
     *
     * @param key the 32-byte key
     * @param iv the 12-byte IV, never reused under one key
     * @param plaintext the plaintext
     * @param aad the additional authenticated data
     * @return {@code ciphertext || tag}
     * @throws AvpException if the key or IV has the wrong length or the cipher fails
     */
    public static byte[] aesGcmSeal(byte[] key, byte[] iv, byte[] plaintext, byte[] aad) throws AvpException {
        return gcm(Cipher.ENCRYPT_MODE, key, iv, plaintext, aad);
    }

    /**
     * AES-256-GCM decryption of {@code ciphertext || tag}.
     *
     * @param key the 32-byte key
     * @param iv the 12-byte IV
     * @param ciphertext the ciphertext with the 16-byte tag appended
     * @param aad the additional authenticated data
     * @return the plaintext
     * @throws AvpException of kind {@link AvpException.Kind#CRYPTO} if the tag does not authenticate
     *     (wrong key, wrong AAD, tampered or truncated bytes)
     */
    public static byte[] aesGcmOpen(byte[] key, byte[] iv, byte[] ciphertext, byte[] aad) throws AvpException {
        if (ciphertext.length < GCM_TAG_BYTES) {
            throw new AvpException(AvpException.Kind.CRYPTO, "ciphertext shorter than the GCM tag");
        }
        return gcm(Cipher.DECRYPT_MODE, key, iv, ciphertext, aad);
    }

    private static byte[] gcm(int mode, byte[] key, byte[] iv, byte[] input, byte[] aad) throws AvpException {
        if (key.length != 32 || iv.length != 12) {
            throw new AvpException(AvpException.Kind.CRYPTO, "AES-256-GCM needs a 32-byte key and a 12-byte IV");
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
            cipher.updateAAD(aad);
            return cipher.doFinal(input);
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new AvpException(AvpException.Kind.CRYPTO, "AES-256-GCM failed", e);
        }
    }

    // ─── X25519 ───────────────────────────────────────────────────────────────────────

    /**
     * X25519 (RFC 7748): the raw, unhashed shared secret of a scalar and a peer's u-coordinate. The
     * scalar is clamped as RFC 7748 specifies.
     *
     * @param scalar the 32-byte private scalar
     * @param u the peer's 32-byte u-coordinate
     * @return the 32-byte shared secret
     * @throws AvpException of kind {@link AvpException.Kind#CRYPTO} if an input has the wrong length
     *     or the agreement fails (for example a small-order point, whose output is all zero)
     */
    public static byte[] x25519(byte[] scalar, byte[] u) throws AvpException {
        if (scalar.length != 32 || u.length != 32) {
            throw new AvpException(AvpException.Kind.CRYPTO, "X25519 needs 32-byte inputs");
        }
        try {
            KeyFactory kf = KeyFactory.getInstance("XDH");
            PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(concat(X25519_PKCS8_PREFIX, scalar)));
            PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(concat(X25519_SPKI_PREFIX, u)));
            KeyAgreement ka = KeyAgreement.getInstance("XDH");
            ka.init(priv);
            ka.doPhase(pub, true);
            return ka.generateSecret();
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new AvpException(AvpException.Kind.CRYPTO, "X25519 failed", e);
        }
    }

    /**
     * The raw X25519 public key of a private scalar: {@code X25519(scalar, 9)}.
     *
     * @param scalar the 32-byte private scalar
     * @return the 32-byte public key
     * @throws AvpException if the scalar has the wrong length
     */
    public static byte[] x25519Public(byte[] scalar) throws AvpException {
        return x25519(scalar, X25519_BASE);
    }

    // ─── Ed25519 ──────────────────────────────────────────────────────────────────────

    /**
     * The raw Ed25519 public key of a 32-byte RFC 8032 seed.
     *
     * <p>The JCA has no direct seed-to-public call, so this runs the Ed25519 key pair generator with a
     * random source that yields exactly the seed (the generator draws the 32-byte private key from it,
     * then derives the public key) and checks that the generated private key is the seed.
     *
     * @param seed the 32-byte seed
     * @return the 32-byte public key
     * @throws AvpException of kind {@link AvpException.Kind#CRYPTO} if the seed has the wrong length
     *     or the derivation fails
     */
    public static byte[] ed25519Public(byte[] seed) throws AvpException {
        if (seed.length != 32) {
            throw new AvpException(AvpException.Kind.CRYPTO, "an Ed25519 seed is 32 bytes");
        }
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
            kpg.initialize(NamedParameterSpec.ED25519, new SeedRandom(seed));
            KeyPair kp = kpg.generateKeyPair();
            byte[] priv = ((EdECPrivateKey) kp.getPrivate()).getBytes().orElse(new byte[0]);
            if (!MessageDigest.isEqual(priv, seed)) {
                throw new AvpException(AvpException.Kind.CRYPTO, "the Ed25519 generator did not use the seed");
            }
            byte[] spki = kp.getPublic().getEncoded();
            return Arrays.copyOfRange(spki, spki.length - 32, spki.length);
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new AvpException(AvpException.Kind.CRYPTO, "Ed25519 key derivation failed", e);
        }
    }

    /**
     * Signs a message with Ed25519 (RFC 8032, deterministic).
     *
     * @param seed the signer's 32-byte seed
     * @param message the message
     * @return the 64-byte signature
     * @throws AvpException of kind {@link AvpException.Kind#CRYPTO} if the seed has the wrong length
     *     or signing fails
     */
    public static byte[] ed25519Sign(byte[] seed, byte[] message) throws AvpException {
        if (seed.length != 32) {
            throw new AvpException(AvpException.Kind.CRYPTO, "an Ed25519 seed is 32 bytes");
        }
        try {
            PrivateKey priv = KeyFactory.getInstance("Ed25519")
                    .generatePrivate(new PKCS8EncodedKeySpec(concat(ED25519_PKCS8_PREFIX, seed)));
            Signature sig = Signature.getInstance("Ed25519");
            sig.initSign(priv);
            sig.update(message);
            return sig.sign();
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new AvpException(AvpException.Kind.CRYPTO, "Ed25519 signing failed", e);
        }
    }

    /**
     * Verifies an Ed25519 signature strictly (SPEC 2): the pre-checks of {@link
     * #ed25519StrictInputsOk(byte[], byte[])}, then RFC 8032 verification. The JDK's own verification is
     * cofactorless and makes none of the pre-checks, so without them it accepts forgeries under a
     * small-order key that has no private key.
     *
     * @param publicKey the 32-byte public key
     * @param message the message
     * @param signature the 64-byte signature
     * @return {@code true} only if the inputs pass the strict pre-checks, the key decodes, and the
     *     signature verifies; never throws
     */
    public static boolean ed25519Verify(byte[] publicKey, byte[] message, byte[] signature) {
        if (!ed25519StrictInputsOk(publicKey, signature)) {
            return false;
        }
        try {
            PublicKey pub = KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(concat(ED25519_SPKI_PREFIX, publicKey)));
            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(pub);
            sig.update(message);
            return sig.verify(signature);
        } catch (GeneralSecurityException | RuntimeException e) {
            // A key that is not a valid point, or a malformed signature, does not verify.
            return false;
        }
    }

    /**
     * The strict pre-checks of SPEC 2 on a raw Ed25519 public key and signature: neither the key nor
     * {@code R} (the first 32 signature bytes) is the encoding of a small-order point or a
     * non-canonical encoding ({@code y >= p}), and {@code S} (the last 32 bytes, little-endian) is
     * below the group order {@code L}.
     *
     * @param publicKey the public key
     * @param signature the signature
     * @return whether the lengths are 32 and 64 and every pre-check passes
     */
    public static boolean ed25519StrictInputsOk(byte[] publicKey, byte[] signature) {
        if (publicKey.length != 32 || signature.length != 64) {
            return false;
        }
        byte[] r = Arrays.copyOfRange(signature, 0, 32);
        if (isSmallOrder(publicKey) || !isCanonicalPoint(publicKey) || isSmallOrder(r) || !isCanonicalPoint(r)) {
            return false;
        }
        return littleEndian(Arrays.copyOfRange(signature, 32, 64)).compareTo(ED25519_L) < 0;
    }

    /** Whether a 32-byte point encoding is on the libsodium small-order blocklist, ignoring the sign bit. */
    private static boolean isSmallOrder(byte[] p) {
        for (byte[] e : ED25519_SMALL_ORDER) {
            int diff = ((p[31] & 0x7f) ^ e[31]);
            for (int k = 0; k < 31; k++) {
                diff |= p[k] ^ e[k];
            }
            if (diff == 0) {
                return true;
            }
        }
        return false;
    }

    /** Whether a 32-byte point encoding is canonical: its {@code y} field, sign bit cleared, is below p. */
    private static boolean isCanonicalPoint(byte[] p) {
        byte[] y = p.clone();
        y[31] &= 0x7f;
        return littleEndian(y).compareTo(ED25519_P) < 0;
    }

    private static BigInteger littleEndian(byte[] b) {
        byte[] be = new byte[b.length];
        for (int k = 0; k < b.length; k++) {
            be[k] = b[b.length - 1 - k];
        }
        return new BigInteger(1, be);
    }

    // ─── Wrap scheme (SPEC 4.4) ───────────────────────────────────────────────────────

    /**
     * Wraps a secret to a recipient's X25519 key with the default scheme, using a fresh random
     * ephemeral key and IV.
     *
     * @param recipientPublic the recipient's 32-byte X25519 public key
     * @param secret the secret, for example a 32-byte data key
     * @param info the label, {@link #WRAP_INFO} or {@link #OWNER_LINK_INFO}
     * @return the wrapped key
     * @throws AvpException if a key has the wrong length or the agreement fails
     */
    public static AvpManifest.WrappedKey wrap(byte[] recipientPublic, byte[] secret, String info) throws AvpException {
        return wrapWith(recipientPublic, secret, info, randomBytes(32), randomBytes(12));
    }

    /**
     * {@link #wrap(byte[], byte[], String)} with a caller-chosen ephemeral key and IV, for reproducing
     * the vectors. Real wraps MUST use a fresh random ephemeral key and IV each time.
     *
     * @param recipientPublic the recipient's 32-byte X25519 public key
     * @param secret the secret
     * @param info the label
     * @param ephemeralPrivate the 32-byte ephemeral X25519 scalar
     * @param iv the 12-byte IV
     * @return the wrapped key
     * @throws AvpException if a key has the wrong length or the agreement fails
     */
    public static AvpManifest.WrappedKey wrapWith(
            byte[] recipientPublic, byte[] secret, String info, byte[] ephemeralPrivate, byte[] iv)
            throws AvpException {
        byte[] label = info.getBytes(StandardCharsets.UTF_8);
        byte[] ephemeralPublic = x25519Public(ephemeralPrivate);
        byte[] shared = x25519(ephemeralPrivate, recipientPublic);
        byte[] kek = hkdf(shared, ephemeralPublic, label, 32);
        byte[] ciphertext = aesGcmSeal(kek, iv, secret, label);
        return new AvpManifest.WrappedKey(SCHEME_ID, ephemeralPublic, iv, ciphertext);
    }

    /**
     * Unwraps a wrapped key with the recipient's X25519 private key under a label. A wrap made under
     * one label fails under the other (SPEC 4.4).
     *
     * @param recipientPrivate the recipient's 32-byte X25519 scalar
     * @param wrapped the wrapped key
     * @param info the label
     * @return the secret
     * @throws AvpException of kind {@link AvpException.Kind#BAD_ENCODING} for an unknown scheme id, and
     *     of kind {@link AvpException.Kind#CRYPTO} if the wrap does not authenticate (wrong key, wrong
     *     label, or tampered bytes)
     */
    public static byte[] unwrap(byte[] recipientPrivate, AvpManifest.WrappedKey wrapped, String info)
            throws AvpException {
        if (!SCHEME_ID.equals(wrapped.schemeId())) {
            throw AvpException.encoding("unsupported wrap scheme");
        }
        byte[] label = info.getBytes(StandardCharsets.UTF_8);
        byte[] shared = x25519(recipientPrivate, wrapped.ephemeralPublicKey());
        byte[] kek = hkdf(shared, wrapped.ephemeralPublicKey(), label, 32);
        return aesGcmOpen(kek, wrapped.iv(), wrapped.ciphertext(), label);
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────────────

    /**
     * Bytes from the JDK's cryptographically secure RNG.
     *
     * @param n the count
     * @return {@code n} random bytes
     */
    public static byte[] randomBytes(int n) {
        byte[] out = new byte[n];
        RANDOM.nextBytes(out);
        return out;
    }

    /**
     * Compares two byte strings in constant time for equal lengths ({@link MessageDigest#isEqual}).
     *
     * @param a the first byte string
     * @param b the second byte string
     * @return whether they are equal
     */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static byte[] hexConstant(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int k = 0; k < out.length; k++) {
            out[k] = (byte) Integer.parseInt(hex.substring(2 * k, 2 * k + 2), 16);
        }
        return out;
    }

    private static byte[] basePoint() {
        byte[] u = new byte[32];
        u[0] = 9;
        return u;
    }

    /** A random source that yields one fixed 32-byte seed once, for {@link #ed25519Public(byte[])}. */
    private static final class SeedRandom extends SecureRandom {
        private static final long serialVersionUID = 1L;
        private final byte[] seed;
        private boolean used;

        SeedRandom(byte[] seed) {
            this.seed = seed.clone();
        }

        @Override
        public synchronized void nextBytes(byte[] bytes) {
            if (used || bytes.length != seed.length) {
                throw new IllegalStateException("the seed source serves one 32-byte draw");
            }
            used = true;
            System.arraycopy(seed, 0, bytes, 0, seed.length);
        }
    }
}
