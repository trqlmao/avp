/*
 * The BIP39 owner identity (SPEC 3.1).
 *
 * SPDX-License-Identifier: MIT
 */

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.text.Normalizer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * The BIP39 owner identity (SPEC 3.1): 256-bit entropy to a 24-word English mnemonic and back, the
 * PBKDF2 seed, and the owner Ed25519 and X25519 keys derived from it with HKDF-SHA256.
 *
 * <p>The English wordlist is read once from the path in the system property {@code avp.wordlist}
 * (default {@code ../../../vectors/bip39-english.txt}, the repository copy as seen from {@code
 * examples/java/avp}) and must match the SHA-256 the vectors pin, so a changed list can never change
 * an owner identity silently.
 */
public final class AvpOwner {

    /** HKDF info label of the owner Ed25519 signing seed (SPEC 3.1). */
    public static final String OWNER_ED25519_INFO = "avp/owner/ed25519/v1";

    /** HKDF info label of the owner X25519 private key (SPEC 3.1). */
    public static final String OWNER_X25519_INFO = "avp/owner/x25519/v1";

    /** SHA-256 of the upstream BIP39 English wordlist file (vectors/bip39-english.txt). */
    private static final String WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";

    /** AVP mnemonics are always 24 words over 32 bytes of entropy (SPEC 3.1). */
    private static final int WORD_COUNT = 24;

    private static volatile Words words;

    private AvpOwner() {}

    /**
     * The owner keys derived from a BIP39 seed (SPEC 3.1). {@link #toString()} shows only the public
     * keys.
     *
     * @param ed25519Seed the 32-byte RFC 8032 seed of the owner signing key
     * @param ed25519Public the 32-byte {@code ownerKey}
     * @param x25519Private the 32-byte owner X25519 private key (clamped by the X25519 function)
     * @param x25519Public the 32-byte owner X25519 public key
     */
    public record OwnerKeys(byte[] ed25519Seed, byte[] ed25519Public, byte[] x25519Private, byte[] x25519Public) {
        /** Copies the keys. */
        public OwnerKeys {
            ed25519Seed = ed25519Seed.clone();
            ed25519Public = ed25519Public.clone();
            x25519Private = x25519Private.clone();
            x25519Public = x25519Public.clone();
        }

        /**
         * The public keys only; the private keys are never printed.
         *
         * @return a description with the base64 public keys
         */
        @Override
        public String toString() {
            return "OwnerKeys[ed25519Public=" + AvpEncoding.base64(ed25519Public) + ", x25519Public="
                    + AvpEncoding.base64(x25519Public) + "]";
        }
    }

    /** The wordlist and its reverse index. */
    private record Words(List<String> list, Map<String, Integer> index) {}

    private static Words words() throws AvpException {
        Words w = words;
        if (w != null) {
            return w;
        }
        synchronized (AvpOwner.class) {
            if (words == null) {
                words = loadWords();
            }
            return words;
        }
    }

    private static Words loadWords() throws AvpException {
        Path path = Path.of(System.getProperty("avp.wordlist", "../../../vectors/bip39-english.txt"));
        byte[] raw;
        try {
            raw = Files.readAllBytes(path);
        } catch (IOException e) {
            throw new AvpException(AvpException.Kind.BAD_ENCODING, "cannot read the BIP39 wordlist " + path, e);
        }
        if (!AvpEncoding.hex(AvpCrypto.sha256(raw)).equals(WORDLIST_SHA256)) {
            throw AvpException.encoding("the BIP39 wordlist does not match the pinned SHA-256");
        }
        String text = new String(raw, StandardCharsets.UTF_8);
        List<String> list = List.of(text.substring(0, text.length() - 1).split("\n", -1));
        if (list.size() != 2048) {
            throw AvpException.encoding("the BIP39 wordlist does not hold 2048 words");
        }
        Map<String, Integer> index = new HashMap<>();
        for (int k = 0; k < list.size(); k++) {
            index.put(list.get(k), k);
        }
        return new Words(list, Map.copyOf(index));
    }

    /**
     * Encodes 32 bytes of entropy as a 24-word BIP39 mnemonic (SPEC 3.1): the first 8 bits of {@code
     * SHA-256(entropy)} are appended as a checksum, the 264 bits are split into 24 groups of 11 bits,
     * most significant first, and each group indexes the English wordlist. Words are joined by one
     * space.
     *
     * @param entropy the 32 bytes of entropy
     * @return the mnemonic
     * @throws AvpException if the entropy is not 32 bytes or the wordlist cannot be loaded
     */
    public static String entropyToMnemonic(byte[] entropy) throws AvpException {
        if (entropy.length != 32) {
            throw AvpException.encoding("AVP entropy is 32 bytes");
        }
        byte[] bits = Arrays.copyOf(entropy, 33);
        bits[32] = AvpCrypto.sha256(entropy)[0];
        List<String> list = words().list();
        StringBuilder out = new StringBuilder();
        for (int w = 0; w < WORD_COUNT; w++) {
            int idx = 0;
            for (int b = 0; b < 11; b++) {
                int bit = w * 11 + b;
                idx = (idx << 1) | ((bits[bit / 8] >> (7 - bit % 8)) & 1);
            }
            if (w > 0) {
                out.append(' ');
            }
            out.append(list.get(idx));
        }
        return out.toString();
    }

    /**
     * Decodes a 24-word BIP39 mnemonic back to its 32 bytes of entropy (SPEC 3.1). The phrase is
     * NFKD-normalized and split on single spaces.
     *
     * @param mnemonic the phrase
     * @return the 32 bytes of entropy
     * @throws AvpException of kind {@link AvpException.Kind#BAD_ENCODING} if the phrase is not exactly
     *     24 words or holds a word that is not in the list (an empty word from a doubled space
     *     included), and of kind {@link AvpException.Kind#BAD_CHECKSUM} if the checksum does not match
     */
    public static byte[] mnemonicToEntropy(String mnemonic) throws AvpException {
        String[] parts = Normalizer.normalize(mnemonic, Normalizer.Form.NFKD).split(" ", -1);
        if (parts.length != WORD_COUNT) {
            throw AvpException.encoding("a mnemonic must be exactly 24 words, got " + parts.length);
        }
        Map<String, Integer> index = words().index();
        byte[] bits = new byte[33];
        for (int w = 0; w < WORD_COUNT; w++) {
            Integer idx = index.get(parts[w]);
            if (idx == null) {
                throw AvpException.encoding("the mnemonic has an unknown word at position " + (w + 1));
            }
            for (int b = 0; b < 11; b++) {
                if (((idx >> (10 - b)) & 1) == 1) {
                    int bit = w * 11 + b;
                    bits[bit / 8] |= (byte) (0x80 >> (bit % 8));
                }
            }
        }
        byte[] entropy = Arrays.copyOf(bits, 32);
        byte[] want = {AvpCrypto.sha256(entropy)[0]};
        if (!MessageDigest.isEqual(want, new byte[] {bits[32]})) {
            throw new AvpException(AvpException.Kind.BAD_CHECKSUM, "the mnemonic checksum does not match");
        }
        return entropy;
    }

    /**
     * The BIP39 seed (SPEC 3.1): {@code PBKDF2-HMAC-SHA512(NFKD(mnemonic), "mnemonic" ||
     * NFKD(passphrase), 2048, 64)}. AVP uses an empty passphrase; the parameter exists for the
     * reference vectors.
     *
     * @param mnemonic the phrase
     * @param passphrase the BIP39 passphrase, empty for AVP
     * @return the 64-byte seed
     * @throws AvpException if the mnemonic is empty or PBKDF2 fails
     */
    public static byte[] mnemonicToSeed(String mnemonic, String passphrase) throws AvpException {
        char[] password = Normalizer.normalize(mnemonic, Normalizer.Form.NFKD).toCharArray();
        byte[] salt =
                ("mnemonic" + Normalizer.normalize(passphrase, Normalizer.Form.NFKD)).getBytes(StandardCharsets.UTF_8);
        if (password.length == 0) {
            throw AvpException.encoding("an empty mnemonic has no seed");
        }
        PBEKeySpec spec = new PBEKeySpec(password, salt, 2048, 512);
        try {
            // The JCA PBKDF2 encodes the char[] password as UTF-8; an English NFKD mnemonic is ASCII.
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512")
                    .generateSecret(spec)
                    .getEncoded();
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new AvpException(AvpException.Kind.CRYPTO, "PBKDF2 failed", e);
        } finally {
            spec.clearPassword();
            Arrays.fill(password, '\0');
        }
    }

    /**
     * Derives the owner keys from a 64-byte BIP39 seed, each as {@code HKDF-SHA256(ikm = seed, salt =
     * empty, info = label, L = 32)} (SPEC 3.1).
     *
     * @param seed the 64-byte seed
     * @return the owner keys
     * @throws AvpException if the seed is not 64 bytes
     */
    public static OwnerKeys fromSeed(byte[] seed) throws AvpException {
        if (seed.length != 64) {
            throw AvpException.encoding("a BIP39 seed is 64 bytes");
        }
        byte[] ed = AvpCrypto.hkdf(seed, new byte[0], OWNER_ED25519_INFO.getBytes(StandardCharsets.UTF_8), 32);
        byte[] x = AvpCrypto.hkdf(seed, new byte[0], OWNER_X25519_INFO.getBytes(StandardCharsets.UTF_8), 32);
        return new OwnerKeys(ed, AvpCrypto.ed25519Public(ed), x, AvpCrypto.x25519Public(x));
    }

    /**
     * Derives the owner keys from the mnemonic entropy: the mnemonic, its empty-passphrase seed, then
     * {@link #fromSeed(byte[])}.
     *
     * @param entropy the 32 bytes of entropy
     * @return the owner keys
     * @throws AvpException if the entropy is not 32 bytes
     */
    public static OwnerKeys fromEntropy(byte[] entropy) throws AvpException {
        return fromSeed(mnemonicToSeed(entropyToMnemonic(entropy), ""));
    }
}
