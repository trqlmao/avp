/*
 * Conformance vector test harness for the AVP Java crypto implementation.
 *
 * Loads vectors/*.json (7 files) relative to the working directory and runs the same checks as
 * examples/go/avp/crypto_test.go, printing PASS/FAIL per case with an assertion counter. Exits
 * non-zero on any failure.
 *
 * Run from examples/java/client after compiling:
 *
 *     javac Crypto.java CryptoVectors.java Client.java && java CryptoVectors
 *
 * SPDX-License-Identifier: MIT
 */

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Conformance vector test harness: loads {@code vectors/*.json} and runs byte-for-byte checks
 * against the AVP crypto implementation in {@link Crypto}.
 *
 * <p>Mirrors the 7 test cases from {@code examples/go/avp/crypto_test.go}:
 * <ol>
 *   <li>aad.json: AAD bytes match expected hex</li>
 *   <li>key-binding-message.json: binding message string</li>
 *   <li>hkdf.json: HKDF-SHA256 PRK and OKM hex</li>
 *   <li>x25519.json: X25519 agreement output hex</li>
 *   <li>ed25519.json: public key derivation + deterministic signature</li>
 *   <li>payload-aead.json: re-encrypt + decrypt + tamper check</li>
 *   <li>key-wrap.json: recipient pubkey derivation + re-wrap + unwrap</li>
 * </ol>
 */
public final class CryptoVectors {

    /** Resolved at startup relative to the working directory. */
    private static final String VECTORS_DIR = "../../../vectors";

    // DER prefix for Ed25519 SubjectPublicKeyInfo (same as Server.java)
    private static final byte[] ED25519_SPKI_PREFIX = Crypto.hexToBytes("302a300506032b6570032100");

    // DER prefix for Ed25519 PKCS8 private key (seed form, RFC 8032)
    private static final byte[] ED25519_PKCS8_PREFIX = Crypto.hexToBytes("302e020100300506032b657004220420");

    private static int checks = 0;
    private static int failures = 0;

    /** Not instantiable. */
    private CryptoVectors() {}

    /**
     * Runs all vector tests and exits with status 0 on full pass, 1 on any failure.
     *
     * @param args ignored
     */
    public static void main(String[] args) {
        try {
            testAad();
            testKeyBinding();
            testHkdf();
            testX25519();
            testEd25519();
            testPayloadAead();
            testKeyWrap();
        } catch (Exception e) {
            System.err.println("FATAL: " + e);
            e.printStackTrace(System.err);
            System.exit(1);
        }
        System.out.println("\n" + checks + " assertions, " + failures + " failure(s).");
        if (failures > 0) {
            System.exit(1);
        }
        System.out.println("All checks PASSED.");
    }

    // ─── 1. AAD vectors ───────────────────────────────────────────────────────

    private static void testAad() throws Exception {
        System.out.println("=== aad.json ===");
        Map<?, ?> file = (Map<?, ?>) loadVector("aad.json");
        List<?> cases = (List<?>) file.get("cases");
        for (Object c : cases) {
            Map<?, ?> m = (Map<?, ?>) c;
            String repoId = (String) m.get("repoId");
            long pv = asLong(m.get("payloadVersion"));
            long ke = asLong(m.get("keyEpoch"));
            String want = (String) m.get("expectedAadHex");
            byte[] aad = Crypto.buildAad(repoId, pv, ke);
            String got = Crypto.hexEncode(aad);
            check("aad repoId=" + repoId, want, got);
        }
    }

    // ─── 2. Key binding message ───────────────────────────────────────────────

    private static void testKeyBinding() throws Exception {
        System.out.println("=== key-binding-message.json ===");
        Map<?, ?> file = (Map<?, ?>) loadVector("key-binding-message.json");
        List<?> cases = (List<?>) file.get("cases");
        for (Object c : cases) {
            Map<?, ?> m = (Map<?, ?>) c;
            String ed = (String) m.get("ed25519PublicKey");
            String x = (String) m.get("x25519PublicKey");
            String want = (String) m.get("expectedMessageUtf8");
            String got = new String(Crypto.keyBindingMessage(ed, x), StandardCharsets.UTF_8);
            check("key-binding", want, got);
        }
    }

    // ─── 3. HKDF vectors ──────────────────────────────────────────────────────

    private static void testHkdf() throws Exception {
        System.out.println("=== hkdf.json ===");
        Map<?, ?> file = (Map<?, ?>) loadVector("hkdf.json");
        List<?> cases = (List<?>) file.get("cases");
        for (Object c : cases) {
            Map<?, ?> m = (Map<?, ?>) c;
            String name = (String) m.get("name");
            byte[] ikm = Crypto.hexToBytes((String) m.get("ikmHex"));
            byte[] saltRaw = Crypto.hexToBytes((String) m.get("saltHex"));
            byte[] info = Crypto.hexToBytes((String) m.get("infoHex"));
            int length = (int) asLong(m.get("length"));
            String wantPrk = (String) m.get("prkHex");
            String wantOkm = (String) m.get("okmHex");

            // PRK test (uses non-empty salt after empty->zero substitution)
            byte[] salt = (saltRaw.length == 0) ? new byte[32] : saltRaw;
            byte[] prk = Crypto.hkdfExtract(salt, ikm);
            check(name + " PRK", wantPrk, Crypto.hexEncode(prk));

            // OKM test (HKDF-SHA256 handles empty-salt internally)
            byte[] okm = Crypto.hkdfSha256(ikm, saltRaw, info, length);
            check(name + " OKM", wantOkm, Crypto.hexEncode(okm));
        }
    }

    // ─── 4. X25519 vectors ────────────────────────────────────────────────────

    private static void testX25519() throws Exception {
        System.out.println("=== x25519.json ===");
        Map<?, ?> file = (Map<?, ?>) loadVector("x25519.json");
        List<?> cases = (List<?>) file.get("cases");
        for (Object c : cases) {
            Map<?, ?> m = (Map<?, ?>) c;
            String name = (String) m.get("name");
            byte[] scalar = Crypto.hexToBytes((String) m.get("scalarHex"));
            byte[] uCoord = Crypto.hexToBytes((String) m.get("uCoordinateHex"));
            String wantHex = (String) m.get("outputHex");

            PrivateKey priv = Crypto.x25519PrivateFromRaw(scalar);
            PublicKey pub = Crypto.x25519PublicFromRaw(uCoord);
            byte[] shared = Crypto.x25519Agree(priv, pub);
            check(name + " shared", wantHex, Crypto.hexEncode(shared));
        }
    }

    // ─── 5. Ed25519 vectors ───────────────────────────────────────────────────

    private static void testEd25519() throws Exception {
        System.out.println("=== ed25519.json ===");
        Map<?, ?> file = (Map<?, ?>) loadVector("ed25519.json");
        List<?> cases = (List<?>) file.get("cases");
        for (Object c : cases) {
            Map<?, ?> m = (Map<?, ?>) c;
            String name = (String) m.get("name");
            byte[] seed = Crypto.hexToBytes((String) m.get("seedHex"));
            String wantPubHex = (String) m.get("publicKeyHex");
            byte[] msg = Crypto.hexToBytes((String) m.get("messageHex"));
            String wantSigHex = (String) m.get("signatureHex");

            // Build Ed25519 private key from seed (PKCS8 prefix + 32-byte seed)
            byte[] pkcs8 = Crypto.concat(ED25519_PKCS8_PREFIX, seed);
            PrivateKey priv = KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));

            // Derive public key from private key (SPKI, last 32 bytes)
            // In JCE Ed25519, the public key is embedded in the PKCS8 private key structure;
            // we can also just extract it from the signer's generated keypair. The most
            // reliable way: sign with priv, then verify with the expected public key.
            // For derivation: build public key from the seed-derived public key hex.
            byte[] pubRaw = Crypto.hexToBytes(wantPubHex);
            byte[] spki = Crypto.concat(ED25519_SPKI_PREFIX, pubRaw);
            PublicKey pub = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));

            // Re-derive the raw public key from the private key via JCE
            // JCE Ed25519 private key PKCS8 export contains the public key; last 32 bytes of SPKI
            // We sign then verify to check the derivation is correct.
            Signature sigObj = Signature.getInstance("Ed25519");
            sigObj.initSign(priv);
            sigObj.update(msg);
            byte[] sig = sigObj.sign();
            check(name + " sig", wantSigHex, Crypto.hexEncode(sig));

            // Verify the signature with the public key from the expected public key hex
            sigObj = Signature.getInstance("Ed25519");
            sigObj.initVerify(pub);
            sigObj.update(msg);
            boolean valid = sigObj.verify(sig);
            if (!valid) {
                fail(name + " verify: signature did not verify");
            } else {
                pass(name + " verify");
            }
        }
    }

    // ─── 6. Payload AEAD vectors ──────────────────────────────────────────────

    private static void testPayloadAead() throws Exception {
        System.out.println("=== payload-aead.json ===");
        Map<?, ?> file = (Map<?, ?>) loadVector("payload-aead.json");
        List<?> cases = (List<?>) file.get("cases");
        for (Object c : cases) {
            Map<?, ?> m = (Map<?, ?>) c;
            String name = (String) m.get("name");
            byte[] key = Crypto.b64Dec((String) m.get("keyB64"));
            byte[] iv = Crypto.b64Dec((String) m.get("ivB64"));
            String repoId = (String) m.get("repoId");
            long pv = asLong(m.get("payloadVersion"));
            long ke = asLong(m.get("keyEpoch"));
            String wantAadHex = (String) m.get("aadHex");
            String ptUtf8 = (String) m.get("plaintextUtf8");
            String wantCtB64 = (String) m.get("ciphertextB64");
            long tamperEpoch = asLong(m.get("tamperEpoch"));

            // (a) AAD check
            byte[] aad = Crypto.buildAad(repoId, pv, ke);
            check(name + " aad", wantAadHex, Crypto.hexEncode(aad));

            // (b) re-encrypt with committed IV and assert ciphertext
            byte[] ct = Crypto.aesgcmSeal(key, iv, ptUtf8.getBytes(StandardCharsets.UTF_8), aad);
            check(name + " ciphertext", wantCtB64, Crypto.b64Enc(ct));

            // (c) decrypt and recover plaintext
            byte[] recovered = Crypto.aesgcmOpen(key, iv, Crypto.b64Dec(wantCtB64), aad);
            check(name + " plaintext", ptUtf8, new String(recovered, StandardCharsets.UTF_8));

            // (d) tampered epoch must fail
            byte[] tamperedAad = Crypto.buildAad(repoId, pv, tamperEpoch);
            boolean threw = false;
            try {
                Crypto.aesgcmOpen(key, iv, Crypto.b64Dec(wantCtB64), tamperedAad);
            } catch (Exception e) {
                threw = true;
            }
            if (!threw) {
                fail(name + " tamper check: decryption with tampered epoch should have failed");
            } else {
                pass(name + " tamper check");
            }
        }
    }

    // ─── 7. Key wrap vectors ──────────────────────────────────────────────────

    private static void testKeyWrap() throws Exception {
        System.out.println("=== key-wrap.json ===");
        Map<?, ?> file = (Map<?, ?>) loadVector("key-wrap.json");
        List<?> cases = (List<?>) file.get("cases");
        for (Object c : cases) {
            Map<?, ?> m = (Map<?, ?>) c;
            String name = (String) m.get("name");
            byte[] recipPrivRaw = Crypto.b64Dec((String) m.get("recipientPrivateKeyB64"));
            String wantRecipPubB64 = (String) m.get("recipientPublicKeyB64");
            byte[] dataKey = Crypto.b64Dec((String) m.get("dataKeyB64"));
            String wantSharedHex = (String) m.get("sharedSecretHex");
            String wantKekHex = (String) m.get("kekHex");
            String infoStr = (String) m.get("info");

            Map<?, ?> wkMap = (Map<?, ?>) m.get("wrappedKey");
            String wantSchemeId = (String) wkMap.get("schemeId");
            byte[] ephPubRaw = Crypto.b64Dec((String) wkMap.get("ephemeralPublicKey"));
            byte[] wkIv = Crypto.b64Dec((String) wkMap.get("iv"));
            String wantCtB64 = (String) wkMap.get("ciphertext");

            // Build recipient private key from raw scalar
            PrivateKey recipPriv = Crypto.x25519PrivateFromRaw(recipPrivRaw);

            // Derive and check recipient public key: the public key is derived from the private key.
            // In JCE XDH, we cannot directly extract the public key from a PrivateKey object
            // produced via PKCS8EncodedKeySpec. We do a workaround: generate the key pair from the
            // raw private scalar and compare via ECDH test or by comparing the SPKI encoding.
            // The reliable approach: re-wrap using the PKCS8 key and compare public key by
            // doing ECDH with the ephemeral public key and checking the shared secret.
            //
            // For the public key derivation check, we use the following: build a KeyPairGenerator
            // with a deterministic seed is not possible in standard JCA. Instead, we verify
            // by checking that X25519(recipPriv, ephPub) == expected shared secret (which
            // implicitly confirms the private key decodes correctly), and separately confirm
            // that the stored recipientPublicKey in the vector is consistent.
            //
            // The cleanest check: use Crypto.x25519Agree(recipPriv, ephPub) == sharedSecretHex.
            PublicKey ephPub = Crypto.x25519PublicFromRaw(ephPubRaw);

            // Check shared secret
            byte[] shared = Crypto.x25519Agree(recipPriv, ephPub);
            check(name + " shared", wantSharedHex, Crypto.hexEncode(shared));

            // Check KEK
            byte[] kek = Crypto.hkdfSha256(shared, ephPubRaw, infoStr.getBytes(StandardCharsets.UTF_8), 32);
            check(name + " kek", wantKekHex, Crypto.hexEncode(kek));

            // (a) re-encrypt data key with committed IV and assert ciphertext
            byte[] ct = Crypto.aesgcmSeal(kek, wkIv, dataKey, infoStr.getBytes(StandardCharsets.UTF_8));
            check(name + " wrapped ciphertext", wantCtB64, Crypto.b64Enc(ct));

            // (b) unwrap with recipient private key and assert data key recovery
            Map<String, Object> wkFull = new LinkedHashMap<>();
            wkFull.put("schemeId", wantSchemeId);
            wkFull.put("ephemeralPublicKey", Crypto.b64Enc(ephPubRaw));
            wkFull.put("iv", Crypto.b64Enc(wkIv));
            wkFull.put("ciphertext", wantCtB64);
            byte[] recovered = Crypto.unwrapDataKey(recipPriv, wkFull);
            if (!Arrays.equals(recovered, dataKey)) {
                fail(name + " unwrap: recovered data key did not match");
            } else {
                pass(name + " unwrap");
            }

            // (c) verify that recipientPublicKeyB64 and recipientPrivateKeyB64 form a real keypair:
            // wrap a fixed known data key to the vector's public key, then unwrap with the private
            // key, and assert the recovered bytes equal the original. Uses a deterministic 32-byte
            // probe (0x00..0x1F) so the check is repeatable and cannot accidentally pass if the
            // keys are mismatched.
            byte[] knownDataKey = new byte[32];
            for (int i = 0; i < 32; i++) {
                knownDataKey[i] = (byte) i; // 0x00..0x1F
            }
            Map<String, Object> probedWk = Crypto.wrapDataKey(wantRecipPubB64, knownDataKey);
            byte[] recoveredProbe = Crypto.unwrapDataKey(recipPriv, probedWk);
            if (!Arrays.equals(recoveredProbe, knownDataKey)) {
                fail(name + " recipientPublicKey consistency: wrap/unwrap probe did not recover known data key");
            } else {
                pass(name + " recipientPublicKey consistency");
            }
        }
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    /** Loads and parses a vector JSON file. */
    private static Object loadVector(String filename) throws IOException {
        String path = VECTORS_DIR + "/" + filename;
        String text = new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8);
        return Client.Json.parse(text);
    }

    /** Asserts {@code got.equals(want)}, printing PASS or FAIL. */
    private static void check(String label, String want, String got) {
        checks++;
        if (want.equals(got)) {
            System.out.printf("  PASS  %s%n", label);
        } else {
            failures++;
            System.out.printf("  FAIL  %s%n    want: %s%n    got:  %s%n", label, want, got);
        }
    }

    /** Records a successful assertion. */
    private static void pass(String label) {
        checks++;
        System.out.printf("  PASS  %s%n", label);
    }

    /** Records a failed assertion. */
    private static void fail(String label) {
        checks++;
        failures++;
        System.out.printf("  FAIL  %s%n", label);
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
