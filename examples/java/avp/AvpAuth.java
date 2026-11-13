/*
 * The challenge transcript of host-issued authentication (SPEC 3.3).
 *
 * SPDX-License-Identifier: MIT
 */

/**
 * The challenge transcript (SPEC 3.3).
 *
 * <p>A client never signs the host-chosen nonce as given. It signs {@code CE(tag "avp/challenge/v1",
 * bytes(hostKey), bytes(ed25519PublicKey), bytes(nonce))}, whose tag keeps the message apart from
 * every other signed construction (SPEC 4.1) and whose {@code hostKey} binds the signature to the host
 * being authenticated to.
 */
public final class AvpAuth {

    /** The CE label of the challenge transcript (SPEC 3.3, 4.1). */
    public static final String CHALLENGE_TAG = "avp/challenge/v1";

    private AvpAuth() {}

    /**
     * The message a client signs to redeem a challenge (SPEC 3.3): {@code CE(tag "avp/challenge/v1",
     * bytes(hostKey), bytes(ed25519PublicKey), bytes(nonce))}.
     *
     * @param hostKey the 32-byte host key of the host being authenticated to
     * @param ed25519PublicKey the 32-byte key requesting the token
     * @param nonce the raw (base64-decoded) nonce bytes
     * @return the message
     * @throws AvpException if a key is not 32 bytes
     */
    public static byte[] challengeMessage(byte[] hostKey, byte[] ed25519PublicKey, byte[] nonce) throws AvpException {
        if (hostKey == null || hostKey.length != 32) {
            throw AvpException.encoding("hostKey must be 32 bytes");
        }
        if (ed25519PublicKey == null || ed25519PublicKey.length != 32) {
            throw AvpException.encoding("ed25519PublicKey must be 32 bytes");
        }
        if (nonce == null) {
            throw AvpException.encoding("nonce is missing");
        }
        return AvpEncoding.tag(CHALLENGE_TAG)
                .bytes(hostKey)
                .bytes(ed25519PublicKey)
                .bytes(nonce)
                .finish();
    }

    /**
     * Signs the challenge transcript for the key of {@code seed} and the host {@code hostKey}.
     *
     * @param hostKey the 32-byte host key of the host being authenticated to
     * @param seed the 32-byte Ed25519 seed of the key requesting the token
     * @param nonce the raw nonce bytes
     * @return the 64-byte signature
     * @throws AvpException if a key or the seed has the wrong length
     */
    public static byte[] signChallenge(byte[] hostKey, byte[] seed, byte[] nonce) throws AvpException {
        return AvpCrypto.ed25519Sign(seed, challengeMessage(hostKey, AvpCrypto.ed25519Public(seed), nonce));
    }

    /**
     * Verifies a challenge signature under {@code ed25519PublicKey} over the transcript built with
     * {@code hostKey}, the verifying host's own key (SPEC 3.3), with strict Ed25519 (SPEC 2). A
     * signature over the raw nonce, or over a transcript built with another host key, does not verify.
     *
     * @param hostKey the verifying host's 32-byte key
     * @param ed25519PublicKey the 32-byte key that requested the token
     * @param nonce the raw nonce bytes
     * @param signature the 64-byte signature
     * @return whether it verifies; never throws on malformed input
     */
    public static boolean verifyChallenge(byte[] hostKey, byte[] ed25519PublicKey, byte[] nonce, byte[] signature) {
        try {
            return AvpCrypto.ed25519Verify(
                    ed25519PublicKey, challengeMessage(hostKey, ed25519PublicKey, nonce), signature);
        } catch (AvpException e) {
            return false;
        }
    }
}
