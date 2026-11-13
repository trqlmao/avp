/*
 * The one checked exception of the shared Java AVP sources.
 *
 * SPDX-License-Identifier: MIT
 */

/**
 * A failure of the shared AVP sources, categorized by {@link Kind}.
 *
 * <p>Every decoder and every cryptographic operation reports a failure on its input with this
 * checked exception; none throws an unchecked exception on attacker-controlled input. A host maps
 * any {@code AvpException} raised while decoding a request body to {@code 400 bad_request} (SPEC
 * 10.4). Messages never contain secret material.
 */
public final class AvpException extends Exception {

    private static final long serialVersionUID = 1L;

    /** The category of a failure. */
    public enum Kind {
        /**
         * Input that does not decode: malformed JSON, bad base64 or hex, a binary field of the wrong
         * length, a value out of range, a duplicate list key, or a mnemonic with the wrong word count
         * or an unknown word.
         */
        BAD_ENCODING,
        /** A signature that does not verify, or a recomputed id that does not match. */
        BAD_SIGNATURE,
        /** A BIP39 mnemonic whose checksum does not match (SPEC 3.1). */
        BAD_CHECKSUM,
        /** An AEAD or key agreement failure: wrong key, wrong label or AAD, or tampered bytes. */
        CRYPTO
    }

    private final Kind kind;

    /**
     * Creates an exception of the given kind.
     *
     * @param kind the category of the failure
     * @param message a description of the failure, free of secret material
     */
    public AvpException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    /**
     * Creates an exception of the given kind with the underlying cause.
     *
     * @param kind the category of the failure
     * @param message a description of the failure, free of secret material
     * @param cause the underlying failure
     */
    public AvpException(Kind kind, String message, Throwable cause) {
        super(message, cause);
        this.kind = kind;
    }

    /**
     * The category of the failure.
     *
     * @return the kind
     */
    public Kind kind() {
        return kind;
    }

    /**
     * A {@link Kind#BAD_ENCODING} exception.
     *
     * @param message a description of the failure
     * @return the exception
     */
    static AvpException encoding(String message) {
        return new AvpException(Kind.BAD_ENCODING, message);
    }
}
