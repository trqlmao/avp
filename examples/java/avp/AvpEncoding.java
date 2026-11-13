/*
 * The canonical encoding writer (SPEC 4.1) and the wire forms of binary values (SPEC 2).
 *
 * SPDX-License-Identifier: MIT
 */

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * Writer for the canonical encoding, CE (SPEC 4.1), plus the base64, base64url, and hex forms of
 * binary values and the unsigned bytewise order lists are sorted by (SPEC 2).
 *
 * <p>Start a CE string with {@link #tag(String)}, append items in the order a construction lists
 * them, and call {@link #finish()}:
 *
 * <pre>{@code
 * byte[] s = AvpEncoding.tag("t").str("ab").i64(2).bool(true).finish();
 * }</pre>
 *
 * <p>A tag label that contains {@code 0x00}, or a negative count, is recorded and makes {@link
 * #finish()} fail, so the writer never produces an ambiguous encoding. A writer is not thread safe.
 */
public final class AvpEncoding {

    private static final Base64.Encoder B64 = Base64.getEncoder();
    private static final Base64.Decoder UNB64 = Base64.getDecoder();
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder UNB64URL = Base64.getUrlDecoder();
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private final ByteArrayOutputStream buf = new ByteArrayOutputStream();
    private String error;

    private AvpEncoding(String label) {
        byte[] b = label.getBytes(StandardCharsets.UTF_8);
        for (byte x : b) {
            if (x == 0) {
                error = "CE tag label contains 0x00";
            }
        }
        buf.writeBytes(b);
        buf.write(0);
    }

    /**
     * Starts a CE string with {@code tag(label)}: the UTF-8 bytes of {@code label}, then one {@code
     * 0x00}.
     *
     * @param label the domain label, for example {@code avp/manifest/v1}
     * @return a new writer
     */
    public static AvpEncoding tag(String label) {
        return new AvpEncoding(label);
    }

    /**
     * Appends {@code bytes(b)}: {@code u32BE(len(b)) || b}.
     *
     * @param b the bytes
     * @return this writer
     */
    public AvpEncoding bytes(byte[] b) {
        count(b.length);
        buf.writeBytes(b);
        return this;
    }

    /**
     * Appends {@code str(s)}: {@code bytes(UTF8(s))}.
     *
     * @param s the string
     * @return this writer
     */
    public AvpEncoding str(String s) {
        return bytes(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Appends {@code i64(n)}: the 8-byte big-endian two's-complement encoding of {@code n}.
     *
     * @param n the integer
     * @return this writer
     */
    public AvpEncoding i64(long n) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            buf.write((int) (n >>> shift) & 0xff);
        }
        return this;
    }

    /**
     * Appends {@code bool(b)}: one byte, {@code 0x00} for false and {@code 0x01} for true.
     *
     * @param b the boolean
     * @return this writer
     */
    public AvpEncoding bool(boolean b) {
        buf.write(b ? 1 : 0);
        return this;
    }

    /**
     * Appends {@code count(n)}: {@code u32BE(n)}. A negative {@code n} is recorded and makes {@link
     * #finish()} fail.
     *
     * @param n the count, at least zero
     * @return this writer
     */
    public AvpEncoding count(int n) {
        if (n < 0) {
            error = "CE count is negative";
            return this;
        }
        buf.write((n >>> 24) & 0xff);
        buf.write((n >>> 16) & 0xff);
        buf.write((n >>> 8) & 0xff);
        buf.write(n & 0xff);
        return this;
    }

    /**
     * Returns the finished CE byte string.
     *
     * @return the bytes
     * @throws AvpException if the tag contained {@code 0x00} or a count was negative
     */
    public byte[] finish() throws AvpException {
        if (error != null) {
            throw AvpException.encoding(error);
        }
        return buf.toByteArray();
    }

    // ─── Ordering (SPEC 2) ────────────────────────────────────────────────────────────

    /**
     * Compares two byte strings as unsigned bytes, the order of every sorted CE list (SPEC 2).
     *
     * @param a the first byte string
     * @param b the second byte string
     * @return a negative number, zero, or a positive number as {@code a} sorts before, equal to, or
     *     after {@code b}
     */
    public static int compare(byte[] a, byte[] b) {
        return Arrays.compareUnsigned(a, b);
    }

    /**
     * Returns the byte strings sorted by {@link #compare(byte[], byte[])}.
     *
     * @param ids the byte strings
     * @param what the name of the list, for the error message
     * @return a new sorted list
     * @throws AvpException if two byte strings are equal: a duplicate makes the wire form malformed
     *     (SPEC 4.2, 4.3)
     */
    public static List<byte[]> sortedUnique(List<byte[]> ids, String what) throws AvpException {
        List<byte[]> out = new ArrayList<>(ids);
        out.sort(AvpEncoding::compare);
        for (int k = 1; k < out.size(); k++) {
            if (compare(out.get(k - 1), out.get(k)) == 0) {
                throw AvpException.encoding("duplicate " + what);
            }
        }
        return out;
    }

    // ─── Wire forms (SPEC 2) ──────────────────────────────────────────────────────────

    /**
     * Encodes bytes as standard base64 with padding, the wire form of binary fields.
     *
     * @param b the bytes
     * @return the base64 text
     */
    public static String base64(byte[] b) {
        return B64.encodeToString(b);
    }

    /**
     * Decodes canonical standard base64 with padding: the text must be exactly what {@link
     * #base64(byte[])} produces for the decoded bytes (no whitespace, no missing padding, no
     * non-zero unused bits).
     *
     * @param s the base64 text
     * @return the bytes
     * @throws AvpException if the text is not canonical standard base64
     */
    public static byte[] fromBase64(String s) throws AvpException {
        byte[] out;
        try {
            out = UNB64.decode(s);
        } catch (IllegalArgumentException e) {
            throw AvpException.encoding("not base64");
        }
        if (!B64.encodeToString(out).equals(s)) {
            throw AvpException.encoding("not canonical base64");
        }
        return out;
    }

    /**
     * Decodes canonical standard base64 that must hold exactly {@code len} bytes.
     *
     * @param s the base64 text
     * @param len the required length
     * @return the bytes
     * @throws AvpException if the text is not canonical base64 or decodes to another length
     */
    public static byte[] fromBase64(String s, int len) throws AvpException {
        byte[] out = fromBase64(s);
        if (out.length != len) {
            throw AvpException.encoding("expected " + len + " bytes, got " + out.length);
        }
        return out;
    }

    /**
     * Encodes bytes as base64url without padding, the form of {@code repoId} and of token text.
     *
     * @param b the bytes
     * @return the base64url text
     */
    public static String base64Url(byte[] b) {
        return B64URL.encodeToString(b);
    }

    /**
     * Decodes canonical base64url without padding.
     *
     * @param s the base64url text
     * @return the bytes
     * @throws AvpException if the text is not canonical base64url-nopad (padding included)
     */
    public static byte[] fromBase64Url(String s) throws AvpException {
        byte[] out;
        try {
            out = UNB64URL.decode(s);
        } catch (IllegalArgumentException e) {
            throw AvpException.encoding("not base64url");
        }
        if (!B64URL.encodeToString(out).equals(s)) {
            throw AvpException.encoding("not canonical base64url without padding");
        }
        return out;
    }

    /**
     * Encodes bytes as lowercase hex.
     *
     * @param b the bytes
     * @return the hex text
     */
    public static String hex(byte[] b) {
        char[] out = new char[b.length * 2];
        for (int k = 0; k < b.length; k++) {
            out[2 * k] = HEX[(b[k] >> 4) & 0xf];
            out[2 * k + 1] = HEX[b[k] & 0xf];
        }
        return new String(out);
    }

    /**
     * Decodes hex, upper or lower case.
     *
     * @param s the hex text
     * @return the bytes
     * @throws AvpException if the length is odd or a character is not a hex digit
     */
    public static byte[] fromHex(String s) throws AvpException {
        if (s.length() % 2 != 0) {
            throw AvpException.encoding("odd hex length");
        }
        byte[] out = new byte[s.length() / 2];
        for (int k = 0; k < out.length; k++) {
            int hi = hexDigit(s.charAt(2 * k));
            int lo = hexDigit(s.charAt(2 * k + 1));
            if (hi < 0 || lo < 0) {
                throw AvpException.encoding("not hex");
            }
            out[k] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    /**
     * The value of one ASCII hex digit.
     *
     * @param c the character
     * @return its value, or {@code -1} if it is not {@code 0-9}, {@code a-f}, or {@code A-F}
     */
    static int hexDigit(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        return -1;
    }
}
