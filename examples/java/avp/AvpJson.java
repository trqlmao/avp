/*
 * A small, strict JSON parser and compact writer for the shared Java AVP sources.
 *
 * SPDX-License-Identifier: MIT
 */

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Strict JSON (RFC 8259) parsing and compact writing, with typed field accessors for decoders.
 *
 * <p>A parsed value is a {@code Map<String, Object>} (a {@link LinkedHashMap} that keeps the field
 * order), a {@code List<Object>}, a {@link String}, a {@link Long} for an integer that fits in 64
 * bits, a {@link BigInteger} for a larger integer, a {@link BigDecimal} for a number with a fraction
 * or an exponent, a {@link Boolean}, or {@code null}. The parser rejects every input RFC 8259 does
 * not allow, and also a duplicate object key, an escaped lone surrogate, nesting deeper than {@link
 * #MAX_DEPTH}, a number literal longer than {@link #MAX_NUMBER_LENGTH}, and bytes that are not
 * well-formed UTF-8. Every rejection is an {@link AvpException}
 * of kind {@link AvpException.Kind#BAD_ENCODING}, which a host answers with {@code 400 bad_request}.
 *
 * <p>The writer emits compact JSON: no whitespace, object fields in map iteration order, and only
 * the escapes JSON requires ({@code "}, {@code \}, and control characters), so a token built from a
 * {@link LinkedHashMap} in the SPEC field order is byte-exact (SPEC 11.1).
 */
public final class AvpJson {

    /** The deepest nesting of arrays and objects the parser accepts. */
    public static final int MAX_DEPTH = 64;

    /** The longest number literal, in characters, the parser accepts. */
    public static final int MAX_NUMBER_LENGTH = 1000;

    private static final BigInteger LONG_MIN = BigInteger.valueOf(Long.MIN_VALUE);
    private static final BigInteger LONG_MAX = BigInteger.valueOf(Long.MAX_VALUE);

    private AvpJson() {}

    // ─── Parsing ──────────────────────────────────────────────────────────────────────

    /**
     * Parses one JSON text.
     *
     * @param text the JSON text
     * @return the parsed value
     * @throws AvpException if the text is not exactly one valid JSON value, with optional whitespace
     */
    public static Object parse(String text) throws AvpException {
        Parser p = new Parser(text);
        p.ws();
        Object v = p.value(0);
        p.ws();
        if (p.pos != text.length()) {
            throw p.fail("trailing characters");
        }
        return v;
    }

    /**
     * Parses one JSON text from UTF-8 bytes.
     *
     * @param utf8 the JSON text as UTF-8
     * @return the parsed value
     * @throws AvpException if the bytes are not well-formed UTF-8 or not one valid JSON value
     */
    public static Object parse(byte[] utf8) throws AvpException {
        String text;
        try {
            text = StandardCharsets.UTF_8
                    .newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(utf8))
                    .toString();
        } catch (CharacterCodingException e) {
            throw AvpException.encoding("JSON is not well-formed UTF-8");
        }
        return parse(text);
    }

    /** A recursive descent parser over one string. */
    private static final class Parser {
        private final String s;
        private int pos;

        Parser(String s) {
            this.s = s;
        }

        AvpException fail(String why) {
            return AvpException.encoding("malformed JSON at offset " + pos + ": " + why);
        }

        void ws() {
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                    return;
                }
                pos++;
            }
        }

        Object value(int depth) throws AvpException {
            if (pos >= s.length()) {
                throw fail("unexpected end");
            }
            char c = s.charAt(pos);
            switch (c) {
                case '{':
                    return object(depth + 1);
                case '[':
                    return array(depth + 1);
                case '"':
                    return string();
                case 't':
                    literal("true");
                    return Boolean.TRUE;
                case 'f':
                    literal("false");
                    return Boolean.FALSE;
                case 'n':
                    literal("null");
                    return null;
                default:
                    if (c == '-' || (c >= '0' && c <= '9')) {
                        return number();
                    }
                    throw fail("unexpected character");
            }
        }

        void literal(String word) throws AvpException {
            if (!s.startsWith(word, pos)) {
                throw fail("bad literal");
            }
            pos += word.length();
        }

        void expect(char c) throws AvpException {
            if (pos >= s.length() || s.charAt(pos) != c) {
                throw fail("expected '" + c + "'");
            }
            pos++;
        }

        Map<String, Object> object(int depth) throws AvpException {
            if (depth > MAX_DEPTH) {
                throw fail("nesting deeper than " + MAX_DEPTH);
            }
            expect('{');
            Map<String, Object> out = new LinkedHashMap<>();
            ws();
            if (pos < s.length() && s.charAt(pos) == '}') {
                pos++;
                return out;
            }
            while (true) {
                ws();
                if (pos >= s.length() || s.charAt(pos) != '"') {
                    throw fail("expected a string key");
                }
                String key = string();
                ws();
                expect(':');
                ws();
                Object v = value(depth);
                if (out.containsKey(key)) {
                    throw fail("duplicate key");
                }
                out.put(key, v);
                ws();
                if (pos < s.length() && s.charAt(pos) == ',') {
                    pos++;
                    continue;
                }
                expect('}');
                return out;
            }
        }

        List<Object> array(int depth) throws AvpException {
            if (depth > MAX_DEPTH) {
                throw fail("nesting deeper than " + MAX_DEPTH);
            }
            expect('[');
            List<Object> out = new ArrayList<>();
            ws();
            if (pos < s.length() && s.charAt(pos) == ']') {
                pos++;
                return out;
            }
            while (true) {
                ws();
                out.add(value(depth));
                ws();
                if (pos < s.length() && s.charAt(pos) == ',') {
                    pos++;
                    continue;
                }
                expect(']');
                return out;
            }
        }

        String string() throws AvpException {
            expect('"');
            StringBuilder out = new StringBuilder();
            while (true) {
                if (pos >= s.length()) {
                    throw fail("unterminated string");
                }
                char c = s.charAt(pos++);
                if (c == '"') {
                    return out.toString();
                }
                if (c < 0x20) {
                    throw fail("unescaped control character");
                }
                if (Character.isSurrogate(c)) {
                    // A Java string can only hold a lone surrogate if it was built that way; JSON
                    // text is Unicode, so require a well-formed pair.
                    if (Character.isHighSurrogate(c) && pos < s.length() && Character.isLowSurrogate(s.charAt(pos))) {
                        out.append(c).append(s.charAt(pos++));
                        continue;
                    }
                    throw fail("lone surrogate");
                }
                if (c != '\\') {
                    out.append(c);
                    continue;
                }
                if (pos >= s.length()) {
                    throw fail("unterminated escape");
                }
                char e = s.charAt(pos++);
                switch (e) {
                    case '"' -> out.append('"');
                    case '\\' -> out.append('\\');
                    case '/' -> out.append('/');
                    case 'b' -> out.append('\b');
                    case 'f' -> out.append('\f');
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case 'u' -> {
                        char u = hex4();
                        if (Character.isHighSurrogate(u)) {
                            if (!s.startsWith("\\u", pos)) {
                                throw fail("lone high surrogate");
                            }
                            pos += 2;
                            char low = hex4();
                            if (!Character.isLowSurrogate(low)) {
                                throw fail("lone high surrogate");
                            }
                            out.append(u).append(low);
                        } else if (Character.isLowSurrogate(u)) {
                            throw fail("lone low surrogate");
                        } else {
                            out.append(u);
                        }
                    }
                    default -> throw fail("bad escape");
                }
            }
        }

        char hex4() throws AvpException {
            if (pos + 4 > s.length()) {
                throw fail("short unicode escape");
            }
            int v = 0;
            for (int k = 0; k < 4; k++) {
                int d = AvpEncoding.hexDigit(s.charAt(pos + k));
                if (d < 0) {
                    throw fail("bad unicode escape");
                }
                v = (v << 4) | d;
            }
            pos += 4;
            return (char) v;
        }

        Object number() throws AvpException {
            int start = pos;
            if (s.charAt(pos) == '-') {
                pos++;
            }
            if (pos >= s.length()) {
                throw fail("bad number");
            }
            if (s.charAt(pos) == '0') {
                pos++;
            } else if (s.charAt(pos) >= '1' && s.charAt(pos) <= '9') {
                digits();
            } else {
                throw fail("bad number");
            }
            boolean integral = true;
            if (pos < s.length() && s.charAt(pos) == '.') {
                integral = false;
                pos++;
                if (digits() == 0) {
                    throw fail("bad fraction");
                }
            }
            if (pos < s.length() && (s.charAt(pos) == 'e' || s.charAt(pos) == 'E')) {
                integral = false;
                pos++;
                if (pos < s.length() && (s.charAt(pos) == '+' || s.charAt(pos) == '-')) {
                    pos++;
                }
                if (digits() == 0) {
                    throw fail("bad exponent");
                }
            }
            if (pos - start > MAX_NUMBER_LENGTH) {
                // Bounds the cost of BigInteger and BigDecimal parsing, which is super-linear in length.
                throw fail("number longer than " + MAX_NUMBER_LENGTH + " characters");
            }
            String text = s.substring(start, pos);
            try {
                if (!integral) {
                    return new BigDecimal(text);
                }
                BigInteger big = new BigInteger(text);
                if (big.compareTo(LONG_MIN) >= 0 && big.compareTo(LONG_MAX) <= 0) {
                    return big.longValue();
                }
                return big;
            } catch (NumberFormatException | ArithmeticException e) {
                throw fail("number out of range");
            }
        }

        int digits() {
            int n = 0;
            while (pos < s.length() && s.charAt(pos) >= '0' && s.charAt(pos) <= '9') {
                pos++;
                n++;
            }
            return n;
        }
    }

    // ─── Writing ──────────────────────────────────────────────────────────────────────

    /**
     * Writes a value as compact JSON.
     *
     * @param value a tree of the types {@link #parse(String)} produces ({@link Integer} is accepted
     *     too); map keys must be strings
     * @return the compact JSON text
     * @throws IllegalArgumentException if the tree holds a value of another type, a programming error
     *     that a tree from {@link #parse(String)} or from this package's encoders cannot cause
     */
    public static String write(Object value) {
        StringBuilder out = new StringBuilder();
        write(out, value);
        return out.toString();
    }

    /**
     * Writes a value as compact JSON in UTF-8.
     *
     * @param value a tree as for {@link #write(Object)}
     * @return the UTF-8 bytes of the compact JSON text
     */
    public static byte[] writeUtf8(Object value) {
        return write(value).getBytes(StandardCharsets.UTF_8);
    }

    private static void write(StringBuilder out, Object v) {
        if (v == null) {
            out.append("null");
        } else if (v instanceof String str) {
            writeString(out, str);
        } else if (v instanceof Boolean b) {
            out.append(b.booleanValue() ? "true" : "false");
        } else if (v instanceof Long || v instanceof Integer || v instanceof BigInteger) {
            out.append(v);
        } else if (v instanceof BigDecimal d) {
            out.append(d.toString());
        } else if (v instanceof Map<?, ?> map) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : map.entrySet()) {
                if (!(e.getKey() instanceof String key)) {
                    throw new IllegalArgumentException("JSON object keys must be strings");
                }
                if (!first) {
                    out.append(',');
                }
                first = false;
                writeString(out, key);
                out.append(':');
                write(out, e.getValue());
            }
            out.append('}');
        } else if (v instanceof List<?> list) {
            out.append('[');
            for (int k = 0; k < list.size(); k++) {
                if (k > 0) {
                    out.append(',');
                }
                write(out, list.get(k));
            }
            out.append(']');
        } else {
            throw new IllegalArgumentException(
                    "not a JSON value: " + v.getClass().getName());
        }
    }

    private static void writeString(StringBuilder out, String s) {
        out.append('"');
        for (int k = 0; k < s.length(); k++) {
            char c = s.charAt(k);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    // ─── Typed access for decoders ────────────────────────────────────────────────────

    /**
     * Casts a parsed value to a JSON object.
     *
     * @param v the value
     * @param what the name of the value, for the error message
     * @return the object
     * @throws AvpException if the value is not an object
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> object(Object v, String what) throws AvpException {
        if (v instanceof Map<?, ?> map) {
            return (Map<String, Object>) map;
        }
        throw AvpException.encoding(what + " must be an object");
    }

    /**
     * Casts a parsed value to a JSON array.
     *
     * @param v the value
     * @param what the name of the value, for the error message
     * @return the array, read only
     * @throws AvpException if the value is not an array
     */
    @SuppressWarnings("unchecked")
    public static List<Object> array(Object v, String what) throws AvpException {
        if (v instanceof List<?> list) {
            return Collections.unmodifiableList((List<Object>) list);
        }
        throw AvpException.encoding(what + " must be an array");
    }

    /**
     * Casts a parsed value to a string.
     *
     * @param v the value
     * @param what the name of the value, for the error message
     * @return the string
     * @throws AvpException if the value is not a string
     */
    public static String string(Object v, String what) throws AvpException {
        if (v instanceof String str) {
            return str;
        }
        throw AvpException.encoding(what + " must be a string");
    }

    /**
     * Casts a parsed value to a 64-bit integer. A number with a fraction or an exponent, or one
     * outside the {@code long} range, is rejected.
     *
     * @param v the value
     * @param what the name of the value, for the error message
     * @return the integer
     * @throws AvpException if the value is not an integer that fits in 64 bits
     */
    public static long integer(Object v, String what) throws AvpException {
        if (v instanceof Long n) {
            return n;
        }
        throw AvpException.encoding(what + " must be an int64 integer");
    }

    /**
     * Casts a parsed value to a boolean.
     *
     * @param v the value
     * @param what the name of the value, for the error message
     * @return the boolean
     * @throws AvpException if the value is not {@code true} or {@code false}
     */
    public static boolean bool(Object v, String what) throws AvpException {
        if (v instanceof Boolean b) {
            return b;
        }
        throw AvpException.encoding(what + " must be a boolean");
    }

    /**
     * The value of a required field.
     *
     * @param o the object
     * @param key the field name
     * @return the value, which may be JSON {@code null}
     * @throws AvpException if the field is absent
     */
    public static Object required(Map<String, Object> o, String key) throws AvpException {
        if (!o.containsKey(key)) {
            throw AvpException.encoding("missing field " + key);
        }
        return o.get(key);
    }

    /**
     * The value of an optional field that has a default when absent.
     *
     * @param o the object
     * @param key the field name
     * @return the value, or empty if the field is absent
     * @throws AvpException if the field is present with the value {@code null}, which is not the
     *     field's type
     */
    public static Optional<Object> optional(Map<String, Object> o, String key) throws AvpException {
        if (!o.containsKey(key)) {
            return Optional.empty();
        }
        Object v = o.get(key);
        if (v == null) {
            throw AvpException.encoding(key + " must not be null");
        }
        return Optional.of(v);
    }

    /**
     * A required string field.
     *
     * @param o the object
     * @param key the field name
     * @return the string
     * @throws AvpException if the field is absent or not a string
     */
    public static String string(Map<String, Object> o, String key) throws AvpException {
        return string(required(o, key), key);
    }

    /**
     * A required 64-bit integer field.
     *
     * @param o the object
     * @param key the field name
     * @return the integer
     * @throws AvpException if the field is absent or not an int64 integer
     */
    public static long integer(Map<String, Object> o, String key) throws AvpException {
        return integer(required(o, key), key);
    }

    /**
     * A required boolean field.
     *
     * @param o the object
     * @param key the field name
     * @return the boolean
     * @throws AvpException if the field is absent or not a boolean
     */
    public static boolean bool(Map<String, Object> o, String key) throws AvpException {
        return bool(required(o, key), key);
    }
}
