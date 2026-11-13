/*
 * Payload v2 (SPEC 5): the per-account, per-field merge, the deletion rule, refresh-token stripping
 * (SPEC 5.1), and the hybrid logical clock that stamps every write.
 *
 * SPDX-License-Identifier: MIT
 */

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/**
 * Payload v2 merge and stamps (SPEC 5, 5.1).
 *
 * <p>Payloads stay JSON trees as {@link AvpJson} parses them: {@code { "v": 2, "accounts": { uuid:
 * Account } }} with {@code Account = { "deleted"?: Stamp, "fields": { name: Field }, "bans": {
 * serverId: Field } }}, {@code Field = { "value", "at", "n", "by" }}, and {@code Stamp = { "at",
 * "n", "by" }}. Every method validates its input and fails with an {@link AvpException} of kind
 * {@link AvpException.Kind#BAD_ENCODING} on a payload of another shape or a {@code v} other than
 * {@code 2}, which a client treats as unreadable (SPEC 7.5). Results are fresh trees: accounts and
 * registers sorted by key, unknown members dropped, an absent {@code value} written as {@code null},
 * and a {@code null} {@code deleted} treated as absent.
 */
public final class AvpPayload {

    /** The fields SPEC 5.1 strips when the refresh-token policy is not {@code true}. */
    public static final List<String> REFRESH_FIELDS = List.of("refreshToken", "expiresAt");

    private AvpPayload() {}

    /** A stamp {@code (at, n, by)}, ordered by {@code at}, {@code n}, then {@code by} as UTF-8 bytes. */
    private record Stamp(long at, long n, String by) {
        int compareTo(Stamp o) {
            if (at != o.at) {
                return Long.compare(at, o.at);
            }
            if (n != o.n) {
                return Long.compare(n, o.n);
            }
            return Arrays.compareUnsigned(by.getBytes(StandardCharsets.UTF_8), o.by.getBytes(StandardCharsets.UTF_8));
        }

        Map<String, Object> json() {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("at", at);
            o.put("n", n);
            o.put("by", by);
            return o;
        }
    }

    /** One last-writer-wins register: a value and its stamp. */
    private record Field(Object value, Stamp stamp) {
        Map<String, Object> json() {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("value", copy(value));
            o.put("at", stamp.at());
            o.put("n", stamp.n());
            o.put("by", stamp.by());
            return o;
        }
    }

    /** One account while merging. */
    private static final class Account {
        private Stamp deleted;
        private final TreeMap<String, Field> fields = new TreeMap<>();
        private final TreeMap<String, Field> bans = new TreeMap<>();

        boolean isDeleted() {
            if (deleted == null) {
                return false;
            }
            for (Field f : fields.values()) {
                if (f.stamp().compareTo(deleted) >= 0) {
                    return false;
                }
            }
            for (Field f : bans.values()) {
                if (f.stamp().compareTo(deleted) >= 0) {
                    return false;
                }
            }
            return true;
        }

        Map<String, Object> json() {
            Map<String, Object> o = new LinkedHashMap<>();
            if (deleted != null) {
                o.put("deleted", deleted.json());
            }
            o.put("fields", registers(fields));
            o.put("bans", registers(bans));
            return o;
        }

        private static Map<String, Object> registers(TreeMap<String, Field> m) {
            Map<String, Object> o = new TreeMap<>();
            for (Map.Entry<String, Field> e : m.entrySet()) {
                o.put(e.getKey(), e.getValue().json());
            }
            return o;
        }
    }

    // ─── Decoding ─────────────────────────────────────────────────────────────────────

    private static Stamp stamp(Object json, String what) throws AvpException {
        Map<String, Object> o = AvpJson.object(json, what);
        return new Stamp(AvpJson.integer(o, "at"), AvpJson.integer(o, "n"), AvpJson.string(o, "by"));
    }

    private static Field field(Object json, String what) throws AvpException {
        Map<String, Object> o = AvpJson.object(json, what);
        return new Field(o.get("value"), stamp(o, what));
    }

    private static Map<String, Object> registers(Map<String, Object> account, String key) throws AvpException {
        return AvpJson.object(AvpJson.optional(account, key).orElse(Map.of()), key);
    }

    /** Merges one account's JSON into the running account. */
    private static void mergeAccount(Account cur, Object json) throws AvpException {
        Map<String, Object> a = AvpJson.object(json, "account");
        Object d = a.get("deleted");
        if (d != null) {
            Stamp s = stamp(d, "deleted");
            if (cur.deleted == null || s.compareTo(cur.deleted) > 0) {
                cur.deleted = s;
            }
        }
        mergeRegisters(cur.fields, registers(a, "fields"));
        mergeRegisters(cur.bans, registers(a, "bans"));
    }

    private static void mergeRegisters(TreeMap<String, Field> into, Map<String, Object> from) throws AvpException {
        for (Map.Entry<String, Object> e : from.entrySet()) {
            Field f = field(e.getValue(), e.getKey());
            Field cur = into.get(e.getKey());
            if (cur == null || f.stamp().compareTo(cur.stamp()) > 0) {
                into.put(e.getKey(), f);
            }
        }
    }

    private static Map<String, Object> accounts(Map<String, Object> payload) throws AvpException {
        Object v = AvpJson.required(payload, "v");
        if (!(v instanceof Long n) || n != 2) {
            throw AvpException.encoding("payload v must be 2");
        }
        return AvpJson.object(AvpJson.required(payload, "accounts"), "accounts");
    }

    // ─── Merge (SPEC 5) ───────────────────────────────────────────────────────────────

    /**
     * Merges payloads (SPEC 5): the union of the accounts; per account, each field name and each ban
     * server id takes the field with the greatest stamp among the inputs; {@code deleted} is the
     * greatest deletion stamp and is absent if no input has one. The merge is commutative,
     * associative, and idempotent. Merging one payload normalizes it; merging none gives an empty
     * payload. The inputs are not modified.
     *
     * @param payloads the payloads
     * @return the merged payload, a fresh tree
     * @throws AvpException if a payload is not of the payload v2 shape
     */
    public static Map<String, Object> merge(List<Map<String, Object>> payloads) throws AvpException {
        TreeMap<String, Account> acc = new TreeMap<>();
        for (Map<String, Object> p : payloads) {
            for (Map.Entry<String, Object> e : accounts(p).entrySet()) {
                mergeAccount(acc.computeIfAbsent(e.getKey(), k -> new Account()), e.getValue());
            }
        }
        return json(acc);
    }

    private static Map<String, Object> json(TreeMap<String, Account> acc) {
        Map<String, Object> accounts = new TreeMap<>();
        for (Map.Entry<String, Account> e : acc.entrySet()) {
            accounts.put(e.getKey(), e.getValue().json());
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("v", 2L);
        out.put("accounts", accounts);
        return out;
    }

    /**
     * Removes the {@code refreshToken} and {@code expiresAt} fields, stamps included, from every
     * account (SPEC 5.1). A client applies it to every payload it encrypts, decrypts, or merges while
     * the policy is not {@code true}. The input is not modified.
     *
     * @param payload the payload
     * @return a normalized copy without the two fields
     * @throws AvpException if the payload is not of the payload v2 shape
     */
    public static Map<String, Object> stripRefresh(Map<String, Object> payload) throws AvpException {
        TreeMap<String, Account> acc = new TreeMap<>();
        for (Map.Entry<String, Object> e : accounts(payload).entrySet()) {
            Account a = new Account();
            mergeAccount(a, e.getValue());
            for (String f : REFRESH_FIELDS) {
                a.fields.remove(f);
            }
            acc.put(e.getKey(), a);
        }
        return json(acc);
    }

    /**
     * Whether an account is deleted (SPEC 5): {@code deleted} exists and is greater than every field
     * stamp and every ban stamp in the account.
     *
     * @param account one account of a payload
     * @return whether it is deleted
     * @throws AvpException if the account is not of the payload v2 shape
     */
    public static boolean isDeleted(Map<String, Object> account) throws AvpException {
        Account a = new Account();
        mergeAccount(a, account);
        return a.isDeleted();
    }

    /**
     * Decodes a payload from its UTF-8 JSON plaintext and normalizes it.
     *
     * @param plaintext the decrypted payload bytes
     * @return the payload
     * @throws AvpException if it is not JSON of the payload v2 shape or its {@code v} is not {@code 2}
     */
    public static Map<String, Object> parse(byte[] plaintext) throws AvpException {
        return merge(List.of(AvpJson.object(AvpJson.parse(plaintext), "payload")));
    }

    /**
     * Encodes a payload as compact UTF-8 JSON, the plaintext a commit encrypts.
     *
     * @param payload the payload
     * @return the UTF-8 bytes
     */
    public static byte[] encode(Map<String, Object> payload) {
        return AvpJson.writeUtf8(payload);
    }

    private static Object copy(Object v) {
        if (v instanceof Map<?, ?> m) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : m.entrySet()) {
                out.put((String) e.getKey(), copy(e.getValue()));
            }
            return out;
        }
        if (v instanceof List<?> l) {
            List<Object> out = new ArrayList<>();
            for (Object x : l) {
                out.add(copy(x));
            }
            return out;
        }
        return v;
    }

    // ─── Hybrid logical clock (SPEC 5) ────────────────────────────────────────────────

    /**
     * A hybrid logical clock with state {@code (at, n)} (SPEC 5). A client observes every stamp of
     * every payload it merges before its next tick, so each stamp it writes exceeds every stamp it
     * has seen. Not thread safe.
     */
    public static final class Hlc {
        private long at;
        private long n;

        /** A clock at {@code (0, 0)}. */
        public Hlc() {}

        /**
         * A clock at a given state, for example one restored from storage.
         *
         * @param at the milliseconds
         * @param n the counter
         */
        public Hlc(long at, long n) {
            this.at = at;
            this.n = n;
        }

        /**
         * The clock's milliseconds.
         *
         * @return {@code at}
         */
        public long at() {
            return at;
        }

        /**
         * The clock's counter.
         *
         * @return {@code n}
         */
        public long n() {
            return n;
        }

        /**
         * Advances the clock for a write: {@code (now, 0)} if {@code now > at}, otherwise {@code (at,
         * n + 1)}. A counter at {@link Long#MAX_VALUE} cannot grow, so the clock then moves to {@code
         * (at + 1, 0)} instead, which still issues a greater stamp.
         *
         * @param nowMs the wall clock in epoch milliseconds
         * @param by the writer's member id
         * @return the write's stamp {@code { at, n, by }}
         */
        public Map<String, Object> tick(long nowMs, String by) {
            if (nowMs > at) {
                at = nowMs;
                n = 0;
            } else if (n < Long.MAX_VALUE) {
                n++;
            } else {
                at = at == Long.MAX_VALUE ? at : at + 1;
                n = 0;
            }
            return new Stamp(at, n, by).json();
        }

        /**
         * Folds in a stamp seen in a merged payload: a later {@code at} is taken with its {@code n};
         * an equal {@code at} takes the larger {@code n}; an earlier one changes nothing.
         *
         * @param stamp a stamp or a field, {@code { at, n, ... }}
         * @throws AvpException if {@code at} or {@code n} is missing or not an int64 integer
         */
        public void observe(Map<String, Object> stamp) throws AvpException {
            long sat = AvpJson.integer(stamp, "at");
            long sn = AvpJson.integer(stamp, "n");
            if (sat > at) {
                at = sat;
                n = sn;
            } else if (sat == at) {
                n = Math.max(n, sn);
            }
        }

        /**
         * Observes every stamp of a payload: each field, ban, and deletion marker.
         *
         * @param payload the payload
         * @throws AvpException if the payload is not of the payload v2 shape
         */
        public void observeAll(Map<String, Object> payload) throws AvpException {
            for (Object a : AvpJson.object(merge(List.of(payload)).get("accounts"), "accounts")
                    .values()) {
                Map<String, Object> account = AvpJson.object(a, "account");
                Optional<Object> d = Optional.ofNullable(account.get("deleted"));
                if (d.isPresent()) {
                    observe(AvpJson.object(d.get(), "deleted"));
                }
                for (String key : List.of("fields", "bans")) {
                    for (Object f : AvpJson.object(account.get(key), key).values()) {
                        observe(AvpJson.object(f, key));
                    }
                }
            }
        }
    }
}
