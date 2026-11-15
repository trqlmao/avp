/*
 * AVP 0.5 reference client, HTTP/JSON profile: the worked flow against live hosts.
 *
 * SPDX-License-Identifier: MIT
 */

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

/**
 * The worked flow of the AVP 0.5 reference client, printing one line per step.
 *
 * <p>The owner creates a repository on host A and writes an account; bob prepares a join on his home host (B
 * when given, else A) and is invited; both write the same account concurrently and the merge keeps both
 * edits; bob leaves and the owner processes the leave as a removal; a new owner device is linked and
 * regenerates the same phrase. With two hosts, every step that crosses hosts waits for replication.
 *
 * <p>The phrase is printed once, at creation, as a client shows it by design (SPEC 3.1). No other secret is
 * printed.
 *
 * <p>Build and run from this directory: {@code javac -d build ../avp/*.java ../server/Server.java
 * ../server/Replication.java *.java} then {@code java -cp build Client}. {@code AVP_SERVER_URL} is the
 * owner's host (default {@code http://localhost:8787}); with {@code AVP_SERVER_URL_B} set, bob's home host is
 * that second host, which must replicate with the first. Exits 0 when every step succeeds and 1 with the
 * error otherwise.
 */
public final class Client {

    /** The account the flow writes; a fixed player UUID. */
    static final String ACCOUNT = "0b5e7f2a-5d1c-4a6e-9c1e-1f0d4a7b3c21";

    /** How long a step waits for replication between hosts. */
    static final Duration WAIT = Duration.ofSeconds(60);

    private Client() {}

    /**
     * Runs the worked flow against {@code AVP_SERVER_URL} and, when set, {@code AVP_SERVER_URL_B}.
     *
     * @param args ignored
     */
    public static void main(String[] args) {
        String urlA = System.getenv("AVP_SERVER_URL");
        if (urlA == null || urlA.isBlank()) {
            urlA = "http://localhost:8787";
        }
        String urlB = System.getenv("AVP_SERVER_URL_B");
        if (urlB != null && urlB.isBlank()) {
            urlB = null;
        }
        PrintStream out = new PrintStream(System.out, true, StandardCharsets.UTF_8);
        try {
            run(urlA.trim(), urlB == null ? null : urlB.trim(), out);
        } catch (Vault.ClientException e) {
            System.err.println("error: " + e.getMessage());
            System.exit(1);
        }
        System.exit(0);
    }

    /** A step that may fail with the client's exception. */
    @FunctionalInterface
    private interface Attempt<T> {
        /** One try: the value, or {@code null} when the step has not happened yet. */
        T run() throws Vault.ClientException;
    }

    /** Waits for a future; this is a CLI program, so blocking here is fine. */
    static <T> T await(CompletableFuture<T> f) throws Vault.ClientException {
        try {
            return f.join();
        } catch (CompletionException e) {
            if (e.getCause() instanceof Vault.ClientException ce) {
                throw ce;
            }
            throw new Vault.ClientException(Vault.ClientException.Kind.FLOW, "unexpected failure: " + e.getCause(), e);
        }
    }

    /** Retries {@code f} until it yields a value, for at most {@link #WAIT}; the last failure is thrown. */
    private static <T> T poll(String what, Attempt<T> f) throws Vault.ClientException {
        long deadline = System.nanoTime() + WAIT.toNanos();
        while (true) {
            Vault.ClientException last;
            try {
                T v = f.run();
                if (v != null) {
                    return v;
                }
                last = new Vault.ClientException(Vault.ClientException.Kind.FLOW, "timed out waiting: " + what);
            } catch (Vault.ClientException e) {
                last = e;
            }
            if (System.nanoTime() >= deadline) {
                throw last;
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new Vault.ClientException(Vault.ClientException.Kind.FLOW, "interrupted waiting: " + what, e);
            }
        }
    }

    /** The value of one field of the flow's account, or {@code null} if the field is absent. */
    private static Object field(Map<String, Object> payload, String name) {
        if (payload.get("accounts") instanceof Map<?, ?> accounts
                && accounts.get(ACCOUNT) instanceof Map<?, ?> account
                && account.get("fields") instanceof Map<?, ?> fields
                && fields.get(name) instanceof Map<?, ?> f) {
            return f.get("value");
        }
        return null;
    }

    private static boolean hasField(Map<String, Object> payload, String name) {
        return payload.get("accounts") instanceof Map<?, ?> accounts
                && accounts.get(ACCOUNT) instanceof Map<?, ?> account
                && account.get("fields") instanceof Map<?, ?> fields
                && fields.containsKey(name);
    }

    private static int accounts(Map<String, Object> payload) {
        return payload.get("accounts") instanceof Map<?, ?> m ? m.size() : 0;
    }

    private static String shortId(byte[] id) {
        return AvpEncoding.base64(id).substring(0, 12);
    }

    /**
     * Runs the worked flow against host {@code urlA} and, when given, bob's home host {@code urlB} (which
     * must replicate with A).
     *
     * @param urlA the owner's host, {@code http://host:port}
     * @param urlB bob's home host, or {@code null} for A
     * @param out where each step is printed
     * @throws Vault.ClientException the first step that fails, or of kind {@link
     *     Vault.ClientException.Kind#FLOW} if a step does not end as expected
     */
    public static void run(String urlA, String urlB, PrintStream out) throws Vault.ClientException {
        Vault.HostClient hostA = await(Vault.HostClient.connect(urlA));
        out.println("hosts: A at " + hostA.locator() + " (host key " + AvpEncoding.base64(hostA.key()) + ")");
        String bobUrl = urlB == null ? urlA : urlB;
        if (urlB != null) {
            try (Vault.HostClient hostB = await(Vault.HostClient.connect(urlB))) {
                out.println("hosts: B at " + hostB.locator() + " (host key " + AvpEncoding.base64(hostB.key()) + ")");
            }
        }

        // Owner identity and repository creation (SPEC 3.1, 8.2).
        Vault.OwnerIdentity ownerId = Vault.OwnerIdentity.generate();
        out.println("create: new owner identity; recovery phrase, shown once (write it down):");
        out.println("  " + ownerId.mnemonic());
        Vault owner = await(Vault.create(hostA, ownerId.keys()));
        AvpTokens.RepoLocator locator = owner.locator();
        out.println("create: repository " + owner.repoId() + " on A, owner fingerprint " + locator.ownerFingerprint());
        out.println("create: repo locator token " + AvpTokens.encode(AvpTokens.toJson(locator)));

        String by = owner.member().id();
        await(owner.write((p, hlc) -> {
            Map<String, Object> s = hlc.tick(Vault.nowMs(), by);
            Vault.setField(p, ACCOUNT, "username", "alice-alt", s);
            Vault.setField(p, ACCOUNT, "accessToken", "access-token-1", s);
            Vault.setField(p, ACCOUNT, "type", "MICROSOFT", s);
            Vault.setField(p, ACCOUNT, "sourceClient", "reference-client", s);
        }));
        out.println("write: owner added one account");

        // Invite (SPEC 8.1, 8.2).
        Vault.Member bob = Vault.Member.generate();
        Vault.HostClient bobHome = await(Vault.HostClient.connect(bobUrl));
        AvpTokens.InviteToken token = await(Vault.prepareJoin(bobHome, bob, owner.repoId()));
        out.println("invite: bob prepared a join on " + (urlB != null ? "B" : "A") + " (key fingerprint "
                + bob.fingerprint() + "), invite token "
                + AvpTokens.encode(AvpTokens.toJson(token)).length()
                + " chars");
        await(owner.invite(token));
        out.println("invite: owner verified the acceptance and wrapped the data key to bob's key (fingerprint "
                + bob.fingerprint() + "), seq " + owner.tip().state().manifestSeq());
        // One connection for every try: its cached token is reused, so waiting for replication does not
        // mint a token per try (a host may cap the live tokens per key, SPEC 12.1, 12.2).
        Vault bobVault = poll("bob's home host carries the repository", () -> {
            Vault v = await(Vault.join(bobHome, bob, locator));
            return hasField(v.payload(), "username") ? v : null;
        });
        out.println("invite: bob joined and reads " + accounts(bobVault.payload()) + " account(s)");

        // Concurrent writes and the merge (SPEC 5).
        long t = Vault.nowMs();
        await(owner.write((p, hlc) -> Vault.setField(p, ACCOUNT, "username", "alice-renamed", hlc.tick(t, by))));
        String bobId = bob.id();
        await(bobVault.write((p, hlc) -> {
            Map<String, Object> s = hlc.tick(t, bobId);
            Vault.setField(p, ACCOUNT, "lastUsed", t, s);
            Vault.setField(p, ACCOUNT, "lastUsedBy", bobId, s);
        }));
        out.println("write: owner renamed the account while bob marked it used, concurrently");
        Vault.PullReport merged = poll("the owner sees bob's write", () -> {
            Vault.PullReport r = await(owner.pull());
            return hasField(owner.payload(), "lastUsedBy") ? r : null;
        });
        if (merged.mergeCommit().isPresent()) {
            out.println("merge: owner merged two heads into commit "
                    + shortId(merged.mergeCommit().get()));
        } else {
            out.println("merge: owner already holds one head covering both writes");
        }
        Map<String, Object> want = owner.payload();
        poll("bob sees the merge", () -> {
            await(bobVault.pull());
            return bobVault.payload().equals(want) ? Boolean.TRUE : null;
        });
        Object username = field(bobVault.payload(), "username");
        Object usedBy = field(bobVault.payload(), "lastUsedBy");
        if (!Objects.equals(username, "alice-renamed") || !Objects.equals(usedBy, bob.id())) {
            throw new Vault.ClientException(Vault.ClientException.Kind.FLOW, "the merge lost an edit");
        }
        out.println("merge: bob sees both edits, username " + AvpJson.write(username) + ", lastUsedBy bob");

        // Leave (SPEC 8.4).
        await(bobVault.leave());
        try {
            await(bobVault.pull());
            throw new Vault.ClientException(Vault.ClientException.Kind.FLOW, "bob kept syncing after leaving");
        } catch (Vault.ClientException e) {
            if (e.kind() != Vault.ClientException.Kind.LEFT) {
                throw e;
            }
        }
        bobHome.close();
        out.println("leave: bob sent a signed leave request and stopped syncing");
        List<byte[]> removed = poll("the owner sees bob's leave request", () -> {
            List<byte[]> r = await(owner.processLeaves());
            return r.isEmpty() ? null : r;
        });
        out.println("leave: owner processed " + removed.size() + " leave request(s) as removal: seq "
                + owner.tip().state().manifestSeq() + ", key epoch "
                + owner.tip().state().keyEpoch());

        // Device linking (SPEC 11.6).
        Vault.LinkSession session = Vault.LinkSession.start();
        String codeNew = session.confirmationCode();
        out.println("link: new device shows link request and code " + codeNew);
        String[] shown = new String[1];
        AvpTokens.LinkGrant grant = Vault.LinkSession.approve(ownerId.entropy(), session.request(), code -> {
            shown[0] = code;
            return code.equals(codeNew);
        });
        out.println("link: existing device shows code " + shown[0] + "; the owner confirms they match");
        Vault.OwnerIdentity linked = session.finish(grant);
        if (!linked.mnemonic().equals(ownerId.mnemonic())) {
            throw new Vault.ClientException(
                    Vault.ClientException.Kind.FLOW, "the linked device derived another phrase");
        }
        out.println("link: the new device regenerated the same 24-word phrase and owner keys");
        try (Vault linkedVault = await(Vault.open(
                await(Vault.HostClient.connect(urlA)), Vault.Member.fromOwner(linked.keys()), owner.repoId()))) {
            out.println("link: the new device reads " + accounts(linkedVault.payload()) + " account(s) at seq "
                    + linkedVault.tip().state().manifestSeq());
        }
        owner.close();
        out.println("done");
    }
}
