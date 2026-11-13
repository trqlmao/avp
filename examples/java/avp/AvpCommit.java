/*
 * Commits (SPEC 4.3): the header bytes, commitId, the author signature, AAD v2, and the payload AEAD.
 *
 * SPDX-License-Identifier: MIT
 */

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Commits of the signed commit graph (SPEC 4.3).
 *
 * <p>As in {@link AvpManifest}, the records copy what they are given and compare arrays by identity;
 * compare commits by {@link Commit#commitId()} or by {@link #toJson(Commit)}.
 */
public final class AvpCommit {

    private AvpCommit() {}

    /**
     * The fields of a commit an author chooses before sealing (SPEC 4.3).
     *
     * @param repoId the repository
     * @param parents the 32-byte parent ids: none for the first commit, two or more for a merge
     * @param manifestSeq the manifest state the author writes under
     * @param manifestHash the 32-byte {@code manifestHash} of that state
     * @param keyEpoch the epoch of the data key that encrypts the payload
     */
    public record Header(String repoId, List<byte[]> parents, long manifestSeq, byte[] manifestHash, long keyEpoch) {
        /** Copies the ids. */
        public Header {
            parents = AvpManifest.copyIds(parents);
            manifestHash = manifestHash.clone();
        }
    }

    /**
     * A commit (SPEC 4.3), field names as in the proto.
     *
     * @param repoId the repository
     * @param commitId the 32-byte commit id, {@code SHA-256(H)}
     * @param parents the 32-byte parent ids
     * @param manifestSeq the manifest state the author wrote under
     * @param manifestHash the 32-byte {@code manifestHash} of that state
     * @param keyEpoch the epoch of the data key that encrypts the payload
     * @param author the author's 32-byte member Ed25519 key
     * @param iv the 12-byte payload AES-GCM IV
     * @param ciphertext the payload ciphertext with the 16-byte tag appended
     * @param authorSignature the 64-byte {@code Ed25519-Sign(author, CE(tag "avp/commit-sig/v1",
     *     bytes(commitId)))}
     */
    public record Commit(
            String repoId,
            byte[] commitId,
            List<byte[]> parents,
            long manifestSeq,
            byte[] manifestHash,
            long keyEpoch,
            byte[] author,
            byte[] iv,
            byte[] ciphertext,
            byte[] authorSignature) {
        /** Copies the arrays and ids. */
        public Commit {
            commitId = commitId.clone();
            parents = AvpManifest.copyIds(parents);
            manifestHash = manifestHash.clone();
            author = author.clone();
            iv = iv.clone();
            ciphertext = ciphertext.clone();
            authorSignature = authorSignature.clone();
        }
    }

    private static void writeParents(AvpEncoding w, List<byte[]> parents) throws AvpException {
        List<byte[]> sorted = AvpEncoding.sortedUnique(parents, "parent id");
        w.count(sorted.size());
        for (byte[] p : sorted) {
            w.bytes(p);
        }
    }

    /**
     * The payload additional authenticated data, AAD v2 (SPEC 4.3), parents sorted.
     *
     * @param repoId the repository
     * @param keyEpoch the epoch
     * @param author the author's Ed25519 key
     * @param parents the parent ids
     * @return the AAD bytes
     * @throws AvpException if a parent id appears twice
     */
    public static byte[] aadV2(String repoId, long keyEpoch, byte[] author, List<byte[]> parents) throws AvpException {
        AvpEncoding w = AvpEncoding.tag("avp/aad/v2").str(repoId).i64(keyEpoch).bytes(author);
        writeParents(w, parents);
        return w.finish();
    }

    /**
     * The message an author signs (SPEC 4.3): {@code CE(tag "avp/commit-sig/v1", bytes(commitId))}.
     *
     * @param commitId the commit id
     * @return the message
     * @throws AvpException never for a well-formed tag; the CE writer is fallible in general
     */
    public static byte[] sigMessage(byte[] commitId) throws AvpException {
        return AvpEncoding.tag("avp/commit-sig/v1").bytes(commitId).finish();
    }

    /**
     * The header bytes {@code H} (SPEC 4.3), parents sorted.
     *
     * @param c the commit
     * @return {@code H}
     * @throws AvpException if a parent id appears twice
     */
    public static byte[] headerBytes(Commit c) throws AvpException {
        AvpEncoding w = AvpEncoding.tag("avp/commit/v1").str(c.repoId());
        writeParents(w, c.parents());
        return w.i64(c.manifestSeq())
                .bytes(c.manifestHash())
                .i64(c.keyEpoch())
                .bytes(c.author())
                .bytes(c.iv())
                .bytes(c.ciphertext())
                .finish();
    }

    /**
     * The commit id recomputed from the header, {@code SHA-256(H)} (SPEC 4.3). This is not the {@code
     * commitId} field; {@link #verify(Commit)} checks that the two match.
     *
     * @param c the commit
     * @return the 32-byte id
     * @throws AvpException if a parent id appears twice
     */
    public static byte[] id(Commit c) throws AvpException {
        return AvpCrypto.sha256(headerBytes(c));
    }

    /**
     * Checks SPEC 7.1: {@code commitId} recomputes from the header and {@code authorSignature}
     * verifies under {@code author}.
     *
     * @param c the commit
     * @return whether both hold; {@code false} for a commit whose parents repeat; never throws
     */
    public static boolean verify(Commit c) {
        try {
            return AvpCrypto.constantTimeEquals(id(c), c.commitId())
                    && AvpCrypto.ed25519Verify(c.author(), sigMessage(c.commitId()), c.authorSignature());
        } catch (AvpException e) {
            return false;
        }
    }

    /**
     * Encrypts a payload under a data key with a fresh random IV and AAD v2, computes the commit id,
     * and signs it with the author key (SPEC 4.3).
     *
     * @param dataKey the 32-byte data key of {@code header.keyEpoch()}
     * @param header the header fields
     * @param plaintext the payload JSON bytes
     * @param authorSeed the author's 32-byte Ed25519 seed
     * @return the commit
     * @throws AvpException if a parent id appears twice, a key has the wrong length, or the AEAD fails
     */
    public static Commit seal(byte[] dataKey, Header header, byte[] plaintext, byte[] authorSeed) throws AvpException {
        return sealWithIv(dataKey, header, plaintext, authorSeed, AvpCrypto.randomBytes(12));
    }

    /**
     * {@link #seal(byte[], Header, byte[], byte[])} with a caller-chosen IV, for reproducing the
     * vectors. Real commits MUST use a fresh random IV each time.
     *
     * @param dataKey the 32-byte data key
     * @param header the header fields
     * @param plaintext the payload JSON bytes
     * @param authorSeed the author's 32-byte Ed25519 seed
     * @param iv the 12-byte IV
     * @return the commit
     * @throws AvpException as {@link #seal(byte[], Header, byte[], byte[])}
     */
    public static Commit sealWithIv(byte[] dataKey, Header header, byte[] plaintext, byte[] authorSeed, byte[] iv)
            throws AvpException {
        byte[] author = AvpCrypto.ed25519Public(authorSeed);
        byte[] aad = aadV2(header.repoId(), header.keyEpoch(), author, header.parents());
        byte[] ciphertext = AvpCrypto.aesGcmSeal(dataKey, iv, plaintext, aad);
        Commit unsigned = new Commit(
                header.repoId(),
                new byte[32],
                header.parents(),
                header.manifestSeq(),
                header.manifestHash(),
                header.keyEpoch(),
                author,
                iv,
                ciphertext,
                new byte[64]);
        byte[] commitId = id(unsigned);
        byte[] signature = AvpCrypto.ed25519Sign(authorSeed, sigMessage(commitId));
        return new Commit(
                header.repoId(),
                commitId,
                header.parents(),
                header.manifestSeq(),
                header.manifestHash(),
                header.keyEpoch(),
                author,
                iv,
                ciphertext,
                signature);
    }

    /**
     * Decrypts the payload under a data key with the AAD v2 built from the commit's own header fields
     * (SPEC 4.3).
     *
     * @param c the commit
     * @param dataKey the 32-byte data key of {@code c.keyEpoch()}
     * @return the payload plaintext
     * @throws AvpException of kind {@link AvpException.Kind#CRYPTO} if the payload does not
     *     authenticate (wrong key, or any of repoId, epoch, author, or parent set differs from what was
     *     sealed), and of kind {@link AvpException.Kind#BAD_ENCODING} if a parent id appears twice
     */
    public static byte[] open(Commit c, byte[] dataKey) throws AvpException {
        byte[] aad = aadV2(c.repoId(), c.keyEpoch(), c.author(), c.parents());
        return AvpCrypto.aesGcmOpen(dataKey, c.iv(), c.ciphertext(), aad);
    }

    /**
     * Decodes a commit from its HTTP/JSON form. Unknown fields are ignored.
     *
     * @param json the parsed JSON value
     * @return the commit
     * @throws AvpException if a field is missing, has the wrong type, or a fixed binary field
     *     ({@code commitId}, each parent, {@code manifestHash}, {@code author}, {@code iv}, {@code
     *     authorSignature}) has the wrong length
     */
    public static Commit fromJson(Object json) throws AvpException {
        Map<String, Object> o = AvpJson.object(json, "Commit");
        return new Commit(
                AvpJson.string(o, "repoId"),
                AvpManifest.key32(o, "commitId"),
                AvpManifest.ids(o, "parents"),
                AvpJson.integer(o, "manifestSeq"),
                AvpManifest.key32(o, "manifestHash"),
                AvpJson.integer(o, "keyEpoch"),
                AvpManifest.key32(o, "author"),
                AvpEncoding.fromBase64(AvpJson.string(o, "iv"), 12),
                AvpEncoding.fromBase64(AvpJson.string(o, "ciphertext")),
                AvpEncoding.fromBase64(AvpJson.string(o, "authorSignature"), 64));
    }

    /**
     * The HTTP/JSON form of a commit, fields in the proto order.
     *
     * @param c the commit
     * @return the JSON tree
     */
    public static Map<String, Object> toJson(Commit c) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("repoId", c.repoId());
        o.put("commitId", AvpEncoding.base64(c.commitId()));
        o.put("parents", AvpManifest.idsJson(c.parents()));
        o.put("manifestSeq", c.manifestSeq());
        o.put("manifestHash", AvpEncoding.base64(c.manifestHash()));
        o.put("keyEpoch", c.keyEpoch());
        o.put("author", AvpEncoding.base64(c.author()));
        o.put("iv", AvpEncoding.base64(c.iv()));
        o.put("ciphertext", AvpEncoding.base64(c.ciphertext()));
        o.put("authorSignature", AvpEncoding.base64(c.authorSignature()));
        return o;
    }
}
