/**
 * Reproducible derivation of the AVP conformance vectors.
 *
 * Two jobs:
 *   --check (default): re-derive every committed vector's value fields from its documented seeds and
 *     assert the committed file matches. This is the provenance and drift gate: the vectors are not
 *     arbitrary bytes, they are exactly what this script computes. Read-only.
 *   --write: (re)generate the files this script owns: negative.json (the MUST-reject bank), the
 *     0.5 construction vectors bip39-owner.json, manifest.json, and commit.json, the tokens of
 *     federation.json, which are derived only from the seeds documented below and in each file, and
 *     merge.json and acceptance.json, whose inputs are built from those seeds and whose expected
 *     results are literal data below, written by hand from the SPEC rule each case cites.
 *
 * The RFC-anchored positive vectors (hkdf, x25519, ed25519, key-wrap) are re-derived and checked here
 * but never rewritten, so their reviewed prose and formatting are preserved. The crypto is reused from the vector-tested reference at ../examples/conformance/src so
 * the generator cannot drift from the runner. The pinned BIP39 wordlist (bip39-english.txt) is
 * checked against the SHA-256 of the upstream bitcoin/bips file.
 *
 *   bun vectors/generate.ts --check
 *   bun vectors/generate.ts --write
 *
 * SPDX-License-Identifier: MIT
 */

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  aesGcmEncrypt,
  ed25519PublicRaw,
  ed25519Sign,
  hkdfSha256,
  importEd25519Private,
  importX25519Private,
  importX25519Public,
  sha256,
  WRAP_INFO,
  WRAP_SCHEME_ID,
  wrapKek,
  wrapSecret,
  x25519,
  x25519PublicRaw,
} from "../examples/conformance/src/crypto.ts";
import { entropyToMnemonic, mnemonicToEntropy, mnemonicToSeed, ownerKeysFromSeed } from "../examples/conformance/src/bip39.ts";
import {
  acceptanceSignMessage,
  buildAadV2,
  commitSigMessage,
  deriveRepoId,
  encodeCommitHeader,
  encodeManifestState,
  keyFingerprint,
  leaveSignMessage,
  linkConfirmationCode,
  manifestHash,
  OWNER_LINK_INFO,
  ownerFingerprint,
  signAcceptance,
  signCommit,
  signLeave,
  signManifest,
  type Acceptance,
  type Commit,
  type HostRef,
  type LeaveRequest,
  type ManifestState,
  type MemberEntry,
  type Removal,
  type SignedManifest,
} from "../examples/conformance/src/constructions.ts";
import { acceptanceToWire, commitToWire, leaveToWire, signedManifestToWire } from "../examples/conformance/src/vectors.ts";

const dir = dirname(fileURLToPath(import.meta.url));
const read = (f: string) => JSON.parse(readFileSync(join(dir, f), "utf8"));

const hex = (b: Buffer) => b.toString("hex");
const b64 = (b: Buffer) => b.toString("base64");
const fromB64 = (s: string) => Buffer.from(s, "base64");
const fromHex = (s: string) => Buffer.from(s, "hex");

// ─── Provenance checks: re-derive committed positive vectors from their seeds ─────

interface Check {
  name: string;
  ok: boolean;
  detail: string;
}

function eq(name: string, got: string, want: string, results: Check[]): void {
  results.push({ name, ok: got === want, detail: got === want ? "" : `got ${got} want ${want}` });
}

/** SHA-256 of the upstream bitcoin/bips bip-0039/english.txt (2048 words, LF, trailing newline). */
const BIP39_ENGLISH_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";

function checkPositives(): Check[] {
  const r: Check[] = [];

  // bip39-english.txt: the pinned upstream wordlist
  const wordlist = readFileSync(join(dir, "bip39-english.txt"));
  eq("bip39-english.txt sha256", hex(sha256(wordlist)), BIP39_ENGLISH_SHA256, r);

  // hkdf.json: HKDF-SHA256 expand output
  for (const c of read("hkdf.json").cases) {
    const okm = hkdfSha256(fromHex(c.ikmHex), fromHex(c.saltHex), fromHex(c.infoHex), c.length);
    eq(`hkdf ${c.name}`, hex(okm), c.okmHex, r);
  }

  // x25519.json: raw ECDH output (unhashed)
  for (const c of read("x25519.json").cases) {
    const out = x25519(importX25519Private(fromHex(c.scalarHex)), importX25519Public(fromHex(c.uCoordinateHex)));
    eq(`x25519 ${c.name}`, hex(out), c.outputHex, r);
  }

  // ed25519.json: derive public key from seed and reproduce the signature
  for (const c of read("ed25519.json").cases) {
    const priv = importEd25519Private(fromHex(c.seedHex));
    eq(`ed25519 ${c.name} pubkey`, hex(ed25519PublicRaw(priv)), c.publicKeyHex, r);
    eq(`ed25519 ${c.name} sig`, hex(ed25519Sign(priv, fromHex(c.messageHex))), c.signatureHex, r);
  }

  // key-wrap.json: shared secret (ECDH symmetry), KEK, and the wrap ciphertext
  for (const c of read("key-wrap.json").cases) {
    const shared = x25519(importX25519Private(fromB64(c.recipientPrivateKeyB64)), importX25519Public(fromB64(c.wrappedKey.ephemeralPublicKey)));
    eq(`key-wrap ${c.name} shared`, hex(shared), c.sharedSecretHex, r);
    const kek = wrapKek(shared, fromB64(c.wrappedKey.ephemeralPublicKey));
    eq(`key-wrap ${c.name} kek`, hex(kek), c.kekHex, r);
    const ct = aesGcmEncrypt(kek, fromB64(c.wrappedKey.iv), WRAP_INFO, fromB64(c.dataKeyB64));
    eq(`key-wrap ${c.name} ciphertext`, b64(ct), c.wrappedKey.ciphertext, r);
  }

  // federation.json: base64url(canonical minified JSON) round-trips
  for (const t of read("federation.json").tokens) {
    eq(`federation ${t.name} encode`, Buffer.from(t.canonicalJson, "utf8").toString("base64url"), t.base64url, r);
    eq(`federation ${t.name} decode`, JSON.stringify(JSON.parse(Buffer.from(t.base64url, "base64url").toString("utf8"))), JSON.stringify(t.decoded), r);
  }

  return r;
}

// ─── 0.5 construction vectors (bip39-owner, manifest, commit), from fixed seeds ─────

/**
 * Three 256-bit-entropy cases of the Trezor BIP39 reference vectors, copied verbatim from
 * https://raw.githubusercontent.com/trezor/python-mnemonic/master/vectors.json (english entries 8,
 * 11, 14; passphrase "TREZOR"). External anchor for entropy -> mnemonic -> seed.
 */
const TREZOR_SOURCE = "https://raw.githubusercontent.com/trezor/python-mnemonic/master/vectors.json (english[8], english[11], english[14])";
const TREZOR = [
  {
    entropyHex: "0000000000000000000000000000000000000000000000000000000000000000",
    mnemonic:
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
    seedHex:
      "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
  },
  {
    entropyHex: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    mnemonic: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
    seedHex:
      "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
  },
  {
    entropyHex: "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
    mnemonic:
      "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
    seedHex:
      "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
  },
];

/** Bytes `start, start + 1, ..., start + n - 1`. */
const counting = (start: number, n: number) => Buffer.from(Array.from({ length: n }, (_, i) => start + i));

const OWNER_ENTROPY = counting(0x00, 32);
const OWNER2_ENTROPY = counting(0x20, 32);
const GENESIS_NONCE = Buffer.alloc(16, 0x01);
const PAYLOAD_IV = Buffer.alloc(12, 0x0c);
/** Data key per epoch. Epoch 0 is the plan's 0x42 key; epoch 1 (after the removal) is 0x43. */
const DATA_KEYS: Record<number, Buffer> = { 0: Buffer.alloc(32, 0x42), 1: Buffer.alloc(32, 0x43) };
const WRAP_DERIVATION =
  "Each wrappedDataKey is the default wrap scheme (SPEC 4.4, info avp/rdk-wrap/v1) of the epoch's data key to the member's X25519 key, " +
  "with ephemeral private key SHA-256(UTF8(\"avp/vectors/wrap-ephemeral/\" + keyEpoch + \"/\" + label)) and IV " +
  "SHA-256(UTF8(\"avp/vectors/wrap-iv/\" + keyEpoch + \"/\" + label))[0..12], label being owner, alice, bob, or carol. " +
  "These are fixed only so the vectors are reproducible: real clients MUST use a fresh random ephemeral key and IV per wrap.";

const wrapEphemeral = (epoch: number, label: string) => sha256(Buffer.from(`avp/vectors/wrap-ephemeral/${epoch}/${label}`, "utf8"));
const wrapIv = (epoch: number, label: string) => sha256(Buffer.from(`avp/vectors/wrap-iv/${epoch}/${label}`, "utf8")).subarray(0, 12);

interface Party {
  label: string;
  edSeed: Buffer;
  edPub: Buffer;
  xPriv: Buffer;
  xPub: Buffer;
}

function memberParty(label: string, byte: number): Party {
  const edSeed = Buffer.alloc(32, byte);
  const xPriv = Buffer.alloc(32, byte);
  return { label, edSeed, edPub: ed25519PublicRaw(importEd25519Private(edSeed)), xPriv, xPub: x25519PublicRaw(importX25519Private(xPriv)) };
}

function ownerParty(entropy: Buffer): Party {
  const k = ownerKeysFromSeed(mnemonicToSeed(entropyToMnemonic(entropy)));
  return { label: "owner", edSeed: k.ed25519Seed, edPub: k.ed25519Public, xPriv: k.x25519Private, xPub: k.x25519Public };
}

function hostRef(seedByte: number, locator: string): HostRef & { seed: Buffer; label: string } {
  const seed = Buffer.alloc(32, seedByte);
  return { label: locator.split(".")[0], seed, hostKey: ed25519PublicRaw(importEd25519Private(seed)), locator };
}

function member(p: Party, epoch: number, home: HostRef): MemberEntry {
  const w = wrapSecret(p.xPub, wrapEphemeral(epoch, p.label), wrapIv(epoch, p.label), DATA_KEYS[epoch]);
  return { ed25519PublicKey: p.edPub, x25519PublicKey: p.xPub, wrappedDataKey: w, keyEpoch: epoch, homeHostKey: home.hostKey };
}

/** Reverse-sorted copy, so the committed wire lists are never already in encoding order. */
function descending<T>(xs: T[], key: (t: T) => Buffer): T[] {
  return [...xs].sort((a, b) => Buffer.compare(key(b), key(a)));
}

function wireOrder(s: ManifestState): ManifestState {
  return {
    ...s,
    hosts: descending(s.hosts, (h) => h.hostKey),
    members: descending(s.members, (m) => m.ed25519PublicKey),
    removals: descending(s.removals, (r) => r.memberKey).map((r) => ({ ...r, frontier: descending(r.frontier, (id) => id) })),
  };
}

function commit(
  author: Party,
  repoId: string,
  parents: Buffer[],
  at: SignedManifest,
  plaintext: string,
): Commit {
  const epoch = at.state.keyEpoch;
  const aad = buildAadV2(repoId, epoch, author.edPub, parents);
  const ciphertext = aesGcmEncrypt(DATA_KEYS[epoch], PAYLOAD_IV, aad, Buffer.from(plaintext, "utf8"));
  return signCommit(
    { repoId, parents, manifestSeq: at.state.manifestSeq, manifestHash: manifestHash(at), keyEpoch: epoch, author: author.edPub, iv: PAYLOAD_IV, ciphertext },
    author.edSeed,
  );
}

function partySeed(p: Party) {
  return { label: p.label, ed25519SeedHex: hex(p.edSeed), ed25519PublicKey: b64(p.edPub), x25519PrivateHex: hex(p.xPriv), x25519PublicKey: b64(p.xPub) };
}

/** The parties and items of the 0.5 construction vectors, reused by the token, acceptance, and negative builders. */
interface Ctx {
  owner: Party;
  alice: Party;
  bob: Party;
  carol: Party;
  hostA: HostRef & { seed: Buffer; label: string };
  hostB: HostRef & { seed: Buffer; label: string };
  hosts: HostRef[];
  repoId: string;
  t0: number;
  m1: SignedManifest;
  m2: SignedManifest;
  c1: Commit;
  c2: Commit;
  c3: Commit;
}

function build05(): { bip39: any; manifest: any; commit: any; ctx: Ctx } {
  // bip39-owner.json
  const bipCases = [
    { name: "owner-counting-00", entropy: OWNER_ENTROPY },
    { name: "owner-counting-20", entropy: OWNER2_ENTROPY },
    { name: "owner-zero", entropy: Buffer.alloc(32) },
  ].map(({ name, entropy }) => {
    const mnemonic = entropyToMnemonic(entropy);
    const seed = mnemonicToSeed(mnemonic);
    const k = ownerKeysFromSeed(seed);
    return {
      name,
      entropyHex: hex(entropy),
      mnemonic,
      passphrase: "",
      seedHex: hex(seed),
      ed25519SeedHex: hex(k.ed25519Seed),
      ed25519PublicKeyHex: hex(k.ed25519Public),
      x25519PrivateHex: hex(k.x25519Private),
      x25519PublicKeyHex: hex(k.x25519Public),
    };
  });
  const bip39 = {
    description:
      "BIP39 owner identity (SPEC 3.1). Each case: 32 bytes of entropy, its 24-word English mnemonic (checksum = first 8 bits of SHA-256(entropy)), " +
      "seed = PBKDF2-HMAC-SHA512(NFKD(mnemonic), UTF8(\"mnemonic\") || NFKD(passphrase), 2048, 64) with the empty AVP passphrase, " +
      "ed25519Seed = HKDF-SHA256(seed, empty salt, \"avp/owner/ed25519/v1\", 32) and its public key (the ownerKey), " +
      "x25519Private = HKDF-SHA256(seed, empty salt, \"avp/owner/x25519/v1\", 32) and its public key. " +
      "`anchors` are three Trezor reference vectors (passphrase \"TREZOR\") that pin entropy to mnemonic to seed against an external implementation; " +
      "owner-zero shares its mnemonic with the first anchor. Generated by vectors/generate.ts.",
    wordlist: { file: "bip39-english.txt", sha256: BIP39_ENGLISH_SHA256, words: 2048 },
    anchors: { source: TREZOR_SOURCE, passphrase: "TREZOR", cases: TREZOR },
    cases: bipCases,
  };

  // parties
  const owner = ownerParty(OWNER_ENTROPY);
  const alice = memberParty("alice", 0x11);
  const bob = memberParty("bob", 0x22);
  const carol = memberParty("carol", 0x33);
  const hostA = hostRef(0xa0, "a.vault.example");
  const hostB = hostRef(0xb0, "b.vault.example");
  const hosts: HostRef[] = [
    { hostKey: hostA.hostKey, locator: hostA.locator },
    { hostKey: hostB.hostKey, locator: hostB.locator },
  ];
  const repoId = deriveRepoId(owner.edPub, GENESIS_NONCE);

  const base = (seq: number, prev: Buffer, keyEpoch: number, share: boolean, members: MemberEntry[], removals: Removal[]): ManifestState => ({
    repoId,
    manifestSeq: seq,
    prevManifestHash: prev,
    ownerKey: owner.edPub,
    genesisNonce: seq === 1 ? GENESIS_NONCE : Buffer.alloc(0),
    schemeId: WRAP_SCHEME_ID,
    keyEpoch,
    shareRefreshTokens: share,
    hosts,
    members,
    removals,
  });
  const sign = (s: ManifestState) => signManifest(wireOrder(s), owner.edSeed);

  // manifest seq 1 and 2, then commits under them, then seq 3 (removal citing two commits) and 4
  const m1 = sign(base(1, Buffer.alloc(0), 0, false, [member(owner, 0, hostA)], []));
  const m2 = sign(
    base(2, manifestHash(m1), 0, false, [member(owner, 0, hostA), member(alice, 0, hostA), member(bob, 0, hostB), member(carol, 0, hostB)], []),
  );

  const t0 = 1767225600000; // 2026-01-01T00:00:00Z
  const uuid1 = "00000000-0000-4000-8000-000000000001";
  const uuid2 = "00000000-0000-4000-8000-000000000002";
  const field = (value: unknown, at: number, n: number, by: Party) => ({ value, at, n, by: b64(by.edPub) });
  const ptRoot = JSON.stringify({ v: 2, accounts: {} });
  const ptChild = JSON.stringify({
    v: 2,
    accounts: { [uuid1]: { fields: { username: field("alt_one", t0, 0, alice), type: field("msa", t0, 0, alice) }, bans: {} } },
  });
  const ptMerge = JSON.stringify({
    v: 2,
    accounts: {
      [uuid1]: {
        fields: { username: field("alt_one", t0, 0, alice), type: field("msa", t0, 0, alice), lastUsedBy: field(b64(carol.edPub), t0 + 60000, 0, carol) },
        bans: { "mc.example": field(null, t0 + 60000, 1, carol) },
      },
      [uuid2]: { deleted: { at: t0 + 120000, n: 0, by: b64(carol.edPub) }, fields: { username: field("alt_two", t0, 0, bob) }, bans: {} },
    },
  });

  const c1 = commit(owner, repoId, [], m1, ptRoot);
  const c2 = commit(alice, repoId, [c1.commitId], m2, ptChild);
  const lowParent = Buffer.alloc(32, 0x00);
  const highParent = Buffer.alloc(32, 0xff);
  const c3 = commit(carol, repoId, [highParent, c2.commitId, lowParent], m2, ptMerge);

  const removalBob: Removal = { memberKey: bob.edPub, removedAtSeq: 3, frontier: [c1.commitId, c2.commitId] };
  const epoch1Members = [member(owner, 1, hostA), member(alice, 1, hostA), member(carol, 1, hostB)];
  const m3 = sign(base(3, manifestHash(m2), 1, false, epoch1Members, [removalBob]));
  const m4 = sign(base(4, manifestHash(m3), 1, true, epoch1Members, [removalBob]));

  const mcase = (name: string, note: string, m: SignedManifest) => ({
    name,
    note,
    signedManifest: signedManifestToWire(m),
    expected: {
      stateHex: hex(encodeManifestState(m.state)),
      manifestHashHex: hex(manifestHash(m)),
      ...(m.state.manifestSeq === 1 ? { repoId: deriveRepoId(m.state.ownerKey, m.state.genesisNonce) } : {}),
    },
  });

  const manifest = {
    description:
      "Manifest states (SPEC 4.1, 4.2): one owner-signed chain of four states. For each case: stateHex = the CE bytes S of signedManifest.state " +
      "(hosts sorted by hostKey, members by ed25519PublicKey, removals by memberKey, frontier ids sorted, all unsigned bytewise), " +
      "signedManifest.ownerSignature = Ed25519-Sign(ownerKey, S), manifestHashHex = SHA-256(S || ownerSignature), and at seq 1 repoId = " +
      "base64url-nopad(SHA-256(CE(tag \"avp/repo-id/v1\", bytes(ownerKey), bytes(genesisNonce)))[0..16]). The wire lists are stored in descending " +
      "order on purpose: an encoder that does not sort fails. The removal frontier ids are the root and single-parent commit ids of commit.json. " +
      "Generated by vectors/generate.ts from `seeds`.",
    seeds: {
      owner: {
        entropyHex: hex(OWNER_ENTROPY),
        ed25519SeedHex: hex(owner.edSeed),
        ownerKey: b64(owner.edPub),
        x25519PrivateHex: hex(owner.xPriv),
        x25519PublicKey: b64(owner.xPub),
      },
      hosts: [hostA, hostB].map((h) => ({ label: h.label, ed25519SeedHex: hex(h.seed), hostKey: b64(h.hostKey), locator: h.locator })),
      members: [alice, bob, carol].map(partySeed),
      genesisNonceHex: hex(GENESIS_NONCE),
      dataKeys: Object.entries(DATA_KEYS).map(([e, k]) => ({ keyEpoch: Number(e), dataKeyHex: hex(k) })),
      wrapDerivation: WRAP_DERIVATION,
    },
    cases: [
      mcase("genesis", "seq 1: empty prevManifestHash, 16-byte genesisNonce, keyEpoch 0, two hosts, the owner as the only member, no removals.", m1),
      mcase("add-members", "seq 2: alice (home a), bob and carol (home b) added at epoch 0; genesisNonce empty from here on.", m2),
      mcase(
        "remove-member",
        "seq 3: bob removed with a two-id frontier (commit.json root and single-parent), keyEpoch bumped to 1 and the epoch 1 data key rewrapped to the remaining members.",
        m3,
      ),
      mcase("policy-flip", "seq 4: shareRefreshTokens turned on; members unchanged; bob's removal repeated unchanged (removals are cumulative).", m4),
    ],
  };

  const ccase = (name: string, note: string, author: Party, plaintext: string, c: Commit) => ({
    name,
    note,
    authorLabel: author.label,
    plaintextUtf8: plaintext,
    commit: commitToWire(c),
    expected: {
      headerHex: hex(encodeCommitHeader(c)),
      commitIdHex: hex(c.commitId),
      aadHex: hex(buildAadV2(c.repoId, c.keyEpoch, c.author, c.parents)),
    },
  });

  const commitFile = {
    description:
      "Commits (SPEC 4.3). For each case: headerHex = the CE header H (parents sorted unsigned bytewise), commitIdHex = SHA-256(H) (also commit.commitId), " +
      "commit.authorSignature = Ed25519-Sign(author, CE(tag \"avp/commit-sig/v1\", bytes(commitId))), aadHex = AAD v2, and commit.ciphertext = " +
      "AES-256-GCM(dataKey, iv, AAD v2, plaintextUtf8) with the 16-byte tag appended. Each commit cites a manifest.json state by manifestSeq and manifestHash. " +
      "The data key and IV are fixed only so the vectors are reproducible (one IV under one key for several plaintexts is never acceptable outside test vectors; " +
      "real clients MUST use a fresh random IV per commit). The merge's parents 0x00..00 and 0xff..ff are synthetic ids that pin sorting at both ends; " +
      "graph validity is the subject of acceptance.json, not of this file. The wire parents are stored unsorted on purpose. Generated by vectors/generate.ts from `seeds`.",
    seeds: {
      dataKeyHex: hex(DATA_KEYS[0]),
      ivHex: hex(PAYLOAD_IV),
      authors: [owner, alice, carol].map((p) => ({ label: p.label, ed25519SeedHex: hex(p.edSeed), ed25519PublicKey: b64(p.edPub) })),
    },
    cases: [
      ccase("root", "the first commit: no parents, by the owner under the genesis state (seq 1, epoch 0).", owner, ptRoot, c1),
      ccase("single-parent", "alice's child of root under seq 2.", alice, ptChild, c2),
      ccase("three-parent-merge", "carol's merge of single-parent and two synthetic ids under seq 2, input order high, mid, low.", carol, ptMerge, c3),
    ],
  };

  const ctx: Ctx = { owner, alice, bob, carol, hostA, hostB, hosts, repoId, t0, m1, m2, c1, c2, c3 };
  return { bip39, manifest, commit: commitFile, ctx };
}

/** Checks the library against the Trezor anchors, so a broken BIP39 cannot regenerate silently. */
function checkAnchors(r: Check[]): void {
  for (const a of TREZOR) {
    eq(`bip39 trezor ${a.entropyHex.slice(0, 8)} mnemonic`, entropyToMnemonic(fromHex(a.entropyHex)), a.mnemonic, r);
    eq(`bip39 trezor ${a.entropyHex.slice(0, 8)} entropy`, hex(mnemonicToEntropy(a.mnemonic)), a.entropyHex, r);
    eq(`bip39 trezor ${a.entropyHex.slice(0, 8)} seed`, hex(mnemonicToSeed(a.mnemonic, "TREZOR")), a.seedHex, r);
  }
}

function checkGenerated(file: string, want: any, r: Check[]): void {
  let got: any;
  try {
    got = read(file);
  } catch {
    eq(`${file} exists`, "missing", "present", r);
    return;
  }
  for (const k of Object.keys(want)) {
    if (!Array.isArray(want[k])) {
      eq(`${file} ${k}`, JSON.stringify(got[k]), JSON.stringify(want[k]), r);
      continue;
    }
    // A list of named items: report each drifted item by name.
    eq(`${file} ${k} count`, String(got[k]?.length), String(want[k].length), r);
    for (const c of want[k]) {
      const g = (got[k] ?? []).find((x: any) => x.name === c.name);
      eq(`${file} ${k} ${c.name}`, JSON.stringify(g), JSON.stringify(c), r);
    }
  }
  eq(`${file} matches generator output`, JSON.stringify(got), JSON.stringify(want), r);
}

// ─── merge.json: payload v2 merge and the HLC (SPEC 5, 5.1), hand-written ─────────

/**
 * Member ids (SPEC 2: base64 of the Ed25519 public key) of alice (seed 0x11), bob (0x22), and carol
 * (0x33), written out so the merge vectors are literal data. By UTF-8 bytes, alice ("0", 0x30) <
 * carol ("F", 0x46) < bob ("o", 0x6f). buildMerge checks them against the derived keys.
 */
const ID_ALICE = "0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc=";
const ID_BOB = "oJql9HpnWYAv+VX43C0qFKXJnSO+l/hkEn/5ODRVpPA=";
const ID_CAROL = "F8t5+ytBIPKx7GXkGY1uCLKOgT/rAeSkAIObheGAgM4=";

/**
 * The merge cases. Every `expected` and `expectedDeleted` below is written by hand from SPEC 5
 * (greatest stamp per field and per ban server id, greatest `deleted`, deleted iff `deleted` is
 * strictly greater than every field and ban stamp) and SPEC 5.1 (strip removes `refreshToken` and
 * `expiresAt` with their stamps). None of it is computed by the merge under test.
 */
function buildMerge(ctx: Ctx): any {
  const derived = [ctx.alice, ctx.bob, ctx.carol].map((p) => b64(p.edPub));
  if (derived.join() !== [ID_ALICE, ID_BOB, ID_CAROL].join()) throw new Error("merge member ids drifted from the party seeds");
  const A = ID_ALICE;
  const B = ID_BOB;
  const C = ID_CAROL;
  const T0 = 1767225600000;
  const f = (value: unknown, at: number, n: number, by: string) => ({ value, at, n, by });
  const s = (at: number, n: number, by: string) => ({ at, n, by });
  const U1 = "00000000-0000-4000-8000-000000000001";
  const U2 = "00000000-0000-4000-8000-000000000002";
  const pl = (accounts: Record<string, unknown>) => ({ v: 2, accounts });
  const banKick = { banned: true, observedAt: T0, source: "kick", detail: "banned for 7d", observedBy: A };
  const banLifted = { banned: false, observedAt: T0 + 500, source: "join", detail: "joined fine", observedBy: B };
  const banPvp = { banned: true, observedAt: T0 + 20, source: "kick", detail: "cheating", observedBy: null };

  const cases = [
    {
      name: "field-conflict-newest-wins",
      note: "username: the later at wins. accessToken: equal at, so the greater n (2, alice) wins over carol's n 1 although carol's id is greater; n is compared before by.",
      inputs: [
        pl({ [U1]: { fields: { username: f("old_name", T0, 0, A), accessToken: f("tok-alice", T0 + 5, 2, A) }, bans: {} } }),
        pl({ [U1]: { fields: { username: f("new_name", T0 + 1000, 0, B), accessToken: f("tok-carol", T0 + 5, 1, C) }, bans: {} } }),
      ],
      expected: pl({ [U1]: { fields: { accessToken: f("tok-alice", T0 + 5, 2, A), username: f("new_name", T0 + 1000, 0, B) }, bans: {} } }),
      expectedDeleted: { [U1]: false },
    },
    {
      name: "tie-broken-by-member-id",
      note: "three writes with equal at and n: by decides, compared by UTF-8 bytes; bob's id (first byte 0x6f) is the greatest.",
      inputs: [
        pl({ [U1]: { fields: { username: f("from_alice", T0, 0, A) }, bans: {} } }),
        pl({ [U1]: { fields: { username: f("from_bob", T0, 0, B) }, bans: {} } }),
        pl({ [U1]: { fields: { username: f("from_carol", T0, 0, C) }, bans: {} } }),
      ],
      expected: pl({ [U1]: { fields: { username: f("from_bob", T0, 0, B) }, bans: {} } }),
      expectedDeleted: { [U1]: false },
    },
    {
      name: "different-fields-both-kept",
      note: "disjoint fields, disjoint ban servers, and disjoint accounts: the result is the union, nothing lost.",
      inputs: [
        pl({ [U1]: { fields: { username: f("alt_one", T0, 0, A) }, bans: { "mc.example": f(banKick, T0, 0, A) } } }),
        pl({
          [U1]: { fields: { type: f("MICROSOFT", T0 + 10, 0, B) }, bans: { "play.example": f(null, T0 + 10, 0, B) } },
          [U2]: { fields: { username: f("alt_two", T0 + 20, 0, B) }, bans: {} },
        }),
      ],
      expected: pl({
        [U1]: {
          fields: { type: f("MICROSOFT", T0 + 10, 0, B), username: f("alt_one", T0, 0, A) },
          bans: { "mc.example": f(banKick, T0, 0, A), "play.example": f(null, T0 + 10, 0, B) },
        },
        [U2]: { fields: { username: f("alt_two", T0 + 20, 0, B) }, bans: {} },
      }),
      expectedDeleted: { [U1]: false, [U2]: false },
    },
    {
      name: "delete-then-edit-revives",
      note: "alice deletes at T0+100; bob sets lastUsed at T0+200. The marker is kept but is not greater than every stamp, so the account is live.",
      inputs: [
        pl({ [U1]: { deleted: s(T0 + 100, 0, A), fields: { username: f("alt_one", T0, 0, A) }, bans: {} } }),
        pl({ [U1]: { fields: { username: f("alt_one", T0, 0, A), lastUsed: f(T0 + 200, T0 + 200, 0, B) }, bans: {} } }),
      ],
      expected: pl({
        [U1]: { deleted: s(T0 + 100, 0, A), fields: { lastUsed: f(T0 + 200, T0 + 200, 0, B), username: f("alt_one", T0, 0, A) }, bans: {} },
      }),
      expectedDeleted: { [U1]: false },
    },
    {
      name: "edit-then-delete-removes",
      note: "bob renames at T0+100; alice deletes at T0+200, after every field stamp, so the account is deleted (its fields stay). u2's marker equals its field stamp, which is not strictly greater, so u2 is live.",
      inputs: [
        pl({
          [U1]: { fields: { username: f("renamed", T0 + 100, 0, B) }, bans: {} },
          [U2]: { deleted: s(T0 + 50, 0, C), fields: { username: f("alt_two", T0 + 50, 0, C) }, bans: {} },
        }),
        pl({ [U1]: { deleted: s(T0 + 200, 0, A), fields: { username: f("orig", T0, 0, A) }, bans: {} } }),
      ],
      expected: pl({
        [U1]: { deleted: s(T0 + 200, 0, A), fields: { username: f("renamed", T0 + 100, 0, B) }, bans: {} },
        [U2]: { deleted: s(T0 + 50, 0, C), fields: { username: f("alt_two", T0 + 50, 0, C) }, bans: {} },
      }),
      expectedDeleted: { [U1]: true, [U2]: false },
    },
    {
      name: "three-way",
      note: "each input wins one field: username from alice, type from bob, accessToken from carol; carol's old marker survives as the only deleted stamp but does not delete.",
      inputs: [
        pl({ [U1]: { fields: { username: f("name_alice", T0 + 300, 0, A), type: f("COOKIE", T0, 0, A) }, bans: {} } }),
        pl({ [U1]: { fields: { type: f("MICROSOFT", T0 + 400, 0, B), accessToken: f("tok-bob", T0 + 100, 0, B) }, bans: {} } }),
        pl({
          [U1]: {
            deleted: s(T0 + 1, 0, C),
            fields: { accessToken: f("tok-carol", T0 + 500, 0, C), username: f("name_carol", T0 + 200, 0, C) },
            bans: {},
          },
        }),
      ],
      expected: pl({
        [U1]: {
          deleted: s(T0 + 1, 0, C),
          fields: { accessToken: f("tok-carol", T0 + 500, 0, C), type: f("MICROSOFT", T0 + 400, 0, B), username: f("name_alice", T0 + 300, 0, A) },
          bans: {},
        },
      }),
      expectedDeleted: { [U1]: false },
    },
    {
      name: "bans-per-server",
      note: "bans merge per server id: mc.example takes bob's later lift, play.example keeps alice's null, pvp.example keeps bob's ban.",
      inputs: [
        pl({
          [U1]: {
            fields: { username: f("alt_one", T0, 0, A) },
            bans: { "mc.example": f(banKick, T0, 0, A), "play.example": f(null, T0 + 10, 0, A) },
          },
        }),
        pl({ [U1]: { fields: {}, bans: { "mc.example": f(banLifted, T0 + 500, 0, B), "pvp.example": f(banPvp, T0 + 20, 0, B) } } }),
      ],
      expected: pl({
        [U1]: {
          fields: { username: f("alt_one", T0, 0, A) },
          bans: { "mc.example": f(banLifted, T0 + 500, 0, B), "play.example": f(null, T0 + 10, 0, A), "pvp.example": f(banPvp, T0 + 20, 0, B) },
        },
      }),
      expectedDeleted: { [U1]: false },
    },
    {
      name: "strip-after-policy-off",
      stripRefresh: true,
      note: "heads written while shareRefreshTokens was true carry refreshToken and expiresAt; with the policy now false the merged result is stripped: both fields and their stamps are gone from every account (u2 is left with no fields).",
      inputs: [
        pl({
          [U1]: {
            fields: {
              username: f("alt_one", T0, 0, A),
              accessToken: f("tok-1", T0 + 100, 0, A),
              refreshToken: f("rt-1", T0 + 100, 0, A),
              expiresAt: f(T0 + 3600000, T0 + 100, 0, A),
            },
            bans: {},
          },
        }),
        pl({
          [U1]: {
            fields: { refreshToken: f("rt-2", T0 + 200, 0, B), expiresAt: f(T0 + 7200000, T0 + 200, 0, B), lastUsed: f(T0 + 200, T0 + 200, 0, B) },
            bans: {},
          },
          [U2]: { fields: { refreshToken: f(null, T0 + 300, 0, C) }, bans: {} },
        }),
      ],
      expected: pl({
        [U1]: { fields: { accessToken: f("tok-1", T0 + 100, 0, A), lastUsed: f(T0 + 200, T0 + 200, 0, B), username: f("alt_one", T0, 0, A) }, bans: {} },
        [U2]: { fields: {}, bans: {} },
      }),
      expectedDeleted: { [U1]: false, [U2]: false },
    },
    {
      name: "strip-then-deleted",
      stripRefresh: true,
      note: "alice deletes at T0+100; bob's refreshToken at T0+200 is the only stamp above the marker. Unstripped, the account is live; with the policy false the stripped result carries no refreshToken, every remaining stamp is below the marker, and the account is deleted.",
      inputs: [
        pl({ [U1]: { deleted: s(T0 + 100, 0, A), fields: { username: f("alt_one", T0, 0, A) }, bans: {} } }),
        pl({ [U1]: { fields: { username: f("alt_one", T0, 0, A), refreshToken: f("rt-late", T0 + 200, 0, B) }, bans: {} } }),
      ],
      expected: pl({ [U1]: { deleted: s(T0 + 100, 0, A), fields: { username: f("alt_one", T0, 0, A) }, bans: {} } }),
      expectedDeleted: { [U1]: true },
    },
  ];

  const hlc = [
    {
      name: "tick-follows-wall-clock",
      note: "tick(now) is (now, 0) when now > at, else (at, n + 1), so a clock that stalls or steps back still issues increasing stamps.",
      start: { at: 0, n: 0 },
      steps: [
        { op: "tick", now: 1000, expect: { at: 1000, n: 0 } },
        { op: "tick", now: 1000, expect: { at: 1000, n: 1 } },
        { op: "tick", now: 999, expect: { at: 1000, n: 2 } },
        { op: "tick", now: 1001, expect: { at: 1001, n: 0 } },
      ],
    },
    {
      name: "observe-then-tick",
      note: "observe takes a later at with its n, the larger n at an equal at, and ignores an earlier at; the next tick then exceeds every observed stamp.",
      start: { at: 1000, n: 0 },
      steps: [
        { op: "observe", stamp: { at: 5000, n: 3, by: A }, expect: { at: 5000, n: 3 } },
        { op: "tick", now: 2000, expect: { at: 5000, n: 4 } },
        { op: "observe", stamp: { at: 5000, n: 9, by: B }, expect: { at: 5000, n: 9 } },
        { op: "observe", stamp: { at: 4000, n: 50, by: C }, expect: { at: 5000, n: 9 } },
        { op: "observe", stamp: { at: 5000, n: 2, by: C }, expect: { at: 5000, n: 9 } },
        { op: "tick", now: 6000, expect: { at: 6000, n: 0 } },
      ],
    },
    {
      name: "observe-later-at-resets-n",
      note: "a later at replaces the state outright, n included, even when the local n was larger.",
      start: { at: 7000, n: 8 },
      steps: [
        { op: "observe", stamp: { at: 7001, n: 0, by: A }, expect: { at: 7001, n: 0 } },
        { op: "tick", now: 7001, expect: { at: 7001, n: 1 } },
      ],
    },
  ];

  return {
    description:
      "Payload v2 merge (SPEC 5, 5.1). Each case: merging `inputs` in every order MUST give `expected` (commutativity), merging `expected` with any input or itself MUST " +
      "give `expected` (idempotence), and merge MUST be associative. When `stripRefresh` is true the result is stripped (SPEC 5.1: refreshToken and expiresAt removed with " +
      "their stamps) after the merge. `expectedDeleted` is the SPEC 5 deletion state of each account. Stamps order by at, then n, then by compared by its UTF-8 bytes. " +
      "`hlc` pins the hybrid logical clock: start at `start`, apply each step, and the state MUST equal `expect` after it (tick returns the new state). " +
      "The expected values are written by hand from the SPEC rule. Member ids are base64 Ed25519 keys of alice (seed 0x11), bob (0x22), carol (0x33) as in manifest.json. " +
      "Generated by vectors/generate.ts.",
    cases,
    hlc,
  };
}

// ─── federation.json: tokens, signatures, fingerprints, linking (SPEC 11) ─────────

const LINK_EPHEMERAL = (i: number) => sha256(Buffer.from(`avp/vectors/link-ephemeral/${i}`, "utf8"));

function token(name: string, schema: string, direction: string, decoded: any, extra: Record<string, unknown> = {}) {
  const canonicalJson = JSON.stringify(decoded);
  return { name, schema, direction, decoded, canonicalJson, base64url: Buffer.from(canonicalJson, "utf8").toString("base64url"), ...extra };
}

interface FedItems {
  acceptance: Acceptance;
  aliceLeave: LeaveRequest;
  linkEphemeralPriv: Buffer;
  grantWrap: ReturnType<typeof wrapSecret>;
}

function buildFederation(ctx: Ctx): { file: any; items: FedItems } {
  const { owner, alice, bob, hostA, hostB, repoId, t0 } = ctx;
  const acceptance = signAcceptance({ repoId, memberKey: alice.edPub, hostKey: hostB.hostKey, expiresAt: t0 + 15 * 60_000 }, hostB.seed);
  const invite = {
    v: 2,
    ed25519PublicKey: b64(alice.edPub),
    x25519PublicKey: b64(alice.xPub),
    homeHostKey: b64(hostB.hostKey),
    homeHostLocator: hostB.locator,
    acceptance: acceptanceToWire(acceptance),
  };
  const fp = ownerFingerprint(owner.edPub);
  const locator = (hostLocator: string) => ({ v: 2, repoId, hostKey: b64(hostA.hostKey), hostLocator, ownerFingerprint: fp });

  const linkEphemeralPriv = LINK_EPHEMERAL(0);
  const linkPub = x25519PublicRaw(importX25519Private(linkEphemeralPriv));
  const grantWrap = wrapSecret(
    linkPub,
    sha256(Buffer.from("avp/vectors/link-wrap-ephemeral", "utf8")),
    sha256(Buffer.from("avp/vectors/link-wrap-iv", "utf8")).subarray(0, 12),
    OWNER_ENTROPY,
    OWNER_LINK_INFO,
  );

  const aliceLeave = signLeave({ repoId, memberKey: alice.edPub, at: t0 + 3_600_000 }, alice.edSeed);
  const bobLeave = signLeave({ repoId, memberKey: bob.edPub, at: t0 + 7_200_000 }, bob.edSeed);
  const leaveCase = (name: string, l: LeaveRequest) => ({
    name,
    schema: "LeaveRequest",
    decoded: leaveToWire(l),
    signatureMessageHex: hex(leaveSignMessage(l)),
  });

  // A second link key whose code has a leading zero, found by counting up, so zero padding is pinned.
  let zeroIdx = 1;
  while (!linkConfirmationCode(x25519PublicRaw(importX25519Private(LINK_EPHEMERAL(zeroIdx)))).startsWith("0")) zeroIdx++;
  const zeroPub = x25519PublicRaw(importX25519Private(LINK_EPHEMERAL(zeroIdx)));

  const file = {
    description:
      "Out-of-band tokens and addressing (SPEC 11). Tokens are base64url-nopad (RFC 4648 section 5) over compact JSON with the fields in the SPEC order and \"v\": 2. " +
      "Each token case is a decode oracle (decoding `base64url` MUST yield `decoded`) and an encode check (`canonicalJson` is the compact form, `base64url` its encoding). " +
      "The invite token's acceptance is signed by the joiner's home host (b.vault.example) over `acceptanceMessageHex` = CE(tag \"avp/accept/v1\", str(repoId), " +
      "bytes(memberKey), bytes(hostKey), i64(expiresAt)). `leaves` are leave request bodies (JSON, not base64url-wrapped) signed by memberKey over `signatureMessageHex` = " +
      "CE(tag \"avp/leave/v1\", str(repoId), bytes(memberKey), i64(at)). `linkCodes` are SPEC 11.6 confirmation codes. The link grant wraps the owner's 32-byte mnemonic " +
      "entropy to the link request's ephemeral key under info avp/owner-link/v1; `checker` holds the link private key (never on the wire) and the expected entropy. " +
      "`fingerprints` pin the member key fingerprint (SPEC 3.2) and owner fingerprint (SPEC 11.2). Keys, hosts, and repoId are those of manifest.json; the link keys are " +
      "SHA-256(UTF8(\"avp/vectors/link-ephemeral/\" + i)) and the grant's wrap ephemeral key and IV are SHA-256 of \"avp/vectors/link-wrap-ephemeral\" and " +
      "\"avp/vectors/link-wrap-iv\" (first 12 bytes), fixed only for reproducibility. The avp-uri cases pin parse and format of avp://<hostLocator>/<repoId>. " +
      "Generated by vectors/generate.ts.",
    tokens: [
      token("invite-token", "InviteToken", "joiner -> owner", invite, { acceptanceMessageHex: hex(acceptanceSignMessage(acceptance)) }),
      token("repo-locator", "RepoLocator", "owner -> joiner", locator(hostA.locator)),
      token("repo-locator-port", "RepoLocator", "owner -> joiner", locator(`${hostA.locator}:8443`)),
      token("link-request", "LinkRequest", "new owner device -> existing owner device", { v: 2, ephemeralPublicKey: b64(linkPub) }),
      token(
        "link-grant",
        "LinkGrant",
        "existing owner device -> new owner device",
        {
          v: 2,
          wrap: { schemeId: grantWrap.schemeId, ephemeralPublicKey: b64(grantWrap.ephemeralPublicKey), iv: b64(grantWrap.iv), ciphertext: b64(grantWrap.ciphertext) },
        },
        { checker: { linkEphemeralPrivateHex: hex(linkEphemeralPriv), entropyHex: hex(OWNER_ENTROPY) } },
      ),
    ],
    leaves: [leaveCase("alice-leaves", aliceLeave), leaveCase("bob-leaves", bobLeave)],
    linkCodes: [
      { name: "link-request", ephemeralPublicKey: b64(linkPub), code: linkConfirmationCode(linkPub) },
      { name: "leading-zero", ephemeralPublicKey: b64(zeroPub), code: linkConfirmationCode(zeroPub) },
    ],
    fingerprints: {
      members: [ctx.alice, ctx.bob, ctx.carol].map((p) => ({
        label: p.label,
        ed25519PublicKey: b64(p.edPub),
        x25519PublicKey: b64(p.xPub),
        fingerprint: keyFingerprint(p.edPub, p.xPub),
      })),
      owner: { ownerKey: b64(owner.edPub), ownerFingerprint: fp },
    },
    uris: [
      { name: "plain-host", uri: `avp://${hostA.locator}/${repoId}`, host: hostA.locator, repoId },
      { name: "host-with-port", uri: `avp://${hostA.locator}:8443/${repoId}`, host: `${hostA.locator}:8443`, repoId },
    ],
  };
  return { file, items: { acceptance, aliceLeave, linkEphemeralPriv, grantWrap } };
}

// ─── acceptance.json: host acceptance scenarios (SPEC 6, 7, 8.3, 8.4) ─────────────

/**
 * Builds the shared host acceptance scenarios. The signed items (states, commits, leave requests)
 * are built from the manifest.json seeds; every `expect`, `finalHeads`, `finalHeld`, and `finalTip`
 * below is written by hand from the SPEC rule named in the scenario's description, never captured
 * from a rules engine.
 */
function buildAcceptance(ctx: Ctx): any {
  const { owner, alice, bob, carol, hostA, hostB, repoId } = ctx;
  const ref = (h: HostRef) => ({ hostKey: h.hostKey, locator: h.locator });
  const HOSTS = [ref(hostA), ref(hostB)];
  const EMPTY = Buffer.alloc(0);
  const PLAINTEXT = Buffer.from(JSON.stringify({ v: 2, accounts: {} }), "utf8");
  const labels = new Map<Commit, string>();
  // The manifest.json data keys, plus an epoch 2 key used only by the epoch-jump scenario.
  const KEYS: Record<number, Buffer> = { ...DATA_KEYS, 2: Buffer.alloc(32, 0x44) };

  // Member wraps as in manifest.json; a non-empty `tweak` varies the wrap ephemeral key and IV, which
  // is owner-chosen randomness, to order two diverged states by manifestHash deterministically.
  const entry = (p: Party, epoch: number, home: HostRef, tweak: string): MemberEntry => {
    const l = tweak === "" ? p.label : `${p.label}/${tweak}`;
    const w = wrapSecret(p.xPub, wrapEphemeral(epoch, l), wrapIv(epoch, l), KEYS[epoch]);
    return { ed25519PublicKey: p.edPub, x25519PublicKey: p.xPub, wrappedDataKey: w, keyEpoch: epoch, homeHostKey: home.hostKey };
  };

  interface StOpts {
    share?: boolean;
    hosts?: HostRef[];
    repoId?: string;
    signer?: Party;
    tweak?: string;
    removals?: Removal[];
  }
  const state = (seq: number, prev: SignedManifest | null, epoch: number, members: Array<[Party, HostRef]>, o: StOpts = {}): SignedManifest => {
    const s: ManifestState = {
      repoId: o.repoId ?? repoId,
      manifestSeq: seq,
      prevManifestHash: prev ? manifestHash(prev) : EMPTY,
      ownerKey: owner.edPub,
      genesisNonce: seq === 1 ? GENESIS_NONCE : EMPTY,
      schemeId: WRAP_SCHEME_ID,
      keyEpoch: epoch,
      shareRefreshTokens: o.share ?? false,
      hosts: o.hosts ?? HOSTS,
      members: members.map(([p, h]) => entry(p, epoch, h, o.tweak ?? "")),
      removals: o.removals ?? [],
    };
    return signManifest(wireOrder(s), (o.signer ?? owner).edSeed);
  };
  /** The first build whose manifestHash is above `other`'s, counting the tweak up from g0. */
  const above = (build: (tweak: string) => SignedManifest, other: SignedManifest): SignedManifest => {
    for (let i = 0; ; i++) {
      const m = build(`g${i}`);
      if (Buffer.compare(manifestHash(m), manifestHash(other)) > 0) return m;
    }
  };

  interface CmOpts {
    epoch?: number;
    seq?: number;
    repoId?: string;
  }
  const cm = (label: string, author: Party, parents: Commit[], at: SignedManifest, o: CmOpts = {}): Commit => {
    const epoch = o.epoch ?? at.state.keyEpoch;
    const rid = o.repoId ?? at.state.repoId;
    const ids = parents.map((p) => p.commitId);
    const iv = sha256(Buffer.from(`avp/vectors/acceptance-iv/${label}`, "utf8")).subarray(0, 12);
    const ciphertext = aesGcmEncrypt(KEYS[epoch], iv, buildAadV2(rid, epoch, author.edPub, ids), PLAINTEXT);
    const c = signCommit(
      { repoId: rid, parents: ids, manifestSeq: o.seq ?? at.state.manifestSeq, manifestHash: manifestHash(at), keyEpoch: epoch, author: author.edPub, iv, ciphertext },
      author.edSeed,
    );
    labels.set(c, label);
    return c;
  };
  const removal = (p: Party, seq: number, frontier: Commit[]): Removal => ({ memberKey: p.edPub, removedAtSeq: seq, frontier: frontier.map((c) => c.commitId) });

  type Expect = "ok" | "bad_request" | "forbidden" | "not_hosted" | "too_many_heads" | "manifest_conflict" | "missing_parents";
  const M = (label: string, m: SignedManifest, expect: Expect, via: "push" | "offer" = "push", commit?: Commit) => ({
    op: "manifest",
    via,
    label: commit ? `${label} + ${labels.get(commit)}` : label,
    item: commit ? { manifest: signedManifestToWire(m), commit: commitToWire(commit) } : { manifest: signedManifestToWire(m) },
    expect,
  });
  const C = (c: Commit, expect: Expect, via: "push" | "offer" = "push", label?: string) => ({
    op: "commit",
    via,
    label: label ?? (labels.get(c) as string),
    item: commitToWire(c),
    expect,
  });
  const L = (label: string, l: LeaveRequest, expect: Expect) => ({ op: "leave", via: "push", label, item: leaveToWire(l), expect });
  const ids = (cs: Commit[]) => cs.map((c) => b64(c.commitId)).sort();
  const scenario = (
    name: string,
    description: string,
    steps: any[],
    finalHeads: Commit[],
    finalHeld: Commit[],
    finalTip: SignedManifest | null,
    finalLeaves?: LeaveRequest[],
  ) => ({
    name,
    description,
    hostKey: b64(hostA.hostKey),
    headBound: 16,
    steps,
    finalHeads: ids(finalHeads),
    finalHeld: ids(finalHeld),
    finalTip: finalTip ? b64(manifestHash(finalTip)) : null,
    ...(finalLeaves
      ? { finalLeaves: finalLeaves.map((l) => ({ memberKey: b64(l.memberKey), at: l.at })).sort((x, y) => (x.memberKey < y.memberKey ? -1 : 1)) }
      : {}),
  });
  /** A manifest step from a wire object, for structurally malformed items that cannot be decoded and signed. */
  const MW = (label: string, wire: unknown, expect: Expect) => ({ op: "manifest", via: "push", label, item: { manifest: wire }, expect });
  /** A commit step from a wire object. */
  const CW = (label: string, wire: unknown, expect: Expect) => ({ op: "commit", via: "push", label, item: wire, expect });
  /** Re-signs a changed copy of a state, for content-rule violations the state builder cannot express. */
  const resign = (m: SignedManifest, change: (s: ManifestState) => ManifestState, signer: Party = owner): SignedManifest =>
    signManifest(wireOrder(change({ ...m.state })), signer.edSeed);

  // The common start: genesis (owner only, hosts a and b, owner home a) published with its first commit.
  const G = state(1, null, 0, [[owner, hostA]]);
  const r = cm("r", owner, [], G);
  const genesis = M("G", G, "ok", "push", r);
  // seq 2 states on G.
  const M2a = state(2, G, 0, [[owner, hostA], [alice, hostA]]);
  const M2ab = state(2, G, 0, [[owner, hostA], [alice, hostA], [bob, hostB]]);
  const sixteen = (at: SignedManifest) => Array.from({ length: 16 }, (_, i) => cm(`head-${i + 1}`, alice, [r], at));

  const scenarios: any[] = [];
  const add = (...args: Parameters<typeof scenario>) => scenarios.push(scenario(...args));

  // ── genesis (SPEC 6.1, 6.2, 8.2) ──
  add(
    "genesis-ok",
    "SPEC 6.2, 8.2: a valid genesis state that lists this host, published with a first commit that has no parents, cites seq 1 and the genesis hash, is by the owner at epoch 0: both are accepted and the commit is the only head.",
    [genesis],
    [r],
    [],
    G,
  );
  {
    const Gx = state(1, null, 0, [[owner, hostA]], { repoId: deriveRepoId(owner.edPub, Buffer.alloc(16, 0x02)) });
    add(
      "genesis-wrong-repo-id",
      "SPEC 6.2, 4.2: the genesis repoId does not recompute from ownerKey and genesisNonce (it was derived from another nonce), so the state is rejected (bad_request) and its commit with it.",
      [M("G-wrong-repo-id", Gx, "bad_request", "push", cm("r-wrong-repo", owner, [], Gx))],
      [],
      [],
      null,
    );
  }
  {
    const Gb = state(1, null, 0, [[owner, hostB]], { hosts: [ref(hostB)] });
    add(
      "genesis-host-not-listed",
      "SPEC 6.1 rule 6, 8.2: a valid genesis whose hosts list only b.vault.example, applied at a.vault.example: not_hosted, nothing stored.",
      [M("G-hosts-b-only", Gb, "not_hosted", "push", cm("r-b", owner, [], Gb))],
      [],
      [],
      null,
    );
  }

  // ── manifest chain (SPEC 6.1, 6.3, 6.4) ──
  {
    const M3 = state(3, M2a, 0, [[owner, hostA], [alice, hostA], [bob, hostB]]);
    add(
      "manifest-seq-skip",
      "SPEC 6.1 rule 4, 6.3: a seq 3 state arrives while the tip is seq 1 (its seq 2 predecessor never arrived); its seq is not tip + 1, so manifest_conflict.",
      [genesis, M("M3", M3, "manifest_conflict")],
      [r],
      [],
      G,
    );
  }
  {
    const forged = state(2, G, 0, [[owner, hostA], [alice, hostA]], { signer: alice });
    add(
      "manifest-bad-owner-sig",
      "SPEC 6.1 rule 2: a seq 2 state whose ownerSignature is alice's signature, not the owner's: bad_request; the tip stays at genesis.",
      [genesis, M("M2-signed-by-alice", forged, "bad_request")],
      [r],
      [],
      G,
    );
  }
  {
    const M3 = state(3, M2a, 0, [[owner, hostA], [alice, hostA], [bob, hostB]]);
    add(
      "manifest-rollback",
      "SPEC 6.3, 6.4, 12.3: after seq 2 and seq 3 are accepted, the seq 2 state is published again; its seq is not tip + 1, so manifest_conflict, and the tip stays at seq 3.",
      [genesis, M("M2", M2a, "ok"), M("M3", M3, "ok"), M("M2-again", M2a, "manifest_conflict")],
      [r],
      [],
      M3,
    );
  }
  {
    const M3 = state(3, M2ab, 0, [[owner, hostA], [alice, hostA]]);
    add(
      "manifest-member-dropped-without-removal",
      "SPEC 6.1 rule 5: a seq 3 state drops bob from members without a removal: bad_request.",
      [genesis, M("M2", M2ab, "ok"), M("M3-drops-bob", M3, "bad_request")],
      [r],
      [],
      M2ab,
    );
  }
  {
    const M3 = state(3, M2ab, 0, [[owner, hostA], [alice, hostA]], { removals: [removal(bob, 3, [r])] });
    add(
      "manifest-removal-without-epoch-bump",
      "SPEC 6.1 rule 5: a seq 3 state adds a removal but keeps keyEpoch 0; a state that adds a removal MUST raise keyEpoch by one: bad_request.",
      [genesis, M("M2", M2ab, "ok"), M("M3-removal-epoch-0", M3, "bad_request")],
      [r],
      [],
      M2ab,
    );
  }

  // ── commits: binding, membership, epoch (SPEC 7.1, 7.2) ──
  {
    const c1 = cm("c1", carol, [r], G);
    add(
      "commit-non-member",
      "SPEC 7.1, 7.2: carol, who is not a member, commits under genesis: forbidden on push (the caller is not a member of the tip) and forbidden by replication (the author is not a member of the cited state).",
      [genesis, C(c1, "forbidden"), C(c1, "forbidden", "offer")],
      [r],
      [],
      G,
    );
  }
  {
    const a1 = cm("a1-epoch-1", alice, [r], M2a, { epoch: 1 });
    add(
      "commit-epoch-mismatch",
      "SPEC 7.2: alice cites seq 2 (keyEpoch 0) but writes keyEpoch 1: forbidden.",
      [genesis, M("M2", M2a, "ok"), C(a1, "forbidden")],
      [r],
      [],
      M2a,
    );
  }
  {
    const a0 = cm("a0", alice, [r], M2a);
    const a1 = cm("a1", alice, [a0], M2a);
    add(
      "commit-unknown-parent",
      "SPEC 7.4: a1's parent a0 is unknown: missing_parents, which is retryable; once a0 is accepted the same a1 is accepted.",
      [genesis, M("M2", M2a, "ok"), C(a1, "missing_parents"), C(a0, "ok"), C(a1, "ok")],
      [a1],
      [],
      M2a,
    );
  }
  {
    const unseen = state(2, G, 0, [[owner, hostA], [alice, hostA], [carol, hostB]]);
    const a1 = cm("a1-cites-unknown-state", alice, [r], unseen);
    const a2 = cm("a2-seq-hash-mismatch", alice, [r], M2a, { seq: 3 });
    add(
      "commit-unknown-manifest",
      "SPEC 7.2 manifest binding: a commit citing a validly signed state this host never received gets missing_parents; so does one citing seq 3 with the seq 2 manifestHash, since the pair names no held state.",
      [genesis, M("M2", M2a, "ok"), C(a1, "missing_parents"), C(a2, "missing_parents")],
      [r],
      [],
      M2a,
    );
  }
  {
    const a1 = cm("a1", alice, [r], M2a);
    const tampered: Commit = { ...a1, ciphertext: flipFirst(a1.ciphertext) };
    labels.set(tampered, "a1-tampered-ciphertext");
    add(
      "commit-id-mismatch",
      "SPEC 7.1: a1 with one ciphertext byte flipped but its commitId and signature kept: the id does not recompute, bad_request; the untampered a1 is then accepted.",
      [genesis, M("M2", M2a, "ok"), C(tampered, "bad_request"), C(a1, "ok")],
      [a1],
      [],
      M2a,
    );
  }
  {
    const a1 = cm("a1", alice, [r], M2a);
    const forged: Commit = { ...a1, authorSignature: ed25519Sign(importEd25519Private(bob.edSeed), commitSigMessage(a1.commitId)) };
    labels.set(forged, "a1-signed-by-bob");
    add(
      "commit-bad-author-signature",
      "SPEC 7.1: a1 whose authorSignature is bob's signature over a1's id: it does not verify under the author (alice), bad_request.",
      [genesis, M("M2", M2a, "ok"), C(forged, "bad_request")],
      [r],
      [],
      M2a,
    );
  }
  {
    const other = deriveRepoId(owner.edPub, Buffer.alloc(16, 0x02));
    const a1 = cm("a1-other-repo", alice, [r], M2a, { repoId: other });
    add(
      "commit-wrong-repo-id",
      "SPEC 7.1: a commit whose repoId is another repository's: bad_request.",
      [genesis, M("M2", M2a, "ok"), C(a1, "bad_request")],
      [r],
      [],
      M2a,
    );
  }
  {
    const a1 = cm("a1", alice, [r], M2a);
    add(
      "commit-repush-idempotent",
      "SPEC 7, 12.3: a commit the host already holds is accepted again with no change, by push and by replication.",
      [genesis, M("M2", M2a, "ok"), C(a1, "ok"), C(a1, "ok"), C(a1, "ok", "offer")],
      [a1],
      [],
      M2a,
    );
  }
  {
    const M3 = state(3, M2a, 0, [[owner, hostA], [alice, hostA], [bob, hostB]]);
    const a1 = cm("a1-cites-seq-2", alice, [r], M2a);
    add(
      "commit-citing-older-state-ok",
      "SPEC 7.2: after seq 3 adds bob, alice's commit citing seq 2 (where she is a member at epoch 0) is still valid.",
      [genesis, M("M2", M2a, "ok"), M("M3", M3, "ok"), C(a1, "ok")],
      [a1],
      [],
      M3,
    );
  }

  // ── heads and the head bound (SPEC 7.4) ──
  {
    const a1 = cm("a1", alice, [r], M2ab);
    const b1 = cm("b1", bob, [r], M2ab);
    add(
      "concurrent-commits-two-heads",
      "SPEC 7.4: alice and bob each write a child of the root; both are accepted and both are heads.",
      [genesis, M("M2", M2ab, "ok"), C(a1, "ok"), C(b1, "ok")],
      [a1, b1],
      [],
      M2ab,
    );
    const mg = cm("merge", alice, [b1, a1], M2ab);
    add(
      "merge-collapses-heads",
      "SPEC 7.4, 5: a merge commit naming both heads as parents is accepted and becomes the only head.",
      [genesis, M("M2", M2ab, "ok"), C(a1, "ok"), C(b1, "ok"), C(mg, "ok")],
      [mg],
      [],
      M2ab,
    );
  }
  {
    const hs = sixteen(M2a);
    const mg = cm("merge-head-1-head-2", alice, [hs[0], hs[1]], M2a);
    add(
      "merge-at-head-bound",
      "SPEC 7.4: sixteen children of the root give sixteen heads (the sixteenth push leaves exactly the bound, which is allowed); a merge of two of them would leave 16 - 2 + 1 = 15 heads and MUST be accepted at the bound.",
      [genesis, M("M2", M2a, "ok"), ...hs.map((h) => C(h, "ok")), C(mg, "ok")],
      [...hs.slice(2), mg],
      [],
      M2a,
    );
  }
  {
    const hs = sixteen(M2a);
    const h17 = cm("head-17", alice, [r], M2a);
    add(
      "seventeenth-head-rejected",
      "SPEC 7.4: with sixteen heads, a client push of a seventeenth child of the root would leave 17 heads, more than the bound: too_many_heads.",
      [genesis, M("M2", M2a, "ok"), ...hs.map((h) => C(h, "ok")), C(h17, "too_many_heads")],
      hs,
      [],
      M2a,
    );
  }
  {
    const hs = sixteen(M2a);
    const h17 = cm("head-17", alice, [r], M2a);
    const h18 = cm("head-18", alice, [r], M2a);
    const mg = cm("merge-head-1-head-2", alice, [hs[0], hs[1]], M2a);
    add(
      "head-bound-exempt-for-replication",
      "SPEC 7.4, 9.1: the head bound applies to client pushes only. With sixteen heads, head-17 by replication is accepted (17 heads); a push of head-18 would leave 18: too_many_heads; a merge of two heads would leave 17 - 2 + 1 = 16 and is accepted.",
      [genesis, M("M2", M2a, "ok"), ...hs.map((h) => C(h, "ok")), C(h17, "ok", "offer"), C(h18, "too_many_heads"), C(mg, "ok")],
      [...hs.slice(2), h17, mg],
      [],
      M2a,
    );
  }

  // ── removal cutoff (SPEC 7.3, 8.3) ──
  // Each starts: M2ab, a1 (alice) and b1 (bob) children of the root, then seq 3 removes bob at
  // epoch 1 with the rotation commit merging the heads the owner saw.
  const epoch1 = (prev: SignedManifest, frontier: Commit[], o: StOpts = {}) =>
    state(3, prev, 1, [[owner, hostA], [alice, hostA]], { removals: [removal(bob, 3, frontier)], ...o });
  {
    const a1 = cm("a1", alice, [r], M2ab);
    const b1 = cm("b1", bob, [r], M2ab);
    const b2 = cm("b2", bob, [r], M2ab);
    const M3 = epoch1(M2ab, [a1, b1, b2]);
    const rot = cm("rot", owner, [a1, b1], M3);
    add(
      "removed-member-frontier-ok",
      "SPEC 7.3, 8.3: seq 3 removes bob with frontier {a1, b1, b2}; the rotation commit merges a1 and b1. b2, bob's commit the owner saw but this host had not, then arrives by replication: its id is in the frontier, so it is accepted (citing seq 2 at epoch 0) and is a head beside the rotation commit.",
      [genesis, M("M2", M2ab, "ok"), C(a1, "ok"), C(b1, "ok"), M("M3", M3, "ok", "push", rot), C(b2, "ok", "offer")],
      [rot, b2],
      [],
      M3,
    );
  }
  {
    const a1 = cm("a1", alice, [r], M2ab);
    const b1 = cm("b1", bob, [r], M2ab);
    const M3 = epoch1(M2ab, [a1, b1]);
    const rot = cm("rot", owner, [a1, b1], M3);
    const b3 = cm("b3-after-cutoff", bob, [r], M2ab);
    const a2 = cm("a2-child-of-b3", alice, [b3], M3);
    add(
      "removed-member-after-cutoff",
      "SPEC 7.3, 7.4: after seq 3 removes bob with frontier {a1, b1}, bob's b3 (a child of the root, citing seq 2 at epoch 0) is neither in the frontier nor an ancestor of a frontier commit: forbidden by replication and on push. alice's child of b3 then has a rejected parent: forbidden.",
      [genesis, M("M2", M2ab, "ok"), C(a1, "ok"), C(b1, "ok"), M("M3", M3, "ok", "push", rot), C(b3, "forbidden", "offer"), C(b3, "forbidden"), C(a2, "forbidden")],
      [rot],
      [],
      M3,
    );
  }
  {
    const a1 = cm("a1", alice, [r], M2ab);
    const b1 = cm("b1", bob, [r], M2ab);
    const M3 = epoch1(M2ab, [a1, b1]);
    const rot = cm("rot", owner, [a1, b1], M3);
    const b4 = cm("b4-child-of-b1", bob, [b1], M2ab);
    add(
      "removed-member-backdated-child-of-frontier",
      "SPEC 7.3: after bob's removal with frontier {a1, b1}, bob backdates b4 citing seq 2 at epoch 0 with parent b1, which is in the frontier. b4's own id is neither in the frontier nor an ancestor of a frontier commit, so it MUST be rejected: forbidden by replication and on push.",
      [genesis, M("M2", M2ab, "ok"), C(a1, "ok"), C(b1, "ok"), M("M3", M3, "ok", "push", rot), C(b4, "forbidden", "offer"), C(b4, "forbidden")],
      [rot],
      [],
      M3,
    );
  }
  {
    const a1 = cm("a1", alice, [r], M2ab);
    const b1 = cm("b1", bob, [r], M2ab);
    const b0 = cm("b0", bob, [r], M2ab);
    const b2 = cm("b2-child-of-b0", bob, [b0], M2ab);
    const M3 = epoch1(M2ab, [a1, b1, b2]);
    const rot = cm("rot", owner, [a1, b1], M3);
    add(
      "removed-member-ancestor-of-frontier",
      "SPEC 7.3: the frontier is {a1, b1, b2} and b2's parent is b0, both unseen here. b0 first: the host lacks frontier commit b2 and cannot decide, so missing_parents. b2: in the frontier but its parent b0 is unknown, missing_parents (its verified header now counts for ancestry). b0 again: an ancestor of frontier commit b2, accepted. b2 again: accepted.",
      [
        genesis,
        M("M2", M2ab, "ok"),
        C(a1, "ok"),
        C(b1, "ok"),
        M("M3", M3, "ok", "push", rot),
        C(b0, "missing_parents", "offer"),
        C(b2, "missing_parents", "offer"),
        C(b0, "ok", "offer"),
        C(b2, "ok", "offer"),
      ],
      [rot, b2],
      [],
      M3,
    );
  }
  {
    const a1 = cm("a1", alice, [r], M2ab);
    const b1 = cm("b1-unseen-by-owner", bob, [r], M2ab);
    const M3 = epoch1(M2ab, [a1]);
    const rot = cm("rot", owner, [a1], M3);
    const a2 = cm("a2-child-of-b1", alice, [b1], M3);
    add(
      "removed-member-dropped-on-removal",
      "SPEC 7.3: this host holds bob's head b1, which never reached the owner; seq 3 removes bob with frontier {a1}. On accepting it the host re-checks bob's commits and drops b1 from the heads; alice's later child of b1 has a rejected parent: forbidden.",
      [genesis, M("M2", M2ab, "ok"), C(a1, "ok"), C(b1, "ok"), M("M3", M3, "ok", "push", rot), C(a2, "forbidden")],
      [rot],
      [],
      M3,
    );
  }

  // ── rotation atomicity (SPEC 8.3) ──
  {
    const M3 = epoch1(M2ab, [r]);
    const rot = cm("rot", owner, [r], M3);
    add(
      "rotation-without-commit",
      "SPEC 8.3, 9.1: seq 3 removes bob and raises the epoch; without its rotation commit it is rejected with bad_request, by replication and on publish. Published with it, both are accepted.",
      [genesis, M("M2", M2ab, "ok"), M("M3", M3, "bad_request", "offer"), M("M3", M3, "bad_request"), M("M3", M3, "ok", "push", rot)],
      [rot],
      [],
      M3,
    );
  }
  {
    const M3 = epoch1(M2ab, [r]);
    const byAlice = cm("rot-by-alice", alice, [r], M3);
    add(
      "rotation-commit-not-owner",
      "SPEC 8.3: the rotation commit of an epoch-raising state MUST be authored by ownerKey; one by alice is bad_request and the state is not adopted either (atomic).",
      [genesis, M("M2", M2ab, "ok"), M("M3", M3, "bad_request", "push", byAlice)],
      [r],
      [],
      M2ab,
    );
  }
  {
    const M3 = epoch1(M2ab, [r]);
    const atEpoch0 = cm("rot-epoch-0", owner, [r], M3, { epoch: 0 });
    add(
      "rotation-commit-wrong-epoch",
      "SPEC 8.3: the rotation commit MUST be at the new epoch (1); one at epoch 0 is bad_request and the state is not adopted.",
      [genesis, M("M2", M2ab, "ok"), M("M3", M3, "bad_request", "push", atEpoch0)],
      [r],
      [],
      M2ab,
    );
  }
  {
    const x = cm("x", alice, [r], M2ab);
    const M3 = epoch1(M2ab, [x]);
    const rot = cm("rot", owner, [x], M3);
    const a3 = cm("a3-cites-seq-3", alice, [r], M3);
    add(
      "rotation-commit-missing-parent",
      "SPEC 8.3 atomicity, 7.2, 7.4: the rotation commit's parent x is unknown, so the pair answers missing_parents and neither is stored: alice's commit citing seq 3 then gets missing_parents too (unknown state). Once x is accepted, the pair and then alice's commit are accepted.",
      [
        genesis,
        M("M2", M2ab, "ok"),
        M("M3", M3, "missing_parents", "push", rot),
        C(a3, "missing_parents"),
        C(x, "ok"),
        M("M3", M3, "ok", "push", rot),
        C(a3, "ok"),
      ],
      [rot, a3],
      [],
      M3,
    );
  }

  // ── diverged owner states (SPEC 6.5) ──
  {
    const X2 = state(2, G, 0, [[owner, hostA], [alice, hostA]]);
    const Y2 = above((t) => state(2, G, 0, [[owner, hostA], [carol, hostB]], { tweak: t }), X2);
    const a1 = cm("a1-cites-X2", alice, [r], X2);
    const c1 = cm("c1-cites-Y2", carol, [r], Y2);
    add(
      "diverged-owner-lower-hash-wins",
      "SPEC 6.5 tie rule: two owner-signed seq 2 states, X2 (adds alice) with the bytewise-lower manifestHash and Y2 (adds carol). The host holds Y2, then receives X2 and switches to it; Y2 offered again loses (manifest_conflict). alice is a member; carol, invited only on the losing chain, is not, so her push is forbidden.",
      [genesis, M("Y2", Y2, "ok", "offer"), M("X2", X2, "ok", "offer"), M("Y2", Y2, "manifest_conflict", "offer"), C(a1, "ok"), C(c1, "forbidden")],
      [a1],
      [],
      X2,
    );
  }
  {
    const X2 = state(2, G, 0, [[owner, hostA], [alice, hostA]]);
    const Y2 = above((t) => state(2, G, 0, [[owner, hostA], [carol, hostB]], { tweak: t }), X2);
    const c1 = cm("c1-cites-Y2", carol, [r], Y2);
    add(
      "diverged-owner-higher-hash-loses",
      "SPEC 6.5, 7.2: holding X2 (lower hash), the host is offered Y2: it loses the tie rule, manifest_conflict, and is retained as a verified losing state. carol's commit citing Y2 then resolves (not missing_parents) and is re-checked: X2 does not list carol and the tip epoch has not passed hers, so it is held (forbidden).",
      [genesis, M("X2", X2, "ok", "offer"), M("Y2", Y2, "manifest_conflict", "offer"), C(c1, "forbidden", "offer")],
      [r],
      [c1],
      X2,
    );
  }
  {
    const L3 = state(3, M2a, 0, [[owner, hostA], [alice, hostA], [carol, hostB]]);
    const H3 = above((t) => state(3, M2a, 0, [[owner, hostA], [alice, hostA], [bob, hostB]], { tweak: t }), L3);
    const a1 = cm("a1-cites-H3", alice, [r], H3);
    const a2 = cm("a2-cites-H3", alice, [a1], H3);
    add(
      "diverged-owner-commit-rechecked-ok",
      "SPEC 6.5: the host holds H3 (adds bob) and accepts alice's a1 citing it; then L3 (adds carol, lower hash) wins. a1 now cites a losing state and is re-checked against L3, which lists alice at the same epoch 0: it stays accepted. A new a2 citing H3 is accepted the same way.",
      [genesis, M("M2", M2a, "ok"), M("H3", H3, "ok"), C(a1, "ok"), M("L3", L3, "ok", "offer"), C(a2, "ok")],
      [a2],
      [],
      L3,
    );
  }
  {
    const W3 = state(3, M2ab, 0, [[owner, hostA], [alice, hostA], [bob, hostB], [carol, hostB]]);
    const L3 = above((t) => epoch1(M2ab, [r], { tweak: t }), W3);
    const rotL = cm("rotL", owner, [r], L3);
    const a1 = cm("a1-cites-L3", alice, [rotL], L3);
    const a2 = cm("a2-cites-L3", alice, [r], L3);
    add(
      "diverged-owner-commit-held",
      "SPEC 6.5: one owner device removes bob (L3, epoch 1, with rotation commit rotL), the other adds carol (W3, epoch 0, lower hash). The host accepts L3, rotL, and alice's a1 at epoch 1; then W3 wins. rotL and a1 cite a losing state, W3 does not list them at epoch 1, and the tip epoch (0) has not passed theirs: they are held (rotL kept with its state, SPEC 8.3) and leave the heads. A push of a1, or of a new a2 citing L3, answers forbidden.",
      [genesis, M("M2", M2ab, "ok"), M("L3", L3, "ok", "push", rotL), C(a1, "ok"), M("W3", W3, "ok", "offer"), C(a1, "forbidden"), C(a2, "forbidden")],
      [r],
      [rotL, a1, a2],
      W3,
    );
  }
  {
    const W3 = state(3, M2a, 0, [[owner, hostA], [alice, hostA]], { share: true });
    const L3 = above((t) => state(3, M2a, 0, [[owner, hostA], [alice, hostA], [carol, hostB]], { tweak: t }), W3);
    const c1 = cm("c1-cites-L3", carol, [r], L3);
    const W4 = state(4, W3, 0, [[owner, hostA], [alice, hostA], [carol, hostB]], { share: true });
    add(
      "held-commit-accepted-after-reinvite",
      "SPEC 6.5: carol is invited only on the losing L3; her c1 citing L3 is accepted while L3 is the tip, then held when W3 (policy flip, lower hash) wins; her push is forbidden while she is not a member. W4 re-invites carol at the same epoch 0: the held c1 is re-checked against W4 and accepted.",
      [genesis, M("M2", M2a, "ok"), M("L3", L3, "ok", "offer"), C(c1, "ok"), M("W3", W3, "ok", "offer"), C(c1, "forbidden"), M("W4", W4, "ok")],
      [c1],
      [],
      W4,
    );
  }
  {
    const W3 = state(3, M2ab, 0, [[owner, hostA], [alice, hostA], [bob, hostB]], { share: true });
    const L3 = above((t) => state(3, M2ab, 0, [[owner, hostA], [alice, hostA], [bob, hostB], [carol, hostB]], { tweak: t }), W3);
    const c1 = cm("c1-cites-L3", carol, [r], L3);
    const c2 = cm("c2-child-of-c1", carol, [c1], L3);
    const W4 = state(4, W3, 1, [[owner, hostA], [alice, hostA]], { share: true, removals: [removal(bob, 4, [r])] });
    const rot4 = cm("rot4", owner, [r], W4);
    const c3 = cm("c3-cites-L3", carol, [r], L3);
    add(
      "held-commit-dropped-after-epoch",
      "SPEC 6.5: carol's c1 and its child c2 cite the losing L3; when W3 (lower hash) wins they are held. W4 removes bob and raises the epoch to 1: re-checked against W4, c1 meets the drop test (tip epoch 1 exceeds its 0) and is dropped permanently, c2 with it. Offering c1 again is forbidden, and a new c3 citing L3 meets the drop test at its first classification: forbidden.",
      [
        genesis,
        M("M2", M2ab, "ok"),
        M("L3", L3, "ok", "offer"),
        C(c1, "ok"),
        C(c2, "ok"),
        M("W3", W3, "ok", "offer"),
        M("W4", W4, "ok", "push", rot4),
        C(c1, "forbidden", "offer"),
        C(c3, "forbidden", "offer"),
      ],
      [rot4],
      [],
      W4,
    );
  }

  // ── leave (SPEC 8.4) ──
  {
    const at = ctx.t0 + 3_600_000;
    const good = signLeave({ repoId, memberKey: alice.edPub, at }, alice.edSeed);
    const forged: LeaveRequest = { ...good, signature: ed25519Sign(importEd25519Private(bob.edSeed), leaveSignMessage(good)) };
    add(
      "leave-bad-signature",
      "SPEC 8.4: a leave request for alice whose signature is bob's: it does not verify under memberKey, bad_request.",
      [genesis, M("M2", M2a, "ok"), L("alice-leave-signed-by-bob", forged, "bad_request")],
      [r],
      [],
      M2a,
    );
    add(
      "leave-ok",
      "SPEC 8.4: alice, a member of the tip and not the owner, publishes a validly signed leave request: accepted.",
      [genesis, M("M2", M2a, "ok"), L("alice-leave", good, "ok")],
      [r],
      [],
      M2a,
    );
    add(
      "leave-non-member",
      "SPEC 8.4: carol, not a member of the tip, publishes a validly signed leave request: forbidden.",
      [genesis, M("M2", M2a, "ok"), L("carol-leave", signLeave({ repoId, memberKey: carol.edPub, at }, carol.edSeed), "forbidden")],
      [r],
      [],
      M2a,
    );
    add(
      "leave-owner",
      "SPEC 8.4: the owner cannot leave its own repository: forbidden.",
      [genesis, M("M2", M2a, "ok"), L("owner-leave", signLeave({ repoId, memberKey: owner.edPub, at }, owner.edSeed), "forbidden")],
      [r],
      [],
      M2a,
    );
  }

  // ── fix round 1: undecided cutoff, client publish, createRepo (SPEC 7.3, 6.3, 8.2) ──
  {
    const a1 = cm("a1", alice, [r], M2ab);
    const b1 = cm("b1", bob, [r], M2ab);
    const b3 = cm("b3-after-cutoff", bob, [r], M2ab);
    const b0 = cm("b0", bob, [r], M2ab);
    const b2 = cm("b2-child-of-b0", bob, [b0], M2ab);
    const M3 = epoch1(M2ab, [a1, b1, b2]);
    const rot = cm("rot", owner, [a1, b1], M3);
    add(
      "removed-member-undecided-then-dropped",
      "SPEC 7.3: bob's b3 is accepted while bob is a member. seq 3 removes bob with frontier {a1, b1, b2}; b2 is unknown, so the host cannot decide b3 and MUST NOT keep accepting it (it leaves the heads, undecided, not dropped). b0 and b2 arrive (each first missing_parents); once b2's verified header is known, the frontier's ancestry is complete, b3 is neither in it nor an ancestor of it, and b3 is dropped. b0 and b2 are then accepted.",
      [
        genesis,
        M("M2", M2ab, "ok"),
        C(a1, "ok"),
        C(b1, "ok"),
        C(b3, "ok", "offer"),
        M("M3", M3, "ok", "push", rot),
        C(b0, "missing_parents", "offer"),
        C(b2, "missing_parents", "offer"),
        C(b0, "ok", "offer"),
        C(b2, "ok", "offer"),
      ],
      [rot, b2],
      [],
      M3,
    );
  }
  {
    const W3 = state(3, M2ab, 0, [[owner, hostA], [alice, hostA], [bob, hostB], [carol, hostB]]);
    const L3 = above((t) => epoch1(M2ab, [r], { tweak: t }), W3);
    const rotL = cm("rotL", owner, [r], L3);
    const a2 = cm("a2-cites-L3", alice, [r], L3);
    const x = cm("x-unseen", alice, [r], W3);
    const W4 = state(4, W3, 1, [[owner, hostA], [bob, hostB], [carol, hostB]], { removals: [removal(alice, 4, [x])] });
    const rot4 = cm("rot4", owner, [r], W4);
    add(
      "removed-member-undecided-held-kept",
      "SPEC 6.5, 7.3: holding W3, the host is offered the losing L3 (epoch 1) with its rotation commit rotL, which is kept held (SPEC 8.3); alice's a2 citing L3 at epoch 1 is held. W4 removes alice (epoch 1) with frontier {x}, a commit this host never saw. Deciding the held commits against W4: rotL meets no drop test and W4 lists the owner at epoch 1, so it is accepted; for a2 the cutoff cannot be decided without x, so a2 is neither accepted (W4 does not list alice) nor dropped: it stays held.",
      [
        genesis,
        M("M2", M2ab, "ok"),
        M("W3", W3, "ok", "offer"),
        M("L3", L3, "manifest_conflict", "offer", rotL),
        C(a2, "forbidden"),
        M("W4", W4, "ok", "push", rot4),
      ],
      [rotL, rot4],
      [a2],
      W4,
    );
  }
  {
    const X2 = state(2, G, 0, [[owner, hostA], [alice, hostA]]);
    const Y2 = above((t) => state(2, G, 0, [[owner, hostA], [carol, hostB]], { tweak: t }), X2);
    add(
      "diverged-owner-publish-needs-tip-plus-one",
      "SPEC 6.3, 6.5: holding Y2 (adds carol), the host gets a client publish of X2 (adds alice), whose manifestHash is lower. A host accepts a state from a client only at tip + 1 linked to the tip, so the publish is manifest_conflict and the tip stays Y2 (X2 is kept as a verified losing state). The same X2 by replication wins the tie rule and becomes the tip.",
      [genesis, M("Y2", Y2, "ok"), M("X2", X2, "manifest_conflict"), M("X2", X2, "ok", "offer")],
      [r],
      [],
      X2,
    );
  }
  add(
    "genesis-without-commit",
    "SPEC 8.2, 10.4: createRepo carries the genesis state and its first commit, accepted together or not at all; a client publish of the genesis without the commit is a malformed request: bad_request, nothing stored.",
    [M("G", G, "bad_request")],
    [],
    [],
    null,
  );

  // ── fix round 1: listed reject paths (SPEC 6.1 rules 1, 3, 5, 6; 6.5; 7.4; 8.4) ──
  const hostC = hostRef(0xc0, "c.vault.example");
  const otherRepo = deriveRepoId(owner.edPub, Buffer.alloc(16, 0x02));
  const M2abc = state(2, G, 0, [[owner, hostA], [alice, hostA], [bob, hostB], [carol, hostB]]);
  const onG = (name: string, rule: string, bad: SignedManifest) =>
    add(name, `SPEC 6.1 rule 5: ${rule}. The seq 2 state is validly signed and links to the tip, so the content rule decides: bad_request.`, [genesis, M("M2-bad", bad, "bad_request")], [r], [], G);
  const onM2ab = (name: string, rule: string, bad: SignedManifest) =>
    add(name, `SPEC 6.1 rule 5: ${rule}. The seq 3 state is validly signed and links to the tip, so the content rule decides: bad_request.`, [genesis, M("M2", M2ab, "ok"), M("M3-bad", bad, "bad_request")], [r], [], M2ab);

  onG("content-hosts-empty", "hosts is not empty; this state lists no host", resign(M2a, (s) => ({ ...s, hosts: [] })));
  onG("content-owner-not-member", "members contains exactly one entry whose ed25519PublicKey equals ownerKey; this state lists only alice", state(2, G, 0, [[alice, hostA]]));
  onG(
    "content-member-epoch-mismatch",
    "every member's keyEpoch equals the state's keyEpoch; alice's entry says 1 in an epoch 0 state",
    resign(M2a, (s) => ({ ...s, members: s.members.map((x) => (x.ed25519PublicKey.equals(alice.edPub) ? { ...x, keyEpoch: 1 } : x)) })),
  );
  onG("content-home-host-not-listed", "every member's homeHostKey equals the hostKey of an entry in hosts; alice's home is c.vault.example, which is not listed", state(2, G, 0, [[owner, hostA], [alice, hostC]]));
  onG("content-repo-id-changed", "repoId is unchanged from the previous state; this one names another repository", resign(M2a, (s) => ({ ...s, repoId: otherRepo })));
  onG("content-owner-key-changed", "ownerKey is unchanged from the previous state; this one, signed by alice, names alice as ownerKey", resign(M2a, (s) => ({ ...s, ownerKey: alice.edPub }), alice));
  onG("content-scheme-id-changed", "schemeId is unchanged from the previous state", resign(M2a, (s) => ({ ...s, schemeId: "X25519-HKDF-SHA256-AESGCM-v2" })));
  onG(
    "content-genesis-nonce-after-seq-1",
    "genesisNonce is empty after seq 1 (also a rule 1 length); this seq 2 state repeats the 16-byte nonce",
    resign(M2a, (s) => ({ ...s, genesisNonce: GENESIS_NONCE })),
  );
  onG("content-epoch-jump-2", "keyEpoch equals the previous keyEpoch or the previous keyEpoch + 1; this state jumps from 0 to 2", state(2, G, 2, [[owner, hostA], [alice, hostA]]));
  onM2ab(
    "content-removed-key-still-member",
    "no member's ed25519PublicKey equals the memberKey of any removal; bob is removed and still listed",
    state(3, M2ab, 1, [[owner, hostA], [alice, hostA], [bob, hostB]], { removals: [removal(bob, 3, [r])] }),
  );
  onM2ab(
    "content-removed-at-seq-out-of-range",
    "every removal's removedAtSeq is at most the state's manifestSeq, and a new removal's equals it; bob's says 4 in a seq 3 state",
    state(3, M2ab, 1, [[owner, hostA], [alice, hostA]], { removals: [removal(bob, 4, [r])] }),
  );
  onM2ab(
    "content-new-removal-of-non-member",
    "every new removal names a key that was a member of the previous state; carol never was",
    state(3, M2ab, 1, [[owner, hostA], [alice, hostA], [bob, hostB]], { removals: [removal(carol, 3, [r])] }),
  );
  onM2ab(
    "content-owner-removed",
    "ownerKey is never removed (and members contains the owner exactly once); this state removes the owner",
    state(3, M2ab, 1, [[alice, hostA], [bob, hostB]], { removals: [removal(owner, 3, [r])] }),
  );
  {
    const M3 = epoch1(M2ab, [r]);
    const rot = cm("rot", owner, [r], M3);
    const altered = state(4, M3, 1, [[owner, hostA], [alice, hostA]], { removals: [removal(bob, 3, [])] });
    const omitted = state(4, M3, 1, [[owner, hostA], [alice, hostA]], { removals: [] });
    add(
      "content-earlier-removal-altered",
      "SPEC 6.1 rule 5: every removal of the previous state appears unchanged (memberKey, removedAtSeq, and frontier); seq 4 repeats bob's removal with an empty frontier: bad_request.",
      [genesis, M("M2", M2ab, "ok"), M("M3", M3, "ok", "push", rot), M("M4-altered-removal", altered, "bad_request")],
      [rot],
      [],
      M3,
    );
    add(
      "content-earlier-removal-omitted",
      "SPEC 6.1 rule 5: removals are cumulative, every removal of the previous state appears unchanged; seq 4 drops bob's removal: bad_request.",
      [genesis, M("M2", M2ab, "ok"), M("M3", M3, "ok", "push", rot), M("M4-omits-removal", omitted, "bad_request")],
      [rot],
      [],
      M3,
    );
  }

  // Genesis failures other than repoId (6.1 rule 3, 6.2).
  const badGenesis = (name: string, rule: string, Gx: SignedManifest) =>
    add(name, `SPEC 6.1 rule 3, 6.2: ${rule}: bad_request, nothing stored.`, [M("G-bad", Gx, "bad_request", "push", cm(`r-${name}`, owner, [], Gx))], [], [], null);
  badGenesis("genesis-epoch-not-zero", "the genesis state MUST have keyEpoch 0; this one has 1", state(1, null, 1, [[owner, hostA]]));
  badGenesis("genesis-extra-member", "the genesis state MUST have exactly one member, the owner; this one also lists alice", state(1, null, 0, [[owner, hostA], [alice, hostA]]));
  badGenesis("genesis-with-removals", "the genesis state MUST have no removals; this one removes bob", state(1, null, 0, [[owner, hostA]], { removals: [removal(bob, 1, [])] }));

  // Rule 6 on a later state (8.6).
  add(
    "manifest-drops-this-host",
    "SPEC 6.1 rule 6, 8.6: a valid seq 2 state lists only b.vault.example (the owner's home moved to b); at a.vault.example it is not_hosted and the tip stays at genesis.",
    [genesis, M("M2-hosts-b-only", state(2, G, 0, [[owner, hostB]], { hosts: [ref(hostB)] }), "not_hosted")],
    [r],
    [],
    G,
  );

  // Rule 1 and 7.1 structure, in the wire form a host receives.
  {
    const w = signedManifestToWire(M2a);
    const dupHost = { ...w, state: { ...w.state, hosts: [w.state.hosts[0], ...w.state.hosts] } };
    const shortWrap = {
      ...w,
      state: {
        ...w.state,
        members: w.state.members.map((x, i) =>
          i === 0 ? { ...x, wrappedDataKey: { ...x.wrappedDataKey, ciphertext: b64(fromB64(x.wrappedDataKey.ciphertext).subarray(0, 47)) } } : x,
        ),
      },
    };
    const shortSig = { ...w, ownerSignature: b64(fromB64(w.ownerSignature).subarray(0, 63)) };
    const shortPrev = { ...w, state: { ...w.state, prevManifestHash: b64(fromB64(w.state.prevManifestHash).subarray(0, 31)) } };
    add(
      "manifest-malformed-structure",
      "SPEC 6.1 rule 1, 4.2: a seq 2 state with a host listed twice, a wrappedDataKey ciphertext of 47 bytes (not 48), a 63-byte ownerSignature, or a 31-byte prevManifestHash is malformed: bad_request each; the intact state is then accepted.",
      [
        genesis,
        MW("M2-duplicate-host", dupHost, "bad_request"),
        MW("M2-wrap-47-bytes", shortWrap, "bad_request"),
        MW("M2-signature-63-bytes", shortSig, "bad_request"),
        MW("M2-prev-hash-31-bytes", shortPrev, "bad_request"),
        M("M2", M2a, "ok"),
      ],
      [r],
      [],
      M2a,
    );
  }
  {
    const a1 = cm("a1", alice, [r], M2a);
    const w = commitToWire(a1);
    add(
      "commit-malformed-structure",
      "SPEC 7.1, 4.3: a commit listing the same parent twice, with an 11-byte iv, a 63-byte authorSignature, or a 15-byte ciphertext (shorter than the GCM tag) is malformed: bad_request each; the intact commit is then accepted.",
      [
        genesis,
        M("M2", M2a, "ok"),
        CW("a1-duplicate-parent", { ...w, parents: [w.parents[0], w.parents[0]] }, "bad_request"),
        CW("a1-iv-11-bytes", { ...w, iv: b64(fromB64(w.iv).subarray(0, 11)) }, "bad_request"),
        CW("a1-signature-63-bytes", { ...w, authorSignature: b64(fromB64(w.authorSignature).subarray(0, 63)) }, "bad_request"),
        CW("a1-ciphertext-15-bytes", { ...w, ciphertext: b64(fromB64(w.ciphertext).subarray(0, 15)) }, "bad_request"),
        C(a1, "ok"),
      ],
      [a1],
      [],
      M2a,
    );
  }

  // 7.4: a commit whose parent is held is held.
  {
    const W3 = state(3, M2ab, 0, [[owner, hostA], [alice, hostA], [bob, hostB], [carol, hostB]]);
    const L3 = above((t) => epoch1(M2ab, [r], { tweak: t }), W3);
    const rotL = cm("rotL", owner, [r], L3);
    const a1 = cm("a1-cites-L3", alice, [rotL], L3);
    const a3 = cm("a3-child-of-a1-cites-W3", alice, [a1], W3);
    add(
      "commit-with-held-parent-held",
      "SPEC 7.4, 6.5: as in diverged-owner-commit-held, rotL and a1 are held once W3 wins. alice's a3 cites the winning W3 correctly (member, epoch 0) but its parent a1 is held, so a3 is held too: forbidden.",
      [genesis, M("M2", M2ab, "ok"), M("L3", L3, "ok", "push", rotL), C(a1, "ok"), M("W3", W3, "ok", "offer"), C(a3, "forbidden")],
      [r],
      [rotL, a1, a3],
      W3,
    );
  }

  // 6.5: losing epoch-raising states, the cutoff on losing commits, switches, held descendants.
  {
    const W3 = state(3, M2abc, 1, [[owner, hostA], [alice, hostA], [carol, hostB]], { removals: [removal(bob, 3, [r])] });
    const rotW = cm("rotW", owner, [r], W3);
    const L3 = above((t) => state(3, M2abc, 1, [[owner, hostA], [alice, hostA], [bob, hostB]], { removals: [removal(carol, 3, [r])], tweak: t }), W3);
    const rotL = cm("rotL-removes-carol", owner, [r], L3);
    const b1 = cm("b1-cites-L3", bob, [r], L3);
    const start = [genesis, M("M2", M2abc, "ok"), M("W3", W3, "ok", "push", rotW), M("L3", L3, "manifest_conflict", "offer", rotL)];
    add(
      "losing-rotation-commit-kept-held",
      "SPEC 6.5, 8.3: holding W3 (removes bob, epoch 1), the host is offered the losing L3 (removes carol, epoch 1, higher hash) with its rotation commit: L3 loses (manifest_conflict) and is retained, and its rotation commit is kept with it as a held commit.",
      start,
      [rotW],
      [rotL],
      W3,
    );
    add(
      "losing-commit-failing-cutoff-rejected",
      "SPEC 6.5 (1), 7.3: bob's b1 cites the retained losing L3 at epoch 1. The removal cutoff takes precedence: bob is removed in the tip W3 with frontier {root} and b1 is neither in it nor an ancestor of it, so b1 is rejected (forbidden), never held.",
      [...start, C(b1, "forbidden", "offer")],
      [rotW],
      [rotL],
      W3,
    );
  }
  {
    const W3 = state(3, M2ab, 0, [[owner, hostA], [alice, hostA], [bob, hostB], [carol, hostB]]);
    const L3 = above((t) => epoch1(M2ab, [r], { tweak: t }), W3);
    const rotL = cm("rotL", owner, [r], L3);
    const a1 = cm("a1-cites-L3", alice, [rotL], L3);
    const W4 = state(4, W3, 1, [[owner, hostA], [bob, hostB], [carol, hostB]], { removals: [removal(alice, 4, [r])] });
    const rot4 = cm("rot4", owner, [r], W4);
    add(
      "held-commit-dropped-on-author-removal",
      "SPEC 6.5 drop test, 7.3: rotL and alice's a1 are held once W3 wins. W4 removes alice (epoch 1) with frontier {root}: a1 is not covered, so it is dropped. rotL meets no drop test and W4 lists the owner at its epoch 1, so it is accepted beside W4's rotation commit.",
      [genesis, M("M2", M2ab, "ok"), M("L3", L3, "ok", "push", rotL), C(a1, "ok"), M("W3", W3, "ok", "offer"), M("W4", W4, "ok", "push", rot4)],
      [rotL, rot4],
      [],
      W4,
    );
  }
  {
    const W3 = epoch1(M2ab, [r]);
    const rotW = cm("rotW", owner, [r], W3);
    const H3 = above((t) => state(3, M2ab, 0, [[owner, hostA], [alice, hostA], [bob, hostB], [carol, hostB]], { tweak: t }), W3);
    const b1 = cm("b1-cites-H3", bob, [r], H3);
    add(
      "chain-switch-drops-by-cutoff",
      "SPEC 6.5, 7.3: the host holds H3 (adds carol) and accepts bob's b1 citing it. W3 (removes bob, epoch 1, frontier {root}, lower hash) then wins with its rotation commit. Re-checking b1 against the winning chain, the removal cutoff takes precedence and b1 fails it: dropped; the rotation commit is the only head.",
      [genesis, M("M2", M2ab, "ok"), M("H3", H3, "ok"), C(b1, "ok"), M("W3", W3, "ok", "offer", rotW)],
      [rotW],
      [],
      W3,
    );
  }
  {
    const W3 = state(3, M2a, 0, [[owner, hostA], [alice, hostA]], { share: true });
    const L3 = above((t) => state(3, M2a, 0, [[owner, hostA], [alice, hostA], [carol, hostB]], { tweak: t }), W3);
    const c1 = cm("c1-cites-L3", carol, [r], L3);
    const c2 = cm("c2-child-of-c1", carol, [c1], L3);
    const W4 = state(4, W3, 0, [[owner, hostA], [alice, hostA], [carol, hostB]], { share: true });
    add(
      "held-descendants-accepted-in-turn",
      "SPEC 6.5: carol's c1 and its child c2 cite the losing L3 and are held when W3 wins. W4 re-invites carol at epoch 0: c1 is accepted, and its held descendant c2 is re-checked in turn and accepted, leaving c2 the only head.",
      [genesis, M("M2", M2a, "ok"), M("L3", L3, "ok", "offer"), C(c1, "ok"), C(c2, "ok"), M("W3", W3, "ok", "offer"), M("W4", W4, "ok")],
      [c2],
      [],
      W4,
    );
  }

  // 8.4: pending leave requests.
  {
    const at = ctx.t0 + 3_600_000;
    const bobLeave = signLeave({ repoId, memberKey: bob.edPub, at }, bob.edSeed);
    const aliceLeave = signLeave({ repoId, memberKey: alice.edPub, at }, alice.edSeed);
    const M3 = epoch1(M2ab, [r]);
    const rot = cm("rot", owner, [r], M3);
    add(
      "leave-dropped-on-removal",
      "SPEC 8.4: the host keeps bob's and alice's leave requests and drops bob's once a state removes bob; alice's stays pending.",
      [genesis, M("M2", M2ab, "ok"), L("bob-leave", bobLeave, "ok"), L("alice-leave", aliceLeave, "ok"), M("M3", M3, "ok", "push", rot)],
      [rot],
      [],
      M3,
      [aliceLeave],
    );
    const later = signLeave({ repoId, memberKey: alice.edPub, at: at + 1000 }, alice.edSeed);
    add(
      "leave-latest-per-member",
      "SPEC 8.4: the host keeps the latest leave request per member; alice sends one and then a later one, and only the later one is pending.",
      [genesis, M("M2", M2a, "ok"), L("alice-leave", aliceLeave, "ok"), L("alice-leave-later", later, "ok")],
      [r],
      [],
      M2a,
      [later],
    );
  }

  // ── fix round 2: a pending commit citing a losing state, and SPEC rule order on a stale publish ──
  {
    // W3's frontier names x, which descends from b1, which cites H3; so H3 is fixed first and W3 is
    // the one whose wraps are varied (label "<member>/g<i>") until its manifestHash is below H3's.
    const H3 = state(3, M2ab, 0, [[owner, hostA], [alice, hostA], [bob, hostB], [carol, hostB]]);
    const b1 = cm("b1-cites-H3", bob, [r], H3);
    const x = cm("x-child-of-b1", bob, [b1], M2ab);
    let W3 = epoch1(M2ab, [x]);
    for (let i = 0; Buffer.compare(manifestHash(W3), manifestHash(H3)) >= 0; i++) W3 = epoch1(M2ab, [x], { tweak: `g${i}` });
    const rotW = cm("rotW", owner, [r], W3);
    add(
      "pending-losing-commit-rechecked-when-decided",
      "SPEC 6.5, 7.3, 7.4: the host holds H3 (adds carol, epoch 0) and accepts bob's b1 citing it. W3 (removes bob at epoch 1 with frontier {x}, lower hash) then wins; x, bob's child of b1, is unknown, so b1's cutoff is undecided and b1 MUST NOT stay accepted. When x arrives its header decides the cutoff (b1 is an ancestor of x), and b1, which cites a losing state, is re-checked by SPEC 6.5: W3 does not list bob, and the drop test holds (tip epoch 1 exceeds b1's 0), so b1 is dropped. x's parent is then rejected: forbidden. The rotation commit is the only head.",
      [genesis, M("M2", M2ab, "ok"), M("H3", H3, "ok"), C(b1, "ok"), M("W3", W3, "ok", "offer", rotW), C(x, "forbidden", "offer")],
      [rotW],
      [],
      W3,
    );
  }
  add(
    "stale-publish-with-content-violation",
    "SPEC 6.1 (the host answers with the first failure, in rule order), 6.3: while the tip is seq 2, a client publishes another seq 2 state on genesis that also lists no host. Rule 4 (chain link: a client state MUST be at tip + 1) fails before rule 5 (content), so the answer is manifest_conflict, not bad_request.",
    [genesis, M("M2", M2a, "ok"), M("M2-stale-no-hosts", resign(M2ab, (s) => ({ ...s, hosts: [] })), "manifest_conflict")],
    [r],
    [],
    M2a,
  );

  // ── fix round 3: a pending cutoff decided by a header learned with a losing rotation commit ──
  {
    // W3's frontier names rotL, which cites L3; so L3 is fixed first and W3's wraps are varied
    // (label "<member>/g<i>") until W3 hashes below L3.
    const b1 = cm("b1", bob, [r], M2ab);
    const L3 = state(3, M2ab, 1, [[owner, hostA], [bob, hostB]], { removals: [removal(alice, 3, [r])] });
    const rotL = cm("rotL-child-of-b1", owner, [b1], L3);
    let W3 = epoch1(M2ab, [rotL]);
    for (let i = 0; Buffer.compare(manifestHash(W3), manifestHash(L3)) >= 0; i++) W3 = epoch1(M2ab, [rotL], { tweak: `g${i}` });
    const rotW = cm("rotW", owner, [r], W3);
    add(
      "pending-commit-resolved-by-losing-rotation-header",
      "SPEC 7.3, 6.5, 8.3: bob's b1 (citing seq 2) is accepted. W3 removes bob at epoch 1 with frontier {rotL}; rotL is unknown here, so b1's cutoff cannot be decided and b1 MUST NOT stay accepted. L3 (removes alice, epoch 1, higher hash) then arrives with its rotation commit rotL, whose parent is b1: L3 loses the tie rule (manifest_conflict) and rotL is kept held with it (SPEC 8.3). Ancestry for the cutoff follows every verified header whether or not accepted (SPEC 7.3), so b1 is an ancestor of frontier commit rotL; covered, and citing the winning seq 2 where bob is a member at epoch 0, b1 is accepted again.",
      [genesis, M("M2", M2ab, "ok"), C(b1, "ok"), M("W3", W3, "ok", "offer", rotW), M("L3", L3, "manifest_conflict", "offer", rotL)],
      [rotW, b1],
      [rotL],
      W3,
    );
  }

  // ── a newly listed host's first copy by replication (SPEC 6.1 rule 6, 8.1, 9.2) ──
  {
    // The owner created the repository on b.vault.example only; seq 2 invites alice, whose home host
    // a.vault.example is new, so it adds that host (SPEC 8.1, 8.6).
    const Gb = state(1, null, 0, [[owner, hostB]], { hosts: [ref(hostB)] });
    const rb = cm("r-b-first-copy", owner, [], Gb);
    const M2 = state(2, Gb, 0, [[owner, hostB], [alice, hostA]]);
    const a1 = cm("a1-first-copy", alice, [rb], M2);
    add(
      "new-host-first-copy-by-offer",
      "SPEC 6.1 rule 6, 8.1, 9.2: a.vault.example is first listed at seq 2 and gets its first copy by replication. The genesis, which lists only b.vault.example, arrives by offer with its first commit and is accepted: rule 6 applies to the tip of the chain being received, which is the seq 2 state that lists this host, not to the states before it. The seq 2 state is then accepted by offer, and alice, whose home host is a.vault.example and who is a member of the tip at epoch 0, pushes a child of the first commit: accepted, the only head.",
      [M("Gb", Gb, "ok", "offer", rb), M("M2-adds-a", M2, "ok", "offer"), C(a1, "ok")],
      [a1],
      [],
      M2,
    );
  }

  return {
    description:
      "Host acceptance scenarios (SPEC 6, 7, 8.3, 8.4, 9.1). Each scenario is one host's view of one repository: create a rules engine for `hostKey` (a.vault.example) " +
      "with head bound `headBound`, apply `steps` in order, and each step's verdict MUST equal `expect` (\"ok\" or the SPEC 10.4 code). Then the accepted commits with no " +
      "accepted child MUST be exactly `finalHeads`, the held commits (SPEC 6.5) exactly `finalHeld`, and the winning chain's tip manifestHash `finalTip` (null when no state " +
      "was accepted). When a scenario has `finalLeaves`, the pending leave requests (SPEC 8.4, one per member) MUST be exactly those `{ memberKey, at }`. A stored commit whose removal cutoff cannot yet be decided (SPEC 7.3) is neither a head nor held. Steps: `op` is manifest, commit, or leave. A manifest step's `item` is `{ manifest: SignedManifest, commit?: Commit }`, the publishManifest body: the " +
      "commit is the genesis commit (createRepo), the rotation commit of an epoch-raising state, or absent; the state and its commit are applied together or not at all " +
      "(SPEC 8.2, 8.3). A commit step's `item` is a Commit; a leave step's `item` is a LeaveRequest. `via` is the path: \"push\" is a client write (push, createRepo, " +
      "publishManifest, leave) whose authenticated caller is the commit author, the owner for a manifest, or memberKey for a leave, with the head bound applied; \"offer\" is " +
      "replication from a peer host (SPEC 9.1): no caller check and no head bound. A held commit answers forbidden on either path. `label` names the item for reading only. " +
      "Every expectation is written by hand from the SPEC rule each description cites. Keys, hosts, data keys, and wraps are those of manifest.json, plus an epoch 2 data key (32 bytes of 0x44) used only by content-epoch-jump-2; each commit's payload " +
      "is {\"v\":2,\"accounts\":{}} under AAD v2 with IV SHA-256(UTF8(\"avp/vectors/acceptance-iv/\" + label))[0..12]. Where two diverged states must hash in a set order, " +
      "the losing one's wraps use the label \"<member>/g<i>\" for the first i that puts its manifestHash above the winner's. Generated by vectors/generate.ts.",
    scenarios,
  };
}

// ─── Negative ("MUST reject") bank, derived from the positive seeds ──────────────

const flipFirst = (b: Buffer) => Buffer.concat([Buffer.from([b[0] ^ 0x01]), b.subarray(1)]);
const flipLast = (b: Buffer) => Buffer.concat([b.subarray(0, b.length - 1), Buffer.from([b[b.length - 1] ^ 0x01])]);
const dropLast = (b: Buffer) => b.subarray(0, b.length - 1);

/**
 * The 0.5 MUST-reject cases, from the manifest.json and commit.json items and the federation.json
 * tokens. Each carries `base`, the fields that make it the valid construction it was mutated from,
 * so a checker can confirm that the one mutation is what makes it fail.
 */
function buildNegatives05(ctx: Ctx, fed: FedItems): any[] {
  const { owner, alice, carol, hostA, hostB, m1, m2, c1, c2, c3 } = ctx;
  const neg = (name: string, op: string, mutation: string, fields: Record<string, unknown>, base: Record<string, unknown>) => ({
    name,
    op,
    mutation,
    expect: "reject",
    ...fields,
    base,
  });
  const wireM = signedManifestToWire;
  const wireC = commitToWire;
  const aliceSign = (msg: Buffer) => ed25519Sign(importEd25519Private(alice.edSeed), msg);
  const aadOf = (repoId: string, keyEpoch: number, author: Buffer, parents: Buffer[]) => ({
    repoId,
    keyEpoch,
    author: b64(author),
    parents: parents.map(b64),
  });
  const goodAad = aadOf(c2.repoId, c2.keyEpoch, c2.author, c2.parents);
  const payload = (name: string, mutation: string, aad: unknown) =>
    neg(`payload/${name}`, "payload-decrypt", mutation, { dataKeyHex: hex(DATA_KEYS[0]), ivB64: b64(c2.iv), ciphertextB64: b64(c2.ciphertext), aad }, { aad: goodAad });
  const wireGrant = { schemeId: fed.grantWrap.schemeId, ephemeralPublicKey: b64(fed.grantWrap.ephemeralPublicKey), iv: b64(fed.grantWrap.iv), ciphertext: b64(fed.grantWrap.ciphertext) };
  const relinked = signManifest({ ...m2.state, prevManifestHash: flipFirst(m2.state.prevManifestHash) }, owner.edSeed);

  return [
    neg(
      "manifest/bad-owner-signature",
      "manifest-verify",
      "flip the first byte of the ownerSignature of manifest.json add-members",
      { signedManifest: wireM({ ...m2, ownerSignature: flipFirst(m2.ownerSignature) }) },
      { signedManifest: wireM(m2) },
    ),
    neg(
      "manifest/signed-by-other-key",
      "manifest-verify",
      "replace the ownerSignature of add-members with alice's signature over the same state bytes",
      { signedManifest: wireM({ ...m2, ownerSignature: aliceSign(encodeManifestState(m2.state)) }) },
      { signedManifest: wireM(m2) },
    ),
    neg(
      "manifest/wrong-prev-hash",
      "manifest-link",
      "flip the first byte of add-members' prevManifestHash and re-sign it with the owner key, so only the link to genesis is wrong",
      { prev: wireM(m1), next: wireM(relinked) },
      { next: wireM(m2) },
    ),
    neg(
      "commit/id-mismatch-tampered-ciphertext",
      "commit-verify",
      "flip the first ciphertext byte of commit.json single-parent, keeping commitId and authorSignature",
      { commit: wireC({ ...c2, ciphertext: flipFirst(c2.ciphertext) }) },
      { commit: wireC(c2) },
    ),
    neg(
      "commit/id-mismatch-tampered-header",
      "commit-verify",
      "change single-parent's manifestSeq from 2 to 1, keeping commitId and authorSignature",
      { commit: wireC({ ...c2, manifestSeq: 1 }) },
      { commit: wireC(c2) },
    ),
    neg(
      "commit/author-signed-other-id",
      "commit-verify",
      "replace single-parent's authorSignature with alice's valid signature over the three-parent-merge commit id",
      { commit: wireC({ ...c2, authorSignature: aliceSign(commitSigMessage(c3.commitId)) }) },
      { commit: wireC(c2) },
    ),
    payload("aad-v2-swapped-parent", "decrypt single-parent with the parent set {three-parent-merge id} in place of {root id}", aadOf(c2.repoId, 0, c2.author, [c3.commitId])),
    payload("aad-v2-wrong-epoch", "decrypt single-parent with keyEpoch 1 in place of 0", aadOf(c2.repoId, 1, c2.author, c2.parents)),
    payload("aad-v2-wrong-author", "decrypt single-parent with carol as the author in place of alice", aadOf(c2.repoId, 0, carol.edPub, c2.parents)),
    payload(
      "aad-v2-wrong-repo-id",
      "decrypt single-parent under another repository's repoId (genesis nonce 0x02..02)",
      aadOf(deriveRepoId(owner.edPub, Buffer.alloc(16, 0x02)), 0, c2.author, c2.parents),
    ),
    payload("aad-v2-dropped-parent", "decrypt single-parent with an empty parent set", aadOf(c2.repoId, 0, c2.author, [])),
    neg(
      "link-grant/unwrapped-with-rdk-wrap-label",
      "wrap-unwrap",
      "unwrap the federation.json link grant with info avp/rdk-wrap/v1 in place of avp/owner-link/v1",
      { recipientPrivateKeyHex: hex(fed.linkEphemeralPriv), wrap: wireGrant, info: "avp/rdk-wrap/v1" },
      { info: "avp/owner-link/v1" },
    ),
    neg(
      "acceptance/verified-with-other-host-key",
      "acceptance-verify",
      "verify the federation.json acceptance (signed by b.vault.example) under a.vault.example's host key",
      { acceptance: acceptanceToWire(fed.acceptance), verifyHostKey: b64(hostA.hostKey) },
      { verifyHostKey: b64(hostB.hostKey) },
    ),
    neg(
      "acceptance/tampered-expires-at",
      "acceptance-verify",
      "add 1 to the acceptance's expiresAt, keeping its signature",
      { acceptance: acceptanceToWire({ ...fed.acceptance, expiresAt: fed.acceptance.expiresAt + 1 }), verifyHostKey: b64(hostB.hostKey) },
      { acceptance: acceptanceToWire(fed.acceptance) },
    ),
    neg(
      "leave/signed-by-other-key",
      "leave-verify",
      "replace the signature of federation.json alice-leaves with carol's signature over the same message",
      { leave: leaveToWire({ ...fed.aliceLeave, signature: ed25519Sign(importEd25519Private(carol.edSeed), leaveSignMessage(fed.aliceLeave)) }) },
      { leave: leaveToWire(fed.aliceLeave) },
    ),
  ];
}

function buildNegatives(extra: any[]): any {
  const kw = read("key-wrap.json").cases[0];
  const ed = read("ed25519.json").cases.find((c: any) => c.name === "rfc8032-test2");
  const edOther = read("ed25519.json").cases.find((c: any) => c.name === "rfc8032-test3");

  // Recompute the valid base ciphertext so the mutations below are self-derived.
  const ephPub = fromB64(kw.wrappedKey.ephemeralPublicKey);
  const recipPriv = fromB64(kw.recipientPrivateKeyB64);
  const kwIv = fromB64(kw.wrappedKey.iv);
  const kek = wrapKek(x25519(importX25519Private(recipPriv), importX25519Public(ephPub)), ephPub);
  const kwCt = aesGcmEncrypt(kek, kwIv, WRAP_INFO, fromB64(kw.dataKeyB64));
  // RFC 7748 §6.1 Bob private scalar, used as a *wrong* recipient key (valid scalar, wrong KEK).
  const wrongRecipientB64 = b64(fromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));

  const sig = fromHex(ed.signatureHex);

  const wrap = (name: string, mutation: string, over: Record<string, unknown>) => ({
    name: `key-wrap/${name}`,
    op: "key-unwrap",
    mutation,
    expect: "reject",
    recipientPrivateKeyB64: kw.recipientPrivateKeyB64,
    ephemeralPublicKeyB64: kw.wrappedKey.ephemeralPublicKey,
    ivB64: kw.wrappedKey.iv,
    ciphertextB64: b64(kwCt),
    ...over,
  });

  const verify = (name: string, mutation: string, over: Record<string, unknown>) => ({
    name: `ed25519/${name}`,
    op: "ed25519-verify",
    mutation,
    expect: "reject",
    publicKeyHex: ed.publicKeyHex,
    messageHex: ed.messageHex,
    signatureHex: ed.signatureHex,
    ...over,
  });

  return {
    description:
      "MUST-reject vectors. Each case starts from a valid construction (the seeds of key-wrap.json and ed25519.json, and the items of manifest.json, commit.json, and federation.json) and applies exactly one mutation; a conformant implementation MUST reject it. 'op' is the operation: 'key-unwrap' (X25519-HKDF-SHA256-AESGCM-v1, info avp/rdk-wrap/v1) and 'wrap-unwrap' (the same scheme under the case's `info`) MUST fail authentication; 'ed25519-verify' MUST return false; 'manifest-verify' (ownerSignature over the state bytes S under ownerKey, SPEC 4.2) MUST fail; 'manifest-link' MUST find that `next` does not link to `prev` (manifestSeq + 1 and prevManifestHash = manifestHash(prev), SPEC 6.3) although `next` is validly signed; 'commit-verify' (commitId recomputes from the header and authorSignature verifies, SPEC 7.1) MUST fail; 'payload-decrypt' (AES-256-GCM under dataKeyHex with AAD v2 built from `aad`, SPEC 4.3) MUST fail authentication; 'acceptance-verify' (the signature under verifyHostKey, SPEC 11.3) and 'leave-verify' (the signature under memberKey, SPEC 11.4) MUST return false. Where a case has `base`, replacing its fields with `base` gives the valid construction, which MUST be accepted. Wire base64 strictness is implementation-specific and intentionally not tested here. Generated by vectors/generate.ts from the same seeds as the positive vectors.",
    cases: [
      wrap("flipped-tag", "flip the last byte of the wrap ciphertext (inside the GCM tag)", { ciphertextB64: b64(flipLast(kwCt)) }),
      wrap("tampered-body", "flip a bit in the first wrap-ciphertext byte", { ciphertextB64: b64(flipFirst(kwCt)) }),
      wrap("truncated-1-byte", "drop the last wrap-ciphertext byte", { ciphertextB64: b64(dropLast(kwCt)) }),
      wrap("wrong-recipient-key", "unwrap with a different recipient private key (wrong KEK)", { recipientPrivateKeyB64: wrongRecipientB64 }),
      wrap("wrong-ephemeral-key", "unwrap against a different ephemeral public key (wrong shared secret)", { ephemeralPublicKeyB64: kw.recipientPublicKeyB64 }),

      verify("flipped-signature", "flip the first signature byte", { signatureHex: hex(flipFirst(sig)) }),
      verify("wrong-message", "verify the valid signature against a different message", { messageHex: "ff" }),
      verify("wrong-public-key", "verify the valid signature under a different public key", { publicKeyHex: edOther.publicKeyHex }),
      ...extra,
    ],
  };
}

// ─── Entry point ────────────────────────────────────────────────────────────────

const write = process.argv.includes("--write");

const positives = checkPositives();
checkAnchors(positives);
const generated = build05();
const federation = buildFederation(generated.ctx);
const negatives = buildNegatives(buildNegatives05(generated.ctx, federation.items));
const owned: Array<[string, any]> = [
  ["bip39-owner.json", generated.bip39],
  ["manifest.json", generated.manifest],
  ["commit.json", generated.commit],
  ["federation.json", federation.file],
  ["merge.json", buildMerge(generated.ctx)],
  ["acceptance.json", buildAcceptance(generated.ctx)],
];
/** The number of items in a generated file, for the log line. */
const itemCount = (content: any) => (content.cases ?? content.scenarios ?? content.tokens ?? []).length;

// --write never rewrites anything while a positive or anchor check fails: a broken primitive, a
// changed wordlist, or a Trezor anchor mismatch must not regenerate the owned files.
const preWriteFailures = positives.filter((c) => !c.ok);
if (write && preWriteFailures.length > 0) {
  for (const c of preWriteFailures) console.error(`  [DRIFT] ${c.name}  (${c.detail})`);
  console.error(`\nRefusing to write: ${preWriteFailures.length} check(s) failed. Nothing was written.`);
  process.exit(1);
}

if (write) {
  writeFileSync(join(dir, "negative.json"), JSON.stringify(negatives, null, 2) + "\n");
  console.log(`Wrote negative.json (${negatives.cases.length} cases).`);
  for (const [file, content] of owned) {
    writeFileSync(join(dir, file), JSON.stringify(content, null, 2) + "\n");
    console.log(`Wrote ${file} (${itemCount(content)} items).`);
  }
} else {
  for (const [file, content] of owned) checkGenerated(file, content, positives);
}

let failed = positives.filter((c) => !c.ok);

if (!write) {
  const committed = JSON.stringify(read("negative.json"));
  const regenerated = JSON.stringify(negatives);
  if (committed !== regenerated) {
    failed = failed.concat([{ name: "negative.json matches generator output", ok: false, detail: "run `bun vectors/generate.ts --write`" }]);
  }
}

for (const c of positives) {
  console.log(`  [${c.ok ? "OK" : "DRIFT"}] ${c.name}${c.ok ? "" : `  (${c.detail})`}`);
}
if (!write) {
  const negOk = failed.every((f) => f.name !== "negative.json matches generator output");
  console.log(`  [${negOk ? "OK" : "DRIFT"}] negative.json matches generator output`);
}

if (failed.length > 0) {
  console.error(`\n${failed.length} vector(s) drifted from their derivation. ${write ? "" : "Re-run with --write if the change is intended."}`);
  process.exitCode = 1;
} else {
  console.log(`\nAll ${positives.length} positive checks reproduce from their seeds; negative bank is ${write ? "written" : "in sync"}.`);
}
