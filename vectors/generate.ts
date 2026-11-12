/**
 * Reproducible derivation of the AVP conformance vectors.
 *
 * Two jobs:
 *   --check (default): re-derive every committed vector's value fields from its documented seeds and
 *     assert the committed file matches. This is the provenance and drift gate: the vectors are not
 *     arbitrary bytes, they are exactly what this script computes. Read-only.
 *   --write: (re)generate the files this script owns: negative.json (the MUST-reject bank) and the
 *     0.5 construction vectors bip39-owner.json, manifest.json, and commit.json, which are derived
 *     only from the seeds documented below and in each file's `seeds`.
 *
 * The RFC-anchored positive vectors (hkdf, x25519, ed25519, key-wrap) and federation.json are
 * re-derived and checked here but never rewritten, so their reviewed prose and formatting are
 * preserved. The crypto is reused from the vector-tested reference at ../examples/conformance/src so
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
  buildAadV2,
  deriveRepoId,
  encodeCommitHeader,
  encodeManifestState,
  manifestHash,
  signCommit,
  signManifest,
  type Commit,
  type HostRef,
  type ManifestState,
  type MemberEntry,
  type Removal,
  type SignedManifest,
} from "../examples/conformance/src/constructions.ts";
import { commitToWire, signedManifestToWire } from "../examples/conformance/src/vectors.ts";

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

function build05(): { bip39: any; manifest: any; commit: any } {
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

  return { bip39, manifest, commit: commitFile };
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
    if (k === "cases") continue;
    eq(`${file} ${k}`, JSON.stringify(got[k]), JSON.stringify(want[k]), r);
  }
  eq(`${file} case count`, String(got.cases?.length), String(want.cases.length), r);
  for (const c of want.cases) {
    const g = (got.cases ?? []).find((x: any) => x.name === c.name);
    eq(`${file} ${c.name}`, JSON.stringify(g), JSON.stringify(c), r);
  }
  eq(`${file} matches generator output`, JSON.stringify(got), JSON.stringify(want), r);
}

// ─── Negative ("MUST reject") bank, derived from the positive seeds ──────────────

const flipFirst = (b: Buffer) => Buffer.concat([Buffer.from([b[0] ^ 0x01]), b.subarray(1)]);
const flipLast = (b: Buffer) => Buffer.concat([b.subarray(0, b.length - 1), Buffer.from([b[b.length - 1] ^ 0x01])]);
const dropLast = (b: Buffer) => b.subarray(0, b.length - 1);

function buildNegatives(): any {
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
      "MUST-reject vectors. Each case starts from a valid construction (the seeds of key-wrap.json and ed25519.json) and applies exactly one mutation; a conformant implementation MUST reject it. 'op' is the operation: 'key-unwrap' (X25519-HKDF-SHA256-AESGCM-v1) MUST fail authentication; 'ed25519-verify' MUST return false. Wire base64 strictness is implementation-specific and intentionally not tested here. Generated by vectors/generate.ts from the same seeds as the positive vectors.",
    cases: [
      wrap("flipped-tag", "flip the last byte of the wrap ciphertext (inside the GCM tag)", { ciphertextB64: b64(flipLast(kwCt)) }),
      wrap("tampered-body", "flip a bit in the first wrap-ciphertext byte", { ciphertextB64: b64(flipFirst(kwCt)) }),
      wrap("truncated-1-byte", "drop the last wrap-ciphertext byte", { ciphertextB64: b64(dropLast(kwCt)) }),
      wrap("wrong-recipient-key", "unwrap with a different recipient private key (wrong KEK)", { recipientPrivateKeyB64: wrongRecipientB64 }),
      wrap("wrong-ephemeral-key", "unwrap against a different ephemeral public key (wrong shared secret)", { ephemeralPublicKeyB64: kw.recipientPublicKeyB64 }),

      verify("flipped-signature", "flip the first signature byte", { signatureHex: hex(flipFirst(sig)) }),
      verify("wrong-message", "verify the valid signature against a different message", { messageHex: "ff" }),
      verify("wrong-public-key", "verify the valid signature under a different public key", { publicKeyHex: edOther.publicKeyHex }),
    ],
  };
}

// ─── Entry point ────────────────────────────────────────────────────────────────

const write = process.argv.includes("--write");

const positives = checkPositives();
checkAnchors(positives);
const negatives = buildNegatives();
const generated = build05();
const owned: Array<[string, any]> = [
  ["bip39-owner.json", generated.bip39],
  ["manifest.json", generated.manifest],
  ["commit.json", generated.commit],
];

if (write) {
  writeFileSync(join(dir, "negative.json"), JSON.stringify(negatives, null, 2) + "\n");
  console.log(`Wrote negative.json (${negatives.cases.length} cases).`);
  for (const [file, content] of owned) {
    writeFileSync(join(dir, file), JSON.stringify(content, null, 2) + "\n");
    console.log(`Wrote ${file} (${content.cases.length} cases).`);
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
