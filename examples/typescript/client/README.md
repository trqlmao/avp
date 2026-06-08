# AVP reference client, TypeScript

A tiny, runnable reference client for the [HTTP/JSON profile](../../../SPEC.md). It drives the full
lifecycle against a running server so you can watch every operation happen end to end, with **real
envelope and key-wrap cryptography**. Node built-ins only; the source is two files,
[`src/client.ts`](src/client.ts) and [`src/crypto.ts`](src/crypto.ts).

```sh
bun install
bun run start          # drives the flow against http://localhost:8787
bun run typecheck      # tsc --noEmit
bun test               # runs crypto.test.ts, including vector cross-checks
```

Point it at a different server with the `AVP_SERVER_URL` environment variable:

```sh
AVP_SERVER_URL=http://vault.example:8787 bun run start
```

You need a server running first. The sibling [`../server`](../server) is the obvious one:

```sh
cd ../server && bun install && bun run start
```

## What it does

In one run, with two locally generated members (`alice` and `bob`):

1. **Generate keypairs.** Each member gets a fresh Ed25519 signing keypair and a fresh X25519
   key-wrapping keypair (`node:crypto`). The base64 raw 32-byte Ed25519 public key is the member id
   (SPEC section 2).
2. **Authenticate.** The `challenge` -> sign nonce -> `token` flow. The client signs the **raw nonce
   bytes** (base64-decoded), which is exactly what a conformant server verifies.
3. **createRepo.** Alice mints a random 32-byte data key, AES-256-GCM-encrypts the initial alt
   payload (binding `repoId/payloadVersion/keyEpoch` into the AAD), wraps the data key to her own
   X25519 key, and creates the repo with the real ciphertext.
4. **pull.** Once at the known version (server reports `unchanged`, omits the envelope) and once
   from version 0 (server returns the current envelope).
5. **push.** Writes a real v2 payload with optimistic concurrency, then deliberately re-pushes at a
   stale expected version to show the `conflict` response.
6. **addMember.** Alice wraps the data key to bob's X25519 public key and adds his member entry to
   the manifest.
7. **fetchMemberKey.** Looks bob's entry back up by member id (URL-encoded, because base64 ids
   contain `+ / =`).
8. **bob decrypts.** Bob authenticates with his own keypair, pulls the shared repo, finds his own
   member entry, unwraps the data key from his X25519 private key, AES-256-GCM-decrypts the payload,
   and prints the recovered alts.

Each step prints a one-line transcript entry. The server is zero-knowledge throughout: it never holds
the data key or the plaintext.

## The crypto (SPEC sections 4-5)

All constructions are in [`src/crypto.ts`](src/crypto.ts), implemented with `node:crypto` builtins
and verified against `vectors/*.json` by [`src/crypto.test.ts`](src/crypto.test.ts):

**Payload AEAD (SPEC section 4)**

```
AAD = UTF8(repoId) || 0x1F || int64BE(payloadVersion) || int64BE(keyEpoch)
ciphertext = AES-256-GCM(dataKey, iv=random(12), aad=AAD, plaintext) || tag
```

Binding the version and epoch counters into the AAD means a stale-epoch or stale-version
ciphertext cannot be decrypted with a fresh key, defeating rollback and cross-epoch replay.

**Data-key wrap scheme `X25519-HKDF-SHA256-AESGCM-v1` (SPEC section 4)**

```
shared      = X25519(ephemeralPriv, recipientPub)          -- raw, unhashed
kek         = HKDF-SHA256(ikm=shared, salt=ephemeralPubRaw, info="avp/rdk-wrap/v1", L=32)
wrappedKey  = AES-256-GCM(kek, iv=random(12), aad="avp/rdk-wrap/v1", plaintext=dataKey) || tag
```

The ECDH secret is used directly as the HKDF input keying material (never as a key). The
ephemeral public key acts as the HKDF salt so the KEK is bound to the specific ECDH exchange.

Wire encoding for all keys, IVs, and ciphertext fields: standard base64 with padding.

## What is simplified (do not ship this)

- **No TLS.** It talks plain HTTP to `localhost` by default. A real client uses HTTPS; bearer tokens
  are credentials and the transport MUST be TLS (SPEC section 12).
- **Single process, no persistence.** It generates fresh keypairs each run and keeps no state.
- **No anti-MITM key-binding verification.** A production client SHOULD (and, off a host it does not
  operate, MUST) verify `MemberEntry.keyBindingSig` before wrapping a data key to a served member
  entry (SPEC section 9). This example skips that step.
- **No member removal / rekeying.** SPEC section 7 describes the rekey flow on member removal; this
  example only adds members.
