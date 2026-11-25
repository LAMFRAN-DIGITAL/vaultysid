# Vaultys ID
This is the main library to handle Vaultys DID and handcheck protocol

[![test](https://github.com/vaultys/vaultysid/actions/workflows/test.yml/badge.svg)](https://github.com/vaultys/vaultysid/actions/workflows/test.yml)
[![Socket](https://socket.dev/api/badge/npm/package/@vaultys/id)](https://socket.dev/npm/package/@vaultys/id)
![Libraries.io dependency status for latest release](https://img.shields.io/librariesio/release/npm/%40vaultys%2Fid)
![NPM Downloads](https://img.shields.io/npm/dw/%40vaultys%2Fid)
![GitHub License](https://img.shields.io/github/license/vaultys/vaultysid)
![Dependents (via libraries.io)](https://img.shields.io/librariesio/dependents/npm/%40vaultys%2Fid)



## Breaking security changes (4.0.0)

4.0.0 is an intentionally breaking security release. Identity ids, DIDs and secrets are unchanged, but the
protocols below are not compatible with 3.x and older:

- **Handshake (Challenger)**: only challenge `version = 1` exists; v0 encoding and v0 signatures are removed and any
  other version is rejected. Signatures are `sign(SHA-256("VAULTYS_HANDSHAKE_V1" || unsignedBytes))` through the
  handshake-only `signHandshake` / `verifyHandshake`. Strict state machine: a responder only accepts an INIT, an
  initiator only a STEP1 matching exactly what it sent, a responder only a COMPLETE matching exactly its STEP1
  (no more signing a STEP1 it never initiated, no replayed COMPLETE, no reflection). `setChallenge` /
  `fromCertificate` are read-only. `createChallenge(protocol, service, metadata?)` lost its `version` argument and
  `IdManager.protocol_version` / `setProtocolVersion` are gone. Accept callbacks receive the remote identity and
  accept flows require an INIT as first message.
- **Signature domains**: `signChallenge` keeps `VAULTYS_SIGN`; the new public `VaultysId.sign` / `verify` use
  `VAULTYS_RAW`. No public API can produce a handshake signature anymore.
- **DHIES v2** replaces DHIES: sender-authenticated (`es || ss`), `0x02 || nonce || e_pk || secretbox`; old
  ciphertexts can't be decrypted.
- **IdManager persistence**: the store always keeps the full secret (`store.secret`); stores/backups restore the
  exact same identity (algorithm, type, DID). Entropy-only (3.x) stores are rejected by `fromStore`; migrate them
  with `IdManager.fromLegacyStore` (see below). Empty backup passphrases are rejected.
- **Default deny** for remote services: `acceptPRF`, `acceptDecryptFile`/`acceptEncryptFile`, `acceptDecrypt` and
  `acceptSignFile` refuse unless an `accept` callback approves the remote. The file-encryption PRF namespace
  (`encryption/...`) is never served through `acceptPRF` to another identity.
- **WebAuthn**: no silent fallback to the insecure `SoftCredentials` authenticator; call `enableSoftCredentials()`
  explicitly (tests only). Assertions require `type === "webauthn.get"` and the UP flag, and check rpId/origin when
  configured with `configureWebAuthn({ rpId, origin })`. FIDO2 Dilithium5 keys are parsed correctly.
- **OTP**: `await me.getOTP(contact, prefix?, timelock?, time?)` is now
  `HMAC-SHA256(SHA-256(X25519(my cypher sk, contact cypher pk)), prefix || certificate || uint64be(counter))`, so only
  the two parties can compute it.
- **requestConnect / acceptConnect** are now a plain `p2p`/`auth` handshake (optionally pinned to a DID) saving the
  contact.
- Untrusted ids, secrets and certificates are length-checked and never throw uncaught `TypeError`s;
  `VaultysId.decrypt` correctly parses a hex sender id.

### Opening a 3.x wallet

A 3.x wallet opens in 4.0 with nothing to ask the user; it never talks the 3.x protocols again.

- `await IdManager.open(store, { legacyFallback? })` opens any store: a 4.0 store as `fromStore` does, a 3.x store
  (which kept only `entropy`) migrated in place, an empty store with a new machine identity. Opening it again opens
  it as it was left; a migration interrupted after the secret was written is finished.
  - Same identity and DID: the type and algorithm, which 3.x did not store, are found from the store's own
    certificates.
  - A store without any certificate gives nothing to check them against. It is opened with `legacyFallback`, by
    default `LEGACY_REOPEN_DEFAULT` (a machine ed25519 identity: what 3.x's own `fromStore` reopened such a store
    as); an app that knows what it created passes that instead. Such a store keeps its `entropy`
    (`isLegacyIdentityGuessed()` is true) until `confirmLegacyIdentity()`, and `fromLegacyStore(store, hint)` can
    still correct it.
  - A 3.x FIDO2 wallet is refused with an explicit error: 3.x stored only its `entropy`, not the credential id of
    the security key, so the store alone cannot reopen it (3.x could not either).
- `IdManager.fromLegacyStore(store, hint?)` is the explicit form: without a certificate it needs `hint`
  (`{ type: 0 | 1 | 2, alg: "ed25519" | "dilithium_ed25519" | "dilithium" }`), and a hint that contradicts the
  certificates is refused. `IdManager.importBackup(data, passphrase)` migrates a 3.x backup as `open` does (`true` or
  a hint: as `fromLegacyStore`; `false`: refused).
- The 3.x (version 0) certificates already in the store that involve this identity and verify are recorded at
  migration (`store.legacy`): `verifyRelationshipCertificate` and `verifyWebOfTrust` keep accepting those, and
  only those. `Challenger.verifyCertificate` still refuses every v0 certificate: v0 handshakes were signed like
  `signChallenge`, so a v0 certificate received later proves nothing.
- `legacyContacts()` and `legacyApps()` list the contacts and apps still on a v0 certificate. A new handshake with
  the same identity (`askContact` / `acceptContact`, both sides on 4.0) replaces its certificate and keeps its
  metadata; a 4.0 certificate is never replaced.
- `vaultysId.dhiesDecryptLegacyV1(message, claimedSenderId)` opens a 3.x DHIES message and returns
  `{ plaintext, senderVerified: false }`: that format never authenticated the sender. 4.0 never writes it.
- Unchanged from 3.x: identities and DIDs, `signChallenge` / file signatures, saltpack messages.
- Not possible: a live handshake between a 3.x and a 4.0 client. 3.x users must upgrade.
- Wallets written by the published 3.0.4 are frozen in `test/interops/legacy-v3-vectors.json`
  (`pnpm test:legacy:vectors` writes new ones), read by the TypeScript tests and by Go (`go/pkg/legacyv3`: identity
  recovery, v0 certificates, DHIES v1). A move from a migrated classical identity to a post-quantum one, keeping
  its contacts, is proposed in `rfc/proposals/IDENTITY-SUCCESSION.md`.

Cross-language vectors: `test/interops/security-v2-vectors.json` (`npx tsx test/interops/generate-security-v2-vectors.ts`).

## Getting Started

From `typescript/`, use Node.js 20 or later and pnpm.

```sh
pnpm install
pnpm build
pnpm test
```

`pnpm build` builds the Node.js and browser packages. CI tests on Node.js 20,
22, 24 and 26. The Node.js WebAuthn tests explicitly enable the software
authenticator and await CBOR encoding and signature verification.

For the browser suite, run `pnpm exec playwright install` once, then
`pnpm test:web`.

## External signing

`VaultysId.fromSigner(signer, encryptionSecretKey)` creates a type `0x01`
identity from a PureEd25519 signer and a local 32-byte X25519 secret. A
signer implements the `Ed25519Signer` interface exported by `@vaultys/id`.
The signer receives the domain-separated bytes prepared by VaultysID and
returns a raw 64-byte signature. Share `identity.id` with verifiers, who can
load it with `VaultysId.fromId()`.

For KMIP in Node.js, see the [optional adapter and local installation instructions](../kmip/README.md).
Browser bundles can use `@vaultys/id` on its own.

## Passport Active Authentication

`VaultysId.fromPassportAA()` creates a version 1, type `0x05` identity from
the passport chip's AA key. Supply DG15, DG14 for ECDSA, a reader for the
selected passport application, and a stable 32-byte local X25519 secret.

For a USB contactless reader on a desktop, use the optional
[`@vaultys/passport-nfc` adapter](../passport-nfc/README.md) to read the data
groups and supply the AA reader. For phone-based NFC, use the
[iOS and Android libraries](../passport-nfc/mobile/README.md) with your app's
native bridge. For an existing native NFC session, use the transceiver
adapter below.

```typescript
import { VaultysId, createPassportAAReader } from "@vaultys/id";

const reader = createPassportAAReader(transceive);
const identity = VaultysId.fromPassportAA({
  dg15,
  dg14,
  reader,
  encryptionSecretKey,
});

const signature = await identity.sign(message);
const valid = VaultysId.fromId(identity.id).verify(message, signature);
```

The `transceive` callback sends the logical APDU to the chip. Your NFC
integration selects the eMRTD application, reads the data groups, handles
BAC/PACE and secure messaging as needed, and returns unwrapped response bytes
including the status word. Set the second argument to `true` if the session
requires extended-length APDUs. A native integration can also supply a
`PassportAAReader` that performs all four AA operations in one session.

The TypeScript implementation supports RSA with ISO 9796-2 partial recovery
and ECDSA with named NIST P-256, P-384 and P-521 or Brainpool P256r1, P384r1
and P512r1 curves. ECDSA uses the supported SHA-2 algorithm advertised in
DG14. The public ID and signature can be verified offline, including in a
browser. A `Challenger` can use this identity in an ordinary handcheck.

Restore signing with `fromPassportAA()` and the same X25519 secret.
`IdManager` can store the public identity as a contact. A local
`IdManager` profile and its backup require an exportable signing secret.
AA proves access to the registered key. Passport authenticity, civil
identity and holder verification require separate evidence.

See the [type 05 wire draft](../rfc/PASSPORT-AA.md). The mock integration
tests run with `pnpm exec mocha test/passportAA.test.ts`.

## Checkout examples
The repository also have some examples. Try them:
- `pnpx tsx example/sideChannelAttack.js`
- `pnpx tsx example/logChallenge.js`
