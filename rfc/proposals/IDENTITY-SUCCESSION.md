# Proposal: Identity succession

**Status:** Proposal for discussion. **Nothing in this document is implemented in this repository.** Open decisions are listed in §8.

## 1. Goal

A VaultysID DID is derived from the identity's public keys. Changing the keys therefore changes the DID, and every contact and service that knew the old identity would have to be told, by hand, that the new one is the same person. That happens:

- when a classical identity (Ed25519) moves to a post-quantum one (hybrid or Dilithium, `rfc/PQ-ENCRYPTION.md`). A 3.x wallet migrated to 4.0 keeps its classical identity and DID (see `rfc/PROTOCOL.md` §3.2); a hybrid identity made from the same entropy has a different DID;
- when a key is replaced: a lost device, a new security key, a suspected compromise;
- when a person who used one global identity with a service moves to a service identity (`rfc/SERVICE-IDENTITIES.md`) and wants that service to keep their account.

A **succession statement** says "the identity `from` is now `to`", signed by both. A contact or a service that knew `from` can then move its trust to `to` without a new meeting.

## 2. Non-goals

- Revocation of a key without a successor. A statement always names its successor.
- Recovering an identity whose old key is lost. The old key must sign. Social or custodial recovery is a different problem.
- Making the succession public. A statement goes to the parties that knew `from`, not to a directory. §6 explains why this matters for service identities.

## 3. Statement

The unsigned statement is the msgpack encoding of the following map. Keys appear in this order and all are required unless marked optional:

| key | type | value |
|---|---|---|
| `v` | int | `1` |
| `from` | bin | the serialized id of the old identity (version 1) |
| `to` | bin | the serialized id of the new identity (version 1) |
| `issuedAt` | int | milliseconds since the epoch, set by the issuer |
| `reason` | str | `"upgrade"`, `"rotation"` or `"service"` |
| `service` | str | optional; the canonical service id (`rfc/SERVICE-IDENTITIES.md` §3), required when `reason` is `"service"` |

Signatures:

```
h      = SHA-256("VAULTYS_SUCCESSION_V1" || unsigned)
sigOld = from.sign(h)
sigNew = to.sign(h)
statement = msgpack({ unsigned, sigOld, sigNew })
```

`VAULTYS_SUCCESSION_V1` is a new signing domain. Like `VAULTYS_HANDSHAKE_V1`, implementations MUST NOT expose any API that signs caller-supplied data under it, so a succession cannot be obtained through `signChallenge` (`VAULTYS_SIGN`) or `sign` (`VAULTYS_RAW`).

## 4. Acceptance

A party that holds a relationship certificate with `from` (a contact) or registered it (a service) accepts a statement when:

1. both signatures verify, `v` is 1, and `from` and `to` are different identities;
2. `from` is an identity it already knows. A statement about an unknown identity carries no trust and is ignored;
3. **first seen wins:** it has not already accepted a statement from `from` naming a different `to`. A second, different successor is a fork: it MUST be refused and SHOULD be shown to the user, since one of the two keys was compromised;
4. when `service` is present, it is the receiving service's own canonical id.

After acceptance:

- the entry of `from` is re-keyed to `to`'s DID. The metadata set on the contact are kept;
- the old relationship certificate is kept as history, together with the statement;
- signatures made by `from` alone, dated after the statement was received, are refused;
- the next contact with `to` SHOULD run a normal handshake, producing a relationship certificate for `to`. A statement is not a relationship certificate.

The receiving party records **its own** reception time. Decisions never rely on `issuedAt`, which the issuer chose.

## 5. Post-quantum moves

The reason to leave a classical key is that it may one day be forged. An attacker able to forge `from`'s signatures can also issue a statement naming their own key as `to`. The rules above limit that attack to the parties that have **not yet** accepted the genuine statement. Hence:

- issue successions to post-quantum identities **early**, while forging classical signatures is out of reach, and deliver them to every known contact and service;
- an implementation MAY set a cutoff date after which a statement whose `from` is classical is accepted only when it is delivered over a post-quantum authenticated channel opened by `to` (`rfc/SECURE-CHANNEL.md`). See §8.

## 6. Service identities

A person who used their global identity with a service, and later uses the service identity derived for that service, can keep their account there with a statement whose `reason` is `"service"` and whose `service` is that service's canonical id.

- The statement links the two identities. It MUST be sent only to that service, over a channel bound to it, and MUST NOT be published. Otherwise anyone who receives it can link the global identity to that service identity, which is exactly what service identities exist to prevent.
- Rule 4 of §4 stops a statement made for one service from being replayed at another.
- One statement per service. Statements for different services are not linked to each other: each names a different `to`.

## 7. Implementation sketch

- `typescript/src/succession.ts`: `createSuccession(from, to, options)`, `verifySuccession(statement)`. In `IdManager`: `acceptSuccession(statement)`, applying §4 to the stores of contacts and registrations, plus a record of the accepted successions for rule 3. TypeScript first, as usual.
- Test vectors from the TypeScript reference, then Go (`go/pkg/succession`) and Rust.
- Delivery: a statement is a self-contained byte string, sent over any `Channel`. Apps decide when to send it (for example right after an identity is upgraded).

Rough effort: the RFC review, then about a week for TypeScript with tests and vectors, a few days each for Go and Rust once Rust has the 4.0 handshake.

## 8. Open decisions

1. The cutoff of §5: whether it is set by the library, by each app, or not at all.
2. Whether `from` may still sign anything after it issued a statement, for example to answer a contact that has not received the statement yet.
3. Whether a statement can be chained (`a → b`, then `b → c`), and how far a party follows such a chain when it only knew `a`.
4. Whether a transparency log or the service anchors of `rfc/SERVICE-IDENTITIES.md` §8 should also record successions of service-side identities, which are public anyway.
5. How a migrated 3.x wallet should use this: whether an app should offer the move to a hybrid identity right after the migration, and whether `reason: "upgrade"` should also carry the old certificate hashes recorded at migration.
