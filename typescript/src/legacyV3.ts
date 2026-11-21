/**
 * Read-only support for wallets written by @vaultys/id 3.x.
 *
 * 3.x stores keep only the 32-byte `entropy` (no type, no algorithm) and its handshakes produced version 0
 * certificates, signed as `signChallenge` still signs today: SHA-256("VAULTYS_SIGN" || v0 encoding), the v0 encoding
 * leaving the metadata out. A v0 certificate is therefore only as good as the place it comes from: anyone who obtains
 * a `signChallenge` signature over chosen bytes can assemble one. So this module never makes a v0 certificate valid
 * in general (`Challenger.verifyCertificate` keeps refusing it). It only lets `IdManager` keep trusting the v0
 * certificates that were already in a 3.x store when that store was migrated, involve the store's own identity and
 * still verify; their hashes are recorded at migration time and nothing else is accepted later.
 */
import { decode } from "@msgpack/msgpack";
import { boxKeyPairFromSecretKey } from "./nacl";
import { Buffer } from "buffer/";
import { hash } from "./crypto";
import type { Store } from "./MemoryStorage";
import VaultysId from "./VaultysId";

export type LegacyAlgorithm = "ed25519" | "dilithium_ed25519" | "dilithium";
/** The identity type and algorithm a 3.x store was created with, when the store alone can't tell. */
export type LegacyIdentityHint = { type: 0 | 1 | 2; alg: LegacyAlgorithm };
/**
 * Recorded in the store under `legacy` when a 3.x store is migrated. `certificates` maps the hex SHA-256 of each
 * trusted v0 certificate to true (an object, not an array: the store serializer turns arrays into Buffers).
 * `guessed` marks a store that had no certificate to check the identity type and algorithm against: its `entropy` is
 * kept until `IdManager.confirmLegacyIdentity()`, so a wrong guess can still be corrected.
 */
export type LegacyMigrationRecord = { from: "3.x"; migratedAt: number; certificates: Record<string, true>; guessed?: true };

/**
 * What `IdManager.fromStore` in 3.x made of a store holding only `entropy`: a machine (type 0) ed25519 identity,
 * whatever the store was created as. The identity a 3.x app got back after a restart, if it reopened its store that
 * way.
 */
export const LEGACY_REOPEN_DEFAULT: LegacyIdentityHint = { type: 0, alg: "ed25519" };

export const LEGACY_RECORD_KEY = "legacy";

type V0Certificate = {
  protocol: string;
  service: string;
  timestamp: number;
  pk1: Buffer;
  pk2: Buffer;
  nonce: Buffer;
  sign1: Buffer;
  sign2: Buffer;
};

const SIGN_INCIPIT = Buffer.from("VAULTYS_SIGN", "utf8");

// The 3.x hand-rolled v0 encoder, byte for byte (including its fixstr headers and its uint64 branch).
const writeString = (name: string, value: string) => Buffer.concat([Buffer.from([0xa0 + name.length]), Buffer.from(name, "ascii"), Buffer.from([0xa0 + value.length]), Buffer.from(value, "ascii")]);

const writeBuffer = (name: string, value: Buffer) => {
  const nameHeader = Buffer.concat([Buffer.from([0xa0 + name.length]), Buffer.from(name, "ascii")]);
  const lengthHeader = value.length <= 65535 ? Buffer.from([0xc5, (value.length >> 8) & 0xff, value.length & 0xff]) : Buffer.from([0xc6, (value.length >> 24) & 0xff, (value.length >> 16) & 0xff, (value.length >> 8) & 0xff, value.length & 0xff]);
  return Buffer.concat([nameHeader, lengthHeader, value]);
};

const writeInt = (name: string, value: number) => {
  const start = Buffer.concat([Buffer.from([0xa0 + name.length]), Buffer.from(name, "ascii")]);
  let end: Buffer;
  if (value >= 0 && value <= 0x7f) end = Buffer.from([value]);
  else if (value < 0 && value >= -0x20) end = Buffer.from([value]);
  else if (value > 0 && value <= 0xff) end = Buffer.from([0xcc, value]);
  else if (value >= -0x80 && value <= 0x7f) end = Buffer.from([0xd0, value]);
  else if (value > 0 && value <= 0xffff) end = Buffer.from([0xcd, value >>> 8, value]);
  else if (value >= -0x8000 && value <= 0x7fff) end = Buffer.from([0xd1, value >>> 8, value]);
  else if (value > 0 && value <= 0xffffffff) end = Buffer.from([0xce, value >>> 24, value >>> 16, value >>> 8, value]);
  else if (value >= -0x80000000 && value <= 0x7fffffff) end = Buffer.from([0xd2, value >>> 24, value >>> 16, value >>> 8, value]);
  else if (value > 0 && value <= 18446744073709551615) {
    const hi = value / 2 ** 32;
    const lo = value % 2 ** 32;
    end = Buffer.from([0xd3, hi >>> 24, hi >>> 16, hi >>> 8, hi, lo >>> 24, lo >>> 16, lo >>> 8, lo]);
  } else end = Buffer.from([0x00]);
  return Buffer.concat([start, end]);
};

const encodeUnsignedV0 = (c: V0Certificate) => Buffer.concat([Buffer.from([0x87]), writeString("protocol", c.protocol), writeString("service", c.service), writeInt("timestamp", c.timestamp), writeBuffer("pk1", c.pk1), writeBuffer("pk2", c.pk2), writeBuffer("nonce", c.nonce), Buffer.from([0xa0 + "metadata".length]), Buffer.from("metadata", "ascii"), Buffer.from([0x80])]);

const isBytes = (v: unknown): v is Uint8Array => v instanceof Uint8Array;

/** A COMPLETE version 0 certificate, decoded, or null. Does not check signatures. */
export const decodeV0Certificate = (certificate: Uint8Array): V0Certificate | null => {
  try {
    const c = decode(Buffer.from(certificate)) as Record<string, unknown>;
    if (!c || typeof c !== "object" || (c.version !== undefined && c.version !== 0)) return null;
    if (typeof c.protocol !== "string" || typeof c.service !== "string" || typeof c.timestamp !== "number") return null;
    if (!isBytes(c.pk1) || !isBytes(c.pk2) || !isBytes(c.nonce) || !isBytes(c.sign1) || !isBytes(c.sign2) || c.nonce.length !== 32) return null;
    return { protocol: c.protocol, service: c.service, timestamp: c.timestamp, pk1: Buffer.from(c.pk1), pk2: Buffer.from(c.pk2), nonce: Buffer.from(c.nonce), sign1: Buffer.from(c.sign1), sign2: Buffer.from(c.sign2) };
  } catch {
    return null;
  }
};

const verifyV0Signature = (id: VaultysId, rawId: Buffer, unsigned: Buffer, signature: Buffer) => {
  try {
    // 3.x signed through signChallenge; 2.x through SHA-256(id || challenge)
    if (id.verifyChallenge(unsigned, signature, true)) return true;
    return !!id.keyManager.verify(hash("sha256", Buffer.concat([rawId, unsigned])), signature, true);
  } catch {
    return false;
  }
};

/** Both signatures of a COMPLETE v0 certificate, with the 3.x rules. Never throws. */
export const verifyV0CertificateSignatures = (certificate: Uint8Array): boolean => {
  const c = decodeV0Certificate(certificate);
  if (!c) return false;
  try {
    const id1 = VaultysId.fromId(c.pk1);
    const id2 = VaultysId.fromId(c.pk2);
    if (id1.version !== 0 || id2.version !== 0) return false;
    const unsigned = encodeUnsignedV0(c);
    return verifyV0Signature(id2, c.pk2, unsigned, c.sign2) && verifyV0Signature(id1, c.pk1, unsigned, c.sign1);
  } catch {
    return false;
  }
};

export const certificateHash = (certificate: Uint8Array) => hash("sha256", Buffer.from(certificate)).toString("hex");

const sameIdentity = (a: VaultysId, rawId: Buffer) => {
  try {
    const b = VaultysId.fromId(rawId);
    return a.type === b.type && Buffer.from(a.keyManager.signer.publicKey).equals(Buffer.from(b.keyManager.signer.publicKey));
  } catch {
    return false;
  }
};

/** Whether `me` is one of the two parties of a v0 certificate. */
export const involves = (me: VaultysId, certificate: Uint8Array) => {
  const c = decodeV0Certificate(certificate);
  return !!c && (sameIdentity(me, c.pk1) || sameIdentity(me, c.pk2));
};

const toBytes = (v: unknown): Buffer | null => {
  if (isBytes(v)) return Buffer.from(v);
  if (v && typeof v === "object" && (v as { type?: string }).type === "Buffer" && Array.isArray((v as { data?: unknown }).data)) return Buffer.from((v as { data: number[] }).data);
  return null;
};

/** Every certificate a 3.x store holds: contacts, registrations and web of trust. */
export const storedCertificates = (store: Store): Buffer[] => {
  const out: Buffer[] = [];
  for (const table of ["contacts", "registrations"]) {
    const sub = store.substore(table);
    for (const key of sub.list()) {
      const cert = toBytes(sub.get(key)?.certificate);
      if (cert) out.push(cert);
    }
  }
  const wot = store.substore("wot");
  for (const key of wot.list()) {
    const cert = toBytes(wot.get(key));
    if (cert) out.push(cert);
  }
  return out;
};

/** A store written by 3.x and not migrated yet: a 32-byte `entropy` and no `secret`. */
export const isLegacyV3Store = (store: Store) => !store.get("secret") && toBytes(store.get("entropy"))?.length === 32;

/** The 32-byte `entropy` of a 3.x store, or null. */
export const legacyEntropy = (store: Store) => {
  const entropy = toBytes(store.get("entropy"));
  return entropy && entropy.length === 32 ? entropy : null;
};

/**
 * A 3.x FIDO2 wallet (type 3 or 4) also stores only `entropy`: the X25519 key of the identity comes from it
 * (secret = SHA-512(entropy)[0..32]), but the credential id the authenticator needs is not in the store, nor in any
 * certificate. Such a wallet is recognized, never rebuilt, so that it is not mistaken for a software identity.
 */
const isOwnFidoParty = (entropy: Buffer, rawId: Buffer) => {
  try {
    const id = VaultysId.fromId(rawId);
    if (!id.isHardware()) return false;
    const cypherPublicKey = Buffer.from(boxKeyPairFromSecretKey(hash("sha512", entropy).slice(0, 32)).publicKey);
    const theirs = (id.keyManager as unknown as { cypher?: { publicKey?: Uint8Array } }).cypher?.publicKey;
    return !!theirs && cypherPublicKey.equals(Buffer.from(theirs));
  } catch {
    return false;
  }
};

const CANDIDATES: LegacyIdentityHint[] = (["ed25519", "dilithium_ed25519", "dilithium"] as const).flatMap((alg) => ([1, 0, 2] as const).map((type) => ({ type, alg })));

/**
 * The identity of a 3.x store (`entropy` only). The type and algorithm are found by matching the candidates against
 * the store's own certificates. With no certificate to match, `hint` is used if given (`guessed: false`, the caller
 * vouches for it), else `fallback` (`guessed: true`), else it fails. A hint that contradicts the certificates is
 * refused, and so is a FIDO2 wallet (its credential id is not in the store).
 */
export const recoverLegacyIdentity = async (store: Store, hint?: LegacyIdentityHint, fallback?: LegacyIdentityHint): Promise<{ vaultysId: VaultysId; guessed: boolean }> => {
  const entropy = legacyEntropy(store);
  if (!entropy) throw new Error("Not a 3.x store: no 32-byte entropy");
  const certificates = storedCertificates(store).filter((c) => decodeV0Certificate(c));
  const matches = (id: VaultysId) => certificates.some((c) => involves(id, c));
  const fido = () =>
    certificates.some((c) => {
      const d = decodeV0Certificate(c)!;
      return isOwnFidoParty(entropy, d.pk1) || isOwnFidoParty(entropy, d.pk2);
    });
  if (hint) {
    const id = await VaultysId.fromEntropy(entropy, hint.type, hint.alg);
    if (certificates.length > 0 && !matches(id)) throw new Error("The type/algorithm hint does not match the identity found in the store's certificates");
    return { vaultysId: id, guessed: false };
  }
  if (certificates.length === 0) {
    if (fallback) return { vaultysId: await VaultysId.fromEntropy(entropy, fallback.type, fallback.alg), guessed: true };
    throw new Error("3.x store without certificates: pass the identity type and algorithm it was created with");
  }
  for (const candidate of CANDIDATES) {
    const id = await VaultysId.fromEntropy(entropy, candidate.type, candidate.alg);
    if (matches(id)) return { vaultysId: id, guessed: false };
  }
  if (fido()) throw new Error("3.x FIDO2 wallet: the store does not hold the credential id of the security key, so it cannot be reopened from the store alone");
  throw new Error("No identity type/algorithm derived from this entropy appears in the store's certificates");
};
