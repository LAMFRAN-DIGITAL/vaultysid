import { Readable, Writable } from "stream";
import Challenger, { CHALLENGE_STATE } from "./Challenger";
import KeyManager, { Ed25519Manager, Fido2Manager, Fido2PRFManager, HybridManager, DilithiumManager } from "./KeyManager";
import { Channel, StreamChannel } from "./MemoryChannel";
import { storagify, Store } from "./MemoryStorage";
import SoftCredentials from "./platform/SoftCredentials";
import VaultysId from "./VaultysId";
import { hash, randomBytes, secureErase } from "./crypto";
import { decode, encode } from "@msgpack/msgpack";
import { Buffer } from "buffer/";
import { SECRETBOX_NONCE_LENGTH, secretboxOpen, secretboxSeal } from "./nacl";
import { VaultysBackup } from "./platform/abstract";
import { platformCrypto } from "./platform";
import DeprecatedKeyManager from "./KeyManager/DeprecatedKeyManager";
import PassportAAManager, { TYPE_PASSPORT_AA } from "./KeyManager/PassportAAManager";
import { LEGACY_RECORD_KEY, LEGACY_REOPEN_DEFAULT, certificateHash, decodeV0Certificate, involves, isLegacyV3Store, legacyEntropy, recoverLegacyIdentity, storedCertificates, verifyV0CertificateSignatures } from "./legacyV3";
import type { LegacyIdentityHint, LegacyMigrationRecord } from "./legacyV3";
import { ContactError, isPostQuantumPeer, type PostQuantumPeerOption } from "./postQuantumPeer";

/**
 * Storage key for "wot" and "signatures": `<timestamp>-<hex SHA-256(data)>`. The timestamp alone made two entries
 * of the same millisecond overwrite each other; keys still sort by date and stay opaque strings.
 */
export const timestampedKey = (data: Buffer | Uint8Array, now: number = Date.now()) => `${now}-${hash("sha256", Buffer.from(data)).toString("hex")}`;

// "vaultys/encryption/" + version = 0x01
const ENCRYPTION_HEADER = Buffer.from("7661756c7479732f656e6372797074696f6e2f01", "hex");
const PRF_NONCE_LENGTH = 32;

const getSignatureType = (challenge: string) => {
  if (challenge.startsWith("vaultys://connect?")) {
    return "LOGIN";
  } else if (challenge.startsWith("vaultys://signfile?")) {
    return "DOCUMENT";
  } else {
    return "UNKNOWN";
  }
};

export type StoredContact = {
  type: number;
  keyManager: KeyManager | DeprecatedKeyManager;
  certificate: Buffer;
};

export type StoredApp = {
  site: string;
  serverId: string;
  certificate: Buffer;
};

export type FileSignature = {
  challenge: Buffer;
  signature: Buffer;
};

export type File = {
  arrayBuffer: Buffer;
  type: string;
  name?: string;
};

export const instanciateContact = (c: StoredContact) => {
  let vaultysId: VaultysId;
  if (c.type === TYPE_PASSPORT_AA) {
    vaultysId = new VaultysId(PassportAAManager.instantiate(c.keyManager as PassportAAManager), c.certificate, c.type);
  } else if (c.type === 3) {
    vaultysId = new VaultysId(Fido2Manager.instantiate(c.keyManager), c.certificate, c.type);
  } else if (c.type === 4) {
    vaultysId = new VaultysId(Fido2PRFManager.instantiate(c.keyManager), c.certificate, c.type);
  } else {
    //console.log(c.keyManager.signer.publicKey.length);
    if (c.keyManager.signer.publicKey.length === 2592) {
      vaultysId = new VaultysId(DilithiumManager.instantiate(c.keyManager), c.certificate, c.type);
    } else if (c.keyManager.signer.publicKey.length === 2592 + 32) {
      vaultysId = new VaultysId(HybridManager.instantiate(c.keyManager), c.certificate, c.type);
    } else if ((c.keyManager as DeprecatedKeyManager).proof) {
      // Legacy contacts are recognised by the `proof` field, which only the
      // bip32-ed25519 key manager ever produced.
      vaultysId = new VaultysId(DeprecatedKeyManager.instantiate(c.keyManager), c.certificate, c.type);
    } else {
      vaultysId = new VaultysId(Ed25519Manager.instantiate(c.keyManager), c.certificate, c.type);
    }
  }
  return vaultysId;
};

export const instanciateApp = (a: StoredApp) => {
  return VaultysId.fromId(Buffer.from(a.serverId, "base64"), a.certificate);
};

// File-encryption PRFs are derived as hmac("prf|encryption/<nonce>/encryption|prf"):
// this namespace is reserved and can't be requested by an arbitrary remote peer.
const FILE_ENCRYPTION_PRF_PREFIX = "encryption/";

/**
 * Consent callback of askContact / acceptContact with the post-quantum peer option: the peer's key manager is checked
 * first (ContactError PEER_NOT_PQ), then the caller's own callback. startSRP / acceptSRP call it before signing.
 */
function postQuantumConsent(options: PostQuantumPeerOption, accept?: (contact: VaultysId) => Promise<boolean>) {
  if (typeof options !== "object" || options === null) throw new ContactError("INVALID_ARGUMENT");
  if (options.requirePostQuantumPeer !== undefined && typeof options.requirePostQuantumPeer !== "boolean") throw new ContactError("INVALID_ARGUMENT");
  if (options.requirePostQuantumPeer !== true) return accept;
  return async (contact: VaultysId) => {
    if (!isPostQuantumPeer(contact)) throw new ContactError("PEER_NOT_PQ");
    return accept ? accept(contact) : true;
  };
}

const denyAll = async () => false;

const sameIdentity = (a: VaultysId, b: VaultysId) => {
  try {
    return a.type === b.type && Buffer.from(a.keyManager.signer.publicKey).equals(Buffer.from(b.keyManager.signer.publicKey)) && Buffer.from(a.keyManager.cypher.publicKey).equals(Buffer.from(b.keyManager.cypher.publicKey));
  } catch {
    return false;
  }
};

// a DID depends on the id serialization version: accept either serialization
const matchesDid = (contact: VaultysId, did: string) => {
  try {
    return ([0, 1] as const).some((v) => VaultysId.fromId(contact.id).toVersion(v).did === did);
  } catch {
    return false;
  }
};

export default class IdManager {
  vaultysId: VaultysId;
  store: Store;

  constructor(vaultysId: VaultysId, store: Store) {
    this.vaultysId = vaultysId;
    this.store = store;
    if (!this.store.get("metadata")) {
      this.store.set("metadata", {});
    }
    // Always persist the full secret: it encodes the identity type (person,
    // machine...), the algorithm (ed25519, dilithium, hybrid...) and the id
    // version, so restoring it yields exactly the same identity and DID.
    this.store.set("secret", this.vaultysId.getSecret());
    // a 3.x store migrated on a guessed type/algorithm keeps its entropy until confirmLegacyIdentity()
    if (this.store.get("entropy") !== undefined && !this.legacyRecord()?.guessed) this.store.delete("entropy");
    this.store.save();
  }

  private legacyRecord() {
    const record = this.store.get(LEGACY_RECORD_KEY) as LegacyMigrationRecord | undefined;
    return record && typeof record === "object" ? record : undefined;
  }

  /**
   * Exports the current profile as a backup
   * @param passphrase passphrase used to encrypt the backup. When omitted the
   * backup is exported in CLEAR (it contains the identity secret). An empty
   * passphrase is rejected.
   * @returns the backup
   */
  async exportBackup(passphrase?: string): Promise<Uint8Array> {
    if (passphrase !== undefined && (typeof passphrase !== "string" || passphrase.length === 0)) {
      throw new Error("Empty passphrase is not allowed");
    }
    if (passphrase === undefined) {
      // Plaintext export
      const exportedData: VaultysBackup = {
        version: 1,
        data: Buffer.from(encode(this.store.toJSON())),
      };
      return encode(exportedData);
    } else {
      const backup = await platformCrypto.pbkdf2.encrypt(passphrase, Buffer.from(encode(this.store.toJSON())));
      if (!backup) throw new Error("Failed to encrypt backup");

      return encode(backup);
    }
  }

  /**
   * Imports a backup file
   * @param backupData The backup file data as Uint8Array
   * @param passphrase Optional passphrase for decryption (only needed for encrypted backups)
   * @param legacy how a 3.x backup (entropy only) is migrated. By default as `open` does; `true` only if its
   * certificates tell the identity type/algorithm, or the type/algorithm it was created with; `false` refuses it
   * @returns Promise resolving to import result or null if import failed
   */
  static async importBackup(backupData: Uint8Array, passphrase?: string, legacy?: boolean | LegacyIdentityHint): Promise<IdManager | null> {
    try {
      // Decode the backup data
      const backup = decode(backupData) as VaultysBackup;
      //console.log(backup);
      let importedData: Buffer | null;

      if (backup.encryptInfo) {
        // This is an encrypted backup
        if (!passphrase) {
          throw new Error("Passphrase required for encrypted backup (empty passphrases are rejected)");
        }

        if (!backup.data) {
          throw new Error("Invalid backup format");
        }

        importedData = await platformCrypto.pbkdf2.decrypt(backup, passphrase);

        if (!importedData) {
          throw new Error("Failed to decrypt backup. Incorrect passphrase?");
        }
      } else {
        importedData = backup.data;
      }

      //console.log(decode(importedData));

      // Import the data into a new profile
      // console.log(importedData, decode(importedData));
      const store = storagify(
        decode(importedData) as object,
        () => {},
        () => {},
      );
      if (legacy === undefined) return await IdManager.open(store);
      if (legacy && isLegacyV3Store(store)) return await IdManager.fromLegacyStore(store, typeof legacy === "object" ? legacy : undefined);
      return await IdManager.fromStore(store);
    } catch (error) {
      console.error("Import error:", error);
      return null;
    }
  }

  /**
   * Restore an IdManager from a store. The identity is restored exactly from
   * the persisted secret (same type, algorithm and DID). A legacy store holding
   * only `entropy` (written by 3.x) is rejected here: migrate it with
   * `IdManager.fromLegacyStore(store)`.
   * An empty store creates a new machine identity.
   */
  static async fromStore(store: Store) {
    const secret = store.get("secret");
    if (secret) {
      const vaultysId = VaultysId.fromSecret(typeof secret === "string" ? secret : Buffer.from(secret).toString("hex"));
      return new IdManager(vaultysId, store);
    }
    if (store.get("entropy")) {
      throw new Error("Legacy (3.x) store without secret: migrate it with IdManager.fromLegacyStore(store).");
    }
    const vaultysId = await VaultysId.generateMachine();
    return new IdManager(vaultysId, store);
  }

  /**
   * Opens a store written by @vaultys/id 3.x, which keeps only `entropy`, and migrates it in place: the same identity
   * (same DID) is restored and the store rewritten with its secret, as 4.0 stores are.
   *
   * The identity type and algorithm are recovered from the store's own certificates; a store without any needs
   * `hint`. The 3.x (version 0) certificates found in the store that involve this identity and verify are recorded
   * (`store.legacy`): `verifyRelationshipCertificate` and `verifyWebOfTrust` keep accepting exactly those, never a
   * v0 certificate obtained later. Contacts still on a v0 certificate are listed by `legacyContacts()`; a new
   * handshake with them replaces it. A store that already has a secret is opened as `fromStore` does.
   */
  static async fromLegacyStore(store: Store, hint?: LegacyIdentityHint) {
    return IdManager.migrateLegacyStore(store, hint);
  }

  /**
   * Opens any store, with nothing to ask the user: a 4.0 store as `fromStore` does, a 3.x store migrated in place as
   * `fromLegacyStore` does, an empty store with a new machine identity. Calling it again on the same store opens it
   * as it was left (the migration happens once).
   *
   * A 3.x store with no certificate gives nothing to check the identity type and algorithm against: it is opened
   * with `legacyFallback`, by default what 3.x itself reopened such a store as (a machine ed25519 identity, see
   * `LEGACY_REOPEN_DEFAULT`); an app that knows what it created passes that instead. Such a store keeps its `entropy`
   * and `isLegacyIdentityGuessed()` stays true until `confirmLegacyIdentity()`; `fromLegacyStore(store, hint)` can
   * still correct it.
   */
  static async open(store: Store, options: { legacyFallback?: LegacyIdentityHint } = {}) {
    if (isLegacyV3Store(store)) return IdManager.migrateLegacyStore(store, undefined, options.legacyFallback ?? LEGACY_REOPEN_DEFAULT);
    return IdManager.fromStore(store);
  }

  private static async migrateLegacyStore(store: Store, hint?: LegacyIdentityHint, fallback?: LegacyIdentityHint) {
    if (store.get("secret")) {
      // a store migrated on a guessed type/algorithm can be migrated again, with the right one
      const record = store.get(LEGACY_RECORD_KEY) as LegacyMigrationRecord | undefined;
      if (!(hint && record?.guessed && legacyEntropy(store))) return IdManager.fromStore(store);
    }
    const { vaultysId, guessed } = await recoverLegacyIdentity(store, hint, fallback);
    const trusted = storedCertificates(store)
      .filter((c) => involves(vaultysId, c) && verifyV0CertificateSignatures(c))
      .map(certificateHash);
    const record: LegacyMigrationRecord = { from: "3.x", migratedAt: Date.now(), certificates: Object.fromEntries(trusted.map((h) => [h, true as const])) };
    if (guessed) record.guessed = true;
    // the record and the secret are written before the entropy is removed (by the constructor)
    store.set(LEGACY_RECORD_KEY, record);
    return new IdManager(vaultysId, store);
  }

  /** True for a 3.x store migrated without any certificate to check its identity type and algorithm against. */
  isLegacyIdentityGuessed() {
    return !!this.legacyRecord()?.guessed;
  }

  /** Confirms the identity of a store migrated on a guessed type/algorithm: its 3.x entropy is then removed. */
  confirmLegacyIdentity() {
    const record = this.legacyRecord();
    if (!record?.guessed) return;
    delete record.guessed;
    this.store.set(LEGACY_RECORD_KEY, record);
    if (this.store.get("entropy") !== undefined) this.store.delete("entropy");
    this.store.save();
  }

  /** A v0 certificate recorded when this store was migrated from 3.x, involving this identity, that still verifies. */
  private isMigratedLegacyCertificate(certificate: Buffer | Uint8Array) {
    const record = this.store.get(LEGACY_RECORD_KEY) as LegacyMigrationRecord | undefined;
    if (!record || typeof record.certificates !== "object" || record.certificates === null) return false;
    const cert = Buffer.from(certificate);
    return record.certificates[certificateHash(cert)] === true && involves(this.vaultysId, cert) && verifyV0CertificateSignatures(cert);
  }

  private async verifyStoredCertificate(certificate: Buffer | Uint8Array) {
    return (await Challenger.verifyCertificate(Buffer.from(certificate))) || this.isMigratedLegacyCertificate(certificate);
  }

  /**
   * DIDs of the contacts still on a 3.x (version 0) certificate. A new handshake with the same contact
   * (`askContact`/`acceptContact`), once both sides run 4.0, replaces it.
   */
  legacyContacts(): string[] {
    return this.legacyEntries("contacts");
  }

  /** DIDs of the registered apps still on a 3.x (version 0) certificate; a new registration replaces it. */
  legacyApps(): string[] {
    return this.legacyEntries("registrations");
  }

  private legacyEntries(table: "contacts" | "registrations") {
    const entries = this.store.substore(table);
    return entries.list().filter((did) => {
      const cert = entries.get(did)?.certificate;
      return !!cert && decodeV0Certificate(Buffer.from(cert)) !== null;
    });
  }

  /**
   * Replaces the 3.x certificate of a stored contact or app by the one a new handshake with the SAME identity just
   * produced: entries are keyed by DID, so the peer is the one already stored. Only the certificate changes (the
   * metadata set on the contact are kept); a 4.0 certificate is never replaced.
   */
  private upgradeLegacyEntry(table: "contacts" | "registrations", did: string, certificate: Buffer | undefined) {
    const entries = this.store.substore(table);
    const stored = entries.get(did);
    if (!stored?.certificate || !certificate || decodeV0Certificate(Buffer.from(stored.certificate)) === null) return;
    if (decodeV0Certificate(Buffer.from(certificate)) !== null) return;
    entries.set(did, { ...stored, certificate });
    this.store.save();
  }

  merge(otherStore: Store, master = true) {
    // TODO: check if same profile ?
    // TODO: revamp contact metadata and sync
    const master_store = master ? otherStore : this.store;
    const slave_store = master ? this.store : otherStore;
    this.store.set("metadata", { ...slave_store.get("metadata"), ...master_store.get("metadata") });
    ["signatures", "wot"].forEach((table) => {
      const other = otherStore.substore(table);
      const me = this.store.substore(table);
      other.list().forEach((k) => {
        if (!me.get(k)) {
          me.set(k, other.get(k));
        }
      });
    });

    const other = otherStore.substore("contacts");
    const me = this.store.substore("contacts");
    const m = master ? other : me;
    const s = master ? me : other;
    other.list().forEach((did) => {
      if (!me.get(did)) {
        me.set(did, other.get(did));
      } else {
        const contact = me.get(did);
        contact.metadata = { ...s.get(did).metadata, ...m.get(did).metadata };
        me.set(did, contact);
      }
    });

    this.store.save();
  }

  async verifyWebOfTrust() {
    let verified = true;
    for (const certid of this.store.substore("wot").list()) {
      const cert = this.store.substore("wot").get(certid);
      // older versions of listCertificates() overwrote the raw certificate with { ...deserialized, raw }
      verified = verified && (await this.verifyStoredCertificate(cert?.raw ?? cert));
      //if (!verified) console.log(Challenger.deserializeCertificate(cert));
    }
    //console.log("wot", verified);
    for (const appid of this.store.substore("registrations").list()) {
      const app = this.store.substore("registrations").get(appid);
      verified = verified && appid === VaultysId.fromId(app.serverId, undefined, "base64").did;
    }
    //console.log("registrations", verified);
    for (const contact of this.contacts) {
      verified = verified && (await this.verifyStoredCertificate(contact!.certificate!));
    }
    //console.log("contacts", verified);
    for (const app of this.apps) {
      verified = verified && (await this.verifyStoredCertificate(app!.certificate!));
    }
    //console.log("apps", verified);

    return verified;
  }

  isHardware() {
    return this.vaultysId.isHardware();
  }

  async signIn() {
    if (!this.vaultysId.isHardware()) return true;
    await window.CredentialUserInteractionRequest();
    const challenge = randomBytes(PRF_NONCE_LENGTH);
    const keyManager = this.vaultysId.keyManager as Fido2Manager;
    const creds = (await navigator.credentials.get({
      publicKey: {
        challenge,
        allowCredentials: [
          {
            type: "public-key",
            id: keyManager.fid,
            transports: keyManager.transports,
          },
        ],
        userVerification: "discouraged",
      },
    })) as PublicKeyCredential;
    if (creds == null) return false;
    const response = creds.response as AuthenticatorAssertionResponse;
    const extractedChallenge = SoftCredentials.extractChallenge(response.clientDataJSON);

    if (challenge.toString("base64") !== extractedChallenge) {
      return false;
    }
    return keyManager.verifyCredentials(creds);
  }

  get contacts() {
    const s = this.store.substore("contacts");
    return s
      .list()
      .map((did) => s.get(did))
      .map(instanciateContact)
      .map((contact) => contact.toVersion(this.vaultysId.version));
  }

  get apps() {
    const s = this.store.substore("registrations");
    return s
      .list()
      .map((did) => s.get(did))
      .map(instanciateApp)
      .map((app) => app.toVersion(this.vaultysId.version));
  }

  getContact(did: string) {
    const c = this.store.substore("contacts").get(did);
    if (!c) return null;
    return instanciateContact(c).toVersion(this.vaultysId.version);
  }

  getApp(did: string) {
    const app = this.store.substore("registrations").get(did);
    if (!app) return null;
    return instanciateApp(app).toVersion(this.vaultysId.version);
  }

  setContactMetadata(did: string, name: string, value: any) {
    const c = this.store.substore("contacts").get(did);
    if (c) {
      if (!c.metadata) {
        c.metadata = {};
      }
      c.metadata[name] = value;
    }
  }

  getContactMetadata(did: string, name: string) {
    const c = this.store.substore("contacts").get(did);
    if (c && c.metadata) {
      return c.metadata[name];
    }
    return null;
  }

  getContactMetadatas(did: string) {
    const c = this.store.substore("contacts").get(did);
    if (c && c.metadata) {
      return c.metadata;
    }
    return null;
  }

  async verifyRelationshipCertificate(did: string) {
    const c = this.store.substore("contacts").get(did) || this.store.substore("registrations").get(did);
    return this.verifyStoredCertificate(c.certificate);
  }

  set name(n) {
    this.store.get("metadata").name = n;
  }

  get name() {
    return this.store.get("metadata").name;
  }

  get displayName() {
    const metadata = this.store.get("metadata");
    const result = metadata.firstname ? metadata.firstname + " " + (metadata.name ?? "") : metadata.name;
    return result?.length > 0 ? result : "Anonymous " + this.vaultysId.fingerprint?.slice(-4);
  }

  set phone(n) {
    this.store.get("metadata").phone = n;
  }

  get phone() {
    return this.store.get("metadata").phone;
  }

  set email(n) {
    this.store.get("metadata").email = n;
  }

  get email() {
    return this.store.get("metadata").email;
  }

  // set avatar(n) {
  //   this.store.get("metadata").avatar = {
  //     data: Buffer.from(n.data).toString("base64"),
  //     type: n.type,
  //   };
  // }

  // get avatar() {
  //   const temp = this.store.get("metadata").avatar;
  //   if (!temp) return null;
  //   return {
  //     data: Buffer.from(temp.data, "base64"),
  //     type: temp.type,
  //   };
  // }

  async signChallenge(challenge: Buffer) {
    const signature = await this.vaultysId.signChallenge(challenge);
    this.store.substore("signatures").set(timestampedKey(signature), {
      signature,
      challenge,
    });
    this.store.save();
    return signature;
  }

  async signFile(file: File) {
    const h = hash("sha256", file.arrayBuffer).toString("hex");
    const challenge = Buffer.from(`vaultys://signfile?hash=${h}&timestamp=${Date.now()}`, "utf-8");
    const payload: FileSignature = {
      challenge,
      signature: await this.vaultysId.signChallenge(challenge),
    };
    this.store.substore("signatures").set(timestampedKey(payload.signature ?? challenge), payload);
    this.store.save();
    return payload;
  }

  verifyFile(file: File, fileSignature: FileSignature, contactId: VaultysId, userVerifiation = true) {
    const data = fileSignature.challenge.toString("utf8");
    if (!data.startsWith("vaultys://signfile?")) {
      return false;
    }
    const h = hash("sha256", file.arrayBuffer).toString("hex");
    const url = new URL(data);
    const fileHash = url.searchParams.get("hash");
    if (h !== fileHash) {
      return false;
    }
    if (url.search.match(/[a-z\d]+=[a-z\d]+/gi)?.length === 2 && url.searchParams.get("timestamp")) {
      return contactId.verifyChallenge(fileSignature.challenge, fileSignature.signature, userVerifiation);
    }
    return false;
  }

  async decryptFile(toDecrypt: File, channel?: Channel) {
    // Extract nonce and ciphertext from arrayBuffer
    const data = new Uint8Array(toDecrypt.arrayBuffer);
    const header = data.slice(0, ENCRYPTION_HEADER.length);
    if (Buffer.from(header).toString("hex") !== ENCRYPTION_HEADER.toString("hex")) {
      throw new Error("Invalid header for encrypted file");
    }
    const prfNonceBytes = data.slice(ENCRYPTION_HEADER.length, ENCRYPTION_HEADER.length + PRF_NONCE_LENGTH);
    const nonceBytes = data.slice(ENCRYPTION_HEADER.length + PRF_NONCE_LENGTH, ENCRYPTION_HEADER.length + PRF_NONCE_LENGTH + SECRETBOX_NONCE_LENGTH);
    const ciphertext = data.slice(ENCRYPTION_HEADER.length + PRF_NONCE_LENGTH + SECRETBOX_NONCE_LENGTH);

    const prf = channel ? await this.requestPRF(channel, "encryption/" + Buffer.from(prfNonceBytes).toString("hex") + "/encryption") : await this.vaultysId.hmac("prf|encryption/" + Buffer.from(prfNonceBytes).toString("hex") + "/encryption|prf");
    if (prf?.length !== PRF_NONCE_LENGTH) {
      throw new Error("Invalid PRF generated");
    }

    // Use sha256 hash of the PRF as the secretbox key (must be 32 bytes)
    const secretKey = hash("sha256", prf);
    secureErase(prf);

    // Decrypt (XSalsa20-Poly1305 secretbox)
    const decrypted = secretboxOpen(ciphertext, nonceBytes, secretKey);
    secureErase(secretKey);

    if (!decrypted) {
      throw new Error("Decryption failed");
    }

    return {
      name: toDecrypt.name,
      type: toDecrypt.type,
      arrayBuffer: Buffer.from(decrypted),
    } as File;
  }

  async encryptFile(toEncrypt: File, channel?: Channel) {
    // Generate a secure random nonce for both the PRF and the secretbox
    const prfNonceBytes = randomBytes(PRF_NONCE_LENGTH);

    const prf = channel ? await this.requestPRF(channel, "encryption/" + Buffer.from(prfNonceBytes).toString("hex") + "/encryption") : await this.vaultysId.hmac("prf|encryption/" + prfNonceBytes.toString("hex") + "/encryption|prf");
    if (prf?.length !== PRF_NONCE_LENGTH) {
      return null;
    }

    // Use sha256 hash of the PRF as the secretbox key (must be 32 bytes)
    const secretKey = hash("sha256", prf);
    secureErase(prf);

    // Generate a random nonce for secretbox encryption
    const nonceBytes = randomBytes(SECRETBOX_NONCE_LENGTH);

    // Encrypt (XSalsa20-Poly1305 secretbox)
    const ciphertext = secretboxSeal(new Uint8Array(toEncrypt.arrayBuffer), nonceBytes, secretKey);
    secureErase(secretKey);

    // Combine encryption nonce and ciphertext into a single buffer
    const result = new Uint8Array(ENCRYPTION_HEADER.length + PRF_NONCE_LENGTH + nonceBytes.length + ciphertext.length);
    result.set(ENCRYPTION_HEADER);
    result.set(prfNonceBytes, ENCRYPTION_HEADER.length);
    result.set(nonceBytes, ENCRYPTION_HEADER.length + PRF_NONCE_LENGTH);
    result.set(ciphertext, ENCRYPTION_HEADER.length + PRF_NONCE_LENGTH + nonceBytes.length);

    return {
      name: toEncrypt.name,
      type: toEncrypt.type,
      arrayBuffer: Buffer.from(result), // Buffer contains secretbox nonce + ciphertext
    } as File;
  }

  getSignatures() {
    const store = this.store.substore("signatures");
    return store
      .list()
      .sort()
      .map((date) => {
        const payload = store.get(date);
        const challenge = Buffer.from(payload.challenge).toString("utf-8");
        return {
          date,
          payload,
          challenge,
          type: getSignatureType(challenge),
        };
      });
  }

  migrate(version: 0 | 1) {
    this.vaultysId.toVersion(version);
    const s = this.store.substore("contacts");
    for (const did of s.list()) {
      const data = s.get(did);
      const contact = instanciateContact(data);
      const newContact = contact.toVersion(version);
      if (newContact.did !== did) {
        s.set(newContact.did, { ...contact, ...newContact, metadata: data.metadata, oldDid: did });
        s.delete(did);
        //console.log(did, "->", newContact.did);
      }
    }

    const apps = this.store.substore("registrations");
    for (const did of apps.list()) {
      const data = apps.get(did);
      const site = instanciateApp(data);
      if (site) {
        const newSite = site.toVersion(version);
        if (newSite.did !== did) {
          const name = data.site === did ? newSite.did : data.site;
          apps.set(newSite.did, { site: name, oldDid: did, serverId: newSite.id.toString("base64"), certificate: data.certificate, timestamp: data.timestamp });
          apps.delete(did);
          // console.log(did, "->", newSite.did);
        }
      }
    }
    this.store.save();
  }

  async verifyChallenge(challenge: Buffer, signature: Buffer) {
    return this.vaultysId.verifyChallenge(challenge, signature, true);
  }

  async upload(channel: Channel, stream: Readable) {
    const challenger = await this.startSRP(channel, "p2p", "transfer");
    if (challenger.isComplete()) {
      const { upload } = StreamChannel(channel);
      await upload(stream);
    } else channel.send(Buffer.from([0]));
  }

  async download(channel: Channel, stream: Writable) {
    const challenger = await this.acceptSRP(channel, "p2p", "transfer");
    if (challenger.isComplete()) {
      const { download } = StreamChannel(channel);
      await download(stream);
    } else channel.send(Buffer.from([0]));
  }

  /**
   * Open an authenticated connection with a contact (initiator side): a plain
   * p2p/auth handshake. When `contactdid` is given, the remote must be that DID.
   * The authenticated remote is saved as contact and returned.
   */
  async requestConnect(channel: Channel, contactdid?: string, metadata: Record<string, string> = {}) {
    const accept = contactdid ? async (contact: VaultysId) => matchesDid(contact, contactdid) : undefined;
    const challenger = await this.startSRP(channel, "p2p", "auth", metadata, accept);
    const contact = challenger.getContactId();
    this.saveContact(contact);
    return contact;
  }

  /**
   * Accept an authenticated connection (responder side of requestConnect).
   * When `contactdid` is given, the remote must be that DID.
   */
  async acceptConnect(channel: Channel, contactdid?: string, metadata: Record<string, string> = {}) {
    const accept = contactdid ? async (contact: VaultysId) => matchesDid(contact, contactdid) : undefined;
    const challenger = await this.acceptSRP(channel, "p2p", "auth", metadata, accept);
    const contact = challenger.getContactId();
    this.saveContact(contact);
    return contact;
  }

  async requestDecrypt(channel: Channel, toDecrypt: Buffer) {
    const challenger = await this.acceptSRP(channel, "p2p", "decrypt");
    if (challenger.isComplete()) {
      channel.send(toDecrypt);
      const new_encrypted = await channel.receive();
      // DHIES v2: only the authenticated remote of this handshake can have produced it
      const decrypted = await this.vaultysId.dhiesDecrypt(Buffer.from(new_encrypted), challenger.getContactId().id);
      return decrypted;
    } else channel.send(Buffer.from([0]));
  }

  /**
   * Decrypt a message on behalf of a remote peer. Denied unless `accept`
   * explicitly approves the remote contact.
   */
  async acceptDecrypt(channel: Channel, accept?: (contact: VaultysId) => Promise<boolean>) {
    const challenger = await this.startSRP(channel, "p2p", "decrypt", {}, accept ?? denyAll);
    if (challenger.isComplete()) {
      const toDecrypt = await channel.receive();
      const decrypted = await this.vaultysId.decrypt(toDecrypt.toString("utf-8"));
      if (decrypted) {
        const encrypted = await this.vaultysId.dhiesEncrypt(decrypted, challenger.getContactId().id);
        channel.send(encrypted ?? Buffer.from([0]));
      } else channel.send(Buffer.from([0]));
    } else channel.send(Buffer.from([0]));
  }

  async requestDecryptFile(channel: Channel, toDecrypt: File) {
    return this.decryptFile(toDecrypt, channel);
  }

  async requestEncryptFile(channel: Channel, toEncrypt: File) {
    return this.encryptFile(toEncrypt, channel);
  }

  /**
   * Provide the file-encryption PRF to a remote peer. Denied unless the remote
   * is this same identity or `accept` explicitly approves it.
   */
  async acceptDecryptFile(channel: Channel, accept?: (contact: VaultysId) => Promise<boolean>) {
    let result_contact = null;
    await this.acceptPRF(
      channel,
      async (contact: VaultysId, appid: string) => {
        if (appid.length > 63 && appid.startsWith(FILE_ENCRYPTION_PRF_PREFIX) && appid.endsWith("/encryption")) {
          const allowed = sameIdentity(contact, this.vaultysId) || (!!accept && (await accept(contact)));
          if (allowed) result_contact = contact;
          return allowed;
        } else return false;
      },
      { allowFileEncryption: true },
    );
    return result_contact;
  }

  // alias since this is symetric key encryption
  acceptEncryptFile = this.acceptDecryptFile;

  async requestSignFile(channel: Channel, file: File) {
    const challenger = await this.acceptSRP(channel, "p2p", "signfile");
    if (challenger.isComplete()) {
      channel.send(Buffer.from(encode(file)));
      const result = await channel.receive();
      let fileSignature: FileSignature;
      try {
        fileSignature = decode(result) as FileSignature;
      } catch {
        return undefined;
      }
      if (!fileSignature || !(fileSignature.challenge instanceof Uint8Array) || !(fileSignature.signature instanceof Uint8Array)) return undefined;
      fileSignature = { challenge: Buffer.from(fileSignature.challenge), signature: Buffer.from(fileSignature.signature) };
      if (this.verifyFile(file, fileSignature, challenger.getContactId().toVersion(1))) {
        return fileSignature;
      } else return undefined;
    } else channel.send(Buffer.from([0]));
  }

  /**
   * Sign a file on behalf of a remote peer. Denied unless `accept` explicitly
   * approves the remote contact and the file.
   */
  async acceptSignFile(channel: Channel, accept?: (contact: VaultysId, file: File) => Promise<boolean>) {
    const challenger = await this.startSRP(channel, "p2p", "signfile");
    if (challenger.isComplete()) {
      const result = await channel.receive();
      const file = decode(result) as File;
      if (accept && (await accept(challenger.getContactId(), file))) {
        const result = await this.signFile(file);
        channel.send(Buffer.from(encode(result)));
      } else channel.send(Buffer.from([0]));
    } else channel.send(Buffer.from([0]));
  }

  async requestPRF(channel: Channel, appid: string, accept?: (contact: VaultysId) => Promise<boolean>) {
    if (appid.length < 3) {
      throw new Error("appid is too short, less than 3 characters");
    }
    if (appid.split("|").length > 1) {
      throw new Error("appid contains illegal character |");
    }
    const challenger = await this.acceptSRP(channel, "p2p", "prf", undefined, accept);
    if (challenger.isComplete()) {
      channel.send(Buffer.from(appid, "utf-8"));
      const prf = await channel.receive();
      return Buffer.from(prf);
    } else channel.send(Buffer.from([0]));
  }

  /**
   * Provide a PRF (hmac of the appid) to a remote peer.
   * DEFAULT DENY: without an `accept` callback only this same identity is served.
   * The file-encryption namespace ("encryption/...") is only served to this same
   * identity, or when explicitly allowed (options.allowFileEncryption, used by
   * acceptDecryptFile) AND accepted.
   */
  async acceptPRF(channel: Channel, accept?: (contact: VaultysId, appid: string) => Promise<boolean>, options: { allowFileEncryption?: boolean } = {}) {
    const challenger = await this.startSRP(channel, "p2p", "prf");
    if (challenger.isComplete()) {
      const result = await channel.receive();
      const appid = Buffer.from(result).toString("utf-8");
      const contact = challenger.getContactId();
      const isSelf = sameIdentity(contact, this.vaultysId);
      let allowed = false;
      if (appid.length < 3 || appid.split("|").length > 1) {
        // error if appid is too short or contains illegal character
        allowed = false;
      } else if (isSelf) {
        allowed = true;
      } else if (appid.startsWith(FILE_ENCRYPTION_PRF_PREFIX) && !options.allowFileEncryption) {
        allowed = false;
      } else {
        allowed = !!accept && (await accept(contact, appid));
      }
      if (!allowed) {
        channel.send(Buffer.from([0]));
      } else {
        const hmac = (await this.vaultysId.hmac("prf|" + appid + "|prf")) ?? Buffer.from([0]);
        channel.send(hmac);
        secureErase(hmac);
      }
    } else channel.send(Buffer.from([0]));
  }

  /***************************/
  /*   SIGNING PARTY HERE!   */
  /***************************/

  listCertificates() {
    const wot = this.store.substore("wot");
    return wot.list().map((timestamp) => {
      const c = wot.get(timestamp);
      if (c.timestamp) {
        return c;
      } else {
        // read-only: the raw certificate must stay in the store for verifyWebOfTrust
        return {
          ...Challenger.deserializeCertificate(c),
          raw: c,
        };
      }
    });
  }

  async startSRP(channel: Channel, protocol: string, service: string, metadata: Record<string, string> = {}, accept?: (contact: VaultysId) => Promise<boolean>) {
    const challenger = new Challenger(this.vaultysId);
    challenger.createChallenge(protocol, service, metadata);
    //console.log(challenger);
    const cert = challenger.getCertificate();
    if (!cert) {
      channel.close();
      channel.send(Buffer.from([0]));
      throw new Error("Error processing challenge");
    }

    channel.send(cert);

    try {
      const message = await channel.receive();
      // console.log("startSRP", message)
      const step1 = Challenger.deserializeCertificate(message);
      if (step1.state !== CHALLENGE_STATE.STEP1 || !step1.pk2) {
        channel.send(Buffer.from([0]));
        throw new Error("Expected a valid STEP1 challenge" + (step1.error ? ": " + step1.error : ""));
      }
      // the consent callback is given the REMOTE party (pk2), before we sign anything
      if (accept && !(await accept(VaultysId.fromId(step1.pk2)))) {
        channel.send(Buffer.from([0]));
        throw new Error("Contact refused");
      }
      await challenger.update(message);
    } catch (error) {
      channel.send(Buffer.from([0]));
      if (error instanceof ContactError) throw error;
      throw new Error(error as string);
    }
    if (challenger.isComplete()) {
      const certificate = challenger.getCertificate();
      if (!certificate) {
        channel.close();
        channel.send(Buffer.from([0]));
        throw new Error("Error processing challenge");
      }
      // there is a caveat here, we are not sure that the last bit of information has been received
      channel.send(certificate);
      this.store.substore("wot").set(timestampedKey(certificate), certificate);
      // TODO create/update merkle tree + sign it
      return challenger;
    } else {
      channel.send(Buffer.from([0]));
      throw new Error("Can't add a new contact if the protocol is not complete");
    }
  }

  async acceptSRP(channel: Channel, protocol: string, service: string, metadata: Record<string, string> = {}, accept?: (contact: VaultysId) => Promise<boolean>) {
    const challenger = new Challenger(this.vaultysId);
    try {
      const message = await channel.receive();
      const chal = Challenger.deserializeCertificate(message);
      // the first message of an accept flow MUST be an INIT (never sign a STEP1/COMPLETE we did not start)
      if (chal.state !== CHALLENGE_STATE.INIT || !chal.pk1) {
        channel.send(Buffer.from([0]));
        throw new Error("Expected a valid INIT challenge" + (chal.error ? ": " + chal.error : ""));
      }
      if (chal.protocol !== protocol) {
        channel.send(Buffer.from([0]));
        throw new Error("protocol is not the one expected: " + chal.protocol + " !=" + protocol);
      }
      if (chal.service !== service) {
        channel.send(Buffer.from([0]));
        throw new Error("service is not the one expected: " + chal.service + " !=" + service);
      }
      // the consent callback is given the REMOTE party (pk1 of an INIT), before we sign anything
      if (accept && !(await accept(VaultysId.fromId(chal.pk1)))) {
        channel.send(Buffer.from([0]));
        throw new Error("Contact refused");
      }
      await challenger.update(message, metadata);
    } catch (error) {
      channel.send(Buffer.from([0]));
      if (error instanceof ContactError) throw error;
      throw new Error(error as string);
    }

    const cert = challenger.getCertificate();
    if (!cert) {
      channel.send(Buffer.from([0]));
      await channel.close();
      throw new Error("Error processing challenge");
    }
    // console.log("acceptSRP sending 1")
    channel.send(cert);
    // console.log("acceptSRP sending 2")

    try {
      const message = await channel.receive();
      // console.log("acceptSRP 2", message)
      await challenger.update(message);
    } catch (error) {
      await channel.close();
      //console.log(challenger, error);
      throw new Error(error as string);
    }
    if (challenger.isComplete()) {
      const certificate = challenger.getCertificate();
      this.store.substore("wot").set(timestampedKey(certificate), certificate);
      // TODO create/update merkle tree + sign it
      return challenger;
    } else {
      await channel.close();
      throw new Error("Can't add a new contact if the protocol is not complete");
    }
  }

  saveApp(app: VaultysId, name?: string) {
    app.toVersion(this.vaultysId.version);
    if (!app.isMachine()) {
      this.saveContact(app);
    } else {
      const appstore = this.store.substore("registrations");
      if (appstore.get(app.did)) this.upgradeLegacyEntry("registrations", app.did, app.certificate);
      else {
        appstore.set(app.did, {
          site: name ?? app.did,
          serverId: app.id.toString("base64"),
          certificate: app.certificate,
        } as StoredApp);
        this.store.save();
      }
    }
  }

  saveContact(contact: VaultysId) {
    contact.toVersion(this.vaultysId.version);
    if (contact.isMachine()) {
      this.saveApp(contact);
    } else {
      const contactstore = this.store.substore("contacts");
      if (contactstore.get(contact.did)) this.upgradeLegacyEntry("contacts", contact.did, contact.certificate);
      else {
        const publicContact = contact.type === TYPE_PASSPORT_AA ? VaultysId.fromId(contact.id, contact.certificate) : contact;
        contactstore.set(contact.did, publicContact as StoredContact);
        this.store.save();
      }
    }
  }

  /**
   * Ask for a contact (initiator of a p2p/auth handshake). With `options.requirePostQuantumPeer`, a responder whose
   * identity does not sign with ML-DSA is refused with ContactError PEER_NOT_PQ, after its STEP1 signature is verified
   * and BEFORE this side signs COMPLETE (rfc/PROTOCOL.md §12.1). Default off.
   */
  async askContact(channel: Channel, metadata: Record<string, string> = {}, accept?: (contact: VaultysId) => Promise<boolean>, options: PostQuantumPeerOption = {}) {
    const consent = postQuantumConsent(options, accept);
    const challenger = await this.startSRP(channel, "p2p", "auth", metadata, consent);
    const contact = challenger.getContactId();
    this.saveContact(contact);
    return contact;
  }

  /**
   * Accept a contact (responder of a p2p/auth handshake). With `options.requirePostQuantumPeer`, an initiator whose
   * identity (pk1 of INIT) does not sign with ML-DSA is refused with ContactError PEER_NOT_PQ BEFORE this side signs
   * STEP1; the initiator still has to prove that pk1 with COMPLETE (rfc/PROTOCOL.md §12.1). Default off.
   */
  async acceptContact(channel: Channel, metadata: Record<string, string> = {}, accept?: (contact: VaultysId) => Promise<boolean>, options: PostQuantumPeerOption = {}) {
    const consent = postQuantumConsent(options, accept);
    const challenger = await this.acceptSRP(channel, "p2p", "auth", metadata, consent);
    const contact = challenger.getContactId();
    this.saveContact(contact);
    return contact;
  }
}
