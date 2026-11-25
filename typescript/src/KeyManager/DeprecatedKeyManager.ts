import { dearmorAndDecrypt, encryptAndArmor } from "@vaultys/saltpack";
import { hash, hmac, randomBytes, secureErase } from "../crypto";
import { Buffer } from "buffer/";
import { BoxKeyPair, boxKeyPairFromSecretKey, scalarMult } from "../nacl";
import { decode, encode } from "@msgpack/msgpack";
import { Bip32PrivateKey, Bip32PublicKey, PublicKey, HARDENED_OFFSET } from "@stricahq/bip32ed25519";
import { hmac as nobleHmac } from "@noble/hashes/hmac.js";
import { sha512 as nobleSha512 } from "@noble/hashes/sha2.js";
import KeyManager from "./AbstractKeyManager";
import { getCypherPublicKeyFromId } from "./CypherManager";
import { dhiesV2Decrypt, dhiesV2Encrypt } from "./dhies";
import { decodeRecord, readVersion, requireBytes } from "./validation";

const LEVEL_ROOT = 1;
const LEVEL_DERIVED = 2;

const sha512 = (data: Buffer) => hash("sha512", data);
const sha256 = (data: Buffer) => hash("sha256", data);

const serializeID_v0 = (km: DeprecatedKeyManager) => {
  const version = Buffer.from([0x84, 0xa1, 0x76, 0]);
  const proof = Buffer.from([0xa1, 0x70, 0xc5, 0x00, km.proof?.length, ...(km.proof || [])]);
  const sign = Buffer.from([0xa1, 0x78, 0xc5, 0x00, km.signer.publicKey.length, ...km.signer.publicKey]);
  const cypher = Buffer.from([0xa1, 0x65, 0xc5, 0x00, km.cypher.publicKey.length, ...km.cypher.publicKey]);
  return Buffer.concat([version, proof, sign, cypher]);
};

const leToBigInt = (bytes: Uint8Array) => bytes.reduceRight((acc, b) => (acc << 8n) | BigInt(b), 0n);
const bigIntToLe = (value: bigint, length: number) => {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++, value >>= 8n) out[i] = Number(value & 0xffn);
  return out;
};

/**
 * The child that @stricahq/bip32ed25519 1.x returned for derive(NaN): the hardened branch of
 * ed25519-bip32 (HMAC over kL ‖ kR), with the 4-byte index written as 0 instead of 2^31. Wallets
 * created before 4.0 reached it through the empty first segment of the path "/0'", so their
 * signing keys depend on it. 2.x rejects a non-integer index, and no standard index reaches this
 * child, so it is computed here, with the same arithmetic as 1.x (kL + 8·ZL[0..28], kR + ZR mod
 * 2^256). test/deprecatedDerivation.test.ts pins the result against the published 2.4.10 package.
 */
const legacyDeriveNaN = (node: Bip32PrivateKey) => {
  const xprv = node.toBytes();
  const kl = xprv.subarray(0, 32);
  const kr = xprv.subarray(32, 64);
  const cc = xprv.subarray(64, 96);
  const data = new Uint8Array(1 + 64 + 4); // index bytes stay 0
  data.set(kl, 1);
  data.set(kr, 33);
  data[0] = 0x00;
  const z = nobleHmac(nobleSha512, cc, data);
  data[0] = 0x01;
  const i = nobleHmac(nobleSha512, cc, data);
  const left = leToBigInt(kl) + 8n * leToBigInt(z.subarray(0, 28));
  if (left >> 256n) throw new Error("legacy derivation: kL overflow");
  const right = (leToBigInt(kr) + leToBigInt(z.subarray(32, 64))) & ((1n << 256n) - 1n);
  const child = new Uint8Array(96);
  child.set(bigIntToLe(left, 32), 0);
  child.set(bigIntToLe(right, 32), 32);
  child.set(i.subarray(32, 64), 64);
  return Bip32PrivateKey.fromBytes(child);
};

export const publicDerivePath = (node: Bip32PublicKey, path: string) => node.derivePath(path);

/**
 * Derives a path with the 1.x semantics: an empty segment (as in "/0'") is the legacy derive(NaN)
 * step, a segment ending in ' is hardened.
 */
export const privateDerivePath = (node: Bip32PrivateKey, path: string) => {
  let result = node;
  if (path.startsWith("m/")) path = path.slice(2);
  path.split("/").forEach((d) => {
    if (d === "") result = legacyDeriveNaN(result);
    else if (d[d.length - 1] == "'") result = result.derive(HARDENED_OFFSET + parseInt(d.substring(0, d.length - 1)));
    else result = result.derive(parseInt(d));
  });
  return result;
};

export type KeyPair = {
  publicKey: Buffer;
  secretKey?: Buffer;
};

export type HISCP = {
  newId: Buffer;
  proofKey: Buffer;
  timestamp: number;
  signature: Buffer;
};

type DataExport = {
  v: 0; // version
  p: Buffer; // proof
  x: Buffer; // signing secretKey or publicKey
  e: Buffer; // encrypting secretKey or publicKey
};

export default class DeprecatedKeyManager {
  level?: number = 1;
  version: 0 | 1 = 1;
  capability: "private" | "public" = "private";
  entropy: Buffer | undefined;
  proof?: Buffer;
  proofKey!: KeyPair;
  signer!: KeyPair;
  cypher!: KeyPair;
  authType: string;
  encType: string;
  swapIndex!: number;

  constructor() {
    this.authType = "Ed25519VerificationKey2020";
    this.encType = "X25519KeyAgreementKey2019";
  }

  static async create_Id25519_fromEntropy(entropy: Buffer, swapIndex = 0) {
    const km = new DeprecatedKeyManager();
    km.entropy = entropy;
    km.level = LEVEL_ROOT;
    km.capability = "private";
    const seed = sha512(entropy);
    const derivedKey = privateDerivePath(await Bip32PrivateKey.fromEntropy(seed.slice(0, 32)), `m/1'/0'/${swapIndex}'`);
    km.proofKey = {
      publicKey: Buffer.from(derivedKey.toBip32PublicKey().toPublicKey().toBytes()),
      secretKey: Buffer.from(derivedKey.toBytes()),
    };
    km.swapIndex = swapIndex;
    km.proof = hash("sha256", km.proofKey.publicKey);
    const privateKey = privateDerivePath(derivedKey, "/0'");
    km.signer = {
      publicKey: Buffer.from(privateKey.toBip32PublicKey().toPublicKey().toBytes()),
      secretKey: Buffer.from(privateKey.toBytes()),
    };
    const swapIndexBuffer = Buffer.alloc(8);
    swapIndexBuffer.writeBigInt64LE(BigInt(swapIndex) as unknown as number, 0);
    const seed2 = sha256(Buffer.concat([seed.slice(32, 64), swapIndexBuffer]));
    const cypher = boxKeyPairFromSecretKey(seed2);
    km.cypher = {
      publicKey: Buffer.from(cypher.publicKey),
      secretKey: Buffer.from(cypher.secretKey),
    };
    return km;
  }

  static generate_Id25519() {
    return DeprecatedKeyManager.create_Id25519_fromEntropy(randomBytes(32));
  }

  get id(): Buffer {
    if (this.version == 0) return serializeID_v0(this);
    else
      return Buffer.from(
        encode({
          v: this.version,
          p: this.proof,
          x: this.signer.publicKey,
          e: this.cypher.publicKey,
        }),
      );
  }

  async getCypher() {
    // todo fetch secretKey here
    const cypher = this.cypher;
    return {
      hmac: (message: string) => (cypher.secretKey ? hmac("sha256", Buffer.from(Buffer.from(cypher.secretKey).toString("hex"), "utf-8"), "VaultysID/" + message + "/end") : undefined),
      signcrypt: async (plaintext: string, publicKeys: Buffer[]) => encryptAndArmor(plaintext, cypher as BoxKeyPair, publicKeys),
      decrypt: async (encryptedMessage: string, senderKey?: Buffer | null) => dearmorAndDecrypt(encryptedMessage, cypher as BoxKeyPair, senderKey),
      diffieHellman: async (publicKey: Buffer) => Buffer.from(scalarMult(cypher.secretKey!, publicKey)),
    };
  }

  async getSigner() {
    // todo fetch secretKey here
    const secretKey = this.signer.secretKey!;
    const privateKey = Bip32PrivateKey.fromBytes(secretKey).toPrivateKey();
    return { sign: async (data: Buffer) => Buffer.from(privateKey.sign(data)) };
  }

  getSecret() {
    return Buffer.from(
      encode({
        v: this.version,
        p: this.proof,
        x: this.signer.secretKey,
        e: this.cypher.secretKey,
      }),
    );
  }

  static fromSecret(secret: Buffer) {
    const data = decodeRecord(secret, "legacy secret");
    const x = requireBytes(data.x, "legacy signing secret key", 96);
    const e = requireBytes(data.e, "X25519 secret key", 32);
    const km = new DeprecatedKeyManager();
    km.version = readVersion(data.v);
    km.level = LEVEL_DERIVED;
    km.capability = "private";
    km.proof = data.p === undefined ? undefined : requireBytes(data.p, "legacy proof");
    km.signer = {
      secretKey: x,
      publicKey: Buffer.from(Bip32PrivateKey.fromBytes(x).toBip32PublicKey().toPublicKey().toBytes()),
    };
    const cypher = boxKeyPairFromSecretKey(e);
    km.cypher = {
      publicKey: Buffer.from(cypher.publicKey),
      secretKey: Buffer.from(cypher.secretKey),
    };
    return km;
  }

  static instantiate(obj: any) {
    const km = new DeprecatedKeyManager();
    km.version = obj.version ?? 0;
    km.level = obj.level;
    km.proof = obj.proof.data ? Buffer.from(obj.proof.data) : Buffer.from(obj.proof);
    km.signer = {
      publicKey: obj.signer.publicKey.data ? Buffer.from(obj.signer.publicKey.data) : Buffer.from(obj.signer.publicKey),
    };
    km.cypher = {
      publicKey: obj.cypher.publicKey.data ? Buffer.from(obj.cypher.publicKey.data) : Buffer.from(obj.cypher.publicKey),
    };
    km.capability = "public"; // instantiated from stored public data only
    return km;
  }

  static fromId(id: Buffer) {
    const data = decodeRecord(id, "legacy id");
    const km = new DeprecatedKeyManager();
    km.version = readVersion(data.v);
    km.level = LEVEL_DERIVED;
    km.capability = "public";
    km.proof = data.p === undefined ? undefined : requireBytes(data.p, "legacy proof");
    km.signer = {
      publicKey: requireBytes(data.x, "legacy public key", 32),
    };
    km.cypher = {
      publicKey: requireBytes(data.e, "X25519 public key", 32),
    };
    // console.log(km)
    return km;
  }

  async sign(data: Buffer) {
    if (this.capability == "public") return null;
    const signer = await this.getSigner();
    return signer.sign(data);
  }

  verify(data: Buffer, signature: Buffer, userVerificationIgnored?: boolean): boolean {
    try {
      // console.log(this.signer.publicKey, data, signature);
      return new PublicKey(this.signer.publicKey).verify(signature, data);
    } catch (error) {
      // console.log(error);
      // console.log(this);
      return false;
    }
  }

  // async createRevocationCertificate(newId) {
  //   if (this.level == LEVEL_ROOT) {
  //     const seed = sha512(this.entropy);
  //     let node = derivePath(
  //       await Bip32PrivateKey.fromEntropy(seed.slice(0, 32)),
  //       "m/1'/0'/1'",
  //     );
  //     const proof = hash("sha256", node.toBip32PublicKey().toBytes());
  //     if (this.proof.toString("hex") == proof.toString("hex")) {
  //       const revocationCertificate = {
  //         xpub: node.toBytes(),
  //         id: this.id,
  //         newId,
  //       };
  //       revocationCertificate.signature = node.toPrivateKey().sign(revocationCertificate);
  //       return revocationCertificate;
  //     } else return null;
  //   } else return null;
  // }

  async createSwapingCertificate() {
    if (this.level === LEVEL_ROOT && this.entropy) {
      const newKey = await DeprecatedKeyManager.create_Id25519_fromEntropy(this.entropy, this.swapIndex + 1);

      const hiscp: HISCP = {
        newId: newKey.id,
        proofKey: this.proofKey.publicKey,
        timestamp: Date.now(),
        signature: Buffer.from([]),
      };
      const timestampBuffer = Buffer.alloc(8);
      timestampBuffer.writeBigUInt64LE(BigInt(hiscp.timestamp) as unknown as number, 0);
      const hiscpBuffer = Buffer.concat([hiscp.newId, hiscp.proofKey, timestampBuffer]);
      hiscp.signature = Buffer.from(Bip32PrivateKey.fromBytes(this.proofKey.secretKey!).toPrivateKey().sign(hiscpBuffer));
      return hiscp;
    }
    return null;
  }

  async verifySwapingCertificate(hiscp: HISCP) {
    const proof = hash("sha256", hiscp.proofKey).toString("hex");
    if (proof === this.proof?.toString("hex")) {
      const timestampBuffer = Buffer.alloc(8);
      timestampBuffer.writeBigUInt64LE(BigInt(hiscp.timestamp) as unknown as number, 0);
      const newKey = DeprecatedKeyManager.fromId(hiscp.newId);
      const hiscpBuffer = Buffer.concat([hiscp.newId, hiscp.proofKey, timestampBuffer]);
      return new PublicKey(hiscp.proofKey).verify(hiscp.signature, hiscpBuffer);
    } else {
      return false;
    }
  }

  cleanSecureData() {
    if (this.cypher?.secretKey) {
      secureErase(this.cypher.secretKey);
      delete this.cypher.secretKey;
    }
    if (this.signer?.secretKey) {
      secureErase(this.signer.secretKey);
      delete this.signer.secretKey;
    }
    if (this.entropy) {
      secureErase(this.entropy);
      delete this.entropy;
    }
  }

  /**
   * Performs a Diffie-Hellman key exchange with another KeyManager instance
   * @param otherKeyManager The other party's KeyManager instance
   * @returns A shared secret that can be used for symmetric encryption
   */
  async performDiffieHellman(otherKeyManager: KeyManager): Promise<Buffer | null> {
    if (this.capability === "public") {
      console.error("Cannot perform DH key exchange with a public key capability");
      return null;
    }

    const cypher = await this.getCypher();
    const otherKey = otherKeyManager.cypher.publicKey;

    // Perform the scalar multiplication to derive the shared secret
    const sharedSecret = await cypher.diffieHellman(otherKey);

    // Hash the shared secret for better security (to derive a symmetric key)
    const derivedKey = sha256(sharedSecret);

    // Securely erase the shared secret from memory
    secureErase(sharedSecret);

    return derivedKey;
  }

  /**
   * Static method to perform a Diffie-Hellman key exchange between two KeyManager instances
   * @param keyManager1 First KeyManager instance
   * @param keyManager2 Second KeyManager instance
   * @returns A shared secret that both parties can derive
   */
  static async diffieHellman(keyManager1: KeyManager, keyManager2: KeyManager): Promise<Buffer | null> {
    return keyManager1.performDiffieHellman(keyManager2);
  }

  /**
   * Encrypt a message using DHIES for a recipient
   * @param message Message to encrypt
   * @param recipientId Recipient's KeyManager ID
   * @returns Encrypted message or null if encryption fails
   */
  async dhiesEncrypt(message: string | Buffer, recipientId: Buffer): Promise<Buffer | null> {
    if (this.capability === "public") return null;
    try {
      const recipientPublicKey = getCypherPublicKeyFromId(recipientId);
      const cypher = await this.getCypher();
      return await dhiesV2Encrypt(message, cypher.diffieHellman, this.cypher.publicKey, recipientPublicKey);
    } catch {
      return null;
    }
  }

  /**
   * Decrypt a message encrypted with DHIES
   * @param encryptedMessage Encrypted message from dhiesEncrypt
   * @returns Decrypted message or null if decryption fails
   */
  async dhiesDecrypt(encryptedMessage: Buffer, senderId: Buffer): Promise<Buffer | null> {
    if (this.capability === "public") return null;
    try {
      const senderPublicKey = getCypherPublicKeyFromId(senderId);
      const cypher = await this.getCypher();
      return await dhiesV2Decrypt(encryptedMessage, cypher.diffieHellman, this.cypher.publicKey, senderPublicKey);
    } catch {
      return null;
    }
  }

  static async encrypt(plaintext: string, recipientIds: Buffer[]) {
    const publicKeys = recipientIds.map(getCypherPublicKeyFromId);
    return await encryptAndArmor(plaintext, null, publicKeys);
  }

  async signcrypt(plaintext: string, recipientIds: Buffer[]) {
    const publicKeys = recipientIds.map(getCypherPublicKeyFromId);
    const cypher = await this.getCypher();
    return await cypher.signcrypt(plaintext, publicKeys);
  }

  async decrypt(encryptedMessage: string, senderId: Buffer | null = null) {
    const cypher = await this.getCypher();
    const senderKey = senderId ? getCypherPublicKeyFromId(senderId) : null;
    const message = await cypher.decrypt(encryptedMessage, senderKey);
    return message.toString();
  }

  // use better hash to prevent attack
  getSecretHash(data: Buffer) {
    const toHash = Buffer.concat([data, Buffer.from("secrethash"), this.cypher.secretKey!]);
    return hash("sha256", toHash);
  }
}
