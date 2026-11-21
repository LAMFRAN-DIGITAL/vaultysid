import { randomBytes, secretboxOpen, secretboxSeal, SECRETBOX_KEY_LENGTH, SECRETBOX_NONCE_LENGTH, SECRETBOX_OVERHEAD_LENGTH } from "./nacl";
import { Buffer } from "buffer/";
import { sha224, sha256, sha512 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";

const getAlgorithm = (alg: string) => {
  const cleanAlg = alg.replaceAll("-", "").toLowerCase();
  if (cleanAlg === "sha256") return sha256;
  if (cleanAlg === "sha512") return sha512;
  if (cleanAlg === "sha224") return sha224;
  return sha256;
};

const _randomBytes = (size: number) => Buffer.from(randomBytes(size));

const hash = (alg: string, buffer: Buffer | Uint8Array) => Buffer.from(getAlgorithm(alg).create().update(buffer).digest());
const _hmac = (alg: string, key: Buffer | Uint8Array, data: string | Buffer | Uint8Array) => Buffer.from(hmac(getAlgorithm(alg), key, typeof data === "string" ? Buffer.from(data, "utf8") : data));

/** NaCl secretbox (XSalsa20-Poly1305), with the shape tweetnacl exposed: `secretbox(m, n, k)`, `secretbox.open(c, n, k)` (null on failure) and the three lengths. */
const secretbox = Object.assign((message: Uint8Array, nonce: Uint8Array, key: Uint8Array) => secretboxSeal(message, nonce, key), {
  open: (box: Uint8Array, nonce: Uint8Array, key: Uint8Array) => secretboxOpen(box, nonce, key),
  keyLength: SECRETBOX_KEY_LENGTH,
  nonceLength: SECRETBOX_NONCE_LENGTH,
  overheadLength: SECRETBOX_OVERHEAD_LENGTH,
});
const toBase64 = (bufferLike: Buffer) => Buffer.from(bufferLike).toString("base64");
const toHex = (bufferLike: Buffer) => Buffer.from(bufferLike).toString("hex");
const toUTF8 = (bufferLike: Buffer) => Buffer.from(bufferLike).toString("utf-8");
const fromBase64 = (string: string) => Buffer.from(string, "base64");
const fromHex = (string: string) => Buffer.from(string, "hex");
const fromUTF8 = (string: string) => Buffer.from(string, "utf-8");
const secureErase = (buffer: Buffer | Uint8Array) => {
  for (let i = 0; i < buffer.length; i++) {
    buffer[i] = 0;
  }
};

export { Buffer, hash, _hmac as hmac, _randomBytes as randomBytes, secretbox, toBase64, toHex, toUTF8, fromBase64, fromHex, fromUTF8, secureErase };
