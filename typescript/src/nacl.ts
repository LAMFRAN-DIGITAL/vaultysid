import { x25519 } from "@noble/curves/ed25519.js";
import { xsalsa20poly1305 } from "@noble/ciphers/salsa.js";
import { randomBytes as nobleRandomBytes } from "@noble/hashes/utils.js";

/**
 * The few NaCl operations the library uses, on @noble/curves (X25519) and @noble/ciphers
 * (XSalsa20-Poly1305), byte for byte what tweetnacl 1.0.3 produced:
 *
 *   boxKeyPairFromSecretKey(sk)   nacl.box.keyPair.fromSecretKey(sk)   public key = X25519(sk, 9), clamped scalar
 *   boxKeyPair()                  nacl.box.keyPair()
 *   scalarMult(sk, pk)            nacl.scalarMult(sk, pk)              RFC 7748 X25519
 *   secretboxSeal(m, n, k)        nacl.secretbox(m, n, k)              tag(16) || ciphertext
 *   secretboxOpen(c, n, k)        nacl.secretbox.open(c, n, k)         null when the tag does not verify
 *
 * One deliberate difference: scalarMult throws on a low-order public key (the five u coordinates whose
 * product with any clamped scalar is zero), where tweetnacl returned 32 zero bytes. Every caller already
 * refused an all-zero shared secret or returned null on failure; this rejects the point before the ladder.
 * test/naclNoble.test.ts checks every function against tweetnacl.
 */

export type BoxKeyPair = { publicKey: Uint8Array; secretKey: Uint8Array };

export const SECRETBOX_KEY_LENGTH = 32;
export const SECRETBOX_NONCE_LENGTH = 24;
export const SECRETBOX_OVERHEAD_LENGTH = 16;
export const BOX_SECRET_KEY_LENGTH = 32;

export const randomBytes = (length: number): Uint8Array => nobleRandomBytes(length);

/** The X25519 key pair of a 32-byte secret key; the secret key is returned as a copy, as tweetnacl did. */
export const boxKeyPairFromSecretKey = (secretKey: Uint8Array): BoxKeyPair => {
  if (!(secretKey instanceof Uint8Array) || secretKey.length !== BOX_SECRET_KEY_LENGTH) throw new Error("bad secret key size");
  const sk = new Uint8Array(secretKey);
  return { publicKey: x25519.getPublicKey(sk), secretKey: sk };
};

export const boxKeyPair = (): BoxKeyPair => boxKeyPairFromSecretKey(randomBytes(BOX_SECRET_KEY_LENGTH));

/** X25519(secretKey, publicKey). Throws on a low-order public key. */
export const scalarMult = (secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array => x25519.getSharedSecret(secretKey, publicKey);

const checkSecretbox = (nonce: Uint8Array, key: Uint8Array) => {
  if (!(key instanceof Uint8Array) || key.length !== SECRETBOX_KEY_LENGTH) throw new Error("bad key size");
  if (!(nonce instanceof Uint8Array) || nonce.length !== SECRETBOX_NONCE_LENGTH) throw new Error("bad nonce size");
};

/** XSalsa20-Poly1305 (NaCl secretbox): tag(16) || ciphertext. */
export const secretboxSeal = (message: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array => {
  checkSecretbox(nonce, key);
  return Uint8Array.from(xsalsa20poly1305(Uint8Array.from(key), Uint8Array.from(nonce)).encrypt(Uint8Array.from(message)));
};

/** Opens a secretbox; null when it is too short or its tag does not verify. */
export const secretboxOpen = (box: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array | null => {
  checkSecretbox(nonce, key);
  if (!(box instanceof Uint8Array) || box.length < SECRETBOX_OVERHEAD_LENGTH) return null;
  try {
    return Uint8Array.from(xsalsa20poly1305(Uint8Array.from(key), Uint8Array.from(nonce)).decrypt(Uint8Array.from(box)));
  } catch {
    return null;
  }
};
