import nacl from "tweetnacl";
import { Buffer } from "buffer/";
import { hash, secureErase } from "../crypto";

/**
 * Decrypt-only DHIES as written by @vaultys/id 3.x: `nonce(24) || ephemeral_pk(32) || secretbox || mac(32)`, keys
 * from X25519(recipient sk, ephemeral pk) and a KDF over the claimed sender and recipient X25519 keys.
 *
 * The sender's key only enters the KDF: nothing proves who encrypted the message, anyone holding the recipient's
 * public key can produce one under any sender id. 4.0 never writes this format (DHIES v2 authenticates the sender).
 */
export const dhiesV1LegacyDecrypt = (encrypted: Uint8Array, recipientSecretKey: Uint8Array, recipientPublicKey: Uint8Array, claimedSenderPublicKey: Uint8Array): Buffer | null => {
  const message = Buffer.from(encrypted);
  if (message.length < 24 + 32 + nacl.secretbox.overheadLength + 32) return null;
  const nonce = message.slice(0, 24);
  const ephemeralPublicKey = message.slice(24, 56);
  const mac = message.slice(message.length - 32);
  const ciphertext = message.slice(56, message.length - 32);
  const sharedSecret = Buffer.from(nacl.scalarMult(recipientSecretKey, ephemeralPublicKey));
  const context = Buffer.concat([Buffer.from("DHIES-KDF"), Buffer.from(claimedSenderPublicKey), Buffer.from(recipientPublicKey)]);
  const encryptionKey = hash("sha512", Buffer.concat([sharedSecret, context, Buffer.from([0x01])])).slice(0, 32);
  const macKey = hash("sha512", Buffer.concat([sharedSecret, context, Buffer.from([0x02])])).slice(0, 32);
  try {
    const expected = hash("sha256", Buffer.concat([macKey, Buffer.from(claimedSenderPublicKey), nonce, ciphertext]));
    let diff = 0;
    for (let i = 0; i < 32; i++) diff |= expected[i] ^ mac[i];
    if (diff !== 0) return null;
    const plaintext = nacl.secretbox.open(ciphertext, nonce, encryptionKey);
    return plaintext ? Buffer.from(plaintext) : null;
  } finally {
    secureErase(sharedSecret);
    secureErase(encryptionKey);
    secureErase(macKey);
  }
};
