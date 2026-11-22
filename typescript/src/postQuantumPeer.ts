// "Post-quantum peer required" policy, shared by the X-Wing bound handshake (xwingChannel.ts, rfc/SECURE-CHANNEL.md §4)
// and by the contact handshake of IdManager (askContact / acceptContact, rfc/PROTOCOL.md §12.1). Kept in its own module
// so that IdManager can use it without importing xwingChannel (which imports IdManager).
import { Buffer } from "buffer/";
import DilithiumManager from "./KeyManager/DilithiumManager";
import HybridManager from "./KeyManager/HybridManager";
import VaultysId from "./VaultysId";

/**
 * Whether an identity signs with ML-DSA: Dilithium (ML-DSA-87) or hybrid (Ed25519 + ML-DSA-87) key manager. Ed25519,
 * FIDO2 and passport identities are not post-quantum signers.
 */
export function isPostQuantumPeer(identity: VaultysId): boolean {
  return identity.keyManager instanceof DilithiumManager || identity.keyManager instanceof HybridManager;
}

/** Same as isPostQuantumPeer, on a serialized id (pk1 / pk2 of a challenge). Never throws. */
export function isPostQuantumPeerId(id: Uint8Array | undefined): boolean {
  if (!(id instanceof Uint8Array)) return false;
  try {
    return isPostQuantumPeer(VaultysId.fromId(Buffer.from(Uint8Array.from(id))));
  } catch {
    return false;
  }
}

export interface PostQuantumPeerOption {
  /**
   * Refuse a peer whose identity does not sign with ML-DSA (Dilithium or hybrid), with PEER_NOT_PQ. Checked on the
   * identity that signed the peer's message BEFORE this side signs anything (STEP1 for the responder, COMPLETE for the
   * initiator): nothing is signed for a classical peer. Default false (compatibility).
   */
  requirePostQuantumPeer?: boolean;
}

/** Errors of the contact handshake options (askContact / acceptContact). Same codes as the X-Wing channel. */
export type ContactErrorCode = "INVALID_ARGUMENT" | "PEER_NOT_PQ";

export class ContactError extends Error {
  readonly code: ContactErrorCode;
  constructor(code: ContactErrorCode) {
    super(`contact: ${code}`);
    this.name = "ContactError";
    this.code = code;
  }
}

export const isContactError = (error: unknown, code?: ContactErrorCode): error is ContactError => error instanceof ContactError && (code === undefined || error.code === code);
