/**
 * Deterministic cross-language vectors of the "post-quantum peer required" option of the contact handshake
 * (askContact / acceptContact in TypeScript, RequestConnectWithOptions / AcceptConnectWithOptions in Go;
 * rfc/PROTOCOL.md §12.1), produced by TypeScript for Go. The Go side produces the reverse file
 * (go/test/compatibility/generate_contact_pq_vectors.go).
 *
 *   pnpm test:contact-pq:vectors    (npx tsx test/interops/generate-contact-pq-vectors.ts)
 *
 * Writes test/interops/contact-pq-peer-ts-vectors.json and copies it to ../go/test/compatibility/testdata/.
 * Running it twice produces byte-identical output.
 *
 * What is frozen, and why it is enough: the option decides on the peer's serialized id only.
 *   - `init`: unsigned INIT messages (p2p/auth) from identities of every signing algorithm. A responder with the
 *     option MUST refuse the Ed25519 one with PEER_NOT_PQ before signing STEP1, and MUST let the others pass this
 *     check (they are then refused by the liveliness window, as any frozen INIT, never with PEER_NOT_PQ).
 *   - `step1`: a STEP1 signed by an Ed25519 responder (Ed25519 is deterministic). An initiator with the option MUST
 *     refuse it with PEER_NOT_PQ once sign2 verifies; the replay checks sign2 and the classification of pk2 (the
 *     initiator's own INIT state cannot be frozen). Hybrid STEP1 that MUST pass are in hybrid-handshake-*-vectors.json.
 */
import { copyFileSync, mkdirSync, writeFileSync } from "fs";
import { dirname, resolve } from "path";
import { Buffer } from "buffer/";
import VaultysId from "../../src/VaultysId";
import Challenger, { ChallengeType } from "../../src/Challenger";
import { isPostQuantumPeer } from "../../src/postQuantumPeer";
import { hash } from "../../src/crypto";

export const CONTACT_PQ_TS_VECTORS = "contact-pq-peer-ts-vectors.json";
export const CONTACT_PQ_GO_VECTORS = "contact-pq-peer-go-vectors.json";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
/** Pinned test inputs: SHA-512 of a readable label, truncated. Never use such values outside tests. */
const pinned = (name: string, length: number) => Buffer.from(hash("sha512", Buffer.from("VaultysID contact PQ test vector/" + name, "ascii")).subarray(0, length));

function check(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error("contact PQ vectors: " + message);
}

const TIMESTAMP = 1763769600000; // 2025-11-22T00:00:00Z, fixed

type Algorithm = "ed25519" | "dilithium" | "dilithium_ed25519";
export const CONTACT_PQ_IDENTITIES: { name: string; type: number; algorithm: Algorithm; postQuantumPeer: boolean }[] = [
  { name: "ed25519_person", type: 0x01, algorithm: "ed25519", postQuantumPeer: false },
  { name: "ed25519_organization", type: 0x02, algorithm: "ed25519", postQuantumPeer: false },
  { name: "dilithium_person", type: 0x01, algorithm: "dilithium", postQuantumPeer: true },
  { name: "hybrid_person", type: 0x01, algorithm: "dilithium_ed25519", postQuantumPeer: true },
  { name: "pq_hybrid_person", type: 0x11, algorithm: "dilithium_ed25519", postQuantumPeer: true },
  { name: "pq_dilithium_machine", type: 0x10, algorithm: "dilithium", postQuantumPeer: true },
];
const STEP1: [string, string, string][] = [["hybrid_person_to_ed25519_organization", "hybrid_person", "ed25519_organization"]];

export async function generateContactPqVectors() {
  const identities: Record<string, unknown> = {};
  const ids: Record<string, VaultysId> = {};
  for (const { name, type, algorithm, postQuantumPeer } of CONTACT_PQ_IDENTITIES) {
    const entropy = pinned("entropy/" + name, 32);
    const id = await VaultysId.fromEntropy(entropy, type, algorithm);
    const parsed = VaultysId.fromId(id.id);
    check(parsed.id.equals(id.id) && parsed.did === id.did, name + ": id round trip");
    check(isPostQuantumPeer(parsed) === postQuantumPeer, name + ": classification");
    ids[name] = id;
    identities[name] = { algorithm, type, entropy: hex(entropy), idLength: id.id.length, id: hex(id.id), did: id.did, postQuantumPeer };
  }

  const init = [];
  for (const { name, postQuantumPeer } of CONTACT_PQ_IDENTITIES) {
    const serializer = new Challenger(ids[name]);
    const challenge: ChallengeType = { version: 1, protocol: "p2p", service: "auth", timestamp: TIMESTAMP, pk1: ids[name].id, nonce: pinned("nonce/init/" + name, 16), metadata: { pk1: { name } }, state: 0 };
    serializer.challenge = challenge;
    const message = serializer.getCertificate();
    const parsed = Challenger.deserializeCertificate(message);
    check(parsed.state === 0 && Buffer.from(parsed.pk1!).equals(ids[name].id), name + ": INIT does not parse");
    init.push({ name: "init_from_" + name, initiator: name, init: hex(message), responderWithOption: postQuantumPeer ? "PQ_CHECK_PASSED" : "PEER_NOT_PQ" });
  }

  const step1 = [];
  for (const [name, initiatorName, responderName] of STEP1) {
    const initiator = ids[initiatorName];
    const responder = ids[responderName];
    const challenge: ChallengeType = {
      version: 1,
      protocol: "p2p",
      service: "auth",
      timestamp: TIMESTAMP,
      pk1: initiator.id,
      pk2: responder.id,
      nonce: pinned("nonce/step1/" + name, 32),
      metadata: { pk1: { name: initiatorName }, pk2: { name: responderName } },
      state: 1,
    };
    const unsigned = Challenger.serializeCertificate(challenge);
    challenge.sign2 = await responder.signHandshake(unsigned);
    const serializer = new Challenger(initiator);
    serializer.challenge = challenge;
    const message = serializer.getCertificate();
    const parsed = Challenger.deserializeCertificate(message);
    check(parsed.state === 1, name + ": STEP1 does not verify: " + parsed.error);
    check(!isPostQuantumPeer(VaultysId.fromId(parsed.pk2!)), name + ": responder must be classical");
    step1.push({ name, initiator: initiatorName, responder: responderName, unsignedBytes: hex(unsigned), sign2: hex(challenge.sign2), step1: hex(message), initiatorWithOption: "PEER_NOT_PQ" });
  }

  return {
    description: "Contact handshake (p2p/auth) with the post-quantum peer option (rfc/PROTOCOL.md §12.1), produced by TypeScript. A responder with the option MUST refuse `init` marked PEER_NOT_PQ before signing STEP1 and let the others pass this check; an initiator with the option MUST refuse `step1` (sign2 verifies, pk2 is Ed25519) before signing COMPLETE.",
    producer: "typescript",
    domain: "VAULTYS_HANDSHAKE_V1",
    code: "PEER_NOT_PQ",
    identities,
    init,
    step1,
  };
}

export const serializeVectors = (vectors: unknown) => JSON.stringify(vectors, null, 2) + "\n";

if (require.main === module) {
  generateContactPqVectors()
    .then((vectors) => {
      const main = resolve(__dirname, CONTACT_PQ_TS_VECTORS);
      writeFileSync(main, serializeVectors(vectors));
      console.log("wrote", main);
      const target = resolve(__dirname, "../../../go/test/compatibility/testdata", CONTACT_PQ_TS_VECTORS);
      mkdirSync(dirname(target), { recursive: true });
      copyFileSync(main, target);
      console.log("copied to", target);
    })
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}
