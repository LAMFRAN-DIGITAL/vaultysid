/**
 * Deterministic cross-language vectors of the v1 handshake (VAULTYS_HANDSHAKE_V1) between HYBRID identities
 * (dilithium_ed25519: sig_ed25519 || ML-DSA-87(digest || sig_ed25519)), produced by TypeScript for Go.
 * The Go side produces the reverse file (go/test/compatibility/generate_hybrid_handshake_vectors.go).
 *
 *   pnpm test:hybrid:vectors        (npx tsx test/interops/generate-hybrid-handshake-vectors.ts)
 *
 * Writes test/interops/hybrid-handshake-ts-vectors.json and copies it to ../go/test/compatibility/testdata/.
 * Running it twice produces byte-identical output.
 *
 * Signatures: the Ed25519 half comes from the real VaultysId.signHandshake (Ed25519 is deterministic); the ML-DSA-87
 * half uses the deterministic variant of FIPS 204 (rnd = 0, noble `extraEntropy: false`) instead of the hedged one,
 * so that the file is reproducible. Both are valid signatures for any verifier; the generator checks that the real
 * (hedged) signature and the deterministic one both verify.
 */
import { copyFileSync, mkdirSync, writeFileSync } from "fs";
import { dirname, resolve } from "path";
import { Buffer } from "buffer/";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import VaultysId, { HANDSHAKE_INCIPIT } from "../../src/VaultysId";
import Challenger, { ChallengeType } from "../../src/Challenger";
import HybridManager from "../../src/KeyManager/HybridManager";
import { hash } from "../../src/crypto";

export const HYBRID_HANDSHAKE_TS_VECTORS = "hybrid-handshake-ts-vectors.json";
export const HYBRID_HANDSHAKE_GO_VECTORS = "hybrid-handshake-go-vectors.json";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
/** Pinned test inputs: SHA-512 of a readable label, truncated. Never use such values outside tests. */
const pinned = (name: string, length: number) => Buffer.from(hash("sha512", Buffer.from("VaultysID hybrid handshake test vector/" + name, "ascii")).subarray(0, length));

function check(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error("hybrid handshake vectors: " + message);
}

const SERVICE_ID = "https://service.test";
const TIMESTAMP = 1763769600000; // 2025-11-22T00:00:00Z, fixed

/** Deterministic hybrid handshake signature (see the header). */
async function signHandshakeDeterministic(identity: VaultysId, unsigned: Buffer): Promise<Buffer> {
  const km = identity.keyManager;
  check(km instanceof HybridManager && km.edSigner?.secretKey && km.pqSigner?.secretKey, "not a private hybrid identity");
  const live = await identity.signHandshake(unsigned);
  const digest = hash("sha256", Buffer.concat([HANDSHAKE_INCIPIT, unsigned]));
  const edSignature = live.subarray(0, 64);
  const pqSignature = Buffer.from(ml_dsa87.sign(Buffer.concat([digest, edSignature]), km.pqSigner.secretKey, { extraEntropy: false }));
  const signature = Buffer.concat([edSignature, pqSignature]);
  const verifier = VaultysId.fromId(identity.id);
  check(verifier.verifyHandshake(unsigned, live), "the real hybrid signature does not verify");
  check(verifier.verifyHandshake(unsigned, signature), "the deterministic hybrid signature does not verify");
  return signature;
}

type IdentitySpec = { name: string; type: number };
const IDENTITIES: IdentitySpec[] = [
  { name: "hybrid_person", type: 0x01 },
  { name: "hybrid_organization", type: 0x02 },
  { name: "pq_hybrid_person", type: 0x11 },
  { name: "pq_hybrid_machine", type: 0x10 },
];
const HANDSHAKES: [string, string, string][] = [
  ["hybrid_person_to_organization", "hybrid_person", "hybrid_organization"],
  ["pq_hybrid_person_to_machine", "pq_hybrid_person", "pq_hybrid_machine"],
];

/** Flips one bit at `offset` of a copy. */
const flip = (bytes: Buffer, offset: number) => {
  const out = Buffer.from(bytes);
  out[offset] ^= 0x01;
  return out;
};

export async function generateHybridHandshakeVectors() {
  const identities: Record<string, unknown> = {};
  const ids: Record<string, VaultysId> = {};
  for (const { name, type } of IDENTITIES) {
    const entropy = pinned("entropy/" + name, 32);
    const id = await VaultysId.fromEntropy(entropy, type, "dilithium_ed25519");
    check(id.keyManager instanceof HybridManager, name + ": key manager");
    const parsed = VaultysId.fromId(id.id);
    check(parsed.id.equals(id.id) && parsed.did === id.did, name + ": id round trip");
    ids[name] = id;
    identities[name] = { algorithm: "dilithium_ed25519", type, entropy: hex(entropy), idLength: id.id.length, id: hex(id.id), did: id.did };
  }

  const handshakes = [];
  const negative = [];
  for (const [name, initiatorName, responderName] of HANDSHAKES) {
    const initiator = ids[initiatorName];
    const responder = ids[responderName];
    const binding = pinned("binding/" + name, 32).toString("base64");
    // keys in sorted order, as Go's challenger.NewMetadata writes them
    const metadata = {
      pk1: { name: initiatorName, "vaultys.channel-binding": binding, "vaultys.service": SERVICE_ID },
      pk2: { name: responderName, "vaultys.channel-binding": binding, "vaultys.service": SERVICE_ID },
    };
    const challenge: ChallengeType = {
      version: 1,
      protocol: "p2p",
      service: "auth",
      timestamp: TIMESTAMP,
      pk1: initiator.id,
      pk2: responder.id,
      nonce: pinned("nonce/" + name, 32),
      metadata,
      state: 1,
    };
    const unsigned = Challenger.serializeCertificate(challenge);
    const handshakeDigest = hash("sha256", Buffer.concat([HANDSHAKE_INCIPIT, unsigned]));
    challenge.sign2 = await signHandshakeDeterministic(responder, unsigned);
    challenge.sign1 = await signHandshakeDeterministic(initiator, unsigned);

    const serializer = new Challenger(initiator);
    serializer.challenge = { ...challenge, sign1: undefined, sign2: undefined, state: 0, pk2: undefined, nonce: Buffer.from(challenge.nonce!.subarray(0, 16)), metadata: { pk1: metadata.pk1 } };
    const init = serializer.getCertificate();
    serializer.challenge = { ...challenge, sign1: undefined, state: 1 };
    const step1 = serializer.getCertificate();
    serializer.challenge = { ...challenge, state: 2 };
    const complete = serializer.getCertificate();

    check(Challenger.deserializeCertificate(init).state === 0, name + ": INIT does not parse");
    check(Challenger.deserializeCertificate(step1).state === 1, name + ": STEP1 does not verify");
    const parsed = Challenger.deserializeCertificate(complete);
    check(parsed.state === 2, name + ": COMPLETE does not verify: " + parsed.error);
    check(await Challenger.verifyCertificate(complete), name + ": verifyCertificate");

    handshakes.push({
      name,
      initiator: initiatorName,
      responder: responderName,
      version: 1,
      protocol: "p2p",
      service: "auth",
      timestamp: TIMESTAMP,
      nonce: hex(challenge.nonce!),
      metadata,
      unsignedBytes: hex(unsigned),
      handshakeDigest: hex(handshakeDigest),
      sign1: hex(challenge.sign1),
      sign2: hex(challenge.sign2),
      init: hex(init),
      step1: hex(step1),
      complete: hex(complete),
    });

    // Tampered COMPLETE certificates (first handshake only, to keep the file small): every verifier MUST refuse them.
    if (name !== HANDSHAKES[0][0]) continue;
    const tampered: [string, Partial<ChallengeType>][] = [
      ["sign1_ed25519_half_altered", { sign1: flip(challenge.sign1, 10) }],
      ["sign1_mldsa_half_altered", { sign1: flip(challenge.sign1, 64 + 100) }],
      ["sign2_mldsa_half_altered", { sign2: flip(challenge.sign2, challenge.sign2.length - 5) }],
      ["sign1_ed25519_only", { sign1: Buffer.from(challenge.sign1.subarray(0, 64)) }],
      ["sign2_mldsa_only", { sign2: Buffer.from(challenge.sign2.subarray(64)) }],
      ["service_metadata_changed", { metadata: { pk1: { ...metadata.pk1, "vaultys.service": "https://other.test" }, pk2: metadata.pk2 } }],
    ];
    for (const [suffix, change] of tampered) {
      serializer.challenge = { ...challenge, ...change, state: 2 };
      const certificate = serializer.getCertificate();
      check(Challenger.deserializeCertificate(certificate).state !== 2, `${name}/${suffix}: tampered certificate accepted`);
      negative.push({ name: `${name}/${suffix}`, complete: hex(certificate) });
    }
  }

  return {
    description: "VAULTYS_HANDSHAKE_V1 between hybrid (dilithium_ed25519) identities, produced by TypeScript. ML-DSA-87 half signed with the deterministic variant of FIPS 204 (rnd = 0); every verifier MUST accept `handshakes` and refuse `negative`.",
    producer: "typescript",
    domain: "VAULTYS_HANDSHAKE_V1",
    algorithm: "dilithium_ed25519",
    identities,
    handshakes,
    negative,
  };
}

export const serializeVectors = (vectors: unknown) => JSON.stringify(vectors, null, 2) + "\n";

if (require.main === module) {
  generateHybridHandshakeVectors()
    .then((vectors) => {
      const main = resolve(__dirname, HYBRID_HANDSHAKE_TS_VECTORS);
      writeFileSync(main, serializeVectors(vectors));
      console.log("wrote", main);
      const target = resolve(__dirname, "../../../go/test/compatibility/testdata", HYBRID_HANDSHAKE_TS_VECTORS);
      mkdirSync(dirname(target), { recursive: true });
      copyFileSync(main, target);
      console.log("copied to", target);
    })
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}
