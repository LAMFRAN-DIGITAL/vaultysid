import assert from "assert";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Buffer } from "buffer/";
import { Challenger, VaultysId } from "..";
import "./shims";
import HybridManager from "../src/KeyManager/HybridManager";
import { HANDSHAKE_INCIPIT } from "../src/VaultysId";
import { hash } from "../src/crypto";
import { generateHybridHandshakeVectors, HYBRID_HANDSHAKE_GO_VECTORS, HYBRID_HANDSHAKE_TS_VECTORS, serializeVectors } from "./interops/generate-hybrid-handshake-vectors";

// v1 handshake between hybrid (dilithium_ed25519) identities, both directions:
// hybrid-handshake-ts-vectors.json (TypeScript -> Go) and hybrid-handshake-go-vectors.json
// (Go -> TypeScript, go/test/compatibility/generate_hybrid_handshake_vectors.go).

type Vectors = {
  producer: string;
  domain: string;
  algorithm: string;
  identities: Record<string, { algorithm: "dilithium_ed25519"; type: number; entropy: string; idLength: number; id: string; did: string }>;
  handshakes: { name: string; initiator: string; responder: string; timestamp: number; nonce: string; metadata: { pk1: Record<string, string>; pk2: Record<string, string> }; unsignedBytes: string; handshakeDigest: string; sign1: string; sign2: string; init: string; step1: string; complete: string }[];
  negative: { name: string; complete: string }[];
};

const read = (file: string): Vectors => JSON.parse(readFileSync(join(__dirname, "interops", file), "utf8"));
const unhex = (s: string) => Buffer.from(s, "hex");

function replay(file: string, producer: string) {
  describe(`${file} (${producer})`, () => {
    const vectors = read(file);

    it("has the expected header and counts", () => {
      assert.strictEqual(vectors.producer, producer);
      assert.strictEqual(vectors.domain, "VAULTYS_HANDSHAKE_V1");
      assert.strictEqual(vectors.algorithm, "dilithium_ed25519");
      assert.strictEqual(Object.keys(vectors.identities).length, 4);
      assert.strictEqual(vectors.handshakes.length, 2);
      assert.strictEqual(vectors.negative.length, 6);
    });

    it("derives the same hybrid identities from the same entropy", async () => {
      for (const [name, ident] of Object.entries(vectors.identities)) {
        const id = await VaultysId.fromEntropy(unhex(ident.entropy), ident.type, ident.algorithm);
        assert.ok(id.keyManager instanceof HybridManager, name);
        assert.strictEqual(id.id.toString("hex"), ident.id, name);
        assert.strictEqual(id.id.length, ident.idLength, name);
        assert.strictEqual(id.did, ident.did, name);
      }
    });

    for (const h of vectors.handshakes) {
      it(`verifies ${h.name}`, async () => {
        const complete = unhex(h.complete);
        const parsed = Challenger.deserializeCertificate(complete);
        assert.strictEqual(parsed.state, 2, String(parsed.error));
        assert.ok(await Challenger.verifyCertificate(complete));
        assert.strictEqual(Buffer.from(parsed.pk1!).toString("hex"), vectors.identities[h.initiator].id);
        assert.strictEqual(Buffer.from(parsed.pk2!).toString("hex"), vectors.identities[h.responder].id);
        assert.strictEqual(parsed.timestamp, h.timestamp);
        assert.deepStrictEqual(parsed.metadata, h.metadata);
        const unsigned = Challenger.serializeCertificate(parsed);
        assert.strictEqual(unsigned.toString("hex"), h.unsignedBytes);
        assert.strictEqual(hash("sha256", Buffer.concat([HANDSHAKE_INCIPIT, unsigned])).toString("hex"), h.handshakeDigest);
        assert.strictEqual(Buffer.from(parsed.sign1!).toString("hex"), h.sign1);
        assert.strictEqual(Buffer.from(parsed.sign2!).toString("hex"), h.sign2);
        assert.strictEqual(parsed.sign1!.length, 64 + 4627);
        const initiator = VaultysId.fromId(parsed.pk1!);
        assert.ok(initiator.verifyHandshake(unsigned, parsed.sign1!));
        // only in the handshake domain
        assert.ok(!initiator.verify(unsigned, parsed.sign1!));
        assert.ok(!initiator.verifyChallenge(unsigned, parsed.sign1!, false));
        assert.strictEqual(Challenger.deserializeCertificate(unhex(h.init)).state, 0);
        assert.strictEqual(Challenger.deserializeCertificate(unhex(h.step1)).state, 1);
      });
    }

    it("refuses every tampered certificate", async () => {
      for (const n of vectors.negative) {
        assert.notStrictEqual(Challenger.deserializeCertificate(unhex(n.complete)).state, 2, n.name);
        assert.strictEqual(await Challenger.verifyCertificate(unhex(n.complete)), false, n.name);
      }
    });
  });
}

describe("hybrid handshake vectors", () => {
  replay(HYBRID_HANDSHAKE_TS_VECTORS, "typescript");
  replay(HYBRID_HANDSHAKE_GO_VECTORS, "go");

  it("regenerates the TypeScript file byte for byte", async () => {
    const expected = readFileSync(join(__dirname, "interops", HYBRID_HANDSHAKE_TS_VECTORS), "utf8");
    assert.strictEqual(serializeVectors(await generateHybridHandshakeVectors()), expected);
  });
});
