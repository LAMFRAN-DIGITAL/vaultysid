import assert from "assert";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Buffer } from "buffer/";
import { Challenger, IdManager, isContactError, MemoryStorage, VaultysId } from "..";
import "./shims";
import type { Channel } from "../src/MemoryChannel";
import { isPostQuantumPeer } from "../src/postQuantumPeer";
import { CONTACT_PQ_GO_VECTORS, CONTACT_PQ_TS_VECTORS, generateContactPqVectors, serializeVectors } from "./interops/generate-contact-pq-vectors";

// Post-quantum peer option of the contact handshake (rfc/PROTOCOL.md §12.1), both directions:
// contact-pq-peer-ts-vectors.json (TypeScript -> Go) and contact-pq-peer-go-vectors.json
// (Go -> TypeScript, go/test/compatibility/generate_contact_pq_vectors.go).

type Vectors = {
  producer: string;
  domain: string;
  code: string;
  identities: Record<string, { algorithm: "ed25519" | "dilithium" | "dilithium_ed25519"; type: number; entropy: string; id: string; did: string; postQuantumPeer: boolean }>;
  init: { name: string; initiator: string; init: string; responderWithOption: "PEER_NOT_PQ" | "PQ_CHECK_PASSED" }[];
  step1: { name: string; initiator: string; responder: string; unsignedBytes: string; sign2: string; step1: string; initiatorWithOption: "PEER_NOT_PQ" }[];
};

const read = <T = Vectors>(file: string): T => JSON.parse(readFileSync(join(__dirname, "interops", file), "utf8"));
const unhex = (s: string) => Buffer.from(s, "hex");

/** A channel that delivers one frozen message and records what the side sends back. */
function oneMessageChannel(message: Buffer): { channel: Channel; sent: Buffer[] } {
  const sent: Buffer[] = [];
  let delivered = false;
  const channel: Channel = {
    start: async () => {},
    close: async () => {},
    send: async (data) => {
      sent.push(Buffer.from(data));
    },
    receive: async () => {
      if (delivered) throw new Error("no more messages");
      delivered = true;
      return message;
    },
    onConnected: () => {},
    getConnectionString: () => "vaultys://test",
    fromConnectionString: () => null,
  };
  return { channel, sent };
}

function replay(file: string, producer: string) {
  describe(`${file} (${producer})`, () => {
    const vectors = read(file);

    it("has the expected header and counts", () => {
      assert.strictEqual(vectors.producer, producer);
      assert.strictEqual(vectors.domain, "VAULTYS_HANDSHAKE_V1");
      assert.strictEqual(vectors.code, "PEER_NOT_PQ");
      assert.strictEqual(Object.keys(vectors.identities).length, 6);
      assert.strictEqual(vectors.init.length, 6);
      assert.strictEqual(vectors.step1.length, 1);
    });

    it("derives the same identities, with the same classification", async () => {
      for (const [name, ident] of Object.entries(vectors.identities)) {
        const id = await VaultysId.fromEntropy(unhex(ident.entropy), ident.type, ident.algorithm);
        assert.strictEqual(id.id.toString("hex"), ident.id, name);
        assert.strictEqual(id.did, ident.did, name);
        assert.strictEqual(isPostQuantumPeer(VaultysId.fromId(unhex(ident.id))), ident.postQuantumPeer, name);
      }
    });

    for (const v of vectors.init) {
      it(`responder with the option: ${v.name} -> ${v.responderWithOption}`, async () => {
        const manager = new IdManager(
          await VaultysId.generatePerson("dilithium_ed25519"),
          MemoryStorage(() => ""),
        );
        const { channel, sent } = oneMessageChannel(unhex(v.init));
        const error = await manager.acceptContact(channel, {}, undefined, { requirePostQuantumPeer: true }).then(
          () => assert.fail("a frozen INIT never completes"),
          (e: unknown) => e,
        );
        if (v.responderWithOption === "PEER_NOT_PQ") assert.ok(isContactError(error, "PEER_NOT_PQ"), String(error));
        else assert.ok(!isContactError(error) && /liveliness/.test(String(error)), String(error));
        // nothing but refusal bytes: no STEP1 signed
        assert.ok(sent.every((m) => m.length === 1 && m[0] === 0));
        assert.strictEqual(manager.contacts.length, 0);
      });
    }

    for (const v of vectors.step1) {
      it(`initiator with the option: ${v.name} -> ${v.initiatorWithOption}`, () => {
        const message = unhex(v.step1);
        const parsed = Challenger.deserializeCertificate(message);
        assert.strictEqual(parsed.state, 1, String(parsed.error)); // sign2 verified
        assert.strictEqual(Challenger.serializeCertificate(parsed).toString("hex"), v.unsignedBytes);
        assert.strictEqual(Buffer.from(parsed.sign2!).toString("hex"), v.sign2);
        assert.strictEqual(Buffer.from(parsed.pk2!).toString("hex"), vectors.identities[v.responder].id);
        assert.strictEqual(isPostQuantumPeer(VaultysId.fromId(Buffer.from(parsed.pk2!))), false);
      });
    }
  });
}

describe("Contact post-quantum peer vectors", () => {
  replay(CONTACT_PQ_TS_VECTORS, "typescript");
  replay(CONTACT_PQ_GO_VECTORS, "go");

  it("regenerates contact-pq-peer-ts-vectors.json byte for byte", async () => {
    const expected = readFileSync(join(__dirname, "interops", CONTACT_PQ_TS_VECTORS), "utf8");
    assert.strictEqual(serializeVectors(await generateContactPqVectors()), expected);
  });

  it("lets the hybrid STEP1 of the hybrid handshake vectors pass the initiator's check", () => {
    for (const file of ["hybrid-handshake-ts-vectors.json", "hybrid-handshake-go-vectors.json"]) {
      for (const h of read<{ handshakes: { name: string; step1: string }[] }>(file).handshakes) {
        const parsed = Challenger.deserializeCertificate(unhex(h.step1));
        assert.strictEqual(parsed.state, 1, h.name);
        assert.ok(isPostQuantumPeer(VaultysId.fromId(Buffer.from(parsed.pk2!))), h.name);
      }
    }
  });
});
