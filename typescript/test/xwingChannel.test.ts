import assert from "assert";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Buffer } from "buffer/";
import { ml_kem768_x25519 } from "@noble/post-quantum/hybrid.js";
import { IdManager, MemoryChannel, MemoryStorage, VaultysId } from "..";
import "./shims";
import type { Channel } from "../src/MemoryChannel";
import { acceptOverXWing, acceptXWingChannel, BINDING_METADATA_KEY, certificateKey, connectOverXWing, identityFingerprint, initiateXWingChannel, isChannelError, isPostQuantumPeer, SERVICE_METADATA_KEY, type ChannelErrorCode } from "../src/xwingChannel";
import { buildVectors, VECTORS_PATH } from "./interops/generate-xwing-channel-vectors";

// rfc/SECURE-CHANNEL.md

const SERVICE = "https://service.test";

async function expectCode(promise: Promise<unknown>, code: ChannelErrorCode) {
  let error: unknown;
  try {
    await promise;
  } catch (e) {
    error = e;
  }
  assert.ok(isChannelError(error, code), `expected ${code}, got ${String(error)}`);
}

/** Wraps a channel so a test can see, drop, change or inject what goes through it. */
function tap(channel: Channel) {
  const sent: Buffer[] = [];
  let mutate: ((data: Buffer) => Buffer | null) | undefined;
  const send = channel.send.bind(channel);
  channel.send = async (data: Buffer) => {
    sent.push(Buffer.from(data));
    const out = mutate ? mutate(Buffer.from(data)) : data;
    if (out) await send(out);
  };
  return {
    sent,
    setMutate(f: (data: Buffer) => Buffer | null) {
      mutate = f;
    },
    raw: send,
  };
}

async function pairOfChannels() {
  const a = MemoryChannel.createBidirectionnal();
  const b = a.otherend!;
  const ta = tap(a);
  const tb = tap(b);
  const [initiator, responder] = await Promise.all([initiateXWingChannel(a), acceptXWingChannel(b)]);
  return { a, b, ta, tb, initiator, responder };
}

/** Counts the handshake signatures an identity produces (the Challenger signs only through signHandshake). */
function countHandshakeSignatures(identity: VaultysId): () => number {
  let count = 0;
  const original = identity.signHandshake.bind(identity);
  identity.signHandshake = async (data) => {
    count++;
    return original(data);
  };
  return () => count;
}

const newManager = async (identity?: VaultysId) =>
  new IdManager(
    identity ?? (await VaultysId.generatePerson()),
    MemoryStorage(() => ""),
  );

describe("X-Wing secure channel", () => {
  describe("X-Wing", () => {
    it("matches the official draft vectors", () => {
      const { vectors } = JSON.parse(readFileSync(join(__dirname, "interops/xwing-draft-vectors.json"), "utf8"));
      const hex = (s: string) => Uint8Array.from(Buffer.from(s, "hex"));
      const h = (u: Uint8Array) => Buffer.from(u).toString("hex");
      for (const v of vectors) {
        assert.strictEqual(h(ml_kem768_x25519.keygen(hex(v.seed)).publicKey), v.pk);
        const enc = ml_kem768_x25519.encapsulate(hex(v.pk), hex(v.eseed));
        assert.strictEqual(h(enc.cipherText), v.ct);
        assert.strictEqual(h(enc.sharedSecret), v.ss);
        assert.strictEqual(h(ml_kem768_x25519.decapsulate(hex(v.ct), hex(v.sk))), v.ss);
      }
    });
  });

  describe("channel", () => {
    it("carries messages both ways, with the same binding on both sides", async () => {
      const { initiator, responder } = await pairOfChannels();
      assert.ok(Buffer.from(initiator.binding).equals(Buffer.from(responder.binding)));
      await initiator.send(Buffer.from("ping"));
      assert.strictEqual((await responder.receive()).toString(), "ping");
      await responder.send(Buffer.from("pong"));
      assert.strictEqual((await initiator.receive()).toString(), "pong");
    });

    it("gives every session its own binding", async () => {
      const one = await pairOfChannels();
      const two = await pairOfChannels();
      assert.ok(!Buffer.from(one.initiator.binding).equals(Buffer.from(two.initiator.binding)));
    });

    it("refuses a replayed record", async () => {
      const { ta, initiator, responder } = await pairOfChannels();
      await initiator.send(Buffer.from("once"));
      await responder.receive();
      await ta.raw(ta.sent[ta.sent.length - 1]);
      await expectCode(responder.receive(), "INVALID_SEQUENCE");
    });

    it("refuses a dropped (skipped) record", async () => {
      const { ta, initiator, responder } = await pairOfChannels();
      let dropped = false;
      ta.setMutate((d) => {
        if (dropped) return d;
        dropped = true;
        return null;
      });
      await initiator.send(Buffer.from("dropped"));
      await initiator.send(Buffer.from("next"));
      await expectCode(responder.receive(), "INVALID_SEQUENCE");
    });

    it("refuses a reflected record", async () => {
      const { a, ta, initiator } = await pairOfChannels();
      await initiator.send(Buffer.from("to the responder"));
      // the attacker sends the initiator's own record back to it
      const reflected = ta.sent[ta.sent.length - 1];
      const tb = a.otherend!;
      await tb.send(reflected);
      await expectCode(initiator.receive(), "AUTH_FAILED");
    });

    it("refuses a tampered record and closes", async () => {
      const { ta, initiator, responder } = await pairOfChannels();
      ta.setMutate((d) => {
        d[d.length - 1] ^= 1;
        return d;
      });
      await initiator.send(Buffer.from("tampered"));
      await expectCode(responder.receive(), "AUTH_FAILED");
      await expectCode(responder.receive(), "CHANNEL_CLOSED");
    });

    it("refuses a malformed M1", async () => {
      const a = MemoryChannel.createBidirectionnal();
      const accepting = acceptXWingChannel(a.otherend!);
      await a.send(Buffer.alloc(10));
      await expectCode(accepting, "INVALID_FORMAT");
    });

    it("times out when the peer stays silent", async () => {
      const a = MemoryChannel.createBidirectionnal();
      await expectCode(initiateXWingChannel(a, { timeoutMs: 50 }), "TIMEOUT");
    });

    it("produces the published vectors", async () => {
      const onDisk = JSON.parse(readFileSync(VECTORS_PATH, "utf8"));
      assert.deepStrictEqual(JSON.parse(JSON.stringify(await buildVectors())), onDisk);
    });
  });

  describe("bound handshake", () => {
    it("authenticates both sides, binds channel and service, and keeps the channel", async () => {
      const user = await newManager();
      const service = await newManager(await VaultysId.generateOrganization());
      const a = MemoryChannel.createBidirectionnal();
      const [left, right] = await Promise.all([connectOverXWing(user, a, SERVICE), acceptOverXWing(service, a.otherend!, SERVICE)]);
      assert.strictEqual(left.contact.did, service.vaultysId.did);
      assert.strictEqual(right.contact.did, user.vaultysId.did);
      assert.strictEqual(user.contacts.length, 1);
      const [cert] = user.listCertificates();
      assert.strictEqual(cert.metadata.pk1[SERVICE_METADATA_KEY], SERVICE);
      assert.strictEqual(cert.metadata.pk2[SERVICE_METADATA_KEY], SERVICE);
      assert.strictEqual(cert.metadata.pk2[BINDING_METADATA_KEY], Buffer.from(left.channel.binding).toString("base64"));
      await left.channel.send(Buffer.from("after handshake"));
      assert.strictEqual((await right.channel.receive()).toString(), "after handshake");
    });

    it("refuses a different service, before anyone signs it", async () => {
      const user = await newManager();
      const service = await newManager();
      const a = MemoryChannel.createBidirectionnal();
      const results = await Promise.allSettled([connectOverXWing(user, a, SERVICE), acceptOverXWing(service, a.otherend!, "https://other.test")]);
      assert.ok(results[1].status === "rejected" && isChannelError(results[1].reason, "SERVICE_MISMATCH"));
      assert.strictEqual(user.contacts.length + service.contacts.length, 0);
    });

    it("refuses an unexpected peer", async () => {
      const user = await newManager();
      const service = await newManager();
      const someoneElse = await VaultysId.generateOrganization();
      const a = MemoryChannel.createBidirectionnal();
      const results = await Promise.allSettled([connectOverXWing(user, a, SERVICE, {}, { expectedPeer: someoneElse }), acceptOverXWing(service, a.otherend!, SERVICE)]);
      assert.ok(results[0].status === "rejected" && isChannelError(results[0].reason, "PEER_MISMATCH"));
      assert.strictEqual(user.contacts.length, 0);
    });

    it("accepts the expected peer", async () => {
      const user = await newManager();
      const service = await newManager();
      const a = MemoryChannel.createBidirectionnal();
      const [left] = await Promise.all([connectOverXWing(user, a, SERVICE, {}, { expectedPeer: VaultysId.fromId(service.vaultysId.id) }), acceptOverXWing(service, a.otherend!, SERVICE)]);
      assert.ok(Buffer.from(identityFingerprint(left.contact)).equals(Buffer.from(identityFingerprint(service.vaultysId))));
    });

    it("refuses a non-canonical service id and reserved metadata keys", async () => {
      const user = await newManager();
      await expectCode(connectOverXWing(user, MemoryChannel.createBidirectionnal(), "https://Service.test/"), "INVALID_SERVICE_ID");
      await expectCode(connectOverXWing(user, MemoryChannel.createBidirectionnal(), SERVICE, { [SERVICE_METADATA_KEY]: "x" }), "INVALID_ARGUMENT");
    });

    it("refuses a handshake relayed from another channel", async () => {
      // the attacker runs one channel with the user and another with the service, and relays the handshake
      const user = await newManager();
      const service = await newManager();
      const toUser = MemoryChannel.createBidirectionnal();
      const toService = MemoryChannel.createBidirectionnal();
      const attack = (async () => {
        const [withUser, withService] = await Promise.all([acceptXWingChannel(toUser.otherend!), initiateXWingChannel(toService)]);
        await withService.send(await withUser.receive());
        await withUser.send(await withService.receive());
      })();
      const results = await Promise.allSettled([connectOverXWing(user, toUser, SERVICE, {}, { timeoutMs: 2000 }), acceptOverXWing(service, toService.otherend!, SERVICE, {}, { timeoutMs: 2000 }), attack]);
      assert.ok(results[1].status === "rejected" && isChannelError(results[1].reason, "BINDING_MISMATCH"));
      assert.strictEqual(user.contacts.length + service.contacts.length, 0);
    });
  });

  describe("post-quantum peer required", () => {
    const hybrid = () => VaultysId.generatePerson("dilithium_ed25519");

    it("tells post-quantum signers apart", async () => {
      assert.strictEqual(isPostQuantumPeer(await hybrid()), true);
      assert.strictEqual(isPostQuantumPeer(await VaultysId.generateMachine("dilithium")), true);
      assert.strictEqual(isPostQuantumPeer(await VaultysId.generatePerson("dilithium_ed25519", true)), true);
      assert.strictEqual(isPostQuantumPeer(await VaultysId.generatePerson()), false);
      // public copies (as received in a challenge) keep their key manager type
      assert.strictEqual(isPostQuantumPeer(VaultysId.fromId((await hybrid()).id)), true);
    });

    it("accepts hybrid identities on both sides", async () => {
      const user = await newManager(await hybrid());
      const service = await newManager(await VaultysId.generateOrganization("dilithium_ed25519"));
      const a = MemoryChannel.createBidirectionnal();
      const [left, right] = await Promise.all([connectOverXWing(user, a, SERVICE, {}, { requirePostQuantumPeer: true }), acceptOverXWing(service, a.otherend!, SERVICE, {}, { requirePostQuantumPeer: true })]);
      assert.strictEqual(left.contact.did, service.vaultysId.did);
      assert.strictEqual(right.contact.did, user.vaultysId.did);
      assert.ok(isPostQuantumPeer(left.contact) && isPostQuantumPeer(right.contact));
      await left.channel.send(Buffer.from("pq"));
      assert.strictEqual((await right.channel.receive()).toString(), "pq");
    });

    it("accepts a Dilithium peer", async () => {
      const user = await newManager(await hybrid());
      const service = await newManager(await VaultysId.generateOrganization("dilithium"));
      const a = MemoryChannel.createBidirectionnal();
      const [left] = await Promise.all([connectOverXWing(user, a, SERVICE, {}, { requirePostQuantumPeer: true }), acceptOverXWing(service, a.otherend!, SERVICE)]);
      assert.strictEqual(left.contact.did, service.vaultysId.did);
    });

    it("initiator: refuses an Ed25519 responder before signing COMPLETE", async () => {
      const user = await newManager(await hybrid());
      const service = await newManager(await VaultysId.generateOrganization());
      const signed = countHandshakeSignatures(user.vaultysId);
      const a = MemoryChannel.createBidirectionnal();
      const results = await Promise.allSettled([connectOverXWing(user, a, SERVICE, {}, { requirePostQuantumPeer: true, timeoutMs: 2000 }), acceptOverXWing(service, a.otherend!, SERVICE, {}, { timeoutMs: 2000 })]);
      assert.ok(results[0].status === "rejected" && isChannelError(results[0].reason, "PEER_NOT_PQ"), String(results[0].status === "rejected" && results[0].reason));
      assert.strictEqual(results[1].status, "rejected");
      assert.strictEqual(signed(), 0);
      assert.strictEqual(user.contacts.length + service.contacts.length, 0);
    });

    it("responder: refuses an Ed25519 initiator before signing STEP1", async () => {
      const user = await newManager();
      const service = await newManager(await VaultysId.generateOrganization("dilithium_ed25519"));
      const signed = countHandshakeSignatures(service.vaultysId);
      const a = MemoryChannel.createBidirectionnal();
      const results = await Promise.allSettled([connectOverXWing(user, a, SERVICE, {}, { timeoutMs: 2000 }), acceptOverXWing(service, a.otherend!, SERVICE, {}, { requirePostQuantumPeer: true, timeoutMs: 2000 })]);
      assert.ok(results[1].status === "rejected" && isChannelError(results[1].reason, "PEER_NOT_PQ"), String(results[1].status === "rejected" && results[1].reason));
      assert.strictEqual(results[0].status, "rejected");
      assert.strictEqual(signed(), 0);
      assert.strictEqual(user.contacts.length + service.contacts.length, 0);
    });

    it("is off by default and refuses a non-boolean value", async () => {
      const user = await newManager();
      const service = await newManager(await hybrid());
      const a = MemoryChannel.createBidirectionnal();
      const [left] = await Promise.all([connectOverXWing(user, a, SERVICE), acceptOverXWing(service, a.otherend!, SERVICE)]);
      assert.strictEqual(left.contact.did, service.vaultysId.did);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await expectCode(connectOverXWing(user, MemoryChannel.createBidirectionnal(), SERVICE, {}, { requirePostQuantumPeer: "yes" as any }), "INVALID_ARGUMENT");
    });
  });

  describe("certificateKey", () => {
    it("keeps two certificates of the same millisecond apart", () => {
      const now = 1700000000000;
      assert.notStrictEqual(certificateKey(Buffer.from("a"), now), certificateKey(Buffer.from("b"), now));
      assert.ok(certificateKey(Buffer.from("a"), now).startsWith(`${now}-`));
    });
  });
});
