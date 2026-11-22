import assert from "assert";
import { Buffer } from "buffer/";
import { ContactError, IdManager, isContactError, isChannelError, MemoryChannel, MemoryStorage, VaultysId } from "..";
import "./shims";
import { isPostQuantumPeer } from "../src/postQuantumPeer";

// rfc/PROTOCOL.md §12.1: askContact / acceptContact with `requirePostQuantumPeer` refuse a peer that does not sign
// with ML-DSA (Dilithium or hybrid), with ContactError PEER_NOT_PQ, before this side signs anything.

const newManager = (identity: VaultysId) =>
  new IdManager(
    identity,
    MemoryStorage(() => ""),
  );
const hybrid = () => VaultysId.generatePerson("dilithium_ed25519");
const required = { requirePostQuantumPeer: true };

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

/** Records what a side sends on a MemoryChannel. */
function recordSent(channel: MemoryChannel): Buffer[] {
  const sent: Buffer[] = [];
  channel.setLogger((data) => sent.push(Buffer.from(data)));
  return sent;
}

describe("Contacts: post-quantum peer required", () => {
  it("accepts hybrid identities on both sides", async () => {
    const m1 = newManager(await hybrid());
    const m2 = newManager(await VaultysId.generateOrganization("dilithium_ed25519"));
    const channel = MemoryChannel.createBidirectionnal();
    const [c1, c2] = await Promise.all([m1.askContact(channel, { name: "a" }, undefined, required), m2.acceptContact(channel.otherend!, { name: "b" }, undefined, required)]);
    assert.strictEqual(c1.did, m2.vaultysId.did);
    assert.strictEqual(c2.did, m1.vaultysId.did);
    assert.ok(isPostQuantumPeer(c1) && isPostQuantumPeer(c2));
    assert.strictEqual(m1.contacts.length + m2.contacts.length, 2);
  });

  it("accepts a Dilithium peer and post-quantum types (0x10 | role)", async () => {
    const m1 = newManager(await VaultysId.generatePerson("dilithium_ed25519", true));
    const m2 = newManager(await VaultysId.generatePerson("dilithium"));
    const channel = MemoryChannel.createBidirectionnal();
    const [c1, c2] = await Promise.all([m1.askContact(channel, {}, undefined, required), m2.acceptContact(channel.otherend!, {}, undefined, required)]);
    assert.strictEqual(c1.did, m2.vaultysId.did);
    assert.strictEqual(c2.did, m1.vaultysId.did);
  });

  it("initiator: refuses an Ed25519 responder before signing COMPLETE", async () => {
    const m1 = newManager(await hybrid());
    const m2 = newManager(await VaultysId.generatePerson());
    const signed = countHandshakeSignatures(m1.vaultysId);
    const channel = MemoryChannel.createBidirectionnal();
    const sent = recordSent(channel);
    const results = await Promise.allSettled([m1.askContact(channel, {}, undefined, required), m2.acceptContact(channel.otherend!, {})]);
    assert.ok(results[0].status === "rejected" && isContactError(results[0].reason, "PEER_NOT_PQ"), String(results[0].status === "rejected" && results[0].reason));
    assert.strictEqual(results[1].status, "rejected");
    assert.strictEqual(signed(), 0);
    // INIT, then only refusal bytes: no COMPLETE left this side
    assert.ok(sent.length >= 2 && sent.slice(1).every((m) => m.length === 1 && m[0] === 0), String(sent.map((m) => m.length)));
    assert.strictEqual(m1.contacts.length + m2.contacts.length, 0);
  });

  it("responder: refuses an Ed25519 initiator before signing STEP1, without calling the consent callback", async () => {
    const m1 = newManager(await VaultysId.generatePerson());
    const m2 = newManager(await hybrid());
    const signed = countHandshakeSignatures(m2.vaultysId);
    const channel = MemoryChannel.createBidirectionnal();
    const sent = recordSent(channel.otherend!);
    let asked = false;
    const consent = async () => (asked = true);
    const results = await Promise.allSettled([m1.askContact(channel, {}), m2.acceptContact(channel.otherend!, {}, consent, required)]);
    assert.ok(results[1].status === "rejected" && isContactError(results[1].reason, "PEER_NOT_PQ"), String(results[1].status === "rejected" && results[1].reason));
    assert.ok(results[1].reason instanceof ContactError && !isChannelError(results[1].reason));
    assert.strictEqual(results[0].status, "rejected");
    assert.strictEqual(signed(), 0);
    assert.strictEqual(asked, false);
    assert.ok(sent.length >= 1 && sent.every((m) => m.length === 1 && m[0] === 0), String(sent.map((m) => m.length)));
    assert.strictEqual(m1.contacts.length + m2.contacts.length, 0);
  });

  it("still asks the caller's consent after the post-quantum check", async () => {
    const m1 = newManager(await hybrid());
    const m2 = newManager(await hybrid());
    const channel = MemoryChannel.createBidirectionnal();
    const results = await Promise.allSettled([m1.askContact(channel, {}, async () => false, required), m2.acceptContact(channel.otherend!, {})]);
    assert.ok(results[0].status === "rejected" && !isContactError(results[0].reason));
    assert.strictEqual(m1.contacts.length, 0);
  });

  it("is off by default and refuses a non-boolean value", async () => {
    const m1 = newManager(await VaultysId.generatePerson());
    const m2 = newManager(await hybrid());
    const channel = MemoryChannel.createBidirectionnal();
    const [c1] = await Promise.all([m1.askContact(channel), m2.acceptContact(channel.otherend!)]);
    assert.strictEqual(c1.did, m2.vaultysId.did);
    const unused = MemoryChannel.createBidirectionnal();
    const sent = recordSent(unused);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await assert.rejects(m1.askContact(unused, {}, undefined, { requirePostQuantumPeer: "yes" as any }), (e) => isContactError(e, "INVALID_ARGUMENT"));
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await assert.rejects(m1.acceptContact(unused, {}, undefined, null as any), (e) => isContactError(e, "INVALID_ARGUMENT"));
    assert.strictEqual(sent.length, 0);
  });
});
