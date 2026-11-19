import assert from "assert";
import { Buffer } from "buffer/";
import * as v3 from "@vaultys/id_3";
import { Challenger, IdManager, MemoryStorage, VaultysId } from "../";

/**
 * Wallets written by the published @vaultys/id 3.0.4, opened with 4.0: stores and backups are migrated, the v0
 * certificates they already hold stay trusted (and only those), old DHIES messages open as "sender not verified".
 */

type V3Manager = InstanceType<typeof v3.IdManager>;

const newWallet3 = async (alg: "ed25519" | "dilithium_ed25519" = "ed25519", type = 1, entropy?: Buffer) => {
  const vid = await v3.VaultysId.fromEntropy((entropy ?? Buffer.from(v3.crypto.randomBytes(32))) as never, type, alg);
  return new v3.IdManager(
    vid,
    v3.MemoryStorage(() => {}),
  );
};

const connect3 = async (a: V3Manager, b: V3Manager) => {
  const channel = v3.MemoryChannel.createBidirectionnal();
  await Promise.all([a.askContact(channel), b.acceptContact(channel.otherend!)]);
};

/** The store a 3.x app would have persisted, as 4.0 reads it back. */
const reopen = (m: V3Manager | IdManager) =>
  MemoryStorage().fromString(
    m.store.toString(),
    () => {},
    () => {},
  );

describe("3.x wallets in 4.0", function () {
  this.timeout(60000);
  let alice3: V3Manager, bob3: V3Manager, carol3: V3Manager, dave3: V3Manager;
  before(async () => {
    alice3 = await newWallet3("ed25519", 1);
    bob3 = await newWallet3("ed25519", 1);
    carol3 = await newWallet3("dilithium_ed25519", 1);
    dave3 = await newWallet3("ed25519", 0);
    alice3.name = "Alice";
    await connect3(alice3, bob3);
    await connect3(alice3, carol3);
    await connect3(dave3, alice3);
  });

  it("fromStore refuses a 3.x store and points to fromLegacyStore", async () => {
    await assert.rejects(IdManager.fromStore(reopen(alice3)), /fromLegacyStore/);
  });

  it("migrates a 3.x store: same DID, secret persisted, contacts and web of trust still verify", async () => {
    const store = reopen(alice3);
    const alice = await IdManager.fromLegacyStore(store);
    assert.equal(alice.vaultysId.did, alice3.vaultysId.did);
    assert.equal(alice.name, "Alice");
    assert.ok(store.get("secret"));
    assert.equal(store.get("entropy"), undefined);
    // bob and carol are contacts; 3.x saved dave, a machine, as a registered app. The web-of-trust entries are the
    // same three certificates.
    assert.equal(Object.keys(store.get("legacy").certificates).length, 3);
    assert.equal(alice.contacts.length, 2);
    assert.equal(alice.apps.length, 1);
    for (const peer of [...alice.contacts, ...alice.apps]) assert.equal(await alice.verifyRelationshipCertificate(peer.did), true, peer.did);
    assert.equal(await alice.verifyWebOfTrust(), true);
    assert.deepEqual(alice.legacyContacts().sort(), [bob3.vaultysId.did, carol3.vaultysId.did].sort());

    // once migrated, the store reopens as a plain 4.0 store
    const again = await IdManager.fromStore(reopen(alice));
    assert.equal(again.vaultysId.did, alice3.vaultysId.did);
    assert.equal(await again.verifyWebOfTrust(), true);
  });

  it("recovers the type and algorithm from the certificates (hybrid person, ed25519 machine)", async () => {
    const carol = await IdManager.fromLegacyStore(reopen(carol3));
    assert.equal(carol.vaultysId.did, carol3.vaultysId.did);
    assert.equal(await carol.verifyWebOfTrust(), true);
    const dave = await IdManager.fromLegacyStore(reopen(dave3));
    assert.equal(dave.vaultysId.did, dave3.vaultysId.did);
    assert.equal(dave.vaultysId.type, 0);
  });

  it("needs the type and algorithm for a store without certificates, and refuses a wrong one", async () => {
    const lonely3 = await newWallet3("dilithium_ed25519", 2);
    await assert.rejects(IdManager.fromLegacyStore(reopen(lonely3)), /type and algorithm/);
    const lonely = await IdManager.fromLegacyStore(reopen(lonely3), { type: 2, alg: "dilithium_ed25519" });
    assert.equal(lonely.vaultysId.did, lonely3.vaultysId.did);
    await assert.rejects(IdManager.fromLegacyStore(reopen(alice3), { type: 2, alg: "ed25519" }), /does not match/);
  });

  it("trusts only the v0 certificates present at migration", async () => {
    const before = reopen(alice3);
    const eve3 = await newWallet3();
    await connect3(alice3, eve3); // a genuine v0 certificate, made after the snapshot
    const alice = await IdManager.fromLegacyStore(before);
    const eveEntry = reopen(alice3).substore("contacts").get(eve3.vaultysId.did);
    alice.store.substore("contacts").set(eve3.vaultysId.did, eveEntry);
    assert.equal(await alice.verifyRelationshipCertificate(eve3.vaultysId.did), false);
    assert.equal(await alice.verifyWebOfTrust(), false);
    // and a v0 certificate is never valid on its own
    assert.equal(await Challenger.verifyCertificate(Buffer.from(eveEntry.certificate)), false);
  });

  it("refuses a recorded certificate whose bytes were changed", async () => {
    const alice = await IdManager.fromLegacyStore(reopen(alice3));
    const did = bob3.vaultysId.did;
    const entry = alice.store.substore("contacts").get(did);
    const tampered = Buffer.from(entry.certificate);
    tampered[tampered.length - 1] ^= 1;
    alice.store.substore("contacts").set(did, { ...entry, certificate: tampered });
    assert.equal(await alice.verifyRelationshipCertificate(did), false);
  });

  it("imports a 3.x backup only when asked to migrate it", async () => {
    const backup = await alice3.exportBackup("phrase de passe");
    assert.equal(await IdManager.importBackup(backup, "phrase de passe"), null);
    const alice = await IdManager.importBackup(backup, "phrase de passe", true);
    assert.ok(alice);
    assert.equal(alice.vaultysId.did, alice3.vaultysId.did);
    assert.equal(await alice.verifyWebOfTrust(), true);
  });

  it("opens 3.x DHIES messages as sender-not-verified, and only for the right keys", async () => {
    const message = await alice3.vaultysId.dhiesEncrypt("ancien message", bob3.vaultysId.id);
    const bob = await IdManager.fromLegacyStore(reopen(bob3));
    const aliceId = Buffer.from(alice3.vaultysId.id);
    assert.equal(await bob.vaultysId.dhiesDecrypt(Buffer.from(message!), aliceId), null);
    const opened = await bob.vaultysId.dhiesDecryptLegacyV1(Buffer.from(message!), aliceId);
    assert.ok(opened);
    assert.equal(opened.plaintext.toString(), "ancien message");
    assert.equal(opened.senderVerified, false);
    assert.equal(await bob.vaultysId.dhiesDecryptLegacyV1(Buffer.from(message!), Buffer.from(carol3.vaultysId.id)), null);
    const carol = await IdManager.fromLegacyStore(reopen(carol3));
    assert.equal(await carol.vaultysId.dhiesDecryptLegacyV1(Buffer.from(message!), aliceId), null);
  });

  it("keeps verifying 3.x file signatures and opening 3.x saltpack messages", async () => {
    const file = { arrayBuffer: Buffer.from("signé en 3.x"), type: "text/plain" };
    const signature = await alice3.signFile(file as never);
    const alice = await IdManager.fromLegacyStore(reopen(alice3));
    const signer = VaultysId.fromId(Buffer.from(alice3.vaultysId.id));
    assert.equal(alice.verifyFile(file, { challenge: Buffer.from(signature.challenge), signature: Buffer.from(signature.signature) }, signer), true);
    const sealed = await alice3.vaultysId.encrypt("saltpack 3.x", [bob3.vaultysId.id]);
    const bob = await IdManager.fromLegacyStore(reopen(bob3));
    assert.equal(await bob.vaultysId.decrypt(sealed), "saltpack 3.x");
  });
});
