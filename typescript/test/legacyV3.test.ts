import assert from "assert";
import { Buffer } from "buffer/";
import * as v3 from "@vaultys/id_3";
import { encode } from "@msgpack/msgpack";
import SoftCredentials from "../src/platform/SoftCredentials";
import "./shims";
import vectors from "./interops/legacy-v3-vectors.json";
import { verifyV0CertificateSignatures } from "../src/legacyV3";
import { Challenger, IdManager, LEGACY_REOPEN_DEFAULT, MemoryChannel, MemoryStorage, VaultysId } from "../";

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

  it("imports a 3.x backup as is, unless told not to", async () => {
    const backup = await alice3.exportBackup("phrase de passe");
    assert.equal(await IdManager.importBackup(backup, "phrase de passe", false), null);
    for (const legacy of [undefined, true] as const) {
      const alice = await IdManager.importBackup(backup, "phrase de passe", legacy);
      assert.ok(alice);
      assert.equal(alice.vaultysId.did, alice3.vaultysId.did);
      assert.equal(await alice.verifyWebOfTrust(), true);
    }
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

  describe("opened with nothing to ask (IdManager.open)", () => {
    it("migrates a 3.x store once, with its contacts, and reopens it as it was left", async () => {
      const store = reopen(alice3);
      const alice = await IdManager.open(store);
      assert.equal(alice.vaultysId.did, alice3.vaultysId.did);
      assert.equal(alice.isLegacyIdentityGuessed(), false);
      assert.equal(store.get("entropy"), undefined);
      assert.equal(await alice.verifyWebOfTrust(), true);
      const migratedAt = store.get("legacy").migratedAt;
      const again = await IdManager.open(store);
      assert.equal(again.vaultysId.did, alice3.vaultysId.did);
      assert.equal(store.get("legacy").migratedAt, migratedAt);
      const later = await IdManager.open(reopen(alice));
      assert.equal(later.vaultysId.did, alice3.vaultysId.did);
      assert.equal(await later.verifyWebOfTrust(), true);
    });

    it("finishes a migration interrupted after the secret was written", async () => {
      const store = reopen(alice3);
      const alice = await IdManager.fromLegacyStore(store);
      store.set("entropy", reopen(alice3).get("entropy"));
      const reopened = await IdManager.open(store);
      assert.equal(reopened.vaultysId.did, alice.vaultysId.did);
      assert.equal(store.get("entropy"), undefined);
    });

    it("opens a store without certificates as 3.x reopened it, keeps its entropy and lets it be corrected", async () => {
      const lonely3 = await newWallet3("dilithium_ed25519", 1);
      // what 3.x itself made of this store after a restart
      const reopened3 = await v3.IdManager.fromStore(v3.MemoryStorage(() => {}).fromString(lonely3.store.toString()));
      const store = reopen(lonely3);
      const lonely = await IdManager.open(store);
      assert.equal(lonely.vaultysId.did, reopened3.vaultysId.did);
      assert.deepEqual({ type: lonely.vaultysId.type, alg: "ed25519" }, LEGACY_REOPEN_DEFAULT);
      assert.equal(lonely.isLegacyIdentityGuessed(), true);
      assert.ok(store.get("entropy"));
      assert.equal((await IdManager.open(store)).vaultysId.did, reopened3.vaultysId.did);

      // the app knew better: corrected to the identity it created
      const corrected = await IdManager.fromLegacyStore(store, { type: 1, alg: "dilithium_ed25519" });
      assert.equal(corrected.vaultysId.did, lonely3.vaultysId.did);
      assert.equal(corrected.isLegacyIdentityGuessed(), false);
      assert.equal(store.get("entropy"), undefined);
      assert.equal((await IdManager.open(store)).vaultysId.did, lonely3.vaultysId.did);
    });

    it("takes the app's own default for a store without certificates, and confirms it", async () => {
      const lonely3 = await newWallet3("dilithium_ed25519", 1);
      const store = reopen(lonely3);
      const lonely = await IdManager.open(store, { legacyFallback: { type: 1, alg: "dilithium_ed25519" } });
      assert.equal(lonely.vaultysId.did, lonely3.vaultysId.did);
      assert.equal(lonely.isLegacyIdentityGuessed(), true);
      lonely.confirmLegacyIdentity();
      assert.equal(lonely.isLegacyIdentityGuessed(), false);
      assert.equal(store.get("entropy"), undefined);
      // once confirmed, no hint changes it any more
      assert.equal((await IdManager.fromLegacyStore(store, { type: 0, alg: "ed25519" })).vaultysId.did, lonely3.vaultysId.did);
    });

    it("ignores the fallback when the certificates tell the identity", async () => {
      const carol = await IdManager.open(reopen(carol3), { legacyFallback: { type: 0, alg: "ed25519" } });
      assert.equal(carol.vaultysId.did, carol3.vaultysId.did);
      assert.equal(carol.isLegacyIdentityGuessed(), false);
    });
  });

  describe("contacts brought to 4.0 by a new handshake", () => {
    const handshake = async (a: IdManager, b: IdManager) => {
      const channel = MemoryChannel.createBidirectionnal();
      await Promise.all([a.askContact(channel), b.acceptContact(channel.otherend!)]);
    };

    it("replaces the v0 certificate of the same contact, on both sides, and keeps its metadata", async () => {
      const alice = await IdManager.open(reopen(alice3));
      const bob = await IdManager.open(reopen(bob3));
      alice.setContactMetadata(bob.vaultysId.did, "surnom", "Bobby");
      assert.ok(alice.legacyContacts().includes(bob.vaultysId.did));
      const count = alice.contacts.length;
      await handshake(bob, alice);
      assert.ok(!alice.legacyContacts().includes(bob.vaultysId.did));
      assert.ok(!bob.legacyContacts().includes(alice.vaultysId.did));
      assert.equal(alice.contacts.length, count);
      assert.equal(alice.getContactMetadata(bob.vaultysId.did, "surnom"), "Bobby");
      const certificate = alice.store.substore("contacts").get(bob.vaultysId.did).certificate;
      assert.equal(await Challenger.verifyCertificate(Buffer.from(certificate)), true);
      assert.equal(await alice.verifyRelationshipCertificate(bob.vaultysId.did), true);
      assert.equal(await alice.verifyWebOfTrust(), true);
      assert.equal(await bob.verifyWebOfTrust(), true);
    });

    it("brings a registered app (a 3.x machine) to 4.0 the same way", async () => {
      const alice = await IdManager.open(reopen(alice3));
      const dave = await IdManager.open(reopen(dave3));
      assert.deepEqual(alice.legacyApps(), [dave.vaultysId.did]);
      await handshake(dave, alice);
      assert.deepEqual(alice.legacyApps(), []);
      assert.equal(await alice.verifyRelationshipCertificate(dave.vaultysId.did), true);
      assert.equal(await alice.verifyWebOfTrust(), true);
    });

    it("never replaces a 4.0 certificate", async () => {
      const alice = await IdManager.open(reopen(alice3));
      const bob = await IdManager.open(reopen(bob3));
      await handshake(bob, alice);
      const first = Buffer.from(alice.store.substore("contacts").get(bob.vaultysId.did).certificate);
      await handshake(bob, alice);
      assert.ok(first.equals(Buffer.from(alice.store.substore("contacts").get(bob.vaultysId.did).certificate)));
    });
  });

  it("recognizes a 3.x FIDO2 wallet, whose store lacks the credential id, instead of opening another identity", async () => {
    const attestation = await navigator.credentials.create(SoftCredentials.createRequest(-7, false));
    // @ts-expect-error SoftCredentials mockup
    const key3 = await v3.VaultysId.fido2FromAttestation(attestation);
    const fido3 = new v3.IdManager(
      key3!,
      v3.MemoryStorage(() => {}),
    );
    assert.deepEqual(Object.keys(JSON.parse(fido3.store.toString())).sort(), ["entropy", "metadata"]);
    // 3.x's own software authenticator no longer runs here, so no 3.x handshake: a v0 certificate between this
    // identity and a contact, built with the 3.x layout (detection reads it, it does not check its signatures)
    const peer = await newWallet3();
    const certificate = Buffer.from(encode({ protocol: "p2p", service: "auth", timestamp: Date.now(), pk1: Buffer.from(key3!.toVersion(0).id), pk2: Buffer.from(peer.vaultysId.toVersion(0).id), nonce: Buffer.alloc(32, 7), sign1: Buffer.alloc(64), sign2: Buffer.alloc(64), metadata: {} }));
    const store = reopen(fido3);
    store.substore("contacts").set(peer.vaultysId.did, { certificate });
    await assert.rejects(IdManager.open(store), /FIDO2 wallet/);
    assert.ok(store.get("entropy"));
    assert.equal(store.get("secret"), undefined);
  });

  describe("frozen 3.0.4 wallets (test/interops/legacy-v3-vectors.json, also read by Go)", () => {
    const open = (name: string) => {
      const w = vectors.wallets.find((x) => x.name === name)!;
      return IdManager.open(
        MemoryStorage().fromString(
          w.store,
          () => {},
          () => {},
        ),
      );
    };

    it("opens every wallet with nothing to ask, as the same identity", async () => {
      for (const w of vectors.wallets) {
        const m = await open(w.name);
        if (w.certificates.length === 0) {
          assert.equal(m.vaultysId.did, vectors.lonelyReopenedDid, w.name);
          assert.equal(m.isLegacyIdentityGuessed(), true, w.name);
        } else {
          assert.equal(m.vaultysId.did, w.did, w.name);
          assert.equal(m.isLegacyIdentityGuessed(), false, w.name);
          assert.equal(await m.verifyWebOfTrust(), true, w.name);
        }
      }
    });

    it("verifies their v0 certificates with the 3.x rules, and not a tampered one", () => {
      for (const w of vectors.wallets) for (const c of w.certificates) assert.equal(verifyV0CertificateSignatures(Buffer.from(c, "hex")), true, w.name);
      assert.equal(verifyV0CertificateSignatures(Buffer.from(vectors.tamperedCertificate, "hex")), false);
    });

    it("opens their DHIES v1 message, sender not verified", async () => {
      const bob = await open(vectors.dhiesV1.to);
      const opened = await bob.vaultysId.dhiesDecryptLegacyV1(Buffer.from(vectors.dhiesV1.message, "hex"), Buffer.from(vectors.dhiesV1.senderId, "hex"));
      assert.equal(opened?.plaintext.toString(), vectors.dhiesV1.plaintext);
      assert.equal(opened?.senderVerified, false);
    });
  });
});
