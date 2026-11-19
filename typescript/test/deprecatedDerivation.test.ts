import assert from "assert";
import { Buffer } from "buffer/";
import { KeyManager as KeyManagerV2 } from "@vaultys/id_2";
import DeprecatedKeyManager from "../src/KeyManager/DeprecatedKeyManager";

/**
 * Old wallets re-derive their keys from the stored entropy (swapIndex rotation in
 * DeprecatedKeyManager). The derivation path "/0'" calls derive(NaN) on the first
 * segment, which @stricahq/bip32ed25519 1.x treats as a hardened index 0 and 2.x
 * refuses. These keys must stay byte-identical to the published 2.4.10 package, so
 * bumping that library must make this test fail rather than silently change keys.
 */
describe("Deprecated (bip32-ed25519) derivation", () => {
  const entropies = [Buffer.alloc(32, 0), Buffer.alloc(32, 0xab), Buffer.from("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "hex")];

  for (const [n, entropy] of entropies.entries()) {
    for (const swapIndex of [0, 1, 7]) {
      it(`matches @vaultys/id 2.4.10 (entropy ${n}, swapIndex ${swapIndex})`, async () => {
        const current = await DeprecatedKeyManager.create_Id25519_fromEntropy(Buffer.from(entropy), swapIndex);
        const legacy = await KeyManagerV2.create_Id25519_fromEntropy(Buffer.from(entropy) as never, swapIndex);
        assert.equal(Buffer.from(current.signer.publicKey).toString("hex"), Buffer.from(legacy.signer.publicKey).toString("hex"));
        assert.equal(Buffer.from(current.signer.secretKey!).toString("hex"), Buffer.from(legacy.signer.secretKey!).toString("hex"));
        assert.equal(Buffer.from(current.proofKey.publicKey).toString("hex"), Buffer.from(legacy.proofKey.publicKey).toString("hex"));
        assert.equal(Buffer.from(current.cypher.publicKey).toString("hex"), Buffer.from(legacy.cypher.publicKey).toString("hex"));
      });
    }
  }

  it("creates a swapping certificate that verifies, and rejects a tampered one", async () => {
    const km = await DeprecatedKeyManager.create_Id25519_fromEntropy(Buffer.alloc(32, 0x42));
    const hiscp = await km.createSwapingCertificate();
    assert.ok(hiscp);
    const next = await DeprecatedKeyManager.create_Id25519_fromEntropy(Buffer.alloc(32, 0x42), 1);
    assert.equal(hiscp.newId.toString("hex"), next.id.toString("hex"));
    assert.equal(await km.verifySwapingCertificate(hiscp), true);
    assert.equal(await km.verifySwapingCertificate({ ...hiscp, timestamp: hiscp.timestamp + 1 }), false);
  });
});
