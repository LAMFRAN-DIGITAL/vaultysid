// Deterministic test vectors for service anchors (rfc/SERVICE-IDENTITIES.md §8).
// Run: pnpm test:anchor:vectors (from typescript/). Ed25519 signatures are deterministic, so anchors are fixed bytes.
// Hybrid (dilithium_ed25519) anchors: the key manager signs with hedged ML-DSA-87; here its signer is replaced by the
// deterministic variant of FIPS 204 (rnd = 0), same construction sig_ed25519 || ML-DSA-87(data || sig_ed25519), so
// that the file is reproducible. Both variants verify identically.

import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { Buffer } from "buffer/";
import { ed25519 } from "@noble/curves/ed25519.js";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import HybridManager from "../../src/KeyManager/HybridManager";
import type VaultysId from "../../src/VaultysId";
import { createServiceAnchor, verifyServiceAnchor } from "../../src/serviceAnchor";
import { deriveServiceIdentity } from "../../src/serviceIdentity";
import { testMaster } from "./generate-service-identity-vectors";

const hex = (u: Uint8Array) => Buffer.from(u).toString("hex");

/** Makes a hybrid identity sign with deterministic ML-DSA-87 (test vectors only). */
function deterministicHybridSigner(identity: VaultysId): VaultysId {
  const km = identity.keyManager;
  if (!(km instanceof HybridManager) || !km.edSigner?.secretKey || !km.pqSigner?.secretKey) throw new Error("not a private hybrid identity");
  const edSecret = km.edSigner.secretKey;
  const pqSecret = km.pqSigner.secretKey;
  km.getSigner = () =>
    Promise.resolve({
      sign: (data: Buffer) => {
        const edSignature = Buffer.from(ed25519.sign(data, edSecret));
        return Promise.resolve(Buffer.concat([edSignature, Buffer.from(ml_dsa87.sign(Buffer.concat([data, edSignature]), pqSecret, { extraEntropy: false }))]));
      },
    });
  return identity;
}

export async function buildVectors() {
  const masterName = "anchors/service";
  const master = testMaster(masterName);
  const valid = [];
  for (const serviceId of ["https://service-a.test", "https://xn--srvice-a-c8g.test"]) {
    const identity = await deriveServiceIdentity(master, serviceId, { role: "organization" });
    const anchor = await createServiceAnchor(identity, serviceId);
    valid.push({ serviceId, did: identity.did, anchor: hex(anchor) });
  }
  const a = Buffer.from(valid[0].anchor, "hex");
  const flip = (i: number) => {
    const b = Buffer.from(a);
    b[i] ^= 1;
    return hex(b);
  };
  const invalid = [
    { name: "fetched from another origin", serviceId: "https://service-b.test", anchor: valid[0].anchor },
    { name: "version byte", serviceId: valid[0].serviceId, anchor: flip(0) },
    { name: "algorithm byte", serviceId: valid[0].serviceId, anchor: flip(1) },
    { name: "signature altered", serviceId: valid[0].serviceId, anchor: flip(a.length - 1) },
    { name: "trailing byte", serviceId: valid[0].serviceId, anchor: hex(Buffer.concat([a, Buffer.from([0])])) },
    { name: "truncated", serviceId: valid[0].serviceId, anchor: hex(a.subarray(0, a.length - 1)) },
    { name: "empty", serviceId: valid[0].serviceId, anchor: "" },
  ];
  // Hybrid service identities: deriveServiceIdentity(master, serviceId, {alg: "dilithium_ed25519", role: "organization"}),
  // with the classical type (0x02) and the post-quantum one (0x12).
  const hybridValid = [];
  for (const postQuantum of [false, true]) {
    const serviceId = "https://service-a.test";
    const identity = deterministicHybridSigner(await deriveServiceIdentity(master, serviceId, { alg: "dilithium_ed25519", role: "organization", postQuantum }));
    const anchor = await createServiceAnchor(identity, serviceId);
    const signatureLength = new DataView(anchor.buffer, anchor.byteOffset + anchor.length - 64 - 4627 - 2, 2).getUint16(0, false);
    if (signatureLength !== 64 + 4627 || verifyServiceAnchor(anchor, serviceId)?.did !== identity.did) throw new Error("hybrid anchor does not verify");
    hybridValid.push({ serviceId, postQuantum, type: identity.type, did: identity.did, idSha256: createHash("sha256").update(identity.id).digest("hex"), signatureLength, anchor: hex(anchor) });
  }
  const h = Buffer.from(hybridValid[0].anchor, "hex");
  const signatureStart = h.length - (64 + 4627);
  const flipH = (i: number) => {
    const b = Buffer.from(h);
    b[i] ^= 1;
    return hex(b);
  };
  // the same anchor with its signature reduced to the Ed25519 half (length field rewritten): a downgrade
  const edOnly = Buffer.concat([h.subarray(0, signatureStart - 2), Buffer.from([0x00, 64]), h.subarray(signatureStart, signatureStart + 64)]);
  const hybridInvalid = [
    { name: "Ed25519 half altered", serviceId: hybridValid[0].serviceId, anchor: flipH(signatureStart + 3) },
    { name: "ML-DSA half altered", serviceId: hybridValid[0].serviceId, anchor: flipH(h.length - 1) },
    { name: "signature reduced to its Ed25519 half", serviceId: hybridValid[0].serviceId, anchor: hex(edOnly) },
    { name: "fetched from another origin", serviceId: "https://service-b.test", anchor: hybridValid[0].anchor },
  ];
  for (const v of hybridInvalid) if (verifyServiceAnchor(Buffer.from(v.anchor, "hex"), v.serviceId) !== null) throw new Error("invalid hybrid anchor accepted: " + v.name);

  return {
    description: 'rfc/SERVICE-IDENTITIES.md §8: service anchors. Identities = deriveServiceIdentity(master, serviceId, {role: organization}), master = SHA-256("vaultysid/test/" || masterName), a PUBLIC test value. valid: verifyServiceAnchor(anchor, serviceId) returns the identity with this DID. invalid: it returns null.',
    testValuesArePublic: true,
    masterName,
    valid,
    invalid,
    hybrid: {
      description: 'Anchors of hybrid service identities: deriveServiceIdentity(master, serviceId, {alg: "dilithium_ed25519", role: "organization", postQuantum}), same master. ML-DSA-87 half signed with the deterministic variant of FIPS 204 (rnd = 0). valid: verifyServiceAnchor returns the identity with this DID, and the derived identity has this DID and SHA-256 of its serialized id. invalid: verifyServiceAnchor returns null.',
      alg: "dilithium_ed25519",
      role: "organization",
      valid: hybridValid,
      invalid: hybridInvalid,
    },
  };
}

export const VECTORS_PATH = join(__dirname, "service-anchor-vectors.json");
/** Copies read by the Go and Rust tests. */
export const VECTOR_COPIES = [join(__dirname, "../../../go/test/compatibility/testdata/service-anchor-vectors.json"), join(__dirname, "../../../rust/tests/data/service-anchor-vectors.json")];

if (require.main === module) {
  buildVectors().then((vectors) => {
    const text = JSON.stringify(vectors, null, 2) + "\n";
    for (const path of [VECTORS_PATH, ...VECTOR_COPIES]) writeFileSync(path, text);
    console.log(`wrote ${VECTORS_PATH}`);
  });
}
