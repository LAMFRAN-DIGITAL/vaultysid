import assert from "assert";
import { readdirSync, readFileSync, statSync } from "fs";
import { join, resolve } from "path";
import nacl from "tweetnacl";
import { Buffer } from "buffer/";
import "./shims";
import { boxKeyPair, boxKeyPairFromSecretKey, randomBytes, scalarMult, secretboxOpen, secretboxSeal } from "../src/nacl";
import { secretbox } from "../src/crypto";

// src/nacl.ts replaced tweetnacl 1.0.3 by @noble/curves (X25519) and @noble/ciphers (XSalsa20-Poly1305).
// tweetnacl stays a devDependency, only as the reference these tests compare against.

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const fromHex = (s: string) => new Uint8Array(Buffer.from(s, "hex"));
const ROUNDS = 500;

const P = 2n ** 255n - 19n;
const le32 = (n: bigint) => {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = Number((n >> BigInt(8 * i)) & 0xffn);
  return out;
};
// Every u whose product with a clamped scalar is zero (orders 1, 2, 4, 8), with the non-canonical
// encodings P and P + 1 and the high-bit variants that RFC 7748 masks.
const LOW_ORDER = [0n, 1n, P - 1n, 325606250916557431795983626356110631294008115727848805560023387167927233504n, 39382357235489614581723060781553021112529911719440698176882885853963445705823n, P, P + 1n].flatMap((u) => {
  const e = le32(u);
  const high = Uint8Array.from(e);
  high[31] |= 0x80;
  return [e, high];
});

describe("NaCl on @noble (byte-compatible with tweetnacl 1.0.3)", () => {
  it("RFC 7748 §6.1: key pairs and shared secret", () => {
    const alice = boxKeyPairFromSecretKey(fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
    const bob = boxKeyPairFromSecretKey(fromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));
    assert.equal(hex(alice.publicKey), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    assert.equal(hex(bob.publicKey), "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    const shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    assert.equal(hex(scalarMult(alice.secretKey, bob.publicKey)), shared);
    assert.equal(hex(scalarMult(bob.secretKey, alice.publicKey)), shared);
  });

  it("boxKeyPairFromSecretKey equals nacl.box.keyPair.fromSecretKey, and copies the secret key", () => {
    for (let i = 0; i < ROUNDS; i++) {
      const sk = randomBytes(32);
      const ours = boxKeyPairFromSecretKey(sk);
      const ref = nacl.box.keyPair.fromSecretKey(sk);
      assert.equal(hex(ours.publicKey), hex(ref.publicKey));
      assert.equal(hex(ours.secretKey), hex(ref.secretKey));
      assert.notStrictEqual(ours.secretKey, sk);
    }
    const kp = boxKeyPair();
    assert.equal(hex(kp.publicKey), hex(nacl.box.keyPair.fromSecretKey(kp.secretKey).publicKey));
  });

  it("refuses a secret key that is not 32 bytes, as tweetnacl did", () => {
    for (const n of [0, 31, 33, 64]) {
      assert.throws(() => boxKeyPairFromSecretKey(new Uint8Array(n)));
      assert.throws(() => nacl.box.keyPair.fromSecretKey(new Uint8Array(n)));
    }
  });

  it("scalarMult equals nacl.scalarMult on random keys, including non-canonical and high-bit u", () => {
    for (let i = 0; i < ROUNDS; i++) {
      const sk = randomBytes(32);
      const pk = i % 2 === 0 ? nacl.box.keyPair().publicKey : randomBytes(32); // random u: about half not on the curve (twist)
      if (i % 5 === 0) pk[31] |= 0x80;
      assert.equal(hex(scalarMult(sk, pk)), hex(nacl.scalarMult(sk, pk)));
    }
    for (const u of [P + 2n, P + 9n, 2n ** 255n - 1n]) {
      const sk = randomBytes(32);
      assert.equal(hex(scalarMult(sk, le32(u))), hex(nacl.scalarMult(sk, le32(u))));
    }
  });

  it("scalarMult throws on low-order public keys, where tweetnacl returned zeros", () => {
    assert.equal(LOW_ORDER.length, 14);
    for (const u of LOW_ORDER) {
      const sk = randomBytes(32);
      assert.equal(hex(nacl.scalarMult(sk, u)), "00".repeat(32));
      assert.throws(() => scalarMult(sk, u));
    }
  });

  it("secretboxSeal equals nacl.secretbox, and each opens the other's box", () => {
    for (let i = 0; i < ROUNDS; i++) {
      const key = randomBytes(32);
      const nonce = randomBytes(24);
      const message = randomBytes(i % 300);
      const ours = secretboxSeal(message, nonce, key);
      const ref = nacl.secretbox(message, nonce, key);
      assert.equal(hex(ours), hex(ref));
      assert.equal(hex(secretboxOpen(ref, nonce, key)!), hex(message));
      assert.equal(hex(nacl.secretbox.open(ours, nonce, key)!), hex(message));
    }
  });

  it("secretboxOpen returns null where nacl.secretbox.open does", () => {
    const key = randomBytes(32);
    const nonce = randomBytes(24);
    const box = secretboxSeal(new Uint8Array([1, 2, 3, 4]), nonce, key);
    const cases: Uint8Array[] = [new Uint8Array(0), new Uint8Array(15), box.slice(0, 16), box.slice(0, box.length - 1)];
    for (let i = 0; i < box.length; i++) {
      const t = Uint8Array.from(box);
      t[i] ^= 0x01;
      cases.push(t);
    }
    for (const c of cases) {
      assert.equal(nacl.secretbox.open(c, nonce, key), null);
      assert.equal(secretboxOpen(c, nonce, key), null);
    }
    assert.equal(secretboxOpen(box, nonce, randomBytes(32)), null);
    assert.equal(hex(secretboxOpen(secretboxSeal(new Uint8Array(0), nonce, key), nonce, key)!), "");
  });

  it("refuses a bad key or nonce length, as tweetnacl did", () => {
    const m = new Uint8Array(3);
    for (const [n, k] of [
      [23, 32],
      [25, 32],
      [24, 31],
      [24, 33],
    ]) {
      assert.throws(() => secretboxSeal(m, new Uint8Array(n), new Uint8Array(k)));
      assert.throws(() => nacl.secretbox(m, new Uint8Array(n), new Uint8Array(k)));
      assert.throws(() => secretboxOpen(new Uint8Array(32), new Uint8Array(n), new Uint8Array(k)));
    }
  });

  it("crypto.secretbox keeps the shape tweetnacl exposed", () => {
    assert.equal(secretbox.keyLength, nacl.secretbox.keyLength);
    assert.equal(secretbox.nonceLength, nacl.secretbox.nonceLength);
    assert.equal(secretbox.overheadLength, nacl.secretbox.overheadLength);
    const key = randomBytes(32);
    const nonce = randomBytes(24);
    const box = secretbox(new Uint8Array([7, 8, 9]), nonce, key);
    assert.equal(hex(box), hex(nacl.secretbox(new Uint8Array([7, 8, 9]), nonce, key)));
    assert.equal(hex(secretbox.open(box, nonce, key)!), "070809");
    assert.equal(secretbox.open(box, nonce, randomBytes(32)), null);
  });

  it("no source file imports tweetnacl any more", () => {
    const offenders: string[] = [];
    const walk = (dir: string) => {
      for (const name of readdirSync(dir)) {
        const path = join(dir, name);
        if (statSync(path).isDirectory()) walk(path);
        else if (/\.tsx?$/.test(name) && /from\s+["']tweetnacl["']|require\(\s*["']tweetnacl["']\s*\)/.test(readFileSync(path, "utf8"))) offenders.push(path);
      }
    };
    walk(resolve(__dirname, "../src"));
    if (/["']tweetnacl["']/.test(readFileSync(resolve(__dirname, "../index.ts"), "utf8"))) offenders.push("index.ts");
    assert.deepEqual(offenders, []);
    const pkg = JSON.parse(readFileSync(resolve(__dirname, "../package.json"), "utf8"));
    assert.equal(pkg.dependencies.tweetnacl, undefined);
  });
});
