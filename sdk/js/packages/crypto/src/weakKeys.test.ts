import { describe, expect, it } from "vitest";
import { keyPairFromSeed } from "./keys.js";
import { isWeakEd25519PublicKey } from "./weakKeys.js";

function fromHex(value: string): Uint8Array {
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(value.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}

// The fourteen encodings of tosctl/src/node-control/contracts/tests/weak_ed25519/mod.rs:
// the eight torsion points, y >= 2^255 - 19 with either sign bit, and the identity and
// order-2 point with the sign bit set.
const WEAK_ED25519_KEYS: readonly string[] = [
  "0100000000000000000000000000000000000000000000000000000000000000",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "0100000000000000000000000000000000000000000000000000000000000080",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
];

describe("isWeakEd25519PublicKey", () => {
  it("refuses every forgeable encoding", () => {
    for (const key of WEAK_ED25519_KEYS) {
      expect(isWeakEd25519PublicKey(fromHex(key)), key).toBe(true);
    }
  });

  it("accepts real keys, including ones that share a weak key's first byte", () => {
    let checked = 0;
    const firstBytes = new Set([0x00, 0x01, 0x26, 0xc7, 0xec, 0xff]);
    for (let n = 0; n < 4096; n++) {
      const seed = new Uint8Array(32);
      seed[0] = n & 0xff;
      seed[1] = n >> 8;
      const { publicKey } = keyPairFromSeed(seed);
      expect(isWeakEd25519PublicKey(publicKey)).toBe(false);
      if (firstBytes.has(publicKey[0] ?? -1)) {
        checked++;
      }
    }
    expect(checked).toBeGreaterThan(20);
  });

  it("accepts the neighbours of each weak encoding", () => {
    // Flipping any bit other than the sign bit leaves the weak set, except within
    // the y >= 2^255 - 19 range, which is checked as a range.
    for (const key of WEAK_ED25519_KEYS.slice(0, 8)) {
      const bytes = fromHex(key);
      if ((bytes[0] ?? 0) >= 0xec) {
        continue;
      }
      const neighbour = new Uint8Array(bytes);
      neighbour[15] = (neighbour[15] ?? 0) ^ 0x01;
      expect(isWeakEd25519PublicKey(neighbour), key).toBe(false);
    }
    const belowP = fromHex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7e");
    expect(isWeakEd25519PublicKey(belowP)).toBe(false);
    const notAllOnes = fromHex("edfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffff7f");
    expect(isWeakEd25519PublicKey(notAllOnes)).toBe(false);
  });

  it("requires 32 bytes", () => {
    expect(() => isWeakEd25519PublicKey(new Uint8Array(31))).toThrow("32 bytes");
    expect(() => isWeakEd25519PublicKey(new Uint8Array(33))).toThrow("32 bytes");
  });
});
