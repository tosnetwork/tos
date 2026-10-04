import { keyPairFromSeed } from "@tos/crypto";
import { describe, expect, it } from "vitest";
import { WalletV3R2 } from "./WalletV3R2.js";
import { WalletV4R2 } from "./WalletV4R2.js";
import { WalletV5R1 } from "./WalletV5R1.js";

const NETWORK = 42;

function fromHex(value: string): Uint8Array {
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(value.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}

// The fourteen encodings of tosctl/src/node-control/contracts/tests/weak_ed25519/mod.rs:
// the eight torsion points, y >= 2^255 - 19 with either sign bit, and the identity and
// order-2 point with the sign bit set. A wallet under any of them has no owner.
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

const FACTORIES = [
  [
    "WalletV3R2",
    (publicKey: Uint8Array) => WalletV3R2.create({ publicKey, networkGlobalId: NETWORK }),
  ],
  [
    "WalletV4R2",
    (publicKey: Uint8Array) => WalletV4R2.create({ publicKey, networkGlobalId: NETWORK }),
  ],
  [
    "WalletV5R1",
    (publicKey: Uint8Array) => WalletV5R1.create({ publicKey, networkGlobalId: NETWORK }),
  ],
] as const;

describe("wallet creation from a raw public key", () => {
  for (const [name, create] of FACTORIES) {
    it(`${name} refuses every key anyone can sign for`, () => {
      for (const key of WEAK_ED25519_KEYS) {
        expect(() => create(fromHex(key)), key).toThrow(
          `${name}: refusing a public key anyone can sign for`,
        );
      }
    });

    it(`${name} refuses a key that is not 32 bytes`, () => {
      expect(() => create(new Uint8Array(31))).toThrow(`${name}: the public key must be 32 bytes`);
      expect(() => create(new Uint8Array(33))).toThrow(`${name}: the public key must be 32 bytes`);
    });

    it(`${name} still creates wallets for real keys`, () => {
      for (let n = 0; n < 64; n++) {
        const seed = new Uint8Array(32);
        seed[0] = n;
        const { publicKey } = keyPairFromSeed(seed);
        expect(create(publicKey).address.workchain).toBe(0);
      }
    });
  }
});
