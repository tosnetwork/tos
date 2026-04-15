import { describe, it, expect } from "vitest";
import { contractAddress, Address } from "@tos/core";
import { keyPairFromSeed } from "@tos/crypto";
import { WalletV4R2 } from "./WalletV4R2.js";
import { WalletV3R2 } from "./WalletV3R2.js";

// ---------------------------------------------------------------------------
// Deterministic test key pairs
// ---------------------------------------------------------------------------
const SEED_A = new Uint8Array(32); // all zeros
const KEY_PAIR_A = keyPairFromSeed(SEED_A);

const SEED_B = new Uint8Array(32);
SEED_B[0] = 1;
const KEY_PAIR_B = keyPairFromSeed(SEED_B);

const SEED_C = new Uint8Array(32);
SEED_C[31] = 0xff;
const KEY_PAIR_C = keyPairFromSeed(SEED_C);

describe("contractAddress", () => {
  it("computed address matches WalletV4R2.address", () => {
    const wallet = WalletV4R2.create({ publicKey: KEY_PAIR_A.publicKey });
    const computed = contractAddress(0, wallet.init);
    expect(computed.equals(wallet.address)).toBe(true);
  });

  it("computed address matches WalletV3R2.address", () => {
    const wallet = WalletV3R2.create({ publicKey: KEY_PAIR_A.publicKey });
    const computed = contractAddress(0, wallet.init);
    expect(computed.equals(wallet.address)).toBe(true);
  });

  it("different workchains produce different addresses", () => {
    const wallet0 = WalletV4R2.create({
      publicKey: KEY_PAIR_A.publicKey,
      workchain: 0,
    });
    const walletN1 = WalletV4R2.create({
      publicKey: KEY_PAIR_A.publicKey,
      workchain: -1,
    });

    const addr0 = contractAddress(0, wallet0.init);
    const addrN1 = contractAddress(-1, walletN1.init);

    expect(addr0.workchain).toBe(0);
    expect(addrN1.workchain).toBe(-1);
    expect(addr0.equals(addrN1)).toBe(false);
  });

  it("different public keys produce different addresses", () => {
    const walletA = WalletV4R2.create({ publicKey: KEY_PAIR_A.publicKey });
    const walletB = WalletV4R2.create({ publicKey: KEY_PAIR_B.publicKey });
    const walletC = WalletV4R2.create({ publicKey: KEY_PAIR_C.publicKey });

    const addrA = contractAddress(0, walletA.init);
    const addrB = contractAddress(0, walletB.init);
    const addrC = contractAddress(0, walletC.init);

    expect(addrA.equals(addrB)).toBe(false);
    expect(addrB.equals(addrC)).toBe(false);
    expect(addrA.equals(addrC)).toBe(false);
  });

  it("address is deterministic — same init always yields the same address", () => {
    const wallet = WalletV4R2.create({ publicKey: KEY_PAIR_A.publicKey });
    const a = contractAddress(0, wallet.init);
    const b = contractAddress(0, wallet.init);
    expect(a.equals(b)).toBe(true);
    expect(a.toRawString()).toBe(b.toRawString());
  });

  it("contractAddress result is a valid Address with 32-byte hash", () => {
    const wallet = WalletV4R2.create({ publicKey: KEY_PAIR_A.publicKey });
    const addr = contractAddress(0, wallet.init);
    expect(addr).toBeInstanceOf(Address);
    expect(addr.hash.length).toBe(32);
    expect(addr.workchain).toBe(0);
  });

  it("raw string form is parseable back to the same address", () => {
    const wallet = WalletV4R2.create({ publicKey: KEY_PAIR_A.publicKey });
    const raw = wallet.address.toRawString();
    const parsed = Address.parseRaw(raw);
    expect(parsed.equals(wallet.address)).toBe(true);
  });

  it("friendly string form is parseable back to the same address", () => {
    const wallet = WalletV4R2.create({ publicKey: KEY_PAIR_A.publicKey });
    const friendly = wallet.address.toString();
    const parsed = Address.parse(friendly);
    expect(parsed.equals(wallet.address)).toBe(true);
  });
});
