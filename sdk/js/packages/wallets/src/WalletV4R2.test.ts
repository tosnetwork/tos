import { describe, it, expect } from "vitest";
import { Cell, Address } from "@tos/core";
import { keyPairFromSeed, signVerify } from "@tos/crypto";
import { WalletV4R2 } from "./WalletV4R2.js";
import { WalletV3R2 } from "./WalletV3R2.js";
import { beginCell } from "@tos/core";

// ---------------------------------------------------------------------------
// Deterministic test key pair
// ---------------------------------------------------------------------------
const SEED = new Uint8Array(32);
const KEY_PAIR = keyPairFromSeed(SEED);

const SEED_B = new Uint8Array(32);
SEED_B[0] = 1;
const KEY_PAIR_B = keyPairFromSeed(SEED_B);

const DEST = new Address(0, new Uint8Array(32));

describe("WalletV4R2", () => {
  // -----------------------------------------------------------------------
  // Address derivation
  // -----------------------------------------------------------------------

  it("creates a wallet with a deterministic address", () => {
    const wallet = WalletV4R2.create({ publicKey: KEY_PAIR.publicKey });
    expect(wallet.address).toBeInstanceOf(Address);
    expect(wallet.address.workchain).toBe(0);
  });

  it("same public key always yields the same address", () => {
    const a = WalletV4R2.create({ publicKey: KEY_PAIR.publicKey });
    const b = WalletV4R2.create({ publicKey: KEY_PAIR.publicKey });
    expect(a.address.equals(b.address)).toBe(true);
  });

  it("different public keys produce different addresses", () => {
    const a = WalletV4R2.create({ publicKey: KEY_PAIR.publicKey });
    const b = WalletV4R2.create({ publicKey: KEY_PAIR_B.publicKey });
    expect(a.address.equals(b.address)).toBe(false);
  });

  it("different workchains produce different addresses", () => {
    const wc0 = WalletV4R2.create({ publicKey: KEY_PAIR.publicKey, workchain: 0 });
    const wcN1 = WalletV4R2.create({ publicKey: KEY_PAIR.publicKey, workchain: -1 });
    expect(wc0.address.equals(wcN1.address)).toBe(false);
  });

  it("V4R2 and V3R2 produce different addresses from the same public key", () => {
    const v3 = WalletV3R2.create({ publicKey: KEY_PAIR.publicKey });
    const v4 = WalletV4R2.create({ publicKey: KEY_PAIR.publicKey });
    // Different contract code → different addresses
    expect(v3.address.equals(v4.address)).toBe(false);
  });

  it("stores the publicKey on the instance", () => {
    const wallet = WalletV4R2.create({ publicKey: KEY_PAIR.publicKey });
    expect(wallet.publicKey).toEqual(KEY_PAIR.publicKey);
  });

  it("has a StateInit with code and data cells", () => {
    const wallet = WalletV4R2.create({ publicKey: KEY_PAIR.publicKey });
    expect(wallet.init.code).toBeInstanceOf(Cell);
    expect(wallet.init.data).toBeInstanceOf(Cell);
  });

  // -----------------------------------------------------------------------
  // createTransfer
  // -----------------------------------------------------------------------

  it("createTransfer returns a Cell", () => {
    const wallet = WalletV4R2.create({ publicKey: KEY_PAIR.publicKey });
    const transfer = wallet.createTransfer({
      seqno: 0,
      secretKey: KEY_PAIR.secretKey,
      validUntil: 1000000,
      messages: [{ to: DEST, value: 1_000_000_000n }],
    });
    expect(transfer).toBeInstanceOf(Cell);
  });

  it("transfer cell survives BOC round-trip", () => {
    const wallet = WalletV4R2.create({ publicKey: KEY_PAIR.publicKey });
    const transfer = wallet.createTransfer({
      seqno: 1,
      secretKey: KEY_PAIR.secretKey,
      validUntil: 1000000,
      messages: [{ to: DEST, value: 500_000_000n }],
    });
    const boc = transfer.toBoc();
    const restored = Cell.fromBoc(boc)[0]!;
    expect(restored.equals(transfer)).toBe(true);
  });

  it("transfer cell has valid V4R2 external message structure with op byte", () => {
    const wallet = WalletV4R2.create({ publicKey: KEY_PAIR.publicKey });
    const seqno = 5;
    const validUntil = 9999999;
    const transfer = wallet.createTransfer({
      seqno,
      secretKey: KEY_PAIR.secretKey,
      validUntil,
      messages: [{ to: DEST, value: 1n }],
    });

    const slice = transfer.beginParse();

    // 512 bits = 64-byte signature
    const signature = slice.loadBuffer(64);
    expect(signature.length).toBe(64);

    // walletId:uint32
    const walletId = slice.loadUint(32);
    expect(walletId).toBe(wallet.walletId);

    // validUntil:uint32
    const loadedValidUntil = slice.loadUint(32);
    expect(loadedValidUntil).toBe(validUntil);

    // seqno:uint32
    const loadedSeqno = slice.loadUint(32);
    expect(loadedSeqno).toBe(seqno);

    // op:uint8 (should be 0 for simple transfer)
    const op = slice.loadUint(8);
    expect(op).toBe(0);

    // At least one ref for the internal message
    expect(slice.remainingRefs).toBeGreaterThanOrEqual(1);
  });

  it("signature is a valid Ed25519 signature", () => {
    const wallet = WalletV4R2.create({ publicKey: KEY_PAIR.publicKey });
    const transfer = wallet.createTransfer({
      seqno: 3,
      secretKey: KEY_PAIR.secretKey,
      validUntil: 5000000,
      messages: [{ to: DEST, value: 100n }],
    });

    const slice = transfer.beginParse();
    const signature = slice.loadBuffer(64);

    // Rebuild the signing message from what remains
    const msgCell = beginCell().storeSlice(slice).endCell();

    expect(signVerify(msgCell.hash(), signature, KEY_PAIR.publicKey)).toBe(true);
  });

  it("createTransfer is deterministic with same inputs", () => {
    const wallet = WalletV4R2.create({ publicKey: KEY_PAIR.publicKey });
    const args = {
      seqno: 10,
      secretKey: KEY_PAIR.secretKey,
      validUntil: 7777777,
      messages: [{ to: DEST, value: 42n }],
    };
    const a = wallet.createTransfer(args);
    const b = wallet.createTransfer(args);
    expect(a.equals(b)).toBe(true);
  });

  it("rejects more than 4 messages", () => {
    const wallet = WalletV4R2.create({ publicKey: KEY_PAIR.publicKey });
    const msgs = Array.from({ length: 5 }, () => ({ to: DEST, value: 1n }));
    expect(() =>
      wallet.createTransfer({
        seqno: 0,
        secretKey: KEY_PAIR.secretKey,
        validUntil: 1000000,
        messages: msgs,
      }),
    ).toThrow();
  });

  it("rejects zero messages", () => {
    const wallet = WalletV4R2.create({ publicKey: KEY_PAIR.publicKey });
    expect(() =>
      wallet.createTransfer({
        seqno: 0,
        secretKey: KEY_PAIR.secretKey,
        validUntil: 1000000,
        messages: [],
      }),
    ).toThrow();
  });

  it("supports up to 4 messages", () => {
    const wallet = WalletV4R2.create({ publicKey: KEY_PAIR.publicKey });
    const msgs = Array.from({ length: 4 }, () => ({ to: DEST, value: 1n }));
    const transfer = wallet.createTransfer({
      seqno: 0,
      secretKey: KEY_PAIR.secretKey,
      validUntil: 1000000,
      messages: msgs,
    });
    expect(transfer).toBeInstanceOf(Cell);
  });
});
