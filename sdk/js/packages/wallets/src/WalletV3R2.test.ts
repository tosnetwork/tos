import { describe, it, expect } from "vitest";
import { Cell, beginCell, Address } from "@tos/core";
import { keyPairFromSeed, signVerify } from "@tos/crypto";
import { WalletV3R2 } from "./WalletV3R2.js";

// ---------------------------------------------------------------------------
// Deterministic test key pair from a fixed 32-byte seed
// ---------------------------------------------------------------------------
const SEED = new Uint8Array(32); // all zeros
const KEY_PAIR = keyPairFromSeed(SEED);

// A second, distinct seed for "different key" tests
const SEED_B = new Uint8Array(32);
SEED_B[0] = 1;
const KEY_PAIR_B = keyPairFromSeed(SEED_B);

// Dummy destination address (workchain 0, 32 zero bytes hash)
const DEST = new Address(0, new Uint8Array(32));

describe("WalletV3R2", () => {
  // -----------------------------------------------------------------------
  // Address derivation
  // -----------------------------------------------------------------------

  it("creates a wallet with a deterministic address", () => {
    const wallet = WalletV3R2.create({ publicKey: KEY_PAIR.publicKey });
    expect(wallet.address).toBeInstanceOf(Address);
    expect(wallet.address.workchain).toBe(0);
  });

  it("same public key always yields the same address", () => {
    const a = WalletV3R2.create({ publicKey: KEY_PAIR.publicKey });
    const b = WalletV3R2.create({ publicKey: KEY_PAIR.publicKey });
    expect(a.address.equals(b.address)).toBe(true);
  });

  it("different public keys produce different addresses", () => {
    const a = WalletV3R2.create({ publicKey: KEY_PAIR.publicKey });
    const b = WalletV3R2.create({ publicKey: KEY_PAIR_B.publicKey });
    expect(a.address.equals(b.address)).toBe(false);
  });

  it("different workchains produce different addresses", () => {
    const wc0 = WalletV3R2.create({ publicKey: KEY_PAIR.publicKey, workchain: 0 });
    const wcN1 = WalletV3R2.create({ publicKey: KEY_PAIR.publicKey, workchain: -1 });
    expect(wc0.address.equals(wcN1.address)).toBe(false);
    expect(wc0.address.workchain).toBe(0);
    expect(wcN1.address.workchain).toBe(-1);
  });

  it("stores the publicKey on the instance", () => {
    const wallet = WalletV3R2.create({ publicKey: KEY_PAIR.publicKey });
    expect(wallet.publicKey).toEqual(KEY_PAIR.publicKey);
  });

  it("has a StateInit with code and data cells", () => {
    const wallet = WalletV3R2.create({ publicKey: KEY_PAIR.publicKey });
    expect(wallet.init).toBeDefined();
    expect(wallet.init.code).toBeInstanceOf(Cell);
    expect(wallet.init.data).toBeInstanceOf(Cell);
  });

  // -----------------------------------------------------------------------
  // createTransfer
  // -----------------------------------------------------------------------

  it("createTransfer returns a Cell", () => {
    const wallet = WalletV3R2.create({ publicKey: KEY_PAIR.publicKey });
    const transfer = wallet.createTransfer({
      seqno: 0,
      secretKey: KEY_PAIR.secretKey,
      validUntil: 1000000,
      messages: [{ to: DEST, value: 1_000_000_000n }],
    });
    expect(transfer).toBeInstanceOf(Cell);
  });

  it("transfer cell survives BOC round-trip", () => {
    const wallet = WalletV3R2.create({ publicKey: KEY_PAIR.publicKey });
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

  it("transfer cell has valid external message structure", () => {
    const wallet = WalletV3R2.create({ publicKey: KEY_PAIR.publicKey });
    const seqno = 5;
    const validUntil = 9999999;
    const transfer = wallet.createTransfer({
      seqno,
      secretKey: KEY_PAIR.secretKey,
      validUntil,
      messages: [{ to: DEST, value: 1n }],
    });

    const slice = transfer.beginParse();

    // First 512 bits = signature (64 bytes)
    const signature = slice.loadBuffer(64);
    expect(signature.length).toBe(64);

    // walletId:uint32  validUntil:uint32  seqno:uint32
    const walletId = slice.loadUint(32);
    expect(walletId).toBe(wallet.walletId);

    const loadedValidUntil = slice.loadUint(32);
    expect(loadedValidUntil).toBe(validUntil);

    const loadedSeqno = slice.loadUint(32);
    expect(loadedSeqno).toBe(seqno);

    // The signature should be verifiable against the signing message hash
    // Rebuild the signing message to verify
    // There should be at least one ref (the internal message)
    expect(slice.remainingRefs).toBeGreaterThanOrEqual(1);
  });

  it("signature is a valid Ed25519 signature over the signing message", () => {
    const wallet = WalletV3R2.create({ publicKey: KEY_PAIR.publicKey });
    const seqno = 3;
    const validUntil = 5000000;

    const transfer = wallet.createTransfer({
      seqno,
      secretKey: KEY_PAIR.secretKey,
      validUntil,
      messages: [{ to: DEST, value: 100n }],
    });

    // Parse the external message
    const slice = transfer.beginParse();
    const signature = slice.loadBuffer(64);

    // Everything after the signature is the signing message content.
    // We need to reconstruct the signing message cell to get its hash.
    // The simplest approach: create the same signing message the wallet would.
    const msgCell = beginCell()
      .storeSlice(slice) // the rest after signature
      .endCell();

    // Verify the signature
    expect(signVerify(msgCell.hash(), signature, KEY_PAIR.publicKey)).toBe(true);
  });

  it("createTransfer is deterministic with same inputs", () => {
    const wallet = WalletV3R2.create({ publicKey: KEY_PAIR.publicKey });
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
    const wallet = WalletV3R2.create({ publicKey: KEY_PAIR.publicKey });
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
    const wallet = WalletV3R2.create({ publicKey: KEY_PAIR.publicKey });
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
    const wallet = WalletV3R2.create({ publicKey: KEY_PAIR.publicKey });
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
