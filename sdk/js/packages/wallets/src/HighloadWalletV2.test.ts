import { describe, it, expect } from "vitest";
import { Cell, Address, Dictionary } from "@tos/core";
import { keyPairFromSeed, signVerify } from "@tos/crypto";
import { HighloadWalletV2, createQueryId } from "./HighloadWalletV2.js";

// ---------------------------------------------------------------------------
// Deterministic test key pair
// ---------------------------------------------------------------------------
const SEED = new Uint8Array(32);
const KEY_PAIR = keyPairFromSeed(SEED);

const SEED_B = new Uint8Array(32);
SEED_B[0] = 1;
const KEY_PAIR_B = keyPairFromSeed(SEED_B);

const DEST = new Address(0, new Uint8Array(32));

describe("HighloadWalletV2", () => {
  // -----------------------------------------------------------------------
  // Address derivation
  // -----------------------------------------------------------------------

  it("creates a wallet with a deterministic address", () => {
    const wallet = HighloadWalletV2.create({ publicKey: KEY_PAIR.publicKey });
    expect(wallet.address).toBeInstanceOf(Address);
    expect(wallet.address.workchain).toBe(0);
  });

  it("same public key always yields the same address", () => {
    const a = HighloadWalletV2.create({ publicKey: KEY_PAIR.publicKey });
    const b = HighloadWalletV2.create({ publicKey: KEY_PAIR.publicKey });
    expect(a.address.equals(b.address)).toBe(true);
  });

  it("different public keys produce different addresses", () => {
    const a = HighloadWalletV2.create({ publicKey: KEY_PAIR.publicKey });
    const b = HighloadWalletV2.create({ publicKey: KEY_PAIR_B.publicKey });
    expect(a.address.equals(b.address)).toBe(false);
  });

  it("has a StateInit with code and data cells", () => {
    const wallet = HighloadWalletV2.create({ publicKey: KEY_PAIR.publicKey });
    expect(wallet.init.code).toBeInstanceOf(Cell);
    expect(wallet.init.data).toBeInstanceOf(Cell);
  });

  // -----------------------------------------------------------------------
  // createQueryId
  // -----------------------------------------------------------------------

  it("createQueryId encodes timestamp and counter correctly", () => {
    const ts = 1700000000;
    const ctr = 42;
    const qid = createQueryId(ts, ctr);
    // queryId = (ts << 32) | ctr
    expect(qid).toBe((BigInt(ts) << 32n) | BigInt(ctr));
  });

  it("createQueryId defaults counter to 0", () => {
    const ts = 1700000000;
    const qid = createQueryId(ts);
    expect(qid).toBe(BigInt(ts) << 32n);
  });

  // -----------------------------------------------------------------------
  // createTransfer
  // -----------------------------------------------------------------------

  it("createTransfer returns a Cell", () => {
    const wallet = HighloadWalletV2.create({ publicKey: KEY_PAIR.publicKey });
    const transfer = wallet.createTransfer({
      seqno: 0,
      secretKey: KEY_PAIR.secretKey,
      validUntil: 1000000,
      messages: [{ to: DEST, value: 1_000_000_000n }],
    });
    expect(transfer).toBeInstanceOf(Cell);
  });

  it("transfer cell survives BOC round-trip", () => {
    const wallet = HighloadWalletV2.create({ publicKey: KEY_PAIR.publicKey });
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

  it("transfer cell has signature inline and signing message as ref", () => {
    const wallet = HighloadWalletV2.create({ publicKey: KEY_PAIR.publicKey });
    const transfer = wallet.createTransfer({
      seqno: 0,
      secretKey: KEY_PAIR.secretKey,
      validUntil: 1000000,
      messages: [{ to: DEST, value: 1n }],
    });

    const slice = transfer.beginParse();

    // 512 bits = 64-byte signature
    const signature = slice.loadBuffer(64);
    expect(signature.length).toBe(64);

    // Signing message is stored as a ref (not inline like V3/V4)
    expect(slice.remainingRefs).toBe(1);
    const signingMsgCell = slice.loadRef();
    expect(signingMsgCell).toBeInstanceOf(Cell);

    // Verify the signing message structure: walletId:uint32 queryId:uint64 dict...
    const msgSlice = signingMsgCell.beginParse();
    const walletId = msgSlice.loadUint(32);
    expect(walletId).toBe(wallet.walletId);

    const queryId = msgSlice.loadUintBig(64);
    expect(queryId).toBeGreaterThan(0n);
  });

  it("signature is valid Ed25519 over the signing message ref", () => {
    const wallet = HighloadWalletV2.create({ publicKey: KEY_PAIR.publicKey });
    const transfer = wallet.createTransfer({
      seqno: 0,
      secretKey: KEY_PAIR.secretKey,
      validUntil: 1000000,
      messages: [{ to: DEST, value: 100n }],
    });

    const slice = transfer.beginParse();
    const signature = slice.loadBuffer(64);
    const signingMsgCell = slice.loadRef();

    expect(
      signVerify(signingMsgCell.hash(), signature, KEY_PAIR.publicKey),
    ).toBe(true);
  });

  it("creates transfer with 3 messages and stores them in a dictionary", () => {
    const wallet = HighloadWalletV2.create({ publicKey: KEY_PAIR.publicKey });
    const msgs = [
      { to: DEST, value: 1_000_000n },
      { to: DEST, value: 2_000_000n },
      { to: DEST, value: 3_000_000n },
    ];
    const transfer = wallet.createTransfer({
      seqno: 0,
      secretKey: KEY_PAIR.secretKey,
      validUntil: 1000000,
      messages: msgs,
    });

    // Verify the dictionary is present in the signing message
    const slice = transfer.beginParse();
    slice.loadBuffer(64); // skip signature
    const signingMsgCell = slice.loadRef();
    const msgSlice = signingMsgCell.beginParse();
    msgSlice.loadUint(32);    // walletId
    msgSlice.loadUintBig(64); // queryId

    // The rest should be a dict — load it as dict(uint16 -> Cell)
    // Slice.loadDict returns Map<bigint, V>
    const dict = msgSlice.loadDict(
      Dictionary.Keys.Uint(16),
      Dictionary.Values.Cell(),
    );

    // The dictionary should have 3 entries
    expect(dict.size).toBe(3);

    // Keys 0, 1, 2 should exist (as bigint)
    for (let i = 0; i < 3; i++) {
      expect(dict.has(BigInt(i))).toBe(true);
      const entryCell = dict.get(BigInt(i))!;
      expect(entryCell).toBeInstanceOf(Cell);

      // Each entry: mode:uint8 + internalMsg:^Cell
      const entrySlice = entryCell.beginParse();
      const mode = entrySlice.loadUint(8);
      expect(mode).toBe(3); // default mode
      const internalMsg = entrySlice.loadRef();
      expect(internalMsg).toBeInstanceOf(Cell);
    }
  });

  it("supports up to 254 messages", () => {
    const wallet = HighloadWalletV2.create({ publicKey: KEY_PAIR.publicKey });
    const msgs = Array.from({ length: 254 }, () => ({ to: DEST, value: 1n }));
    const transfer = wallet.createTransfer({
      seqno: 0,
      secretKey: KEY_PAIR.secretKey,
      validUntil: 1000000,
      messages: msgs,
    });
    expect(transfer).toBeInstanceOf(Cell);

    // Verify the dictionary has 254 entries
    const slice = transfer.beginParse();
    slice.loadBuffer(64);
    const signingMsgCell = slice.loadRef();
    const msgSlice = signingMsgCell.beginParse();
    msgSlice.loadUint(32);
    msgSlice.loadUintBig(64);

    const dict254 = msgSlice.loadDict(
      Dictionary.Keys.Uint(16),
      Dictionary.Values.Cell(),
    );
    expect(dict254.size).toBe(254);
  });

  it("rejects more than 254 messages", () => {
    const wallet = HighloadWalletV2.create({ publicKey: KEY_PAIR.publicKey });
    const msgs = Array.from({ length: 255 }, () => ({ to: DEST, value: 1n }));
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
    const wallet = HighloadWalletV2.create({ publicKey: KEY_PAIR.publicKey });
    expect(() =>
      wallet.createTransfer({
        seqno: 0,
        secretKey: KEY_PAIR.secretKey,
        validUntil: 1000000,
        messages: [],
      }),
    ).toThrow();
  });

  // -----------------------------------------------------------------------
  // createTransferWithQueryId
  // -----------------------------------------------------------------------

  it("createTransferWithQueryId uses the provided queryId", () => {
    const wallet = HighloadWalletV2.create({ publicKey: KEY_PAIR.publicKey });
    const queryId = 12345678n;
    const transfer = wallet.createTransferWithQueryId({
      queryId,
      secretKey: KEY_PAIR.secretKey,
      messages: [{ to: DEST, value: 1n }],
    });

    const slice = transfer.beginParse();
    slice.loadBuffer(64); // skip signature
    const signingMsgCell = slice.loadRef();
    const msgSlice = signingMsgCell.beginParse();
    msgSlice.loadUint(32); // walletId
    const storedQid = msgSlice.loadUintBig(64);
    expect(storedQid).toBe(queryId);
  });
});
