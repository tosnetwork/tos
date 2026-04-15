import { describe, it, expect } from "vitest";
import { Cell, Address, beginCell } from "@tos/core";
import { keyPairFromSeed, signVerify } from "@tos/crypto";
import { WalletV5R1 } from "./WalletV5R1.js";
import { WalletV4R2 } from "./WalletV4R2.js";

// ---------------------------------------------------------------------------
// Deterministic test key pair
// ---------------------------------------------------------------------------
const SEED = new Uint8Array(32);
const KEY_PAIR = keyPairFromSeed(SEED);

const SEED_B = new Uint8Array(32);
SEED_B[0] = 1;
const KEY_PAIR_B = keyPairFromSeed(SEED_B);

const DEST = new Address(0, new Uint8Array(32));

/** ACTION_SEND_MSG opcode used by V5 */
const ACTION_SEND_MSG = 0x0ec3c86d;
/** External signed request opcode used by V5 */
const AUTH_SIGNED_EXTERNAL = 0x7369676e;

describe("WalletV5R1", () => {
  // -----------------------------------------------------------------------
  // Address derivation
  // -----------------------------------------------------------------------

  it("creates a wallet with a deterministic address", () => {
    const wallet = WalletV5R1.create({ publicKey: KEY_PAIR.publicKey });
    expect(wallet.address).toBeInstanceOf(Address);
    expect(wallet.address.workchain).toBe(0);
  });

  it("same public key always yields the same address", () => {
    const a = WalletV5R1.create({ publicKey: KEY_PAIR.publicKey });
    const b = WalletV5R1.create({ publicKey: KEY_PAIR.publicKey });
    expect(a.address.equals(b.address)).toBe(true);
  });

  it("different public keys produce different addresses", () => {
    const a = WalletV5R1.create({ publicKey: KEY_PAIR.publicKey });
    const b = WalletV5R1.create({ publicKey: KEY_PAIR_B.publicKey });
    expect(a.address.equals(b.address)).toBe(false);
  });

  it("V5R1 address differs from V4R2 address for the same key", () => {
    const v5 = WalletV5R1.create({ publicKey: KEY_PAIR.publicKey });
    const v4 = WalletV4R2.create({ publicKey: KEY_PAIR.publicKey });
    expect(v5.address.equals(v4.address)).toBe(false);
  });

  it("has a StateInit with code and data cells", () => {
    const wallet = WalletV5R1.create({ publicKey: KEY_PAIR.publicKey });
    expect(wallet.init.code).toBeInstanceOf(Cell);
    expect(wallet.init.data).toBeInstanceOf(Cell);
  });

  // -----------------------------------------------------------------------
  // createTransfer
  // -----------------------------------------------------------------------

  it("createTransfer returns a Cell", () => {
    const wallet = WalletV5R1.create({ publicKey: KEY_PAIR.publicKey });
    const transfer = wallet.createTransfer({
      seqno: 0,
      secretKey: KEY_PAIR.secretKey,
      validUntil: 1000000,
      messages: [{ to: DEST, value: 1_000_000_000n }],
    });
    expect(transfer).toBeInstanceOf(Cell);
  });

  it("transfer cell survives BOC round-trip", () => {
    const wallet = WalletV5R1.create({ publicKey: KEY_PAIR.publicKey });
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

  it("transfer cell has valid V5 external message structure with actions ref", () => {
    const wallet = WalletV5R1.create({ publicKey: KEY_PAIR.publicKey });
    const seqno = 5;
    const validUntil = 9999999;
    const transfer = wallet.createTransfer({
      seqno,
      secretKey: KEY_PAIR.secretKey,
      validUntil,
      messages: [{ to: DEST, value: 1n }],
    });

    const slice = transfer.beginParse();

    const opcode = slice.loadUint(32);
    expect(opcode).toBe(AUTH_SIGNED_EXTERNAL);

    // global_id:int32 (TOS V5 anti-replay)
    const globalId = slice.loadInt(32);
    expect(globalId).toBe(wallet.networkGlobalId);

    // walletId:uint32 (plain subwallet number)
    const walletId = slice.loadUint(32);
    expect(walletId).toBe(wallet.walletId);

    // validUntil:uint32
    const loadedValidUntil = slice.loadUint(32);
    expect(loadedValidUntil).toBe(validUntil);

    // seqno:uint32
    const loadedSeqno = slice.loadUint(32);
    expect(loadedSeqno).toBe(seqno);

    const actionsCell = slice.loadMaybeRef();
    expect(actionsCell).toBeInstanceOf(Cell);

    const hasExtendedActions = slice.loadBit();
    expect(hasExtendedActions).toBe(false);

    // 512 bits = 64-byte signature
    const signature = slice.loadBuffer(64);
    expect(signature.length).toBe(64);
  });

  it("actions list contains ACTION_SEND_MSG entries for each message", () => {
    const wallet = WalletV5R1.create({ publicKey: KEY_PAIR.publicKey });
    const transfer = wallet.createTransfer({
      seqno: 0,
      secretKey: KEY_PAIR.secretKey,
      validUntil: 1000000,
      messages: [
        { to: DEST, value: 1n },
        { to: DEST, value: 2n },
      ],
    });

    const extSlice = transfer.beginParse();
    extSlice.loadUint(32);   // opcode
    extSlice.loadInt(32);    // global_id
    extSlice.loadUint(32);   // walletId
    extSlice.loadUint(32);   // validUntil
    extSlice.loadUint(32);   // seqno
    extSlice.loadBit();      // maybe-ref out_actions = true

    // Walk the actions linked list
    let actionCell = extSlice.loadRef();
    let messageCount = 0;

    // The chain is: actionCell → ref(prev) + action_send_msg opcode + mode + ref(msg)
    while (actionCell.bits.length > 0) {
      const actionSlice = actionCell.beginParse();
      const previousAction = actionSlice.loadRef();
      const opcode = actionSlice.loadUint(32);
      expect(opcode).toBe(ACTION_SEND_MSG);

      const mode = actionSlice.loadUint(8);
      expect(mode).toBe(3); // default mode

      // Ref 1: the internal message
      const internalMsg = actionSlice.loadRef();
      expect(internalMsg).toBeInstanceOf(Cell);

      // Follow the prev link until we reach the empty terminator cell.
      actionCell = previousAction;
      messageCount++;
    }

    expect(messageCount).toBe(2);
  });

  it("signature is valid Ed25519 over the signing message", () => {
    const wallet = WalletV5R1.create({ publicKey: KEY_PAIR.publicKey });
    const transfer = wallet.createTransfer({
      seqno: 3,
      secretKey: KEY_PAIR.secretKey,
      validUntil: 5000000,
      messages: [{ to: DEST, value: 100n }],
    });

    const slice = transfer.beginParse();
    const opcode = slice.loadUint(32);
    const globalId = slice.loadInt(32);
    const walletId = slice.loadUint(32);
    const validUntil = slice.loadUint(32);
    const seqno = slice.loadUint(32);
    const outActions = slice.loadMaybeRef();
    const hasExtendedActions = slice.loadBit();
    const signature = slice.loadBuffer(64);

    // Reconstruct the signing message and verify signature
    const msgCell = beginCell()
      .storeUint(opcode, 32)
      .storeInt(globalId, 32)
      .storeUint(walletId, 32)
      .storeUint(validUntil, 32)
      .storeUint(seqno, 32)
      .storeMaybeRef(outActions)
      .storeBit(hasExtendedActions)
      .endCell();
    expect(signVerify(msgCell.hash(), signature, KEY_PAIR.publicKey)).toBe(true);
  });

  it("createTransfer is deterministic with same inputs", () => {
    const wallet = WalletV5R1.create({ publicKey: KEY_PAIR.publicKey });
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

  it("rejects zero messages", () => {
    const wallet = WalletV5R1.create({ publicKey: KEY_PAIR.publicKey });
    expect(() =>
      wallet.createTransfer({
        seqno: 0,
        secretKey: KEY_PAIR.secretKey,
        validUntil: 1000000,
        messages: [],
      }),
    ).toThrow();
  });
});
