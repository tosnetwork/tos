import { describe, it, expect } from "vitest";
import { Cell, Address, beginCell } from "@tos/core";
import { createInternalMessage } from "./utils.js";
import type { OutMessage } from "./types.js";

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------
const DEST = new Address(0, new Uint8Array(32));

const DEST_WC1 = new Address(
  -1,
  new Uint8Array(32).fill(0xaa),
);

describe("createInternalMessage", () => {
  it("returns a Cell", () => {
    const msg: OutMessage = { to: DEST, value: 1_000_000_000n };
    const cell = createInternalMessage(msg);
    expect(cell).toBeInstanceOf(Cell);
  });

  it("starts with int_msg_info tag = 0", () => {
    const msg: OutMessage = { to: DEST, value: 1n };
    const cell = createInternalMessage(msg);
    const slice = cell.beginParse();

    // int_msg_info$0
    const tag = slice.loadBit();
    expect(tag).toBe(false); // 0 bit = int_msg_info
  });

  it("sets ihr_disabled=true, bounce=true (default), bounced=false", () => {
    const msg: OutMessage = { to: DEST, value: 1n };
    const cell = createInternalMessage(msg);
    const slice = cell.beginParse();

    slice.loadBit(); // skip tag (0)

    const ihrDisabled = slice.loadBit();
    expect(ihrDisabled).toBe(true);

    const bounce = slice.loadBit();
    expect(bounce).toBe(true);

    const bounced = slice.loadBit();
    expect(bounced).toBe(false);
  });

  it("sets bounce=false when specified", () => {
    const msg: OutMessage = { to: DEST, value: 1n, bounce: false };
    const cell = createInternalMessage(msg);
    const slice = cell.beginParse();

    slice.loadBit(); // tag
    slice.loadBit(); // ihr_disabled

    const bounce = slice.loadBit();
    expect(bounce).toBe(false);
  });

  it("stores src as addr_none (00)", () => {
    const msg: OutMessage = { to: DEST, value: 1n };
    const cell = createInternalMessage(msg);
    const slice = cell.beginParse();

    // Skip: tag(1) + ihr_disabled(1) + bounce(1) + bounced(1) = 4 bits
    slice.skip(4);

    // src: addr_none$00
    const srcTag = slice.loadUint(2);
    expect(srcTag).toBe(0);
  });

  it("stores the destination address", () => {
    const msg: OutMessage = { to: DEST, value: 1n };
    const cell = createInternalMessage(msg);
    const slice = cell.beginParse();

    // Skip: tag(1) + ihr_disabled(1) + bounce(1) + bounced(1) + src(2) = 6 bits
    slice.skip(6);

    const addr = slice.loadAddress();
    expect(addr.equals(DEST)).toBe(true);
  });

  it("stores the destination address for workchain -1", () => {
    const msg: OutMessage = { to: DEST_WC1, value: 1n };
    const cell = createInternalMessage(msg);
    const slice = cell.beginParse();

    slice.skip(6); // tag + ihr + bounce + bounced + src
    const addr = slice.loadAddress();
    expect(addr.equals(DEST_WC1)).toBe(true);
    expect(addr.workchain).toBe(-1);
  });

  it("stores the value as coins", () => {
    const value = 5_000_000_000n; // 5 TOS
    const msg: OutMessage = { to: DEST, value };
    const cell = createInternalMessage(msg);
    const slice = cell.beginParse();

    slice.skip(6); // tag + flags + src
    slice.loadAddress(); // dest

    const coins = slice.loadCoins();
    expect(coins).toBe(value);
  });

  it("has no init and no body by default", () => {
    const msg: OutMessage = { to: DEST, value: 1n };
    const cell = createInternalMessage(msg);
    const slice = cell.beginParse();

    // Skip to after created_at:
    // tag(1) + ihr(1) + bounce(1) + bounced(1) + src(2) = 6 bits
    slice.skip(6);
    slice.loadAddress(); // dest
    slice.loadCoins();   // value
    slice.loadUint(1);   // extra-currencies dict (empty = 0)
    slice.loadCoins();   // ihr_fee
    slice.loadCoins();   // fwd_fee
    slice.loadUintBig(64); // created_lt
    slice.loadUint(32);    // created_at

    // init: Maybe = 0 (no init)
    const hasInit = slice.loadBit();
    expect(hasInit).toBe(false);

    // body: Either = 0 (inline empty)
    const hasBody = slice.loadBit();
    expect(hasBody).toBe(false);
  });

  it("stores body as a ref when provided", () => {
    const body = beginCell().storeUint(0xdeadbeef, 32).endCell();
    const msg: OutMessage = { to: DEST, value: 1n, body };
    const cell = createInternalMessage(msg);
    const slice = cell.beginParse();

    // Navigate to after created_at
    slice.skip(6);
    slice.loadAddress();
    slice.loadCoins();
    slice.loadUint(1);   // extra currencies
    slice.loadCoins();   // ihr_fee
    slice.loadCoins();   // fwd_fee
    slice.loadUintBig(64);
    slice.loadUint(32);

    // init
    const hasInit = slice.loadBit();
    expect(hasInit).toBe(false);

    // body: Either right = 1 → ref
    const bodyIsRef = slice.loadBit();
    expect(bodyIsRef).toBe(true);

    const bodyCell = slice.loadRef();
    const bodySlice = bodyCell.beginParse();
    const value = bodySlice.loadUint(32);
    expect(value).toBe(0xdeadbeef);
  });

  it("stores init as a ref when provided", () => {
    const code = beginCell().storeUint(1, 8).endCell();
    const data = beginCell().storeUint(2, 8).endCell();
    const msg: OutMessage = {
      to: DEST,
      value: 1n,
      init: { code, data },
    };
    const cell = createInternalMessage(msg);
    const slice = cell.beginParse();

    // Navigate to after created_at
    slice.skip(6);
    slice.loadAddress();
    slice.loadCoins();
    slice.loadUint(1);
    slice.loadCoins();
    slice.loadCoins();
    slice.loadUintBig(64);
    slice.loadUint(32);

    // init: 1 (has init), 1 (as ref)
    const hasInit = slice.loadBit();
    expect(hasInit).toBe(true);
    const initIsRef = slice.loadBit();
    expect(initIsRef).toBe(true);

    const initCell = slice.loadRef();
    expect(initCell).toBeInstanceOf(Cell);

    // The StateInit cell should contain our code and data refs
    const initSlice = initCell.beginParse();
    // split_depth: 0, special: 0, code: 1, data: 1, library: 0
    expect(initSlice.loadBit()).toBe(false); // no split_depth
    expect(initSlice.loadBit()).toBe(false); // no special
    expect(initSlice.loadBit()).toBe(true);  // has code
    const codeRef = initSlice.loadRef();
    expect(initSlice.loadBit()).toBe(true);  // has data
    const dataRef = initSlice.loadRef();
    expect(initSlice.loadBit()).toBe(false); // no library

    // Verify code and data content
    expect(codeRef.beginParse().loadUint(8)).toBe(1);
    expect(dataRef.beginParse().loadUint(8)).toBe(2);
  });

  it("message cell survives BOC round-trip", () => {
    const body = beginCell().storeUint(42, 32).endCell();
    const msg: OutMessage = { to: DEST, value: 1_000_000n, body };
    const cell = createInternalMessage(msg);

    const boc = cell.toBoc();
    const restored = Cell.fromBoc(boc)[0]!;
    expect(restored.equals(cell)).toBe(true);
  });

  it("produces deterministic output for the same inputs", () => {
    const msg: OutMessage = { to: DEST, value: 123_456_789n };
    const a = createInternalMessage(msg);
    const b = createInternalMessage(msg);
    expect(a.equals(b)).toBe(true);
  });
});
