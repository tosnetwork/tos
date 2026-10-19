/**
 * Internal message building utilities for wallet contracts.
 *
 * These helpers serialize OutMessage descriptors into Cell structures
 * that match the TVM internal message format (int_msg_info$0).
 */

import {
  beginCell,
  Cell,
  type StateInit,
} from "@tos/core";
import { isWeakEd25519PublicKey } from "@tos/crypto";
import { ErrorCodes, TosError } from "@tos/client";
import type { OutMessage } from "./types.js";

/**
 * The public key a wallet is created for, refused when it is not 32 bytes or
 * is a prohibited weak or non-canonical encoding (some of which take signatures
 * forged with no secret): a caller handing in a raw key (rather than one
 * derived from its own secret) would otherwise compute and fund the address
 * without noticing.
 *
 * @throws Error naming the wallet when the key is malformed or forgeable
 */
export function requireWalletPublicKey(publicKey: Uint8Array, wallet: string): Uint8Array {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) {
    throw new Error(`${wallet}: the public key must be 32 bytes`);
  }
  if (isWeakEd25519PublicKey(publicKey)) {
    throw new Error(`${wallet}: refusing a weak or non-canonical Ed25519 public key`);
  }
  return publicKey;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Default send mode: PAY_GAS_SEPARATELY + IGNORE_ERRORS = 3.
 *
 * The ignore-errors flag stays on by default. The wallet contracts accept the
 * message and advance their seqno in the compute phase; if a message then
 * fails in the action phase without that flag, the whole action phase fails,
 * the new seqno is discarded with it, and the same signed message stays valid
 * and can be executed (and charged) again until `validUntil`. With the flag the
 * failed message is skipped and the seqno advances, so a signed transfer runs
 * at most once.
 *
 * The cost is that a skipped message is not an error on chain: the
 * transaction succeeds and charges its fee while no value moves. That is why
 * `sendTransfer` refuses, before signing, a transfer the balance visibly
 * cannot cover (see {@link requireAffordable}), and why the confirmation is
 * `waitForTransfer` from `@tos/client`, which compares the transaction's
 * outgoing messages with the transfer, never a seqno change.
 */
export const DEFAULT_SEND_MODE = 3;

/** Send-mode flag: carry the whole remaining balance (the message value is ignored). */
const SEND_MODE_CARRY_ALL_BALANCE = 128;

/** Largest value a uint32 `validUntil` field can hold. */
const MAX_VALID_UNTIL = 0xffffffff;

// ---------------------------------------------------------------------------
// State-init serialization
// ---------------------------------------------------------------------------

/**
 * Serialize a StateInit into a Cell.
 *
 * Layout (TL-B):
 *   _ split_depth:(Maybe (## 5)) special:(Maybe TickTock)
 *     code:(Maybe ^Cell) data:(Maybe ^Cell)
 *     library:(Maybe ^Cell) = StateInit;
 */
function storeStateInit(init: StateInit): Cell {
  const b = beginCell();
  b.storeUint(0, 1); // no split_depth
  b.storeUint(0, 1); // no special/ticktock
  if (init.code) {
    b.storeUint(1, 1);
    b.storeRef(init.code);
  } else {
    b.storeUint(0, 1);
  }
  if (init.data) {
    b.storeUint(1, 1);
    b.storeRef(init.data);
  } else {
    b.storeUint(0, 1);
  }
  b.storeUint(0, 1); // no library
  return b.endCell();
}

// ---------------------------------------------------------------------------
// Internal message builder
// ---------------------------------------------------------------------------

/**
 * Build an internal message Cell from an OutMessage descriptor.
 *
 * This creates a `CommonMsgInfo` with `int_msg_info$0` header, optional
 * state-init, and optional body, following the TL-B schema:
 *
 *   int_msg_info$0 ihr_disabled:Bool bounce:Bool bounced:Bool
 *     src:MsgAddressInt dest:MsgAddressInt
 *     value:CurrencyCollection ihr_fee:Grams fwd_fee:Grams
 *     created_lt:uint64 created_at:uint32 = CommonMsgInfo;
 *
 *   message$_ {X:Type} info:CommonMsgInfo
 *     init:(Maybe (Either StateInit ^StateInit))
 *     body:(Either X ^X) = Message X;
 */
/**
 * Build an internal message Cell from an OutMessage descriptor.
 *
 * @param msg - The outgoing message descriptor
 * @returns A Cell containing the serialized internal message
 *
 * @example
 * ```typescript
 * const cell = createInternalMessage({
 *   to: Address.parse("0:abc..."),
 *   value: toNano("1.5"),
 *   body: comment("Hello"),
 * });
 * ```
 */
export function createInternalMessage(msg: OutMessage): Cell {
  const bounce = msg.bounce !== undefined ? msg.bounce : true;

  const b = beginCell();

  // --- CommonMsgInfo: int_msg_info$0 ---
  b.storeUint(0, 1);     // int_msg_info tag = 0
  b.storeBit(true);       // ihr_disabled = true
  b.storeBit(bounce);     // bounce
  b.storeBit(false);      // bounced = false

  // src: addr_none$00 (filled by validator)
  b.storeUint(0, 2);

  // dest: MsgAddressInt
  b.storeAddress(msg.to);

  // value: CurrencyCollection = grams + empty extra-currencies dict
  b.storeCoins(msg.value);
  b.storeUint(0, 1); // empty extra-currency dict

  // ihr_fee, fwd_fee, created_lt, created_at (zeros, filled by validators)
  b.storeCoins(0n);  // ihr_fee
  b.storeCoins(0n);  // fwd_fee
  b.storeUint(0, 64); // created_lt
  b.storeUint(0, 32); // created_at

  // --- init:(Maybe (Either StateInit ^StateInit)) ---
  if (msg.init) {
    b.storeUint(1, 1); // has init
    b.storeUint(1, 1); // Either: right = ^StateInit (store as ref)
    b.storeRef(storeStateInit(msg.init));
  } else {
    b.storeUint(0, 1); // no init
  }

  // --- body:(Either X ^X) ---
  if (msg.body) {
    b.storeUint(1, 1); // Either: right = ^X (store body as ref)
    b.storeRef(msg.body);
  } else {
    b.storeUint(0, 1); // Either: left = empty inline body
  }

  return b.endCell();
}

/**
 * Serialize a list of OutMessages into cell refs suitable for appending
 * to a wallet signing message.
 *
 * Standard wallets (V3, V4) support up to 4 messages; each message is
 * stored as: `mode:uint8` written to the signing message builder, then
 * the internal message cell is pushed as a ref.
 *
 * @param messages - Array of OutMessage descriptors.
 * @param builder - The Builder to write mode bytes and attach refs to.
 */
export function storeOutMessages(
  messages: OutMessage[],
  builder: ReturnType<typeof beginCell>,
  sendMode?: number,
): void {
  for (const msg of messages) {
    builder.storeUint(effectiveSendMode(msg, sendMode), 8);
    builder.storeRef(createInternalMessage(msg));
  }
}

/**
 * The send mode a message goes out with: its own `mode`, else the transfer's
 * `sendMode`, else {@link DEFAULT_SEND_MODE}.
 *
 * @throws Error when the chosen mode is not an integer in 0..255
 */
export function effectiveSendMode(msg: OutMessage, sendMode?: number): number {
  const mode = msg.mode ?? sendMode ?? DEFAULT_SEND_MODE;
  if (!Number.isInteger(mode) || mode < 0 || mode > 255) {
    throw new Error(`send mode must be an integer in 0..255, got ${String(mode)}`);
  }
  return mode;
}

/**
 * Refuse, before anything is signed, a transfer the wallet visibly cannot pay.
 *
 * Rule: the values of all messages not sent with the carry-all-balance flag
 * (128) must add up to strictly less than the wallet's balance. Every wallet
 * transaction pays its own fees from the balance before its messages leave, so
 * a transfer of the whole balance cannot succeed either. Fees are not
 * estimated here, so passing this check does not mean the transfer will
 * settle: a transfer that fits the balance but not the balance less fees is
 * caught afterwards by `waitForTransfer`.
 *
 * @param messages - The transfer's messages
 * @param balance  - The wallet's current balance in nanoTOS
 * @param sendMode - The transfer-level send mode, if any
 * @param wallet   - Wallet name for error messages
 * @throws TosError with code `INSUFFICIENT_BALANCE` when the rule fails
 * @throws Error when a message value is not a non-negative bigint
 */
export function requireAffordable(
  messages: OutMessage[],
  balance: bigint,
  sendMode: number | undefined,
  wallet: string,
): void {
  let total = 0n;
  for (const msg of messages) {
    if (typeof msg.value !== "bigint" || msg.value < 0n) {
      throw new Error(`${wallet}: message value must be a non-negative bigint`);
    }
    if ((effectiveSendMode(msg, sendMode) & SEND_MODE_CARRY_ALL_BALANCE) === 0) {
      total += msg.value;
    }
  }
  if (total >= balance) {
    throw new TosError(
      `${wallet}: the transfer sends ${total} nanoTOS but the wallet holds ${balance}; the balance must exceed the value sent, since fees are paid from it too`,
      ErrorCodes.INSUFFICIENT_BALANCE,
    );
  }
}

/**
 * The `validUntil` a signed message carries: the caller's value, or the
 * current time + 60 seconds when none is given.
 *
 * The wallet contracts refuse a message whose `validUntil` is not after the
 * current time (exit 35), so a value already in the past would only produce a
 * signature nobody can use: it is refused here instead.
 *
 * @throws Error when `validUntil` is not an integer, exceeds uint32, or is not
 *   after the current time
 */
export function resolveValidUntil(validUntil: number | undefined, wallet: string): number {
  const now = Math.floor(Date.now() / 1000);
  if (validUntil === undefined) {
    return now + 60;
  }
  if (!Number.isInteger(validUntil) || validUntil < 0 || validUntil > MAX_VALID_UNTIL) {
    throw new Error(`${wallet}: validUntil must be a uint32 UNIX time, got ${String(validUntil)}`);
  }
  if (validUntil <= now) {
    throw new Error(
      `${wallet}: validUntil ${validUntil} is not after the current time ${now}; the wallet would refuse the message`,
    );
  }
  return validUntil;
}
