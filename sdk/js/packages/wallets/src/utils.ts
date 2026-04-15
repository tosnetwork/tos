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
import type { OutMessage } from "./types.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Default send mode: PAY_GAS_SEPARATELY + IGNORE_ERRORS = 3 */
const DEFAULT_SEND_MODE = 3;

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
): void {
  for (const msg of messages) {
    const mode = msg.mode ?? DEFAULT_SEND_MODE;
    builder.storeUint(mode, 8);
    builder.storeRef(createInternalMessage(msg));
  }
}

/**
 * Return the default valid-until timestamp: current time + 60 seconds.
 */
export function defaultValidUntil(): number {
  return Math.floor(Date.now() / 1000) + 60;
}
