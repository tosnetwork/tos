/**
 * @tos/client — Signer interface.
 *
 * A Signer represents a key-holder that can sign arbitrary bytes and send
 * messages on-chain.  Wallet implementations in @tos/wallets typically
 * implement this interface.
 */

import type { AddressLike, CellLike } from "./TosProvider.js";
import type { SendMode, StateInit } from "./ContractProvider.js";

// ---------------------------------------------------------------------------
// SenderArguments
// ---------------------------------------------------------------------------

/** Arguments accepted by {@link Signer.send}. */
export interface SenderArguments {
  to: AddressLike;
  value: bigint;
  body?: CellLike;
  sendMode?: SendMode;
  bounce?: boolean;
  init?: StateInit;
}

// ---------------------------------------------------------------------------
// Signer
// ---------------------------------------------------------------------------

export interface Signer {
  /** The address of the signing account (wallet). */
  readonly address: AddressLike;

  /**
   * Produce an Ed25519 detached signature over arbitrary bytes.
   *
   * @param message - The bytes to sign.
   * @returns The 64-byte signature.
   */
  sign(message: Uint8Array): Promise<Uint8Array>;

  /**
   * Construct, sign, and broadcast an internal message.
   *
   * @param args - Message parameters.
   */
  send(args: SenderArguments): Promise<void>;
}
