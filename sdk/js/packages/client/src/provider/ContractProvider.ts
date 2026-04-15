/**
 * @tos/client — ContractProvider interface.
 *
 * This is the per-contract adapter that the `open()` function injects as the
 * first argument to contract methods.  It mirrors the shape used by @ton/core
 * so that contract wrapper libraries remain portable.
 */

import type { AddressLike, CellLike, TupleItemLike } from "./TosProvider.js";

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

/** Current on-chain state of a contract. */
export interface ContractState {
  balance: bigint;
  last: { lt: string; hash: string } | null;
  state: "active" | "frozen" | "uninitialized";
  code: Uint8Array | null;
  data: Uint8Array | null;
}

/**
 * Minimal TupleReader-like interface so that contract wrappers can read
 * typed values from the TVM stack without importing @tos/core directly.
 */
export interface StackReader {
  readBigNumber(): bigint;
  readNumber(): number;
  readBoolean(): boolean;
  readAddress(): unknown;
  readCell(): unknown;
  readCellOpt(): unknown | null;
  readTuple(): StackReader;
  readonly remaining: number;
}

/** Result of a get-method invocation. */
export interface ContractGetResult {
  gasUsed: number;
  exitCode: number;
  stack: StackReader;
}

/** Confirmation returned after sending an internal / external message. */
export interface SendConfirmation {
  hash?: string;
  status?: number;
}

/**
 * A SendMode enum placeholder.  Actual values come from @tos/core; this
 * keeps the interface self-contained so that @tos/client can be type-checked
 * independently.
 */
export type SendMode = number;

/** StateInit components (code + data cells). */
export interface StateInit {
  code?: CellLike | null;
  data?: CellLike | null;
}

/** Arguments for an internal send. */
export interface SenderArguments {
  to: AddressLike;
  value: bigint;
  body?: CellLike;
  sendMode?: SendMode;
  bounce?: boolean;
  init?: StateInit;
}

// ---------------------------------------------------------------------------
// ContractProvider
// ---------------------------------------------------------------------------

export interface ContractProvider {
  /** Fetch the current on-chain state (balance, code, data, status). */
  getState(): Promise<ContractState>;

  /**
   * Invoke a get-method on the contract.
   *
   * @param method - Method name or numeric id.
   * @param args   - TVM stack arguments.
   */
  get(method: string | number, args?: TupleItemLike[]): Promise<ContractGetResult>;

  /**
   * Send an internal message to this contract via the provided sender.
   *
   * @param via  - The sender (typically a wallet) that will relay the message.
   * @param args - Message parameters (destination is implicitly this contract).
   */
  internal(via: { send(args: SenderArguments): Promise<void> }, args: Omit<SenderArguments, "to">): Promise<SendConfirmation>;

  /**
   * Send an external message directly to the contract.
   *
   * @param message - The BOC-serializable message cell.
   */
  external(message: CellLike | Uint8Array | string): Promise<SendConfirmation>;
}
