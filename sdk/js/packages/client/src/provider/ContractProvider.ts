/**
 * @tos/client — ContractProvider interface.
 *
 * This is the per-contract adapter that the `open()` function injects as the
 * first argument to contract methods.  It mirrors the standard provider shape
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

/** Confirmation returned after sending an internal message. */
export interface SendConfirmation {
  hash?: string;
  status?: number;
}

/**
 * What the node returned for an accepted external message: its hash, which a
 * transaction's `in_msg.hash` will equal once the chain executes it.
 * Acceptance is not settlement; see `waitForTransaction`.
 */
export interface ExternalSendResult {
  hash: string;
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
   * Resolves only when the method ran and exited successfully (0 or 1); the
   * stack of a failed run is never handed out.
   *
   * @param method - Method name or numeric id.
   * @param args   - TVM stack arguments.
   * @throws TosNotDeployedError when the account is not active (exit code -256)
   * @throws TosContractError when the method exits with any other code
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
   * @returns The external message hash the node accepted.
   */
  external(message: CellLike | Uint8Array | string): Promise<ExternalSendResult>;
}
