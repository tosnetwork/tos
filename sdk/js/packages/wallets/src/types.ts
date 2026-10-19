/**
 * Wallet-specific types for the @tos/wallets package.
 *
 * These types define the interface that all wallet contract implementations
 * must satisfy, as well as the argument shapes for creating and sending
 * transfers.
 */

import type {
  Address,
  Cell,
  Contract,
  StateInit,
  SendMode,
} from "@tos/core";
import type {
  ContractProvider,
  Signer,
  PendingTransfer,
} from "@tos/client";

// ---------------------------------------------------------------------------
// Outgoing message descriptor
// ---------------------------------------------------------------------------

/**
 * Describes a single outgoing internal message to be included in
 * a wallet transfer.
 */
export interface OutMessage {
  /** Destination address. */
  to: Address;
  /** Value to transfer in nanoTOS. */
  value: bigint;
  /** Optional message body cell. */
  body?: Cell;
  /** Whether the message should bounce on failure (default true). */
  bounce?: boolean;
  /** Optional StateInit for deploying the destination contract. */
  init?: StateInit;
  /**
   * Send mode flags. Defaults to the transfer's `sendMode`, else
   * PAY_GAS_SEPARATELY | IGNORE_ERRORS (3). With IGNORE_ERRORS a message the
   * wallet cannot pay is skipped while the transaction still succeeds; confirm
   * with `waitForTransfer`, which detects the missing outgoing message.
   */
  mode?: SendMode;
}

// ---------------------------------------------------------------------------
// Transfer argument types
// ---------------------------------------------------------------------------

/**
 * Arguments for building a transfer body cell synchronously.
 * The caller provides the seqno and (optionally) validUntil.
 */
export interface CreateTransferArgs {
  /** Current sequence number of the wallet. */
  seqno: number;
  /** List of outgoing messages (up to 4 for V3R2/V4R2, 255 for V5R1). */
  messages: OutMessage[];
  /**
   * UNIX time (seconds) after which the wallet refuses the message. Defaults
   * to now + 60 s; a value not after the current time is refused before signing.
   */
  validUntil?: number;
  /** Ed25519 secret key (64 bytes) used to sign the transfer body. */
  secretKey: Uint8Array;
  /** Send mode for every message that sets no `mode` of its own (default 3). */
  sendMode?: SendMode;
}

/**
 * Arguments for building a transfer body cell asynchronously.
 * Same as CreateTransferArgs but the secret key may be provided via
 * an async signer callback.
 */
export interface CreateTransferAsyncArgs {
  /** Current sequence number of the wallet. */
  seqno: number;
  /** List of outgoing messages. */
  messages: OutMessage[];
  /**
   * UNIX time (seconds) after which the wallet refuses the message. Defaults
   * to now + 60 s; a value not after the current time is refused before signing.
   */
  validUntil?: number;
  /** Async signing function: receives the hash to sign, returns 64-byte signature. */
  signer: (message: Uint8Array) => Promise<Uint8Array>;
  /** Send mode for every message that sets no `mode` of its own (default 3). */
  sendMode?: SendMode;
}

/**
 * Arguments for the high-level sendTransfer method that queries seqno,
 * builds, signs, and submits the transfer via a ContractProvider.
 */
export interface SendTransferArgs {
  /** List of outgoing messages. */
  messages: OutMessage[];
  /**
   * UNIX time (seconds) after which the wallet refuses the message. Defaults
   * to now + 60 s; a value not after the current time is refused before signing.
   */
  validUntil?: number;
  /** Send mode for every message that sets no `mode` of its own (default 3). */
  sendMode?: SendMode;
}

// ---------------------------------------------------------------------------
// Wallet interface
// ---------------------------------------------------------------------------

/**
 * The Wallet interface extends the base Contract and adds the methods
 * that all wallet contract implementations must provide.
 */
export interface Wallet extends Contract {
  /**
   * Query the on-chain sequence number.
   *
   * @throws TosNotDeployedError when the wallet is not deployed
   */
  getSeqno(provider: ContractProvider): Promise<number>;

  /**
   * Query the on-chain balance in nanoTOS.
   */
  getBalance(provider: ContractProvider): Promise<bigint>;

  /**
   * Query the on-chain public key (32 bytes).
   */
  getPublicKey(provider: ContractProvider): Promise<Uint8Array>;

  /**
   * Build and sign a transfer body cell synchronously.
   * Returns the complete external message body (signature + payload).
   */
  createTransfer(args: CreateTransferArgs): Cell;

  /**
   * Build and sign a transfer body cell asynchronously
   * (e.g. when using a hardware wallet signer).
   */
  createTransferAsync(args: CreateTransferAsyncArgs): Promise<Cell>;

  /**
   * High-level: query seqno and balance, build, sign, and submit a transfer.
   *
   * Refuses before signing when the wallet is not deployed, when the message
   * values are not below the balance, or when `validUntil` is not in the
   * future. The result only means the node accepted the message; pass it to
   * `waitForTransfer` to learn whether the transfer was delivered.
   *
   * A never-deployed wallet has no seqno to read, so this throws
   * `TosNotDeployedError` for it: its first message must be signed with seqno
   * 0 and carry the StateInit, which is what `sendDeploy` sends. Deploy first,
   * confirm with `waitForTransfer`, then transfer.
   */
  sendTransfer(
    provider: ContractProvider,
    via: Signer,
    args: SendTransferArgs,
  ): Promise<PendingTransfer>;

  /**
   * Deploy the wallet contract on-chain. Returns the external message hash
   * with no outgoing messages expected; pass it to `waitForTransfer`.
   */
  sendDeploy(
    provider: ContractProvider,
    via: Signer,
    value: bigint,
  ): Promise<PendingTransfer>;
}
