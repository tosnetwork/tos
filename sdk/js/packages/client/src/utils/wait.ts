/**
 * @tos/client — Transaction confirmation utilities.
 *
 * A node accepting a message (`sendQuery`, `sendBocReturnHash`) only means it
 * was queued; it says nothing about what the chain did with it. These helpers
 * find the transaction the message produced and judge it.
 *
 * ## Confirming a transfer
 *
 * ```typescript
 * const sent = await wallet.sendTransfer(signer, { messages: [...] });
 * const tx = await waitForTransfer(client, wallet.address, sent);
 * ```
 *
 * `waitForTransfer` resolves only when the transaction executed and created
 * exactly the outgoing messages the transfer carried. Otherwise it throws:
 * {@link TosNotDeliveredError} when the transaction exists but delivered
 * nothing (or less than was signed), `WAIT_TIMEOUT` when no transaction for
 * the message appeared in time.
 *
 * A wallet's seqno is not a confirmation. Wallets send their messages with
 * the ignore-errors flag (see `@tos/wallets`), so a transfer the balance
 * cannot pay still runs, charges its fee and increments the seqno while no
 * value moves; only the transaction's outgoing messages show whether it was
 * delivered.
 */

import { ErrorCodes, TosError, TosNotDeliveredError, TosRpcError } from "../errors.js";
import type { AddressLike, TosProvider } from "../provider/TosProvider.js";
import type { Transaction } from "../types.js";

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface WaitOpts {
  /** Maximum time to wait in milliseconds (default 60 000). */
  timeout?: number;
  /** Polling interval in milliseconds (default 1500). */
  pollInterval?: number;
}

/**
 * What a wallet returns for a message it sent: the hash of the external
 * message, and how many outgoing messages its transaction must create for the
 * transfer to count as delivered (0 for a deployment).
 */
export interface PendingTransfer {
  /** Hash of the external message, as `sendQuery` returned it (base64). */
  hash: string;
  /** Outgoing messages the transfer carries. */
  outMessages: number;
}

/** How many of the account's latest transactions each poll inspects. */
const TRANSACTIONS_PER_POLL = 16;

// ---------------------------------------------------------------------------
// waitForTransaction
// ---------------------------------------------------------------------------

/**
 * Poll `getTransactions` until the transaction whose inbound message is
 * `messageHash` appears, and return it without judging it.
 *
 * The hash to pass is the external message hash `sendQuery` or
 * `sendBocReturnHash` returned (not a transaction hash). It is compared as
 * bytes with each transaction's `in_msg.hash`, so base64, base64url and hex
 * spellings of the same 32 bytes all match.
 *
 * Transient failures (network errors, timeouts, server errors marked
 * retryable) are retried until the deadline; any other error is thrown at once.
 *
 * @param client      - A TosProvider (typically a TosClient instance).
 * @param address     - The account the message was sent to.
 * @param messageHash - The external message hash returned when it was sent.
 * @param opts        - Timeout and polling options.
 * @returns The transaction that consumed the message.
 * @throws {TosError} `INVALID_PARAMETER` when `messageHash` is not 32 bytes in
 *   base64 or hex; `INVALID_RESPONSE` when the node's answer is malformed;
 *   `WAIT_TIMEOUT` when the transaction does not appear in time.
 *
 * @example
 * ```typescript
 * const { hash } = await client.sendBocReturnHash(boc);
 * const tx = await waitForTransaction(client, addr, hash);
 * ```
 */
export async function waitForTransaction(
  client: TosProvider,
  address: AddressLike | string,
  messageHash: string,
  opts?: WaitOpts,
): Promise<Transaction> {
  const wanted = decodeHash(messageHash);
  if (wanted === null) {
    throw new TosError(
      `waitForTransaction: message hash ${JSON.stringify(messageHash)} is not 32 bytes in base64 or hex`,
      ErrorCodes.INVALID_PARAMETER,
    );
  }
  const timeout = opts?.timeout ?? 60_000;
  const interval = opts?.pollInterval ?? 1_500;
  const deadline = Date.now() + timeout;

  let lastFailure: Error | undefined;
  for (;;) {
    let transactions: unknown = null;
    try {
      transactions = await client.getTransactions(address, TRANSACTIONS_PER_POLL);
    } catch (err) {
      if (!isTransient(err)) throw err;
      lastFailure = err as Error;
    }
    if (transactions !== null) {
      const found = findByInboundMessage(transactions, wanted);
      if (found !== null) return found;
    }
    const remaining = deadline - Date.now();
    if (remaining <= 0) break;
    await sleep(Math.min(interval, remaining));
  }

  throw new TosError(
    `No transaction consumed message ${messageHash} within ${timeout}ms`,
    ErrorCodes.WAIT_TIMEOUT,
    lastFailure,
  );
}

// ---------------------------------------------------------------------------
// Delivery verdict
// ---------------------------------------------------------------------------

/**
 * Require that an executed transaction delivered a transfer of
 * `expectedOutMessages` outgoing messages: an ordinary, not aborted
 * transaction whose compute phase ran and succeeded (exit code 0 or 1), whose
 * action phase succeeded, and which created exactly that many outgoing
 * messages. A wallet sending with the ignore-errors flag skips a message it
 * cannot pay and still reports a successful action phase, so the count is what
 * catches an unaffordable transfer.
 *
 * @param tx                  - A transaction as `getTransactions` returned it.
 * @param expectedOutMessages - Outgoing messages the transfer carried.
 * @throws {TosNotDeliveredError} naming the first failed condition
 * @throws {TosError} `INVALID_PARAMETER` when `expectedOutMessages` is not a
 *   non-negative integer; `INVALID_RESPONSE` when the transaction has no
 *   `out_msgs` list
 */
export function requireDelivered(tx: Transaction, expectedOutMessages: number): void {
  if (!Number.isInteger(expectedOutMessages) || expectedOutMessages < 0) {
    throw new TosError(
      `requireDelivered: expectedOutMessages must be a non-negative integer, got ${expectedOutMessages}`,
      ErrorCodes.INVALID_PARAMETER,
    );
  }
  if (tx.transaction_type !== "ordinary") {
    throw new TosNotDeliveredError(
      `the transaction type is ${String(tx.transaction_type)}, not ordinary`,
      tx,
    );
  }
  if (tx.aborted !== false) {
    throw new TosNotDeliveredError(
      tx.aborted === true
        ? "the transaction aborted"
        : "the node did not report whether the transaction aborted",
      tx,
    );
  }
  const compute = tx.compute;
  if (compute == null) {
    throw new TosNotDeliveredError("the node reported no compute phase", tx);
  }
  if (compute.skipped) {
    throw new TosNotDeliveredError(
      `the compute phase was skipped (reason ${compute.skip_reason})`,
      tx,
    );
  }
  if (!compute.success || (compute.exit_code !== 0 && compute.exit_code !== 1)) {
    throw new TosNotDeliveredError(
      `the compute phase failed with exit code ${compute.exit_code}`,
      tx,
    );
  }
  const action = tx.action;
  if (action == null) {
    throw new TosNotDeliveredError("the transaction has no action phase", tx);
  }
  if (!action.success) {
    throw new TosNotDeliveredError(
      `the action phase failed with result code ${action.result_code}`,
      tx,
    );
  }
  if (!Array.isArray(tx.out_msgs)) {
    throw new TosError("the transaction carries no out_msgs list", ErrorCodes.INVALID_RESPONSE);
  }
  if (tx.out_msgs.length !== expectedOutMessages) {
    const skipped =
      action.skipped_actions > 0 ? ` (the action phase skipped ${action.skipped_actions})` : "";
    throw new TosNotDeliveredError(
      `the transfer carried ${expectedOutMessages} outgoing message(s) but the transaction created ${tx.out_msgs.length}${skipped}`,
      tx,
    );
  }
}

// ---------------------------------------------------------------------------
// waitForTransfer
// ---------------------------------------------------------------------------

/**
 * Wait for the transaction a wallet transfer (or deployment) produced and
 * require that it delivered: the confirmation to use after `sendTransfer` or
 * `sendDeploy`. See {@link requireDelivered} for what "delivered" means.
 *
 * @param client  - A TosProvider (typically a TosClient instance).
 * @param address - The wallet address.
 * @param sent    - What `sendTransfer` / `sendDeploy` returned.
 * @param opts    - Timeout and polling options.
 * @returns The delivered transaction.
 * @throws {TosNotDeliveredError} when the transaction executed but did not deliver
 * @throws {TosError} `WAIT_TIMEOUT` when no transaction for the message appeared in time
 *
 * @example
 * ```typescript
 * const sent = await wallet.sendTransfer(signer, { messages: [{ to, value }] });
 * await waitForTransfer(client, wallet.address, sent);
 * ```
 */
export async function waitForTransfer(
  client: TosProvider,
  address: AddressLike | string,
  sent: PendingTransfer,
  opts?: WaitOpts,
): Promise<Transaction> {
  if (!Number.isInteger(sent.outMessages) || sent.outMessages < 0) {
    throw new TosError(
      `waitForTransfer: outMessages must be a non-negative integer, got ${sent.outMessages}`,
      ErrorCodes.INVALID_PARAMETER,
    );
  }
  const tx = await waitForTransaction(client, address, sent.hash, opts);
  requireDelivered(tx, sent.outMessages);
  return tx;
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

function findByInboundMessage(transactions: unknown, wanted: Uint8Array): Transaction | null {
  if (!Array.isArray(transactions)) {
    throw new TosError("getTransactions did not return an array", ErrorCodes.INVALID_RESPONSE);
  }
  for (const tx of transactions as Array<Transaction | null | undefined>) {
    const inbound = tx?.in_msg;
    // A transaction without an inbound message (tick-tock), or one whose
    // message the node could not render, cannot be the one being looked for.
    if (tx == null || inbound == null || inbound.hash === undefined) continue;
    const hash = decodeHash(inbound.hash);
    if (hash === null) {
      throw new TosError(
        `getTransactions returned an in_msg.hash that is not 32 bytes: ${JSON.stringify(inbound.hash)}`,
        ErrorCodes.INVALID_RESPONSE,
      );
    }
    if (bytesEqual(hash, wanted)) return tx;
  }
  return null;
}

/** A failure worth polling through: transport trouble or a retryable server error. */
function isTransient(err: unknown): boolean {
  if (err instanceof TosRpcError) return err.retryable;
  if (err instanceof TosError) {
    return (
      err.code === ErrorCodes.NETWORK_ERROR ||
      err.code === ErrorCodes.TIMEOUT ||
      err.code === ErrorCodes.RETRY_EXHAUSTED
    );
  }
  return false;
}

const BASE64_32 = /^[A-Za-z0-9+/_-]{43}=?$/;
const HEX_32 = /^[0-9a-fA-F]{64}$/;

/** Decode a 32-byte hash spelled in hex, base64 or base64url; null otherwise. */
function decodeHash(value: unknown): Uint8Array | null {
  if (typeof value !== "string") return null;
  const bytes = new Uint8Array(32);
  if (HEX_32.test(value)) {
    for (let i = 0; i < 32; i++) {
      bytes[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }
  if (!BASE64_32.test(value)) return null;
  let binary: string;
  try {
    binary = atob(`${value.replace(/-/g, "+").replace(/_/g, "/").replace(/=$/, "")}=`);
  } catch {
    return null;
  }
  if (binary.length !== 32) return null;
  for (let i = 0; i < 32; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
