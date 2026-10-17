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
 * `waitForTransfer` resolves only when the wallet's transaction executed and
 * created exactly the outgoing messages the transfer carried. Otherwise:
 *
 * - {@link TosNotDeliveredError}: the transaction exists but did not deliver
 *   everything that was signed. Some messages may still have left; the error
 *   lists them in `createdMessages`. Resend only the missing ones.
 * - `WAIT_TIMEOUT`: no transaction for the message was found in time. The
 *   outcome is unknown: the message may still be executed until its
 *   `validUntil`. Do not resend before `validUntil` has passed; then look again
 *   (a late transaction is still found), and only resend if there is none.
 *
 * A wallet's seqno is not a confirmation. Wallets send their messages with
 * the ignore-errors flag (see `@tos/wallets`), so a transfer the balance
 * cannot pay still runs, charges its fee and increments the seqno while no
 * value moves; only the transaction's outgoing messages show whether it was
 * delivered.
 *
 * ## What "delivered" covers
 *
 * Delivered means the value left the sender: the wallet's own transaction
 * created the messages. It does not mean the recipient kept it. Each
 * outgoing message is executed later in the recipient's own transaction, and
 * a bounceable message (the default) to an address that cannot take it, for
 * example one that is not deployed, comes back to the wallet as a bounced
 * message, less fees, when the recipient's transaction can still pay for
 * it. To follow a message to the recipient, pass it to {@link waitForReceipt}:
 *
 * ```typescript
 * const tx = await waitForTransfer(client, wallet.address, sent);
 * for (const message of tx.out_msgs) {
 *   const { transaction, bounce } = await waitForReceipt(client, message);
 *   // bounce: the bounced message the recipient actually sent back, or null
 * }
 * ```
 */

import { ErrorCodes, TosError, TosNotDeliveredError, TosRpcError } from "../errors.js";
import type { AddressLike, TosProvider } from "../provider/TosProvider.js";
import type { MessageSummary, Transaction } from "../types.js";

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface WaitOpts {
  /** Maximum time to wait in milliseconds (default 60 000). */
  timeout?: number;
  /** Polling interval in milliseconds (default 1500). */
  pollInterval?: number;
  /**
   * The logical time of the account's last transaction before the message was
   * sent (decimal string). Only transactions after it (lt strictly greater)
   * can match: an earlier transaction for an identical message, such as a
   * previous attempt of the same signed transfer, is never returned. Each poll
   * pages back through the account's history until it reaches that
   * transaction, so transactions arriving in between cannot push the one
   * looked for out of view. Without it, each poll looks at most
   * {@link MAX_TRANSACTIONS_PER_POLL} transactions back and any matching
   * transaction counts.
   */
  afterLt?: string;
}

/**
 * What a wallet returns for a message it sent: the hash of the external
 * message, how many outgoing messages its transaction must create for the
 * transfer to count as delivered (0 for a deployment), and where in the
 * wallet's history to stop looking for it.
 */
export interface PendingTransfer {
  /** Hash of the external message, as `sendQuery` returned it (base64). */
  hash: string;
  /** Outgoing messages the transfer carries. */
  outMessages: number;
  /** The wallet's last transaction lt read before sending, when known. */
  afterLt?: string;
}

/** How many transactions each `getTransactions` page asks for. */
const PAGE_SIZE = 16;

/** The most transactions one poll pages back through. */
export const MAX_TRANSACTIONS_PER_POLL = 1024;

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
 * Each poll pages back from the newest transaction until it reaches
 * `opts.afterLt` (or the start of the account's history, or
 * {@link MAX_TRANSACTIONS_PER_POLL} transactions). The timeout bounds the
 * whole call, the history scan and each request included.
 *
 * Transient failures (network errors, timeouts, server errors marked
 * retryable) are retried until the deadline; any other error is thrown at once.
 *
 * @param client      - A TosProvider (typically a TosClient instance).
 * @param address     - The account the message was sent to.
 * @param messageHash - The external message hash returned when it was sent.
 * @param opts        - Timeout, polling and paging options.
 * @returns The transaction that consumed the message.
 * @throws {TosError} `INVALID_PARAMETER` when `messageHash` is not 32 bytes in
 *   base64 or hex or `afterLt` is not a decimal lt; `INVALID_RESPONSE` when the
 *   node's answer is malformed; `WAIT_TIMEOUT` when no transaction was found
 *   in time. A timeout means the outcome is unknown, not that the message
 *   failed: it may still execute until its `validUntil`, so do not resend it
 *   before then.
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
  const afterLt = opts?.afterLt === undefined ? null : parseLt(opts.afterLt);
  if (afterLt === undefined) {
    throw new TosError(
      `waitForTransaction: afterLt ${JSON.stringify(opts?.afterLt)} is not a decimal lt`,
      ErrorCodes.INVALID_PARAMETER,
    );
  }
  const timeout = opts?.timeout ?? 60_000;
  const interval = opts?.pollInterval ?? 1_500;
  const deadline = Date.now() + timeout;

  let lastFailure: Error | undefined;
  for (;;) {
    try {
      const found = await searchHistory(client, address, wanted, afterLt, deadline);
      if (found !== null) return found;
    } catch (err) {
      if (!isTransient(err)) throw err;
      lastFailure = err as Error;
    }
    const remaining = deadline - Date.now();
    if (remaining <= 0) break;
    await sleep(Math.min(interval, remaining));
  }

  throw new TosError(
    `No transaction consumed message ${messageHash} within ${timeout}ms; the outcome is unknown and the message may still execute until its validUntil, so do not resend it before then`,
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
 * This judges the sender's transaction only: it says the value left the
 * wallet, not that the recipient kept it (see {@link waitForReceipt}).
 *
 * @param tx                  - A transaction as `getTransactions` returned it.
 * @param expectedOutMessages - Outgoing messages the transfer carried.
 * @throws {TosNotDeliveredError} naming the first failed condition, with the
 *   messages that did leave in `createdMessages`
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
 * `sendDeploy`. See {@link requireDelivered} for what "delivered" means. The
 * search pages back to `sent.afterLt` unless `opts.afterLt` is given.
 *
 * @param client  - A TosProvider (typically a TosClient instance).
 * @param address - The wallet address.
 * @param sent    - What `sendTransfer` / `sendDeploy` returned.
 * @param opts    - Timeout, polling and paging options.
 * @returns The delivered transaction.
 * @throws {TosNotDeliveredError} when the transaction executed but did not
 *   deliver everything; `createdMessages` lists what did leave
 * @throws {TosError} `WAIT_TIMEOUT` when no transaction for the message
 *   appeared in time: outcome unknown, do not resend before `validUntil`
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
  const afterLt = opts?.afterLt ?? sent.afterLt;
  const tx = await waitForTransaction(client, address, sent.hash, {
    ...opts,
    ...(afterLt === undefined ? {} : { afterLt }),
  });
  requireDelivered(tx, sent.outMessages);
  return tx;
}

// ---------------------------------------------------------------------------
// waitForReceipt
// ---------------------------------------------------------------------------

/**
 * Follow an outgoing message (an entry of a transaction's `out_msgs`) to the
 * transaction that executed it on the recipient's account, and return that
 * transaction without judging it.
 *
 * Whether the value came back is only shown by an actual bounced message:
 * `bounce` is the outgoing message of the recipient's transaction marked
 * `bounced: true`, or null when it sent none. Do not infer it from the
 * transaction's state. `aborted` alone proves neither a bounce nor a refund:
 * a recipient whose action phase failed without bounce-on-failure keeps the
 * value although the transaction aborted, and a failed compute phase can
 * leave too little to pay for a bounce, so none is created. A non-bounceable
 * message is never bounced.
 *
 * @param client  - A TosProvider (typically a TosClient instance).
 * @param message - The internal message, as `out_msgs` lists it.
 * @param opts    - Timeout, polling and paging options.
 * @returns The recipient's transaction for the message and the bounced
 *   message it sent back, if any.
 * @throws {TosError} `INVALID_PARAMETER` when the message is not an internal
 *   message with a destination and a hash; `WAIT_TIMEOUT` when it is not found
 *   in time
 */
export async function waitForReceipt(
  client: TosProvider,
  message: MessageSummary,
  opts?: WaitOpts,
): Promise<Receipt> {
  if (
    message?.kind !== "internal" ||
    typeof message.destination !== "string" ||
    message.destination.length === 0 ||
    typeof message.hash !== "string"
  ) {
    throw new TosError(
      "waitForReceipt: the message must be an internal message with a destination and a hash",
      ErrorCodes.INVALID_PARAMETER,
    );
  }
  const transaction = await waitForTransaction(client, message.destination, message.hash, opts);
  if (!Array.isArray(transaction.out_msgs)) {
    throw new TosError(
      "the receipt transaction carries no out_msgs list",
      ErrorCodes.INVALID_RESPONSE,
    );
  }
  const bounce =
    transaction.out_msgs.find((out) => out?.kind === "internal" && out.bounced === true) ?? null;
  return { transaction, bounce };
}

/** The recipient's side of a message, as {@link waitForReceipt} returns it. */
export interface Receipt {
  /** The transaction that executed the message on the recipient's account. */
  transaction: Transaction;
  /** The bounced message that transaction sent back, or null when it sent none. */
  bounce: MessageSummary | null;
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

/**
 * One poll: page back from the newest transaction until the message is found,
 * the page reaches `afterLt`, the history ends, or the per-poll bound is hit.
 */
async function searchHistory(
  client: TosProvider,
  address: AddressLike | string,
  wanted: Uint8Array,
  afterLt: bigint | null,
  deadline: number,
): Promise<Transaction | null> {
  let cursor: { lt: string; hash: string } | null = null;
  let seen = 0;
  while (seen < MAX_TRANSACTIONS_PER_POLL) {
    const page: unknown = await beforeDeadline(
      client.getTransactions(
        address,
        PAGE_SIZE,
        cursor === null ? undefined : { lt: cursor.lt, hash: cursor.hash },
      ),
      deadline,
    );
    if (!Array.isArray(page)) {
      throw new TosError("getTransactions did not return an array", ErrorCodes.INVALID_RESPONSE);
    }
    // A page that starts at the cursor repeats the cursor's transaction first.
    const fresh = (page as Array<Transaction | null | undefined>).filter(
      (tx) => cursor === null || tx?.transaction_id?.lt !== cursor.lt,
    );
    // Only transactions strictly after afterLt may match: an older one for an
    // identical message is a previous attempt, not this one.
    const candidates = afterLt === null ? fresh : fresh.filter((tx) => requireLt(tx) > afterLt);
    const found = findByInboundMessage(candidates, wanted);
    if (found !== null) return found;
    seen += fresh.length;
    if (fresh.length === 0 || page.length < PAGE_SIZE) return null;
    const oldest = fresh[fresh.length - 1];
    const oldestLt = requireLt(oldest);
    const oldestHash = oldest?.transaction_id?.hash;
    if (typeof oldestHash !== "string") {
      throw new TosError(
        "getTransactions returned a transaction without a valid transaction_id",
        ErrorCodes.INVALID_RESPONSE,
      );
    }
    if (afterLt !== null && oldestLt <= afterLt) return null;
    cursor = { lt: oldestLt.toString(), hash: oldestHash };
  }
  return null;
}

function findByInboundMessage(
  transactions: Array<Transaction | null | undefined>,
  wanted: Uint8Array,
): Transaction | null {
  for (const tx of transactions) {
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

/** A transaction's lt; a transaction without a valid one is a malformed answer. */
function requireLt(tx: Transaction | null | undefined): bigint {
  const lt = parseLt(tx?.transaction_id?.lt);
  if (lt === undefined) {
    throw new TosError(
      "getTransactions returned a transaction without a valid transaction_id",
      ErrorCodes.INVALID_RESPONSE,
    );
  }
  return lt;
}

/**
 * Settle with `request`, or fail with a transient `TIMEOUT` once `deadline`
 * passes, so a slow node cannot hold the call past its timeout.
 */
function beforeDeadline<T>(request: Promise<T>, deadline: number): Promise<T> {
  const remaining = deadline - Date.now();
  const expired = () =>
    new TosError("the wait deadline passed during a request", ErrorCodes.TIMEOUT);
  if (remaining <= 0) {
    request.catch(() => undefined);
    return Promise.reject(expired());
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(expired()), remaining);
  });
  // The abandoned request may still fail later; that is not an unhandled error.
  request.catch(() => undefined);
  return Promise.race([request, timeout]).finally(() => clearTimeout(timer));
}

/** A logical time as a decimal string; undefined when it is not one. */
function parseLt(value: unknown): bigint | undefined {
  if (typeof value !== "string" || !/^[0-9]{1,20}$/.test(value)) return undefined;
  return BigInt(value);
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
