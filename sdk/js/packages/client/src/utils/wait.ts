/**
 * @tos/client — Transaction confirmation utilities.
 *
 * These helpers poll the chain until a specific condition is met, useful for
 * waiting until a sent transaction is confirmed.
 */

import type { TosProvider, AddressLike } from "../provider/TosProvider.js";
import { TosError, ErrorCodes } from "../errors.js";

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

export interface WaitOpts {
  /** Maximum time to wait in milliseconds (default 60 000). */
  timeout?: number;
  /** Polling interval in milliseconds (default 1500). */
  pollInterval?: number;
}

// ---------------------------------------------------------------------------
// waitForTransaction
// ---------------------------------------------------------------------------

/**
 * Poll `getTransactions` until a transaction with the given hash appears.
 *
 * @param client  - A TosProvider (typically a TosClient instance).
 * @param address - The account address to query.
 * @param hash    - The base64-encoded transaction hash to look for.
 * @param opts    - Timeout and polling options.
 * @returns The matching transaction data.
 * @throws {TosError} with code `WAIT_TIMEOUT` if the transaction is not found in time
 *
 * @example
 * ```typescript
 * const result = await client.sendBocReturnHash(boc);
 * const tx = await waitForTransaction(client, addr, result.hash);
 * ```
 */
export async function waitForTransaction(
  client: TosProvider,
  address: AddressLike | string,
  hash: string,
  opts?: WaitOpts,
): Promise<unknown> {
  const timeout = opts?.timeout ?? 60_000;
  const interval = opts?.pollInterval ?? 1_500;
  const deadline = Date.now() + timeout;

  while (Date.now() < deadline) {
    try {
      const result = await client.getTransactions(address, 10);
      // C++ RPC may return a raw array or a { transactions: [...] } wrapper
      const txns = Array.isArray(result) ? result : ((result as unknown as Record<string, unknown>).transactions as unknown[] ?? []);
      const found = (txns as Array<Record<string, unknown>>).find(
        (tx) => (tx.transaction_id as Record<string, unknown>)?.hash === hash,
      );
      if (found) return found;
    } catch {
      // Ignore transient errors and keep polling.
    }
    const remaining = deadline - Date.now();
    if (remaining <= 0) break;
    await sleep(Math.min(interval, remaining));
  }

  throw new TosError(
    `Transaction ${hash} not found within ${timeout}ms`,
    ErrorCodes.WAIT_TIMEOUT,
  );
}

// ---------------------------------------------------------------------------
// waitForSeqnoChange
// ---------------------------------------------------------------------------

/**
 * Poll a wallet's seqno until it changes from `currentSeqno`.
 *
 * This is the simplest way to wait for an outgoing transfer to be confirmed:
 * read the seqno before sending, send the message, then call this function.
 *
 * @param client       - A TosProvider (typically a TosClient instance).
 * @param address      - The wallet address.
 * @param currentSeqno - The seqno value before the transfer was sent.
 * @param opts         - Timeout and polling options.
 * @returns The new seqno once it changes.
 * @throws {TosError} with code `WAIT_TIMEOUT` if the seqno does not change in time
 *
 * @example
 * ```typescript
 * const seqno = await wallet.getSeqno();
 * await wallet.sendTransfer(signer, { messages: [...] });
 * const newSeqno = await waitForSeqnoChange(client, wallet.address, seqno);
 * ```
 */
export async function waitForSeqnoChange(
  client: TosProvider,
  address: AddressLike | string,
  currentSeqno: number,
  opts?: WaitOpts,
): Promise<number> {
  const timeout = opts?.timeout ?? 60_000;
  const interval = opts?.pollInterval ?? 1_500;
  const deadline = Date.now() + timeout;

  while (Date.now() < deadline) {
    try {
      const info = await client.getWalletInformation(address);
      if (info.seqno != null && info.seqno !== currentSeqno) {
        return info.seqno;
      }
    } catch {
      // Ignore transient errors and keep polling.
    }
    const remaining = deadline - Date.now();
    if (remaining <= 0) break;
    await sleep(Math.min(interval, remaining));
  }

  throw new TosError(
    `Seqno did not change from ${currentSeqno} within ${timeout}ms`,
    ErrorCodes.WAIT_TIMEOUT,
  );
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
