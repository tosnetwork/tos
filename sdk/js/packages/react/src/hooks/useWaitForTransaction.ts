/**
 * @tos/react — useWaitForTransaction hook.
 *
 * Polls the chain until a transaction with the given hash appears.
 * Internally uses the `waitForTransaction` utility from `@tos/client`.
 */

import { waitForTransaction } from "@tos/client";
import type { QueryOptions, QueryResult } from "../types.js";
import { useClient } from "./useClient.js";
import { useQuery } from "./useQuery.js";

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/** Options for {@link useWaitForTransaction}. */
export interface UseWaitForTransactionOptions extends QueryOptions {
  /** The account address to poll. Required when `hash` is provided. */
  address?: string;
  /** Maximum wait time in ms. Default `60_000` (60 s). */
  timeout?: number;
  /** Poll interval in ms. Default `1_500` (1.5 s). */
  pollInterval?: number;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Wait for a transaction to appear on-chain.
 *
 * The query is automatically enabled when both `hash` and `address` are
 * provided. Once the transaction is found it is cached and polling stops.
 *
 * @param hash - Base64-encoded transaction hash (or `undefined` to pause).
 * @param opts - Query and wait options.
 * @returns A query result with `data` typed as `unknown` (raw transaction object).
 */
export function useWaitForTransaction(
  hash?: string | null,
  opts?: UseWaitForTransactionOptions,
): QueryResult<unknown> {
  const client = useClient();
  const address = opts?.address ?? "";
  const timeout = opts?.timeout ?? 60_000;
  const pollInterval = opts?.pollInterval ?? 1_500;
  const enabled = (opts?.enabled ?? true) && !!hash && !!address;

  return useQuery<unknown>({
    queryKey: ["waitForTransaction", address, hash ?? ""],
    queryFn: () =>
      waitForTransaction(client, address, hash!, { timeout, pollInterval }),
    enabled,
    // No auto-refetch — the queryFn itself polls internally.
    refetchInterval: undefined,
  });
}
