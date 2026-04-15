/**
 * @tos/react — useTransactions hook.
 *
 * Infinite-scroll pagination over account transactions using the lt/hash
 * cursor from `getTransactions`.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import type { Address } from "@tos/core";
import type { Transaction } from "@tos/client";
import { TosError } from "@tos/client";
import type { InfiniteQueryResult } from "../types.js";
import { useClient } from "./useClient.js";

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/** Options for {@link useTransactions}. */
export interface UseTransactionsOptions {
  /** Number of transactions per page. Default `20`. */
  limit?: number;
  /** When `false`, the query is paused. Default `true` when address is set. */
  enabled?: boolean;
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

interface Cursor {
  lt: string;
  hash: string;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Paginated transaction history for an account.
 *
 * Returns accumulated pages and helpers for infinite scroll.
 *
 * @param address - The account address (string, Address, or null/undefined to pause).
 * @param opts    - Query options.
 * @returns An infinite query result with `data` as `Transaction[]`.
 */
export function useTransactions(
  address?: Address | string | null,
  opts?: UseTransactionsOptions,
): InfiniteQueryResult<Transaction> {
  const client = useClient();
  const addrStr = address ? String(address) : "";
  const limit = opts?.limit ?? 20;
  const enabled = (opts?.enabled ?? true) && !!address;

  const [data, setData] = useState<Transaction[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isFetchingNextPage, setIsFetchingNextPage] = useState(false);
  const [error, setError] = useState<TosError | null>(null);
  const [hasNextPage, setHasNextPage] = useState(true);

  const cursorRef = useRef<Cursor | null>(null);
  const initialFetchDone = useRef(false);

  // Reset when address changes.
  useEffect(() => {
    cursorRef.current = null;
    initialFetchDone.current = false;
    setData([]);
    setError(null);
    setHasNextPage(true);
    setIsLoading(false);
    setIsFetchingNextPage(false);
  }, [addrStr]);

  const fetchPage = useCallback(
    async (isInitial: boolean) => {
      if (!enabled) return;
      if (isInitial) {
        setIsLoading(true);
      } else {
        setIsFetchingNextPage(true);
      }
      setError(null);

      try {
        const cursor = cursorRef.current;
        const txns = await client.getTransactions(addrStr, limit, cursor ? { lt: cursor.lt, hash: cursor.hash } : undefined);

        const list = Array.isArray(txns) ? txns : [];

        if (list.length > 0) {
          const last = list[list.length - 1]!;
          cursorRef.current = {
            lt: last.transaction_id.lt,
            hash: last.transaction_id.hash,
          };
        }

        if (list.length < limit) {
          setHasNextPage(false);
        }

        setData((prev) => (isInitial ? list : [...prev, ...list]));
      } catch (err: unknown) {
        const tosErr =
          err instanceof TosError
            ? err
            : new TosError(
                err instanceof Error ? err.message : String(err),
                "QUERY_ERROR",
                err instanceof Error ? err : undefined,
              );
        setError(tosErr);
      } finally {
        setIsLoading(false);
        setIsFetchingNextPage(false);
      }
    },
    [client, addrStr, limit, enabled],
  );

  // Auto-fetch first page when enabled and not yet loaded.
  useEffect(() => {
    if (!enabled || initialFetchDone.current) return;
    initialFetchDone.current = true;
    let isCancelled = false;
    void (async () => {
      if (!isCancelled) await fetchPage(true);
    })();
    return () => { isCancelled = true; };
  }, [enabled, fetchPage]);

  const fetchNextPage = useCallback(() => {
    if (!hasNextPage || isFetchingNextPage) return;
    void fetchPage(false);
  }, [fetchPage, hasNextPage, isFetchingNextPage]);

  const refetch = useCallback(() => {
    cursorRef.current = null;
    setHasNextPage(true);
    void fetchPage(true);
  }, [fetchPage]);

  return {
    data,
    isLoading,
    isFetchingNextPage,
    error,
    hasNextPage,
    fetchNextPage,
    refetch,
  };
}
