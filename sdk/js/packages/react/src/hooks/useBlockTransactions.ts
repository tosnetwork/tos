/**
 * @tos/react — useBlockTransactions hook.
 *
 * Fetches transactions within a specific block identified by workchain, shard,
 * and seqno.
 */

import type { BlockTransactions } from "@tos/client";
import type { QueryOptions, QueryResult } from "../types.js";
import { useClient } from "./useClient.js";
import { useQuery } from "./useQuery.js";

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/** Options for {@link useBlockTransactions}. */
export interface UseBlockTransactionsOptions extends QueryOptions {
  /** Maximum number of transactions to return. Default `40`. */
  count?: number;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Fetch transactions in a specific block.
 *
 * @param workchain - Block workchain (-1 for masterchain, 0 for basechain).
 * @param shard     - Block shard identifier.
 * @param seqno     - Block sequence number.
 * @param opts      - Query options.
 * @returns A query result with `data` typed as {@link BlockTransactions}.
 *
 * @example
 * ```tsx
 * const { data } = useBlockTransactions(-1, "-9223372036854775808", 12345);
 * ```
 */
export function useBlockTransactions(
  workchain?: number | null,
  shard?: string | null,
  seqno?: number | null,
  opts?: UseBlockTransactionsOptions,
): QueryResult<BlockTransactions> {
  const client = useClient();
  const count = opts?.count ?? 40;
  const enabled =
    (opts?.enabled ?? true) &&
    workchain != null &&
    shard != null &&
    seqno != null;

  return useQuery<BlockTransactions>({
    queryKey: [
      "blockTransactions",
      String(workchain ?? ""),
      shard ?? "",
      String(seqno ?? ""),
      String(count),
    ],
    queryFn: () => client.getBlockTransactions(workchain!, shard!, seqno!, { count }),
    enabled,
    refetchInterval: opts?.refetchInterval,
  });
}
