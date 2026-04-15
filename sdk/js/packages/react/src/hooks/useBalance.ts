/**
 * @tos/react — useBalance hook.
 *
 * Fetches the account balance (in nanoTOS) as a `bigint`, with automatic
 * 10-second polling.
 */

import type { Address } from "@tos/core";
import type { QueryOptions, QueryResult } from "../types.js";
import { useClient } from "./useClient.js";
import { useQuery } from "./useQuery.js";

/** Options for {@link useBalance}. */
export interface UseBalanceOptions extends QueryOptions {
  /** Auto-refetch interval in ms. Default `10_000` (10 s). */
  refetchInterval?: number;
}

/**
 * Fetch the balance of a TOS account.
 *
 * @param address - The account address (string, Address, or null/undefined to pause).
 * @param opts    - Query options.
 * @returns A query result with `data` typed as `bigint`.
 *
 * @example
 * ```tsx
 * function Balance({ addr }: { addr: string }) {
 *   const { data, isLoading } = useBalance(addr);
 *   if (isLoading) return <span>Loading...</span>;
 *   return <span>{data?.toString()} nanoTOS</span>;
 * }
 * ```
 */
export function useBalance(
  address?: Address | string | null,
  opts?: UseBalanceOptions,
): QueryResult<bigint> {
  const client = useClient();
  const addrStr = address ? String(address) : "";
  const enabled = (opts?.enabled ?? true) && !!address;
  const refetchInterval = opts?.refetchInterval ?? 10_000;

  return useQuery<bigint>({
    queryKey: ["balance", addrStr],
    queryFn: async () => {
      const raw = await client.getBalance(addrStr);
      return BigInt(raw);
    },
    enabled,
    refetchInterval,
  });
}
