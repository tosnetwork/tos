/**
 * @tos/react — useTokenData hook.
 *
 * Fetches general token data via `getTokenData` (supports Jetton masters,
 * NFT collections, NFT items, and Jetton wallets).
 */

import type { Address } from "@tos/core";
import type { TokenData } from "@tos/client";
import type { QueryOptions, QueryResult } from "../types.js";
import { useClient } from "./useClient.js";
import { useQuery } from "./useQuery.js";

/** Options for {@link useTokenData}. */
export interface UseTokenDataOptions extends QueryOptions {
  /** Auto-refetch interval in ms. Default `60_000` (60 s). */
  refetchInterval?: number;
}

/**
 * Fetch token data for a contract address.
 *
 * The returned data type is a discriminated union — check `data["@type"]` to
 * determine whether it is a Jetton master, Jetton wallet, NFT item, or NFT
 * collection.
 *
 * @param address - The token contract address.
 * @param opts    - Query options.
 * @returns A query result with `data` typed as {@link TokenData}.
 */
export function useTokenData(
  address?: Address | string | null,
  opts?: UseTokenDataOptions,
): QueryResult<TokenData> {
  const client = useClient();
  const addrStr = address ? String(address) : "";
  const enabled = (opts?.enabled ?? true) && !!address;
  const refetchInterval = opts?.refetchInterval ?? 60_000;

  return useQuery<TokenData>({
    queryKey: ["tokenData", addrStr],
    queryFn: () => client.getTokenData(addrStr),
    enabled,
    refetchInterval,
  });
}
