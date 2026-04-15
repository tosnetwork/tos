/**
 * @tos/react — useAccountInfo hook.
 *
 * Fetches full account information via `getAddressInformation`, with 30-second
 * auto-refresh.
 */

import type { Address } from "@tos/core";
import type { AccountInfo } from "@tos/client";
import type { QueryOptions, QueryResult } from "../types.js";
import { useClient } from "./useClient.js";
import { useQuery } from "./useQuery.js";

/** Options for {@link useAccountInfo}. */
export interface UseAccountInfoOptions extends QueryOptions {
  /** Auto-refetch interval in ms. Default `30_000` (30 s). */
  refetchInterval?: number;
}

/**
 * Fetch full account information.
 *
 * @param address - The account address (string, Address, or null/undefined to pause).
 * @param opts    - Query options.
 * @returns A query result with `data` typed as {@link AccountInfo}.
 */
export function useAccountInfo(
  address?: Address | string | null,
  opts?: UseAccountInfoOptions,
): QueryResult<AccountInfo> {
  const client = useClient();
  const addrStr = address ? String(address) : "";
  const enabled = (opts?.enabled ?? true) && !!address;
  const refetchInterval = opts?.refetchInterval ?? 30_000;

  return useQuery<AccountInfo>({
    queryKey: ["accountInfo", addrStr],
    queryFn: () => client.getAddressInformation(addrStr),
    enabled,
    refetchInterval,
  });
}
