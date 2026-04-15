/**
 * @tos/react — useAccountCapability hook.
 *
 * Fetches the account capability record via `getAccountCapability`.
 */

import type { Address } from "@tos/core";
import type { AccountCapability } from "@tos/client";
import type { QueryOptions, QueryResult } from "../types.js";
import { useClient } from "./useClient.js";
import { useQuery } from "./useQuery.js";

/** Options for {@link useAccountCapability}. */
export interface UseAccountCapabilityOptions extends QueryOptions {}

/**
 * Fetch the account capability record.
 *
 * @param address - The account address (string, Address, or null/undefined to pause).
 * @param opts    - Query options.
 * @returns A query result with `data` typed as {@link AccountCapability}.
 */
export function useAccountCapability(
  address?: Address | string | null,
  opts?: UseAccountCapabilityOptions,
): QueryResult<AccountCapability> {
  const client = useClient();
  const addrStr = address ? String(address) : "";
  const enabled = (opts?.enabled ?? true) && !!address;
  const refetchInterval = opts?.refetchInterval;

  return useQuery<AccountCapability>({
    queryKey: ["accountCapability", addrStr],
    queryFn: () => client.getAccountCapability(addrStr),
    enabled,
    refetchInterval,
  });
}
