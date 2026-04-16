/**
 * @tos/react — useMasterchainInfo hook.
 *
 * Fetches the current masterchain info (latest block, state root hash, etc.).
 */

import type { MasterchainInfo } from "@tos/client";
import type { QueryOptions, QueryResult } from "../types.js";
import { useClient } from "./useClient.js";
import { useQuery } from "./useQuery.js";

/** Options for {@link useMasterchainInfo}. */
export interface UseMasterchainInfoOptions extends QueryOptions {}

/**
 * Fetch the current masterchain information.
 *
 * @param opts - Query options.
 * @returns A query result with `data` typed as {@link MasterchainInfo}.
 *
 * @example
 * ```tsx
 * const { data } = useMasterchainInfo();
 * if (data) console.log("Latest seqno:", data.last.seqno);
 * ```
 */
export function useMasterchainInfo(
  opts?: UseMasterchainInfoOptions,
): QueryResult<MasterchainInfo> {
  const client = useClient();
  const enabled = opts?.enabled ?? true;

  return useQuery<MasterchainInfo>({
    queryKey: ["masterchainInfo"],
    queryFn: () => client.getMasterchainInfo(),
    enabled,
    refetchInterval: opts?.refetchInterval,
  });
}
