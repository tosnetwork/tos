/**
 * @tos/react — useBlockSeqno hook.
 *
 * Returns the latest masterchain block sequence number, auto-refreshing
 * every 5 seconds.
 */

import type { QueryOptions, QueryResult } from "../types.js";
import { useClient } from "./useClient.js";
import { useQuery } from "./useQuery.js";

/** Options for {@link useBlockSeqno}. */
export interface UseBlockSeqnoOptions extends QueryOptions {
  /** Auto-refetch interval in ms. Default `5_000` (5 s). */
  refetchInterval?: number;
}

/**
 * Fetch the latest masterchain block seqno.
 *
 * @param opts - Query options.
 * @returns A query result with `data` typed as `number`.
 *
 * @example
 * ```tsx
 * const { data: seqno } = useBlockSeqno();
 * ```
 */
export function useBlockSeqno(
  opts?: UseBlockSeqnoOptions,
): QueryResult<number> {
  const client = useClient();
  const enabled = opts?.enabled ?? true;
  const refetchInterval = opts?.refetchInterval ?? 5_000;

  return useQuery<number>({
    queryKey: ["blockSeqno"],
    queryFn: async () => {
      const info = await client.getMasterchainInfo();
      return info.last.seqno;
    },
    enabled,
    refetchInterval,
  });
}
