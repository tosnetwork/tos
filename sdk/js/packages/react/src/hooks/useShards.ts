/**
 * @tos/react — useShards hook.
 *
 * Fetches shard information for a given masterchain seqno.
 */

import type { ShardInfo } from "@tos/client";
import type { QueryOptions, QueryResult } from "../types.js";
import { useClient } from "./useClient.js";
import { useQuery } from "./useQuery.js";

/** Options for {@link useShards}. */
export interface UseShardsOptions extends QueryOptions {}

/**
 * Fetch shard information for a masterchain block.
 *
 * @param seqno - Masterchain block sequence number (or `undefined` to pause).
 * @param opts  - Query options.
 * @returns A query result with `data` typed as {@link ShardInfo}.
 *
 * @example
 * ```tsx
 * const { data: seqno } = useBlockSeqno();
 * const { data: shards } = useShards(seqno);
 * ```
 */
export function useShards(
  seqno?: number | null,
  opts?: UseShardsOptions,
): QueryResult<ShardInfo> {
  const client = useClient();
  const enabled = (opts?.enabled ?? true) && seqno != null;

  return useQuery<ShardInfo>({
    queryKey: ["shards", String(seqno ?? "")],
    queryFn: () => client.getShards(seqno!),
    enabled,
    refetchInterval: opts?.refetchInterval,
  });
}
