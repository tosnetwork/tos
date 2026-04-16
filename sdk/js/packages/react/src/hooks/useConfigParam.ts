/**
 * @tos/react — useConfigParam hook.
 *
 * Fetches a single blockchain configuration parameter by number.
 */

import type { QueryOptions, QueryResult } from "../types.js";
import { useClient } from "./useClient.js";
import { useQuery } from "./useQuery.js";

/** Options for {@link useConfigParam}. */
export interface UseConfigParamOptions extends QueryOptions {}

/** The shape returned by `getConfigParam`. */
export interface ConfigParamResult {
  config: { bytes: string };
}

/**
 * Fetch a blockchain configuration parameter.
 *
 * @param param - Configuration parameter number.
 * @param opts  - Query options.
 * @returns A query result with `data` typed as {@link ConfigParamResult}.
 *
 * @example
 * ```tsx
 * const { data } = useConfigParam(34); // validator set
 * ```
 */
export function useConfigParam(
  param?: number | null,
  opts?: UseConfigParamOptions,
): QueryResult<ConfigParamResult> {
  const client = useClient();
  const enabled = (opts?.enabled ?? true) && param != null;

  return useQuery<ConfigParamResult>({
    queryKey: ["configParam", String(param ?? "")],
    queryFn: () => client.getConfigParam(param!),
    enabled,
    refetchInterval: opts?.refetchInterval,
  });
}
