/**
 * @tos/react — useEstimateFee hook.
 *
 * Estimates the fee for sending a message without broadcasting it.
 */

import type { Address, Cell } from "@tos/core";
import type { FeeEstimate } from "@tos/client";
import type { QueryOptions, QueryResult } from "../types.js";
import { useClient } from "./useClient.js";
import { useQuery } from "./useQuery.js";

// ---------------------------------------------------------------------------
// Args
// ---------------------------------------------------------------------------

/** Arguments for {@link useEstimateFee}. */
export interface UseEstimateFeeArgs {
  /** Target contract address. */
  address: Address | string;
  /** Message body (Cell or base64 string). */
  body: Cell | string;
  /** Optional deploy init code. */
  initCode?: Cell | string;
  /** Optional deploy init data. */
  initData?: Cell | string;
  /** Whether to skip signature verification. */
  ignoreChksig?: boolean;
}

/** Options for {@link useEstimateFee}. */
export interface UseEstimateFeeOptions extends QueryOptions {}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Estimate the fee for a message.
 *
 * @param args - Fee estimation arguments.
 * @param opts - Query options.
 * @returns A query result with `data` typed as {@link FeeEstimate}.
 */
export function useEstimateFee(
  args?: UseEstimateFeeArgs | null,
  opts?: UseEstimateFeeOptions,
): QueryResult<FeeEstimate> {
  const client = useClient();
  const addrStr = args?.address ? String(args.address) : "";
  const bodyStr = args?.body ? String(args.body) : "";
  const enabled = (opts?.enabled ?? true) && !!args?.address && !!args?.body;

  return useQuery<FeeEstimate>({
    queryKey: ["estimateFee", addrStr, bodyStr],
    queryFn: () =>
      client.estimateFee(
        args!.address,
        args!.body,
        args!.initCode,
        args!.initData,
        args!.ignoreChksig,
      ),
    enabled,
    refetchInterval: opts?.refetchInterval,
  });
}
