/**
 * @tos/react — useJettonBalance hook.
 *
 * Convenience hook that wraps {@link useContractRead} with the standard
 * `get_wallet_data` get-method to fetch a Jetton wallet balance.
 */

import type { Address } from "@tos/core";
import type { QueryOptions, QueryResult } from "../types.js";
import { useContractRead } from "./useContractRead.js";

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/** Arguments for {@link useJettonBalance}. */
export interface UseJettonBalanceArgs {
  /** Jetton wallet contract address (NOT the Jetton master address). */
  address: Address | string;
}

/** Options for {@link useJettonBalance}. */
export interface UseJettonBalanceOptions extends QueryOptions {}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Fetch the Jetton balance from a Jetton wallet contract.
 *
 * Calls `get_wallet_data` and reads the first stack element (balance) as a
 * `bigint`.
 *
 * @param args - Jetton wallet arguments.
 * @param opts - Query options.
 * @returns A query result with `data` typed as `bigint`.
 *
 * @example
 * ```tsx
 * const { data: jettonBalance } = useJettonBalance({ address: myJettonWallet });
 * ```
 */
export function useJettonBalance(
  args?: UseJettonBalanceArgs | null,
  opts?: UseJettonBalanceOptions,
): QueryResult<bigint> {
  return useContractRead<bigint>(
    args?.address
      ? {
          address: args.address,
          method: "get_wallet_data",
          parse: (stack) => stack.readBigNumber(),
        }
      : null,
    {
      enabled: opts?.enabled,
      refetchInterval: opts?.refetchInterval,
    },
  );
}
