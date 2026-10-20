/**
 * @tos/react — useTokenBalance hook.
 *
 * Convenience hook that wraps {@link useContractRead} with the standard
 * `get_wallet_data` get-method to fetch a Token wallet balance.
 */

import type { Address } from "@tos/core";
import type { QueryOptions, QueryResult } from "../types.js";
import { useContractRead } from "./useContractRead.js";

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/** Arguments for {@link useTokenBalance}. */
export interface UseTokenBalanceArgs {
  /** Token wallet contract address (NOT the Token master address). */
  address: Address | string;
}

/** Options for {@link useTokenBalance}. */
export interface UseTokenBalanceOptions extends QueryOptions {}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Fetch the Token balance from a Token wallet contract.
 *
 * Calls `get_wallet_data` and reads the first stack element (balance) as a
 * `bigint`.
 *
 * @param args - Token wallet arguments.
 * @param opts - Query options.
 * @returns A query result with `data` typed as `bigint`.
 *
 * @example
 * ```tsx
 * const { data: tokenBalance } = useTokenBalance({ address: myTokenWallet });
 * ```
 */
export function useTokenBalance(
  args?: UseTokenBalanceArgs | null,
  opts?: UseTokenBalanceOptions,
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
