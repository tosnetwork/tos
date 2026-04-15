/**
 * @tos/react — useNftData hook.
 *
 * Fetches NFT item data via a `get_nft_data` contract read.
 */

import type { Address } from "@tos/core";
import type { QueryOptions, QueryResult } from "../types.js";
import { useContractRead } from "./useContractRead.js";

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

/** Parsed NFT item data from `get_nft_data`. */
export interface NftItemInfo {
  /** Whether the NFT has been initialized. */
  init: boolean;
  /** Index within the collection (or -1 for standalone). */
  index: bigint;
  /** Collection address as raw stack value, or `null` for standalone NFTs. */
  collectionAddress: unknown;
  /** Owner address as raw stack value. */
  ownerAddress: unknown;
  /** Individual content cell (raw). */
  content: unknown;
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/** Options for {@link useNftData}. */
export interface UseNftDataOptions extends QueryOptions {}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Fetch NFT item data via the `get_nft_data` get-method.
 *
 * @param address - The NFT item contract address.
 * @param opts    - Query options.
 * @returns A query result with `data` typed as {@link NftItemInfo}.
 *
 * @example
 * ```tsx
 * const { data } = useNftData(nftAddress);
 * if (data) console.log("NFT index:", data.index.toString());
 * ```
 */
export function useNftData(
  address?: Address | string | null,
  opts?: UseNftDataOptions,
): QueryResult<NftItemInfo> {
  return useContractRead<NftItemInfo>(
    address
      ? {
          address,
          method: "get_nft_data",
          parse: (stack) => ({
            init: stack.readBoolean(),
            index: stack.readBigNumber(),
            collectionAddress: stack.readAddress(),
            ownerAddress: stack.readAddress(),
            content: stack.readCell(),
          }),
        }
      : null,
    {
      enabled: opts?.enabled,
      refetchInterval: opts?.refetchInterval,
    },
  );
}
