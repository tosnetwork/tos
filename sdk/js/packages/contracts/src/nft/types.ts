import type { Address, Cell } from '@tos/core';

/**
 * On-chain data returned by the `get_collection_data` TVM get-method (TEP-62).
 */
export interface NftCollectionData {
    /**
     * Index that will be assigned to the next minted item. Hash-indexed
     * collections (uint256 indexes, e.g. the `.tos` domain collection)
     * return -1 here: their indexes are derived, not sequential.
     */
    nextItemIndex: bigint;
    /** Raw collection content cell (off-chain or on-chain metadata). */
    content: Cell;
    /** Address of the collection owner / admin. */
    ownerAddress: Address;
}

/**
 * On-chain data returned by the `get_nft_data` TVM get-method (TEP-62).
 */
export interface NftItemData {
    /** Whether the NFT item has been deployed and initialized. */
    initialized: boolean;
    /**
     * Index of this item inside the collection: sequential for standard
     * collections, a uint256 hash for hash-indexed ones (e.g. `.tos`
     * domains, where it is the TVM slice_hash of the label).
     */
    index: bigint;
    /** Address of the parent collection (or zero-address for standalone items). */
    collectionAddress: Address;
    /** Current owner of the NFT, or null for an uninitialized item. */
    ownerAddress: Address | null;
    /** Raw individual content cell. */
    content: Cell;
}
