import { Address, beginCell, Cell, Contract, StateInit } from '@tos/core';
import type { ContractProvider, Signer } from '@tos/client';
import type { NftCollectionData } from './types';

/**
 * Opcodes used by the NFT Collection (TEP-62).
 */
const Opcodes = {
    mint: 1, // deploy new NFT item
} as const;

/**
 * NFT Collection contract wrapper (TEP-62).
 *
 * Provides read helpers for the standard `get_collection_data`,
 * `get_nft_address_by_index`, and `get_nft_content` get-methods,
 * plus a write helper for minting new items.
 *
 * @example
 * ```typescript
 * import { NftCollection } from "@tos/contracts";
 * import { TosClient, open } from "@tos/client";
 *
 * const client = new TosClient({ endpoint: "http://localhost:8081" });
 * const collection = open(NftCollection.create(collectionAddress), client);
 *
 * const data = await collection.getCollectionData();
 * console.log(data.nextItemIndex, data.ownerAddress.toString());
 * ```
 */
export class NftCollection implements Contract {
    readonly address: Address;
    readonly init?: StateInit;

    private constructor(address: Address, init?: StateInit) {
        this.address = address;
        this.init = init;
    }

    /**
     * Create an NftCollection wrapper for an already-deployed contract.
     *
     * @param address - The on-chain address of the NFT collection contract
     * @returns A new NftCollection wrapper
     *
     * @example
     * ```typescript
     * const collection = NftCollection.create(Address.parse("0:abc..."));
     * ```
     */
    static create(address: Address): NftCollection {
        return new NftCollection(address);
    }

    // ------------------------------------------------------------------ reads

    /**
     * Fetch the on-chain collection data.
     *
     * Calls `get_collection_data` which returns:
     *   next_item_index(int) collection_content(cell) owner_address(slice)
     */
    async getCollectionData(provider: ContractProvider): Promise<NftCollectionData> {
        const result = await provider.get('get_collection_data', []);

        const nextItemIndex = result.stack.readBigNumber();
        const content = result.stack.readCell() as Cell;
        const ownerAddress = result.stack.readAddress() as Address;

        return { nextItemIndex, content, ownerAddress };
    }

    /**
     * Derive the NFT item contract address for a given index.
     *
     * Calls `get_nft_address_by_index` with the item index on the stack.
     */
    async getNftAddressByIndex(
        provider: ContractProvider,
        index: bigint,
    ): Promise<Address> {
        const result = await provider.get('get_nft_address_by_index', [
            { type: 'int', value: index },
        ]);
        return result.stack.readAddress() as Address;
    }

    /**
     * Resolve the full content URI for an NFT item.
     *
     * Calls `get_nft_content` with the item index and individual content cell.
     * The collection contract concatenates its base URI with the item-specific
     * content and returns a single content cell.
     */
    async getNftContent(
        provider: ContractProvider,
        index: bigint,
        individualContent: Cell,
    ): Promise<string> {
        const result = await provider.get('get_nft_content', [
            { type: 'int', value: index },
            { type: 'cell', cell: individualContent },
        ]);

        const contentCell = result.stack.readCell() as Cell;
        return parseOffchainUri(contentCell);
    }

    // ----------------------------------------------------------------- writes

    /**
     * Mint (deploy) a new NFT item inside this collection.
     *
     * The message body follows the standard layout:
     *   op(32) = 1  query_id(64)  item_index(64)  amount(coins)
     *   ref: item_owner(address) + ref(item_content)
     *
     * Only sequential 64-bit-indexed collections use this op. Hash-indexed
     * collections (uint256 indexes, e.g. the `.tos` domain collection, whose
     * `next_item_index` is -1) mint through their own flow — for `.tos`,
     * an op-0 comment registration; see the dns module.
     *
     * @param args.index   - sequential item index (must fit 64 bits)
     * @param args.owner   - initial owner of the new NFT
     * @param args.content - individual content cell for the item
     * @param args.value   - TOS (in nanoTOS) attached to the deploy message
     */
    async sendMint(
        provider: ContractProvider,
        via: Signer,
        args: {
            index: bigint;
            owner: Address;
            content: Cell;
            value: bigint;
            queryId?: bigint;
        },
    ): Promise<void> {
        if (args.index >= 1n << 64n) {
            throw new Error(
                'sendMint requires a sequential 64-bit index; hash-indexed collections ' +
                    '(uint256 indexes, e.g. .tos domains) do not use the op-1 mint',
            );
        }

        const itemContent = beginCell()
            .storeAddress(args.owner)
            .storeRef(args.content)
            .endCell();

        const body = beginCell()
            .storeUint(Opcodes.mint, 32)
            .storeUint(args.queryId ?? 0n, 64)
            .storeUint(args.index, 64)
            .storeCoins(args.value)
            .storeRef(itemContent)
            .endCell();

        await provider.internal(via, {
            value: args.value,
            body,
        });
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Parse an off-chain content cell (TEP-64, prefix 0x01) into a UTF-8 string.
 */
function parseOffchainUri(cell: Cell): string {
    const slice = cell.beginParse();
    const prefix = slice.loadUint(8);

    if (prefix === 0x01) {
        return slice.loadStringTail();
    }

    // If not off-chain, return an empty string — callers can inspect the
    // raw cell for on-chain metadata.
    return '';
}
