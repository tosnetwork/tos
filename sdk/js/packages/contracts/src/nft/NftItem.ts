import { Address, beginCell, Cell, Contract, StateInit } from '@tos/core';
import type { ContractProvider, Signer } from '@tos/client';
import type { NftItemData } from './types';

/**
 * Opcodes used by the NFT Item (TEP-62).
 */
const Opcodes = {
    transfer: 0x5fcc3d14,
} as const;

/**
 * NFT Item contract wrapper (TEP-62).
 *
 * Wraps a single deployed NFT item contract, providing read access
 * to `get_nft_data` and a write helper for ownership transfers.
 *
 * @example
 * ```typescript
 * import { NftItem } from "@tos/contracts";
 * import { TosClient, open } from "@tos/client";
 *
 * const client = new TosClient({ endpoint: "http://localhost:8081" });
 * const item = open(NftItem.create(itemAddress), client);
 *
 * const data = await item.getNftData();
 * console.log(data.ownerAddress.toString(), data.index);
 * ```
 */
export class NftItem implements Contract {
    readonly address: Address;
    readonly init?: StateInit;

    private constructor(address: Address, init?: StateInit) {
        this.address = address;
        this.init = init;
    }

    /**
     * Create an NftItem wrapper for an already-deployed item contract.
     *
     * @param address - The on-chain address of the NFT item contract
     * @returns A new NftItem wrapper
     *
     * @example
     * ```typescript
     * const item = NftItem.create(Address.parse("0:abc..."));
     * ```
     */
    static create(address: Address): NftItem {
        return new NftItem(address);
    }

    // ------------------------------------------------------------------ reads

    /**
     * Fetch the full on-chain NFT item data.
     *
     * Calls `get_nft_data` which returns:
     *   init?(int) index(int) collection_address(slice)
     *   owner_address(slice) content(cell)
     */
    async getNftData(provider: ContractProvider): Promise<NftItemData> {
        const result = await provider.get('get_nft_data', []);

        const initialized = result.stack.readBoolean();
        const index = result.stack.readBigNumber();
        const collectionAddress = result.stack.readAddress() as Address;
        const ownerAddress = result.stack.readAddress() as Address;
        const content = result.stack.readCell() as Cell;

        return { initialized, index, collectionAddress, ownerAddress, content };
    }

    // ----------------------------------------------------------------- writes

    /**
     * Transfer this NFT to a new owner.
     *
     * The message body follows TEP-62 `transfer` layout:
     *   op(32) query_id(64) new_owner(address)
     *   response_destination(address) custom_payload(maybe-ref)
     *   forward_amount(coins) forward_payload(either)
     *
     * @param args.to              - new owner address
     * @param args.responseAddress - address to receive leftover TOS + notifications
     * @param args.forwardAmount   - TOS forwarded with the ownership_assigned notification
     * @param args.forwardPayload  - optional payload forwarded to the new owner
     */
    async sendTransfer(
        provider: ContractProvider,
        via: Signer,
        args: {
            to: Address;
            value: bigint;
            responseAddress?: Address;
            forwardAmount?: bigint;
            forwardPayload?: Cell;
            queryId?: bigint;
        },
    ): Promise<void> {
        const builder = beginCell()
            .storeUint(Opcodes.transfer, 32)
            .storeUint(args.queryId ?? 0n, 64)
            .storeAddress(args.to)
            .storeAddress(args.responseAddress ?? args.to)
            .storeBit(false) // null custom_payload
            .storeCoins(args.forwardAmount ?? 0n);

        if (args.forwardPayload) {
            builder.storeBit(true); // forward_payload in a separate ref
            builder.storeRef(args.forwardPayload);
        } else {
            builder.storeBit(false); // empty forward_payload in current slice
        }

        await provider.internal(via, {
            value: args.value,
            body: builder.endCell(),
        });
    }
}
