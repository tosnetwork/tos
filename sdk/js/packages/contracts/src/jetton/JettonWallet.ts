import { Address, beginCell, Cell, Contract, StateInit } from '@tos/core';
import type { ContractProvider, Signer } from '@tos/client';

/**
 * Opcodes used by the Jetton Wallet (TEP-74).
 */
const Opcodes = {
    transfer: 0x0f8a7ea5,
    burn: 0x595f07bc,
} as const;

/**
 * Jetton Wallet contract wrapper (TEP-74).
 *
 * Every owner has a dedicated jetton-wallet contract per jetton type.
 * This wrapper provides read access to `get_wallet_data` and write
 * helpers for transferring and burning jettons.
 *
 * @example
 * ```typescript
 * import { JettonWallet } from "@tos/contracts";
 * import { TosClient, open } from "@tos/client";
 *
 * const client = new TosClient({ endpoint: "http://localhost:8081" });
 * const wallet = open(JettonWallet.create(walletAddress), client);
 *
 * const balance = await wallet.getBalance();
 * const owner = await wallet.getOwner();
 * ```
 */
export class JettonWallet implements Contract {
    readonly address: Address;
    readonly init?: StateInit;

    private constructor(address: Address, init?: StateInit) {
        this.address = address;
        this.init = init;
    }

    /**
     * Create a JettonWallet wrapper for an already-deployed wallet contract.
     *
     * @param address - The on-chain address of the jetton wallet contract
     * @returns A new JettonWallet wrapper
     *
     * @example
     * ```typescript
     * const jWallet = JettonWallet.create(Address.parse("0:abc..."));
     * ```
     */
    static create(address: Address): JettonWallet {
        return new JettonWallet(address);
    }

    // ------------------------------------------------------------------ reads

    /**
     * Fetch the current jetton balance of this wallet.
     */
    async getBalance(provider: ContractProvider): Promise<bigint> {
        const result = await provider.get('get_wallet_data', []);
        return result.stack.readBigNumber();
    }

    /**
     * Fetch the owner address of this jetton wallet.
     */
    async getOwner(provider: ContractProvider): Promise<Address> {
        const result = await provider.get('get_wallet_data', []);
        result.stack.readBigNumber(); // balance
        return result.stack.readAddress() as Address;
    }

    /**
     * Fetch the address of the jetton master (minter) contract.
     */
    async getJettonMaster(provider: ContractProvider): Promise<Address> {
        const result = await provider.get('get_wallet_data', []);
        result.stack.readBigNumber(); // balance
        result.stack.readAddress();   // owner
        return result.stack.readAddress() as Address;
    }

    // ----------------------------------------------------------------- writes

    /**
     * Send a jetton transfer from this wallet to another owner.
     *
     * The message follows TEP-74 `transfer` layout:
     *   op(32) query_id(64) amount(coins) destination(address)
     *   response_destination(address) custom_payload(maybe-ref)
     *   forward_ton_amount(coins) forward_payload(either)
     *
     * @param args.to              - new owner of the jettons
     * @param args.amount          - number of jettons to transfer (indivisible units)
     * @param args.responseAddress - address to receive leftover TOS + notifications
     * @param args.forwardAmount   - TOS amount forwarded with the transfer notification
     * @param args.forwardPayload  - optional payload forwarded to the new owner
     */
    async sendTransfer(
        provider: ContractProvider,
        via: Signer,
        args: {
            to: Address;
            amount: bigint;
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
            .storeCoins(args.amount)
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

    /**
     * Burn jettons held by this wallet.
     *
     * The burned tokens are deducted from total supply on the minter side.
     *
     * @param args.amount          - number of jettons to burn (indivisible units)
     * @param args.responseAddress - address to receive the burn confirmation
     */
    async sendBurn(
        provider: ContractProvider,
        via: Signer,
        args: {
            amount: bigint;
            value: bigint;
            responseAddress?: Address;
            queryId?: bigint;
        },
    ): Promise<void> {
        const body = beginCell()
            .storeUint(Opcodes.burn, 32)
            .storeUint(args.queryId ?? 0n, 64)
            .storeCoins(args.amount)
            .storeAddress(args.responseAddress ?? null)
            .endCell();

        await provider.internal(via, {
            value: args.value,
            body,
        });
    }
}
