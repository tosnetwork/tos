import { Address, beginCell, Cell, Contract, StateInit } from '@tos/core';
import type { ContractProvider, Signer } from '@tos/client';
import type { JettonData, JettonContent } from './types';

/**
 * Opcodes used by the Jetton Minter (TEP-74 master contract).
 */
const Opcodes = {
    mint: 0x642b7d07,
    changeAdmin: 0x6501f354,
    internalTransfer: 0x178d4519,
} as const;

/**
 * Jetton Master / Minter contract wrapper (TEP-74).
 *
 * Provides read helpers for the standard `get_jetton_data` and
 * `get_wallet_address` get-methods, and write helpers for minting
 * tokens and changing the admin address.
 *
 * @example
 * ```typescript
 * import { JettonMinter } from "@tos/contracts";
 * import { TosClient, open } from "@tos/client";
 *
 * const client = new TosClient({ endpoint: "http://localhost:8081" });
 * const minter = open(JettonMinter.create(minterAddress), client);
 *
 * const data = await minter.getJettonData();
 * console.log(data.totalSupply, data.mintable);
 *
 * const walletAddr = await minter.getJettonWalletAddress(ownerAddress);
 * ```
 */
export class JettonMinter implements Contract {
    readonly address: Address;
    readonly init?: StateInit;

    private constructor(address: Address, init?: StateInit) {
        this.address = address;
        this.init = init;
    }

    /**
     * Create a JettonMinter wrapper for an already-deployed contract.
     *
     * @param address - The on-chain address of the jetton minter contract
     * @returns A new JettonMinter wrapper
     *
     * @example
     * ```typescript
     * const minter = JettonMinter.create(Address.parse("0:abc..."));
     * ```
     */
    static create(address: Address): JettonMinter {
        return new JettonMinter(address);
    }

    // ------------------------------------------------------------------ reads

    /**
     * Fetch the current total supply of the jetton.
     */
    async getTotalSupply(provider: ContractProvider): Promise<bigint> {
        const result = await provider.get('get_jetton_data', []);
        return result.stack.readBigNumber();
    }

    /**
     * Fetch the admin (owner) address of the jetton minter.
     */
    async getAdminAddress(provider: ContractProvider): Promise<Address> {
        const result = await provider.get('get_jetton_data', []);
        result.stack.readBigNumber();   // total_supply
        result.stack.readBoolean();     // mintable
        return result.stack.readAddress() as Address;
    }

    /**
     * Derive the jetton-wallet address for a given owner.
     */
    async getJettonWalletAddress(
        provider: ContractProvider,
        owner: Address,
    ): Promise<Address> {
        const result = await provider.get('get_wallet_address', [
            {
                type: 'slice',
                cell: beginCell().storeAddress(owner).endCell(),
            },
        ]);
        return result.stack.readAddress() as Address;
    }

    /**
     * Fetch the full `get_jetton_data` result.
     */
    async getJettonData(provider: ContractProvider): Promise<JettonData> {
        const result = await provider.get('get_jetton_data', []);

        const totalSupply = result.stack.readBigNumber();
        const mintable = result.stack.readBoolean();
        const adminAddress = result.stack.readAddress() as Address;
        const content = result.stack.readCell() as Cell;
        const walletCode = result.stack.readCell() as Cell;

        return { totalSupply, mintable, adminAddress, content, walletCode };
    }

    /**
     * Parse the off-chain / on-chain content cell into a typed object.
     *
     * This is a best-effort parser: it reads the content cell returned by
     * `get_jetton_data` and tries to decode TEP-64 metadata.  Fields that
     * cannot be decoded are left `undefined`.
     */
    async getContent(provider: ContractProvider): Promise<JettonContent> {
        const { content } = await this.getJettonData(provider);
        return parseJettonContent(content);
    }

    // ----------------------------------------------------------------- writes

    /**
     * Send a mint transaction to the Jetton Minter.
     *
     * @param provider - injected by `open()`
     * @param via      - the signing sender
     * @param args.to     - destination owner address for the newly minted tokens
     * @param args.amount - amount of jettons to mint (in indivisible units)
     * @param args.value  - amount of TOS (in nanoTOS) attached to the message
     */
    async sendMint(
        provider: ContractProvider,
        via: Signer,
        args: {
            to: Address;
            amount: bigint;
            value: bigint;
            queryId?: bigint;
        },
    ): Promise<void> {
        const queryId = args.queryId ?? 0n;

        const mintBody = beginCell()
            .storeUint(Opcodes.mint, 32)
            .storeUint(queryId, 64)
            .storeAddress(args.to)
            .storeCoins(args.value)
            .storeRef(
                beginCell()
                    .storeUint(Opcodes.internalTransfer, 32)
                    .storeUint(queryId, 64)
                    .storeCoins(args.amount)
                    .storeAddress(null) // from_address
                    .storeAddress(null) // response_address
                    .storeCoins(0n)     // forward_amount
                    .storeBit(false)    // no forward_payload
                    .endCell(),
            )
            .endCell();

        await provider.internal(via, {
            value: args.value,
            body: mintBody,
        });
    }

    /**
     * Send a change-admin message to transfer minter ownership.
     */
    async sendChangeAdmin(
        provider: ContractProvider,
        via: Signer,
        newAdmin: Address,
        opts?: { queryId?: bigint; value?: bigint },
    ): Promise<void> {
        const body = beginCell()
            .storeUint(Opcodes.changeAdmin, 32)
            .storeUint(opts?.queryId ?? 0n, 64)
            .storeAddress(newAdmin)
            .endCell();

        await provider.internal(via, {
            value: opts?.value ?? 50000000n, // 0.05 TOS default
            body,
        });
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Best-effort parser for TEP-64 off-chain content.
 *
 * Layout: first byte 0x01 indicates off-chain; the remaining bytes
 * are a UTF-8 encoded URI.  On-chain (0x00) content uses a dict of
 * sha256-keyed entries — we return an empty object in that case and
 * let callers handle it at a higher level.
 */
function parseJettonContent(cell: Cell): JettonContent {
    const slice = cell.beginParse();
    const prefix = slice.loadUint(8);

    if (prefix === 0x01) {
        // Off-chain content: remaining data is a UTF-8 URI
        const uriBytes = slice.loadBuffer(slice.remainingBits / 8);
        const uri = new TextDecoder().decode(uriBytes);
        return { uri };
    }

    // On-chain (0x00) or unknown prefix — return empty content
    return {};
}
