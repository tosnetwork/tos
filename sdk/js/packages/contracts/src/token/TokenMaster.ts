import { Address, beginCell, Cell, Contract, StateInit } from '@tos/core';
import type { ContractProvider, Signer } from '@tos/client';
import type { FungibleTokenData, TokenContent } from './types';

/**
 * Opcodes used by the Token Minter (TOS Token V1 master contract).
 */
const Opcodes = {
    mint: 0x642b7d07,
    changeAdmin: 0x6501f354,
    internalTransfer: 0x178d4519,
} as const;

/**
 * Token Master / Minter contract wrapper (TOS Token V1).
 *
 * Provides read helpers for the standard `get_token_data` and
 * `get_wallet_address` get-methods, and write helpers for minting
 * tokens and changing the admin address.
 *
 * @example
 * ```typescript
 * import { TokenMaster } from "@tos/contracts";
 * import { TosClient, open } from "@tos/client";
 *
 * const client = new TosClient({ endpoint: "http://localhost:8081" });
 * const minter = open(TokenMaster.create(minterAddress), client);
 *
 * const data = await minter.getTokenData();
 * console.log(data.totalSupply, data.mintable);
 *
 * const walletAddr = await minter.getTokenWalletAddress(ownerAddress);
 * ```
 */
export class TokenMaster implements Contract {
    readonly address: Address;
    readonly init?: StateInit;

    private constructor(address: Address, init?: StateInit) {
        this.address = address;
        this.init = init;
    }

    /**
     * Create a TokenMaster wrapper for an already-deployed contract.
     *
     * @param address - The on-chain address of the token minter contract
     * @returns A new TokenMaster wrapper
     *
     * @example
     * ```typescript
     * const minter = TokenMaster.create(Address.parse("0:abc..."));
     * ```
     */
    static create(address: Address): TokenMaster {
        return new TokenMaster(address);
    }

    // ------------------------------------------------------------------ reads

    /**
     * Fetch the current total supply of the token.
     */
    async getTotalSupply(provider: ContractProvider): Promise<bigint> {
        const result = await provider.get('get_token_data', []);
        return result.stack.readBigNumber();
    }

    /**
     * Fetch the admin (owner) address of the token minter.
     */
    async getAdminAddress(provider: ContractProvider): Promise<Address> {
        const result = await provider.get('get_token_data', []);
        result.stack.readBigNumber();   // total_supply
        result.stack.readBoolean();     // mintable
        return result.stack.readAddress() as Address;
    }

    /**
     * Derive the token-wallet address for a given owner.
     */
    async getTokenWalletAddress(
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
     * Fetch the full `get_token_data` result.
     */
    async getTokenData(provider: ContractProvider): Promise<FungibleTokenData> {
        const result = await provider.get('get_token_data', []);

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
     * `get_token_data` and tries to decode TEP-64 metadata.  Fields that
     * cannot be decoded are left `undefined`.
     */
    async getContent(provider: ContractProvider): Promise<TokenContent> {
        const { content } = await this.getTokenData(provider);
        return parseTokenContent(content);
    }

    // ----------------------------------------------------------------- writes

    /**
     * Send a mint transaction to the Token Minter.
     *
     * @param provider - injected by `open()`
     * @param via      - the signing sender
     * @param args.to     - destination owner address for the newly minted tokens
     * @param args.amount - amount of tokens to mint (in indivisible units)
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
function parseTokenContent(cell: Cell): TokenContent {
    const slice = cell.beginParse();
    const prefix = slice.loadUint(8);

    if (prefix === 0x01) {
        return { uri: slice.loadStringTail() };
    }

    // On-chain (0x00) or unknown prefix — return empty content
    return {};
}
