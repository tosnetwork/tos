import type { Address, Cell } from '@tos/core';

/**
 * On-chain data returned by the `get_jetton_data` TVM get-method (TEP-74).
 */
export interface JettonData {
    /** Current total supply in indivisible units. */
    totalSupply: bigint;
    /** Whether the admin can still mint new tokens. */
    mintable: boolean;
    /** Address of the contract admin (can mint / change admin). */
    adminAddress: Address;
    /** Raw content cell (off-chain or on-chain metadata). */
    content: Cell;
    /** Jetton-wallet code used to derive wallet addresses. */
    walletCode: Cell;
}

/**
 * Parsed off-chain / on-chain Jetton metadata (TEP-64 token data standard).
 */
export interface JettonContent {
    /** Off-chain JSON URI (if present). */
    uri?: string;
    /** Human-readable token name. */
    name?: string;
    /** Short ticker symbol. */
    symbol?: string;
    /** Number of decimal places. */
    decimals?: number;
    /** Human-readable description. */
    description?: string;
    /** URI pointing to the token image. */
    image?: string;
}
