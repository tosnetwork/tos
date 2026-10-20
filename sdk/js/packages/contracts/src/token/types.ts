import type { Address, Cell } from '@tos/core';

/**
 * On-chain data returned by the `get_token_data` TVM get-method (TOS Token V1).
 */
export interface FungibleTokenData {
    /** Current total supply in indivisible units. */
    totalSupply: bigint;
    /** Whether the admin can still mint new tokens. */
    mintable: boolean;
    /** Address of the contract admin (can mint / change admin). */
    adminAddress: Address;
    /** Raw content cell (off-chain or on-chain metadata). */
    content: Cell;
    /** Token-wallet code used to derive wallet addresses. */
    walletCode: Cell;
}

/**
 * Parsed off-chain / on-chain Token metadata (TEP-64 token data standard).
 */
export interface TokenContent {
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
