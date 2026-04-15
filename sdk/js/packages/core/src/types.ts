/**
 * Shared types for the @tos/core package.
 */

import type { Address } from './address/Address';
import type { Cell } from './boc/Cell';

/** Cell type discriminator matching TVM spec. */
export enum CellType {
    ordinary = -1,
    prunedBranch = 1,
    merkleProof = 3,
    merkleUpdate = 4,
}

/** Send mode flags for outgoing messages. */
export enum SendMode {
    NONE = 0,
    PAY_GAS_SEPARATELY = 1,
    IGNORE_ERRORS = 2,
    DESTROY_ACCOUNT_IF_ZERO = 32,
    CARRY_ALL_REMAINING_INCOMING_VALUE = 64,
    CARRY_ALL_REMAINING_BALANCE = 128,
}

/** Minimal state initialisation (code + data). */
export interface StateInit {
    code: Cell;
    data: Cell;
}

/** Contract interface. */
export interface Contract {
    readonly address: Address;
    readonly init?: StateInit;
}

/** Extra currency descriptor. */
export interface ExtraCurrency {
    id: number;
    amount: string;
}

/**
 * Address information in multiple formats.
 * Uses snake_case matching the C++ wire format convention.
 */
export interface AddressInfo {
    is_valid: boolean;
    is_bounceable: boolean;
    is_test_only: boolean;
    is_url_safe: boolean;
    workchain: number;
    hash_hex: string;
    raw_form: string;
    bounceable_b64: string;
    bounceable_b64url: string;
    non_bounceable_b64: string;
    non_bounceable_b64url: string;
}

/** Hash in multiple text encodings. */
export interface HashInfo {
    b64: string;
    b64url: string;
    hex: string;
}

/** Maybe type: value, null, or undefined. */
export type Maybe<T> = T | null | undefined;
