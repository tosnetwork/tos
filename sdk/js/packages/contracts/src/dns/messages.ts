/**
 * Message-body builders for the inherited .tos Domain Item / Collection ABI.
 * The registrar signs and sends these through the user's wallet; nothing
 * here holds keys.
 */
import { Address, beginCell, Cell } from '@tos/core';
import { labelContractError, utf8 } from './name';

export const OP_TRANSFER = 0x5fcc3d14;
export const OP_GET_STATIC_DATA = 0x2fcb26a2;
export const OP_EDIT_CONTENT = 0x1a0b9d51;
export const OP_CHANGE_DNS_RECORD = 0x4eb1f0f9;
export const OP_DNS_BALANCE_RELEASE = 0x4ed14b65;
export const OP_FILL_UP = 0x370fec51;
export const OP_OUTBID_NOTIFICATION = 0x557cea20;

/**
 * Registration: an op-0 text comment whose body is the plaintext label,
 * sent to the COLLECTION with at least minPrice() attached. Long labels
 * continue in a single-ref chain, exactly as the collection reads them.
 */
export function registerBody(label: string): Cell {
    const err = labelContractError(label);
    if (err) {
        throw new Error(`invalid label: ${err}`);
    }
    const bytes = utf8(label);
    const headCapacity = Math.floor((1023 - 32) / 8); // 123 bytes beside the op
    const head = beginCell().storeUint(0, 32);
    head.storeBuffer(bytes.subarray(0, Math.min(bytes.length, headCapacity)));
    if (bytes.length > headCapacity) {
        head.storeRef(beginCell().storeBuffer(bytes.subarray(headCapacity)).endCell());
    }
    return head.endCell();
}

/** A bid or an owner top-up: an empty body sent to the DOMAIN ITEM. */
export function bidBody(): Cell {
    return beginCell().endCell();
}

/** Renewal top-up from any sender: op::fill_up refreshes last_fill_up_time. */
export function fillUpBody(queryId: bigint = 0n): Cell {
    return beginCell().storeUint(OP_FILL_UP, 32).storeUint(queryId, 64).endCell();
}

/**
 * Finalize a completed auction from any address: get_static_data is the one
 * inherited operation with a query_id, no sender check, and no side effect
 * beyond a report — and it does NOT refresh last_fill_up_time (DNS.md §6.4).
 */
export function finishAuctionBody(queryId: bigint = 0n): Cell {
    return beginCell().storeUint(OP_GET_STATIC_DATA, 32).storeUint(queryId, 64).endCell();
}

/** Set (value present) or delete (value null) one record category. */
export function changeRecordBody(category: bigint, value: Cell | null, queryId: bigint = 0n): Cell {
    const b = beginCell()
        .storeUint(OP_CHANGE_DNS_RECORD, 32)
        .storeUint(queryId, 64)
        .storeUint(category, 256);
    if (value !== null) {
        b.storeRef(value);
    }
    return b.endCell();
}

/** Standard NFT transfer (owner only; refused while an auction is active). */
export function transferBody(
    newOwner: Address,
    responseTo: Address,
    forwardAmount: bigint = 0n,
    queryId: bigint = 0n,
): Cell {
    return beginCell()
        .storeUint(OP_TRANSFER, 32)
        .storeUint(queryId, 64)
        .storeAddress(newOwner)
        .storeAddress(responseTo)
        .storeBit(0) // no custom payload
        .storeCoins(forwardAmount)
        .endCell();
}

/**
 * Release an overdue name (anyone; requires value >= current minimum price).
 * Starts a seven-day auction with the caller as first bidder; the former
 * owner is refunded the releasable balance with errors ignored.
 */
export function releaseBody(queryId: bigint = 0n): Cell {
    return beginCell().storeUint(OP_DNS_BALANCE_RELEASE, 32).storeUint(queryId, 64).endCell();
}
