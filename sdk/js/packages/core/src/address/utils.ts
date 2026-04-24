/**
 * Address utility functions.
 */

import { Address } from './Address';
import type { AddressInfo, HashInfo, StateInit } from '../types';
import {
    bytesToBase64,
    bytesToBase64Url,
    bytesToHex,
    hexToBytes,
    base64ToBytes,
    base64UrlToBytes,
} from '../utils/encoding';
import { beginCell } from '../boc/Builder';

/**
 * Convert a raw address (`workchain:hex`) to friendly base64url format.
 *
 * @param rawAddress - Raw address string (e.g. `"0:abcdef..."`)
 * @returns URL-safe bounceable friendly address string
 *
 * @example
 * ```typescript
 * const friendly = packAddress("0:abcdef...");
 * // "EQBvW8Z5..."
 * ```
 */
export function packAddress(rawAddress: string): string {
    const addr = Address.parseRaw(rawAddress);
    return addr.toString({ urlSafe: true, bounceable: true });
}

/**
 * Convert a friendly base64 address to raw format (`workchain:hex`).
 *
 * @param friendlyAddress - Friendly base64 address string
 * @returns Raw address string
 *
 * @example
 * ```typescript
 * const raw = unpackAddress("EQBvW8Z5...");
 * // "0:6f5bc679..."
 * ```
 */
export function unpackAddress(friendlyAddress: string): string {
    const { address } = Address.parseFriendly(friendlyAddress);
    return address.toRawString();
}

/**
 * Detect the format of an address string and return all address variants.
 *
 * Returns an {@link AddressInfo} object with bounceable/non-bounceable forms
 * in both base64 and base64url encodings, along with raw format and metadata.
 *
 * @param addressStr - Address string in any supported format
 * @returns An AddressInfo object with all address variants, or `is_valid: false` if invalid
 *
 * @example
 * ```typescript
 * const info = detectAddress("0:abcdef...");
 * console.log(info.bounceable_b64url); // friendly format
 * console.log(info.raw_form);           // raw format
 * ```
 */
export function detectAddress(addressStr: string): AddressInfo {
    let addr: Address;
    let isBounceable = true;
    let isTestOnly = false;
    let isUrlSafe = false;

    try {
        if (Address.isFriendly(addressStr)) {
            const parsed = Address.parseFriendly(addressStr);
            addr = parsed.address;
            isBounceable = parsed.isBounceable;
            isTestOnly = parsed.isTestOnly;
            // Detect if URL-safe based on characters
            isUrlSafe = addressStr.includes('-') || addressStr.includes('_');
        } else if (Address.isRaw(addressStr)) {
            addr = Address.parseRaw(addressStr);
        } else {
            return {
                is_valid: false,
                is_bounceable: false,
                is_test_only: false,
                is_url_safe: false,
                workchain: 0,
                hash_hex: '',
                raw_form: '',
                bounceable_b64: '',
                bounceable_b64url: '',
                non_bounceable_b64: '',
                non_bounceable_b64url: '',
            };
        }
    } catch {
        return {
            is_valid: false,
            is_bounceable: false,
            is_test_only: false,
            is_url_safe: false,
            workchain: 0,
            hash_hex: '',
            raw_form: '',
            bounceable_b64: '',
            bounceable_b64url: '',
            non_bounceable_b64: '',
            non_bounceable_b64url: '',
        };
    }

    return {
        is_valid: true,
        is_bounceable: isBounceable,
        is_test_only: isTestOnly,
        is_url_safe: isUrlSafe,
        workchain: addr.workchain,
        hash_hex: bytesToHex(addr.hash),
        raw_form: addr.toRawString(),
        bounceable_b64: addr.toString({
            urlSafe: false,
            bounceable: true,
            testOnly: isTestOnly,
        }),
        bounceable_b64url: addr.toString({
            urlSafe: true,
            bounceable: true,
            testOnly: isTestOnly,
        }),
        non_bounceable_b64: addr.toString({
            urlSafe: false,
            bounceable: false,
            testOnly: isTestOnly,
        }),
        non_bounceable_b64url: addr.toString({
            urlSafe: true,
            bounceable: false,
            testOnly: isTestOnly,
        }),
    };
}

/**
 * Detect the encoding format of a hash string and return all variants.
 *
 * @param hash - Hash string in hex, base64, or base64url format
 * @returns A HashInfo object with the hash in all three formats
 *
 * @example
 * ```typescript
 * const info = detectHash("abcdef0123456789...");
 * console.log(info.b64);    // base64 encoding
 * console.log(info.b64url); // URL-safe base64
 * console.log(info.hex);    // hex encoding
 * ```
 */
export function detectHash(hash: string): HashInfo {
    let bytes: Uint8Array;

    if (/^[a-f0-9]{64}$/i.test(hash)) {
        bytes = hexToBytes(hash);
    } else if (hash.includes('-') || hash.includes('_')) {
        bytes = base64UrlToBytes(hash);
    } else {
        bytes = base64ToBytes(hash);
    }

    return {
        b64: bytesToBase64(bytes),
        b64url: bytesToBase64Url(bytes),
        hex: bytesToHex(bytes),
    };
}

/**
 * Compute the deterministic contract address from a workchain and StateInit.
 *
 * The address is derived from the SHA-256 hash of the serialized StateInit cell,
 * matching the on-chain address computation in the TOS VM.
 *
 * @param workchain - Workchain ID (0 for basechain, -1 for masterchain)
 * @param init - StateInit containing the contract code and initial data cells
 * @returns The computed contract Address
 *
 * @example
 * ```typescript
 * const init: StateInit = { code: codeCell, data: dataCell };
 * const addr = contractAddress(0, init);
 * console.log(addr.toString()); // friendly address
 * ```
 */
export function contractAddress(
    workchain: number,
    init: StateInit,
): Address {
    const stateInitCell = beginCell()
        .storeBit(false) // split_depth: Maybe (## 5)
        .storeBit(false) // special: Maybe TickTock
        .storeBit(true)  // code: Maybe ^Cell
        .storeRef(init.code)
        .storeBit(true)  // data: Maybe ^Cell
        .storeRef(init.data)
        .storeBit(false) // library: empty dict
        .endCell();

    const hash = stateInitCell.hash();
    return new Address(workchain, hash);
}
