/**
 * TOS-compatible Address class.
 * Friendly format uses CRC16 checksum (CCITT).
 * Operates on Uint8Array only -- no Buffer dependency.
 */

import { crc16 } from '../utils/crc';
import {
    hexToBytes,
    bytesToHex,
    bytesToBase64,
    base64ToBytes,
} from '../utils/encoding';

const BOUNCEABLE_TAG = 0x11;
const NON_BOUNCEABLE_TAG = 0x51;
const TEST_FLAG = 0x80;

function parseFriendlyAddress(src: string): {
    isTestOnly: boolean;
    isBounceable: boolean;
    workchain: number;
    hash: Uint8Array;
} {
    // Convert URL-safe base64 to standard base64
    const b64 = src.replace(/-/g, '+').replace(/_/g, '/');
    const data = base64ToBytes(b64);

    // 1 byte tag + 1 byte workchain + 32 bytes hash + 2 bytes crc
    if (data.length !== 36) {
        throw new Error('Unknown address type: byte length is not equal to 36');
    }

    const addr = data.subarray(0, 34);
    const crc = data.subarray(34, 36);
    const calcedCrc = crc16(addr);
    if (calcedCrc[0] !== crc[0] || calcedCrc[1] !== crc[1]) {
        throw new Error('Invalid checksum: ' + src);
    }

    let tag = addr[0]!;
    let isTestOnly = false;
    let isBounceable = false;

    if (tag & TEST_FLAG) {
        isTestOnly = true;
        tag = tag ^ TEST_FLAG;
    }

    if (tag !== BOUNCEABLE_TAG && tag !== NON_BOUNCEABLE_TAG) {
        throw new Error('Unknown address tag');
    }

    isBounceable = tag === BOUNCEABLE_TAG;

    let workchain: number;
    if (addr[1] === 0xff) {
        workchain = -1;
    } else {
        workchain = addr[1]!;
    }

    const hash = addr.subarray(2, 34);

    return { isTestOnly, isBounceable, workchain, hash: new Uint8Array(hash) };
}

/**
 * Represents a TOS blockchain address with workchain and 256-bit hash.
 *
 * Supports both raw format (`workchain:hex_hash`) and friendly base64 format
 * with CRC16 checksum. Instances are immutable and frozen after construction.
 *
 * @example
 * ```typescript
 * // Parse any address format
 * const addr = Address.parse("0:abcdef...");
 * const addr2 = Address.parse("EQBvW8...");
 *
 * // Convert to different formats
 * addr.toRawString();    // "0:abcdef..."
 * addr.toString();       // URL-safe bounceable base64
 * addr.toString({ bounceable: false }); // non-bounceable format
 * ```
 */
export class Address {
    /**
     * Type guard to check if a value is an Address instance.
     *
     * @param src - The value to check
     * @returns true if src is an Address
     *
     * @example
     * ```typescript
     * if (Address.isAddress(value)) {
     *   console.log(value.workchain);
     * }
     * ```
     */
    static isAddress(src: unknown): src is Address {
        return src instanceof Address;
    }

    /**
     * Check if a string looks like a friendly (base64) address format.
     *
     * @param source - The string to test
     * @returns true if the string has the right length and character set for friendly format
     *
     * @example
     * ```typescript
     * Address.isFriendly("EQBvW8Z5huBkMJYdnfAEM5JqTNkuWX3diqYENkWsIL0XggGG"); // true
     * Address.isFriendly("0:abc..."); // false
     * ```
     */
    static isFriendly(source: string): boolean {
        if (source.length !== 48) {
            return false;
        }
        if (!/^[A-Za-z0-9+/_-]+$/.test(source)) {
            return false;
        }
        return true;
    }

    /**
     * Check if a string looks like a raw address format (`workchain:hex_hash`).
     *
     * @param source - The string to test
     * @returns true if the string matches raw address format
     *
     * @example
     * ```typescript
     * Address.isRaw("0:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"); // true
     * Address.isRaw("EQBvW8Z5..."); // false
     * ```
     */
    static isRaw(source: string): boolean {
        if (source.indexOf(':') === -1) {
            return false;
        }
        const parts = source.split(':');
        const wc = parts[0]!;
        const hash = parts[1];
        if (!hash || !Number.isInteger(parseFloat(wc))) {
            return false;
        }
        if (!/^[a-f0-9]+$/i.test(hash)) {
            return false;
        }
        if (hash.length !== 64) {
            return false;
        }
        return true;
    }

    /**
     * Check if a string is a valid TOS address (raw or friendly format).
     *
     * @param source - The string to validate
     * @returns true if the string can be parsed as a valid address
     *
     * @example
     * ```typescript
     * Address.isValid("0:abcdef...64hex..."); // true
     * Address.isValid("not-an-address");      // false
     * ```
     */
    static isValid(source: string): boolean {
        try {
            Address.parse(source);
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Normalize any address representation to a canonical friendly string.
     *
     * @param source - An Address instance or a string in any supported format
     * @returns The address in URL-safe bounceable friendly format
     *
     * @example
     * ```typescript
     * Address.normalize("0:abcdef..."); // "EQBvW8Z5..."
     * ```
     */
    static normalize(source: string | Address): string {
        if (typeof source === 'string') {
            return Address.parse(source).toString();
        }
        return source.toString();
    }

    /**
     * Parse an address string in any supported format (raw or friendly).
     *
     * @param source - Address string to parse
     * @returns A new Address instance
     * @throws Error if the string cannot be parsed
     *
     * @example
     * ```typescript
     * const addr = Address.parse("0:abcdef...");
     * const addr2 = Address.parse("EQBvW8Z5...");
     * ```
     */
    static parse(source: string): Address {
        if (Address.isFriendly(source)) {
            return Address.parseFriendly(source).address;
        } else if (Address.isRaw(source)) {
            return Address.parseRaw(source);
        } else {
            throw new Error('Unknown address type: ' + source);
        }
    }

    /**
     * Parse a raw format address (`workchain:hex_hash`).
     *
     * @param source - Raw address string (e.g. `"0:abcdef..."`)
     * @returns A new Address instance
     *
     * @example
     * ```typescript
     * const addr = Address.parseRaw("0:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
     * ```
     */
    static parseRaw(source: string): Address {
        const parts = source.split(':');
        const workchain = parseInt(parts[0]!, 10);
        const hash = hexToBytes(parts[1]!);
        return new Address(workchain, hash);
    }

    /**
     * Parse a friendly (base64) address and return bounce/testOnly metadata.
     *
     * @param source - Friendly address string (48 characters, base64)
     * @returns Object with `isBounceable`, `isTestOnly`, and `address` fields
     *
     * @example
     * ```typescript
     * const { address, isBounceable } = Address.parseFriendly("EQBvW8Z5...");
     * console.log(isBounceable); // true
     * ```
     */
    static parseFriendly(source: string): {
        isBounceable: boolean;
        isTestOnly: boolean;
        address: Address;
    } {
        const r = parseFriendlyAddress(source);
        return {
            isBounceable: r.isBounceable,
            isTestOnly: r.isTestOnly,
            address: new Address(r.workchain, r.hash),
        };
    }

    /** The workchain ID (0 for basechain, -1 for masterchain). */
    readonly workchain: number;
    /** The 256-bit (32-byte) account hash. */
    readonly hash: Uint8Array;

    /**
     * Construct a new Address from workchain and hash.
     *
     * @param workchain - Workchain ID (0 for basechain, -1 for masterchain)
     * @param hash - 32-byte address hash
     *
     * @example
     * ```typescript
     * const addr = new Address(0, hash32bytes);
     * ```
     */
    constructor(workchain: number, hash: Uint8Array) {
        if (hash.length !== 32) {
            throw new Error('Invalid address hash length: ' + hash.length);
        }
        this.workchain = workchain;
        this.hash = new Uint8Array(hash);
        Object.freeze(this);
    }

    /**
     * Convert the address to raw format (`workchain:hex_hash`).
     *
     * @returns Raw address string
     *
     * @example
     * ```typescript
     * addr.toRawString(); // "0:abcdef0123..."
     * ```
     */
    toRawString(): string {
        return this.workchain + ':' + bytesToHex(this.hash);
    }

    /**
     * Check if this address equals another address.
     *
     * @param src - The address to compare with
     * @returns true if both addresses have the same workchain and hash
     *
     * @example
     * ```typescript
     * const a = Address.parse("0:abc...");
     * const b = Address.parse("0:abc...");
     * a.equals(b); // true
     * ```
     */
    equals(src: Address): boolean {
        if (src.workchain !== this.workchain) {
            return false;
        }
        for (let i = 0; i < 32; i++) {
            if (src.hash[i] !== this.hash[i]) return false;
        }
        return true;
    }

    /**
     * Serialize the address to a 36-byte Uint8Array (tag + workchain + hash + CRC16).
     *
     * @param args - Optional flags for bounceable and testOnly encoding
     * @returns 36-byte Uint8Array suitable for base64 encoding
     */
    toStringBuffer(args?: {
        bounceable?: boolean;
        testOnly?: boolean;
    }): Uint8Array {
        const testOnly = args?.testOnly ?? false;
        const bounceable = args?.bounceable ?? true;

        let tag = bounceable ? BOUNCEABLE_TAG : NON_BOUNCEABLE_TAG;
        if (testOnly) {
            tag |= TEST_FLAG;
        }

        const addr = new Uint8Array(34);
        addr[0] = tag;
        addr[1] = this.workchain === -1 ? 0xff : this.workchain;
        addr.set(this.hash, 2);

        const addressWithChecksum = new Uint8Array(36);
        addressWithChecksum.set(addr);
        addressWithChecksum.set(crc16(addr), 34);
        return addressWithChecksum;
    }

    /**
     * Convert the address to a friendly base64 string.
     *
     * @param args - Optional formatting flags
     * @param args.urlSafe - Use URL-safe base64 (default true)
     * @param args.bounceable - Encode as bounceable (default true)
     * @param args.testOnly - Mark as testnet-only (default false)
     * @returns Friendly base64 address string
     *
     * @example
     * ```typescript
     * addr.toString(); // URL-safe bounceable by default
     * addr.toString({ bounceable: false }); // non-bounceable
     * addr.toString({ urlSafe: false });    // standard base64
     * ```
     */
    toString(args?: {
        urlSafe?: boolean;
        bounceable?: boolean;
        testOnly?: boolean;
    }): string {
        const urlSafe = args?.urlSafe ?? true;
        const buffer = this.toStringBuffer(args);
        if (urlSafe) {
            return bytesToBase64(buffer)
                .replace(/\+/g, '-')
                .replace(/\//g, '_');
        }
        return bytesToBase64(buffer);
    }
}

/**
 * Shorthand for `Address.parse()`. Parse an address string in any format.
 *
 * @param src - Address string to parse (raw or friendly format)
 * @returns A new Address instance
 *
 * @example
 * ```typescript
 * const addr = address("0:abcdef...");
 * const addr2 = address("EQBvW8Z5...");
 * ```
 */
export function address(src: string): Address {
    return Address.parse(src);
}
