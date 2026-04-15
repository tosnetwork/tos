/**
 * Internal key serialization for Dictionary.
 * Converts typed keys to/from string representation for Map storage.
 */

import { Address } from '../../address/Address';
import { BitString, paddedBufferToBits } from '../../boc/BitString';
import { bytesToHex, hexToBytes } from '../../utils/encoding';

export function serializeInternalKey(value: unknown): string {
    if (typeof value === 'number') {
        if (!Number.isSafeInteger(value)) {
            throw new Error('Invalid key type: not a safe integer: ' + value);
        }
        return 'n:' + value.toString(10);
    } else if (typeof value === 'bigint') {
        return 'b:' + value.toString(10);
    } else if (Address.isAddress(value)) {
        return 'a:' + value.toString();
    } else if (value instanceof Uint8Array) {
        return 'f:' + bytesToHex(value);
    } else if (BitString.isBitString(value)) {
        return 'B:' + value.toString();
    }
    throw new Error('Invalid key type');
}

export function deserializeInternalKey(value: string): unknown {
    const k = value.slice(0, 2);
    const v = value.slice(2);
    if (k === 'n:') {
        return parseInt(v, 10);
    } else if (k === 'b:') {
        return BigInt(v);
    } else if (k === 'a:') {
        return Address.parse(v);
    } else if (k === 'f:') {
        return hexToBytes(v);
    } else if (k === 'B:') {
        const lastDash = v.slice(-1) === '_';
        const isPadded = lastDash || v.length % 2 !== 0;
        if (isPadded) {
            let charLen = lastDash ? v.length - 1 : v.length;
            const padded = v.substring(0, charLen) + '0';
            if (!lastDash && (charLen & 1) !== 0) {
                return new BitString(hexToBytes(padded), 0, charLen << 2);
            } else {
                return paddedBufferToBits(hexToBytes(padded));
            }
        } else {
            return new BitString(hexToBytes(v), 0, v.length << 2);
        }
    }
    throw new Error('Invalid key type: ' + k);
}
