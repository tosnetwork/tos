/**
 * BitString is an immutable bit array backed by a Uint8Array.
 * Bits are stored in big-endian order (MSB first within each byte).
 */

import { bytesToHex } from '../utils/encoding';

/**
 * Immutable bit array backed by a Uint8Array, with big-endian bit ordering.
 *
 * BitStrings are created by the Builder or by parsing cells. They support
 * substring and equality operations, and can be converted to hex representation.
 *
 * @example
 * ```typescript
 * const bits = cell.bits;
 * console.log(bits.length);  // number of bits
 * console.log(bits.at(0));   // first bit (boolean)
 * console.log(bits.toString()); // hex representation
 * ```
 */
export class BitString {
    static readonly EMPTY = new BitString(new Uint8Array(0), 0, 0);

    private readonly _offset: number;
    private readonly _length: number;
    private readonly _data: Uint8Array;

    static isBitString(src: unknown): src is BitString {
        return src instanceof BitString;
    }

    /**
     * @param data   Backing byte array (must not be modified externally)
     * @param offset Bit offset from the start of data
     * @param length Number of bits in this string
     */
    constructor(data: Uint8Array, offset: number, length: number) {
        if (length < 0) {
            throw new Error(`Length ${length} is out of bounds`);
        }
        this._length = length;
        this._data = data;
        this._offset = offset;
    }

    get length(): number {
        return this._length;
    }

    /**
     * Returns the bit at the given index.
     * @returns true if the bit is 1, false if 0
     */
    at(index: number): boolean {
        if (index >= this._length) {
            throw new Error(`Index ${index} > ${this._length} is out of bounds`);
        }
        if (index < 0) {
            throw new Error(`Index ${index} < 0 is out of bounds`);
        }
        const byteIndex = (this._offset + index) >> 3;
        const bitIndex = 7 - ((this._offset + index) % 8);
        return (this._data[byteIndex]! & (1 << bitIndex)) !== 0;
    }

    /**
     * Get a substring of bits.
     */
    substring(offset: number, length: number): BitString {
        if (offset > this._length) {
            throw new Error(`Offset(${offset}) > ${this._length} is out of bounds`);
        }
        if (offset < 0) {
            throw new Error(`Offset(${offset}) < 0 is out of bounds`);
        }
        if (length === 0) {
            return BitString.EMPTY;
        }
        if (offset + length > this._length) {
            throw new Error(
                `Offset ${offset} + Length ${length} > ${this._length} is out of bounds`,
            );
        }
        return new BitString(this._data, this._offset + offset, length);
    }

    /**
     * Try to get a Uint8Array view of the region without copying.
     * Returns null if the region is not byte-aligned.
     */
    subbuffer(offset: number, length: number): Uint8Array | null {
        if (offset > this._length) {
            throw new Error(`Offset ${offset} is out of bounds`);
        }
        if (offset < 0) {
            throw new Error(`Offset ${offset} is out of bounds`);
        }
        if (offset + length > this._length) {
            throw new Error(
                `Offset + Length = ${offset + length} is out of bounds`,
            );
        }
        if (length % 8 !== 0) {
            return null;
        }
        if ((this._offset + offset) % 8 !== 0) {
            return null;
        }
        const start = (this._offset + offset) >> 3;
        const end = start + (length >> 3);
        return this._data.subarray(start, end);
    }

    equals(b: BitString): boolean {
        if (this._length !== b._length) {
            return false;
        }
        for (let i = 0; i < this._length; i++) {
            if (this.at(i) !== b.at(i)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Canonical hex string representation with padding marker.
     */
    toString(): string {
        const padded = bitsToPaddedBuffer(this);
        if (this._length % 4 === 0) {
            const s = bytesToHex(padded.subarray(0, Math.ceil(this._length / 8))).toUpperCase();
            if (this._length % 8 === 0) {
                return s;
            }
            return s.substring(0, s.length - 1);
        }
        const hex = bytesToHex(padded).toUpperCase();
        if (this._length % 8 <= 4) {
            return hex.substring(0, hex.length - 1) + '_';
        }
        return hex + '_';
    }
}

/**
 * Pad a BitString to a byte-aligned buffer using `1+0*` padding.
 *
 * @param bits - The BitString to pad
 * @returns Padded byte array
 */
export function bitsToPaddedBuffer(bits: BitString): Uint8Array {
    const builder = new BitBuilderLite(Math.ceil(bits.length / 8) * 8);
    for (let i = 0; i < bits.length; i++) {
        builder.writeBit(bits.at(i));
    }
    const padding = Math.ceil(bits.length / 8) * 8 - bits.length;
    for (let i = 0; i < padding; i++) {
        builder.writeBit(i === 0);
    }
    return builder.buffer();
}

/**
 * Interpret a padded byte buffer as a BitString (reverse of `bitsToPaddedBuffer`).
 *
 * @param buff - Padded byte array
 * @returns The decoded BitString
 */
export function paddedBufferToBits(buff: Uint8Array): BitString {
    let bitLen = 0;
    for (let i = buff.length - 1; i >= 0; i--) {
        if (buff[i] !== 0) {
            const testByte = buff[i]!;
            let bitPos = testByte & -testByte;
            if ((bitPos & 1) === 0) {
                bitPos = Math.log2(bitPos) + 1;
            }
            if (i > 0) {
                bitLen = i << 3;
            }
            bitLen += 8 - bitPos;
            break;
        }
    }
    return new BitString(buff, 0, bitLen);
}

/**
 * Minimal bit builder used only within this module to avoid circular deps.
 */
class BitBuilderLite {
    private _buffer: Uint8Array;
    private _length: number;

    constructor(size: number) {
        this._buffer = new Uint8Array(Math.ceil(size / 8));
        this._length = 0;
    }

    writeBit(value: boolean): void {
        if (value) {
            const idx = (this._length / 8) | 0;
            this._buffer[idx] = (this._buffer[idx] ?? 0) | (1 << (7 - (this._length % 8)));
        }
        this._length++;
    }

    buffer(): Uint8Array {
        return this._buffer.subarray(0, Math.ceil(this._length / 8));
    }
}
