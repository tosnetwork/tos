/**
 * Mutable bit builder. Writes bits into a Uint8Array in big-endian order.
 */

import { Address } from '../address/Address';
import { ExternalAddress } from '../address/ExternalAddress';
import { BitString } from './BitString';
import type { Maybe } from '../types';

/**
 * Mutable bit builder that writes bits into a Uint8Array in big-endian order.
 *
 * This is the low-level building block used by {@link Builder}. Most users
 * should use `beginCell()` instead of using BitBuilder directly.
 */
export class BitBuilder {
    private _buffer: Uint8Array;
    private _length: number;

    constructor(size: number = 1023) {
        this._buffer = new Uint8Array(Math.ceil(size / 8));
        this._length = 0;
    }

    get length(): number {
        return this._length;
    }

    writeBit(value: boolean | number): void {
        const n = this._length;
        if (n >= this._buffer.length * 8) {
            throw new Error('BitBuilder overflow');
        }
        if (
            (typeof value === 'boolean' && value) ||
            (typeof value === 'number' && value > 0)
        ) {
            const idx = (n / 8) | 0;
            this._buffer[idx] = (this._buffer[idx] ?? 0) | (1 << (7 - (n % 8)));
        }
        this._length++;
    }

    writeBits(src: BitString): void {
        for (let i = 0; i < src.length; i++) {
            this.writeBit(src.at(i));
        }
    }

    writeBytes(src: Uint8Array): void {
        if (this._length % 8 === 0) {
            if (this._length + src.length * 8 > this._buffer.length * 8) {
                throw new Error('BitBuilder overflow');
            }
            this._buffer.set(src, this._length / 8);
            this._length += src.length * 8;
        } else {
            for (let i = 0; i < src.length; i++) {
                this.writeUint(src[i]!, 8);
            }
        }
    }

    writeUint(value: bigint | number, bits: number): void {
        if (bits < 0 || !Number.isSafeInteger(bits)) {
            throw new Error(`invalid bit length. Got ${bits}`);
        }
        const v = BigInt(value);
        if (bits === 0) {
            if (v !== 0n) {
                throw new Error(`value is not zero for ${bits} bits. Got ${value}`);
            }
            return;
        }
        const vBits = 1n << BigInt(bits);
        if (v < 0 || v >= vBits) {
            throw new Error(`bitLength is too small for a value ${value}. Got ${bits}`);
        }
        if (this._length + bits > this._buffer.length * 8) {
            throw new Error('BitBuilder overflow');
        }

        const tillByte = 8 - (this._length % 8);
        if (tillByte > 0) {
            const bidx = Math.floor(this._length / 8);
            if (bits < tillByte) {
                const wb = Number(v);
                this._buffer[bidx] = (this._buffer[bidx] ?? 0) | (wb << (tillByte - bits));
                this._length += bits;
            } else {
                const wb = Number(v >> BigInt(bits - tillByte));
                this._buffer[bidx] = (this._buffer[bidx] ?? 0) | wb;
                this._length += tillByte;
            }
        }
        let remaining = bits - tillByte;

        while (remaining > 0) {
            const byteIdx = this._length / 8;
            if (remaining >= 8) {
                this._buffer[byteIdx] = Number(
                    (v >> BigInt(remaining - 8)) & 0xffn,
                );
                this._length += 8;
                remaining -= 8;
            } else {
                this._buffer[byteIdx] = Number(
                    (v << BigInt(8 - remaining)) & 0xffn,
                );
                this._length += remaining;
                remaining = 0;
            }
        }
    }

    writeInt(value: bigint | number, bits: number): void {
        let v = BigInt(value);
        if (bits < 0 || !Number.isSafeInteger(bits)) {
            throw new Error(`invalid bit length. Got ${bits}`);
        }
        if (bits === 0) {
            if (v !== 0n) {
                throw new Error(`value is not zero for ${bits} bits. Got ${value}`);
            }
            return;
        }
        if (bits === 1) {
            if (v !== -1n && v !== 0n) {
                throw new Error(`value is not zero or -1 for ${bits} bits. Got ${value}`);
            }
            this.writeBit(v === -1n);
            return;
        }
        const vBits = 1n << (BigInt(bits) - 1n);
        if (v < -vBits || v >= vBits) {
            throw new Error(`value is out of range for ${bits} bits. Got ${value}`);
        }
        if (v < 0) {
            this.writeBit(true);
            v = vBits + v;
        } else {
            this.writeBit(false);
        }
        this.writeUint(v, bits - 1);
    }

    writeVarUint(value: number | bigint, bits: number): void {
        const v = BigInt(value);
        if (bits < 0 || !Number.isSafeInteger(bits)) {
            throw new Error(`invalid bit length. Got ${bits}`);
        }
        if (v < 0) {
            throw new Error(`value is negative. Got ${value}`);
        }
        if (v === 0n) {
            this.writeUint(0, bits);
            return;
        }
        const sizeBytes = Math.ceil(v.toString(2).length / 8);
        const sizeBits = sizeBytes * 8;
        this.writeUint(sizeBytes, bits);
        this.writeUint(v, sizeBits);
    }

    writeVarInt(value: number | bigint, bits: number): void {
        const v = BigInt(value);
        if (bits < 0 || !Number.isSafeInteger(bits)) {
            throw new Error(`invalid bit length. Got ${bits}`);
        }
        if (v === 0n) {
            this.writeUint(0, bits);
            return;
        }
        const v2 = v > 0 ? v : -v;
        const sizeBytes = Math.ceil((v2.toString(2).length + 1) / 8);
        const sizeBits = sizeBytes * 8;
        this.writeUint(sizeBytes, bits);
        this.writeInt(v, sizeBits);
    }

    writeCoins(amount: number | bigint): void {
        this.writeVarUint(amount, 4);
    }

    writeAddress(address: Maybe<Address | ExternalAddress>): void {
        if (address === null || address === undefined) {
            this.writeUint(0, 2);
            return;
        }
        if (Address.isAddress(address)) {
            this.writeUint(2, 2);
            this.writeUint(0, 1);
            this.writeInt(address.workchain, 8);
            this.writeBytes(address.hash);
            return;
        }
        if (ExternalAddress.isAddress(address)) {
            this.writeUint(1, 2);
            this.writeUint(address.bits, 9);
            this.writeUint(address.value, address.bits);
            return;
        }
        throw new Error(`Invalid address. Got ${address}`);
    }

    build(): BitString {
        return new BitString(this._buffer, 0, this._length);
    }

    buffer(): Uint8Array {
        if (this._length % 8 !== 0) {
            throw new Error('BitBuilder buffer is not byte aligned');
        }
        return this._buffer.subarray(0, this._length / 8);
    }
}
