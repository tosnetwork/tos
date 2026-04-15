/**
 * Cursor-based bit reader. Reads bits from a BitString.
 */

import { Address } from '../address/Address';
import { ExternalAddress } from '../address/ExternalAddress';
import { BitString } from './BitString';

/**
 * Low-level cursor-based bit reader. Reads bits from a BitString.
 *
 * This is the building block used internally by {@link Slice}. Most users
 * should use `cell.beginParse()` and the Slice API instead.
 */
export class BitReader {
    private _bits: BitString;
    private _offset: number;
    private _checkpoints: number[] = [];

    constructor(bits: BitString, offset: number = 0) {
        this._bits = bits;
        this._offset = offset;
    }

    get offset(): number {
        return this._offset;
    }

    get remaining(): number {
        return this._bits.length - this._offset;
    }

    skip(bits: number): void {
        if (bits < 0 || this._offset + bits > this._bits.length) {
            throw new Error(`Index ${this._offset + bits} is out of bounds`);
        }
        this._offset += bits;
    }

    reset(): void {
        if (this._checkpoints.length > 0) {
            this._offset = this._checkpoints.pop()!;
        } else {
            this._offset = 0;
        }
    }

    save(): void {
        this._checkpoints.push(this._offset);
    }

    loadBit(): boolean {
        const r = this._bits.at(this._offset);
        this._offset++;
        return r;
    }

    preloadBit(): boolean {
        return this._bits.at(this._offset);
    }

    loadBits(bits: number): BitString {
        const r = this._bits.substring(this._offset, bits);
        this._offset += bits;
        return r;
    }

    preloadBits(bits: number): BitString {
        return this._bits.substring(this._offset, bits);
    }

    loadBuffer(bytes: number): Uint8Array {
        const buf = this._preloadBuffer(bytes, this._offset);
        this._offset += bytes * 8;
        return buf;
    }

    preloadBuffer(bytes: number): Uint8Array {
        return this._preloadBuffer(bytes, this._offset);
    }

    loadUint(bits: number): number {
        return this._toSafeInteger(this.loadUintBig(bits), 'loadUintBig');
    }

    loadUintBig(bits: number): bigint {
        const loaded = this.preloadUintBig(bits);
        this._offset += bits;
        return loaded;
    }

    preloadUint(bits: number): number {
        return this._toSafeInteger(
            this._preloadUint(bits, this._offset),
            'preloadUintBig',
        );
    }

    preloadUintBig(bits: number): bigint {
        return this._preloadUint(bits, this._offset);
    }

    loadInt(bits: number): number {
        const res = this._preloadInt(bits, this._offset);
        this._offset += bits;
        return this._toSafeInteger(res, 'loadIntBig');
    }

    loadIntBig(bits: number): bigint {
        const res = this._preloadInt(bits, this._offset);
        this._offset += bits;
        return res;
    }

    preloadInt(bits: number): number {
        return this._toSafeInteger(
            this._preloadInt(bits, this._offset),
            'preloadIntBig',
        );
    }

    preloadIntBig(bits: number): bigint {
        return this._preloadInt(bits, this._offset);
    }

    loadVarUint(bits: number): number {
        const size = Number(this.loadUint(bits));
        return this._toSafeInteger(this.loadUintBig(size * 8), 'loadVarUintBig');
    }

    loadVarUintBig(bits: number): bigint {
        const size = Number(this.loadUint(bits));
        return this.loadUintBig(size * 8);
    }

    preloadVarUint(bits: number): number {
        const size = Number(this._preloadUint(bits, this._offset));
        return this._toSafeInteger(
            this._preloadUint(size * 8, this._offset + bits),
            'preloadVarUintBig',
        );
    }

    preloadVarUintBig(bits: number): bigint {
        const size = Number(this._preloadUint(bits, this._offset));
        return this._preloadUint(size * 8, this._offset + bits);
    }

    loadVarInt(bits: number): number {
        const size = Number(this.loadUint(bits));
        return this._toSafeInteger(this.loadIntBig(size * 8), 'loadVarIntBig');
    }

    loadVarIntBig(bits: number): bigint {
        const size = Number(this.loadUint(bits));
        return this.loadIntBig(size * 8);
    }

    preloadVarInt(bits: number): number {
        const size = Number(this._preloadUint(bits, this._offset));
        return this._toSafeInteger(
            this._preloadInt(size * 8, this._offset + bits),
            'preloadVarIntBig',
        );
    }

    preloadVarIntBig(bits: number): bigint {
        const size = Number(this._preloadUint(bits, this._offset));
        return this._preloadInt(size * 8, this._offset + bits);
    }

    loadCoins(): bigint {
        return this.loadVarUintBig(4);
    }

    preloadCoins(): bigint {
        return this.preloadVarUintBig(4);
    }

    loadAddress(): Address {
        const type = Number(this._preloadUint(2, this._offset));
        if (type === 2) {
            return this._loadInternalAddress();
        }
        throw new Error('Invalid address: ' + type);
    }

    loadMaybeAddress(): Address | null {
        const type = Number(this._preloadUint(2, this._offset));
        if (type === 0) {
            this._offset += 2;
            return null;
        } else if (type === 2) {
            return this._loadInternalAddress();
        }
        throw new Error('Invalid address');
    }

    loadExternalAddress(): ExternalAddress {
        const type = Number(this._preloadUint(2, this._offset));
        if (type === 1) {
            return this._loadExternalAddress();
        }
        throw new Error('Invalid address');
    }

    loadMaybeExternalAddress(): ExternalAddress | null {
        const type = Number(this._preloadUint(2, this._offset));
        if (type === 0) {
            this._offset += 2;
            return null;
        } else if (type === 1) {
            return this._loadExternalAddress();
        }
        throw new Error('Invalid address');
    }

    loadAddressAny(): Address | ExternalAddress | null {
        const type = Number(this._preloadUint(2, this._offset));
        if (type === 0) {
            this._offset += 2;
            return null;
        } else if (type === 2) {
            return this._loadInternalAddress();
        } else if (type === 1) {
            return this._loadExternalAddress();
        } else if (type === 3) {
            throw new Error('Unsupported');
        }
        throw new Error('Unreachable');
    }

    loadPaddedBits(bits: number): BitString {
        if (bits % 8 !== 0) {
            throw new Error('Invalid number of bits');
        }
        let length = bits;
        while (true) {
            if (this._bits.at(this._offset + length - 1)) {
                length--;
                break;
            } else {
                length--;
            }
        }
        const r = this._bits.substring(this._offset, length);
        this._offset += bits;
        return r;
    }

    clone(): BitReader {
        const r = new BitReader(this._bits, this._offset);
        r._checkpoints = [...this._checkpoints];
        return r;
    }

    // --- private ---

    private _preloadInt(bits: number, offset: number): bigint {
        if (bits === 0) return 0n;
        const sign = this._bits.at(offset);
        let res = 0n;
        for (let i = 0; i < bits - 1; i++) {
            if (this._bits.at(offset + 1 + i)) {
                res += 1n << BigInt(bits - i - 1 - 1);
            }
        }
        if (sign) {
            res = res - (1n << BigInt(bits - 1));
        }
        return res;
    }

    private _preloadUint(bits: number, offset: number): bigint {
        if (bits === 0) return 0n;
        let res = 0n;
        for (let i = 0; i < bits; i++) {
            if (this._bits.at(offset + i)) {
                res += 1n << BigInt(bits - i - 1);
            }
        }
        return res;
    }

    private _preloadBuffer(bytes: number, offset: number): Uint8Array {
        const fastBuffer = this._bits.subbuffer(offset, bytes * 8);
        if (fastBuffer) {
            // Return a copy to avoid mutation
            return new Uint8Array(fastBuffer);
        }
        const buf = new Uint8Array(bytes);
        for (let i = 0; i < bytes; i++) {
            buf[i] = Number(this._preloadUint(8, offset + i * 8));
        }
        return buf;
    }

    private _loadInternalAddress(): Address {
        const type = Number(this._preloadUint(2, this._offset));
        if (type !== 2) throw new Error('Invalid address');

        // Skip anycast
        if (this._preloadUint(1, this._offset + 2) !== 0n) {
            const rewriteDepth = Number(this._preloadUint(5, this._offset + 3));
            this._offset += 5 + rewriteDepth;
        }

        const wc = Number(this._preloadInt(8, this._offset + 3));
        const hash = this._preloadBuffer(32, this._offset + 11);
        this._offset += 267;
        return new Address(wc, hash);
    }

    private _loadExternalAddress(): ExternalAddress {
        const type = Number(this._preloadUint(2, this._offset));
        if (type !== 1) throw new Error('Invalid address');
        const bits = Number(this._preloadUint(9, this._offset + 2));
        const value = this._preloadUint(bits, this._offset + 11);
        this._offset += 11 + bits;
        return new ExternalAddress(value, bits);
    }

    private _toSafeInteger(src: bigint, alt: string): number {
        if (
            BigInt(Number.MAX_SAFE_INTEGER) < src ||
            src < BigInt(Number.MIN_SAFE_INTEGER)
        ) {
            throw new TypeError(
                `${src} is out of safe integer range. Use ${alt} instead`,
            );
        }
        return Number(src);
    }
}
