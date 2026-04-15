/**
 * Slice: cursor-based cell reader.
 * Advances internal position on each load* call.
 */

import { Address } from '../address/Address';
import { ExternalAddress } from '../address/ExternalAddress';
import { BitReader } from './BitReader';
import { BitString } from './BitString';
import { Cell } from './Cell';
import { bytesToString } from '../utils/encoding';

// These circular imports are safe in ES modules (live bindings).
// By the time any method is called at runtime, all modules are initialized.
import { beginCell, type Builder } from './Builder';
import { parseDict } from '../dict/parseDict';

/**
 * Cursor-based cell reader. Each `load*` call advances the internal position.
 * Use `preload*` methods to read without advancing.
 *
 * Obtain a Slice by calling `cell.beginParse()` or `cell.asSlice()`.
 *
 * @example
 * ```typescript
 * const slice = cell.beginParse();
 * const opCode = slice.loadUint(32);
 * const addr = slice.loadAddress();
 * const amount = slice.loadCoins();
 * const child = slice.loadRef();
 * ```
 */
export class Slice {
    private _reader: BitReader;
    private _refs: Cell[];
    private _refsOffset: number;

    constructor(reader: BitReader, refs: Cell[]) {
        this._reader = reader.clone();
        this._refs = [...refs];
        this._refsOffset = 0;
    }

    // --- Properties ---

    get remainingBits(): number {
        return this._reader.remaining;
    }

    get offsetBits(): number {
        return this._reader.offset;
    }

    get remainingRefs(): number {
        return this._refs.length - this._refsOffset;
    }

    get offsetRefs(): number {
        return this._refsOffset;
    }

    // --- Bits ---

    skip(bits: number): this {
        this._reader.skip(bits);
        return this;
    }

    /**
     * Load a single bit and advance the cursor.
     *
     * @returns true if the bit is 1, false if 0
     */
    loadBit(): boolean {
        return this._reader.loadBit();
    }

    preloadBit(): boolean {
        return this._reader.preloadBit();
    }

    loadBoolean(): boolean {
        return this.loadBit();
    }

    loadBits(bits: number): BitString {
        return this._reader.loadBits(bits);
    }

    preloadBits(bits: number): BitString {
        return this._reader.preloadBits(bits);
    }

    // --- Uint ---

    /**
     * Load an unsigned integer and advance the cursor.
     *
     * @param bits - Number of bits to read
     * @returns The unsigned integer value (as a number; throws if unsafe)
     *
     * @example
     * ```typescript
     * const opCode = slice.loadUint(32);
     * ```
     */
    loadUint(bits: number): number {
        return this._reader.loadUint(bits);
    }

    /**
     * Load an unsigned integer as a bigint and advance the cursor.
     *
     * @param bits - Number of bits to read
     * @returns The unsigned integer value as a bigint
     */
    loadUintBig(bits: number): bigint {
        return this._reader.loadUintBig(bits);
    }

    preloadUint(bits: number): number {
        return this._reader.preloadUint(bits);
    }

    preloadUintBig(bits: number): bigint {
        return this._reader.preloadUintBig(bits);
    }

    // --- Int ---

    loadInt(bits: number): number {
        return this._reader.loadInt(bits);
    }

    loadIntBig(bits: number): bigint {
        return this._reader.loadIntBig(bits);
    }

    preloadInt(bits: number): number {
        return this._reader.preloadInt(bits);
    }

    preloadIntBig(bits: number): bigint {
        return this._reader.preloadIntBig(bits);
    }

    // --- VarUint ---

    loadVarUint(bits: number): number {
        return this._reader.loadVarUint(bits);
    }

    loadVarUintBig(bits: number): bigint {
        return this._reader.loadVarUintBig(bits);
    }

    preloadVarUint(bits: number): number {
        return this._reader.preloadVarUint(bits);
    }

    preloadVarUintBig(bits: number): bigint {
        return this._reader.preloadVarUintBig(bits);
    }

    // --- VarInt ---

    loadVarInt(bits: number): number {
        return this._reader.loadVarInt(bits);
    }

    loadVarIntBig(bits: number): bigint {
        return this._reader.loadVarIntBig(bits);
    }

    preloadVarInt(bits: number): number {
        return this._reader.preloadVarInt(bits);
    }

    preloadVarIntBig(bits: number): bigint {
        return this._reader.preloadVarIntBig(bits);
    }

    // --- Coins ---

    /**
     * Load a variable-length coin amount and advance the cursor.
     *
     * @returns The coin amount as a bigint (in nanoTOS)
     *
     * @example
     * ```typescript
     * const amount = slice.loadCoins(); // e.g. 1500000000n
     * ```
     */
    loadCoins(): bigint {
        return this._reader.loadCoins();
    }

    preloadCoins(): bigint {
        return this._reader.preloadCoins();
    }

    // --- Address ---

    /**
     * Load an internal address and advance the cursor.
     *
     * @returns The parsed Address
     * @throws Error if the address type is not internal (type=2)
     *
     * @example
     * ```typescript
     * const addr = slice.loadAddress();
     * console.log(addr.toString());
     * ```
     */
    loadAddress(): Address {
        return this._reader.loadAddress();
    }

    /**
     * Load an optional internal address (returns null for addr_none).
     *
     * @returns The parsed Address, or null if addr_none
     */
    loadMaybeAddress(): Address | null {
        return this._reader.loadMaybeAddress();
    }

    loadExternalAddress(): ExternalAddress {
        return this._reader.loadExternalAddress();
    }

    loadMaybeExternalAddress(): ExternalAddress | null {
        return this._reader.loadMaybeExternalAddress();
    }

    loadAddressAny(): Address | ExternalAddress | null {
        return this._reader.loadAddressAny();
    }

    // --- Refs ---

    /**
     * Load the next cell reference and advance the ref cursor.
     *
     * @returns The referenced Cell
     * @throws Error if no more references are available
     *
     * @example
     * ```typescript
     * const childCell = slice.loadRef();
     * const childSlice = childCell.beginParse();
     * ```
     */
    loadRef(): Cell {
        if (this._refsOffset >= this._refs.length) {
            throw new Error('No more references');
        }
        return this._refs[this._refsOffset++]!;
    }

    preloadRef(): Cell {
        if (this._refsOffset >= this._refs.length) {
            throw new Error('No more references');
        }
        return this._refs[this._refsOffset]!;
    }

    loadMaybeRef(): Cell | null {
        if (this.loadBit()) {
            return this.loadRef();
        }
        return null;
    }

    preloadMaybeRef(): Cell | null {
        if (this.preloadBit()) {
            return this.preloadRef();
        }
        return null;
    }

    // --- Buffer ---

    loadBuffer(bytes: number): Uint8Array {
        return this._reader.loadBuffer(bytes);
    }

    preloadBuffer(bytes: number): Uint8Array {
        return this._reader.preloadBuffer(bytes);
    }

    // --- Strings ---

    /**
     * Load a UTF-8 string stored in snake (tail-recursive) format.
     *
     * @returns The decoded string
     */
    loadStringTail(): string {
        return readString(this);
    }

    loadStringRefTail(): string {
        return readString(this.loadRef().beginParse());
    }

    // --- Dict ---

    loadDict<V>(
        key: { bits: number; parse(src: bigint): unknown },
        value: { parse(src: Slice): V },
    ): Map<bigint, V> {
        const cell = this.loadMaybeRef();
        if (!cell || cell.isExotic) {
            return new Map<bigint, V>();
        }
        return parseDict<V>(cell.beginParse(), key.bits, value.parse);
    }

    // --- End ---

    /**
     * Assert that the slice has been fully consumed (no remaining bits or refs).
     *
     * @throws Error if the slice is not empty
     */
    endParse(): void {
        if (this.remainingBits > 0 || this.remainingRefs > 0) {
            throw new Error('Slice is not empty');
        }
    }

    // --- Conversion ---

    asCell(): Cell {
        return beginCell().storeSlice(this).endCell();
    }

    asBuilder(): Builder {
        return beginCell().storeSlice(this);
    }

    // --- Clone ---

    /**
     * Create a copy of this Slice.
     *
     * @param fromStart - If true, reset the cursor to the beginning (default false)
     * @returns A new Slice with its own cursor position
     */
    clone(fromStart: boolean = false): Slice {
        if (fromStart) {
            const reader = this._reader.clone();
            reader.reset();
            return new Slice(reader, this._refs);
        }
        const res = new Slice(this._reader, this._refs);
        res._refsOffset = this._refsOffset;
        return res;
    }

    toString(): string {
        return this.asCell().toString();
    }
}

// -- String reading helper (tail-recursive snake format) --

function readStringBytes(slice: Slice): Uint8Array {
    if (slice.remainingBits % 8 !== 0) {
        throw new Error(`Invalid string length: ${slice.remainingBits}`);
    }
    if (slice.remainingRefs !== 0 && slice.remainingRefs !== 1) {
        throw new Error(`Invalid number of refs: ${slice.remainingRefs}`);
    }

    let res: Uint8Array;
    if (slice.remainingBits === 0) {
        res = new Uint8Array(0);
    } else {
        res = slice.loadBuffer(slice.remainingBits / 8);
    }

    if (slice.remainingRefs === 1) {
        const tail = readStringBytes(slice.loadRef().beginParse());
        const merged = new Uint8Array(res.length + tail.length);
        merged.set(res);
        merged.set(tail, res.length);
        return merged;
    }

    return res;
}

function readString(slice: Slice): string {
    return bytesToString(readStringBytes(slice));
}
