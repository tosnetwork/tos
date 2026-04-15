/**
 * Fluent Builder for constructing Cells.
 * All store* methods return `this` for chaining.
 */

import { Address } from '../address/Address';
import { ExternalAddress } from '../address/ExternalAddress';
import { BitBuilder } from './BitBuilder';
import { BitString } from './BitString';
import { Cell } from './Cell';
import { Slice } from './Slice';
import { stringToBytes } from '../utils/encoding';
import type { Maybe } from '../types';

/**
 * Start building a new cell. Returns a fluent Builder whose store methods
 * can be chained, finalized with `.endCell()`.
 *
 * @returns A new empty Builder
 *
 * @example
 * ```typescript
 * const cell = beginCell()
 *   .storeUint(0x12345678, 32)
 *   .storeAddress(addr)
 *   .storeCoins(toNano("1.5"))
 *   .endCell();
 * ```
 */
export function beginCell(): Builder {
    return new Builder();
}

/**
 * Fluent cell builder. All `store*` methods return `this` for chaining.
 * Call {@link endCell} to finalize and produce an immutable {@link Cell}.
 *
 * @example
 * ```typescript
 * const cell = beginCell()
 *   .storeUint(42, 32)
 *   .storeAddress(addr)
 *   .storeRef(otherCell)
 *   .endCell();
 * ```
 */
export class Builder {
    private _bits: BitBuilder;
    private _refs: Cell[];

    constructor() {
        this._bits = new BitBuilder();
        this._refs = [];
    }

    /** Bits written so far */
    get bits(): number {
        return this._bits.length;
    }

    /** Refs written so far */
    get refs(): number {
        return this._refs.length;
    }

    /** Remaining available bits */
    get remainingBits(): number {
        return 1023 - this.bits;
    }

    /** Alias for remainingBits (TON compat) */
    get availableBits(): number {
        return 1023 - this.bits;
    }

    /** Remaining available refs */
    get remainingRefs(): number {
        return 4 - this.refs;
    }

    /** Alias for remainingRefs (TON compat) */
    get availableRefs(): number {
        return 4 - this.refs;
    }

    // --- Bits ---

    /**
     * Store a single bit.
     *
     * @param value - true/1 for bit=1, false/0 for bit=0
     * @returns this Builder for chaining
     */
    storeBit(value: boolean | number): this {
        this._bits.writeBit(value);
        return this;
    }

    /**
     * Store a BitString.
     *
     * @param src - The BitString to append
     * @returns this Builder for chaining
     */
    storeBits(src: BitString): this {
        this._bits.writeBits(src);
        return this;
    }

    // --- Buffer ---

    /**
     * Store raw bytes.
     *
     * @param src - Byte array to store
     * @param bytes - Expected length (for validation); omit to accept any length
     * @returns this Builder for chaining
     */
    storeBuffer(src: Uint8Array, bytes?: Maybe<number>): this {
        if (bytes !== undefined && bytes !== null) {
            if (src.length !== bytes) {
                throw new Error(
                    `Buffer length ${src.length} is not equal to ${bytes}`,
                );
            }
        }
        this._bits.writeBytes(src);
        return this;
    }

    // --- Uint ---

    /**
     * Store an unsigned integer.
     *
     * @param value - The unsigned integer value
     * @param bits - Number of bits to use for encoding
     * @returns this Builder for chaining
     *
     * @example
     * ```typescript
     * beginCell().storeUint(0x12345678, 32).endCell();
     * ```
     */
    storeUint(value: bigint | number, bits: number): this {
        this._bits.writeUint(value, bits);
        return this;
    }

    /** Store an optional unsigned integer (1-bit flag + value if present). */
    storeMaybeUint(value: Maybe<number | bigint>, bits: number): this {
        if (value !== null && value !== undefined) {
            this.storeBit(1);
            this.storeUint(value, bits);
        } else {
            this.storeBit(0);
        }
        return this;
    }

    // --- Int ---

    /**
     * Store a signed integer.
     *
     * @param value - The signed integer value
     * @param bits - Number of bits to use for encoding
     * @returns this Builder for chaining
     */
    storeInt(value: bigint | number, bits: number): this {
        this._bits.writeInt(value, bits);
        return this;
    }

    /** Store an optional signed integer (1-bit flag + value if present). */
    storeMaybeInt(value: Maybe<number | bigint>, bits: number): this {
        if (value !== null && value !== undefined) {
            this.storeBit(1);
            this.storeInt(value, bits);
        } else {
            this.storeBit(0);
        }
        return this;
    }

    // --- VarUint ---

    /** Store a variable-length unsigned integer. */
    storeVarUint(value: number | bigint, bits: number): this {
        this._bits.writeVarUint(value, bits);
        return this;
    }

    // --- VarInt ---

    /** Store a variable-length signed integer. */
    storeVarInt(value: number | bigint, bits: number): this {
        this._bits.writeVarInt(value, bits);
        return this;
    }

    // --- Coins ---

    /**
     * Store a variable-length coin amount (TOS/nanoTOS).
     *
     * @param amount - Coin amount in nanoTOS
     * @returns this Builder for chaining
     *
     * @example
     * ```typescript
     * beginCell().storeCoins(toNano("1.5")).endCell();
     * ```
     */
    storeCoins(amount: number | bigint): this {
        this._bits.writeCoins(amount);
        return this;
    }

    /** Store an optional coin amount (1-bit flag + coins if present). */
    storeMaybeCoins(amount: Maybe<number | bigint>): this {
        if (amount !== null && amount !== undefined) {
            this.storeBit(1);
            this.storeCoins(amount);
        } else {
            this.storeBit(0);
        }
        return this;
    }

    // --- Address ---

    /**
     * Store an internal or external address (or null for addr_none).
     *
     * @param address - The address to store, or null/undefined for addr_none
     * @returns this Builder for chaining
     *
     * @example
     * ```typescript
     * beginCell().storeAddress(Address.parse("0:abc...")).endCell();
     * ```
     */
    storeAddress(address: Maybe<Address | ExternalAddress>): this {
        this._bits.writeAddress(address);
        return this;
    }

    // --- Refs ---

    /**
     * Store a reference to another cell (max 4 refs per cell).
     *
     * @param cell - A Cell or Builder to store as a reference
     * @returns this Builder for chaining
     * @throws Error if the cell already has 4 references
     *
     * @example
     * ```typescript
     * const inner = beginCell().storeUint(42, 32).endCell();
     * const outer = beginCell().storeRef(inner).endCell();
     * ```
     */
    storeRef(cell: Cell | Builder): this {
        if (this._refs.length >= 4) {
            throw new Error('Too many references');
        }
        if (cell instanceof Cell) {
            this._refs.push(cell);
        } else if (cell instanceof Builder) {
            this._refs.push(cell.endCell());
        } else {
            throw new Error('Invalid argument');
        }
        return this;
    }

    /** Store an optional cell reference (1-bit flag + ref if present). */
    storeMaybeRef(cell?: Maybe<Cell | Builder>): this {
        if (cell) {
            this.storeBit(1);
            this.storeRef(cell);
        } else {
            this.storeBit(0);
        }
        return this;
    }

    // --- Slice ---

    /**
     * Store the remaining contents of a Slice (bits and refs).
     *
     * @param src - The Slice whose remaining data will be copied
     * @returns this Builder for chaining
     */
    storeSlice(src: Slice): this {
        const c = src.clone();
        if (c.remainingBits > 0) {
            this.storeBits(c.loadBits(c.remainingBits));
        }
        while (c.remainingRefs > 0) {
            this.storeRef(c.loadRef());
        }
        return this;
    }

    // --- Builder ---

    /** Store the contents of another Builder. */
    storeBuilder(src: Builder): this {
        return this.storeSlice(src.endCell().beginParse());
    }

    // --- Strings ---

    /**
     * Store a UTF-8 string using the snake-format encoding (tail-recursive refs).
     *
     * @param src - The string to store
     * @returns this Builder for chaining
     *
     * @example
     * ```typescript
     * beginCell().storeStringTail("Hello, TOS!").endCell();
     * ```
     */
    storeStringTail(src: string): this {
        writeStringToBuilder(src, this);
        return this;
    }

    /** Store a UTF-8 string as a ref cell using snake-format encoding. */
    storeStringRefTail(src: string): this {
        this.storeRef(beginCell().storeStringTail(src));
        return this;
    }

    // --- Dict ---

    /**
     * Store a Dictionary as a maybe-ref (1-bit flag + optional ref).
     *
     * @param dict - The Dictionary to store, or null/undefined for empty dict (bit=0)
     * @param key - Optional key serializer override
     * @param value - Optional value serializer override
     * @returns this Builder for chaining
     */
    storeDict(dict?: Maybe<{ store(builder: Builder, key?: unknown, value?: unknown): void }>,
              key?: unknown,
              value?: unknown): this {
        if (dict) {
            dict.store(this, key, value);
        } else {
            this.storeBit(0);
        }
        return this;
    }

    // --- Writable ---

    /** Store data using a custom writer function. */
    storeWritable(writer: ((builder: Builder) => void)): this {
        writer(this);
        return this;
    }

    /** Alias for {@link storeWritable}. */
    store(writer: ((builder: Builder) => void)): this {
        return this.storeWritable(writer);
    }

    // --- End ---

    /**
     * Finalize the builder and produce an immutable Cell.
     *
     * @param opts - Set `exotic: true` to create an exotic cell
     * @returns The constructed Cell
     *
     * @example
     * ```typescript
     * const cell = beginCell()
     *   .storeUint(0, 32)
     *   .endCell();
     * ```
     */
    endCell(opts?: { exotic?: boolean }): Cell {
        return new Cell({
            bits: this._bits.build(),
            refs: this._refs,
            exotic: opts?.exotic,
        });
    }

    /** Alias for {@link endCell}. */
    asCell(): Cell {
        return this.endCell();
    }

    /** Finalize and parse the result as a Slice. */
    asSlice(): Slice {
        return this.endCell().beginParse();
    }
}

// --- String writing helper ---

function writeStringBuffer(src: Uint8Array, builder: Builder): void {
    if (src.length > 0) {
        const bytes = Math.floor(builder.availableBits / 8);
        if (src.length > bytes) {
            const a = src.subarray(0, bytes);
            const t = src.subarray(bytes);
            builder.storeBuffer(a);
            const bb = beginCell();
            writeStringBuffer(t, bb);
            builder.storeRef(bb.endCell());
        } else {
            builder.storeBuffer(src);
        }
    }
}

function writeStringToBuilder(src: string, builder: Builder): void {
    writeStringBuffer(stringToBytes(src), builder);
}
