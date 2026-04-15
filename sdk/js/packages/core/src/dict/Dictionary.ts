/**
 * Generic Dictionary<K, V> - TVM hashmap implementation.
 */

import { Address } from '../address/Address';
import { beginCell, Builder } from '../boc/Builder';
import { Cell } from '../boc/Cell';
import { Slice } from '../boc/Slice';
import { BitString } from '../boc/BitString';
import type { Maybe } from '../types';
import { parseDict } from './parseDict';
import { serializeDict } from './serializeDict';
import {
    deserializeInternalKey,
    serializeInternalKey,
} from './utils/internalKeySerializer';

export type DictionaryKeyTypes = Address | number | bigint | Uint8Array | BitString;

export interface DictionaryKey<K extends DictionaryKeyTypes> {
    bits: number;
    serialize(src: K): bigint;
    parse(src: bigint): K;
}

export interface DictionaryValue<V> {
    serialize(src: V, builder: Builder): void;
    parse(src: Slice): V;
}

/**
 * Generic TVM hashmap (dictionary) implementation.
 *
 * Provides typed get/set/delete operations on a TVM dictionary, with built-in
 * key and value serializers accessible via `Dictionary.Keys` and `Dictionary.Values`.
 *
 * @example
 * ```typescript
 * // Create a dictionary mapping uint32 keys to bigint values
 * const dict = Dictionary.empty<number, bigint>(
 *   Dictionary.Keys.Uint(32),
 *   Dictionary.Values.BigInt(64),
 * );
 * dict.set(1, 100n);
 * dict.set(2, 200n);
 *
 * // Store in a cell
 * const cell = beginCell().storeDict(dict).endCell();
 *
 * // Load from a cell
 * const loaded = Dictionary.load(
 *   Dictionary.Keys.Uint(32),
 *   Dictionary.Values.BigInt(64),
 *   cell.beginParse(),
 * );
 * ```
 */
export class Dictionary<K extends DictionaryKeyTypes, V> {
    /**
     * Built-in key serializer factories for common key types.
     *
     * @example
     * ```typescript
     * Dictionary.Keys.Uint(32)    // uint32 keys
     * Dictionary.Keys.Address()   // Address keys
     * Dictionary.Keys.BigInt(256) // 256-bit signed bigint keys
     * ```
     */
    static Keys = {
        Address: (): DictionaryKey<Address> => createAddressKey(),
        BigInt: (bits: number): DictionaryKey<bigint> => createBigIntKey(bits),
        Int: (bits: number): DictionaryKey<number> => createIntKey(bits),
        BigUint: (bits: number): DictionaryKey<bigint> => createBigUintKey(bits),
        Uint: (bits: number): DictionaryKey<number> => createUintKey(bits),
        Buffer: (bytes: number): DictionaryKey<Uint8Array> => createBufferKey(bytes),
        BitString: (bits: number): DictionaryKey<BitString> => createBitStringKey(bits),
    };

    /**
     * Built-in value serializer factories for common value types.
     *
     * @example
     * ```typescript
     * Dictionary.Values.BigInt(64)   // 64-bit signed bigint values
     * Dictionary.Values.Cell()       // Cell values (stored as refs)
     * Dictionary.Values.Address()    // Address values
     * Dictionary.Values.Bool()       // Boolean values (1 bit)
     * ```
     */
    static Values = {
        BigInt: (bits: number): DictionaryValue<bigint> => createBigIntValue(bits),
        Int: (bits: number): DictionaryValue<number> => createIntValue(bits),
        BigUint: (bits: number): DictionaryValue<bigint> => createBigUintValue(bits),
        Uint: (bits: number): DictionaryValue<number> => createUintValue(bits),
        Bool: (): DictionaryValue<boolean> => createBooleanValue(),
        Address: (): DictionaryValue<Address> => createAddressValue(),
        Cell: (): DictionaryValue<Cell> => createCellValue(),
        Buffer: (bytes: number): DictionaryValue<Uint8Array> => createBufferValue(bytes),
        BitString: (bits: number): DictionaryValue<BitString> => createBitStringValue(bits),
        Dictionary: <K2 extends DictionaryKeyTypes, V2>(
            key: DictionaryKey<K2>,
            value: DictionaryValue<V2>,
        ): DictionaryValue<Dictionary<K2, V2>> => createDictionaryValue(key, value),
    };

    // ---- Static constructors ----

    /**
     * Create an empty dictionary, optionally with key/value serializers.
     *
     * @param key - Optional key serializer
     * @param value - Optional value serializer
     * @returns An empty Dictionary
     *
     * @example
     * ```typescript
     * const dict = Dictionary.empty(
     *   Dictionary.Keys.Uint(32),
     *   Dictionary.Values.BigInt(64),
     * );
     * ```
     */
    static empty<K extends DictionaryKeyTypes, V>(
        key?: Maybe<DictionaryKey<K>>,
        value?: Maybe<DictionaryValue<V>>,
    ): Dictionary<K, V> {
        if (key && value) {
            return new Dictionary<K, V>(new Map(), key, value);
        }
        return new Dictionary<K, V>(new Map(), null, null);
    }

    /**
     * Load a dictionary from a Slice or Cell (reads a maybe-ref).
     *
     * @param key - Key serializer
     * @param value - Value serializer
     * @param sc - Source Slice or Cell to read from
     * @returns The loaded Dictionary
     *
     * @example
     * ```typescript
     * const dict = Dictionary.load(
     *   Dictionary.Keys.Uint(32),
     *   Dictionary.Values.BigInt(64),
     *   cell.beginParse(),
     * );
     * ```
     */
    static load<K extends DictionaryKeyTypes, V>(
        key: DictionaryKey<K>,
        value: DictionaryValue<V>,
        sc: Slice | Cell,
    ): Dictionary<K, V> {
        let slice: Slice;
        if (sc instanceof Cell) {
            if (sc.isExotic) {
                return Dictionary.empty<K, V>(key, value);
            }
            slice = sc.beginParse();
        } else {
            slice = sc;
        }
        const cell = slice.loadMaybeRef();
        if (cell && !cell.isExotic) {
            return Dictionary.loadDirect<K, V>(key, value, cell.beginParse());
        }
        return Dictionary.empty<K, V>(key, value);
    }

    /**
     * Load a dictionary directly from a Slice or Cell (without the maybe-ref prefix bit).
     *
     * @param key - Key serializer
     * @param value - Value serializer
     * @param sc - Source Slice, Cell, or null (returns empty dict)
     * @returns The loaded Dictionary
     */
    static loadDirect<K extends DictionaryKeyTypes, V>(
        key: DictionaryKey<K>,
        value: DictionaryValue<V>,
        sc: Slice | Cell | null,
    ): Dictionary<K, V> {
        if (!sc) {
            return Dictionary.empty<K, V>(key, value);
        }
        let slice: Slice;
        if (sc instanceof Cell) {
            slice = sc.beginParse();
        } else {
            slice = sc;
        }
        const values = parseDict(slice, key.bits, value.parse);
        const prepare = new Map<string, V>();
        for (const [k, v] of values) {
            prepare.set(serializeInternalKey(key.parse(k)), v);
        }
        return new Dictionary(prepare, key, value);
    }

    // ---- Instance ----

    private readonly _key: DictionaryKey<K> | null;
    private readonly _value: DictionaryValue<V> | null;
    private readonly _map: Map<string, V>;

    private constructor(
        values: Map<string, V>,
        key: DictionaryKey<K> | null,
        value: DictionaryValue<V> | null,
    ) {
        this._key = key;
        this._value = value;
        this._map = values;
    }

    get size(): number {
        return this._map.size;
    }

    /**
     * Get a value by key.
     *
     * @param key - The key to look up
     * @returns The value, or undefined if the key is not in the dictionary
     */
    get(key: K): V | undefined {
        return this._map.get(serializeInternalKey(key));
    }

    has(key: K): boolean {
        return this._map.has(serializeInternalKey(key));
    }

    /**
     * Set a key-value pair in the dictionary.
     *
     * @param key - The key
     * @param value - The value to store
     * @returns this Dictionary for chaining
     */
    set(key: K, value: V): this {
        this._map.set(serializeInternalKey(key), value);
        return this;
    }

    delete(key: K): boolean {
        return this._map.delete(serializeInternalKey(key));
    }

    clear(): void {
        this._map.clear();
    }

    *[Symbol.iterator](): IterableIterator<[K, V]> {
        for (const [k, v] of this._map) {
            yield [deserializeInternalKey(k) as K, v];
        }
    }

    keys(): K[] {
        return Array.from(this._map.keys()).map(
            (v) => deserializeInternalKey(v) as K,
        );
    }

    values(): V[] {
        return Array.from(this._map.values());
    }

    store(
        builder: Builder,
        key?: Maybe<DictionaryKey<K>>,
        value?: Maybe<DictionaryValue<V>>,
    ): void {
        if (this._map.size === 0) {
            builder.storeBit(0);
        } else {
            const resolvedKey = (key ?? this._key)!;
            const resolvedValue = (value ?? this._value)!;
            if (!resolvedKey) throw new Error('Key serializer is not defined');
            if (!resolvedValue) throw new Error('Value serializer is not defined');

            const prepared = new Map<bigint, V>();
            for (const [k, v] of this._map) {
                prepared.set(
                    resolvedKey.serialize(deserializeInternalKey(k) as K),
                    v,
                );
            }

            builder.storeBit(1);
            const dd = beginCell();
            serializeDict(prepared, resolvedKey.bits, resolvedValue.serialize, dd);
            builder.storeRef(dd.endCell());
        }
    }

    storeDirect(
        builder: Builder,
        key?: Maybe<DictionaryKey<K>>,
        value?: Maybe<DictionaryValue<V>>,
    ): void {
        if (this._map.size === 0) {
            throw new Error('Cannot store empty dictionary directly');
        }
        const resolvedKey = (key ?? this._key)!;
        const resolvedValue = (value ?? this._value)!;
        if (!resolvedKey) throw new Error('Key serializer is not defined');
        if (!resolvedValue) throw new Error('Value serializer is not defined');

        const prepared = new Map<bigint, V>();
        for (const [k, v] of this._map) {
            prepared.set(
                resolvedKey.serialize(deserializeInternalKey(k) as K),
                v,
            );
        }
        serializeDict(prepared, resolvedKey.bits, resolvedValue.serialize, builder);
    }
}

// ===========================================================================
// Key factories
// ===========================================================================

function createAddressKey(): DictionaryKey<Address> {
    return {
        bits: 267,
        serialize: (src) => {
            if (!Address.isAddress(src)) throw new Error('Key is not an address');
            return beginCell()
                .storeAddress(src)
                .endCell()
                .beginParse()
                .preloadUintBig(267);
        },
        parse: (src) => {
            return beginCell()
                .storeUint(src, 267)
                .endCell()
                .beginParse()
                .loadAddress();
        },
    };
}

function createBigIntKey(bits: number): DictionaryKey<bigint> {
    return {
        bits,
        serialize: (src) => {
            if (typeof src !== 'bigint') throw new Error('Key is not a bigint');
            return beginCell()
                .storeInt(src, bits)
                .endCell()
                .beginParse()
                .loadUintBig(bits);
        },
        parse: (src) => {
            return beginCell()
                .storeUint(src, bits)
                .endCell()
                .beginParse()
                .loadIntBig(bits);
        },
    };
}

function createIntKey(bits: number): DictionaryKey<number> {
    return {
        bits,
        serialize: (src) => {
            if (typeof src !== 'number') throw new Error('Key is not a number');
            if (!Number.isSafeInteger(src)) throw new Error('Key is not a safe integer: ' + src);
            return beginCell()
                .storeInt(src, bits)
                .endCell()
                .beginParse()
                .loadUintBig(bits);
        },
        parse: (src) => {
            return beginCell()
                .storeUint(src, bits)
                .endCell()
                .beginParse()
                .loadInt(bits);
        },
    };
}

function createBigUintKey(bits: number): DictionaryKey<bigint> {
    return {
        bits,
        serialize: (src) => {
            if (typeof src !== 'bigint') throw new Error('Key is not a bigint');
            if (src < 0) throw new Error('Key is negative: ' + src);
            return beginCell()
                .storeUint(src, bits)
                .endCell()
                .beginParse()
                .loadUintBig(bits);
        },
        parse: (src) => {
            return beginCell()
                .storeUint(src, bits)
                .endCell()
                .beginParse()
                .loadUintBig(bits);
        },
    };
}

function createUintKey(bits: number): DictionaryKey<number> {
    return {
        bits,
        serialize: (src) => {
            if (typeof src !== 'number') throw new Error('Key is not a number');
            if (!Number.isSafeInteger(src)) throw new Error('Key is not a safe integer: ' + src);
            if (src < 0) throw new Error('Key is negative: ' + src);
            return beginCell()
                .storeUint(src, bits)
                .endCell()
                .beginParse()
                .loadUintBig(bits);
        },
        parse: (src) => {
            return Number(
                beginCell()
                    .storeUint(src, bits)
                    .endCell()
                    .beginParse()
                    .loadUint(bits),
            );
        },
    };
}

function createBufferKey(bytes: number): DictionaryKey<Uint8Array> {
    return {
        bits: bytes * 8,
        serialize: (src) => {
            if (!(src instanceof Uint8Array)) throw new Error('Key is not a Uint8Array');
            return beginCell()
                .storeBuffer(src)
                .endCell()
                .beginParse()
                .loadUintBig(bytes * 8);
        },
        parse: (src) => {
            return beginCell()
                .storeUint(src, bytes * 8)
                .endCell()
                .beginParse()
                .loadBuffer(bytes);
        },
    };
}

function createBitStringKey(bits: number): DictionaryKey<BitString> {
    return {
        bits,
        serialize: (src) => {
            if (!BitString.isBitString(src)) throw new Error('Key is not a BitString');
            return beginCell()
                .storeBits(src)
                .endCell()
                .beginParse()
                .loadUintBig(bits);
        },
        parse: (src) => {
            return beginCell()
                .storeUint(src, bits)
                .endCell()
                .beginParse()
                .loadBits(bits);
        },
    };
}

// ===========================================================================
// Value factories
// ===========================================================================

function createIntValue(bits: number): DictionaryValue<number> {
    return {
        serialize: (src, builder) => { builder.storeInt(src, bits); },
        parse: (src) => {
            const value = src.loadInt(bits);
            src.endParse();
            return value;
        },
    };
}

function createBigIntValue(bits: number): DictionaryValue<bigint> {
    return {
        serialize: (src, builder) => { builder.storeInt(src, bits); },
        parse: (src) => {
            const value = src.loadIntBig(bits);
            src.endParse();
            return value;
        },
    };
}

function createUintValue(bits: number): DictionaryValue<number> {
    return {
        serialize: (src, builder) => { builder.storeUint(src, bits); },
        parse: (src) => {
            const value = src.loadUint(bits);
            src.endParse();
            return value;
        },
    };
}

function createBigUintValue(bits: number): DictionaryValue<bigint> {
    return {
        serialize: (src, builder) => { builder.storeUint(src, bits); },
        parse: (src) => {
            const value = src.loadUintBig(bits);
            src.endParse();
            return value;
        },
    };
}

function createBooleanValue(): DictionaryValue<boolean> {
    return {
        serialize: (src, builder) => { builder.storeBit(src); },
        parse: (src) => {
            const value = src.loadBit();
            src.endParse();
            return value;
        },
    };
}

function createAddressValue(): DictionaryValue<Address> {
    return {
        serialize: (src, builder) => { builder.storeAddress(src); },
        parse: (src) => {
            const addr = src.loadAddress();
            src.endParse();
            return addr;
        },
    };
}

function createCellValue(): DictionaryValue<Cell> {
    return {
        serialize: (src, builder) => { builder.storeRef(src); },
        parse: (src) => {
            const value = src.loadRef();
            src.endParse();
            return value;
        },
    };
}

function createBufferValue(size: number): DictionaryValue<Uint8Array> {
    return {
        serialize: (src, builder) => {
            if (src.length !== size) throw new Error('Invalid buffer size');
            builder.storeBuffer(src);
        },
        parse: (src) => {
            const value = src.loadBuffer(size);
            src.endParse();
            return value;
        },
    };
}

function createBitStringValue(bits: number): DictionaryValue<BitString> {
    return {
        serialize: (src, builder) => {
            if (src.length !== bits) throw new Error('Invalid BitString size');
            builder.storeBits(src);
        },
        parse: (src) => {
            const value = src.loadBits(bits);
            src.endParse();
            return value;
        },
    };
}

function createDictionaryValue<K extends DictionaryKeyTypes, V>(
    key: DictionaryKey<K>,
    value: DictionaryValue<V>,
): DictionaryValue<Dictionary<K, V>> {
    return {
        serialize: (src, builder) => { src.store(builder); },
        parse: (src) => {
            const dict = Dictionary.load(key, value, src);
            src.endParse();
            return dict as Dictionary<K, V>;
        },
    };
}
