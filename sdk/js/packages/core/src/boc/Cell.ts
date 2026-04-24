/**
 * Cell as described in TVM spec.
 * Max 1023 bits, 4 refs.
 */

import { BitString } from './BitString';
import { BitReader } from './BitReader';
import { CellType } from './cell/CellType';
import { LevelMask } from './cell/LevelMask';
import { resolveExotic } from './cell/resolveExotic';
import { wonderCalculator } from './cell/wonderCalculator';
import { deserializeBoc, serializeBoc } from './cell/serialization';
import { Slice } from './Slice';
import { beginCell } from './Builder';
import { bytesToBase64, bytesToHex, base64ToBytes, hexToBytes } from '../utils/encoding';

export { CellType } from './cell/CellType';

/**
 * Immutable TVM Cell: the fundamental data unit in the TOS blockchain.
 *
 * A Cell holds up to 1023 bits and up to 4 references to other Cells.
 * Cells are content-addressed by their SHA-256 hash. Use {@link beginCell}
 * to construct Cells via the fluent Builder API.
 *
 * @example
 * ```typescript
 * // Deserialize from base64 BOC
 * const cell = Cell.fromBase64("te6cck...");
 *
 * // Parse cell contents
 * const slice = cell.beginParse();
 * const value = slice.loadUint(32);
 *
 * // Serialize back to base64
 * const boc = cell.toBase64();
 * ```
 */
export class Cell {
    /** The empty cell singleton (0 bits, 0 refs). */
    static readonly EMPTY = new Cell();

    /**
     * Deserialize cells from a BOC (Bag of Cells) binary.
     *
     * @param src - BOC binary data as Uint8Array
     * @returns Array of root cells contained in the BOC
     *
     * @example
     * ```typescript
     * const cells = Cell.fromBoc(bocBytes);
     * const rootCell = cells[0];
     * ```
     */
    static fromBoc(src: Uint8Array): Cell[] {
        return deserializeBoc(src);
    }

    /**
     * Deserialize a single cell from a base64-encoded BOC string.
     *
     * @param src - Base64-encoded BOC string
     * @returns The single root cell
     * @throws Error if the BOC contains more than one root cell
     *
     * @example
     * ```typescript
     * const cell = Cell.fromBase64("te6cckEBAQEA...");
     * ```
     */
    static fromBase64(src: string): Cell {
        const parsed = Cell.fromBoc(base64ToBytes(src));
        if (parsed.length !== 1) {
            throw new Error('Deserialized more than one cell');
        }
        return parsed[0]!;
    }

    /**
     * Deserialize a single cell from a hex-encoded BOC string.
     *
     * @param src - Hex-encoded BOC string
     * @returns The single root cell
     * @throws Error if the BOC contains more than one root cell
     *
     * @example
     * ```typescript
     * const cell = Cell.fromHex("b5ee9c72...");
     * ```
     */
    static fromHex(src: string): Cell {
        const parsed = Cell.fromBoc(hexToBytes(src));
        if (parsed.length !== 1) {
            throw new Error('Deserialized more than one cell');
        }
        return parsed[0]!;
    }

    readonly type: CellType;
    readonly bits: BitString;
    readonly refs: Cell[];
    readonly mask: LevelMask;

    private _hashes: Uint8Array[] = [];
    private _depths: number[] = [];

    constructor(opts?: {
        exotic?: boolean;
        bits?: BitString;
        refs?: Cell[];
    }) {
        let bits = BitString.EMPTY;
        if (opts?.bits) {
            bits = opts.bits;
        }

        let refs: Cell[] = [];
        if (opts?.refs) {
            refs = [...opts.refs];
        }

        let hashes: Uint8Array[];
        let depths: number[];
        let mask: LevelMask;
        let type = CellType.Ordinary;

        if (opts?.exotic) {
            const resolved = resolveExotic(bits, refs);
            const wonders = wonderCalculator(resolved.type, bits, refs);
            mask = wonders.mask;
            depths = wonders.depths;
            hashes = wonders.hashes;
            type = resolved.type;
        } else {
            if (refs.length > 4) {
                throw new Error('Invalid number of references');
            }
            if (bits.length > 1023) {
                throw new Error(`Bits overflow: ${bits.length} > 1023`);
            }
            const wonders = wonderCalculator(CellType.Ordinary, bits, refs);
            mask = wonders.mask;
            depths = wonders.depths;
            hashes = wonders.hashes;
            type = CellType.Ordinary;
        }

        this.type = type;
        this.bits = bits;
        this.refs = refs;
        this.mask = mask;
        this._depths = depths;
        this._hashes = hashes;

        Object.freeze(this.refs);
        Object.freeze(this.bits);
        Object.freeze(this.mask);
        Object.freeze(this._depths);
        Object.freeze(this._hashes);
    }

    /** Whether this cell is exotic (MerkleProof, MerkleUpdate, or PrunedBranch). */
    get isExotic(): boolean {
        return this.type !== CellType.Ordinary;
    }

    /**
     * Begin parsing this cell's contents as a Slice.
     *
     * @param allowExotic - If true, allows parsing exotic cells (default false)
     * @returns A new Slice positioned at the start of this cell's data
     * @throws Error if the cell is exotic and allowExotic is false
     *
     * @example
     * ```typescript
     * const slice = cell.beginParse();
     * const opCode = slice.loadUint(32);
     * const addr = slice.loadAddress();
     * ```
     */
    beginParse(allowExotic: boolean = false): Slice {
        if (this.isExotic && !allowExotic) {
            throw new Error('Exotic cells cannot be parsed');
        }
        return new Slice(new BitReader(this.bits), this.refs);
    }

    /**
     * Get the SHA-256 hash of this cell at a given level.
     *
     * @param level - Hash level (default 3, the highest standard level)
     * @returns 32-byte hash as Uint8Array
     *
     * @example
     * ```typescript
     * const hash = cell.hash();
     * console.log(bytesToHex(hash));
     * ```
     */
    hash(level: number = 3): Uint8Array {
        return this._hashes[Math.min(this._hashes.length - 1, level)]!;
    }

    /**
     * Get the depth of this cell's tree at a given level.
     *
     * @param level - Depth level (default 3)
     * @returns The tree depth
     */
    depth(level: number = 3): number {
        return this._depths[Math.min(this._depths.length - 1, level)]!;
    }

    level(): number {
        return this.mask.level;
    }

    /**
     * Check if this cell equals another cell by comparing their hashes.
     *
     * @param other - The cell to compare with
     * @returns true if both cells have the same hash
     */
    equals(other: Cell): boolean {
        const a = this.hash();
        const b = other.hash();
        if (a.length !== b.length) return false;
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) return false;
        }
        return true;
    }

    /**
     * Serialize this cell to a BOC (Bag of Cells) binary.
     *
     * @param opts - Serialization options (idx for cell index, crc32 for checksum)
     * @returns BOC binary as Uint8Array
     *
     * @example
     * ```typescript
     * const boc = cell.toBoc();
     * const bocNoCrc = cell.toBoc({ crc32: false });
     * ```
     */
    toBoc(opts?: {
        idx?: boolean | null | undefined;
        crc32?: boolean | null | undefined;
    }): Uint8Array {
        const idx = opts?.idx ?? false;
        const crc32 = opts?.crc32 ?? true;
        return serializeBoc(this, { idx, crc32 });
    }

    /**
     * Serialize this cell to a base64-encoded BOC string.
     *
     * @param opts - Serialization options
     * @returns Base64-encoded BOC string
     *
     * @example
     * ```typescript
     * const b64 = cell.toBase64();
     * ```
     */
    toBase64(opts?: {
        idx?: boolean | null | undefined;
        crc32?: boolean | null | undefined;
    }): string {
        return bytesToBase64(this.toBoc(opts));
    }

    /**
     * Serialize this cell to a hex-encoded BOC string.
     *
     * @param opts - Serialization options
     * @returns Hex-encoded BOC string
     */
    toHex(opts?: {
        idx?: boolean | null | undefined;
        crc32?: boolean | null | undefined;
    }): string {
        return bytesToHex(this.toBoc(opts));
    }

    toString(indent?: string): string {
        const id = indent || '';
        let t = 'x';
        if (this.isExotic) {
            if (this.type === CellType.MerkleProof) {
                t = 'p';
            } else if (this.type === CellType.MerkleUpdate) {
                t = 'u';
            } else if (this.type === CellType.PrunedBranch) {
                t = 'p';
            }
        }
        let s =
            id + (this.isExotic ? t : 'x') + '{' + this.bits.toString() + '}';
        for (const ref of this.refs) {
            s += '\n' + ref.toString(id + ' ');
        }
        return s;
    }

    /** Alias for `beginParse()`. */
    asSlice(): Slice {
        return this.beginParse();
    }

    /** Convert this cell to a Builder containing the same data. */
    asBuilder() {
        return beginCell().storeSlice(this.asSlice());
    }
}
