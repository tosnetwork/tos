/**
 * BOC (Bag of Cells) serialization and deserialization.
 * Compatible with TON binary format.
 */

import { BitReader } from '../BitReader';
import { BitString } from '../BitString';
import { BitBuilder } from '../BitBuilder';
import { Cell } from '../Cell';
import { topologicalSort } from './topologicalSort';
import { getBitsDescriptor, getRefsDescriptor } from './descriptor';
import { bitsToPaddedBuffer } from '../BitString';
import { crc32c } from '../../utils/crc';

function bitsForNumber(src: bigint | number, mode: 'int' | 'uint'): number {
    const v = BigInt(src);
    if (mode === 'uint') {
        if (v < 0) throw new Error(`value is negative. Got ${src}`);
        if (v === 0n) return 0;
        return v.toString(2).length;
    }
    if (v === 0n || v === -1n) return 1;
    const v2 = v > 0 ? v : -v;
    return v2.toString(2).length + 1;
}

function getHashesCount(levelMask: number): number {
    let mask = levelMask & 7;
    let n = 0;
    for (let i = 0; i < 3; i++) {
        n += mask & 1;
        mask = mask >> 1;
    }
    return n + 1;
}

function readCell(
    reader: BitReader,
    sizeBytes: number,
): { bits: BitString; refs: number[]; exotic: boolean } {
    // D1
    const d1 = reader.loadUint(8);
    const refsCount = d1 % 8;
    const exotic = !!(d1 & 8);

    // D2
    const d2 = reader.loadUint(8);
    const dataBytesize = Math.ceil(d2 / 2);
    const paddingAdded = !!(d2 % 2);

    const levelMask = d1 >> 5;
    const hasHashes = (d1 & 16) !== 0;

    const hashesSize = hasHashes ? getHashesCount(levelMask) * 32 : 0;
    const depthSize = hasHashes ? getHashesCount(levelMask) * 2 : 0;

    reader.skip(hashesSize * 8);
    reader.skip(depthSize * 8);

    // Bits
    let bits = BitString.EMPTY;
    if (dataBytesize > 0) {
        if (paddingAdded) {
            bits = reader.loadPaddedBits(dataBytesize * 8);
        } else {
            bits = reader.loadBits(dataBytesize * 8);
        }
    }

    // Refs
    const refs: number[] = [];
    for (let i = 0; i < refsCount; i++) {
        refs.push(reader.loadUint(sizeBytes * 8));
    }

    return { bits, refs, exotic };
}

function calcCellSize(cell: Cell, sizeBytes: number): number {
    return (
        2 /* D1+D2 */ +
        Math.ceil(cell.bits.length / 8) +
        cell.refs.length * sizeBytes
    );
}

export function parseBoc(src: Uint8Array): {
    size: number;
    offBytes: number;
    cells: number;
    roots: number;
    absent: number;
    totalCellSize: number;
    index: Uint8Array | null;
    cellData: Uint8Array;
    root: number[];
} {
    const reader = new BitReader(
        new BitString(src, 0, src.length * 8),
    );
    const magic = reader.loadUint(32);

    if (magic === 0x68ff65f3) {
        const size = reader.loadUint(8);
        const offBytes = reader.loadUint(8);
        const cells = reader.loadUint(size * 8);
        const roots = reader.loadUint(size * 8);
        const absent = reader.loadUint(size * 8);
        const totalCellSize = reader.loadUint(offBytes * 8);
        const index = reader.loadBuffer(cells * offBytes);
        const cellData = reader.loadBuffer(totalCellSize);
        return {
            size, offBytes, cells, roots, absent, totalCellSize,
            index, cellData, root: [0],
        };
    } else if (magic === 0xacc3a728) {
        const size = reader.loadUint(8);
        const offBytes = reader.loadUint(8);
        const cells = reader.loadUint(size * 8);
        const roots = reader.loadUint(size * 8);
        const absent = reader.loadUint(size * 8);
        const totalCellSize = reader.loadUint(offBytes * 8);
        const index = reader.loadBuffer(cells * offBytes);
        const cellData = reader.loadBuffer(totalCellSize);
        const crc = reader.loadBuffer(4);
        const computed = crc32c(src.subarray(0, src.length - 4));
        if (!uint8ArraysEqual(computed, crc)) {
            throw new Error('Invalid CRC32C');
        }
        return {
            size, offBytes, cells, roots, absent, totalCellSize,
            index, cellData, root: [0],
        };
    } else if (magic === 0xb5ee9c72) {
        const hasIdx = reader.loadUint(1);
        const hasCrc32c = reader.loadUint(1);
        reader.loadUint(1); // hasCacheBits
        reader.loadUint(2); // flags
        const size = reader.loadUint(3);
        const offBytes = reader.loadUint(8);
        const cells = reader.loadUint(size * 8);
        const roots = reader.loadUint(size * 8);
        const absent = reader.loadUint(size * 8);
        const totalCellSize = reader.loadUint(offBytes * 8);
        const root: number[] = [];
        for (let i = 0; i < roots; i++) {
            root.push(reader.loadUint(size * 8));
        }
        let index: Uint8Array | null = null;
        if (hasIdx) {
            index = reader.loadBuffer(cells * offBytes);
        }
        const cellData = reader.loadBuffer(totalCellSize);
        if (hasCrc32c) {
            const crc = reader.loadBuffer(4);
            const computed = crc32c(src.subarray(0, src.length - 4));
            if (!uint8ArraysEqual(computed, crc)) {
                throw new Error('Invalid CRC32C');
            }
        }
        return {
            size, offBytes, cells, roots, absent, totalCellSize,
            index, cellData, root,
        };
    }
    throw new Error('Invalid magic');
}

export function deserializeBoc(src: Uint8Array): Cell[] {
    const boc = parseBoc(src);
    const reader = new BitReader(
        new BitString(boc.cellData, 0, boc.cellData.length * 8),
    );

    const cells: {
        bits: BitString;
        refs: number[];
        exotic: boolean;
        result: Cell | null;
    }[] = [];
    for (let i = 0; i < boc.cells; i++) {
        const cll = readCell(reader, boc.size);
        cells.push({ ...cll, result: null });
    }

    // Build cells in reverse order
    for (let i = cells.length - 1; i >= 0; i--) {
        const cellEntry = cells[i]!;
        const refs: Cell[] = [];
        for (const r of cellEntry.refs) {
            const refEntry = cells[r]!;
            if (!refEntry.result) {
                throw new Error('Invalid BOC file');
            }
            refs.push(refEntry.result);
        }
        cellEntry.result = new Cell({
            bits: cellEntry.bits,
            refs,
            exotic: cellEntry.exotic,
        });
    }

    const roots: Cell[] = [];
    for (let i = 0; i < boc.root.length; i++) {
        const rootIdx = boc.root[i]!;
        roots.push(cells[rootIdx]!.result!);
    }

    return roots;
}

function writeCellToBuilder(
    cell: Cell,
    refs: number[],
    sizeBytes: number,
    to: BitBuilder,
): void {
    const d1 = getRefsDescriptor(cell.refs, cell.mask.value, cell.type);
    const d2 = getBitsDescriptor(cell.bits);
    to.writeUint(d1, 8);
    to.writeUint(d2, 8);
    to.writeBytes(bitsToPaddedBuffer(cell.bits));
    for (const r of refs) {
        to.writeUint(r, sizeBytes * 8);
    }
}

export function serializeBoc(
    root: Cell,
    opts: { idx: boolean; crc32: boolean },
): Uint8Array {
    const allCells = topologicalSort(root);

    const cellsNum = allCells.length;
    const has_idx = opts.idx;
    const has_crc32c = opts.crc32;
    const has_cache_bits = false;
    const flags = 0;
    const sizeBytes = Math.max(
        Math.ceil(bitsForNumber(cellsNum, 'uint') / 8),
        1,
    );

    let totalCellSize = 0;
    const index: number[] = [];
    for (const c of allCells) {
        const sz = calcCellSize(c.cell, sizeBytes);
        totalCellSize += sz;
        index.push(totalCellSize);
    }

    const offsetBytes = Math.max(
        Math.ceil(bitsForNumber(totalCellSize, 'uint') / 8),
        1,
    );

    const totalSize =
        (4 + // magic
            1 + // flags and s_bytes
            1 + // offset_bytes
            3 * sizeBytes + // cells_num, roots, complete
            offsetBytes + // full_size
            1 * sizeBytes + // root_idx
            (has_idx ? cellsNum * offsetBytes : 0) +
            totalCellSize +
            (has_crc32c ? 4 : 0)) *
        8;

    const builder = new BitBuilder(totalSize);
    builder.writeUint(0xb5ee9c72, 32);
    builder.writeBit(has_idx);
    builder.writeBit(has_crc32c);
    builder.writeBit(has_cache_bits);
    builder.writeUint(flags, 2);
    builder.writeUint(sizeBytes, 3);
    builder.writeUint(offsetBytes, 8);
    builder.writeUint(cellsNum, sizeBytes * 8);
    builder.writeUint(1, sizeBytes * 8); // roots
    builder.writeUint(0, sizeBytes * 8); // absent
    builder.writeUint(totalCellSize, offsetBytes * 8);
    builder.writeUint(0, sizeBytes * 8); // root id

    if (has_idx) {
        for (let i = 0; i < cellsNum; i++) {
            builder.writeUint(index[i]!, offsetBytes * 8);
        }
    }

    for (let i = 0; i < cellsNum; i++) {
        const entry = allCells[i]!;
        writeCellToBuilder(entry.cell, entry.refs, sizeBytes, builder);
    }

    if (has_crc32c) {
        const crc = crc32c(builder.buffer());
        builder.writeBytes(crc);
    }

    const res = builder.buffer();
    if (res.length !== totalSize / 8) {
        throw new Error('Internal error');
    }
    return res;
}

function uint8ArraysEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}
