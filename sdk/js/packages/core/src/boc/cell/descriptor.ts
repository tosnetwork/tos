/**
 * Cell descriptor bytes and cell representation for hashing.
 */

import { BitString, bitsToPaddedBuffer } from '../BitString';
import type { Cell } from '../Cell';
import { CellType } from './CellType';

export function getRefsDescriptor(
    refs: Cell[],
    levelMask: number,
    type: CellType,
): number {
    return (
        refs.length + (type !== CellType.Ordinary ? 1 : 0) * 8 + levelMask * 32
    );
}

export function getBitsDescriptor(bits: BitString): number {
    const len = bits.length;
    return Math.ceil(len / 8) + Math.floor(len / 8);
}

export function getRepr(
    originalBits: BitString,
    bits: BitString,
    refs: Cell[],
    level: number,
    levelMask: number,
    type: CellType,
): Uint8Array {
    const bitsLen = Math.ceil(bits.length / 8);
    const repr = new Uint8Array(2 + bitsLen + (2 + 32) * refs.length);

    let cursor = 0;
    repr[cursor++] = getRefsDescriptor(refs, levelMask, type);
    repr[cursor++] = getBitsDescriptor(originalBits);

    // Write padded bits
    const padded = bitsToPaddedBuffer(bits);
    repr.set(padded.subarray(0, bitsLen), cursor);
    cursor += bitsLen;

    // Write ref depths
    for (const c of refs) {
        let childDepth: number;
        if (type === CellType.MerkleProof || type === CellType.MerkleUpdate) {
            childDepth = c.depth(level + 1);
        } else {
            childDepth = c.depth(level);
        }
        repr[cursor++] = Math.floor(childDepth / 256);
        repr[cursor++] = childDepth % 256;
    }

    // Write ref hashes
    for (const c of refs) {
        let childHash: Uint8Array;
        if (type === CellType.MerkleProof || type === CellType.MerkleUpdate) {
            childHash = c.hash(level + 1);
        } else {
            childHash = c.hash(level);
        }
        repr.set(childHash, cursor);
        cursor += 32;
    }

    return repr;
}
