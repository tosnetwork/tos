/**
 * Resolve exotic cell type from the first byte of the cell data.
 */

import { BitString } from '../BitString';
import { BitReader } from '../BitReader';
import type { Cell } from '../Cell';
import { CellType } from './CellType';

export function resolveExotic(
    bits: BitString,
    _refs: Cell[],
): { type: CellType } {
    const reader = new BitReader(bits);
    const type = reader.preloadUint(8);

    if (type === 1) {
        return { type: CellType.PrunedBranch };
    }
    if (type === 2) {
        return { type: CellType.Library };
    }
    if (type === 3) {
        return { type: CellType.MerkleProof };
    }
    if (type === 4) {
        return { type: CellType.MerkleUpdate };
    }
    throw new Error('Invalid exotic cell type: ' + type);
}
