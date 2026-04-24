/**
 * Compute cell hashes, depths, and level mask.
 * Replicates the C++ DataCell.cpp logic.
 */

import { BitString } from '../BitString';
import type { Cell } from '../Cell';
import { CellType } from './CellType';
import { LevelMask } from './LevelMask';
import { getRepr } from './descriptor';
import { sha256 } from '../../utils/sha256';
import { BitReader } from '../BitReader';

interface ExoticPrunedEntry {
    hash: Uint8Array;
    depth: number;
}

interface ExoticPruned {
    mask: number;
    pruned: ExoticPrunedEntry[];
}

function parsePruned(bits: BitString, refs: Cell[]): ExoticPruned {
    if (refs.length !== 0) {
        throw new Error('Pruned branch must have zero refs');
    }
    const reader = new BitReader(bits);
    const type = reader.loadUint(8);
    if (type !== 1) throw new Error('Not a pruned branch');

    const mask = reader.loadUint(8);
    const lm = new LevelMask(mask);

    const pruned: ExoticPrunedEntry[] = [];
    const hashCount = lm.hashCount;

    // Read hashes
    const hashes: Uint8Array[] = [];
    for (let i = 0; i < hashCount; i++) {
        hashes.push(reader.loadBuffer(32));
    }

    // Read depths
    const depths: number[] = [];
    for (let i = 0; i < hashCount; i++) {
        depths.push(reader.loadUint(16));
    }

    for (let i = 0; i < hashCount; i++) {
        pruned.push({ hash: hashes[i]!, depth: depths[i]! });
    }

    return { mask, pruned };
}

export function wonderCalculator(
    type: CellType,
    bits: BitString,
    refs: Cell[],
): { mask: LevelMask; hashes: Uint8Array[]; depths: number[] } {
    // Resolving level mask
    let levelMask: LevelMask;
    let pruned: ExoticPruned | null = null;

    if (type === CellType.Ordinary) {
        let mask = 0;
        for (const r of refs) {
            mask = mask | r.mask.value;
        }
        levelMask = new LevelMask(mask);
    } else if (type === CellType.PrunedBranch) {
        pruned = parsePruned(bits, refs);
        levelMask = new LevelMask(pruned.mask);
    } else if (type === CellType.MerkleProof) {
        levelMask = new LevelMask(refs[0]!.mask.value >> 1);
    } else if (type === CellType.MerkleUpdate) {
        levelMask = new LevelMask(
            (refs[0]!.mask.value | refs[1]!.mask.value) >> 1,
        );
    } else if (type === CellType.Library) {
        levelMask = new LevelMask();
    } else {
        throw new Error('Unsupported exotic type');
    }

    // Calculate hashes and depths
    const depths: number[] = [];
    const hashes: Uint8Array[] = [];

    const hashCount =
        type === CellType.PrunedBranch ? 1 : levelMask.hashCount;
    const totalHashCount = levelMask.hashCount;
    const hashIOffset = totalHashCount - hashCount;

    for (let levelI = 0, hashI = 0; levelI <= levelMask.level; levelI++) {
        if (!levelMask.isSignificant(levelI)) {
            continue;
        }
        if (hashI < hashIOffset) {
            hashI++;
            continue;
        }

        // Bits
        let currentBits: BitString;
        if (hashI === hashIOffset) {
            currentBits = bits;
        } else {
            currentBits = new BitString(
                hashes[hashI - hashIOffset - 1]!,
                0,
                256,
            );
        }

        // Depth
        let currentDepth = 0;
        for (const c of refs) {
            let childDepth: number;
            if (
                type === CellType.MerkleProof ||
                type === CellType.MerkleUpdate
            ) {
                childDepth = c.depth(levelI + 1);
            } else {
                childDepth = c.depth(levelI);
            }
            currentDepth = Math.max(currentDepth, childDepth);
        }
        if (refs.length > 0) {
            currentDepth++;
        }

        // Hash
        const repr = getRepr(
            bits,
            currentBits,
            refs,
            levelI,
            levelMask.apply(levelI).value,
            type,
        );
        const hash = sha256(repr);

        const destI = hashI - hashIOffset;
        depths[destI] = currentDepth;
        hashes[destI] = hash;

        hashI++;
    }

    // Build resolved arrays for all 4 levels
    const resolvedHashes: Uint8Array[] = [];
    const resolvedDepths: number[] = [];

    if (pruned) {
        for (let i = 0; i < 4; i++) {
            const { hashIndex } = levelMask.apply(i);
            const { hashIndex: thisHashIndex } = levelMask;
            if (hashIndex !== thisHashIndex) {
                resolvedHashes.push(pruned.pruned[hashIndex]!.hash);
                resolvedDepths.push(pruned.pruned[hashIndex]!.depth);
            } else {
                resolvedHashes.push(hashes[0]!);
                resolvedDepths.push(depths[0]!);
            }
        }
    } else {
        for (let i = 0; i < 4; i++) {
            resolvedHashes.push(hashes[levelMask.apply(i).hashIndex]!);
            resolvedDepths.push(depths[levelMask.apply(i).hashIndex]!);
        }
    }

    return {
        mask: levelMask,
        hashes: resolvedHashes,
        depths: resolvedDepths,
    };
}
