/**
 * Topological sort of cells for BOC serialization.
 */

import type { Cell } from '../Cell';
import { bytesToHex } from '../../utils/encoding';

export function topologicalSort(
    src: Cell,
): { cell: Cell; refs: number[] }[] {
    const pending: Cell[] = [src];
    const allCells = new Map<string, { cell: Cell; refs: string[] }>();
    const notPermCells = new Set<string>();
    const sorted: string[] = [];

    // Collect all cells
    while (pending.length > 0) {
        const cells = [...pending];
        pending.length = 0;
        for (const cell of cells) {
            const hash = bytesToHex(cell.hash());
            if (allCells.has(hash)) {
                continue;
            }
            notPermCells.add(hash);
            allCells.set(hash, {
                cell: cell,
                refs: cell.refs.map((v) => bytesToHex(v.hash())),
            });
            for (const r of cell.refs) {
                pending.push(r);
            }
        }
    }

    // DFS topological sort
    const tempMark = new Set<string>();

    function visit(hash: string): void {
        if (!notPermCells.has(hash)) {
            return;
        }
        if (tempMark.has(hash)) {
            throw new Error('Not a DAG');
        }
        tempMark.add(hash);
        const refs = allCells.get(hash)!.refs;
        for (let ci = refs.length - 1; ci >= 0; ci--) {
            visit(refs[ci]!);
        }
        sorted.push(hash);
        tempMark.delete(hash);
        notPermCells.delete(hash);
    }

    while (notPermCells.size > 0) {
        const id = Array.from(notPermCells)[0]!;
        visit(id);
    }

    const indexes = new Map<string, number>();
    for (let i = 0; i < sorted.length; i++) {
        indexes.set(sorted[sorted.length - i - 1]!, i);
    }

    const result: { cell: Cell; refs: number[] }[] = [];
    for (let i = sorted.length - 1; i >= 0; i--) {
        const ent = sorted[i]!;
        const rrr = allCells.get(ent)!;
        result.push({
            cell: rrr.cell,
            refs: rrr.refs.map((v) => indexes.get(v)!),
        });
    }

    return result;
}
