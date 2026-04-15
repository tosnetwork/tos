/**
 * TupleReader: reads TupleItems sequentially (like a stack).
 */

import type { TupleItem } from './TupleItem';
import type { Cell } from '../boc/Cell';
import { Address } from '../address/Address';

/**
 * Sequential reader for TVM tuple/stack items.
 *
 * Reads items one at a time with typed accessors. Each `read*` call
 * pops the next item from the front of the list.
 *
 * @example
 * ```typescript
 * const reader = new TupleReader(items);
 * const balance = reader.readBigNumber();
 * const owner = reader.readAddress();
 * const content = reader.readCell();
 * ```
 */
export class TupleReader {
    private readonly items: TupleItem[];

    constructor(items: TupleItem[]) {
        this.items = [...items];
    }

    get remaining(): number {
        return this.items.length;
    }

    peek(): TupleItem {
        if (this.items.length === 0) {
            throw new Error('EOF');
        }
        return this.items[0]!;
    }

    pop(): TupleItem {
        if (this.items.length === 0) {
            throw new Error('EOF');
        }
        return this.items.splice(0, 1)[0]!;
    }

    skip(num: number = 1): this {
        for (let i = 0; i < num; i++) {
            this.pop();
        }
        return this;
    }

    /**
     * Read the next item as a bigint.
     *
     * @returns The integer value as a bigint
     * @throws Error if the next item is not an integer
     */
    readBigNumber(): bigint {
        const popped = this.pop();
        if (popped.type !== 'int') {
            throw new Error('Not a number');
        }
        return popped.value;
    }

    readBigNumberOpt(): bigint | null {
        const popped = this.pop();
        if (popped.type === 'null') return null;
        if (popped.type !== 'int') throw new Error('Not a number');
        return popped.value;
    }

    /**
     * Read the next item as a safe JavaScript number.
     *
     * @returns The integer value as a number
     * @throws Error if the next item is not an integer
     */
    readNumber(): number {
        return Number(this.readBigNumber());
    }

    readNumberOpt(): number | null {
        const r = this.readBigNumberOpt();
        return r !== null ? Number(r) : null;
    }

    readBoolean(): boolean {
        const res = this.readNumber();
        return res !== 0;
    }

    readBooleanOpt(): boolean | null {
        const res = this.readNumberOpt();
        if (res !== null) {
            return res !== 0;
        }
        return null;
    }

    /**
     * Read the next item as an Address (expects a cell containing an address).
     *
     * @returns The parsed Address
     * @throws Error if the next item cannot be parsed as an address
     */
    readAddress(): Address {
        const r = this.readCell().beginParse().loadAddress();
        if (r !== null) {
            return r;
        }
        throw new Error('Not an address');
    }

    readAddressOpt(): Address | null {
        const r = this.readCellOpt();
        if (r !== null) {
            return r.beginParse().loadMaybeAddress();
        }
        return null;
    }

    /**
     * Read the next item as a Cell.
     *
     * @returns The Cell value
     * @throws Error if the next item is not a cell, slice, or builder
     */
    readCell(): Cell {
        const popped = this.pop();
        if (
            popped.type !== 'cell' &&
            popped.type !== 'slice' &&
            popped.type !== 'builder'
        ) {
            throw new Error('Not a cell: ' + popped.type);
        }
        return popped.cell;
    }

    readCellOpt(): Cell | null {
        const popped = this.pop();
        if (popped.type === 'null') return null;
        if (
            popped.type !== 'cell' &&
            popped.type !== 'slice' &&
            popped.type !== 'builder'
        ) {
            throw new Error('Not a cell');
        }
        return popped.cell;
    }

    readTuple(): TupleReader {
        const popped = this.pop();
        if (popped.type !== 'tuple') {
            throw new Error('Not a tuple');
        }
        return new TupleReader(popped.items);
    }

    readTupleOpt(): TupleReader | null {
        const popped = this.pop();
        if (popped.type === 'null') return null;
        if (popped.type !== 'tuple') throw new Error('Not a tuple');
        return new TupleReader(popped.items);
    }

    readBuffer(): Uint8Array {
        const s = this.readCell().beginParse();
        if (s.remainingRefs !== 0) throw new Error('Not a buffer');
        if (s.remainingBits % 8 !== 0) throw new Error('Not a buffer');
        return s.loadBuffer(s.remainingBits / 8);
    }

    readBufferOpt(): Uint8Array | null {
        const r = this.readCellOpt();
        if (r !== null) {
            const s = r.beginParse();
            if (s.remainingRefs !== 0 || s.remainingBits % 8 !== 0) {
                throw new Error('Not a buffer');
            }
            return s.loadBuffer(s.remainingBits / 8);
        }
        return null;
    }

    readString(): string {
        const s = this.readCell().beginParse();
        return s.loadStringTail();
    }

    readStringOpt(): string | null {
        const r = this.readCellOpt();
        if (r !== null) {
            return r.beginParse().loadStringTail();
        }
        return null;
    }
}
