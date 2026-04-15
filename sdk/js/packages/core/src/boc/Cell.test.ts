import { describe, it, expect } from 'vitest';
import { Cell } from './Cell';
import { beginCell } from './Builder';

describe('Cell', () => {
    // ---- Basic build/serialize/deserialize ----
    it('should build a cell, serialize to BOC, and deserialize back', () => {
        const cell = beginCell().storeUint(42, 32).endCell();
        const boc = cell.toBoc();
        const parsed = Cell.fromBoc(boc);
        expect(parsed.length).toBe(1);
        const slice = parsed[0]!.beginParse();
        expect(slice.loadUint(32)).toBe(42);
    });

    // ---- Nested cells ----
    it('should round-trip nested cells with child refs', () => {
        const child = beginCell().storeUint(99, 16).endCell();
        const parent = beginCell()
            .storeUint(1, 8)
            .storeRef(child)
            .endCell();

        const boc = parent.toBoc();
        const parsed = Cell.fromBoc(boc)[0]!;
        const slice = parsed.beginParse();
        expect(slice.loadUint(8)).toBe(1);
        const childSlice = slice.loadRef().beginParse();
        expect(childSlice.loadUint(16)).toBe(99);
    });

    // ---- fromBase64 / toBase64 round-trip ----
    it('should round-trip via fromBase64/toBase64', () => {
        const cell = beginCell().storeUint(12345, 32).endCell();
        const b64 = cell.toBase64();
        const restored = Cell.fromBase64(b64);
        expect(restored.equals(cell)).toBe(true);
    });

    // ---- hash() ----
    it('should return a 32-byte hash', () => {
        const cell = beginCell().storeUint(42, 32).endCell();
        const h = cell.hash();
        expect(h).toBeInstanceOf(Uint8Array);
        expect(h.length).toBe(32);
    });

    // ---- equals() ----
    it('should equal identical cells', () => {
        const a = beginCell().storeUint(7, 8).endCell();
        const b = beginCell().storeUint(7, 8).endCell();
        expect(a.equals(b)).toBe(true);
    });

    it('should not equal different cells', () => {
        const a = beginCell().storeUint(7, 8).endCell();
        const b = beginCell().storeUint(8, 8).endCell();
        expect(a.equals(b)).toBe(false);
    });

    // ---- Maximum cell: 1023 bits, 4 refs ----
    it('should allow a cell with 1023 bits', () => {
        const builder = beginCell();
        // Fill 1023 bits: 127 full bytes (1016 bits) + 7 bits
        for (let i = 0; i < 127; i++) {
            builder.storeUint(0xff, 8);
        }
        builder.storeUint(0x7f, 7); // 7 more bits
        expect(builder.remainingBits).toBe(0);
        const cell = builder.endCell();
        expect(cell.bits.length).toBe(1023);
    });

    it('should allow a cell with 4 refs', () => {
        const ref = beginCell().endCell();
        const cell = beginCell()
            .storeRef(ref)
            .storeRef(ref)
            .storeRef(ref)
            .storeRef(ref)
            .endCell();
        expect(cell.refs.length).toBe(4);
    });

    // ---- Overflow: 1024 bits should throw ----
    it('should throw when storing 1024 bits', () => {
        expect(() => {
            const builder = beginCell();
            for (let i = 0; i < 128; i++) {
                builder.storeUint(0xff, 8);
            }
            builder.endCell();
        }).toThrow();
    });

    // ---- 5 refs should throw ----
    it('should throw when storing 5 refs', () => {
        const ref = beginCell().endCell();
        expect(() => {
            beginCell()
                .storeRef(ref)
                .storeRef(ref)
                .storeRef(ref)
                .storeRef(ref)
                .storeRef(ref)
                .endCell();
        }).toThrow();
    });

    // ---- Empty cell ----
    it('should serialize and deserialize an empty cell', () => {
        const cell = beginCell().endCell();
        const boc = cell.toBoc();
        const restored = Cell.fromBoc(boc)[0]!;
        expect(restored.equals(cell)).toBe(true);
    });

    // ---- Cell.EMPTY ----
    it('Cell.EMPTY has zero bits and refs', () => {
        expect(Cell.EMPTY.bits.length).toBe(0);
        expect(Cell.EMPTY.refs.length).toBe(0);
    });

    // ---- fromHex / toHex round-trip ----
    it('should round-trip via fromHex/toHex', () => {
        const cell = beginCell().storeUint(0xdeadbeef, 32).endCell();
        const hex = cell.toHex();
        const restored = Cell.fromHex(hex);
        expect(restored.equals(cell)).toBe(true);
    });

    // ---- Multiple refs with data round-trip ----
    it('should round-trip parent cell with multiple refs and data', () => {
        const ref1 = beginCell().storeUint(123456789, 32).endCell();
        const ref2 = beginCell().storeUint(987654321, 32).endCell();
        const cell = beginCell()
            .storeUint(42, 16)
            .storeRef(ref1)
            .storeRef(ref2)
            .endCell();

        const boc = cell.toBoc();
        const parsed = Cell.fromBoc(boc)[0]!;
        expect(parsed.equals(cell)).toBe(true);

        const s = parsed.beginParse();
        expect(s.loadUint(16)).toBe(42);
        expect(s.loadRef().beginParse().loadUint(32)).toBe(123456789);
        expect(s.loadRef().beginParse().loadUint(32)).toBe(987654321);
    });
});
