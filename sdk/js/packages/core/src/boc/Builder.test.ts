import { describe, it, expect } from 'vitest';
import { beginCell } from './Builder';
import { Address } from '../address/Address';

describe('Builder', () => {
    // ---- storeUint ----
    it('should store and read back uint values', () => {
        const cell = beginCell().storeUint(255, 8).endCell();
        expect(cell.beginParse().loadUint(8)).toBe(255);
    });

    it('should store uint 0', () => {
        const cell = beginCell().storeUint(0, 32).endCell();
        expect(cell.beginParse().loadUint(32)).toBe(0);
    });

    it('should store big uint via bigint', () => {
        const cell = beginCell().storeUint(0xdeadbeefn, 32).endCell();
        expect(cell.beginParse().loadUint(32)).toBe(0xdeadbeef);
    });

    // ---- storeInt ----
    it('should store and read back int values', () => {
        const cell = beginCell().storeInt(-1, 8).endCell();
        expect(cell.beginParse().loadInt(8)).toBe(-1);
    });

    it('should store positive int', () => {
        const cell = beginCell().storeInt(42, 16).endCell();
        expect(cell.beginParse().loadInt(16)).toBe(42);
    });

    it('should store int 0', () => {
        const cell = beginCell().storeInt(0, 8).endCell();
        expect(cell.beginParse().loadInt(8)).toBe(0);
    });

    // ---- storeBit ----
    it('should store bits (boolean)', () => {
        const cell = beginCell().storeBit(true).storeBit(false).endCell();
        const s = cell.beginParse();
        expect(s.loadBit()).toBe(true);
        expect(s.loadBit()).toBe(false);
    });

    it('should store bits (number)', () => {
        const cell = beginCell().storeBit(1).storeBit(0).endCell();
        const s = cell.beginParse();
        expect(s.loadBit()).toBe(true);
        expect(s.loadBit()).toBe(false);
    });

    // ---- storeBits ----
    it('should store BitString', () => {
        const src = beginCell().storeUint(0b10110, 5).endCell();
        const bits = src.bits;
        const cell = beginCell().storeBits(bits).endCell();
        expect(cell.bits.equals(bits)).toBe(true);
    });

    // ---- storeCoins ----
    it('should store and read coins', () => {
        const cell = beginCell().storeCoins(1000000000n).endCell();
        expect(cell.beginParse().loadCoins()).toBe(1000000000n);
    });

    it('should store zero coins', () => {
        const cell = beginCell().storeCoins(0n).endCell();
        expect(cell.beginParse().loadCoins()).toBe(0n);
    });

    // ---- storeAddress ----
    it('should store and read address', () => {
        const addr = Address.parseRaw(
            '0:2cf55953e92efbeadab7ba725c3f93a0b23f842cbba72d7b8e6f510a70e422e3',
        );
        const cell = beginCell().storeAddress(addr).endCell();
        const loaded = cell.beginParse().loadAddress();
        expect(loaded.equals(addr)).toBe(true);
    });

    it('should store null address (addr_none)', () => {
        const cell = beginCell().storeAddress(null).endCell();
        const loaded = cell.beginParse().loadMaybeAddress();
        expect(loaded).toBeNull();
    });

    // ---- storeRef ----
    it('should store a cell reference', () => {
        const ref = beginCell().storeUint(42, 8).endCell();
        const cell = beginCell().storeRef(ref).endCell();
        const loaded = cell.beginParse().loadRef();
        expect(loaded.equals(ref)).toBe(true);
    });

    it('should store a Builder as ref (auto endCell)', () => {
        const refBuilder = beginCell().storeUint(42, 8);
        const cell = beginCell().storeRef(refBuilder).endCell();
        const loaded = cell.beginParse().loadRef();
        expect(loaded.beginParse().loadUint(8)).toBe(42);
    });

    // ---- storeMaybeRef ----
    it('should store maybeRef with value', () => {
        const ref = beginCell().storeUint(1, 8).endCell();
        const cell = beginCell().storeMaybeRef(ref).endCell();
        const s = cell.beginParse();
        expect(s.loadBit()).toBe(true);
        expect(s.loadRef().beginParse().loadUint(8)).toBe(1);
    });

    it('should store maybeRef with null', () => {
        const cell = beginCell().storeMaybeRef(null).endCell();
        const s = cell.beginParse();
        expect(s.loadBit()).toBe(false);
    });

    // ---- storeStringTail ----
    it('should store and read string', () => {
        const cell = beginCell().storeStringTail('hello world').endCell();
        const s = cell.beginParse();
        expect(s.loadStringTail()).toBe('hello world');
    });

    it('should store empty string', () => {
        const cell = beginCell().storeStringTail('').endCell();
        const s = cell.beginParse();
        expect(s.loadStringTail()).toBe('');
    });

    // ---- storeBuffer ----
    it('should store and read buffer', () => {
        const buf = new Uint8Array([1, 2, 3, 4]);
        const cell = beginCell().storeBuffer(buf).endCell();
        const loaded = cell.beginParse().loadBuffer(4);
        expect(loaded).toEqual(buf);
    });

    // ---- remainingBits / remainingRefs ----
    it('should track remainingBits correctly', () => {
        const b = beginCell();
        expect(b.remainingBits).toBe(1023);
        b.storeUint(0, 8);
        expect(b.remainingBits).toBe(1015);
        b.storeUint(0, 16);
        expect(b.remainingBits).toBe(999);
    });

    it('should track remainingRefs correctly', () => {
        const b = beginCell();
        expect(b.remainingRefs).toBe(4);
        b.storeRef(beginCell().endCell());
        expect(b.remainingRefs).toBe(3);
        b.storeRef(beginCell().endCell());
        expect(b.remainingRefs).toBe(2);
    });

    // ---- Chaining ----
    it('should support method chaining', () => {
        const cell = beginCell()
            .storeUint(1, 8)
            .storeUint(2, 8)
            .storeUint(3, 8)
            .endCell();

        const s = cell.beginParse();
        expect(s.loadUint(8)).toBe(1);
        expect(s.loadUint(8)).toBe(2);
        expect(s.loadUint(8)).toBe(3);
    });

    // ---- overflow checks ----
    it('should throw on ref overflow (more than 4)', () => {
        const ref = beginCell().endCell();
        expect(() => {
            beginCell()
                .storeRef(ref)
                .storeRef(ref)
                .storeRef(ref)
                .storeRef(ref)
                .storeRef(ref);
        }).toThrow();
    });
});
