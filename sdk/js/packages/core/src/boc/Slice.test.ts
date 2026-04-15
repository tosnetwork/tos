import { describe, it, expect } from 'vitest';
import { beginCell } from './Builder';
import { Address } from '../address/Address';

describe('Slice', () => {
    // ---- loadUint / loadInt ----
    it('should load uint and int', () => {
        const cell = beginCell()
            .storeUint(200, 8)
            .storeInt(-50, 16)
            .endCell();
        const s = cell.beginParse();
        expect(s.loadUint(8)).toBe(200);
        expect(s.loadInt(16)).toBe(-50);
    });

    // ---- loadBit ----
    it('should load individual bits', () => {
        const cell = beginCell().storeBit(true).storeBit(false).storeBit(true).endCell();
        const s = cell.beginParse();
        expect(s.loadBit()).toBe(true);
        expect(s.loadBit()).toBe(false);
        expect(s.loadBit()).toBe(true);
    });

    // ---- loadCoins ----
    it('should load coins', () => {
        const cell = beginCell().storeCoins(5000000000n).endCell();
        const s = cell.beginParse();
        expect(s.loadCoins()).toBe(5000000000n);
    });

    // ---- loadAddress ----
    it('should load address', () => {
        const addr = Address.parseRaw(
            '0:2cf55953e92efbeadab7ba725c3f93a0b23f842cbba72d7b8e6f510a70e422e3',
        );
        const cell = beginCell().storeAddress(addr).endCell();
        const loaded = cell.beginParse().loadAddress();
        expect(loaded.equals(addr)).toBe(true);
    });

    // ---- loadRef ----
    it('should load a ref', () => {
        const ref = beginCell().storeUint(42, 8).endCell();
        const cell = beginCell().storeRef(ref).endCell();
        const s = cell.beginParse();
        const loadedRef = s.loadRef();
        expect(loadedRef.beginParse().loadUint(8)).toBe(42);
    });

    // ---- preloadUint does not advance cursor ----
    it('preloadUint should not advance the cursor', () => {
        const cell = beginCell().storeUint(77, 8).endCell();
        const s = cell.beginParse();
        const val1 = s.preloadUint(8);
        const val2 = s.preloadUint(8);
        expect(val1).toBe(77);
        expect(val2).toBe(77);
        // cursor is still at 0 — loadUint should still return 77
        expect(s.loadUint(8)).toBe(77);
    });

    // ---- endParse ----
    it('endParse should succeed on empty slice', () => {
        const cell = beginCell().storeUint(42, 8).endCell();
        const s = cell.beginParse();
        s.loadUint(8);
        expect(() => s.endParse()).not.toThrow();
    });

    it('endParse should throw on non-empty slice', () => {
        const cell = beginCell().storeUint(42, 8).endCell();
        const s = cell.beginParse();
        expect(() => s.endParse()).toThrow('Slice is not empty');
    });

    it('endParse should throw when refs remain', () => {
        const ref = beginCell().endCell();
        const cell = beginCell().storeRef(ref).endCell();
        const s = cell.beginParse();
        expect(() => s.endParse()).toThrow('Slice is not empty');
    });

    // ---- skip ----
    it('skip should advance cursor correctly', () => {
        const cell = beginCell().storeUint(0xAB, 8).storeUint(0xCD, 8).endCell();
        const s = cell.beginParse();
        s.skip(8);
        expect(s.loadUint(8)).toBe(0xCD);
    });

    it('skip chaining', () => {
        const cell = beginCell().storeUint(1, 8).storeUint(2, 8).storeUint(3, 8).endCell();
        const s = cell.beginParse();
        s.skip(16);
        expect(s.loadUint(8)).toBe(3);
    });

    // ---- remainingBits / remainingRefs ----
    it('should track remainingBits', () => {
        const cell = beginCell().storeUint(0, 32).endCell();
        const s = cell.beginParse();
        expect(s.remainingBits).toBe(32);
        s.loadUint(8);
        expect(s.remainingBits).toBe(24);
    });

    it('should track remainingRefs', () => {
        const ref = beginCell().endCell();
        const cell = beginCell().storeRef(ref).storeRef(ref).endCell();
        const s = cell.beginParse();
        expect(s.remainingRefs).toBe(2);
        s.loadRef();
        expect(s.remainingRefs).toBe(1);
    });

    // ---- loadBuffer ----
    it('should load buffer', () => {
        const buf = new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]);
        const cell = beginCell().storeBuffer(buf).endCell();
        const loaded = cell.beginParse().loadBuffer(4);
        expect(loaded).toEqual(buf);
    });

    // ---- loadStringTail ----
    it('should load string tail', () => {
        const cell = beginCell().storeStringTail('hello').endCell();
        const s = cell.beginParse();
        expect(s.loadStringTail()).toBe('hello');
    });

    // ---- clone ----
    it('clone should produce independent slice', () => {
        const cell = beginCell().storeUint(1, 8).storeUint(2, 8).endCell();
        const s = cell.beginParse();
        s.loadUint(8); // advance
        const cloned = s.clone();
        expect(cloned.loadUint(8)).toBe(2);
        // original should also still have the same value at same position
        expect(s.loadUint(8)).toBe(2);
    });

    // ---- loadMaybeRef ----
    it('loadMaybeRef should return cell when bit=1', () => {
        const ref = beginCell().storeUint(42, 8).endCell();
        const cell = beginCell().storeMaybeRef(ref).endCell();
        const s = cell.beginParse();
        const maybeRef = s.loadMaybeRef();
        expect(maybeRef).not.toBeNull();
        expect(maybeRef!.beginParse().loadUint(8)).toBe(42);
    });

    it('loadMaybeRef should return null when bit=0', () => {
        const cell = beginCell().storeMaybeRef(null).endCell();
        const s = cell.beginParse();
        expect(s.loadMaybeRef()).toBeNull();
    });

    // ---- preloadRef ----
    it('preloadRef should not advance ref cursor', () => {
        const ref = beginCell().storeUint(42, 8).endCell();
        const cell = beginCell().storeRef(ref).endCell();
        const s = cell.beginParse();
        const r1 = s.preloadRef();
        const r2 = s.preloadRef();
        expect(r1.equals(r2)).toBe(true);
        // loadRef still works
        expect(s.loadRef().equals(ref)).toBe(true);
    });
});
