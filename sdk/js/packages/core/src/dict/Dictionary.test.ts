import { describe, it, expect } from 'vitest';
import { Dictionary } from './Dictionary';
import { beginCell } from '../boc/Builder';

describe('Dictionary', () => {
    // ---- Empty dictionary ----
    it('should create an empty dictionary', () => {
        const dict = Dictionary.empty(
            Dictionary.Keys.Int(32),
            Dictionary.Values.BigInt(64),
        );
        expect(dict.size).toBe(0);
    });

    // ---- set / get ----
    it('should set and get values', () => {
        const dict = Dictionary.empty(
            Dictionary.Keys.Int(32),
            Dictionary.Values.BigInt(64),
        );
        dict.set(1, 100n);
        dict.set(2, 200n);
        expect(dict.get(1)).toBe(100n);
        expect(dict.get(2)).toBe(200n);
        expect(dict.get(3)).toBeUndefined();
    });

    // ---- has ----
    it('has() returns true for existing keys', () => {
        const dict = Dictionary.empty(
            Dictionary.Keys.Int(32),
            Dictionary.Values.BigInt(64),
        );
        dict.set(42, 999n);
        expect(dict.has(42)).toBe(true);
        expect(dict.has(43)).toBe(false);
    });

    // ---- delete ----
    it('delete() removes a key', () => {
        const dict = Dictionary.empty(
            Dictionary.Keys.Int(32),
            Dictionary.Values.BigInt(64),
        );
        dict.set(1, 100n);
        expect(dict.delete(1)).toBe(true);
        expect(dict.has(1)).toBe(false);
        expect(dict.size).toBe(0);
    });

    it('delete() returns false for non-existent key', () => {
        const dict = Dictionary.empty(
            Dictionary.Keys.Int(32),
            Dictionary.Values.BigInt(64),
        );
        expect(dict.delete(999)).toBe(false);
    });

    // ---- keys / values ----
    it('keys() and values() return correct arrays', () => {
        const dict = Dictionary.empty(
            Dictionary.Keys.Int(32),
            Dictionary.Values.BigInt(64),
        );
        dict.set(10, 100n);
        dict.set(20, 200n);
        dict.set(30, 300n);

        const keys = dict.keys();
        const values = dict.values();
        expect(keys.length).toBe(3);
        expect(values.length).toBe(3);
        expect(keys).toContain(10);
        expect(keys).toContain(20);
        expect(keys).toContain(30);
        expect(values).toContain(100n);
        expect(values).toContain(200n);
        expect(values).toContain(300n);
    });

    // ---- size ----
    it('size updates correctly', () => {
        const dict = Dictionary.empty(
            Dictionary.Keys.Int(32),
            Dictionary.Values.BigInt(64),
        );
        expect(dict.size).toBe(0);
        dict.set(1, 1n);
        expect(dict.size).toBe(1);
        dict.set(2, 2n);
        expect(dict.size).toBe(2);
        dict.delete(1);
        expect(dict.size).toBe(1);
    });

    // ---- clear ----
    it('clear() empties the dictionary', () => {
        const dict = Dictionary.empty(
            Dictionary.Keys.Int(32),
            Dictionary.Values.BigInt(64),
        );
        dict.set(1, 1n);
        dict.set(2, 2n);
        dict.clear();
        expect(dict.size).toBe(0);
    });

    // ---- Uint keys ----
    it('should work with Uint keys', () => {
        const dict = Dictionary.empty(
            Dictionary.Keys.Uint(16),
            Dictionary.Values.Uint(16),
        );
        dict.set(0, 0);
        dict.set(65535, 1);
        expect(dict.get(0)).toBe(0);
        expect(dict.get(65535)).toBe(1);
    });

    // ---- BigInt keys ----
    it('should work with BigInt keys', () => {
        const dict = Dictionary.empty(
            Dictionary.Keys.BigInt(256),
            Dictionary.Values.Bool(),
        );
        dict.set(0n, true);
        dict.set(1n, false);
        expect(dict.get(0n)).toBe(true);
        expect(dict.get(1n)).toBe(false);
    });

    // ---- Overwrite existing key ----
    it('should overwrite value for existing key', () => {
        const dict = Dictionary.empty(
            Dictionary.Keys.Int(32),
            Dictionary.Values.BigInt(64),
        );
        dict.set(1, 100n);
        dict.set(1, 200n);
        expect(dict.get(1)).toBe(200n);
        expect(dict.size).toBe(1);
    });

    // ---- Serialization round-trip ----
    it('should serialize and deserialize via Cell', () => {
        const key = Dictionary.Keys.Int(32);
        const value = Dictionary.Values.BigInt(64);
        const dict = Dictionary.empty(key, value);
        dict.set(1, 100n);
        dict.set(2, 200n);
        dict.set(-1, -50n);

        // Serialize to cell
        const cell = beginCell().storeDict(dict).endCell();

        // Deserialize
        const loaded = Dictionary.load(key, value, cell.beginParse());
        expect(loaded.get(1)).toBe(100n);
        expect(loaded.get(2)).toBe(200n);
        expect(loaded.get(-1)).toBe(-50n);
        expect(loaded.size).toBe(3);
    });

    // ---- Iterator ----
    it('should support iteration via Symbol.iterator', () => {
        const dict = Dictionary.empty(
            Dictionary.Keys.Int(32),
            Dictionary.Values.BigInt(64),
        );
        dict.set(1, 10n);
        dict.set(2, 20n);

        const entries: [number, bigint][] = [];
        for (const [k, v] of dict) {
            entries.push([k, v]);
        }
        expect(entries.length).toBe(2);
    });
});
