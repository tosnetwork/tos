import { describe, it, expect } from 'vitest';
import { toNano, fromNano } from './convert';

describe('toNano', () => {
    it('toNano("1") === 1000000000n', () => {
        expect(toNano('1')).toBe(1000000000n);
    });

    it('toNano("1.5") === 1500000000n', () => {
        expect(toNano('1.5')).toBe(1500000000n);
    });

    it('toNano("0.000000001") === 1n', () => {
        expect(toNano('0.000000001')).toBe(1n);
    });

    it('toNano("0") === 0n', () => {
        expect(toNano('0')).toBe(0n);
    });

    it('toNano(bigint) multiplies by 1e9', () => {
        expect(toNano(2n)).toBe(2000000000n);
    });

    it('toNano(number) works for small values', () => {
        expect(toNano(1)).toBe(1000000000n);
    });

    it('toNano("0.5") === 500000000n', () => {
        expect(toNano('0.5')).toBe(500000000n);
    });

    it('toNano("-1") === -1000000000n', () => {
        expect(toNano('-1')).toBe(-1000000000n);
    });

    it('throws on too many decimals', () => {
        expect(() => toNano('0.0000000001')).toThrow();
    });

    it('throws on invalid string', () => {
        expect(() => toNano('.')).toThrow();
    });
});

describe('fromNano', () => {
    it('fromNano(1500000000n) === "1.5"', () => {
        expect(fromNano(1500000000n)).toBe('1.5');
    });

    it('fromNano(0n) === "0"', () => {
        expect(fromNano(0n)).toBe('0');
    });

    it('fromNano(1000000000n) === "1"', () => {
        expect(fromNano(1000000000n)).toBe('1');
    });

    it('fromNano(1n) === "0.000000001"', () => {
        expect(fromNano(1n)).toBe('0.000000001');
    });

    it('fromNano(-1500000000n) === "-1.5"', () => {
        expect(fromNano(-1500000000n)).toBe('-1.5');
    });

    it('round-trip: fromNano(toNano(x)) === x', () => {
        expect(fromNano(toNano('123.456'))).toBe('123.456');
    });
});
