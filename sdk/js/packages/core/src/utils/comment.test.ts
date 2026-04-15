import { describe, it, expect } from 'vitest';
import { comment } from './comment';
import { Cell } from '../boc/Cell';

describe('comment', () => {
    it('should produce a cell with opcode 0 followed by UTF-8 text', () => {
        const cell = comment('hello');
        const s = cell.beginParse();

        // First 32 bits = opcode 0
        expect(s.loadUint(32)).toBe(0);

        // Remainder is the UTF-8 string
        expect(s.loadStringTail()).toBe('hello');
    });

    it('should handle empty string', () => {
        const cell = comment('');
        const s = cell.beginParse();
        expect(s.loadUint(32)).toBe(0);
        expect(s.loadStringTail()).toBe('');
    });

    it('should handle unicode string', () => {
        const cell = comment('Hello \u{1F600}');
        const s = cell.beginParse();
        expect(s.loadUint(32)).toBe(0);
        expect(s.loadStringTail()).toBe('Hello \u{1F600}');
    });

    it('round-trip through BOC', () => {
        const cell = comment('test message');
        const boc = cell.toBoc();

        const restored = Cell.fromBoc(boc)[0]!;
        const s = restored.beginParse();
        expect(s.loadUint(32)).toBe(0);
        expect(s.loadStringTail()).toBe('test message');
    });
});
