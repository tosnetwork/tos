import { describe, it, expect } from 'vitest';
import {
    hexToBytes,
    bytesToHex,
    base64ToBytes,
    bytesToBase64,
    base64UrlToBytes,
    bytesToBase64Url,
    stringToBytes,
    bytesToString,
} from './encoding';

describe('hexToBytes / bytesToHex', () => {
    it('round-trip', () => {
        const original = new Uint8Array([0, 1, 127, 128, 255]);
        const hex = bytesToHex(original);
        const back = hexToBytes(hex);
        expect(back).toEqual(original);
    });

    it('known vector: 0xdead -> "dead"', () => {
        expect(bytesToHex(new Uint8Array([0xde, 0xad]))).toBe('dead');
    });

    it('known vector: hexToBytes("dead")', () => {
        expect(hexToBytes('dead')).toEqual(new Uint8Array([0xde, 0xad]));
    });

    it('empty input', () => {
        expect(bytesToHex(new Uint8Array([]))).toBe('');
        expect(hexToBytes('')).toEqual(new Uint8Array([]));
    });

    it('throws on odd-length hex', () => {
        expect(() => hexToBytes('abc')).toThrow();
    });

    it('throws on invalid hex chars', () => {
        expect(() => hexToBytes('zz')).toThrow();
    });
});

describe('base64ToBytes / bytesToBase64', () => {
    it('round-trip', () => {
        const original = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
        const b64 = bytesToBase64(original);
        const back = base64ToBytes(b64);
        expect(back).toEqual(original);
    });

    it('known vector: "Hello" -> "SGVsbG8="', () => {
        const bytes = new Uint8Array([72, 101, 108, 108, 111]);
        expect(bytesToBase64(bytes)).toBe('SGVsbG8=');
    });

    it('empty', () => {
        expect(bytesToBase64(new Uint8Array([]))).toBe('');
        expect(base64ToBytes('')).toEqual(new Uint8Array([]));
    });

    it('single byte', () => {
        const b = new Uint8Array([0xff]);
        const encoded = bytesToBase64(b);
        expect(base64ToBytes(encoded)).toEqual(b);
    });

    it('two bytes', () => {
        const b = new Uint8Array([0xde, 0xad]);
        const encoded = bytesToBase64(b);
        expect(base64ToBytes(encoded)).toEqual(b);
    });
});

describe('base64Url', () => {
    it('round-trip', () => {
        const original = new Uint8Array([0xff, 0xfe, 0xfd, 0x3e, 0x3f]);
        const b64url = bytesToBase64Url(original);
        const back = base64UrlToBytes(b64url);
        expect(back).toEqual(original);
    });

    it('url-safe chars: no +, /, or =', () => {
        const data = new Uint8Array(256);
        for (let i = 0; i < 256; i++) data[i] = i;
        const encoded = bytesToBase64Url(data);
        expect(encoded).not.toContain('+');
        expect(encoded).not.toContain('/');
        expect(encoded).not.toContain('=');
    });
});

describe('stringToBytes / bytesToString', () => {
    it('round-trip for ASCII', () => {
        expect(bytesToString(stringToBytes('hello'))).toBe('hello');
    });

    it('round-trip for Unicode', () => {
        const s = 'Hello \u{1F600}';
        expect(bytesToString(stringToBytes(s))).toBe(s);
    });

    it('empty string', () => {
        expect(bytesToString(stringToBytes(''))).toBe('');
    });
});
