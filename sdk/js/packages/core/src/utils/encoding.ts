/**
 * Isomorphic encoding utilities (no Buffer dependency).
 * All functions operate on Uint8Array.
 */

const HEX_CHARS = '0123456789abcdef';

/**
 * Convert a byte array to a lowercase hex string.
 *
 * @param bytes - The bytes to encode
 * @returns Lowercase hex string
 *
 * @example
 * ```typescript
 * bytesToHex(new Uint8Array([0xab, 0xcd])); // "abcd"
 * ```
 */
export function bytesToHex(bytes: Uint8Array): string {
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        const b = bytes[i] as number;
        hex += HEX_CHARS[(b >> 4) as number];
        hex += HEX_CHARS[(b & 0x0f) as number];
    }
    return hex;
}

/**
 * Decode a hex string to a byte array.
 *
 * @param hex - Hex string (must have even length)
 * @returns Decoded bytes
 *
 * @example
 * ```typescript
 * hexToBytes("abcd"); // Uint8Array [0xab, 0xcd]
 * ```
 */
export function hexToBytes(hex: string): Uint8Array {
    if (hex.length % 2 !== 0) {
        throw new Error('Invalid hex string length');
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        const hi = parseInt(hex.charAt(i), 16);
        const lo = parseInt(hex.charAt(i + 1), 16);
        if (Number.isNaN(hi) || Number.isNaN(lo)) {
            throw new Error('Invalid hex character');
        }
        bytes[i / 2] = (hi << 4) | lo;
    }
    return bytes;
}

// Standard base64 alphabet
const B64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function makeDecodeTable(alphabet: string): Int32Array {
    const table = new Int32Array(128).fill(-1);
    for (let i = 0; i < alphabet.length; i++) {
        table[alphabet.charCodeAt(i)] = i;
    }
    return table;
}

const B64_DECODE = makeDecodeTable(B64_CHARS);

/**
 * Encode a byte array to a standard base64 string (with padding).
 *
 * @param bytes - The bytes to encode
 * @returns Standard base64 string
 *
 * @example
 * ```typescript
 * bytesToBase64(new Uint8Array([72, 101, 108, 108, 111])); // "SGVsbG8="
 * ```
 */
export function bytesToBase64(bytes: Uint8Array): string {
    let result = '';
    const len = bytes.length;
    const remainder = len % 3;
    const mainLen = len - remainder;

    for (let i = 0; i < mainLen; i += 3) {
        const b0 = bytes[i] as number;
        const b1 = bytes[i + 1] as number;
        const b2 = bytes[i + 2] as number;
        const n = (b0 << 16) | (b1 << 8) | b2;
        result += B64_CHARS.charAt((n >> 18) & 0x3f);
        result += B64_CHARS.charAt((n >> 12) & 0x3f);
        result += B64_CHARS.charAt((n >> 6) & 0x3f);
        result += B64_CHARS.charAt(n & 0x3f);
    }

    if (remainder === 1) {
        const b0 = bytes[mainLen] as number;
        result += B64_CHARS.charAt((b0 >> 2) & 0x3f);
        result += B64_CHARS.charAt((b0 << 4) & 0x3f);
        result += '==';
    } else if (remainder === 2) {
        const b0 = bytes[mainLen] as number;
        const b1 = bytes[mainLen + 1] as number;
        const n = (b0 << 8) | b1;
        result += B64_CHARS.charAt((n >> 10) & 0x3f);
        result += B64_CHARS.charAt((n >> 4) & 0x3f);
        result += B64_CHARS.charAt((n << 2) & 0x3f);
        result += '=';
    }

    return result;
}

/**
 * Decode a standard base64 string to a byte array.
 *
 * @param b64 - Standard base64 string (with padding)
 * @returns Decoded bytes
 *
 * @example
 * ```typescript
 * base64ToBytes("SGVsbG8="); // Uint8Array [72, 101, 108, 108, 111]
 * ```
 */
export function base64ToBytes(b64: string): Uint8Array {
    const len = b64.length;
    let padding = 0;
    if (len > 0 && b64.charAt(len - 1) === '=') padding++;
    if (len > 1 && b64.charAt(len - 2) === '=') padding++;

    const outputLen = (len * 3) / 4 - padding;
    const bytes = new Uint8Array(outputLen);

    let j = 0;
    for (let i = 0; i < len; i += 4) {
        const c0 = b64.charCodeAt(i);
        const c1 = b64.charCodeAt(i + 1);

        const v0 = c0 < 128 ? (B64_DECODE[c0] as number) : -1;
        const v1 = c1 < 128 ? (B64_DECODE[c1] as number) : -1;
        const v2 = i + 2 < len && b64.charAt(i + 2) !== '='
            ? (B64_DECODE[b64.charCodeAt(i + 2)] as number)
            : 0;
        const v3 = i + 3 < len && b64.charAt(i + 3) !== '='
            ? (B64_DECODE[b64.charCodeAt(i + 3)] as number)
            : 0;

        if (v0 === -1 || v1 === -1) {
            throw new Error('Invalid base64 character');
        }

        const n = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;

        if (j < outputLen) bytes[j++] = (n >> 16) & 0xff;
        if (j < outputLen) bytes[j++] = (n >> 8) & 0xff;
        if (j < outputLen) bytes[j++] = n & 0xff;
    }

    return bytes;
}

/**
 * Encode a byte array to a URL-safe base64 string (no padding).
 *
 * @param bytes - The bytes to encode
 * @returns URL-safe base64 string (uses `-` and `_` instead of `+` and `/`)
 *
 * @example
 * ```typescript
 * bytesToBase64Url(data); // "SGVsbG8"
 * ```
 */
export function bytesToBase64Url(bytes: Uint8Array): string {
    return bytesToBase64(bytes)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

/**
 * Decode a URL-safe base64 string to a byte array.
 *
 * @param b64url - URL-safe base64 string (may omit padding)
 * @returns Decoded bytes
 *
 * @example
 * ```typescript
 * base64UrlToBytes("SGVsbG8"); // Uint8Array [72, 101, 108, 108, 111]
 * ```
 */
export function base64UrlToBytes(b64url: string): Uint8Array {
    let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4 !== 0) {
        b64 += '=';
    }
    return base64ToBytes(b64);
}

/**
 * Encode a string as UTF-8 bytes.
 */
export function stringToBytes(str: string): Uint8Array {
    // Pure-JS UTF-8 encoder for environments without TextEncoder
    const bytes: number[] = [];
    for (let i = 0; i < str.length; i++) {
        let code = str.charCodeAt(i);
        if (code >= 0xd800 && code <= 0xdbff && i + 1 < str.length) {
            const lo = str.charCodeAt(i + 1);
            if (lo >= 0xdc00 && lo <= 0xdfff) {
                code = ((code - 0xd800) << 10) + (lo - 0xdc00) + 0x10000;
                i++;
            }
        }
        if (code < 0x80) {
            bytes.push(code);
        } else if (code < 0x800) {
            bytes.push(0xc0 | (code >> 6));
            bytes.push(0x80 | (code & 0x3f));
        } else if (code < 0x10000) {
            bytes.push(0xe0 | (code >> 12));
            bytes.push(0x80 | ((code >> 6) & 0x3f));
            bytes.push(0x80 | (code & 0x3f));
        } else {
            bytes.push(0xf0 | (code >> 18));
            bytes.push(0x80 | ((code >> 12) & 0x3f));
            bytes.push(0x80 | ((code >> 6) & 0x3f));
            bytes.push(0x80 | (code & 0x3f));
        }
    }
    return new Uint8Array(bytes);
}

/**
 * Decode UTF-8 bytes to a string.
 */
export function bytesToString(bytes: Uint8Array): string {
    let str = '';
    let i = 0;
    while (i < bytes.length) {
        const b = bytes[i] as number;
        if (b < 0x80) {
            str += String.fromCharCode(b);
            i++;
        } else if ((b & 0xe0) === 0xc0) {
            const c = ((b & 0x1f) << 6) | ((bytes[i + 1] as number) & 0x3f);
            str += String.fromCharCode(c);
            i += 2;
        } else if ((b & 0xf0) === 0xe0) {
            const c =
                ((b & 0x0f) << 12) |
                (((bytes[i + 1] as number) & 0x3f) << 6) |
                ((bytes[i + 2] as number) & 0x3f);
            str += String.fromCharCode(c);
            i += 3;
        } else {
            const c =
                ((b & 0x07) << 18) |
                (((bytes[i + 1] as number) & 0x3f) << 12) |
                (((bytes[i + 2] as number) & 0x3f) << 6) |
                ((bytes[i + 3] as number) & 0x3f);
            // Encode as surrogate pair
            const hi = 0xd800 + ((c - 0x10000) >> 10);
            const lo = 0xdc00 + ((c - 0x10000) & 0x3ff);
            str += String.fromCharCode(hi, lo);
            i += 4;
        }
    }
    return str;
}
