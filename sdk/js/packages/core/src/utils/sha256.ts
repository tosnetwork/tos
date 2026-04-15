/**
 * SHA-256 implementation.
 * Will be replaced by @tos/crypto dependency when wired.
 * Pure JS -- no Node.js or Web Crypto API dependency.
 */

const K: readonly number[] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

function rotr(x: number, n: number): number {
    return ((x >>> n) | (x << (32 - n))) >>> 0;
}

/**
 * Compute a SHA-256 hash synchronously using a pure JavaScript implementation.
 *
 * This is used internally for cell hashing. For general-purpose hashing,
 * prefer the async `sha256` from `@tos/crypto` which uses Web Crypto API.
 *
 * @param data - The data to hash
 * @returns 32-byte SHA-256 digest
 *
 * @example
 * ```typescript
 * const hash = sha256(new Uint8Array([1, 2, 3]));
 * console.log(bytesToHex(hash));
 * ```
 */
export function sha256(data: Uint8Array): Uint8Array {
    const msgLen = data.length;
    const bitLen = msgLen * 8;
    const totalBytes = Math.ceil((msgLen + 9) / 64) * 64;
    const msg = new Uint8Array(totalBytes);
    msg.set(data);
    msg[msgLen] = 0x80;

    // Write length in bits as big-endian 64-bit integer.
    // For messages < 2^32 bits we only need the low 32 bits.
    const view = new DataView(msg.buffer, msg.byteOffset, msg.byteLength);
    view.setUint32(totalBytes - 4, bitLen, false);

    // Initial hash values
    let h0 = 0x6a09e667 >>> 0;
    let h1 = 0xbb67ae85 >>> 0;
    let h2 = 0x3c6ef372 >>> 0;
    let h3 = 0xa54ff53a >>> 0;
    let h4 = 0x510e527f >>> 0;
    let h5 = 0x9b05688c >>> 0;
    let h6 = 0x1f83d9ab >>> 0;
    let h7 = 0x5be0cd19 >>> 0;

    const w = new Uint32Array(64);

    for (let offset = 0; offset < totalBytes; offset += 64) {
        for (let i = 0; i < 16; i++) {
            w[i] = view.getUint32(offset + i * 4, false);
        }
        for (let i = 16; i < 64; i++) {
            const wi15 = w[i - 15] as number;
            const wi2 = w[i - 2] as number;
            const wi16 = w[i - 16] as number;
            const wi7 = w[i - 7] as number;
            const s0 = rotr(wi15, 7) ^ rotr(wi15, 18) ^ (wi15 >>> 3);
            const s1 = rotr(wi2, 17) ^ rotr(wi2, 19) ^ (wi2 >>> 10);
            w[i] = (wi16 + s0 + wi7 + s1) >>> 0;
        }

        let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;

        for (let i = 0; i < 64; i++) {
            const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const ch = (e & f) ^ (~e & g);
            const temp1 = (h + S1 + ch + (K[i] as number) + (w[i] as number)) >>> 0;
            const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = (S0 + maj) >>> 0;

            h = g;
            g = f;
            f = e;
            e = (d + temp1) >>> 0;
            d = c;
            c = b;
            b = a;
            a = (temp1 + temp2) >>> 0;
        }

        h0 = (h0 + a) >>> 0;
        h1 = (h1 + b) >>> 0;
        h2 = (h2 + c) >>> 0;
        h3 = (h3 + d) >>> 0;
        h4 = (h4 + e) >>> 0;
        h5 = (h5 + f) >>> 0;
        h6 = (h6 + g) >>> 0;
        h7 = (h7 + h) >>> 0;
    }

    const result = new Uint8Array(32);
    const rv = new DataView(result.buffer);
    rv.setUint32(0, h0, false);
    rv.setUint32(4, h1, false);
    rv.setUint32(8, h2, false);
    rv.setUint32(12, h3, false);
    rv.setUint32(16, h4, false);
    rv.setUint32(20, h5, false);
    rv.setUint32(24, h6, false);
    rv.setUint32(28, h7, false);

    return result;
}
