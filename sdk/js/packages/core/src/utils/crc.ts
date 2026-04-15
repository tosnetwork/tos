/**
 * CRC16 (CCITT/XMODEM) for address encoding and CRC32C for BOC serialization.
 * Operates on Uint8Array only -- no Buffer dependency.
 */

/**
 * Compute CRC16 CCITT (XModem variant, poly 0x1021).
 *
 * Used in TON/TOS friendly address encoding for checksum verification.
 *
 * @param data - Input bytes
 * @returns 2-byte CRC16 checksum as Uint8Array
 *
 * @example
 * ```typescript
 * const checksum = crc16(addressBytes);
 * ```
 */
export function crc16(data: Uint8Array): Uint8Array {
    const poly = 0x1021;
    let reg = 0;
    // Process data + 2 zero bytes
    const message = new Uint8Array(data.length + 2);
    message.set(data);
    for (let i = 0; i < message.length; i++) {
        const byte = message[i] as number;
        let mask = 0x80;
        while (mask > 0) {
            reg <<= 1;
            if (byte & mask) {
                reg += 1;
            }
            mask >>= 1;
            if (reg > 0xffff) {
                reg &= 0xffff;
                reg ^= poly;
            }
        }
    }
    return new Uint8Array([Math.floor(reg / 256), reg % 256]);
}

/**
 * CRC32C (Castagnoli) for BOC serialization.
 */
const CRC32C_POLY = 0x82f63b78;

/**
 * Compute CRC32C (Castagnoli) checksum for BOC serialization.
 *
 * @param source - Input bytes
 * @returns 4-byte CRC32C checksum as Uint8Array (little-endian)
 *
 * @example
 * ```typescript
 * const checksum = crc32c(bocBytes);
 * ```
 */
export function crc32c(source: Uint8Array): Uint8Array {
    let crc = 0 ^ 0xffffffff;
    for (let n = 0; n < source.length; n++) {
        crc ^= source[n] as number;
        crc = crc & 1 ? (crc >>> 1) ^ CRC32C_POLY : crc >>> 1;
        crc = crc & 1 ? (crc >>> 1) ^ CRC32C_POLY : crc >>> 1;
        crc = crc & 1 ? (crc >>> 1) ^ CRC32C_POLY : crc >>> 1;
        crc = crc & 1 ? (crc >>> 1) ^ CRC32C_POLY : crc >>> 1;
        crc = crc & 1 ? (crc >>> 1) ^ CRC32C_POLY : crc >>> 1;
        crc = crc & 1 ? (crc >>> 1) ^ CRC32C_POLY : crc >>> 1;
        crc = crc & 1 ? (crc >>> 1) ^ CRC32C_POLY : crc >>> 1;
        crc = crc & 1 ? (crc >>> 1) ^ CRC32C_POLY : crc >>> 1;
    }
    crc = crc ^ 0xffffffff;

    // Little-endian 4-byte result
    const res = new Uint8Array(4);
    res[0] = crc & 0xff;
    res[1] = (crc >>> 8) & 0xff;
    res[2] = (crc >>> 16) & 0xff;
    res[3] = (crc >>> 24) & 0xff;
    return res;
}
