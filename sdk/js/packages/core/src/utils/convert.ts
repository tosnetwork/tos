/**
 * Unit conversion between human-readable TOS amounts and nanoTOS.
 * 1 TOS = 1,000,000,000 nanoTOS (10^9).
 */

/**
 * Convert a human-readable TOS amount to nanoTOS (the smallest unit).
 *
 * @param src - Amount in TOS as a number, string, or bigint
 * @returns The amount in nanoTOS as a bigint
 *
 * @example
 * ```typescript
 * toNano("1.5");   // 1500000000n
 * toNano(1);       // 1000000000n
 * toNano(2n);      // 2000000000n
 * toNano("0.001"); // 1000000n
 * ```
 */
export function toNano(src: number | string | bigint): bigint {
    if (typeof src === 'bigint') {
        return src * 1000000000n;
    }

    if (typeof src === 'number') {
        if (!Number.isFinite(src)) {
            throw new Error('Invalid number');
        }
        if (Math.log10(src) <= 6) {
            src = src.toLocaleString('en', {
                minimumFractionDigits: 9,
                useGrouping: false,
            });
        } else if (src - Math.trunc(src) === 0) {
            src = src.toLocaleString('en', {
                maximumFractionDigits: 0,
                useGrouping: false,
            });
        } else {
            throw new Error(
                'Not enough precision for a number value. Use string value instead',
            );
        }
    }

    // Check sign
    let neg = false;
    while (src.startsWith('-')) {
        neg = !neg;
        src = src.slice(1);
    }

    // Split string
    if (src === '.') {
        throw new Error('Invalid number');
    }
    const parts = src.split('.');
    if (parts.length > 2) {
        throw new Error('Invalid number');
    }

    // Prepare parts
    let whole = parts[0];
    let frac = parts[1];
    if (!whole) {
        whole = '0';
    }
    if (!frac) {
        frac = '0';
    }
    if (frac.length > 9) {
        throw new Error('Invalid number');
    }
    while (frac.length < 9) {
        frac += '0';
    }

    // Convert
    let r = BigInt(whole) * 1000000000n + BigInt(frac);
    if (neg) {
        r = -r;
    }
    return r;
}

/**
 * Convert a nanoTOS amount to a human-readable TOS string.
 *
 * @param src - Amount in nanoTOS as a bigint, number, or string
 * @returns The amount in TOS as a decimal string
 *
 * @example
 * ```typescript
 * fromNano(1500000000n); // "1.5"
 * fromNano(1000000000n); // "1"
 * fromNano(1000000n);    // "0.001"
 * fromNano("500000000");  // "0.5"
 * ```
 */
export function fromNano(src: bigint | number | string): string {
    let v = BigInt(src);
    let neg = false;
    if (v < 0) {
        neg = true;
        v = -v;
    }

    // Convert fraction
    const frac = v % 1000000000n;
    let fracStr = frac.toString();
    while (fracStr.length < 9) {
        fracStr = '0' + fracStr;
    }
    fracStr = fracStr.match(/^([0-9]*[1-9]|0)(0*)/)![1]!;

    // Convert whole
    const whole = v / 1000000000n;
    const wholeStr = whole.toString();

    // Value
    let value = `${wholeStr}${fracStr === '0' ? '' : `.${fracStr}`}`;
    if (neg) {
        value = '-' + value;
    }

    return value;
}
