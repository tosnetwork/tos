/**
 * External address representation.
 */

/**
 * Represents a TVM external address (addr_extern).
 *
 * External addresses consist of a value and a bit length, used for
 * addressing entities outside the blockchain (e.g., DNS, external systems).
 *
 * @example
 * ```typescript
 * const ext = new ExternalAddress(123n, 32);
 * console.log(ext.toString()); // "External<32:123>"
 * ```
 */
export class ExternalAddress {
    /**
     * Type guard to check if a value is an ExternalAddress.
     *
     * @param src - The value to check
     * @returns true if src is an ExternalAddress
     */
    static isAddress(src: unknown): src is ExternalAddress {
        return src instanceof ExternalAddress;
    }

    readonly value: bigint;
    readonly bits: number;

    constructor(value: bigint, bits: number) {
        this.value = value;
        this.bits = bits;
    }

    toString(): string {
        return `External<${this.bits}:${this.value}>`;
    }
}
