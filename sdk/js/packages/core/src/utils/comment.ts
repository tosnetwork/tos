/**
 * Build a comment cell: op=0 followed by UTF-8 string.
 */

import { beginCell } from '../boc/Builder';
import { Cell } from '../boc/Cell';

/**
 * Create a comment cell for use as a message body.
 *
 * Produces a cell with `op=0` (text comment) followed by the UTF-8 encoded
 * string in snake format. This is the standard way to attach human-readable
 * comments to TOS transfers.
 *
 * @param text - The comment text
 * @returns A Cell containing the comment body
 *
 * @example
 * ```typescript
 * const body = comment("Thank you for the payment!");
 * // Use as message body in a transfer
 * ```
 */
export function comment(text: string): Cell {
    return beginCell()
        .storeUint(0, 32)       // op = 0 (text comment)
        .storeStringTail(text)
        .endCell();
}
