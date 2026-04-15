/**
 * Parse a dictionary (hashmap) from a Slice.
 */

import { Slice } from '../boc/Slice';

function readUnaryLength(slice: Slice): number {
    let res = 0;
    while (slice.loadBit()) {
        res++;
    }
    return res;
}

function doParse<V>(
    prefix: string,
    slice: Slice,
    n: number,
    res: Map<bigint, V>,
    extractor: (src: Slice) => V,
): void {
    const lb0 = slice.loadBit() ? 1 : 0;
    let prefixLength = 0;
    let pp = prefix;

    if (lb0 === 0) {
        // Short label
        prefixLength = readUnaryLength(slice);
        for (let i = 0; i < prefixLength; i++) {
            pp += slice.loadBit() ? '1' : '0';
        }
    } else {
        const lb1 = slice.loadBit() ? 1 : 0;
        if (lb1 === 0) {
            // Long label
            prefixLength = slice.loadUint(Math.ceil(Math.log2(n + 1)));
            for (let i = 0; i < prefixLength; i++) {
                pp += slice.loadBit() ? '1' : '0';
            }
        } else {
            // Same label
            const bit = slice.loadBit() ? '1' : '0';
            prefixLength = slice.loadUint(Math.ceil(Math.log2(n + 1)));
            for (let i = 0; i < prefixLength; i++) {
                pp += bit;
            }
        }
    }

    if (n - prefixLength === 0) {
        res.set(BigInt('0b' + pp), extractor(slice));
    } else {
        const left = slice.loadRef();
        const right = slice.loadRef();
        if (!left.isExotic) {
            doParse(
                pp + '0',
                left.beginParse(),
                n - prefixLength - 1,
                res,
                extractor,
            );
        }
        if (!right.isExotic) {
            doParse(
                pp + '1',
                right.beginParse(),
                n - prefixLength - 1,
                res,
                extractor,
            );
        }
    }
}

export function parseDict<V>(
    sc: Slice | null,
    keySize: number,
    extractor: (src: Slice) => V,
): Map<bigint, V> {
    const res = new Map<bigint, V>();
    if (sc) {
        doParse('', sc, keySize, res, extractor);
    }
    return res;
}
