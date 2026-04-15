/**
 * Serialize a dictionary (hashmap) to a Builder.
 */

import { beginCell, Builder } from '../boc/Builder';
import { findCommonPrefix } from './utils/findCommonPrefix';

// Tree types

type Node<T> =
    | { type: 'fork'; left: Edge<T>; right: Edge<T> }
    | { type: 'leaf'; value: T };

type Edge<T> = {
    label: string;
    node: Node<T>;
};

function pad(src: string, size: number): string {
    while (src.length < size) {
        src = '0' + src;
    }
    return src;
}

function forkMap<T>(src: Map<string, T>, prefixLen: number): {
    left: Map<string, T>;
    right: Map<string, T>;
} {
    if (src.size === 0) throw new Error('Internal inconsistency');
    const left = new Map<string, T>();
    const right = new Map<string, T>();
    for (const [k, d] of src.entries()) {
        if (k[prefixLen] === '0') {
            left.set(k, d);
        } else {
            right.set(k, d);
        }
    }
    if (left.size === 0) throw new Error('Internal inconsistency. Left empty.');
    if (right.size === 0) throw new Error('Internal inconsistency. Right empty.');
    return { left, right };
}

function buildNode<T>(src: Map<string, T>, prefixLen: number): Node<T> {
    if (src.size === 0) throw new Error('Internal inconsistency');
    if (src.size === 1) {
        return { type: 'leaf', value: Array.from(src.values())[0] as T };
    }
    const { left, right } = forkMap(src, prefixLen);
    return {
        type: 'fork',
        left: buildEdge(left, prefixLen + 1),
        right: buildEdge(right, prefixLen + 1),
    };
}

function buildEdge<T>(src: Map<string, T>, prefixLen: number = 0): Edge<T> {
    if (src.size === 0) throw new Error('Internal inconsistency');
    const label = findCommonPrefix(Array.from(src.keys()), prefixLen);
    return { label, node: buildNode(src, label.length + prefixLen) };
}

function buildTree<T>(src: Map<bigint, T>, keyLength: number): Edge<T> {
    const converted = new Map<string, T>();
    for (const [k, v] of src) {
        converted.set(pad(k.toString(2), keyLength), v);
    }
    return buildEdge(converted);
}

// Label serialization

function labelShortLength(src: string): number {
    return 1 + src.length + 1 + src.length;
}

function labelLongLength(src: string, keyLength: number): number {
    return 1 + 1 + Math.ceil(Math.log2(keyLength + 1)) + src.length;
}

function labelSameLength(keyLength: number): number {
    return 1 + 1 + 1 + Math.ceil(Math.log2(keyLength + 1));
}

function isSame(src: string): boolean {
    if (src.length <= 1) return true;
    for (let i = 1; i < src.length; i++) {
        if (src[i] !== src[0]) return false;
    }
    return true;
}

function detectLabelType(
    src: string,
    keyLength: number,
): 'short' | 'long' | 'same' {
    let kind: 'short' | 'long' | 'same' = 'short';
    let kindLength = labelShortLength(src);

    const longLen = labelLongLength(src, keyLength);
    if (longLen < kindLength) {
        kindLength = longLen;
        kind = 'long';
    }

    if (isSame(src)) {
        const sameLen = labelSameLength(keyLength);
        if (sameLen < kindLength) {
            kind = 'same';
        }
    }

    return kind;
}

function writeLabelShort(src: string, to: Builder): void {
    to.storeBit(0);
    for (let i = 0; i < src.length; i++) {
        to.storeBit(1);
    }
    to.storeBit(0);
    if (src.length > 0) {
        to.storeUint(BigInt('0b' + src), src.length);
    }
}

function writeLabelLong(src: string, keyLength: number, to: Builder): void {
    to.storeBit(1);
    to.storeBit(0);
    const length = Math.ceil(Math.log2(keyLength + 1));
    to.storeUint(src.length, length);
    if (src.length > 0) {
        to.storeUint(BigInt('0b' + src), src.length);
    }
}

function writeLabelSame(
    value: number | boolean,
    length: number,
    keyLength: number,
    to: Builder,
): void {
    to.storeBit(1);
    to.storeBit(1);
    to.storeBit(value);
    const lenLen = Math.ceil(Math.log2(keyLength + 1));
    to.storeUint(length, lenLen);
}

function writeLabel(src: string, keyLength: number, to: Builder): void {
    const type = detectLabelType(src, keyLength);
    if (type === 'short') {
        writeLabelShort(src, to);
    } else if (type === 'long') {
        writeLabelLong(src, keyLength, to);
    } else if (type === 'same') {
        writeLabelSame(src[0] === '1', src.length, keyLength, to);
    }
}

function writeNode<T>(
    src: Node<T>,
    keyLength: number,
    serializer: (src: T, cell: Builder) => void,
    to: Builder,
): void {
    if (src.type === 'leaf') {
        serializer(src.value, to);
    }
    if (src.type === 'fork') {
        const leftCell = beginCell();
        const rightCell = beginCell();
        writeEdge(src.left, keyLength - 1, serializer, leftCell);
        writeEdge(src.right, keyLength - 1, serializer, rightCell);
        to.storeRef(leftCell);
        to.storeRef(rightCell);
    }
}

function writeEdge<T>(
    src: Edge<T>,
    keyLength: number,
    serializer: (src: T, cell: Builder) => void,
    to: Builder,
): void {
    writeLabel(src.label, keyLength, to);
    writeNode(src.node, keyLength - src.label.length, serializer, to);
}

export function serializeDict<T>(
    src: Map<bigint, T>,
    keyLength: number,
    serializer: (src: T, cell: Builder) => void,
    to: Builder,
): void {
    const tree = buildTree<T>(src, keyLength);
    writeEdge(tree, keyLength, serializer, to);
}
