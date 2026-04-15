/**
 * @tos/core -- TOS Blockchain TypeScript SDK foundation layer.
 *
 * Compatible with the TON Cell/BOC binary format.
 * No Buffer dependency -- isomorphic with Uint8Array only.
 */

// ---- Types ----
export {
    CellType,
    SendMode,
    type StateInit,
    type Contract,
    type ExtraCurrency,
    type AddressInfo,
    type HashInfo,
    type Maybe,
} from './types';

// ---- Address ----
export { Address, address } from './address/Address';
export { ExternalAddress } from './address/ExternalAddress';
export {
    packAddress,
    unpackAddress,
    detectAddress,
    detectHash,
    contractAddress,
} from './address/utils';

// ---- BitString ----
export { BitString, bitsToPaddedBuffer, paddedBufferToBits } from './boc/BitString';
export { BitBuilder } from './boc/BitBuilder';
export { BitReader } from './boc/BitReader';

// ---- Cell / Builder / Slice ----
export { Cell, CellType as InternalCellType } from './boc/Cell';
export { Builder, beginCell } from './boc/Builder';
export { Slice } from './boc/Slice';

// ---- Dictionary ----
export {
    Dictionary,
    type DictionaryKey,
    type DictionaryKeyTypes,
    type DictionaryValue,
} from './dict/Dictionary';

// ---- Tuple ----
export {
    type TupleItem,
    type TupleItemNull,
    type TupleItemInt,
    type TupleItemNaN,
    type TupleItemCell,
    type TupleItemSlice,
    type TupleItemBuilder,
    type Tuple,
} from './tuple/TupleItem';
export { TupleReader } from './tuple/TupleReader';

// ---- Utilities ----
export { toNano, fromNano } from './utils/convert';
export { crc16, crc32c } from './utils/crc';
export { comment } from './utils/comment';
export {
    base64ToBytes,
    bytesToBase64,
    hexToBytes,
    bytesToHex,
    base64UrlToBytes,
    bytesToBase64Url,
    stringToBytes,
    bytesToString,
} from './utils/encoding';
export { sha256 } from './utils/sha256';
