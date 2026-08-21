/**
 * Deterministic Domain Item identity, mirroring the on-chain derivation in
 * crypto/smartcont/dns/func/nft-collection.fc:
 *
 *   item_index = slice_hash(label)          ; TVM HASHSU: repr hash of the
 *                                           ; cell holding the label slice —
 *                                           ; NOT plain sha256(label)
 *   item_data  = uint256(index) || MsgAddressInt(collection)
 *   StateInit  = b{00110} ^code ^data
 *   address    = addr_std(workchain, cell_hash(StateInit))
 *
 * Clients derive this address locally and reject any collection response,
 * next-resolver record, indexer row, or gateway result naming a different
 * item (DNS.md §5.2). The network tuple is deliberately NOT an input:
 * mainnet/testnet separation comes from the collection address itself.
 */
import { Address, beginCell, bytesToHex, sha256 } from '@tos/core';
import { labelContractError, utf8 } from './name';

const MAX_SLICE_HASH_BYTES = 127;

/** slice_hash(label): repr hash of a refless, byte-aligned cell. */
export function labelSliceHash(label: string): Uint8Array {
    const bytes = utf8(label);
    if (bytes.length > MAX_SLICE_HASH_BYTES) {
        throw new Error('label too long for a single cell');
    }
    const repr = new Uint8Array(2 + bytes.length);
    repr[0] = 0; // d1: no refs, level 0
    repr[1] = bytes.length * 2; // d2 for byte-aligned data
    repr.set(bytes, 2);
    return sha256(repr);
}

export function itemIndex(label: string): bigint {
    return BigInt('0x' + bytesToHex(labelSliceHash(label)));
}

export interface DnsCollectionConfig {
    /** deployed .tos Collection address (deployment configuration, not derived) */
    collection: Address;
    /** pinned Domain Item code cell hash (reproducible-build record), 32 bytes */
    itemCodeHash: Uint8Array;
    /** depth of the pinned item code cell */
    itemCodeDepth: number;
    /** workchain items are deployed in; the contracts pin workchain 0 */
    itemWorkchain?: number;
}

/**
 * cell_hash(StateInit) computed from the pinned item code hash without the
 * code cell itself: repr hash = sha256(d1 ‖ d2 ‖ data-with-completion-tag ‖
 * ref depths (2-byte BE each) ‖ ref hashes).
 */
export function itemStateInitHash(config: DnsCollectionConfig, label: string): Uint8Array {
    const err = labelContractError(label);
    if (err) {
        throw new Error(`invalid label: ${err}`);
    }
    if (config.itemCodeHash.length !== 32) {
        throw new Error('item code hash must be 32 bytes');
    }
    const data = beginCell()
        .storeUint(itemIndex(label), 256)
        .storeAddress(config.collection)
        .endCell();
    const dataHash = data.hash();
    const dataDepth = data.depth();

    // StateInit: b{00110} (no split_depth, not special, has code, has data,
    // no libraries), refs [code, data]; d1 = 2 refs, d2 = 1 (5 bits rounds to
    // one byte), payload byte = 00110 + completion tag = 0x34.
    const repr = new Uint8Array(3 + 2 + 2 + 32 + 32);
    repr[0] = 2; // d1
    repr[1] = 1; // d2
    repr[2] = 0x34; // b{00110} + completion tag
    repr[3] = (config.itemCodeDepth >> 8) & 0xff;
    repr[4] = config.itemCodeDepth & 0xff;
    repr[5] = (dataDepth >> 8) & 0xff;
    repr[6] = dataDepth & 0xff;
    repr.set(config.itemCodeHash, 7);
    repr.set(dataHash, 39);
    return sha256(repr);
}

export function deriveItemAddress(config: DnsCollectionConfig, label: string): Address {
    return new Address(config.itemWorkchain ?? 0, itemStateInitHash(config, label));
}
