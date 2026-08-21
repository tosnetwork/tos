/**
 * Deterministic Domain Item identity, mirroring the on-chain derivation in
 * tosnetwork/dns-contract nft-collection.fc:
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
import { sha256 } from '@noble/hashes/sha256';
import { Builder, Cell, bytesToHex } from './cell.js';
import { RawAddress, storeAddress } from './address.js';
import { labelContractError, utf8 } from './name.js';

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

const MAX_SLICE_HASH_BYTES = 127;

export function itemIndex(label: string): bigint {
  return BigInt('0x' + bytesToHex(labelSliceHash(label)));
}

export interface CollectionConfig {
  /** deployed .tos Collection address (deployment configuration, not derived) */
  collection: RawAddress;
  /** pinned Domain Item code cell hash (reproducible-build record) */
  itemCodeHash: Uint8Array;
  /** depth of the pinned item code cell */
  itemCodeDepth: number;
  /** workchain items are deployed in; the contracts pin workchain 0 */
  itemWorkchain?: number;
}

export function itemStateInit(config: CollectionConfig, label: string): Cell {
  const err = labelContractError(label);
  if (err) {
    throw new Error(`invalid label: ${err}`);
  }
  const data = new Builder()
    .storeUint(itemIndex(label), 256);
  storeAddress(data, config.collection);
  const code = Cell.external(config.itemCodeHash, config.itemCodeDepth);
  return new Builder()
    .storeBits('00110') // no split_depth, not special, has code, has data, no libs
    .storeRef(code)
    .storeRef(data.endCell())
    .endCell();
}

export function deriveItemAddress(config: CollectionConfig, label: string): RawAddress {
  return {
    workchain: config.itemWorkchain ?? 0,
    hash: itemStateInit(config, label).hash(),
  };
}
