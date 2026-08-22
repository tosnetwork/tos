/**
 * DNSRecord codecs (TL-B tags from tos/crypto/block/block.tlb) with the
 * strict category-to-record-type check of DNS.md §7: a record whose tag is
 * not the one assigned to the requested category fails closed.
 */
import { Builder, Cell, Slice, bytesToHex } from './cell.js';
import { RawAddress, loadAddress, storeAddress } from './address.js';
import { CATEGORY_RECORD_TYPES, RecordType } from './categories.js';

export const TAG_DNS_TEXT = 0x1eda;
export const TAG_DNS_NEXT_RESOLVER = 0xba93;
export const TAG_DNS_ADNL_ADDRESS = 0xad01;
export const TAG_DNS_SMC_ADDRESS = 0x9fd3;
export const TAG_DNS_STORAGE_ADDRESS = 0x7473;

export function makeSmcAddressRecord(addr: RawAddress): Cell {
  const b = new Builder().storeUint(TAG_DNS_SMC_ADDRESS, 16);
  storeAddress(b, addr);
  b.storeUint(0, 8); // flags: no capability list
  return b.endCell();
}

export function makeNextResolverRecord(resolver: RawAddress): Cell {
  const b = new Builder().storeUint(TAG_DNS_NEXT_RESOLVER, 16);
  storeAddress(b, resolver);
  return b.endCell();
}

export function makeAdnlAddressRecord(adnl: Uint8Array): Cell {
  if (adnl.length !== 32) {
    throw new Error('ADNL address must be 32 bytes');
  }
  return new Builder()
    .storeUint(TAG_DNS_ADNL_ADDRESS, 16)
    .storeBytes(adnl)
    .storeUint(0, 8) // flags: no protocol list
    .endCell();
}

export function makeStorageAddressRecord(bagId: Uint8Array): Cell {
  if (bagId.length !== 32) {
    throw new Error('storage bag id must be 32 bytes');
  }
  return new Builder().storeUint(TAG_DNS_STORAGE_ADDRESS, 16).storeBytes(bagId).endCell();
}

export type ParsedRecord =
  | { type: 'dns_smc_address'; address: RawAddress }
  | { type: 'dns_next_resolver'; resolver: RawAddress }
  | { type: 'dns_adnl_address'; adnl: string }
  | { type: 'dns_storage_address'; bagId: string }
  | { type: 'dns_text' };

/** Decode one DNSRecord cell, failing closed on unknown tags. */
export function parseRecord(cell: Cell): ParsedRecord {
  const s = cell.beginParse();
  if (s.remainingBits < 16) {
    throw new Error('record too short for a TL-B tag');
  }
  const tag = Number(s.loadUint(16));
  switch (tag) {
    case TAG_DNS_SMC_ADDRESS: {
      const address = loadAddress(s);
      readFlagList(s);
      requireExhausted(s);
      return { type: 'dns_smc_address', address };
    }
    case TAG_DNS_NEXT_RESOLVER: {
      const resolver = loadAddress(s);
      requireExhausted(s);
      return { type: 'dns_next_resolver', resolver };
    }
    case TAG_DNS_ADNL_ADDRESS: {
      const adnl = bytesToHex(s.loadBytes(32));
      readFlagList(s);
      requireExhausted(s);
      return { type: 'dns_adnl_address', adnl };
    }
    case TAG_DNS_STORAGE_ADDRESS: {
      const bagId = bytesToHex(s.loadBytes(32));
      requireExhausted(s);
      return { type: 'dns_storage_address', bagId };
    }
    case TAG_DNS_TEXT:
      // chunked Text payload: presentation-only, never authoritative;
      // the chunk contents are not interpreted here
      return { type: 'dns_text' };
    default:
      throw new Error(`unknown DNSRecord tag 0x${tag.toString(16)}: failing closed`);
  }
}

/**
 * Decode a record for a specific requested category, enforcing the strict
 * category-to-record-type table. Throws on any mismatch.
 */
export function parseRecordForCategory(cell: Cell, category: bigint): ParsedRecord {
  const record = parseRecord(cell);
  const expected: RecordType | undefined = CATEGORY_RECORD_TYPES.get(category);
  if (expected === undefined) {
    throw new Error('unknown category: failing closed');
  }
  if (record.type !== expected) {
    throw new Error(
      `record type ${record.type} does not match the ${expected} required by this category`,
    );
  }
  return record;
}

function readFlagList(s: Slice): void {
  const flags = Number(s.loadUint(8));
  if (flags > 1) {
    throw new Error('invalid record flags');
  }
  if (flags & 1) {
    // capability/protocol list present: tolerated but not interpreted
    while (s.remainingBits > 0) {
      s.loadBit();
    }
  }
}

function requireExhausted(s: Slice): void {
  if (s.remainingBits !== 0) {
    throw new Error('trailing data after DNSRecord: failing closed');
  }
}
