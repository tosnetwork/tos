/**
 * DNSRecord codecs (TL-B tags from crypto/block/block.tlb) with the strict
 * category-to-record-type check of DNS.md §7: a record whose tag is not the
 * one assigned to the requested category fails closed.
 */
import { Address, beginCell, bytesToHex, Cell, Slice } from '@tos/core';
import { CATEGORY_RECORD_TYPES, DnsRecordType } from './categories';

export const TAG_DNS_TEXT = 0x1eda;
export const TAG_DNS_NEXT_RESOLVER = 0xba93;
export const TAG_DNS_ADNL_ADDRESS = 0xad01;
export const TAG_DNS_SMC_ADDRESS = 0x9fd3;
export const TAG_DNS_STORAGE_ADDRESS = 0x7473;

export function makeSmcAddressRecord(addr: Address): Cell {
    return beginCell()
        .storeUint(TAG_DNS_SMC_ADDRESS, 16)
        .storeAddress(addr)
        .storeUint(0, 8) // flags: no capability list
        .endCell();
}

export function makeNextResolverRecord(resolver: Address): Cell {
    return beginCell().storeUint(TAG_DNS_NEXT_RESOLVER, 16).storeAddress(resolver).endCell();
}

export function makeAdnlAddressRecord(adnl: Uint8Array): Cell {
    if (adnl.length !== 32) {
        throw new Error('ADNL address must be 32 bytes');
    }
    return beginCell()
        .storeUint(TAG_DNS_ADNL_ADDRESS, 16)
        .storeBuffer(adnl)
        .storeUint(0, 8) // flags: no protocol list
        .endCell();
}

export function makeStorageAddressRecord(bagId: Uint8Array): Cell {
    if (bagId.length !== 32) {
        throw new Error('storage bag id must be 32 bytes');
    }
    return beginCell().storeUint(TAG_DNS_STORAGE_ADDRESS, 16).storeBuffer(bagId).endCell();
}

export type ParsedDnsRecord =
    | { type: 'dns_smc_address'; address: Address }
    | { type: 'dns_next_resolver'; resolver: Address }
    | { type: 'dns_adnl_address'; adnl: string }
    | { type: 'dns_storage_address'; bagId: string }
    | { type: 'dns_text' };

/** Decode one DNSRecord cell, failing closed on unknown tags. */
export function parseDnsRecord(cell: Cell): ParsedDnsRecord {
    const s = cell.beginParse();
    if (s.remainingBits < 16) {
        throw new Error('record too short for a TL-B tag');
    }
    const tag = s.loadUint(16);
    switch (tag) {
        case TAG_DNS_SMC_ADDRESS: {
            const address = s.loadAddress();
            readFlagList(s);
            requireExhausted(s);
            return { type: 'dns_smc_address', address };
        }
        case TAG_DNS_NEXT_RESOLVER: {
            const resolver = s.loadAddress();
            requireExhausted(s);
            return { type: 'dns_next_resolver', resolver };
        }
        case TAG_DNS_ADNL_ADDRESS: {
            const adnl = bytesToHex(s.loadBuffer(32));
            readFlagList(s);
            requireExhausted(s);
            return { type: 'dns_adnl_address', adnl };
        }
        case TAG_DNS_STORAGE_ADDRESS: {
            const bagId = bytesToHex(s.loadBuffer(32));
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
export function parseDnsRecordForCategory(cell: Cell, category: bigint): ParsedDnsRecord {
    const record = parseDnsRecord(cell);
    const expected: DnsRecordType | undefined = CATEGORY_RECORD_TYPES.get(category);
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
    const flags = s.loadUint(8);
    if (flags > 1) {
        throw new Error('invalid record flags');
    }
    if (flags & 1) {
        // capability/protocol list present: tolerated but not interpreted
        s.skip(s.remainingBits);
    }
}

function requireExhausted(s: Slice): void {
    if (s.remainingBits !== 0) {
        throw new Error('trailing data after DNSRecord: failing closed');
    }
}
