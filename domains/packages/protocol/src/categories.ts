/**
 * DNS record categories: sha256 of the UTF-8 category name. Category zero is
 * not a category — it requests the complete record dictionary.
 */
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from './cell.js';
import { utf8 } from './name.js';

export function categoryHash(name: string): bigint {
  return BigInt('0x' + bytesToHex(sha256(utf8(name))));
}

export const CATEGORY_ALL = 0n;

/** Pinned in TOS code (contracts and rldp-http-proxy). */
export const CATEGORY_DNS_NEXT_RESOLVER = categoryHash('dns_next_resolver');
export const CATEGORY_SITE = categoryHash('site');

/** Proposed by the TOS DNS design; hashes frozen by the TIP corpus. */
export const CATEGORY_WALLET = categoryHash('wallet');
export const CATEGORY_AGENT = categoryHash('agent');
export const CATEGORY_CAPABILITY = categoryHash('capability');
export const CATEGORY_MESSENGER = categoryHash('messenger');
export const CATEGORY_STORAGE = categoryHash('storage');
export const CATEGORY_TEXT = categoryHash('text');

export type RecordType =
  | 'dns_smc_address'
  | 'dns_adnl_address'
  | 'dns_storage_address'
  | 'dns_next_resolver'
  | 'dns_text';

/**
 * Strict category-to-record-type table (DNS.md §7): a record whose TL-B tag
 * differs from the type assigned to the requested category fails closed.
 */
export const CATEGORY_RECORD_TYPES: ReadonlyMap<bigint, RecordType> = new Map<bigint, RecordType>([
  [CATEGORY_DNS_NEXT_RESOLVER, 'dns_next_resolver'],
  [CATEGORY_SITE, 'dns_adnl_address'],
  [CATEGORY_WALLET, 'dns_smc_address'],
  [CATEGORY_AGENT, 'dns_smc_address'],
  [CATEGORY_CAPABILITY, 'dns_smc_address'],
  [CATEGORY_MESSENGER, 'dns_smc_address'],
  [CATEGORY_STORAGE, 'dns_storage_address'],
  [CATEGORY_TEXT, 'dns_text'],
]);
