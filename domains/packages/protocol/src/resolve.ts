/**
 * Transport-agnostic hop validation for the dnsresolve chain (DNS.md §5.5,
 * §8). The caller performs the actual get-method calls against one finalized
 * checkpoint; this module decides whether each answer is acceptable and what
 * the next hop is. Every check fails closed.
 */
import { Cell } from './cell.js';
import { RawAddress, formatRawAddress } from './address.js';
import { parseRecord } from './records.js';

/** Uniform resolver hop budget shared by every TOS client. */
export const MAX_RESOLVER_HOPS = 8;

export interface HopResult {
  /** consumed-bit count returned by dnsresolve */
  usedBits: number;
  /** the record cell, or null */
  value: Cell | null;
}

export type HopOutcome =
  | { kind: 'not-found' }
  | { kind: 'terminal'; value: Cell | null }
  | { kind: 'continue'; nextResolver: RawAddress; remaining: Uint8Array };

/**
 * Validate one dnsresolve answer for the encoded query slice `query`.
 *
 * Rules (all inherited-client compatible):
 *  - used_bits <= 0        -> not found;
 *  - used_bits % 8 != 0    -> malformed;
 *  - used_bits > 8*len     -> resolver claims more than it was given;
 *  - partial answers must stop at a component boundary and decode exactly as
 *    dns_next_resolver with a valid address;
 *  - hop budget exhaustion is a distinct error, never "not found".
 */
export function validateHop(query: Uint8Array, hop: HopResult, hopsLeft: number): HopOutcome {
  if (hop.usedBits <= 0) {
    return { kind: 'not-found' };
  }
  if (hop.usedBits % 8 !== 0) {
    throw new Error(`consumed-bit count ${hop.usedBits} is not byte aligned`);
  }
  if (hop.usedBits > 8 * query.length) {
    throw new Error(
      `resolver claims ${hop.usedBits} bits of an ${8 * query.length}-bit query`,
    );
  }
  const pos = hop.usedBits >> 3;
  if (pos === query.length) {
    return { kind: 'terminal', value: hop.value };
  }
  // partial resolution: must stop at a component boundary
  if (query[pos - 1] !== 0 && query[pos] !== 0) {
    throw new Error('domain split not at a component boundary');
  }
  if (hop.value === null) {
    return { kind: 'not-found' };
  }
  const record = parseRecord(hop.value);
  if (record.type !== 'dns_next_resolver') {
    throw new Error(
      `partially resolved answer carries ${record.type}, not dns_next_resolver: failing closed`,
    );
  }
  if (hopsLeft <= 1) {
    throw new Error(
      `resolver hop limit (${MAX_RESOLVER_HOPS}) exhausted; ` +
        `next resolver would be ${formatRawAddress(record.resolver)}`,
    );
  }
  return {
    kind: 'continue',
    nextResolver: record.resolver,
    remaining: query.subarray(pos),
  };
}
