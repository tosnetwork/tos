/**
 * Fail-closed multi-hop dnsresolve driver (DNS.md §5.5, §8). The transport
 * is injected: the runner executes one `dnsresolve` get-method call against
 * one resolver and returns the raw (used_bits, value) answer. Every check
 * fails closed, the hop budget is uniform, and the structured outcome names
 * its provenance class honestly.
 */
import { Address, Cell } from '@tos/core';
import { encodeName } from './name';
import { parseDnsRecord } from './records';

/** Uniform resolver hop budget shared by every TOS client. */
export const MAX_RESOLVER_HOPS = 8;

export interface DnsHopResult {
    /** consumed-bit count returned by dnsresolve */
    usedBits: number;
    /** the record cell, or null */
    value: Cell | null;
}

export type DnsHopOutcome =
    | { kind: 'not-found' }
    | { kind: 'terminal'; value: Cell | null }
    | { kind: 'continue'; nextResolver: Address; remaining: Uint8Array };

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
export function validateHop(query: Uint8Array, hop: DnsHopResult, hopsLeft: number): DnsHopOutcome {
    if (hop.usedBits <= 0) {
        return { kind: 'not-found' };
    }
    if (hop.usedBits % 8 !== 0) {
        throw new Error(`consumed-bit count ${hop.usedBits} is not byte aligned`);
    }
    if (hop.usedBits > 8 * query.length) {
        throw new Error(`resolver claims ${hop.usedBits} bits of an ${8 * query.length}-bit query`);
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
    const record = parseDnsRecord(hop.value);
    if (record.type !== 'dns_next_resolver') {
        throw new Error(
            `partially resolved answer carries ${record.type}, not dns_next_resolver: failing closed`,
        );
    }
    if (hopsLeft <= 1) {
        throw new Error(
            `resolver hop limit (${MAX_RESOLVER_HOPS}) exhausted; ` +
                `next resolver would be ${record.resolver.toRawString()}`,
        );
    }
    return {
        kind: 'continue',
        nextResolver: record.resolver,
        remaining: query.subarray(pos),
    };
}

/** Executes one dnsresolve get-method call against one resolver. */
export type DnsResolveRunner = (
    resolver: Address,
    encodedQuery: Uint8Array,
    category: bigint,
) => Promise<DnsHopResult>;

export interface DnsResolveOutcome {
    found: boolean;
    value: Cell | null;
    /** every resolver contacted, root first */
    resolverPath: Address[];
    hops: number;
    /**
     * Assurance actually provided (DNS.md §8.1). A plain JSON-RPC get-method
     * caller only gets "evaluated": the method ran against a named state,
     * with no proof that state is genuine.
     */
    provenanceClass: 'evaluated';
}

/**
 * Resolve a dotted name from the given root with the uniform hop budget.
 * The caller is responsible for pinning every runner call to one finalized
 * checkpoint where the transport supports it.
 */
export async function resolveName(
    runner: DnsResolveRunner,
    root: Address,
    name: string,
    category: bigint,
): Promise<DnsResolveOutcome> {
    let query = encodeName(name);
    let resolver = root;
    const resolverPath: Address[] = [];
    for (let hopsLeft = MAX_RESOLVER_HOPS; hopsLeft > 0; hopsLeft--) {
        resolverPath.push(resolver);
        const hop = await runner(resolver, query, category);
        const outcome = validateHop(query, hop, hopsLeft);
        if (outcome.kind === 'not-found') {
            return {
                found: false,
                value: null,
                resolverPath,
                hops: resolverPath.length,
                provenanceClass: 'evaluated',
            };
        }
        if (outcome.kind === 'terminal') {
            return {
                found: outcome.value !== null,
                value: outcome.value,
                resolverPath,
                hops: resolverPath.length,
                provenanceClass: 'evaluated',
            };
        }
        resolver = outcome.nextResolver;
        query = outcome.remaining;
    }
    // unreachable: validateHop throws on exhaustion before the loop ends
    throw new Error(`resolver hop limit (${MAX_RESOLVER_HOPS}) exhausted`);
}
