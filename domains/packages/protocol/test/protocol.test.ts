import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  AUCTION_END_DURATION,
  AUCTION_START_DURATION,
  Builder,
  CATEGORY_DNS_NEXT_RESOLVER,
  CATEGORY_WALLET,
  MAX_RESOLVER_HOPS,
  ONE_MONTH,
  ONE_TOS,
  ONE_YEAR,
  bytesToHex,
  canonicalizeName,
  classifyDomain,
  decodeName,
  deriveItemAddress,
  encodeName,
  finishAuctionBody,
  formatRawAddress,
  hexToBytes,
  initialAuctionDuration,
  itemIndex,
  labelContractError,
  labelSliceHash,
  labelUiWarnings,
  makeNextResolverRecord,
  makeSmcAddressRecord,
  minPrice,
  minimumNextBid,
  outbidRefund,
  parseBoc,
  parseRawAddress,
  parseRecordForCategory,
  prolongedEndTime,
  registerBody,
  validateHop,
} from '../src/index.js';

const vectors = JSON.parse(
  readFileSync(fileURLToPath(new URL('./vectors.json', import.meta.url)), 'utf8'),
);

describe('name encoding (DNS.md §4.2)', () => {
  it('encodes reverse zero-delimited', () => {
    const enc = encodeName('translate.alice.tos');
    expect(new TextDecoder().decode(enc)).toBe('tos\0alice\0translate\0');
    expect(enc.length).toBe(20); // dotted length + 1
  });

  it('round-trips', () => {
    expect(decodeName(encodeName('translate.alice.tos'))).toBe('translate.alice.tos');
  });

  it('encoded length is dotted length + 1 regardless of label count', () => {
    const twoLabels = 'a'.repeat(122) + '.tos'; // 126 dotted bytes, 2 labels
    const manyLabels = 'ab.'.repeat(40) + 'cd.tos'; // 126 dotted bytes, 42 labels
    expect(encodeName(twoLabels).length).toBe(127);
    expect(new TextEncoder().encode(manyLabels).length).toBe(126);
    expect(encodeName(manyLabels).length).toBe(127);
  });

  it('rejects a 127-byte dotted name', () => {
    const over = 'a'.repeat(123) + '.tos';
    expect(() => encodeName(over)).toThrow(/126/);
  });

  it('rejects trailing dots, empty labels, and forbidden characters', () => {
    expect(() => canonicalizeName('alice.tos.')).toThrow(/trailing dot/);
    expect(() => canonicalizeName('a..tos')).toThrow(/empty label/);
    expect(() => canonicalizeName('.')).toThrow();
    expect(() => canonicalizeName('a b.tos')).toThrow(/forbidden/);
    expect(() => canonicalizeName('a/b.tos')).toThrow(/forbidden/);
  });

  it('case-folds for lookup only, and reports it', () => {
    const c = canonicalizeName('Alice.TOS');
    expect(c.name).toBe('alice.tos');
    expect(c.caseFolded).toBe(true);
  });
});

describe('contract label rule vs UI policy (DNS.md §4.1)', () => {
  it('enforces the exact check_domain_string rule', () => {
    expect(labelContractError('alice')).toBeNull();
    expect(labelContractError('a-b-c')).toBeNull();
    expect(labelContractError('a--b')).toBeNull(); // consecutive interior hyphens register
    expect(labelContractError('xn--80ak6aa92e')).toBeNull(); // xn-- registers
    expect(labelContractError('abc')).toMatch(/at least 4/);
    expect(labelContractError('a'.repeat(127))).toMatch(/at most 126/);
    expect(labelContractError('-abc')).toMatch(/hyphen/); // error 203
    expect(labelContractError('abc-')).toMatch(/hyphen/);
    expect(labelContractError('Alice')).toMatch(/outside/);
    expect(labelContractError('älice')).toMatch(/outside/);
  });

  it('warns without blocking on risky-but-valid labels', () => {
    expect(labelUiWarnings('xn--80ak6aa92e')).toContain('xn-- punycode prefix: potential homograph');
    expect(labelUiWarnings('a--b')).toContain('consecutive hyphens');
    expect(labelUiWarnings('a'.repeat(64)).length).toBeGreaterThan(0);
    expect(labelUiWarnings('alice')).toEqual([]);
  });
});

describe('item identity (DNS.md §5.2) against fift ground truth', () => {
  it('slice_hash matches TVM HASHSU and differs from plain sha256', () => {
    expect(bytesToHex(labelSliceHash('alice'))).toBe(vectors.alice_slice_hash);
    expect(vectors.alice_slice_hash).not.toBe(vectors.alice_plain_sha256);
  });

  it('derives the Domain Item address byte-for-byte', () => {
    const addr = deriveItemAddress(
      {
        collection: parseRawAddress(vectors.collection_address),
        itemCodeHash: hexToBytes(vectors.item_code_hash),
        itemCodeDepth: vectors.item_code_depth,
      },
      'alice',
    );
    expect(formatRawAddress(addr)).toBe(vectors.alice_item_address);
  });

  it('item index is the big-endian integer of the slice hash', () => {
    expect(itemIndex('alice').toString(16)).toBe(vectors.alice_slice_hash.replace(/^0+/, ''));
  });
});

describe('category hashes (DNS.md §7)', () => {
  it('reproduces the code-pinned dns_next_resolver constant', () => {
    expect(CATEGORY_DNS_NEXT_RESOLVER.toString(16)).toBe(
      vectors.category_dns_next_resolver.replace(/^0+/, ''),
    );
  });
});

describe('auction arithmetic (DNS.md §6) mirroring the FunC source', () => {
  const start = vectors.auction_start_time as number;

  it('minimum price tiers and 21-month decay', () => {
    expect(minPrice(5, start + 1, start)).toBe(500n * ONE_TOS);
    // one elapsed month: floor(500e9 * 90 / 100)
    expect(minPrice(5, start + ONE_MONTH, start)).toBe((500n * ONE_TOS * 90n) / 100n);
    // beyond 21 months: flat end tier
    expect(minPrice(5, start + 22 * ONE_MONTH, start)).toBe(50n * ONE_TOS);
    expect(minPrice(11, start + 1, start)).toBe(10n * ONE_TOS);
  });

  it('duration ramp: 7 days to 1 hour in twelve 30-day steps', () => {
    expect(initialAuctionDuration(start + 1, start)).toBe(AUCTION_START_DURATION);
    expect(initialAuctionDuration(start + ONE_MONTH, start)).toBe(604800 - 50100);
    expect(initialAuctionDuration(start + 12 * ONE_MONTH, start)).toBe(AUCTION_END_DURATION);
    expect(initialAuctionDuration(start + 100 * ONE_MONTH, start)).toBe(AUCTION_END_DURATION);
    expect(() => initialAuctionDuration(start, start)).toThrow(/not launched/);
  });

  it('105% threshold uses muldiv floor and inclusive comparison', () => {
    expect(minimumNextBid(100n * ONE_TOS)).toBe(105n * ONE_TOS);
    expect(minimumNextBid(1n)).toBe(1n); // floor(1*105/100) = 1
    expect(minimumNextBid(999n)).toBe(1048n);
  });

  it('anti-sniping extension leaves at least one hour', () => {
    const end = 1_000_000;
    expect(prolongedEndTime(end, end - 7200)).toBe(end); // >1h left: unchanged
    expect(prolongedEndTime(end, end - 60)).toBe(end - 60 + 3600);
  });

  it('outbid refund is capped by balance minus the storage reserve', () => {
    expect(outbidRefund(10n * ONE_TOS, 12n * ONE_TOS)).toBe(10n * ONE_TOS);
    expect(outbidRefund(10n * ONE_TOS, 10n * ONE_TOS + 1n)).toBe(9n * ONE_TOS + 1n);
    expect(outbidRefund(10n * ONE_TOS, ONE_TOS)).toBe(0n);
  });
});

describe('fail-closed lifecycle (DNS.md §6.5)', () => {
  const now = 2_000_000_000;

  it('active auction is never safe to resolve', () => {
    const c = classifyDomain(
      { maxBidAddress: '0:' + '11'.repeat(32), maxBidAmount: ONE_TOS, auctionEndTime: now + 100 },
      now - 10,
      now,
    );
    expect(c.state).toBe('auction');
    expect(c.safeToResolve).toBe(false);
  });

  it('ended-but-unfinalized auction is distinct from ownership', () => {
    const c = classifyDomain(
      { maxBidAddress: '0:' + '11'.repeat(32), maxBidAmount: ONE_TOS, auctionEndTime: now - 1 },
      now - 10,
      now,
    );
    expect(c.state).toBe('auction-ended-unfinalized');
    expect(c.safeToResolve).toBe(false);
  });

  it('strict 366-day boundary: exactly one year is still leased', () => {
    expect(classifyDomain(null, now - ONE_YEAR, now).state).toBe('leased');
    expect(classifyDomain(null, now - ONE_YEAR - 1, now).state).toBe('releasable');
    expect(classifyDomain(null, now - ONE_YEAR - 1, now).safeToResolve).toBe(false);
  });

  it('renewal deadline runs from last_fill_up_time', () => {
    const c = classifyDomain(null, now - 5, now);
    expect(c.renewalDeadline).toBe(now - 5 + ONE_YEAR);
  });
});

describe('message bodies (inherited ABI)', () => {
  it('registration is an op-0 comment with the plaintext label', () => {
    const body = registerBody('alice');
    const s = body.beginParse();
    expect(s.loadUint(32)).toBe(0n);
    expect(new TextDecoder().decode(s.loadBytes(5))).toBe('alice');
    expect(s.remainingBits).toBe(0);
  });

  it('long labels continue in a single ref', () => {
    const label = 'a'.repeat(126);
    const body = registerBody(label);
    const s = body.beginParse();
    s.loadUint(32);
    expect(s.remainingBits).toBe(123 * 8);
    const tail = body.beginParse();
    tail.loadUint(32);
    tail.loadBytes(123);
    expect(new TextDecoder().decode(tail.loadRef().beginParse().loadBytes(3))).toBe('aaa');
  });

  it('finish uses get_static_data with a query id and no other payload', () => {
    const s = finishAuctionBody(7n).beginParse();
    expect(Number(s.loadUint(32))).toBe(0x2fcb26a2);
    expect(s.loadUint(64)).toBe(7n);
    expect(s.remainingBits).toBe(0);
  });

  it('refuses to build a registration for a contract-invalid label', () => {
    expect(() => registerBody('-abc')).toThrow(/hyphen/);
  });
});

describe('record codecs and strict category checks (DNS.md §7)', () => {
  const addr = parseRawAddress('0:' + 'ab'.repeat(32));

  it('round-trips dns_smc_address under the wallet category', () => {
    const rec = parseRecordForCategory(makeSmcAddressRecord(addr), CATEGORY_WALLET);
    if (rec.type !== 'dns_smc_address') throw new Error('unreachable');
    expect(formatRawAddress(rec.address)).toBe(formatRawAddress(addr));
  });

  it('fails closed on a type mismatch', () => {
    expect(() =>
      parseRecordForCategory(makeNextResolverRecord(addr), CATEGORY_WALLET),
    ).toThrow(/does not match/);
  });

  it('fails closed on unknown categories and unknown tags', () => {
    expect(() => parseRecordForCategory(makeSmcAddressRecord(addr), 12345n)).toThrow(
      /unknown category/,
    );
    const bogus = new Builder().storeUint(0x1234, 16).endCell();
    expect(() => parseRecordForCategory(bogus, CATEGORY_WALLET)).toThrow(/unknown DNSRecord tag/);
  });
});

describe('hop validation (DNS.md §5.5, §8)', () => {
  const query = encodeName('translate.alice.tos'); // tos\0alice\0translate\0
  const resolver = parseRawAddress('0:' + 'cd'.repeat(32));

  it('accepts the worked root hop: 24 bits consumed before the separator', () => {
    const out = validateHop(query, { usedBits: 24, value: makeNextResolverRecord(resolver) }, 8);
    if (out.kind !== 'continue') throw new Error(out.kind);
    expect(new TextDecoder().decode(out.remaining)).toBe('\0alice\0translate\0');
  });

  it('accepts a hop that consumes the separator (inherited manual root)', () => {
    const out = validateHop(query, { usedBits: 32, value: makeNextResolverRecord(resolver) }, 8);
    if (out.kind !== 'continue') throw new Error(out.kind);
    expect(new TextDecoder().decode(out.remaining)).toBe('alice\0translate\0');
  });

  it('rejects a split inside a component', () => {
    expect(() =>
      validateHop(query, { usedBits: 16, value: makeNextResolverRecord(resolver) }, 8),
    ).toThrow(/component boundary/);
  });

  it('rejects misaligned and over-claimed counts', () => {
    expect(() => validateHop(query, { usedBits: 12, value: null }, 8)).toThrow(/byte aligned/);
    expect(() =>
      validateHop(query, { usedBits: 8 * query.length + 8, value: null }, 8),
    ).toThrow(/claims/);
  });

  it('fails closed when a partial answer is not a next resolver', () => {
    const wrong = makeSmcAddressRecord(resolver);
    expect(() => validateHop(query, { usedBits: 32, value: wrong }, 8)).toThrow(/failing closed/);
  });

  it('reports hop exhaustion distinctly from not-found', () => {
    expect(() =>
      validateHop(query, { usedBits: 32, value: makeNextResolverRecord(resolver) }, 1),
    ).toThrow(/hop limit/);
    expect(MAX_RESOLVER_HOPS).toBe(8);
  });

  it('terminal full consumption returns the value', () => {
    const out = validateHop(query, { usedBits: 8 * query.length, value: null }, 8);
    expect(out.kind).toBe('terminal');
  });
});

describe('BOC parsing', () => {
  it('parses a builder-composed cell serialized by fift (root code smoke)', () => {
    // d1=00 d2=0a "alice": the canonical slice-hash preimage as a BOC
    const cell = new Builder().storeBytes(new TextEncoder().encode('alice')).endCell();
    expect(bytesToHex(cell.hash())).toBe(vectors.alice_slice_hash);
  });

  it('rejects garbage', () => {
    expect(() => parseBoc(new Uint8Array([1, 2, 3]))).toThrow(/BOC/);
  });
});
