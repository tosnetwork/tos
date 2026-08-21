import { describe, expect, it } from "vitest";
import { Address, beginCell, bytesToHex, Cell, hexToBytes } from "@tos/core";
import {
  AUCTION_START_DURATION,
  bidBody,
  canonicalizeName,
  CATEGORY_DNS_NEXT_RESOLVER,
  CATEGORY_WALLET,
  changeRecordBody,
  classifyDomain,
  decodeName,
  deriveItemAddress,
  encodeName,
  finishAuctionBody,
  initialAuctionDuration,
  itemIndex,
  labelContractError,
  labelSliceHash,
  labelUiWarnings,
  makeAdnlAddressRecord,
  makeNextResolverRecord,
  makeSmcAddressRecord,
  makeStorageAddressRecord,
  MAX_RESOLVER_HOPS,
  minimumNextBid,
  minPrice,
  ONE_TOS,
  OP_CHANGE_DNS_RECORD,
  OP_GET_STATIC_DATA,
  parseDnsRecord,
  parseDnsRecordForCategory,
  prolongedEndTime,
  registerBody,
  resolveName,
  transferBody,
  validateHop,
  type DnsCollectionConfig,
  type DnsHopResult,
} from "./index.js";

// Ground truth from crypto/smartcont/dns/deploy/gen-vectors.fif (the fift
// toolchain against the compiled .tos contracts); regenerate after any
// contract or tos-config.fc change.
const VECTORS = {
  auctionStartTime: 1735689600,
  itemCodeHash: "501f3036d7b892f6b35113addb8f0c271d9e50b581199600b9baf6b04e2de8fb",
  itemCodeDepth: 11,
  collectionAddress: "0:9af984dec57312139ca31cf499aaeb8fddd7f323442fd7ea41fd4bc68025a27f",
  aliceSliceHash: "56121e387810a23e51711d37fbb3241ee8ea09af40a72d0a1b37985af8af1d08",
  alicePlainSha256: "2bd806c97f0e00af1a1fc3328fa763a9269723c8db8fac4f93af71db186d6e90",
  aliceItemAddress: "0:7f4832987201ad76f96f8aaf9da1f14eff201e7526100937d10468ad5f8ab427",
  categoryDnsNextResolver: "19f02441ee588fdb26ee24b2568dd035c3c9206e11ab979be62e55558a1d17ff",
};

const CONFIG: DnsCollectionConfig = {
  collection: Address.parseRaw(VECTORS.collectionAddress),
  itemCodeHash: hexToBytes(VECTORS.itemCodeHash),
  itemCodeDepth: VECTORS.itemCodeDepth,
};

const utf8 = (s: string) => new TextEncoder().encode(s);

describe("name encoding", () => {
  it("encodes in reverse zero-delimited form", () => {
    expect(encodeName("alice.tos")).toEqual(utf8("tos\0alice\0"));
    expect(encodeName("translate.alice.tos")).toEqual(utf8("tos\0alice\0translate\0"));
  });

  it("round-trips through decodeName", () => {
    expect(decodeName(encodeName("translate.alice.tos"))).toBe("translate.alice.tos");
  });

  it("accepts a 126-byte dotted name and rejects 127", () => {
    const label126 = "ab.".repeat(40) + "cd.tos"; // 126 bytes dotted
    expect(encodeName(label126).length).toBe(127);
    const label127 = "ab.".repeat(40) + "cde.tos";
    expect(() => encodeName(label127)).toThrow(/at most 126 resolve/);
  });

  it("rejects trailing dots and empty labels instead of repairing them", () => {
    expect(() => canonicalizeName("alice.tos.")).toThrow(/trailing dot/);
    expect(() => canonicalizeName("alice..tos")).toThrow(/empty label/);
  });

  it("reports case folding as a repair", () => {
    expect(canonicalizeName("Alice.tos").caseFolded).toBe(true);
    expect(canonicalizeName("alice.tos").caseFolded).toBe(false);
  });
});

describe("label rules", () => {
  it("enforces the exact contract rule", () => {
    expect(labelContractError("alice")).toBeNull();
    expect(labelContractError("ali-ce")).toBeNull();
    expect(labelContractError("bob")).toMatch(/at least 4/);
    expect(labelContractError("-alice")).toMatch(/hyphen/);
    expect(labelContractError("alice-")).toMatch(/hyphen/);
    expect(labelContractError("aLice")).toMatch(/outside lowercase/);
    expect(labelContractError("a".repeat(127))).toMatch(/at most 126/);
  });

  it("separates UI policy from the contract rule", () => {
    expect(labelContractError("xn--test")).toBeNull();
    expect(labelUiWarnings("xn--test")).toContain("xn-- punycode prefix: potential homograph");
    expect(labelUiWarnings("a--b")).toContain("consecutive hyphens");
  });
});

describe("item identity", () => {
  it("computes slice_hash (TVM HASHSU), not plain sha256", () => {
    expect(bytesToHex(labelSliceHash("alice"))).toBe(VECTORS.aliceSliceHash);
    expect(VECTORS.aliceSliceHash).not.toBe(VECTORS.alicePlainSha256);
    expect(itemIndex("alice")).toBe(BigInt("0x" + VECTORS.aliceSliceHash));
  });

  it("derives the item address byte-exactly against the fift ground truth", () => {
    const derived = deriveItemAddress(CONFIG, "alice");
    expect(derived.toRawString()).toBe(VECTORS.aliceItemAddress);
  });

  it("rejects contract-invalid labels before deriving", () => {
    expect(() => deriveItemAddress(CONFIG, "-alice")).toThrow(/hyphen/);
  });
});

describe("categories", () => {
  it("matches the pinned dns_next_resolver hash", () => {
    expect(CATEGORY_DNS_NEXT_RESOLVER).toBe(BigInt("0x" + VECTORS.categoryDnsNextResolver));
  });
});

describe("auction arithmetic", () => {
  const t0 = VECTORS.auctionStartTime;

  it("prices by tier with 10% monthly floor decay", () => {
    expect(minPrice(5, t0 + 1, t0)).toBe(500n * ONE_TOS);
    expect(minPrice(5, t0 + 2_592_000, t0)).toBe(450n * ONE_TOS);
    expect(minPrice(5, t0 + 22 * 2_592_000, t0)).toBe(50n * ONE_TOS);
  });

  it("requires a 105% replacement bid inclusively", () => {
    const current = 1_000n * ONE_TOS;
    const threshold = minimumNextBid(current);
    expect(threshold).toBe(1_050n * ONE_TOS);
    // acceptance is >= threshold: exactly 105% wins
    expect(threshold >= minimumNextBid(current)).toBe(true);
  });

  it("ramps the first-auction duration from 7 days to 1 hour", () => {
    expect(initialAuctionDuration(t0 + 1, t0)).toBe(AUCTION_START_DURATION);
    expect(initialAuctionDuration(t0 + 13 * 2_592_000, t0)).toBe(3600);
    expect(() => initialAuctionDuration(t0, t0)).toThrow(/not launched/);
  });

  it("extends a sniped auction to leave one hour", () => {
    expect(prolongedEndTime(1000, 500)).toBe(1000 + 3600 - 500);
    expect(prolongedEndTime(10_000, 500)).toBe(10_000);
  });

  it("classifies the lifecycle fail-closed", () => {
    const auction = { maxBidAddress: "0:00", maxBidAmount: 1n, auctionEndTime: 2000 };
    expect(classifyDomain(auction, 0, 1000).state).toBe("auction");
    expect(classifyDomain(auction, 0, 3000).state).toBe("auction-ended-unfinalized");
    expect(classifyDomain(null, 1000, 1000 + 31_622_400).state).toBe("leased");
    expect(classifyDomain(null, 1000, 1000 + 31_622_401).state).toBe("releasable");
    expect(classifyDomain(auction, 0, 1000).safeToResolve).toBe(false);
    expect(classifyDomain(null, 1000, 2000).safeToResolve).toBe(true);
  });
});

describe("message bodies", () => {
  it("builds an op-0 comment registration", () => {
    const s = registerBody("alice").beginParse();
    expect(s.loadUint(32)).toBe(0);
    expect(new TextDecoder().decode(s.loadBuffer(5))).toBe("alice");
    expect(s.remainingBits).toBe(0);
    expect(s.remainingRefs).toBe(0);
  });

  it("continues a long label in a single ref", () => {
    const label = "a".repeat(126);
    const s = registerBody(label).beginParse();
    s.loadUint(32);
    expect(new TextDecoder().decode(s.loadBuffer(123))).toBe("a".repeat(123));
    const tail = s.loadRef().beginParse();
    expect(new TextDecoder().decode(tail.loadBuffer(3))).toBe("aaa");
  });

  it("builds bid, finish, and record bodies with the inherited ops", () => {
    expect(bidBody().bits.length).toBe(0);
    const finish = finishAuctionBody(7n).beginParse();
    expect(finish.loadUint(32)).toBe(OP_GET_STATIC_DATA);
    expect(finish.loadUintBig(64)).toBe(7n);

    const set = changeRecordBody(CATEGORY_WALLET, beginCell().endCell()).beginParse();
    expect(set.loadUint(32)).toBe(OP_CHANGE_DNS_RECORD);
    set.loadUintBig(64);
    expect(set.loadUintBig(256)).toBe(CATEGORY_WALLET);
    expect(set.remainingRefs).toBe(1);

    const del = changeRecordBody(CATEGORY_WALLET, null).beginParse();
    del.loadUint(32);
    del.loadUintBig(64);
    del.loadUintBig(256);
    expect(del.remainingRefs).toBe(0);
  });

  it("round-trips a transfer body", () => {
    const owner = Address.parseRaw(VECTORS.aliceItemAddress);
    const resp = Address.parseRaw(VECTORS.collectionAddress);
    const s = transferBody(owner, resp, 5n, 9n).beginParse();
    s.loadUint(32);
    expect(s.loadUintBig(64)).toBe(9n);
    expect((s.loadAddress() as Address).equals(owner)).toBe(true);
    expect((s.loadAddress() as Address).equals(resp)).toBe(true);
    expect(s.loadBit()).toBe(false);
    expect(s.loadCoins()).toBe(5n);
  });
});

describe("record codecs", () => {
  const addr = Address.parseRaw(VECTORS.collectionAddress);

  it("round-trips every record type", () => {
    const smc = parseDnsRecord(makeSmcAddressRecord(addr));
    expect(smc.type).toBe("dns_smc_address");

    const next = parseDnsRecord(makeNextResolverRecord(addr));
    expect(next.type).toBe("dns_next_resolver");

    const adnl = parseDnsRecord(makeAdnlAddressRecord(new Uint8Array(32).fill(7)));
    expect(adnl.type === "dns_adnl_address" && adnl.adnl).toBe("07".repeat(32));

    const bag = parseDnsRecord(makeStorageAddressRecord(new Uint8Array(32).fill(9)));
    expect(bag.type).toBe("dns_storage_address");
  });

  it("fails closed on unknown tags and category mismatches", () => {
    const bogus = beginCell().storeUint(0xdead, 16).endCell();
    expect(() => parseDnsRecord(bogus)).toThrow(/unknown DNSRecord tag/);
    expect(() => parseDnsRecordForCategory(makeNextResolverRecord(addr), CATEGORY_WALLET)).toThrow(
      /does not match/,
    );
    expect(() => parseDnsRecordForCategory(makeSmcAddressRecord(addr), 123n)).toThrow(
      /unknown category/,
    );
  });
});

describe("hop validation and resolution", () => {
  const query = encodeName("alice.tos"); // "tos\0alice\0" — 10 bytes
  const resolver = Address.parseRaw(VECTORS.collectionAddress);

  it("treats used_bits <= 0 as not found", () => {
    expect(validateHop(query, { usedBits: 0, value: null }, 8).kind).toBe("not-found");
  });

  it("rejects misaligned and over-claimed answers", () => {
    expect(() => validateHop(query, { usedBits: 13, value: null }, 8)).toThrow(/byte aligned/);
    expect(() => validateHop(query, { usedBits: 8 * 11, value: null }, 8)).toThrow(/claims/);
  });

  it("rejects a split that is not at a component boundary", () => {
    // 2 bytes consumed: "to|s\0alice\0" — neither side of the cut is NUL
    expect(() => validateHop(query, { usedBits: 16, value: null }, 8)).toThrow(
      /component boundary/,
    );
  });

  it("requires partial answers to be next-resolver records", () => {
    const wrong = makeSmcAddressRecord(resolver);
    expect(() => validateHop(query, { usedBits: 32, value: wrong }, 8)).toThrow(/failing closed/);
  });

  it("reports hop exhaustion distinctly from not-found", () => {
    const next = makeNextResolverRecord(resolver);
    expect(() => validateHop(query, { usedBits: 32, value: next }, 1)).toThrow(/hop limit/);
  });

  it("resolves a two-hop chain with full provenance", async () => {
    const itemAddr = Address.parseRaw(VECTORS.aliceItemAddress);
    const record = makeSmcAddressRecord(resolver);
    const runner = async (target: Address, q: Uint8Array): Promise<DnsHopResult> => {
      if (q.length === 10) {
        // root consumes "tos\0" and delegates to the collection... here the
        // fake delegates straight to the item for a two-hop chain
        return { usedBits: 32, value: makeNextResolverRecord(itemAddr) };
      }
      expect(target.equals(itemAddr)).toBe(true);
      return { usedBits: 8 * q.length, value: record };
    };
    const outcome = await resolveName(runner, resolver, "alice.tos", CATEGORY_WALLET);
    expect(outcome.found).toBe(true);
    expect((outcome.value as Cell).equals(record)).toBe(true);
    expect(outcome.hops).toBe(2);
    expect(outcome.resolverPath.map((a) => a.toRawString())).toEqual([
      resolver.toRawString(),
      itemAddr.toRawString(),
    ]);
    expect(outcome.provenanceClass).toBe("evaluated");
    expect(MAX_RESOLVER_HOPS).toBe(8);
  });
});
