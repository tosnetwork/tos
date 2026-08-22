/**
 * Pure mirrors of the on-chain auction, renewal, and release arithmetic in
 * tosnetwork/dns-contract (nft-item.fc, dns-utils.fc). These reproduce the
 * contract's integer math exactly; they are projections for UX and safety
 * checks, never an authority. All amounts are in base units (1e9 = 1 TOS).
 */

export const ONE_MONTH = 2_592_000; // 30 days
export const ONE_YEAR = 31_622_400; // 366 days
export const AUCTION_START_DURATION = 604_800; // 7 days
export const AUCTION_END_DURATION = 3_600; // 1 hour
export const AUCTION_PROLONGATION = 3_600; // 1 hour
export const ONE_TOS = 1_000_000_000n;
export const MIN_STORAGE_RESERVE = ONE_TOS; // min_tons_for_storage()

/** get_min_price_config: (start, end) whole-token tiers by label byte length. */
export function minPriceTiers(labelByteLength: number): [bigint, bigint] {
  switch (labelByteLength) {
    case 4:
      return [1000n, 100n];
    case 5:
      return [500n, 50n];
    case 6:
      return [400n, 40n];
    case 7:
      return [300n, 30n];
    case 8:
      return [200n, 20n];
    case 9:
      return [100n, 10n];
    case 10:
      return [50n, 5n];
    default:
      return [10n, 1n];
  }
}

/**
 * get_min_price: tier start decayed by 10% per elapsed 30-day month, floor
 * division each step, flat at the end tier after 21 months.
 */
export function minPrice(labelByteLength: number, nowUnix: number, auctionStartTime: number): bigint {
  const [startTokens, endTokens] = minPriceTiers(labelByteLength);
  let start = startTokens * ONE_TOS;
  const end = endTokens * ONE_TOS;
  const months = Math.floor((nowUnix - auctionStartTime) / ONE_MONTH);
  if (months > 21) {
    return end;
  }
  for (let i = 0; i < months; i++) {
    start = (start * 90n) / 100n;
  }
  return start;
}

/**
 * First-auction duration: seven days falling to one hour in twelve 30-day
 * steps after launch (ramp complete after 360 days). Only the registration
 * auction ramps; a release re-auction is always seven days.
 */
export function initialAuctionDuration(nowUnix: number, auctionStartTime: number): number {
  if (nowUnix <= auctionStartTime) {
    throw new Error('auction has not launched (Collection error 199)');
  }
  let months = Math.floor((nowUnix - auctionStartTime) / ONE_MONTH);
  if (months > 12) {
    months = 12;
  }
  return (
    AUCTION_START_DURATION -
    Math.floor(((AUCTION_START_DURATION - AUCTION_END_DURATION) * months) / 12)
  );
}

/** muldiv(max_bid, 105, 100): the inclusive minimum for a replacement bid. */
export function minimumNextBid(currentMaxBid: bigint): bigint {
  return (currentMaxBid * 105n) / 100n;
}

/** Anti-sniping: a bid always leaves at least one hour on the clock. */
export function prolongedEndTime(auctionEndTime: number, nowUnix: number): number {
  const delta = AUCTION_PROLONGATION - (auctionEndTime - nowUnix);
  return delta > 0 ? auctionEndTime + delta : auctionEndTime;
}

/**
 * Outbid refund actually sent: min(previous max bid, balance minus the
 * storage reserve). The cap normally does not bind, but a client must not
 * assume the refund always equals the previous bid.
 */
export function outbidRefund(previousMaxBid: bigint, itemBalance: bigint): bigint {
  const cap = itemBalance - MIN_STORAGE_RESERVE;
  const amount = previousMaxBid > cap ? cap : previousMaxBid;
  return amount > 0n ? amount : 0n;
}

export interface AuctionInfo {
  maxBidAddress: string | null;
  maxBidAmount: bigint;
  auctionEndTime: number;
}

export interface DomainLifecycle {
  state: 'auction' | 'auction-ended-unfinalized' | 'leased' | 'releasable';
  /** true only when records may be trusted by security-sensitive consumers */
  safeToResolve: boolean;
  renewalDeadline: number | null;
  detail: string;
}

/**
 * Fail-closed lifecycle interpretation (DNS.md §6.5): the raw item retains
 * records while overdue or under auction, so wallets, gateways, Agent
 * software, and payment flows must derive the state from get_auction_info()
 * and get_last_fill_up_time() and refuse stale records.
 *
 * The renewal clock runs from the LAST BID of the winning auction, not from
 * the win: every accepted bid refreshes last_fill_up_time and finalization
 * preserves it.
 */
export function classifyDomain(
  auction: AuctionInfo | null,
  lastFillUpTime: number,
  nowUnix: number,
): DomainLifecycle {
  if (auction !== null) {
    if (nowUnix > auction.auctionEndTime) {
      return {
        state: 'auction-ended-unfinalized',
        safeToResolve: false,
        renewalDeadline: null,
        detail:
          'auction ended but no finalizing transaction has executed; ' +
          'ownership is not yet assigned on-chain',
      };
    }
    return {
      state: 'auction',
      safeToResolve: false,
      renewalDeadline: null,
      detail: 'auction in progress; any records belong to a previous lease',
    };
  }
  const deadline = lastFillUpTime + ONE_YEAR;
  if (nowUnix - lastFillUpTime > ONE_YEAR) {
    return {
      state: 'releasable',
      safeToResolve: false,
      renewalDeadline: deadline,
      detail: 'renewal deadline passed; anyone may release and re-auction this name',
    };
  }
  return {
    state: 'leased',
    safeToResolve: true,
    renewalDeadline: deadline,
    detail: 'active lease',
  };
}
