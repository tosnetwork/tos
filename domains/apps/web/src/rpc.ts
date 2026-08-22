import {
  classifyDomain,
  deriveItemAddress,
  formatRawAddress,
  loadAddress,
  parseBoc,
  base64ToBytes,
  type AuctionInfo,
  type DomainLifecycle,
  type RawAddress,
} from '@tos-domains/protocol';

export interface DomainSnapshot {
  name: string;
  label: string;
  itemAddress: string;
  exists: boolean;
  owner: string | null;
  auction: AuctionInfo | null;
  lastFillUpTime: number | null;
  lifecycle: DomainLifecycle | null;
  observedAt: number;
}

export interface RpcConfig {
  endpoint: string;
  collection: RawAddress;
  itemCodeHash: Uint8Array;
  itemCodeDepth: number;
}

type RunResult = { exit_code: number; stack: unknown[] };

export class TosRpc {
  private id = 0;

  constructor(private readonly endpoint: string) {
    const url = new URL(endpoint);
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '::1'].includes(url.hostname))) {
      throw new Error('RPC must use HTTPS (HTTP is allowed only on localhost)');
    }
  }

  async call<T>(method: string, params: Record<string, unknown> = {}): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 12_000);
    try {
      const response = await fetch(this.endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: ++this.id, method, params }),
        signal: controller.signal,
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
      });
      if (!response.ok) throw new Error(`RPC HTTP ${response.status}`);
      const envelope = await response.json() as { result?: T; error?: { message?: string } };
      if (envelope.error) throw new Error(envelope.error.message ?? 'RPC rejected the request');
      if (envelope.result === undefined) throw new Error('RPC returned no result');
      return envelope.result;
    } finally {
      clearTimeout(timer);
    }
  }

  async run(address: string, method: string): Promise<unknown[]> {
    const result = await this.call<RunResult>('runGetMethod', { address, method, stack: [] });
    if (result.exit_code !== 0 && result.exit_code !== 1) {
      throw new Error(`${method} failed with TVM exit code ${result.exit_code}`);
    }
    if (!Array.isArray(result.stack)) throw new Error(`${method} returned a malformed stack`);
    return result.stack;
  }
}

export async function inspectDomain(config: RpcConfig, label: string): Promise<DomainSnapshot> {
  const itemAddress = formatRawAddress(deriveItemAddress(config, label));
  const rpc = new TosRpc(config.endpoint);
  const observedAt = Math.floor(Date.now() / 1_000);
  try {
    const [auctionStack, fillStack, nftStack] = await Promise.all([
      rpc.run(itemAddress, 'get_auction_info'),
      rpc.run(itemAddress, 'get_last_fill_up_time'),
      rpc.run(itemAddress, 'get_nft_data'),
    ]);
    if (auctionStack.length < 3 || fillStack.length < 1 || nftStack.length < 4) {
      throw new Error('Domain Item getters returned incomplete stacks');
    }
    const auctionEndTime = stackNumber(auctionStack[2]);
    const auction: AuctionInfo | null = auctionEndTime === 0 ? null : {
      maxBidAddress: stackAddress(auctionStack[0]),
      maxBidAmount: stackBigInt(auctionStack[1]),
      auctionEndTime,
    };
    const lastFillUpTime = stackNumber(fillStack[0]);
    const owner = stackAddress(nftStack[3]);
    return {
      name: `${label}.tos`, label, itemAddress, exists: true, owner, auction,
      lastFillUpTime, lifecycle: classifyDomain(auction, lastFillUpTime, observedAt), observedAt,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!/empty|not exist|uninitialized|account state|cannot run method/i.test(message)) throw error;
    return {
      name: `${label}.tos`, label, itemAddress, exists: false, owner: null, auction: null,
      lastFillUpTime: null, lifecycle: null, observedAt,
    };
  }
}

export function stackBigInt(entry: unknown): bigint {
  if (typeof entry === 'bigint' || typeof entry === 'number' || typeof entry === 'string') return BigInt(entry);
  if (Array.isArray(entry) && entry[0] === 'num') return BigInt(String(entry[1]));
  const object = entry as Record<string, unknown>;
  if (object?.['@type'] === 'tvm.stackEntryNumber') {
    const number = object.number as Record<string, unknown>;
    return BigInt(String(number?.number));
  }
  throw new Error('expected a TVM number');
}

export function stackNumber(entry: unknown): number {
  const value = stackBigInt(entry);
  if (value < BigInt(Number.MIN_SAFE_INTEGER) || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error('TVM number exceeds the JavaScript safe range');
  }
  return Number(value);
}

export function stackAddress(entry: unknown): string | null {
  if (isNullEntry(entry)) return null;
  const bytes = stackCellBytes(entry);
  const slice = parseBoc(base64ToBytes(bytes)).beginParse();
  if (slice.remainingBits >= 2 && Number(slice.loadUint(2)) === 0) return null;
  // Reparse because the constructor peek above consumed two bits.
  return formatRawAddress(loadAddress(parseBoc(base64ToBytes(bytes)).beginParse()));
}

function isNullEntry(entry: unknown): boolean {
  return (entry as Record<string, unknown>)?.['@type'] === 'tvm.stackEntryNull' ||
    Array.isArray(entry) && entry[0] === 'null';
}

function stackCellBytes(entry: unknown): string {
  if (Array.isArray(entry) && (entry[0] === 'cell' || entry[0] === 'slice')) {
    return String((entry[1] as Record<string, unknown>)?.bytes ?? '');
  }
  const object = entry as Record<string, unknown>;
  const container = (object?.cell ?? object?.slice) as Record<string, unknown>;
  const value = String(container?.bytes ?? '');
  if (!value) throw new Error('expected a TVM cell or slice');
  return value;
}
