/**
 * @tos/client — open() function and OpenedContract type.
 *
 * The `open()` utility wraps a Contract instance with a Proxy that
 * auto-injects a {@link ContractProvider} as the first argument to any
 * method whose first parameter is typed as `ContractProvider`.
 *
 * This mirrors the pattern used by @ton/core's `openContract()`.
 *
 * ## How it works
 *
 * ```ts
 * class MyJetton implements Contract {
 *   constructor(readonly address: Address) {}
 *   async getBalance(provider: ContractProvider): Promise<bigint> { ... }
 * }
 *
 * const jetton = open(new MyJetton(addr), client);
 * // provider is injected automatically:
 * const balance = await jetton.getBalance();
 * ```
 */

import type { TosProvider, AddressLike, CellLike } from "./TosProvider.js";
import type { ContractProvider, ContractGetResult, ContractState, SendConfirmation, SenderArguments, StackReader as IStackReader } from "./ContractProvider.js";
import type { TupleItemLike } from "./TosProvider.js";
import { StackReaderImpl } from "../utils/StackReader.js";

// Cell/Address parser for RichStackReader. Injected via setCoreParser().
let _cellFromBase64: ((b64: string) => unknown) | null = null;
let _addressFromCell: ((b64: string) => unknown) | null = null;

/**
 * Inject @tos/core parsing functions so the RichStackReader can convert
 * base64 BOC strings into actual Cell and Address objects.
 * Call this once at app startup:
 *   import { Cell } from "@tos/core";
 *   import { setCoreParser } from "@tos/client";
 *   setCoreParser(Cell);
 */
export function setCoreParser(CellClass: {
  fromBase64(b64: string): { beginParse(): { loadAddress(): unknown } };
}): void {
  _cellFromBase64 = (b64: string) => CellClass.fromBase64(b64);
  _addressFromCell = (b64: string) => CellClass.fromBase64(b64).beginParse().loadAddress();
}

// Auto-detect @tos/core if available (CJS environments)
try {
  const g = globalThis as Record<string, unknown>;
  const r = g["require"] as ((m: string) => Record<string, unknown>) | undefined;
  if (typeof r === "function") {
    const core = r("@tos/core") as Record<string, unknown>;
    if (core?.Cell) setCoreParser(core.Cell as Parameters<typeof setCoreParser>[0]);
  }
} catch { /* @tos/core not available at load time */ }

// ---------------------------------------------------------------------------
// Minimal Contract shape (avoid importing @tos/core at runtime)
// ---------------------------------------------------------------------------

/** The subset of the @tos/core Contract interface that open() relies on. */
export interface ContractLike {
  readonly address: AddressLike;
  // Any method whose first param is a ContractProvider will be auto-injected.
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// OpenedContract mapped type
// ---------------------------------------------------------------------------

/**
 * For every method that accepts `ContractProvider` as its first argument,
 * produce a version that omits that argument (it is injected by the proxy).
 * All other properties pass through unchanged.
 */
export type OpenedContract<T extends ContractLike> = {
  [K in keyof T]: T[K] extends (provider: ContractProvider, ...args: infer A) => infer R
    ? (...args: A) => R
    : T[K];
};

// ---------------------------------------------------------------------------
// ContractProvider adapter (bridges TosProvider ↔ ContractProvider)
// ---------------------------------------------------------------------------

function makeContractProvider(address: AddressLike, client: TosProvider, contract?: ContractLike): ContractProvider {
  const addrString = typeof address === "string"
    ? address
    : address.toRawString();

  return {
    async getState(): Promise<ContractState> {
      const info = await client.getAddressInformation(addrString);
      const balance = BigInt(info.balance);
      const last = info.last_transaction_id
        ? { lt: info.last_transaction_id.lt, hash: info.last_transaction_id.hash }
        : null;
      const state = info.state as "active" | "frozen" | "uninitialized";

      // Decode code and data from base64 to Uint8Array
      let code: Uint8Array | null = null;
      let data: Uint8Array | null = null;
      if (info.code) {
        code = base64ToBytes(info.code);
      }
      if (info.data) {
        data = base64ToBytes(info.data);
      }

      return { balance, last, state, code, data };
    },

    async get(method: string | number, args?: TupleItemLike[]): Promise<ContractGetResult> {
      const result = await client.runGetMethod(addrString, method, args);
      return {
        gasUsed: result.gas_used,
        exitCode: result.exit_code,
        // C++ JSON-RPC returns stack top-first; reverse to bottom-first for sequential reading
        stack: new RichStackReader(new StackReaderImpl([...result.stack].reverse())),
      };
    },

    async internal(
      via: { send(args: SenderArguments): Promise<void> },
      args: Omit<SenderArguments, "to">,
    ): Promise<SendConfirmation> {
      await via.send({ ...args, to: address });
      return {};
    },

    async external(message: CellLike | Uint8Array | string): Promise<SendConfirmation> {
      // Wrap the body into a full ext_in_msg_info external message via sendQuery.
      // sendQuery on the C++ side builds the external message envelope (address, init, body).
      const init = (contract as Record<string, unknown>)?.["init"] as
        | { code?: CellLike; data?: CellLike }
        | undefined;
      const result = await client.sendQuery({
        address: addrString,
        body: message as CellLike | string,
        ...(init?.code ? { init_code: init.code } : {}),
        ...(init?.data ? { init_data: init.data } : {}),
      });
      return { hash: result.hash };
    },
  };
}

// ---------------------------------------------------------------------------
// open()
// ---------------------------------------------------------------------------

/**
 * Wrap a contract so that every method receiving a `ContractProvider` as its
 * first argument gets it injected automatically from the given TosProvider.
 *
 * This is the primary way to use wallet and contract wrappers with a client.
 * After calling `open()`, you can call contract methods without manually
 * passing the provider.
 *
 * @param contract - A contract instance with an `address` property
 * @param provider - A TosProvider (typically a TosClient instance)
 * @returns A proxied contract where ContractProvider args are auto-injected
 *
 * @example
 * ```typescript
 * import { TosClient, open } from "@tos/client";
 * import { WalletV4R2 } from "@tos/wallets";
 *
 * const client = new TosClient({ endpoint: "http://localhost:8081" });
 * const wallet = open(WalletV4R2.create({ publicKey: keys.publicKey }), client);
 *
 * // ContractProvider is injected automatically:
 * const seqno = await wallet.getSeqno();
 * const balance = await wallet.getBalance();
 * ```
 */
export function open<T extends ContractLike>(
  contract: T,
  provider: TosProvider,
): OpenedContract<T> {
  const contractProvider = makeContractProvider(contract.address, provider, contract);

  return new Proxy(contract, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver);
      if (typeof value !== "function") {
        return value;
      }
      // Return a wrapper that injects the ContractProvider as the first arg.
      return (...args: unknown[]) =>
        (value as Function).call(target, contractProvider, ...args);
    },
  }) as unknown as OpenedContract<T>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function base64ToBytes(b64: string): Uint8Array {
  // Pure-JS base64 decoding -- works in Node.js 16+ and all modern browsers.
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Wraps a raw StackReaderImpl to parse base64 cell/slice entries into actual
 * @tos/core Cell and Address objects using the injected parser.
 */
class RichStackReader implements IStackReader {
  private inner: StackReaderImpl;
  constructor(inner: StackReaderImpl) { this.inner = inner; }

  get remaining(): number { return this.inner.remaining; }
  readBigNumber(): bigint { return this.inner.readBigNumber(); }
  readNumber(): number { return this.inner.readNumber(); }
  readBoolean(): boolean { return this.inner.readBoolean(); }
  readTuple(): IStackReader { return new RichStackReader(this.inner.readTuple() as StackReaderImpl); }

  readCell(): unknown {
    const b64 = this.inner.readCell() as string;
    return _cellFromBase64 ? _cellFromBase64(b64) : b64;
  }

  readCellOpt(): unknown | null {
    const val = this.inner.readCellOpt();
    if (val === null) return null;
    return (_cellFromBase64 && typeof val === "string") ? _cellFromBase64(val) : val;
  }

  readAddress(): unknown {
    const b64 = this.inner.readAddress() as string;
    return _addressFromCell ? _addressFromCell(b64) : b64;
  }
}
