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
import type { ContractProvider, ContractGetResult, ContractState, SendConfirmation, SenderArguments } from "./ContractProvider.js";
import type { TupleItemLike } from "./TosProvider.js";
import { StackReaderImpl } from "../utils/StackReader.js";

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
        stack: new StackReaderImpl(result.stack),
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
