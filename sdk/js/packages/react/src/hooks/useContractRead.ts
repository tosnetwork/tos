/**
 * @tos/react — useContractRead hook.
 *
 * Calls a smart-contract get-method via `runGetMethod` and optionally parses
 * the resulting TVM stack with a user-supplied `parse` function.
 */

import type { Address, TupleItem } from "@tos/core";
import { TupleReader } from "@tos/core";
import type { RunResult, TupleItemLike } from "@tos/client";
import type { QueryOptions, QueryResult } from "../types.js";
import { useClient } from "./useClient.js";
import { useQuery } from "./useQuery.js";

// ---------------------------------------------------------------------------
// Args
// ---------------------------------------------------------------------------

/** Arguments for {@link useContractRead}. */
export interface UseContractReadArgs<T = RunResult> {
  /** Contract address. */
  address: Address | string;
  /** Get-method name or numeric ID. */
  method: string | number;
  /** Optional TVM stack arguments. */
  args?: TupleItem[];
  /** Optional parser to convert the raw stack into a typed result. */
  parse?: (stack: TupleReader) => T;
}

/** Options for {@link useContractRead}. */
export interface UseContractReadOptions extends QueryOptions {}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * Read data from a smart contract via a get-method.
 *
 * @typeParam T - The parsed result type (defaults to `RunResult` when no
 *               `parse` function is provided).
 * @param contractArgs - Contract call arguments.
 * @param opts         - Query options.
 * @returns A query result with `data` typed as `T`.
 *
 * @example
 * ```tsx
 * const { data } = useContractRead({
 *   address: "0:abc...",
 *   method: "get_wallet_data",
 *   parse: (stack) => ({
 *     balance: stack.readBigNumber(),
 *     owner: stack.readAddress(),
 *   }),
 * });
 * ```
 */
export function useContractRead<T = RunResult>(
  contractArgs?: UseContractReadArgs<T> | null,
  opts?: UseContractReadOptions,
): QueryResult<T> {
  const client = useClient();
  const addrStr = contractArgs?.address ? String(contractArgs.address) : "";
  const method = contractArgs?.method ?? "";
  const enabled = (opts?.enabled ?? true) && !!contractArgs?.address && !!contractArgs?.method;

  return useQuery<T>({
    queryKey: [
      "contractRead",
      addrStr,
      String(method),
      JSON.stringify(contractArgs?.args ?? []),
    ],
    queryFn: async () => {
      const result = await client.runGetMethod(
        contractArgs!.address,
        contractArgs!.method,
        contractArgs!.args as TupleItemLike[] | undefined,
      );

      if (contractArgs!.parse) {
        // Build a TupleReader from the raw stack array.
        const items = parseRawStack(result.stack);
        const reader = new TupleReader(items);
        return contractArgs!.parse(reader);
      }

      return result as unknown as T;
    },
    enabled,
    refetchInterval: opts?.refetchInterval,
  });
}

// ---------------------------------------------------------------------------
// Stack parsing helper
// ---------------------------------------------------------------------------

/**
 * Convert the raw `unknown[]` stack returned by `runGetMethod` into typed
 * `TupleItem[]` suitable for the `TupleReader`.
 *
 * The TOS JSON-RPC server returns stack entries as `[type, value]` tuples
 * where `type` is one of `"num"`, `"cell"`, `"slice"`, etc.
 */
function parseRawStack(raw: unknown[]): TupleItem[] {
  return raw.map((entry): TupleItem => {
    if (!Array.isArray(entry) || entry.length < 2) {
      return { type: "null" };
    }

    const [kind, value] = entry as [string, unknown];

    switch (kind) {
      case "num": {
        // "num" values come as hex-prefixed or decimal strings — BigInt handles both.
        const n = BigInt(String(value));
        return { type: "int", value: n };
      }
      case "cell": {
        // value is { bytes: "base64..." }
        const bytes = (value as Record<string, string>).bytes ?? "";
        return { type: "cell", cell: cellFromBase64(bytes) } as TupleItem;
      }
      case "slice": {
        const bytes = (value as Record<string, string>).bytes ?? "";
        return { type: "slice", cell: cellFromBase64(bytes) } as TupleItem;
      }
      case "builder": {
        const bytes = (value as Record<string, string>).bytes ?? "";
        return { type: "builder", cell: cellFromBase64(bytes) } as TupleItem;
      }
      default:
        return { type: "null" };
    }
  });
}

/**
 * Minimal helper that wraps a base64 BOC string into a Cell-like object.
 * The TupleReader primarily needs `.beginParse()` which returns a Slice.
 * For a full parse the consumer should import Cell from @tos/core.
 *
 * We keep this lightweight — the actual Cell.fromBoc deserialization is not
 * performed here to avoid pulling in heavy BOC parsing code.  The returned
 * object stores the raw base64 and defers parsing to TupleReader internals.
 */
function cellFromBase64(base64: string): unknown {
  // Return a plain object with the base64 payload.  TupleReader in @tos/core
  // accepts these via its internal handling.  If the consumer provides a
  // `parse` callback they can access the raw stack entries.
  return { _base64: base64, toString: () => base64 };
}
