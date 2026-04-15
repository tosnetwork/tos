/**
 * @tos/client — StackReader implementation.
 *
 * Wraps the raw TVM stack entries returned by JSON-RPC `runGetMethod` into a
 * cursor-based reader with typed read helpers.  This matches the TupleReader
 * pattern from @tos/core but operates on the wire-format stack entries so that
 * @tos/client can remain self-contained.
 *
 * Wire-format stack entries (from C++ JSON-RPC) come in two shapes:
 *
 * 1. Named-type objects (default runGetMethod):
 *    { "@type": "tvm.stackEntryNumber", "number": { "@type": "tvm.numberDecimal", "number": "123" } }
 *    { "@type": "tvm.stackEntryCell",   "cell":   { "bytes": "<base64 BOC>" } }
 *    { "@type": "tvm.stackEntryTuple",  "tuple":  { "elements": [...] } }
 *    { "@type": "tvm.stackEntryList",   "list":   { "elements": [...] } }
 *
 * 2. Compact-array tuples (runGetMethodStd):
 *    ["num",   "0x7b"]
 *    ["cell",  { "bytes": "<base64>" }]
 *    ["tuple", { "elements": [...] }]
 *    ["list",  { "elements": [...] }]
 */

import type { StackReader as IStackReader } from "../provider/ContractProvider.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function bigIntFromEntry(entry: unknown): bigint {
  if (entry === null || entry === undefined) {
    throw new Error("StackReader: expected a number entry, got null/undefined");
  }

  // Named-type format: { "@type": "tvm.stackEntryNumber", "number": { "number": "123" } }
  const obj = entry as Record<string, unknown>;
  if (obj["@type"] === "tvm.stackEntryNumber") {
    const inner = obj["number"] as Record<string, unknown>;
    const numStr = String(inner?.["number"] ?? inner);
    return BigInt(numStr);
  }

  // Compact-array format: ["num", "0x7b"]
  if (Array.isArray(entry) && entry[0] === "num") {
    return BigInt(entry[1] as string);
  }

  // Bare number value (already parsed)
  if (typeof entry === "bigint") return entry;
  if (typeof entry === "number") return BigInt(entry);
  if (typeof entry === "string") return BigInt(entry);

  throw new Error(`StackReader: cannot read bigint from stack entry: ${JSON.stringify(entry)}`);
}

function cellBytesFromEntry(entry: unknown): string {
  if (entry === null || entry === undefined) {
    throw new Error("StackReader: expected a cell entry, got null/undefined");
  }

  const obj = entry as Record<string, unknown>;

  // Named-type: { "@type": "tvm.stackEntryCell", "cell": { "bytes": "..." } }
  if (obj["@type"] === "tvm.stackEntryCell") {
    const cell = obj["cell"] as Record<string, unknown>;
    return String(cell?.["bytes"] ?? "");
  }

  // Compact-array: ["cell", { "bytes": "..." }]
  if (Array.isArray(entry) && entry[0] === "cell") {
    const cell = entry[1] as Record<string, unknown>;
    return String(cell?.["bytes"] ?? "");
  }

  throw new Error(`StackReader: cannot read cell from stack entry: ${JSON.stringify(entry)}`);
}

function tupleElementsFromEntry(entry: unknown): unknown[] {
  const obj = entry as Record<string, unknown>;

  // Named-type: { "@type": "tvm.stackEntryTuple", "tuple": { "elements": [...] } }
  if (obj["@type"] === "tvm.stackEntryTuple" || obj["@type"] === "tvm.stackEntryList") {
    const container = (obj["tuple"] ?? obj["list"]) as Record<string, unknown>;
    return (container?.["elements"] ?? []) as unknown[];
  }

  // Compact-array: ["tuple", { "elements": [...] }]
  if (Array.isArray(entry) && (entry[0] === "tuple" || entry[0] === "list")) {
    const container = entry[1] as Record<string, unknown>;
    return (container?.["elements"] ?? []) as unknown[];
  }

  throw new Error(`StackReader: cannot read tuple from stack entry: ${JSON.stringify(entry)}`);
}

// ---------------------------------------------------------------------------
// StackReader
// ---------------------------------------------------------------------------

/**
 * Reads TVM stack entries returned by the JSON-RPC `runGetMethod` response.
 *
 * Wraps raw wire-format stack entries into a cursor-based reader with
 * typed accessors. Supports both named-type and compact-array formats.
 *
 * @example
 * ```typescript
 * const result = await client.runGetMethod(addr, "get_jetton_data");
 * const reader = new StackReaderImpl(result.stack);
 * const supply = reader.readBigNumber();
 * const mintable = reader.readBoolean();
 * ```
 */
export class StackReaderImpl implements IStackReader {
  private items: unknown[];
  private cursor = 0;

  constructor(items: unknown[]) {
    this.items = items;
  }

  get remaining(): number {
    return this.items.length - this.cursor;
  }

  private pop(): unknown {
    if (this.cursor >= this.items.length) {
      throw new Error("StackReader: stack underflow — no more items");
    }
    return this.items[this.cursor++];
  }

  readBigNumber(): bigint {
    return bigIntFromEntry(this.pop());
  }

  readNumber(): number {
    const n = this.readBigNumber();
    if (n > Number.MAX_SAFE_INTEGER || n < Number.MIN_SAFE_INTEGER) {
      throw new Error(`StackReader: number ${n} is outside safe integer range`);
    }
    return Number(n);
  }

  readBoolean(): boolean {
    const n = this.readBigNumber();
    if (n === 0n) return false;
    if (n === -1n || n === 1n) return true;
    throw new Error(`StackReader: expected boolean (0 or -1), got ${n}`);
  }

  readAddress(): unknown {
    // Returns the raw cell bytes string — contract wrappers will parse it.
    // The address is returned as a cell on the TVM stack; the consumer can
    // parse it into an Address object using @tos/core.
    const b64 = cellBytesFromEntry(this.pop());
    return b64;
  }

  readCell(): unknown {
    return cellBytesFromEntry(this.pop());
  }

  readCellOpt(): unknown | null {
    if (this.cursor >= this.items.length) return null;
    const entry = this.items[this.cursor];
    const obj = entry as Record<string, unknown>;

    // Check for null entry
    if (obj?.["@type"] === "tvm.stackEntryNull" ||
        (Array.isArray(entry) && entry[0] === "null")) {
      this.cursor++;
      return null;
    }

    return this.readCell();
  }

  readTuple(): IStackReader {
    const elements = tupleElementsFromEntry(this.pop());
    return new StackReaderImpl(elements);
  }
}
