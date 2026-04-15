/**
 * @tos/client — Error hierarchy.
 *
 * All errors subclass {@link TosError} so callers can catch the whole family
 * with a single `instanceof` check.
 */

// Re-export the Address type for TosContractError (imported from @tos/core
// at the boundary; kept as `unknown` here to avoid a hard runtime dep in
// error-only paths).

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/**
 * Canonical error codes emitted by the TOS JSON-RPC server and this client.
 *
 * The numeric values match JSON-RPC 2.0 reserved ranges plus TOS-specific
 * extensions.
 */
export const ErrorCodes = {
  // JSON-RPC 2.0 standard
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,

  // TOS-specific server errors
  LITESERVER_ERROR: -32000,
  LITESERVER_TIMEOUT: -32001,
  ACCOUNT_NOT_FOUND: -32002,
  BLOCK_NOT_FOUND: -32003,
  TRANSACTION_NOT_FOUND: -32004,
  CONFIG_NOT_FOUND: -32005,
  READONLY_MODE: -32006,

  // Client-side errors
  NETWORK_ERROR: "NETWORK_ERROR",
  CLIENT_ERROR: "CLIENT_ERROR",
  TIMEOUT: "TIMEOUT",
  RETRY_EXHAUSTED: "RETRY_EXHAUSTED",
  INVALID_ADDRESS: "INVALID_ADDRESS",
  INVALID_RESPONSE: "INVALID_RESPONSE",
  CONTRACT_ERROR: "CONTRACT_ERROR",
  WAIT_TIMEOUT: "WAIT_TIMEOUT",
} as const;

export type ErrorCode = (typeof ErrorCodes)[keyof typeof ErrorCodes];

// ---------------------------------------------------------------------------
// Base error
// ---------------------------------------------------------------------------

/**
 * Base error class for all TOS client errors.
 *
 * All errors from the TOS client library extend this class, allowing
 * callers to catch the entire error family with `instanceof TosError`.
 *
 * @example
 * ```typescript
 * try {
 *   await client.getAddressInformation(addr);
 * } catch (err) {
 *   if (err instanceof TosError) {
 *     console.log(err.code, err.message);
 *   }
 * }
 * ```
 */
export class TosError extends Error {
  readonly code: string | number;
  override readonly cause?: Error;

  constructor(message: string, code: string | number, cause?: Error) {
    super(message);
    this.name = "TosError";
    this.code = code;
    this.cause = cause;
    // Fix prototype chain for instanceof checks.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// ---------------------------------------------------------------------------
// RPC error (remote)
// ---------------------------------------------------------------------------

/**
 * Error returned by the TOS JSON-RPC server (deterministic, not retried).
 *
 * @example
 * ```typescript
 * try {
 *   await client.runGetMethod(addr, "nonexistent_method");
 * } catch (err) {
 *   if (err instanceof TosRpcError) {
 *     console.log(err.rpcCode, err.rpcData);
 *   }
 * }
 * ```
 */
export class TosRpcError extends TosError {
  readonly rpcCode: number;
  readonly rpcData?: unknown;

  constructor(message: string, rpcCode: number, rpcData?: unknown) {
    super(message, rpcCode);
    this.name = "TosRpcError";
    this.rpcCode = rpcCode;
    this.rpcData = rpcData;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// ---------------------------------------------------------------------------
// Contract error (VM exit code)
// ---------------------------------------------------------------------------

/**
 * Error representing a TVM contract execution failure (non-zero exit code).
 */
export class TosContractError extends TosError {
  readonly exitCode: number;
  /** The raw address string of the contract that failed. */
  readonly address: string;

  constructor(message: string, exitCode: number, address: string) {
    super(message, ErrorCodes.CONTRACT_ERROR);
    this.name = "TosContractError";
    this.exitCode = exitCode;
    this.address = address;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
