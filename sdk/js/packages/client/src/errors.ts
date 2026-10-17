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
 * The numeric values are the JSON-RPC `error.code` values the server sends;
 * several reasons share a code, so branch on {@link TosRpcError.reason}.
 */
export const ErrorCodes = {
  // JSON-RPC 2.0 standard
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,

  // TOS-specific server errors
  UNAUTHORIZED: -32000,
  NOT_FOUND: -32004,
  RATE_LIMITED: -32005,
  STATE_UNSUPPORTED: -32006,
  BLOCK_ID_MISMATCH: -32009,

  // Client-side errors
  NETWORK_ERROR: "NETWORK_ERROR",
  CLIENT_ERROR: "CLIENT_ERROR",
  INVALID_PARAMETER: "INVALID_PARAMETER",
  TIMEOUT: "TIMEOUT",
  RETRY_EXHAUSTED: "RETRY_EXHAUSTED",
  INVALID_ADDRESS: "INVALID_ADDRESS",
  INVALID_RESPONSE: "INVALID_RESPONSE",
  CONTRACT_ERROR: "CONTRACT_ERROR",
  WAIT_TIMEOUT: "WAIT_TIMEOUT",
} as const;

export type ErrorCode = (typeof ErrorCodes)[keyof typeof ErrorCodes];

/**
 * The `error.data.reason` values the server sends, each with the JSON-RPC
 * code and retryability it always carries.
 */
export const ErrorReasons = {
  PARSE_ERROR: { code: -32700, retryable: false },
  INVALID_REQUEST: { code: -32600, retryable: false },
  METHOD_NOT_FOUND: { code: -32601, retryable: false },
  WRITE_DISABLED: { code: -32601, retryable: false },
  INVALID_ARGUMENT: { code: -32602, retryable: false },
  INTERNAL_ERROR: { code: -32603, retryable: false },
  UNAUTHORIZED: { code: -32000, retryable: false },
  RATE_LIMITED: { code: -32005, retryable: true },
  NOT_FOUND: { code: -32004, retryable: false },
  CONFIG_PARAM_ABSENT: { code: -32004, retryable: false },
  BLOCK_UNAVAILABLE: { code: -32004, retryable: false },
  PERMISSION_SOURCE_UNSUPPORTED: { code: -32006, retryable: false },
  PERMISSION_SOURCE_DEFERRED: { code: -32006, retryable: false },
  INDEXED_STATE_STALE: { code: -32006, retryable: false },
  LIFECYCLE_IMMUTABLE: { code: -32006, retryable: false },
  CONTRACT_KIND_UNSUPPORTED: { code: -32006, retryable: false },
  UPSTREAM_UNAVAILABLE: { code: -32603, retryable: true },
  UNSIGNED_BLOCK: { code: -32602, retryable: false },
  BLOCK_ID_MISMATCH: { code: -32009, retryable: false },
  EVIDENCE_INVALID: { code: -32603, retryable: false },
  UNSUPPORTED_CARRIER: { code: -32603, retryable: false },
  STATE_INVALID: { code: -32603, retryable: false },
  RESOURCE_LIMIT: { code: -32603, retryable: false },
  VERIFICATION_BACKEND_FAILURE: { code: -32603, retryable: true },
} as const;

/** A reason this client knows; a newer server may send others. */
export type ErrorReason = keyof typeof ErrorReasons;

/** The `error.data` object of every server error. */
export interface RpcErrorData {
  schema_version: 1;
  /** A known {@link ErrorReason}, or an upper-case identifier from a newer server. */
  reason: ErrorReason | (string & {});
  /** Whether repeating the same request later may succeed. */
  retryable: boolean;
}

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
 * Error returned by the TOS JSON-RPC server.
 *
 * The client never repeats a request on its own after one: {@link retryable}
 * tells the caller whether repeating it later may succeed.
 *
 * @example
 * ```typescript
 * try {
 *   await client.getConfigParam(43);
 * } catch (err) {
 *   if (err instanceof TosRpcError && err.reason === "CONFIG_PARAM_ABSENT") {
 *     // the parameter is not set on chain
 *   }
 * }
 * ```
 */
export class TosRpcError extends TosError {
  /** The JSON-RPC `error.code`. */
  readonly rpcCode: number;
  /** The `error.data` object as the server sent it. */
  readonly rpcData: RpcErrorData;
  /** `error.data.reason`. */
  readonly reason: RpcErrorData["reason"];
  /** `error.data.retryable`. */
  readonly retryable: boolean;
  /** The HTTP status the error arrived with (200 for method-level errors). */
  readonly httpStatus: number;

  constructor(message: string, rpcCode: number, rpcData: RpcErrorData, httpStatus = 200) {
    super(message, rpcCode);
    this.name = "TosRpcError";
    this.rpcCode = rpcCode;
    this.rpcData = rpcData;
    this.reason = rpcData.reason;
    this.retryable = rpcData.retryable;
    this.httpStatus = httpStatus;
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
