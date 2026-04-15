/**
 * Error types and codes for @tos/connect.
 */

/** Numeric error codes used in the TOS Connect protocol and SDK. */
export const ConnectErrorCodes = {
  /** The user rejected the action in the wallet UI. */
  USER_REJECTED: 300,
  /** The requested wallet was not found / not installed. */
  WALLET_NOT_FOUND: 100,
  /** Unable to reach the HTTP bridge server. */
  BRIDGE_UNREACHABLE: 400,
  /** The encrypted session has expired (TTL elapsed). */
  SESSION_EXPIRED: 401,
  /** Restoring a previous session failed. */
  SESSION_RESTORE_FAILED: 402,
  /** The user rejected the transaction. */
  TX_REJECTED: 301,
  /** Timed out waiting for the wallet to respond. */
  TX_TIMEOUT: 500,
  /** The transaction request was malformed. */
  TX_INVALID: 501,
  /** Wallet reports an incompatible protocol version. */
  PROTOCOL_VERSION_MISMATCH: 600,
  /** Could not fetch the DApp manifest. */
  MANIFEST_FETCH_FAILED: 700,
} as const;

export type ConnectErrorCode = (typeof ConnectErrorCodes)[keyof typeof ConnectErrorCodes];

/**
 * Structured error thrown by TosConnect operations.
 *
 * - `code` is a human-readable string tag.
 * - `connectCode` is the numeric protocol-level error code (when applicable).
 */
export class TosConnectError extends Error {
  readonly code: string;
  readonly connectCode?: number;

  constructor(message: string, code: string, connectCode?: number) {
    super(message);
    this.name = "TosConnectError";
    this.code = code;
    this.connectCode = connectCode;
  }
}

// ---------------------------------------------------------------------------
// Factory helpers (internal convenience)
// ---------------------------------------------------------------------------

export function userRejectedError(message = "User rejected the action"): TosConnectError {
  return new TosConnectError(message, "USER_REJECTED", ConnectErrorCodes.USER_REJECTED);
}

export function walletNotFoundError(message = "Wallet not found"): TosConnectError {
  return new TosConnectError(message, "WALLET_NOT_FOUND", ConnectErrorCodes.WALLET_NOT_FOUND);
}

export function bridgeUnreachableError(message = "Bridge server unreachable"): TosConnectError {
  return new TosConnectError(message, "BRIDGE_UNREACHABLE", ConnectErrorCodes.BRIDGE_UNREACHABLE);
}

export function sessionExpiredError(message = "Session expired"): TosConnectError {
  return new TosConnectError(message, "SESSION_EXPIRED", ConnectErrorCodes.SESSION_EXPIRED);
}

export function sessionRestoreFailedError(message = "Failed to restore session"): TosConnectError {
  return new TosConnectError(message, "SESSION_RESTORE_FAILED", ConnectErrorCodes.SESSION_RESTORE_FAILED);
}

export function txRejectedError(message = "Transaction rejected"): TosConnectError {
  return new TosConnectError(message, "TX_REJECTED", ConnectErrorCodes.TX_REJECTED);
}

export function txTimeoutError(message = "Transaction timed out"): TosConnectError {
  return new TosConnectError(message, "TX_TIMEOUT", ConnectErrorCodes.TX_TIMEOUT);
}

export function txInvalidError(message = "Invalid transaction request"): TosConnectError {
  return new TosConnectError(message, "TX_INVALID", ConnectErrorCodes.TX_INVALID);
}

export function protocolVersionMismatchError(message = "Protocol version mismatch"): TosConnectError {
  return new TosConnectError(message, "PROTOCOL_VERSION_MISMATCH", ConnectErrorCodes.PROTOCOL_VERSION_MISMATCH);
}

export function manifestFetchFailedError(message = "Failed to fetch DApp manifest"): TosConnectError {
  return new TosConnectError(message, "MANIFEST_FETCH_FAILED", ConnectErrorCodes.MANIFEST_FETCH_FAILED);
}
