import { describe, it, expect } from "vitest";
import {
  TosConnectError,
  ConnectErrorCodes,
  userRejectedError,
  walletNotFoundError,
  bridgeUnreachableError,
  sessionExpiredError,
  sessionRestoreFailedError,
  txRejectedError,
  txTimeoutError,
  txInvalidError,
  protocolVersionMismatchError,
  manifestFetchFailedError,
} from "./errors.js";

// ---------------------------------------------------------------------------
// ConnectErrorCodes
// ---------------------------------------------------------------------------

describe("ConnectErrorCodes", () => {
  it("has all 10 entries with correct numeric values", () => {
    expect(ConnectErrorCodes.USER_REJECTED).toBe(300);
    expect(ConnectErrorCodes.WALLET_NOT_FOUND).toBe(100);
    expect(ConnectErrorCodes.BRIDGE_UNREACHABLE).toBe(400);
    expect(ConnectErrorCodes.SESSION_EXPIRED).toBe(401);
    expect(ConnectErrorCodes.SESSION_RESTORE_FAILED).toBe(402);
    expect(ConnectErrorCodes.TX_REJECTED).toBe(300);
    expect(ConnectErrorCodes.TX_TIMEOUT).toBe(500);
    expect(ConnectErrorCodes.TX_INVALID).toBe(501);
    expect(ConnectErrorCodes.PROTOCOL_VERSION_MISMATCH).toBe(600);
    expect(ConnectErrorCodes.MANIFEST_FETCH_FAILED).toBe(700);
  });

  it("has exactly 10 keys", () => {
    expect(Object.keys(ConnectErrorCodes)).toHaveLength(10);
  });
});

// ---------------------------------------------------------------------------
// TosConnectError
// ---------------------------------------------------------------------------

describe("TosConnectError", () => {
  it("is instanceof Error", () => {
    const err = new TosConnectError("test", "TEST_CODE", 999);
    expect(err).toBeInstanceOf(Error);
  });

  it("is instanceof TosConnectError", () => {
    const err = new TosConnectError("test", "TEST_CODE", 999);
    expect(err).toBeInstanceOf(TosConnectError);
  });

  it("has correct name", () => {
    const err = new TosConnectError("test", "TEST_CODE");
    expect(err.name).toBe("TosConnectError");
  });

  it("has correct code and connectCode", () => {
    const err = new TosConnectError("hello", "MY_CODE", 42);
    expect(err.code).toBe("MY_CODE");
    expect(err.connectCode).toBe(42);
    expect(err.message).toBe("hello");
  });

  it("connectCode is undefined when not provided", () => {
    const err = new TosConnectError("msg", "CODE");
    expect(err.connectCode).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Factory functions
// ---------------------------------------------------------------------------

describe("Error factory functions", () => {
  it("userRejectedError produces correct code and connectCode", () => {
    const err = userRejectedError();
    expect(err).toBeInstanceOf(TosConnectError);
    expect(err).toBeInstanceOf(Error);
    expect(err.code).toBe("USER_REJECTED");
    expect(err.connectCode).toBe(ConnectErrorCodes.USER_REJECTED);
    expect(err.message).toBe("User rejected the action");
  });

  it("userRejectedError accepts custom message", () => {
    const err = userRejectedError("custom msg");
    expect(err.message).toBe("custom msg");
    expect(err.code).toBe("USER_REJECTED");
  });

  it("walletNotFoundError produces correct code and connectCode", () => {
    const err = walletNotFoundError();
    expect(err.code).toBe("WALLET_NOT_FOUND");
    expect(err.connectCode).toBe(ConnectErrorCodes.WALLET_NOT_FOUND);
    expect(err.message).toBe("Wallet not found");
  });

  it("bridgeUnreachableError produces correct code and connectCode", () => {
    const err = bridgeUnreachableError();
    expect(err.code).toBe("BRIDGE_UNREACHABLE");
    expect(err.connectCode).toBe(ConnectErrorCodes.BRIDGE_UNREACHABLE);
    expect(err.message).toBe("Bridge server unreachable");
  });

  it("sessionExpiredError produces correct code and connectCode", () => {
    const err = sessionExpiredError();
    expect(err.code).toBe("SESSION_EXPIRED");
    expect(err.connectCode).toBe(ConnectErrorCodes.SESSION_EXPIRED);
    expect(err.message).toBe("Session expired");
  });

  it("sessionRestoreFailedError produces correct code and connectCode", () => {
    const err = sessionRestoreFailedError();
    expect(err.code).toBe("SESSION_RESTORE_FAILED");
    expect(err.connectCode).toBe(ConnectErrorCodes.SESSION_RESTORE_FAILED);
    expect(err.message).toBe("Failed to restore session");
  });

  it("txRejectedError produces correct code and connectCode", () => {
    const err = txRejectedError();
    expect(err.code).toBe("TX_REJECTED");
    expect(err.connectCode).toBe(ConnectErrorCodes.TX_REJECTED);
    expect(err.message).toBe("Transaction rejected");
  });

  it("txTimeoutError produces correct code and connectCode", () => {
    const err = txTimeoutError();
    expect(err.code).toBe("TX_TIMEOUT");
    expect(err.connectCode).toBe(ConnectErrorCodes.TX_TIMEOUT);
    expect(err.message).toBe("Transaction timed out");
  });

  it("txInvalidError produces correct code and connectCode", () => {
    const err = txInvalidError();
    expect(err.code).toBe("TX_INVALID");
    expect(err.connectCode).toBe(ConnectErrorCodes.TX_INVALID);
    expect(err.message).toBe("Invalid transaction request");
  });

  it("protocolVersionMismatchError produces correct code and connectCode", () => {
    const err = protocolVersionMismatchError();
    expect(err.code).toBe("PROTOCOL_VERSION_MISMATCH");
    expect(err.connectCode).toBe(ConnectErrorCodes.PROTOCOL_VERSION_MISMATCH);
    expect(err.message).toBe("Protocol version mismatch");
  });

  it("manifestFetchFailedError produces correct code and connectCode", () => {
    const err = manifestFetchFailedError();
    expect(err.code).toBe("MANIFEST_FETCH_FAILED");
    expect(err.connectCode).toBe(ConnectErrorCodes.MANIFEST_FETCH_FAILED);
    expect(err.message).toBe("Failed to fetch DApp manifest");
  });
});
