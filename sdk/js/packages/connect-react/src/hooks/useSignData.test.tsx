import React from "react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, act, waitFor } from "@testing-library/react";
import { useSignData } from "./useSignData.js";
import { ConnectContext } from "../context.js";
import type { ConnectContextValue, TosConnectInstance } from "../types.js";
import type { SignDataResponse } from "@tos/connect";
import { TosError } from "@tos/client";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createMockConnector(
  overrides?: Partial<TosConnectInstance>,
): TosConnectInstance {
  return {
    connect: vi.fn(() => null),
    disconnect: vi.fn(async () => {}),
    restoreConnection: vi.fn(async () => {}),
    sendTransaction: vi.fn(async () => ({ boc: "mock-boc" })),
    signData: vi.fn(async () => ({
      signature: "base64sig",
      address: "0:abc",
      timestamp: 1234567890,
      payload: "hello",
    })),
    getWallets: vi.fn(async () => []),
    onStatusChange: vi.fn(() => vi.fn()),
    connected: true,
    wallet: null,
    ...overrides,
  };
}

function createMockConnectContext(
  overrides?: Partial<ConnectContextValue>,
): ConnectContextValue {
  return {
    connector: null,
    wallet: null,
    connecting: false,
    disconnect: vi.fn(async () => {}),
    connect: vi.fn(),
    ...overrides,
  };
}

function createWrapper(value: ConnectContextValue) {
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return (
      <ConnectContext.Provider value={value}>
        {children}
      </ConnectContext.Provider>
    );
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("useSignData", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns initial state: isPending=false, data=undefined, error=null", () => {
    const { result } = renderHook(() => useSignData());

    expect(result.current.isPending).toBe(false);
    expect(result.current.data).toBeUndefined();
    expect(result.current.error).toBeNull();
    expect(typeof result.current.signData).toBe("function");
    expect(typeof result.current.signDataAsync).toBe("function");
  });

  it("signDataAsync throws TosError when no connector is available", async () => {
    const { result } = renderHook(() => useSignData());

    let thrownError: unknown;
    await act(async () => {
      try {
        await result.current.signDataAsync({ type: "text", data: "hello" });
      } catch (err) {
        thrownError = err;
      }
    });

    expect(thrownError).toBeTruthy();
    expect((thrownError as TosError).message).toBe("No wallet connected");
  });

  it("signDataAsync throws when connector has no signData method", async () => {
    const connector = createMockConnector();
    // Remove signData to simulate unsupported feature
    (connector as any).signData = undefined;

    const ctx = createMockConnectContext({ connector });
    const { result } = renderHook(() => useSignData(), {
      wrapper: createWrapper(ctx),
    });

    let thrownError: unknown;
    await act(async () => {
      try {
        await result.current.signDataAsync({ type: "text", data: "hello" });
      } catch (err) {
        thrownError = err;
      }
    });

    expect(thrownError).toBeTruthy();
    expect((thrownError as TosError).message).toBe("Wallet does not support signData");
  });

  it("signDataAsync resolves with mock response when connector is available", async () => {
    const mockResponse: SignDataResponse = {
      signature: "mockSig==",
      address: "0:deadbeef",
      timestamp: 1700000000,
      payload: "test-payload",
    };
    const mockSignData = vi.fn(async () => mockResponse);
    const connector = createMockConnector({ signData: mockSignData });
    const ctx = createMockConnectContext({ connector });

    const { result } = renderHook(() => useSignData(), {
      wrapper: createWrapper(ctx),
    });

    let response: SignDataResponse | undefined;
    await act(async () => {
      response = await result.current.signDataAsync({
        type: "text",
        data: "test-payload",
      });
    });

    expect(response).toEqual(mockResponse);
    expect(result.current.data).toEqual(mockResponse);
    expect(result.current.isPending).toBe(false);
    expect(result.current.error).toBeNull();
    expect(mockSignData).toHaveBeenCalledWith({
      type: "text",
      data: "test-payload",
    });
  });

  it("sets error state when signDataAsync fails", async () => {
    const mockSignData = vi.fn(async () => {
      throw new Error("User rejected");
    });
    const connector = createMockConnector({ signData: mockSignData });
    const ctx = createMockConnectContext({ connector });

    const { result } = renderHook(() => useSignData(), {
      wrapper: createWrapper(ctx),
    });

    let thrownError: unknown;
    await act(async () => {
      try {
        await result.current.signDataAsync({ type: "text", data: "hello" });
      } catch (err) {
        thrownError = err;
      }
    });

    expect(thrownError).toBeTruthy();
    expect(result.current.isPending).toBe(false);
    expect(result.current.error).not.toBeNull();
    expect(result.current.error!.message).toBe("User rejected");
  });

  it("wraps non-TosError errors into TosError", async () => {
    const mockSignData = vi.fn(async () => {
      throw new Error("Something broke");
    });
    const connector = createMockConnector({ signData: mockSignData });
    const ctx = createMockConnectContext({ connector });

    const { result } = renderHook(() => useSignData(), {
      wrapper: createWrapper(ctx),
    });

    await act(async () => {
      try {
        await result.current.signDataAsync({ type: "text", data: "hello" });
      } catch {
        // expected
      }
    });

    expect(result.current.error).toBeInstanceOf(TosError);
    expect(result.current.error!.code).toBe("SIGN_DATA_ERROR");
  });

  it("preserves TosError if the connector throws one", async () => {
    const originalError = new TosError("Wallet rejected", "USER_REJECTED");
    const mockSignData = vi.fn(async () => {
      throw originalError;
    });
    const connector = createMockConnector({ signData: mockSignData });
    const ctx = createMockConnectContext({ connector });

    const { result } = renderHook(() => useSignData(), {
      wrapper: createWrapper(ctx),
    });

    await act(async () => {
      try {
        await result.current.signDataAsync({ type: "text", data: "hello" });
      } catch {
        // expected
      }
    });

    expect(result.current.error).toBe(originalError);
    expect(result.current.error!.code).toBe("USER_REJECTED");
  });

  it("signData (fire-and-forget) does not throw when no connector is available", async () => {
    const ctx = createMockConnectContext({ connector: null });
    const { result } = renderHook(() => useSignData(), {
      wrapper: createWrapper(ctx),
    });

    // signData should swallow the error (caught by internal .catch)
    // and not throw to the caller
    await act(async () => {
      result.current.signData({ type: "text", data: "hello" });
      // Let the internal promise settle
      await new Promise((r) => setTimeout(r, 50));
    });

    // The throw happens before setError is called (early guard),
    // so error state may remain null. The key behavior: no throw
    // escapes to the caller.
    expect(result.current.isPending).toBe(false);
  });

  it("signData (fire-and-forget) sets error state when connector rejects", async () => {
    const mockSignData = vi.fn(async () => {
      throw new Error("Sign failed");
    });
    const connector = createMockConnector({ signData: mockSignData });
    const ctx = createMockConnectContext({ connector });

    const { result } = renderHook(() => useSignData(), {
      wrapper: createWrapper(ctx),
    });

    await act(async () => {
      result.current.signData({ type: "text", data: "hello" });
      await new Promise((r) => setTimeout(r, 50));
    });

    await waitFor(() => {
      expect(result.current.error).not.toBeNull();
    });
    expect(result.current.error!.message).toBe("Sign failed");
    expect(result.current.isPending).toBe(false);
  });

  it("signData (fire-and-forget) stores successful result", async () => {
    const mockResponse: SignDataResponse = {
      signature: "sig",
      address: "0:abc",
      timestamp: 123,
      payload: "data",
    };
    const connector = createMockConnector({
      signData: vi.fn(async () => mockResponse),
    });
    const ctx = createMockConnectContext({ connector });

    const { result } = renderHook(() => useSignData(), {
      wrapper: createWrapper(ctx),
    });

    await act(async () => {
      result.current.signData({ type: "text", data: "data" });
      // Wait for the internal promise to resolve
      await new Promise((r) => setTimeout(r, 50));
    });

    await waitFor(() => {
      expect(result.current.data).toEqual(mockResponse);
    });
    expect(result.current.error).toBeNull();
  });
});
