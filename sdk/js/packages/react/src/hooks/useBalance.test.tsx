import React from "react";
import { describe, it, expect, vi } from "vitest";
import { renderHook, waitFor, act } from "@testing-library/react";
import { TosClientContext } from "../context.js";
import { useBalance } from "./useBalance.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createMockClient(overrides: Record<string, any> = {}) {
  return {
    getBalance: vi.fn().mockResolvedValue("1000000000"),
    getAddressInformation: vi.fn(),
    getMasterchainInfo: vi.fn(),
    getTransactions: vi.fn(),
    runGetMethod: vi.fn(),
    estimateFee: vi.fn(),
    getConfig: vi.fn(),
    getShards: vi.fn(),
    getBlockTransactions: vi.fn(),
    getAccountCapability: vi.fn(),
    rawCall: vi.fn(),
    ...overrides,
  } as any;
}

function createWrapper(client: any) {
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return (
      <TosClientContext.Provider value={client}>
        {children}
      </TosClientContext.Provider>
    );
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("useBalance", () => {
  it("returns balance as bigint when address is provided", async () => {
    const client = createMockClient({
      getBalance: vi.fn().mockResolvedValue("5000000000"),
    });

    const { result } = renderHook(
      () => useBalance("0:abcdef1234567890"),
      { wrapper: createWrapper(client) },
    );

    await waitFor(() => {
      expect(result.current.data).toBeDefined();
    });

    expect(result.current.data).toBe(5000000000n);
    expect(result.current.isLoading).toBe(false);
    expect(result.current.error).toBeNull();
    expect(client.getBalance).toHaveBeenCalledWith("0:abcdef1234567890");
  });

  it("returns undefined data when address is null (auto-pauses)", async () => {
    const client = createMockClient();

    const { result } = renderHook(
      () => useBalance(null),
      { wrapper: createWrapper(client) },
    );

    // Give time for potential fetch
    await new Promise((r) => setTimeout(r, 50));

    expect(client.getBalance).not.toHaveBeenCalled();
    expect(result.current.data).toBeUndefined();
  });

  it("returns undefined data when address is undefined (auto-pauses)", async () => {
    const client = createMockClient();

    const { result } = renderHook(
      () => useBalance(undefined),
      { wrapper: createWrapper(client) },
    );

    await new Promise((r) => setTimeout(r, 50));

    expect(client.getBalance).not.toHaveBeenCalled();
    expect(result.current.data).toBeUndefined();
  });

  it("pauses when enabled is false even with a valid address", async () => {
    const client = createMockClient();

    const { result } = renderHook(
      () => useBalance("0:abc", { enabled: false }),
      { wrapper: createWrapper(client) },
    );

    await new Promise((r) => setTimeout(r, 50));

    expect(client.getBalance).not.toHaveBeenCalled();
    expect(result.current.data).toBeUndefined();
  });

  it("refetch() re-fetches the balance", async () => {
    let callCount = 0;
    const client = createMockClient({
      getBalance: vi.fn().mockImplementation(async () => {
        callCount++;
        return String(callCount * 1000000000);
      }),
    });

    const { result } = renderHook(
      () => useBalance("0:addr"),
      { wrapper: createWrapper(client) },
    );

    await waitFor(() => {
      expect(result.current.data).toBe(1000000000n);
    });

    act(() => {
      result.current.refetch();
    });

    await waitFor(() => {
      expect(result.current.data).toBe(2000000000n);
    });

    expect(client.getBalance).toHaveBeenCalledTimes(2);
  });

  it("handles fetch error gracefully", async () => {
    const client = createMockClient({
      getBalance: vi.fn().mockRejectedValue(new Error("rpc down")),
    });

    const { result } = renderHook(
      () => useBalance("0:bad-addr"),
      { wrapper: createWrapper(client) },
    );

    await waitFor(() => {
      expect(result.current.error).not.toBeNull();
    });

    expect(result.current.error!.message).toBe("rpc down");
    expect(result.current.isLoading).toBe(false);
    expect(result.current.data).toBeUndefined();
  });
});
