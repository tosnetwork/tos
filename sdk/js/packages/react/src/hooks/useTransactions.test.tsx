import React from "react";
import { describe, it, expect, vi } from "vitest";
import { renderHook, act, waitFor } from "@testing-library/react";
import { TosClientContext } from "../context.js";
import { useTransactions } from "./useTransactions.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeTx(lt: string, hash: string) {
  return {
    "@type": "raw.transaction" as const,
    data: "base64...",
    transaction_id: { "@type": "internal.transactionId" as const, lt, hash },
    fee: "1000",
    storage_fee: "100",
    other_fee: "200",
  };
}

function createMockClient(overrides: Record<string, any> = {}) {
  return {
    getBalance: vi.fn(),
    getAddressInformation: vi.fn(),
    getMasterchainInfo: vi.fn(),
    getTransactions: vi.fn().mockResolvedValue([]),
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

describe("useTransactions", () => {
  it("returns initial empty array", () => {
    const client = createMockClient();
    const { result } = renderHook(
      () => useTransactions(null),
      { wrapper: createWrapper(client) },
    );

    expect(result.current.data).toEqual([]);
    expect(result.current.isLoading).toBe(false);
    expect(result.current.isFetchingNextPage).toBe(false);
    expect(result.current.error).toBeNull();
  });

  it("fetches and populates data when address is provided", async () => {
    const txns = [
      makeTx("1000", "hash1"),
      makeTx("999", "hash2"),
    ];
    const client = createMockClient({
      getTransactions: vi.fn().mockResolvedValue(txns),
    });

    const { result } = renderHook(
      () => useTransactions("0:account-addr", { limit: 2 }),
      { wrapper: createWrapper(client) },
    );

    await waitFor(() => {
      expect(result.current.data.length).toBe(2);
    });

    expect(result.current.data[0]!.transaction_id.lt).toBe("1000");
    expect(result.current.data[1]!.transaction_id.lt).toBe("999");
    expect(result.current.isLoading).toBe(false);
    expect(result.current.error).toBeNull();
    expect(client.getTransactions).toHaveBeenCalledWith(
      "0:account-addr",
      2,
      undefined,
    );
  });

  it("does not fetch when address is null", async () => {
    const client = createMockClient();
    const { result } = renderHook(
      () => useTransactions(null),
      { wrapper: createWrapper(client) },
    );

    await new Promise((r) => setTimeout(r, 50));

    expect(client.getTransactions).not.toHaveBeenCalled();
    expect(result.current.data).toEqual([]);
  });

  it("does not fetch when enabled is false", async () => {
    const client = createMockClient();
    const { result } = renderHook(
      () => useTransactions("0:addr", { enabled: false }),
      { wrapper: createWrapper(client) },
    );

    await new Promise((r) => setTimeout(r, 50));

    expect(client.getTransactions).not.toHaveBeenCalled();
    expect(result.current.data).toEqual([]);
  });

  it("fetchNextPage() appends more items", async () => {
    const page1 = [
      makeTx("1000", "h1"),
      makeTx("999", "h2"),
    ];
    const page2 = [
      makeTx("998", "h3"),
      makeTx("997", "h4"),
    ];

    const client = createMockClient({
      getTransactions: vi
        .fn()
        .mockResolvedValueOnce(page1)
        .mockResolvedValueOnce(page2),
    });

    const { result } = renderHook(
      () => useTransactions("0:account", { limit: 2 }),
      { wrapper: createWrapper(client) },
    );

    // Wait for first page
    await waitFor(() => {
      expect(result.current.data.length).toBe(2);
    });

    expect(result.current.hasNextPage).toBe(true);

    // Fetch next page
    act(() => {
      result.current.fetchNextPage();
    });

    await waitFor(() => {
      expect(result.current.data.length).toBe(4);
    });

    expect(result.current.data[2]!.transaction_id.lt).toBe("998");
    expect(result.current.data[3]!.transaction_id.lt).toBe("997");

    // Verify the second call used the cursor from the last tx of page 1
    expect(client.getTransactions).toHaveBeenCalledTimes(2);
    expect(client.getTransactions).toHaveBeenNthCalledWith(
      2,
      "0:account",
      2,
      { lt: "999", hash: "h2" },
    );
  });

  it("sets hasNextPage=false when fewer items than limit are returned", async () => {
    const partial = [makeTx("100", "only-one")];
    const client = createMockClient({
      getTransactions: vi.fn().mockResolvedValue(partial),
    });

    const { result } = renderHook(
      () => useTransactions("0:addr", { limit: 20 }),
      { wrapper: createWrapper(client) },
    );

    await waitFor(() => {
      expect(result.current.data.length).toBe(1);
    });

    expect(result.current.hasNextPage).toBe(false);
  });

  it("refetch() re-fetches from the beginning", async () => {
    const page1 = [makeTx("10", "a"), makeTx("9", "b")];
    const freshPage = [makeTx("20", "c"), makeTx("19", "d")];

    const client = createMockClient({
      getTransactions: vi
        .fn()
        .mockResolvedValueOnce(page1)
        .mockResolvedValueOnce(freshPage),
    });

    const { result } = renderHook(
      () => useTransactions("0:addr", { limit: 2 }),
      { wrapper: createWrapper(client) },
    );

    await waitFor(() => {
      expect(result.current.data.length).toBe(2);
    });

    // Refetch from beginning
    act(() => {
      result.current.refetch();
    });

    await waitFor(() => {
      expect(result.current.data[0]!.transaction_id.lt).toBe("20");
    });

    // Data should be replaced, not appended
    expect(result.current.data.length).toBe(2);
    expect(result.current.hasNextPage).toBe(true);
  });

  it("handles fetch error gracefully", async () => {
    const client = createMockClient({
      getTransactions: vi.fn().mockRejectedValue(new Error("rpc error")),
    });

    const { result } = renderHook(
      () => useTransactions("0:addr"),
      { wrapper: createWrapper(client) },
    );

    await waitFor(() => {
      expect(result.current.error).not.toBeNull();
    });

    expect(result.current.error!.message).toBe("rpc error");
    expect(result.current.isLoading).toBe(false);
    expect(result.current.data).toEqual([]);
  });
});
