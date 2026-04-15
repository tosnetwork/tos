import React from "react";
import { describe, it, expect, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { TosClientContext } from "../context.js";
import { useContractRead } from "./useContractRead.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createMockClient(overrides: Record<string, any> = {}) {
  return {
    getBalance: vi.fn(),
    getAddressInformation: vi.fn(),
    getMasterchainInfo: vi.fn(),
    getTransactions: vi.fn(),
    runGetMethod: vi.fn().mockResolvedValue({
      "@type": "smc.runResult",
      gas_used: 100,
      exit_code: 0,
      stack: [],
    }),
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

describe("useContractRead", () => {
  it("calls client.runGetMethod with correct address and method", async () => {
    const client = createMockClient({
      runGetMethod: vi.fn().mockResolvedValue({
        "@type": "smc.runResult",
        gas_used: 50,
        exit_code: 0,
        stack: [],
      }),
    });

    const { result } = renderHook(
      () =>
        useContractRead({
          address: "0:contract-addr",
          method: "get_data",
        }),
      { wrapper: createWrapper(client) },
    );

    await waitFor(() => {
      expect(result.current.data).toBeDefined();
    });

    expect(client.runGetMethod).toHaveBeenCalledWith(
      "0:contract-addr",
      "get_data",
      undefined,
    );
    expect(result.current.isLoading).toBe(false);
    expect(result.current.error).toBeNull();
  });

  it("parse function transforms the result", async () => {
    const client = createMockClient({
      runGetMethod: vi.fn().mockResolvedValue({
        "@type": "smc.runResult",
        gas_used: 100,
        exit_code: 0,
        stack: [["num", "0x2a"]],
      }),
    });

    const { result } = renderHook(
      () =>
        useContractRead({
          address: "0:contract",
          method: "get_value",
          parse: (stack) => {
            const val = stack.readBigNumber();
            return { value: val };
          },
        }),
      { wrapper: createWrapper(client) },
    );

    await waitFor(() => {
      expect(result.current.data).toBeDefined();
    });

    expect(result.current.data).toEqual({ value: 42n });
  });

  it("enabled=false prevents query from firing", async () => {
    const client = createMockClient();

    const { result } = renderHook(
      () =>
        useContractRead(
          { address: "0:abc", method: "get" },
          { enabled: false },
        ),
      { wrapper: createWrapper(client) },
    );

    await new Promise((r) => setTimeout(r, 50));

    expect(client.runGetMethod).not.toHaveBeenCalled();
    expect(result.current.data).toBeUndefined();
  });

  it("auto-pauses when contractArgs is null", async () => {
    const client = createMockClient();

    const { result } = renderHook(
      () => useContractRead(null),
      { wrapper: createWrapper(client) },
    );

    await new Promise((r) => setTimeout(r, 50));

    expect(client.runGetMethod).not.toHaveBeenCalled();
    expect(result.current.data).toBeUndefined();
  });

  it("auto-pauses when address is empty", async () => {
    const client = createMockClient();

    const { result } = renderHook(
      () =>
        useContractRead({
          address: "",
          method: "get",
        }),
      { wrapper: createWrapper(client) },
    );

    await new Promise((r) => setTimeout(r, 50));

    expect(client.runGetMethod).not.toHaveBeenCalled();
  });

  it("auto-pauses when method is empty", async () => {
    const client = createMockClient();

    const { result } = renderHook(
      () =>
        useContractRead({
          address: "0:addr",
          method: "",
        }),
      { wrapper: createWrapper(client) },
    );

    await new Promise((r) => setTimeout(r, 50));

    expect(client.runGetMethod).not.toHaveBeenCalled();
  });

  it("handles errors from runGetMethod", async () => {
    const client = createMockClient({
      runGetMethod: vi.fn().mockRejectedValue(new Error("contract not found")),
    });

    const { result } = renderHook(
      () =>
        useContractRead({
          address: "0:nonexistent",
          method: "get_data",
        }),
      { wrapper: createWrapper(client) },
    );

    await waitFor(() => {
      expect(result.current.error).not.toBeNull();
    });

    expect(result.current.error!.message).toBe("contract not found");
    expect(result.current.isLoading).toBe(false);
  });

  it("returns raw RunResult when no parse function is provided", async () => {
    const rawResult = {
      "@type": "smc.runResult",
      gas_used: 200,
      exit_code: 0,
      stack: [],
    };
    const client = createMockClient({
      runGetMethod: vi.fn().mockResolvedValue(rawResult),
    });

    const { result } = renderHook(
      () =>
        useContractRead({
          address: "0:addr",
          method: "seqno",
        }),
      { wrapper: createWrapper(client) },
    );

    await waitFor(() => {
      expect(result.current.data).toBeDefined();
    });

    expect(result.current.data).toEqual(rawResult);
  });
});
