import React from "react";
import { describe, it, expect, vi } from "vitest";
import { renderHook, act, waitFor } from "@testing-library/react";
import { TosClientContext, SenderContext } from "../context.js";
import { useSendTransaction } from "./useSendTransaction.js";
import type { Sender } from "../types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createMockClient() {
  return {
    getBalance: vi.fn(),
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
  } as any;
}

function createWrapper(client: any, sender: Sender | null = null) {
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return (
      <TosClientContext.Provider value={client}>
        <SenderContext.Provider value={sender}>
          {children}
        </SenderContext.Provider>
      </TosClientContext.Provider>
    );
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("useSendTransaction", () => {
  it("has correct initial state", () => {
    const client = createMockClient();
    const { result } = renderHook(() => useSendTransaction(), {
      wrapper: createWrapper(client),
    });

    expect(result.current.isPending).toBe(false);
    expect(result.current.isSuccess).toBe(false);
    expect(result.current.isError).toBe(false);
    expect(result.current.data).toBeUndefined();
    expect(result.current.error).toBeNull();
    expect(typeof result.current.sendTransaction).toBe("function");
    expect(typeof result.current.sendTransactionAsync).toBe("function");
    expect(typeof result.current.reset).toBe("function");
  });

  it("throws error when no sender is available", async () => {
    const client = createMockClient();
    const { result } = renderHook(() => useSendTransaction(), {
      wrapper: createWrapper(client, null),
    });

    act(() => {
      result.current.sendTransaction({
        to: "0:dest",
        value: 1_000_000_000n,
      });
    });

    await waitFor(() => {
      expect(result.current.isError).toBe(true);
    });

    expect(result.current.error).not.toBeNull();
    expect(result.current.error!.message).toMatch(/No sender available/);
    expect(result.current.isPending).toBe(false);
  });

  it("calls sender.send() with correct args when sender is available", async () => {
    const client = createMockClient();
    const mockSender: Sender = {
      send: vi.fn().mockResolvedValue({ hash: "txhash123", status: 1 }),
    };

    const { result } = renderHook(() => useSendTransaction(), {
      wrapper: createWrapper(client, mockSender),
    });

    await act(async () => {
      await result.current.sendTransactionAsync({
        to: "0:destination",
        value: 2_000_000_000n,
        bounce: false,
      });
    });

    expect(mockSender.send).toHaveBeenCalledWith({
      to: "0:destination",
      value: 2_000_000_000n,
      body: undefined,
      bounce: false,
    });
    expect(result.current.isSuccess).toBe(true);
    expect(result.current.data).toEqual({ hash: "txhash123", status: 1 });
    expect(result.current.isPending).toBe(false);
  });

  it("tracks isPending/isSuccess lifecycle", async () => {
    const client = createMockClient();
    let resolveSend!: (val: any) => void;
    const mockSender: Sender = {
      send: vi.fn().mockImplementation(
        () =>
          new Promise((resolve) => {
            resolveSend = resolve;
          }),
      ),
    };

    const { result } = renderHook(() => useSendTransaction(), {
      wrapper: createWrapper(client, mockSender),
    });

    // Start the send
    act(() => {
      result.current.sendTransaction({
        to: "0:addr",
        value: 500_000_000n,
      });
    });

    // Should be pending
    expect(result.current.isPending).toBe(true);
    expect(result.current.isSuccess).toBe(false);

    // Resolve the send
    await act(async () => {
      resolveSend({ hash: "abc" });
      // Let microtasks flush
      await new Promise((r) => setTimeout(r, 0));
    });

    expect(result.current.isPending).toBe(false);
    expect(result.current.isSuccess).toBe(true);
    expect(result.current.data).toEqual({ hash: "abc" });
  });

  it("reset() clears state back to idle", async () => {
    const client = createMockClient();
    const mockSender: Sender = {
      send: vi.fn().mockResolvedValue({ hash: "h" }),
    };

    const { result } = renderHook(() => useSendTransaction(), {
      wrapper: createWrapper(client, mockSender),
    });

    await act(async () => {
      await result.current.sendTransactionAsync({
        to: "0:x",
        value: 1n,
      });
    });

    expect(result.current.isSuccess).toBe(true);

    act(() => {
      result.current.reset();
    });

    expect(result.current.isPending).toBe(false);
    expect(result.current.isSuccess).toBe(false);
    expect(result.current.isError).toBe(false);
    expect(result.current.data).toBeUndefined();
    expect(result.current.error).toBeNull();
  });
});
