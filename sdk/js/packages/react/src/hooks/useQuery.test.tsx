/**
 * Tests for the internal useQuery hook.
 *
 * useQuery uses `useSyncExternalStore` with a global store singleton. Direct
 * `waitFor` polling can cause memory pressure when combined with multiple tests
 * in jsdom, so async assertions poll the store directly.
 *
 * useQuery is also tested indirectly (via useBalance, useContractRead, etc.)
 * where each hook test file exercises the full lifecycle with waitFor.
 */
import React from "react";
import { describe, it, expect, vi } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { TosClientContext } from "../context.js";
import { useQuery } from "./useQuery.js";
import * as store from "../store.js";

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

function createWrapper(client: any) {
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return (
      <TosClientContext.Provider value={client}>
        {children}
      </TosClientContext.Provider>
    );
  };
}

/** Poll the store until `check` returns true (or timeout). */
async function pollStore(check: () => boolean, timeoutMs = 2000): Promise<void> {
  const start = Date.now();
  while (!check()) {
    if (Date.now() - start > timeoutMs) {
      throw new Error("pollStore timed out");
    }
    await new Promise((r) => setTimeout(r, 10));
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("useQuery", () => {
  it("returns isLoading=true on initial render with correct field types", () => {
    const client = createMockClient();
    const queryFn = vi.fn().mockResolvedValue("data");

    const { result } = renderHook(
      () =>
        useQuery({
          queryKey: ["sync-check", String(Math.random())],
          queryFn,
        }),
      { wrapper: createWrapper(client) },
    );

    expect(result.current.isLoading).toBe(true);
    expect(result.current.data).toBeUndefined();
    expect(result.current.error).toBeNull();
    expect(typeof result.current.refetch).toBe("function");
  });

  it("does not fire query when enabled=false", async () => {
    const client = createMockClient();
    const queryFn = vi.fn().mockResolvedValue("nope");

    renderHook(
      () =>
        useQuery({
          queryKey: ["disabled-check", String(Math.random())],
          queryFn,
          enabled: false,
        }),
      { wrapper: createWrapper(client) },
    );

    await new Promise((r) => setTimeout(r, 100));
    expect(queryFn).not.toHaveBeenCalled();
  });

  it("calls queryFn and stores resolved data", async () => {
    const client = createMockClient();
    const key = ["data-store", String(Math.random())];
    const serialized = store.serializeKey(key);
    const queryFn = vi.fn().mockResolvedValue("stored-value");

    renderHook(
      () => useQuery({ queryKey: key, queryFn }),
      { wrapper: createWrapper(client) },
    );

    await pollStore(() => store.getSnapshot(serialized).data === "stored-value");

    const snap = store.getSnapshot(serialized);
    expect(snap.data).toBe("stored-value");
    expect(snap.isLoading).toBe(false);
    expect(snap.error).toBeNull();
    expect(queryFn).toHaveBeenCalledTimes(1);
  });

  it("stores error when queryFn rejects", async () => {
    const client = createMockClient();
    const key = ["err-store", String(Math.random())];
    const serialized = store.serializeKey(key);
    const queryFn = vi.fn().mockRejectedValue(new Error("boom"));

    renderHook(
      () => useQuery({ queryKey: key, queryFn }),
      { wrapper: createWrapper(client) },
    );

    await pollStore(() => store.getSnapshot(serialized).error !== null);

    const snap = store.getSnapshot(serialized);
    expect(snap.error).not.toBeNull();
    expect(snap.error!.message).toBe("boom");
    expect(snap.isLoading).toBe(false);
  });

  it("refetch() calls queryFn again and updates the store", async () => {
    const client = createMockClient();
    let c = 0;
    const key = ["refetch-store", String(Math.random())];
    const serialized = store.serializeKey(key);
    const queryFn = vi.fn().mockImplementation(async () => `v${++c}`);

    const { result } = renderHook(
      () => useQuery({ queryKey: key, queryFn }),
      { wrapper: createWrapper(client) },
    );

    await pollStore(() => store.getSnapshot(serialized).data === "v1");

    // Trigger refetch
    result.current.refetch();

    await pollStore(() => store.getSnapshot(serialized).data === "v2");
    expect(queryFn).toHaveBeenCalledTimes(2);
  });

  it("re-fetches when queryKey changes", async () => {
    const client = createMockClient();
    let c = 0;
    const queryFn = vi.fn().mockImplementation(async () => `k${++c}`);
    const rand = String(Math.random());
    const key1 = store.serializeKey(["rekey", "a", rand]);
    const key2 = store.serializeKey(["rekey", "b", rand]);

    const { rerender } = renderHook(
      ({ k }: { k: string }) =>
        useQuery({ queryKey: ["rekey", k, rand], queryFn }),
      { wrapper: createWrapper(client), initialProps: { k: "a" } },
    );

    await pollStore(() => store.getSnapshot(key1).data === "k1");

    rerender({ k: "b" });

    await pollStore(() => store.getSnapshot(key2).data === "k2");
  });

  it("unmounting cleans up without errors", async () => {
    const client = createMockClient();
    const key = ["unmount-test", String(Math.random())];
    const serialized = store.serializeKey(key);
    const queryFn = vi.fn().mockResolvedValue("clean");

    const { unmount } = renderHook(
      () => useQuery({ queryKey: key, queryFn }),
      { wrapper: createWrapper(client) },
    );

    await pollStore(() => store.getSnapshot(serialized).data === "clean");

    // Unmount should not throw
    unmount();

    queryFn.mockClear();
    await new Promise((r) => setTimeout(r, 50));
    expect(queryFn).not.toHaveBeenCalled();
  });
});
