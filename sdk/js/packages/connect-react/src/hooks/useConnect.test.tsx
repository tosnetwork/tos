import React from "react";
import { describe, it, expect, vi } from "vitest";
import { renderHook } from "@testing-library/react";
import { useConnect } from "./useConnect.js";
import { ConnectContext } from "../context.js";
import type { ConnectContextValue } from "../types.js";
import type { ConnectedWallet } from "@tos/connect";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

function createMockWallet(): ConnectedWallet {
  return {
    device: {
      platform: "browser",
      appName: "TestWallet",
      appVersion: "1.0.0",
      maxProtocolVersion: 2,
      features: [],
    },
    account: {
      address: "0:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
      chain: "-239",
    },
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("useConnect", () => {
  it("returns disconnected defaults outside provider (context is null)", () => {
    const { result } = renderHook(() => useConnect());

    expect(result.current.connected).toBe(false);
    expect(result.current.connecting).toBe(false);
    expect(typeof result.current.connect).toBe("function");
    expect(typeof result.current.disconnect).toBe("function");
  });

  it("connect() is a no-op outside provider", () => {
    const { result } = renderHook(() => useConnect());

    // Should not throw
    expect(() => result.current.connect()).not.toThrow();
  });

  it("disconnect() is a no-op outside provider", async () => {
    const { result } = renderHook(() => useConnect());

    // Should return a resolved promise
    await expect(result.current.disconnect()).resolves.toBeUndefined();
  });

  it("returns connected=false when context has no wallet", () => {
    const ctx = createMockConnectContext({ wallet: null });
    const { result } = renderHook(() => useConnect(), {
      wrapper: createWrapper(ctx),
    });

    expect(result.current.connected).toBe(false);
    expect(result.current.connecting).toBe(false);
  });

  it("returns connected=true when context has a wallet", () => {
    const ctx = createMockConnectContext({ wallet: createMockWallet() });
    const { result } = renderHook(() => useConnect(), {
      wrapper: createWrapper(ctx),
    });

    expect(result.current.connected).toBe(true);
  });

  it("returns connecting=true when context is connecting", () => {
    const ctx = createMockConnectContext({ connecting: true });
    const { result } = renderHook(() => useConnect(), {
      wrapper: createWrapper(ctx),
    });

    expect(result.current.connecting).toBe(true);
    expect(result.current.connected).toBe(false);
  });

  it("delegates connect() to the context connect function", () => {
    const mockConnectFn = vi.fn();
    const ctx = createMockConnectContext({ connect: mockConnectFn });
    const { result } = renderHook(() => useConnect(), {
      wrapper: createWrapper(ctx),
    });

    const walletInfo = { name: "TestWallet", appName: "TestWallet", image: "", aboutUrl: "", bridgeUrl: "" } as any;
    result.current.connect(walletInfo);

    expect(mockConnectFn).toHaveBeenCalledWith(walletInfo);
  });

  it("delegates disconnect() to the context disconnect function", async () => {
    const mockDisconnect = vi.fn(async () => {});
    const ctx = createMockConnectContext({ disconnect: mockDisconnect });
    const { result } = renderHook(() => useConnect(), {
      wrapper: createWrapper(ctx),
    });

    await result.current.disconnect();
    expect(mockDisconnect).toHaveBeenCalled();
  });
});
