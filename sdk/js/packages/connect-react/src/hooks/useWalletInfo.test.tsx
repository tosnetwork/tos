import React from "react";
import { describe, it, expect, vi } from "vitest";
import { renderHook } from "@testing-library/react";
import { useWalletInfo } from "./useWalletInfo.js";
import { ConnectContext } from "../context.js";
import type { ConnectContextValue } from "../types.js";
import type { ConnectedWallet, WalletFeature } from "@tos/connect";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createMockWallet(
  overrides?: Partial<ConnectedWallet>,
): ConnectedWallet {
  return {
    device: {
      platform: "browser",
      appName: "TosWallet",
      appVersion: "2.1.0",
      maxProtocolVersion: 2,
      features: [
        { name: "SendTransaction", maxMessages: 4 },
        { name: "SignData" },
      ],
    },
    account: {
      address: "0:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
      chain: "-239",
    },
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

describe("useWalletInfo", () => {
  it("returns null values when not connected (outside provider)", () => {
    const { result } = renderHook(() => useWalletInfo());

    expect(result.current.name).toBeNull();
    expect(result.current.icon).toBeNull();
    expect(result.current.platform).toBeNull();
    expect(result.current.features).toBeNull();
  });

  it("returns null values when context has no wallet", () => {
    const ctx = createMockConnectContext({ wallet: null });
    const { result } = renderHook(() => useWalletInfo(), {
      wrapper: createWrapper(ctx),
    });

    expect(result.current.name).toBeNull();
    expect(result.current.icon).toBeNull();
    expect(result.current.platform).toBeNull();
    expect(result.current.features).toBeNull();
  });

  it("returns wallet metadata when connected", () => {
    const wallet = createMockWallet();
    const ctx = createMockConnectContext({ wallet });
    const { result } = renderHook(() => useWalletInfo(), {
      wrapper: createWrapper(ctx),
    });

    expect(result.current.name).toBe("TosWallet");
    expect(result.current.platform).toBe("browser");
    expect(result.current.features).toEqual([
      { name: "SendTransaction", maxMessages: 4 },
      { name: "SignData" },
    ]);
  });

  it("returns null for icon (icon URL is not in DeviceInfo)", () => {
    const wallet = createMockWallet();
    const ctx = createMockConnectContext({ wallet });
    const { result } = renderHook(() => useWalletInfo(), {
      wrapper: createWrapper(ctx),
    });

    // Per source code: icon is always null since it's not in DeviceInfo
    expect(result.current.icon).toBeNull();
  });

  it("handles different platform values", () => {
    const wallet = createMockWallet({
      device: {
        platform: "mobile",
        appName: "MobileWallet",
        appVersion: "1.0.0",
        maxProtocolVersion: 2,
        features: [],
      },
    });
    const ctx = createMockConnectContext({ wallet });
    const { result } = renderHook(() => useWalletInfo(), {
      wrapper: createWrapper(ctx),
    });

    expect(result.current.name).toBe("MobileWallet");
    expect(result.current.platform).toBe("mobile");
    expect(result.current.features).toEqual([]);
  });
});
