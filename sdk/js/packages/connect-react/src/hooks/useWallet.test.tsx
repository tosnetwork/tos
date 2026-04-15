import React from "react";
import { describe, it, expect, vi } from "vitest";
import { renderHook } from "@testing-library/react";
import { useWallet } from "./useWallet.js";
import { ConnectContext } from "../context.js";
import type { ConnectContextValue } from "../types.js";
import type { ConnectedWallet } from "@tos/connect";

// ---------------------------------------------------------------------------
// Mock wallet factory
// ---------------------------------------------------------------------------

function createMockWallet(overrides?: Partial<ConnectedWallet>): ConnectedWallet {
  return {
    device: {
      platform: "browser",
      appName: "TestWallet",
      appVersion: "1.0.0",
      maxProtocolVersion: 2,
      features: [{ name: "SendTransaction", maxMessages: 4 }],
    },
    account: {
      address: "0:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
      chain: "-239",
      publicKey: "aabbccdd",
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

describe("useWallet", () => {
  it("returns disconnected defaults outside provider (context is null)", () => {
    const { result } = renderHook(() => useWallet());

    expect(result.current.connected).toBe(false);
    expect(result.current.address).toBeNull();
    expect(result.current.publicKey).toBeNull();
    expect(result.current.chain).toBeNull();
    expect(result.current.wallet).toBeNull();
    expect(typeof result.current.disconnect).toBe("function");
  });

  it("returns disconnected defaults when context has no wallet", () => {
    const ctx = createMockConnectContext({ wallet: null });
    const { result } = renderHook(() => useWallet(), {
      wrapper: createWrapper(ctx),
    });

    expect(result.current.connected).toBe(false);
    expect(result.current.address).toBeNull();
    expect(result.current.publicKey).toBeNull();
    expect(result.current.chain).toBeNull();
    expect(result.current.wallet).toBeNull();
  });

  it("uses the context disconnect when available but wallet is null", () => {
    const mockDisconnect = vi.fn(async () => {});
    const ctx = createMockConnectContext({
      wallet: null,
      disconnect: mockDisconnect,
    });
    const { result } = renderHook(() => useWallet(), {
      wrapper: createWrapper(ctx),
    });

    expect(result.current.disconnect).toBe(mockDisconnect);
  });

  it("returns connected=true and parses address when wallet is provided", () => {
    const wallet = createMockWallet();
    const ctx = createMockConnectContext({ wallet });
    const { result } = renderHook(() => useWallet(), {
      wrapper: createWrapper(ctx),
    });

    expect(result.current.connected).toBe(true);
    expect(result.current.address).not.toBeNull();
    // The Address.parse should have produced an Address instance
    expect(result.current.address!.workchain).toBe(0);
  });

  it("parses hex public key to Uint8Array", () => {
    const wallet = createMockWallet({
      account: {
        address: "0:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        chain: "-239",
        publicKey: "aabbccdd",
      },
    });
    const ctx = createMockConnectContext({ wallet });
    const { result } = renderHook(() => useWallet(), {
      wrapper: createWrapper(ctx),
    });

    expect(result.current.publicKey).toBeInstanceOf(Uint8Array);
    expect(result.current.publicKey!.length).toBe(4);
    expect(result.current.publicKey![0]).toBe(0xaa);
    expect(result.current.publicKey![1]).toBe(0xbb);
    expect(result.current.publicKey![2]).toBe(0xcc);
    expect(result.current.publicKey![3]).toBe(0xdd);
  });

  it("returns chain from account", () => {
    const wallet = createMockWallet();
    const ctx = createMockConnectContext({ wallet });
    const { result } = renderHook(() => useWallet(), {
      wrapper: createWrapper(ctx),
    });

    expect(result.current.chain).toBe("-239");
  });

  it("returns the full wallet object", () => {
    const wallet = createMockWallet();
    const ctx = createMockConnectContext({ wallet });
    const { result } = renderHook(() => useWallet(), {
      wrapper: createWrapper(ctx),
    });

    expect(result.current.wallet).toBe(wallet);
  });

  it("returns disconnect from context when wallet is connected", () => {
    const mockDisconnect = vi.fn(async () => {});
    const wallet = createMockWallet();
    const ctx = createMockConnectContext({ wallet, disconnect: mockDisconnect });
    const { result } = renderHook(() => useWallet(), {
      wrapper: createWrapper(ctx),
    });

    expect(result.current.disconnect).toBe(mockDisconnect);
  });

  it("handles missing publicKey gracefully", () => {
    const wallet = createMockWallet({
      account: {
        address: "0:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        chain: "-239",
        // no publicKey
      },
    });
    const ctx = createMockConnectContext({ wallet });
    const { result } = renderHook(() => useWallet(), {
      wrapper: createWrapper(ctx),
    });

    expect(result.current.connected).toBe(true);
    expect(result.current.publicKey).toBeNull();
  });

  it("handles malformed address gracefully", () => {
    const wallet = createMockWallet({
      account: {
        address: "invalid-address",
        chain: "-239",
      },
    });
    const ctx = createMockConnectContext({ wallet });
    const { result } = renderHook(() => useWallet(), {
      wrapper: createWrapper(ctx),
    });

    // Should still be connected, but address parse fails
    expect(result.current.connected).toBe(true);
    expect(result.current.address).toBeNull();
  });
});
