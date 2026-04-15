import React, { useState } from "react";
import { describe, it, expect, vi } from "vitest";
import { renderHook, act, render, screen, fireEvent } from "@testing-library/react";
import { useOnDisconnect } from "./useOnDisconnect.js";
import { ConnectContext } from "../context.js";
import type { ConnectContextValue } from "../types.js";
import type { ConnectedWallet } from "@tos/connect";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("useOnDisconnect", () => {
  it("does NOT call callback when initially disconnected (wallet is null)", () => {
    const callback = vi.fn();
    const ctx = createMockConnectContext({ wallet: null });

    renderHook(() => useOnDisconnect(callback), {
      wrapper: ({ children }) => (
        <ConnectContext.Provider value={ctx}>
          {children}
        </ConnectContext.Provider>
      ),
    });

    expect(callback).not.toHaveBeenCalled();
  });

  it("does NOT call callback when initially connected and stays connected", () => {
    const callback = vi.fn();
    const wallet = createMockWallet();
    const ctx = createMockConnectContext({ wallet });

    renderHook(() => useOnDisconnect(callback), {
      wrapper: ({ children }) => (
        <ConnectContext.Provider value={ctx}>
          {children}
        </ConnectContext.Provider>
      ),
    });

    expect(callback).not.toHaveBeenCalled();
  });

  it("calls callback when wallet transitions from connected to null", () => {
    const callback = vi.fn();
    const wallet = createMockWallet();

    // Use a stateful wrapper to control the context value
    function StatefulWrapper({ children }: { children: React.ReactNode }) {
      const [currentWallet, setCurrentWallet] = useState<ConnectedWallet | null>(wallet);

      const ctx = createMockConnectContext({ wallet: currentWallet });

      return (
        <ConnectContext.Provider value={ctx}>
          {children}
          <button
            data-testid="disconnect-btn"
            onClick={() => setCurrentWallet(null)}
          >
            Disconnect
          </button>
        </ConnectContext.Provider>
      );
    }

    // We need a component that uses the hook so we can trigger re-renders
    function TestComponent() {
      useOnDisconnect(callback);
      return null;
    }

    render(
      <StatefulWrapper>
        <TestComponent />
      </StatefulWrapper>,
    );

    // Initially, callback should not have been called
    expect(callback).not.toHaveBeenCalled();

    // Trigger disconnect
    act(() => {
      fireEvent.click(screen.getByTestId("disconnect-btn"));
    });

    // Now callback should have been called once
    expect(callback).toHaveBeenCalledTimes(1);
  });

  it("does NOT call callback when wallet transitions from null to connected", () => {
    const callback = vi.fn();
    const wallet = createMockWallet();

    function StatefulWrapper({ children }: { children: React.ReactNode }) {
      const [currentWallet, setCurrentWallet] = useState<ConnectedWallet | null>(null);

      const ctx = createMockConnectContext({ wallet: currentWallet });

      return (
        <ConnectContext.Provider value={ctx}>
          {children}
          <button
            data-testid="connect-btn"
            onClick={() => setCurrentWallet(wallet)}
          >
            Connect
          </button>
        </ConnectContext.Provider>
      );
    }

    function TestComponent() {
      useOnDisconnect(callback);
      return null;
    }

    render(
      <StatefulWrapper>
        <TestComponent />
      </StatefulWrapper>,
    );

    act(() => {
      fireEvent.click(screen.getByTestId("connect-btn"));
    });

    expect(callback).not.toHaveBeenCalled();
  });

  it("does NOT call callback outside provider (context is null)", () => {
    const callback = vi.fn();

    renderHook(() => useOnDisconnect(callback));

    expect(callback).not.toHaveBeenCalled();
  });

  it("uses the latest callback reference via ref", () => {
    const wallet = createMockWallet();
    const callback1 = vi.fn();
    const callback2 = vi.fn();

    function StatefulWrapper({ children }: { children: React.ReactNode }) {
      const [currentWallet, setCurrentWallet] = useState<ConnectedWallet | null>(wallet);

      const ctx = createMockConnectContext({ wallet: currentWallet });

      return (
        <ConnectContext.Provider value={ctx}>
          {children}
          <button
            data-testid="disconnect-btn"
            onClick={() => setCurrentWallet(null)}
          >
            Disconnect
          </button>
        </ConnectContext.Provider>
      );
    }

    function TestComponent({ cb }: { cb: () => void }) {
      useOnDisconnect(cb);
      return null;
    }

    const { rerender } = render(
      <StatefulWrapper>
        <TestComponent cb={callback1} />
      </StatefulWrapper>,
    );

    // Update the callback before disconnecting
    rerender(
      <StatefulWrapper>
        <TestComponent cb={callback2} />
      </StatefulWrapper>,
    );

    act(() => {
      fireEvent.click(screen.getByTestId("disconnect-btn"));
    });

    // callback2 should be called (the latest one), not callback1
    expect(callback1).not.toHaveBeenCalled();
    expect(callback2).toHaveBeenCalledTimes(1);
  });
});
