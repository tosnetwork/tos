import React from "react";
import { describe, it, expect, vi } from "vitest";
import { renderHook } from "@testing-library/react";
import { useConnectModal } from "./useConnectModal.js";
import { ModalContext } from "../context.js";
import type { ModalContextValue } from "../types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createMockModalContext(
  overrides?: Partial<ModalContextValue>,
): ModalContextValue {
  return {
    openConnectModal: vi.fn(),
    closeConnectModal: vi.fn(),
    openAccountModal: vi.fn(),
    closeAccountModal: vi.fn(),
    connectModalOpen: false,
    accountModalOpen: false,
    ...overrides,
  };
}

function createWrapper(value: ModalContextValue) {
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return (
      <ModalContext.Provider value={value}>
        {children}
      </ModalContext.Provider>
    );
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("useConnectModal", () => {
  it("returns isOpen=false by default outside provider", () => {
    const { result } = renderHook(() => useConnectModal());

    expect(result.current.isOpen).toBe(false);
    expect(typeof result.current.open).toBe("function");
    expect(typeof result.current.close).toBe("function");
  });

  it("open() is a no-op outside provider", () => {
    const { result } = renderHook(() => useConnectModal());

    // Should not throw
    expect(() => result.current.open()).not.toThrow();
  });

  it("close() is a no-op outside provider", () => {
    const { result } = renderHook(() => useConnectModal());

    expect(() => result.current.close()).not.toThrow();
  });

  it("returns isOpen=false when modal context has connectModalOpen=false", () => {
    const ctx = createMockModalContext({ connectModalOpen: false });
    const { result } = renderHook(() => useConnectModal(), {
      wrapper: createWrapper(ctx),
    });

    expect(result.current.isOpen).toBe(false);
  });

  it("returns isOpen=true when modal context has connectModalOpen=true", () => {
    const ctx = createMockModalContext({ connectModalOpen: true });
    const { result } = renderHook(() => useConnectModal(), {
      wrapper: createWrapper(ctx),
    });

    expect(result.current.isOpen).toBe(true);
  });

  it("delegates open() to context.openConnectModal", () => {
    const mockOpen = vi.fn();
    const ctx = createMockModalContext({ openConnectModal: mockOpen });
    const { result } = renderHook(() => useConnectModal(), {
      wrapper: createWrapper(ctx),
    });

    result.current.open();
    expect(mockOpen).toHaveBeenCalledTimes(1);
  });

  it("delegates close() to context.closeConnectModal", () => {
    const mockClose = vi.fn();
    const ctx = createMockModalContext({ closeConnectModal: mockClose });
    const { result } = renderHook(() => useConnectModal(), {
      wrapper: createWrapper(ctx),
    });

    result.current.close();
    expect(mockClose).toHaveBeenCalledTimes(1);
  });
});
