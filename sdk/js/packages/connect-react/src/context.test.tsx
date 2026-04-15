import React, { useContext } from "react";
import { describe, it, expect } from "vitest";
import { render, screen, renderHook } from "@testing-library/react";
import {
  ConnectContext,
  ModalContext,
  ThemeContext,
  TranslationContext,
  DEFAULT_TRANSLATIONS,
} from "./context.js";

// ---------------------------------------------------------------------------
// ConnectContext
// ---------------------------------------------------------------------------

describe("ConnectContext", () => {
  it("has a default value of null", () => {
    const { result } = renderHook(() => useContext(ConnectContext));
    expect(result.current).toBeNull();
  });

  it("provides and consumes a ConnectContextValue", () => {
    const mockValue = {
      connector: null,
      wallet: null,
      connecting: false,
      disconnect: async () => {},
      connect: () => {},
    };

    function Consumer() {
      const ctx = useContext(ConnectContext);
      return <span data-testid="connected">{String(ctx?.connecting)}</span>;
    }

    render(
      <ConnectContext.Provider value={mockValue}>
        <Consumer />
      </ConnectContext.Provider>,
    );

    expect(screen.getByTestId("connected").textContent).toBe("false");
  });
});

// ---------------------------------------------------------------------------
// ModalContext
// ---------------------------------------------------------------------------

describe("ModalContext", () => {
  it("has a default value of null", () => {
    const { result } = renderHook(() => useContext(ModalContext));
    expect(result.current).toBeNull();
  });

  it("provides and consumes a ModalContextValue", () => {
    const mockValue = {
      openConnectModal: () => {},
      closeConnectModal: () => {},
      openAccountModal: () => {},
      closeAccountModal: () => {},
      connectModalOpen: true,
      accountModalOpen: false,
    };

    function Consumer() {
      const ctx = useContext(ModalContext);
      return (
        <span data-testid="modal-open">
          {String(ctx?.connectModalOpen)}
        </span>
      );
    }

    render(
      <ModalContext.Provider value={mockValue}>
        <Consumer />
      </ModalContext.Provider>,
    );

    expect(screen.getByTestId("modal-open").textContent).toBe("true");
  });
});

// ---------------------------------------------------------------------------
// ThemeContext
// ---------------------------------------------------------------------------

describe("ThemeContext", () => {
  it("has sensible light-mode defaults", () => {
    const { result } = renderHook(() => useContext(ThemeContext));

    expect(result.current.mode).toBe("light");
    expect(result.current.accentColor).toBe("#0098EA");
    expect(result.current.borderRadius).toBe("16px");
    expect(result.current.fontFamily).toContain("apple-system");
  });

  it("can be overridden with a custom theme", () => {
    const custom = {
      mode: "dark" as const,
      accentColor: "#FF0000",
      borderRadius: "8px",
      fontFamily: "monospace",
    };

    function Consumer() {
      const theme = useContext(ThemeContext);
      return <span data-testid="mode">{theme.mode}</span>;
    }

    render(
      <ThemeContext.Provider value={custom}>
        <Consumer />
      </ThemeContext.Provider>,
    );

    expect(screen.getByTestId("mode").textContent).toBe("dark");
  });
});

// ---------------------------------------------------------------------------
// TranslationContext
// ---------------------------------------------------------------------------

describe("TranslationContext", () => {
  it("provides default translations", () => {
    const { result } = renderHook(() => useContext(TranslationContext));

    expect(result.current.connectButton).toBe("Connect Wallet");
    expect(result.current.disconnect).toBe("Disconnect");
    expect(result.current.copyAddress).toBe("Copy Address");
    expect(result.current.connecting).toBe("Connecting...");
    expect(result.current.connected).toBe("Connected");
    expect(result.current.walletModalTitle).toBe("Choose a Wallet");
    expect(result.current.signRequestTitle).toBe("Signature Request");
    expect(result.current.transactionSent).toBe("Transaction Sent");
    expect(result.current.error).toBe("Error");
  });

  it("matches the exported DEFAULT_TRANSLATIONS constant", () => {
    const { result } = renderHook(() => useContext(TranslationContext));
    expect(result.current).toEqual(DEFAULT_TRANSLATIONS);
  });

  it("can be overridden with custom translations", () => {
    const custom = {
      ...DEFAULT_TRANSLATIONS,
      connectButton: "Log In",
    };

    function Consumer() {
      const t = useContext(TranslationContext);
      return <span data-testid="label">{t.connectButton}</span>;
    }

    render(
      <TranslationContext.Provider value={custom}>
        <Consumer />
      </TranslationContext.Provider>,
    );

    expect(screen.getByTestId("label").textContent).toBe("Log In");
  });
});
