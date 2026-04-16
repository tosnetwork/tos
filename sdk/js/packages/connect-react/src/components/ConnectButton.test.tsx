import React from "react";
import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { ConnectButton } from "./ConnectButton.js";
import { ConnectContext, ModalContext, TranslationContext } from "../context.js";
import type { ConnectContextValue, ModalContextValue, TranslationKeys } from "../types.js";
import type { ConnectedWallet } from "@tos/connect";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const DEFAULT_TRANSLATIONS: TranslationKeys = {
  connectButton: "Connect Wallet",
  disconnect: "Disconnect",
  copyAddress: "Copy Address",
  connecting: "Connecting...",
  connected: "Connected",
  walletModalTitle: "Choose a Wallet",
  signRequestTitle: "Signature Request",
  transactionSent: "Transaction Sent",
  error: "Error",
};

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

interface WrapperOptions {
  connect?: Partial<ConnectContextValue>;
  modal?: Partial<ModalContextValue>;
  translations?: TranslationKeys;
}

function createWrapper(options: WrapperOptions = {}) {
  const connectValue = createMockConnectContext(options.connect);
  const modalValue = createMockModalContext(options.modal);
  const translations = options.translations ?? DEFAULT_TRANSLATIONS;

  return function Wrapper({ children }: { children: React.ReactNode }) {
    return (
      <TranslationContext.Provider value={translations}>
        <ConnectContext.Provider value={connectValue}>
          <ModalContext.Provider value={modalValue}>
            {children}
          </ModalContext.Provider>
        </ConnectContext.Provider>
      </TranslationContext.Provider>
    );
  };
}

// ---------------------------------------------------------------------------
// Default ConnectButton
// ---------------------------------------------------------------------------

describe("ConnectButton", () => {
  it('renders "Connect Wallet" button when disconnected', () => {
    render(<ConnectButton />, { wrapper: createWrapper() });

    expect(screen.getByText("Connect Wallet")).toBeTruthy();
    expect(screen.getByRole("button")).toBeTruthy();
  });

  it("renders the label prop when provided", () => {
    render(<ConnectButton label="Login" />, { wrapper: createWrapper() });

    expect(screen.getByText("Login")).toBeTruthy();
  });

  it("shows connecting text when connecting", () => {
    render(<ConnectButton />, {
      wrapper: createWrapper({ connect: { connecting: true } }),
    });

    expect(screen.getByText("Connecting...")).toBeTruthy();
  });

  it("button is disabled when connecting", () => {
    render(<ConnectButton />, {
      wrapper: createWrapper({ connect: { connecting: true } }),
    });

    const button = screen.getByRole("button");
    expect(button).toHaveProperty("disabled", true);
  });

  it("opens connect modal when clicked while disconnected", () => {
    const mockOpenConnectModal = vi.fn();
    render(<ConnectButton />, {
      wrapper: createWrapper({
        modal: { openConnectModal: mockOpenConnectModal },
      }),
    });

    fireEvent.click(screen.getByRole("button"));
    expect(mockOpenConnectModal).toHaveBeenCalledTimes(1);
  });

  it("shows address when connected", () => {
    const wallet = createMockWallet();
    render(<ConnectButton />, {
      wrapper: createWrapper({ connect: { wallet } }),
    });

    // The button should exist and have the connected class
    const button = screen.getByRole("button");
    expect(button.className).toContain("tos-connect-button--connected");
  });

  it("opens account modal when clicked while connected", () => {
    const mockOpenAccountModal = vi.fn();
    const wallet = createMockWallet();
    render(<ConnectButton />, {
      wrapper: createWrapper({
        connect: { wallet },
        modal: { openAccountModal: mockOpenAccountModal },
      }),
    });

    fireEvent.click(screen.getByRole("button"));
    expect(mockOpenAccountModal).toHaveBeenCalledTimes(1);
  });

  it("shows wallet name in full account status mode", () => {
    const wallet = createMockWallet();
    render(<ConnectButton accountStatus="full" />, {
      wrapper: createWrapper({ connect: { wallet } }),
    });

    expect(screen.getByText("TestWallet")).toBeTruthy();
  });

  it("hides wallet name in address-only account status mode", () => {
    const wallet = createMockWallet();
    render(<ConnectButton accountStatus="address" />, {
      wrapper: createWrapper({ connect: { wallet } }),
    });

    expect(screen.queryByText("TestWallet")).toBeNull();
  });

  it("uses custom translation for connect button label", () => {
    const customTranslations = {
      ...DEFAULT_TRANSLATIONS,
      connectButton: "Sign In",
    };
    render(<ConnectButton />, {
      wrapper: createWrapper({ translations: customTranslations }),
    });

    expect(screen.getByText("Sign In")).toBeTruthy();
  });

  it("label prop takes precedence over translation", () => {
    const customTranslations = {
      ...DEFAULT_TRANSLATIONS,
      connectButton: "Sign In",
    };
    render(<ConnectButton label="Custom Label" />, {
      wrapper: createWrapper({ translations: customTranslations }),
    });

    expect(screen.getByText("Custom Label")).toBeTruthy();
    expect(screen.queryByText("Sign In")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// ConnectButton.Custom
// ---------------------------------------------------------------------------

describe("ConnectButton.Custom", () => {
  it("renders children with render props", () => {
    render(
      <ConnectButton.Custom>
        {(props) => (
          <span data-testid="custom">
            {props.connected ? "YES" : "NO"}
          </span>
        )}
      </ConnectButton.Custom>,
      { wrapper: createWrapper() },
    );

    expect(screen.getByTestId("custom").textContent).toBe("NO");
  });

  it("receives connected=false outside provider", () => {
    // Without any wrapper, context is null
    render(
      <ConnectButton.Custom>
        {(props) => (
          <>
            <span data-testid="connected">{String(props.connected)}</span>
            <span data-testid="address">{String(props.address)}</span>
            <span data-testid="balance">{String(props.balance)}</span>
            <span data-testid="walletName">{String(props.walletName)}</span>
          </>
        )}
      </ConnectButton.Custom>,
    );

    expect(screen.getByTestId("connected").textContent).toBe("false");
    expect(screen.getByTestId("address").textContent).toBe("null");
    expect(screen.getByTestId("balance").textContent).toBe("null");
    expect(screen.getByTestId("walletName").textContent).toBe("null");
  });

  it("receives connected=true when wallet is in context", () => {
    const wallet = createMockWallet();
    render(
      <ConnectButton.Custom>
        {(props) => (
          <>
            <span data-testid="connected">{String(props.connected)}</span>
            <span data-testid="walletName">{String(props.walletName)}</span>
          </>
        )}
      </ConnectButton.Custom>,
      { wrapper: createWrapper({ connect: { wallet } }) },
    );

    expect(screen.getByTestId("connected").textContent).toBe("true");
    expect(screen.getByTestId("walletName").textContent).toBe("TestWallet");
  });

  it("provides openConnectModal and disconnect as callable functions", () => {
    const mockOpen = vi.fn();
    const mockDisconnect = vi.fn(async () => {});

    render(
      <ConnectButton.Custom>
        {(props) => (
          <>
            <button data-testid="open" onClick={props.openConnectModal}>
              Open
            </button>
            <button data-testid="disconnect" onClick={props.disconnect}>
              DC
            </button>
          </>
        )}
      </ConnectButton.Custom>,
      {
        wrapper: createWrapper({
          connect: { disconnect: mockDisconnect },
          modal: { openConnectModal: mockOpen },
        }),
      },
    );

    fireEvent.click(screen.getByTestId("open"));
    expect(mockOpen).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByTestId("disconnect"));
    expect(mockDisconnect).toHaveBeenCalledTimes(1);
  });

  it("provides openAccountModal as a callable function", () => {
    const mockOpenAccount = vi.fn();

    render(
      <ConnectButton.Custom>
        {(props) => (
          <button data-testid="account" onClick={props.openAccountModal}>
            Account
          </button>
        )}
      </ConnectButton.Custom>,
      {
        wrapper: createWrapper({
          modal: { openAccountModal: mockOpenAccount },
        }),
      },
    );

    fireEvent.click(screen.getByTestId("account"));
    expect(mockOpenAccount).toHaveBeenCalledTimes(1);
  });
});
