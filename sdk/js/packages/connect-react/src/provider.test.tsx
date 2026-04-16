import React, { useContext } from "react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { TosConnectProvider } from "./provider.js";
import { ThemeContext, TranslationContext, ConnectContext, ModalContext } from "./context.js";

// ---------------------------------------------------------------------------
// Mock @tos/connect — the provider does a dynamic import("@tos/connect")
// ---------------------------------------------------------------------------

const mockOnStatusChange = vi.fn(() => vi.fn()); // returns unsubscribe
const mockRestoreConnection = vi.fn(() => Promise.resolve());
const mockConnect = vi.fn();
const mockDisconnect = vi.fn(() => Promise.resolve());
const mockGetWallets = vi.fn(() => Promise.resolve([]));
const mockSignData = vi.fn();

vi.mock("@tos/connect", () => ({
  TosConnect: class MockTosConnect {
    connected = false;
    wallet = null;
    connect = mockConnect;
    disconnect = mockDisconnect;
    restoreConnection = mockRestoreConnection;
    sendTransaction = vi.fn();
    signData = mockSignData;
    getWallets = mockGetWallets;
    onStatusChange = mockOnStatusChange;
  },
  TosConnectError: class extends Error {
    code: string;
    constructor(message: string, code: string) {
      super(message);
      this.code = code;
    }
  },
  ConnectErrorCodes: {},
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderWithProvider(
  ui: React.ReactElement,
  props?: Partial<React.ComponentProps<typeof TosConnectProvider>>,
) {
  const defaultConfig = { manifestUrl: "https://test.com/manifest.json" };
  return render(
    <TosConnectProvider config={defaultConfig} {...props}>
      {ui}
    </TosConnectProvider>,
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks();
});

describe("TosConnectProvider", () => {
  it("renders children", () => {
    renderWithProvider(<div data-testid="child">Hello</div>);
    expect(screen.getByTestId("child").textContent).toBe("Hello");
  });

  it("renders multiple children", () => {
    render(
      <TosConnectProvider config={{ manifestUrl: "https://test.com/manifest.json" }}>
        <span data-testid="a">A</span>
        <span data-testid="b">B</span>
      </TosConnectProvider>,
    );
    expect(screen.getByTestId("a")).toBeTruthy();
    expect(screen.getByTestId("b")).toBeTruthy();
  });

  it("provides default light theme", () => {
    function ThemeConsumer() {
      const theme = useContext(ThemeContext);
      return (
        <>
          <span data-testid="mode">{theme.mode}</span>
          <span data-testid="accent">{theme.accentColor}</span>
        </>
      );
    }

    renderWithProvider(<ThemeConsumer />);
    expect(screen.getByTestId("mode").textContent).toBe("light");
    expect(screen.getByTestId("accent").textContent).toBe("#0098EA");
  });

  it("resolves explicit dark theme", () => {
    function ThemeConsumer() {
      const theme = useContext(ThemeContext);
      return <span data-testid="mode">{theme.mode}</span>;
    }

    render(
      <TosConnectProvider
        config={{ manifestUrl: "https://test.com/manifest.json" }}
        theme="dark"
      >
        <ThemeConsumer />
      </TosConnectProvider>,
    );

    expect(screen.getByTestId("mode").textContent).toBe("dark");
  });

  it("resolves a ThemeConfig object with custom values", () => {
    function ThemeConsumer() {
      const theme = useContext(ThemeContext);
      return (
        <>
          <span data-testid="mode">{theme.mode}</span>
          <span data-testid="radius">{theme.borderRadius}</span>
          <span data-testid="accent">{theme.accentColor}</span>
        </>
      );
    }

    render(
      <TosConnectProvider
        config={{ manifestUrl: "https://test.com/manifest.json" }}
        theme={{ mode: "dark", accentColor: "#FF0000", borderRadius: "8px" }}
      >
        <ThemeConsumer />
      </TosConnectProvider>,
    );

    expect(screen.getByTestId("mode").textContent).toBe("dark");
    expect(screen.getByTestId("radius").textContent).toBe("8px");
    expect(screen.getByTestId("accent").textContent).toBe("#FF0000");
  });

  it("merges partial translations with defaults", () => {
    function TranslationConsumer() {
      const t = useContext(TranslationContext);
      return (
        <>
          <span data-testid="connect">{t.connectButton}</span>
          <span data-testid="disconnect">{t.disconnect}</span>
        </>
      );
    }

    render(
      <TosConnectProvider
        config={{ manifestUrl: "https://test.com/manifest.json" }}
        translations={{ connectButton: "Login" }}
      >
        <TranslationConsumer />
      </TosConnectProvider>,
    );

    expect(screen.getByTestId("connect").textContent).toBe("Login");
    // Non-overridden translation should keep its default
    expect(screen.getByTestId("disconnect").textContent).toBe("Disconnect");
  });

  it("provides ConnectContext with initial disconnected state", () => {
    function ConnectConsumer() {
      const ctx = useContext(ConnectContext);
      return (
        <>
          <span data-testid="wallet">{String(ctx?.wallet)}</span>
          <span data-testid="connecting">{String(ctx?.connecting)}</span>
        </>
      );
    }

    renderWithProvider(<ConnectConsumer />);
    expect(screen.getByTestId("wallet").textContent).toBe("null");
    expect(screen.getByTestId("connecting").textContent).toBe("false");
  });

  it("provides ModalContext with initial closed state", () => {
    function ModalConsumer() {
      const ctx = useContext(ModalContext);
      return (
        <>
          <span data-testid="connect-modal">{String(ctx?.connectModalOpen)}</span>
          <span data-testid="account-modal">{String(ctx?.accountModalOpen)}</span>
        </>
      );
    }

    renderWithProvider(<ModalConsumer />);
    expect(screen.getByTestId("connect-modal").textContent).toBe("false");
    expect(screen.getByTestId("account-modal").textContent).toBe("false");
  });

  it("accepts config.manifestUrl without crashing", () => {
    const { container } = render(
      <TosConnectProvider config={{ manifestUrl: "https://my-dapp.com/manifest.json" }}>
        <div>OK</div>
      </TosConnectProvider>,
    );
    expect(container.textContent).toContain("OK");
  });

  it("accepts config with all optional fields", () => {
    const { container } = render(
      <TosConnectProvider
        config={{
          manifestUrl: "https://my-dapp.com/manifest.json",
          network: "testnet",
          endpoint: "https://custom-rpc.com",
          bridgeUrl: "https://bridge.example.com",
          apiKey: "test-key-123",
        }}
      >
        <div>OK</div>
      </TosConnectProvider>,
    );
    expect(container.textContent).toContain("OK");
  });

  it("initializes TosConnect connector asynchronously", async () => {
    function ConnectorConsumer() {
      const ctx = useContext(ConnectContext);
      return (
        <span data-testid="has-connector">
          {ctx?.connector !== null ? "yes" : "no"}
        </span>
      );
    }

    renderWithProvider(<ConnectorConsumer />);

    // After the async import resolves, the connector should be set
    await waitFor(() => {
      expect(screen.getByTestId("has-connector").textContent).toBe("yes");
    });
  });

  it("calls restoreConnection on mount", async () => {
    renderWithProvider(<div>child</div>);

    await waitFor(() => {
      expect(mockRestoreConnection).toHaveBeenCalled();
    });
  });

  it("subscribes to onStatusChange on mount", async () => {
    renderWithProvider(<div>child</div>);

    await waitFor(() => {
      expect(mockOnStatusChange).toHaveBeenCalled();
    });
  });
});
