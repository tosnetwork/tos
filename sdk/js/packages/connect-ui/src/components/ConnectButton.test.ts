import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { ConnectButton, type ConnectButtonCallbacks } from "./ConnectButton.js";
import { I18nManager } from "../i18n/index.js";
import { ThemeManager } from "../styles/theme.js";
import type { ConnectedWallet, ConnectedAccount } from "@tos/connect";

// jsdom does not implement matchMedia; stub it globally
beforeEach(() => {
  Object.defineProperty(window, "matchMedia", {
    writable: true,
    configurable: true,
    value: vi.fn().mockImplementation((query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createMockCallbacks(overrides: Partial<ConnectButtonCallbacks> = {}): ConnectButtonCallbacks {
  return {
    onClickDisconnected: vi.fn(),
    onClickConnected: vi.fn(),
    onDisconnect: vi.fn(),
    getWallet: vi.fn().mockReturnValue(null),
    getAccount: vi.fn().mockReturnValue(null),
    getFriendlyAddress: vi.fn().mockReturnValue("EQBvW8Z5nAbcdef0123456789"),
    getBalance: vi.fn().mockReturnValue(null),
    ...overrides,
  };
}

function createMockWallet(): ConnectedWallet {
  return {
    device: {
      platform: "browser",
      appName: "TOS Wallet",
      appVersion: "1.0.0",
      maxProtocolVersion: 2,
      features: [],
    },
    account: {
      address: "0:abc123def456",
      chain: "-239",
      publicKey: "aabbccdd",
    },
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ConnectButton", () => {
  let container: HTMLDivElement;
  let i18n: I18nManager;
  let theme: ThemeManager;

  beforeEach(() => {
    container = document.createElement("div");
    container.id = "test-button-root";
    document.body.appendChild(container);
    i18n = new I18nManager("en");
    theme = new ThemeManager("light");
  });

  afterEach(() => {
    container.remove();
  });

  // -------------------------------------------------------------------------
  // Mount & render
  // -------------------------------------------------------------------------

  describe("mount", () => {
    it("renders a button inside the container", () => {
      const cb = new ConnectButton(i18n, theme, createMockCallbacks());
      cb.mount(container);

      const host = container.querySelector("[data-tos-connect-button]");
      expect(host).not.toBeNull();

      const shadow = host!.shadowRoot;
      expect(shadow).not.toBeNull();

      const button = shadow!.querySelector(".tos-connect-button");
      expect(button).not.toBeNull();

      cb.destroy();
    });

    it("mounts by string ID", () => {
      const cb = new ConnectButton(i18n, theme, createMockCallbacks());
      cb.mount("test-button-root");

      const host = container.querySelector("[data-tos-connect-button]");
      expect(host).not.toBeNull();

      cb.destroy();
    });

    it('button renders with "Connect Wallet" text when disconnected', () => {
      const cb = new ConnectButton(i18n, theme, createMockCallbacks());
      cb.mount(container);

      const host = container.querySelector("[data-tos-connect-button]")!;
      const button = host.shadowRoot!.querySelector(".tos-connect-button")!;
      expect(button.textContent).toContain("Connect Wallet");

      cb.destroy();
    });

    it("button has the wallet icon SVG when disconnected", () => {
      const cb = new ConnectButton(i18n, theme, createMockCallbacks());
      cb.mount(container);

      const host = container.querySelector("[data-tos-connect-button]")!;
      const icon = host.shadowRoot!.querySelector(".tos-connect-button__icon");
      expect(icon).not.toBeNull();
      expect(icon!.innerHTML).toContain("<svg");

      cb.destroy();
    });
  });

  // -------------------------------------------------------------------------
  // update
  // -------------------------------------------------------------------------

  describe("update", () => {
    it("update(null) keeps the disconnected state", () => {
      const cb = new ConnectButton(i18n, theme, createMockCallbacks());
      cb.mount(container);
      cb.update(null);

      const host = container.querySelector("[data-tos-connect-button]")!;
      const button = host.shadowRoot!.querySelector(".tos-connect-button")!;
      expect(button.textContent).toContain("Connect Wallet");
      expect(button.classList.contains("tos-connect-button--connected")).toBe(false);

      cb.destroy();
    });

    it("update(wallet) switches to connected state with shortened address", () => {
      const wallet = createMockWallet();
      const callbacks = createMockCallbacks({
        getFriendlyAddress: vi.fn().mockReturnValue("EQBvW8Z5nAbcdef0123456789"),
      });
      const cb = new ConnectButton(i18n, theme, callbacks);
      cb.mount(container);
      cb.update(wallet);

      const host = container.querySelector("[data-tos-connect-button]")!;
      const button = host.shadowRoot!.querySelector(".tos-connect-button")!;
      expect(button.classList.contains("tos-connect-button--connected")).toBe(true);

      const addressSpan = host.shadowRoot!.querySelector(".tos-connect-button__address");
      expect(addressSpan).not.toBeNull();
      // "EQBvW8Z5nAbcdef0123456789" shortened = "EQBv...789"
      expect(addressSpan!.textContent).toBe("EQBv...789");

      cb.destroy();
    });

    it("update(wallet) shows balance when available", () => {
      const wallet = createMockWallet();
      const callbacks = createMockCallbacks({
        getFriendlyAddress: vi.fn().mockReturnValue("EQBvW8Z5nAbcdef0123456789"),
        getBalance: vi.fn().mockReturnValue("1500000000"),
      });
      const cb = new ConnectButton(i18n, theme, callbacks);
      cb.mount(container);
      cb.update(wallet);

      const host = container.querySelector("[data-tos-connect-button]")!;
      const balanceSpan = host.shadowRoot!.querySelector(".tos-connect-button__balance");
      expect(balanceSpan).not.toBeNull();
      expect(balanceSpan!.textContent).toBe("1.50 TOS");

      cb.destroy();
    });

    it("update(wallet) does not show balance when null", () => {
      const wallet = createMockWallet();
      const callbacks = createMockCallbacks({
        getFriendlyAddress: vi.fn().mockReturnValue("EQBvW8Z5nAbcdef0123456789"),
        getBalance: vi.fn().mockReturnValue(null),
      });
      const cb = new ConnectButton(i18n, theme, callbacks);
      cb.mount(container);
      cb.update(wallet);

      const host = container.querySelector("[data-tos-connect-button]")!;
      const balanceSpan = host.shadowRoot!.querySelector(".tos-connect-button__balance");
      expect(balanceSpan).toBeNull();

      cb.destroy();
    });
  });

  // -------------------------------------------------------------------------
  // Click behaviour
  // -------------------------------------------------------------------------

  describe("click", () => {
    it("calls onClickDisconnected when disconnected button is clicked", () => {
      const callbacks = createMockCallbacks();
      const cb = new ConnectButton(i18n, theme, callbacks);
      cb.mount(container);

      const host = container.querySelector("[data-tos-connect-button]")!;
      const button = host.shadowRoot!.querySelector(".tos-connect-button") as HTMLButtonElement;
      button.click();

      expect(callbacks.onClickDisconnected).toHaveBeenCalledTimes(1);

      cb.destroy();
    });
  });

  // -------------------------------------------------------------------------
  // destroy
  // -------------------------------------------------------------------------

  describe("destroy", () => {
    it("removes the host element from the DOM", () => {
      const cb = new ConnectButton(i18n, theme, createMockCallbacks());
      cb.mount(container);

      expect(container.querySelector("[data-tos-connect-button]")).not.toBeNull();

      cb.destroy();

      expect(container.querySelector("[data-tos-connect-button]")).toBeNull();
    });

    it("does not throw when called without mount", () => {
      const cb = new ConnectButton(i18n, theme, createMockCallbacks());
      expect(() => cb.destroy()).not.toThrow();
    });

    it("does not throw when called twice", () => {
      const cb = new ConnectButton(i18n, theme, createMockCallbacks());
      cb.mount(container);
      cb.destroy();
      expect(() => cb.destroy()).not.toThrow();
    });
  });
});
