import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { ConnectModal, type ConnectModalCallbacks } from "./ConnectModal.js";
import { I18nManager } from "../i18n/index.js";
import { ThemeManager } from "../styles/theme.js";
import type { WalletInfo } from "@tos/connect";

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

const MOCK_WALLETS: WalletInfo[] = [
  {
    name: "TOS Wallet",
    appName: "toswallet",
    imageUrl: "https://wallet.tos.network/assets/icon.png",
    platforms: ["ios", "android", "chrome"],
    universalLink: "https://wallet.tos.network/connect",
    bridgeUrl: "https://bridge.tos.network/bridge",
    jsBridgeKey: "tosWallet",
  },
  {
    name: "TOS Keeper",
    appName: "toskeeper",
    imageUrl: "https://keeper.tos.network/assets/icon.png",
    platforms: ["ios", "android"],
    universalLink: "https://keeper.tos.network/connect",
    bridgeUrl: "https://bridge.tos.network/bridge",
    jsBridgeKey: "tosKeeper",
  },
];

function createMockCallbacks(overrides: Partial<ConnectModalCallbacks> = {}): ConnectModalCallbacks {
  return {
    onSelectWallet: vi.fn(),
    onClose: vi.fn(),
    getUniversalLink: vi.fn().mockReturnValue("https://wallet.tos.network/connect?v=2&id=abc&r={}"),
    ...overrides,
  };
}

function createModal(
  callbacks?: Partial<ConnectModalCallbacks>,
  wallets?: WalletInfo[],
): ConnectModal {
  return new ConnectModal(
    new I18nManager("en"),
    new ThemeManager("light"),
    wallets ?? MOCK_WALLETS,
    createMockCallbacks(callbacks),
  );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("ConnectModal", () => {
  afterEach(() => {
    // Clean up any modals left in the DOM
    document.querySelectorAll("[data-tos-connect-modal]").forEach((el) => el.remove());
    document.body.style.overflow = "";
  });

  // -------------------------------------------------------------------------
  // Construction
  // -------------------------------------------------------------------------

  describe("constructor", () => {
    it("creates a modal instance", () => {
      const modal = createModal();
      expect(modal).toBeDefined();
      expect(modal.isOpen).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // open
  // -------------------------------------------------------------------------

  describe("open", () => {
    it("adds the host element to document.body", () => {
      const modal = createModal();
      modal.open();

      const host = document.querySelector("[data-tos-connect-modal]");
      expect(host).not.toBeNull();

      modal.destroy();
    });

    it("sets isOpen to true", () => {
      const modal = createModal();
      modal.open();
      expect(modal.isOpen).toBe(true);
      modal.destroy();
    });

    it("has a shadow root with an overlay", () => {
      const modal = createModal();
      modal.open();

      const host = document.querySelector("[data-tos-connect-modal]")!;
      const shadow = host.shadowRoot;
      expect(shadow).not.toBeNull();

      const overlay = shadow!.querySelector(".tos-modal-overlay");
      expect(overlay).not.toBeNull();

      modal.destroy();
    });

    it("renders the wallet list view initially", () => {
      const modal = createModal();
      modal.open();
      expect(modal.view).toBe("wallets");
      modal.destroy();
    });

    it("renders wallet items with their names", () => {
      const modal = createModal();
      modal.open();

      const host = document.querySelector("[data-tos-connect-modal]")!;
      const shadow = host.shadowRoot!;
      const walletNames = shadow.querySelectorAll(".tos-wallet-item__name");

      expect(walletNames.length).toBe(MOCK_WALLETS.length);
      expect(walletNames[0]!.textContent).toBe("TOS Wallet");
      expect(walletNames[1]!.textContent).toBe("TOS Keeper");

      modal.destroy();
    });

    it("renders a close button", () => {
      const modal = createModal();
      modal.open();

      const host = document.querySelector("[data-tos-connect-modal]")!;
      const closeBtn = host.shadowRoot!.querySelector(".tos-modal__close-btn");
      expect(closeBtn).not.toBeNull();

      modal.destroy();
    });

    it("sets overflow hidden on body to prevent scroll", () => {
      const modal = createModal();
      modal.open();
      expect(document.body.style.overflow).toBe("hidden");
      modal.destroy();
    });

    it("does not open twice", () => {
      const modal = createModal();
      modal.open();
      modal.open(); // should be a no-op

      const hosts = document.querySelectorAll("[data-tos-connect-modal]");
      expect(hosts.length).toBe(1);

      modal.destroy();
    });

    it("sets ARIA attributes on the overlay", () => {
      const modal = createModal();
      modal.open();

      const host = document.querySelector("[data-tos-connect-modal]")!;
      const overlay = host.shadowRoot!.querySelector(".tos-modal-overlay")!;
      expect(overlay.getAttribute("role")).toBe("dialog");
      expect(overlay.getAttribute("aria-modal")).toBe("true");
      expect(overlay.getAttribute("aria-label")).toBe("Choose a Wallet");

      modal.destroy();
    });
  });

  // -------------------------------------------------------------------------
  // close
  // -------------------------------------------------------------------------

  describe("close", () => {
    it("removes the host from the DOM after closing", async () => {
      const modal = createModal();
      modal.open();
      expect(modal.isOpen).toBe(true);

      await modal.close();
      expect(modal.isOpen).toBe(false);

      const host = document.querySelector("[data-tos-connect-modal]");
      expect(host).toBeNull();
    });

    it("does not throw when closing an already-closed modal", async () => {
      const modal = createModal();
      await expect(modal.close()).resolves.toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // destroy
  // -------------------------------------------------------------------------

  describe("destroy", () => {
    it("cleans up the DOM", () => {
      const modal = createModal();
      modal.open();
      modal.destroy();

      const host = document.querySelector("[data-tos-connect-modal]");
      expect(host).toBeNull();
      expect(modal.isOpen).toBe(false);
    });

    it("does not throw on double destroy", () => {
      const modal = createModal();
      modal.open();
      modal.destroy();
      expect(() => modal.destroy()).not.toThrow();
    });

    it("does not throw when called without open", () => {
      const modal = createModal();
      expect(() => modal.destroy()).not.toThrow();
    });
  });

  // -------------------------------------------------------------------------
  // Wallet selection callback
  // -------------------------------------------------------------------------

  describe("wallet selection", () => {
    it("calls onSelectWallet when a wallet item is clicked", () => {
      const onSelectWallet = vi.fn();
      const modal = createModal({ onSelectWallet });
      modal.open();

      const host = document.querySelector("[data-tos-connect-modal]")!;
      const items = host.shadowRoot!.querySelectorAll(".tos-wallet-item");
      expect(items.length).toBeGreaterThan(0);

      (items[0] as HTMLElement).click();
      expect(onSelectWallet).toHaveBeenCalledTimes(1);
      expect(onSelectWallet).toHaveBeenCalledWith(MOCK_WALLETS[0]);

      modal.destroy();
    });

    it("calls onSelectWallet via keyboard Enter", () => {
      const onSelectWallet = vi.fn();
      const modal = createModal({ onSelectWallet });
      modal.open();

      const host = document.querySelector("[data-tos-connect-modal]")!;
      const items = host.shadowRoot!.querySelectorAll(".tos-wallet-item");
      const item = items[0] as HTMLElement;

      item.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
      expect(onSelectWallet).toHaveBeenCalledTimes(1);

      modal.destroy();
    });
  });

  // -------------------------------------------------------------------------
  // Close button callback
  // -------------------------------------------------------------------------

  describe("close button", () => {
    it("calls onClose when close button is clicked", () => {
      const onClose = vi.fn();
      const modal = createModal({ onClose });
      modal.open();

      const host = document.querySelector("[data-tos-connect-modal]")!;
      const closeBtn = host.shadowRoot!.querySelector(".tos-modal__close-btn") as HTMLElement;
      closeBtn.click();

      expect(onClose).toHaveBeenCalledTimes(1);

      modal.destroy();
    });
  });

  // -------------------------------------------------------------------------
  // Escape key
  // -------------------------------------------------------------------------

  describe("escape key", () => {
    it("calls onClose when Escape is pressed", () => {
      const onClose = vi.fn();
      const modal = createModal({ onClose });
      modal.open();

      document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
      expect(onClose).toHaveBeenCalledTimes(1);

      modal.destroy();
    });
  });

  // -------------------------------------------------------------------------
  // QR code view
  // -------------------------------------------------------------------------

  describe("showQRCode", () => {
    it("switches to QR view and renders SVG", () => {
      const modal = createModal();
      modal.open();

      modal.showQRCode(MOCK_WALLETS[0]!, "https://wallet.tos.network/connect?v=2");
      expect(modal.view).toBe("qr");
      expect(modal.activeWallet).toBe(MOCK_WALLETS[0]);

      const host = document.querySelector("[data-tos-connect-modal]")!;
      const qrContainer = host.shadowRoot!.querySelector(".tos-qr-view__container");
      expect(qrContainer).not.toBeNull();
      expect(qrContainer!.innerHTML).toContain("<svg");

      // Shows the hint text
      const hint = host.shadowRoot!.querySelector(".tos-qr-view__hint");
      expect(hint).not.toBeNull();
      expect(hint!.textContent).toBe("Scan QR Code");

      // Shows the back button
      const backBtn = host.shadowRoot!.querySelector(".tos-modal__back-btn") as HTMLElement;
      expect(backBtn.style.display).not.toBe("none");

      modal.destroy();
    });
  });

  // -------------------------------------------------------------------------
  // Connecting view
  // -------------------------------------------------------------------------

  describe("showConnecting", () => {
    it("switches to connecting view with spinner", () => {
      const modal = createModal();
      modal.open();

      modal.showConnecting(MOCK_WALLETS[0]!);
      expect(modal.view).toBe("connecting");

      const host = document.querySelector("[data-tos-connect-modal]")!;
      const spinner = host.shadowRoot!.querySelector(".tos-connecting__spinner");
      expect(spinner).not.toBeNull();

      const text = host.shadowRoot!.querySelector(".tos-connecting__text");
      expect(text).not.toBeNull();
      expect(text!.textContent).toBe("Connecting...");

      modal.destroy();
    });
  });

  // -------------------------------------------------------------------------
  // Title updates
  // -------------------------------------------------------------------------

  describe("title updates", () => {
    it('shows "Choose a Wallet" as initial title', () => {
      const modal = createModal();
      modal.open();

      const host = document.querySelector("[data-tos-connect-modal]")!;
      const title = host.shadowRoot!.querySelector(".tos-modal__title");
      expect(title!.textContent).toBe("Choose a Wallet");

      modal.destroy();
    });

    it("shows the wallet name as title in QR view", () => {
      const modal = createModal();
      modal.open();
      modal.showQRCode(MOCK_WALLETS[0]!, "https://link");

      const host = document.querySelector("[data-tos-connect-modal]")!;
      const title = host.shadowRoot!.querySelector(".tos-modal__title");
      expect(title!.textContent).toBe("TOS Wallet");

      modal.destroy();
    });
  });
});
