import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { TosConnectUI } from "./TosConnectUI.js";

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

  // Stub fetch globally to prevent actual network calls (balance polling)
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
    ok: false,
    json: async () => ({}),
  }));
});

afterEach(() => {
  vi.restoreAllMocks();
});

function createUI(overrides: Record<string, unknown> = {}): TosConnectUI {
  return new TosConnectUI({
    manifestUrl: "https://myapp.com/manifest.json",
    ...overrides,
  });
}

describe("TosConnectUI", () => {
  // -------------------------------------------------------------------------
  // Construction
  // -------------------------------------------------------------------------

  describe("constructor", () => {
    it("creates an instance with manifestUrl", () => {
      const ui = createUI();
      expect(ui).toBeDefined();
      ui.destroy();
    });

    it("accepts optional theme, language, and bridgeUrl", () => {
      const ui = createUI({
        theme: "dark",
        language: "zh",
        bridgeUrl: "https://bridge.example.com/bridge",
      });
      expect(ui).toBeDefined();
      ui.destroy();
    });
  });

  // -------------------------------------------------------------------------
  // Initial state
  // -------------------------------------------------------------------------

  describe("initial state", () => {
    it("connected is false", () => {
      const ui = createUI();
      expect(ui.connected).toBe(false);
      ui.destroy();
    });

    it("account is null", () => {
      const ui = createUI();
      expect(ui.account).toBe(null);
      ui.destroy();
    });

    it("wallet is null", () => {
      const ui = createUI();
      expect(ui.wallet).toBe(null);
      ui.destroy();
    });

    it('modalState is "closed"', () => {
      const ui = createUI();
      expect(ui.modalState).toBe("closed");
      ui.destroy();
    });
  });

  // -------------------------------------------------------------------------
  // onStatusChange
  // -------------------------------------------------------------------------

  describe("onStatusChange", () => {
    it("returns an unsubscribe function", () => {
      const ui = createUI();
      const unsubscribe = ui.onStatusChange(() => {});
      expect(typeof unsubscribe).toBe("function");
      unsubscribe();
      ui.destroy();
    });

    it("callback is invoked on disconnect", async () => {
      const ui = createUI();
      const cb = vi.fn();
      ui.onStatusChange(cb);
      await ui.disconnect();
      expect(cb).toHaveBeenCalledWith(null);
      ui.destroy();
    });

    it("unsubscribe stops future notifications", async () => {
      const ui = createUI();
      const cb = vi.fn();
      const unsub = ui.onStatusChange(cb);
      unsub();
      await ui.disconnect();
      expect(cb).not.toHaveBeenCalled();
      ui.destroy();
    });
  });

  // -------------------------------------------------------------------------
  // onModalStateChange
  // -------------------------------------------------------------------------

  describe("onModalStateChange", () => {
    it("returns an unsubscribe function", () => {
      const ui = createUI();
      const unsubscribe = ui.onModalStateChange(() => {});
      expect(typeof unsubscribe).toBe("function");
      unsubscribe();
      ui.destroy();
    });

    it("callback is invoked when modal opens", () => {
      const ui = createUI();
      const cb = vi.fn();
      ui.onModalStateChange(cb);
      ui.openModal();
      expect(cb).toHaveBeenCalledWith("opened");
      ui.closeModal();
      ui.destroy();
    });

    it("callback is invoked when modal closes", () => {
      const ui = createUI();
      const cb = vi.fn();
      ui.onModalStateChange(cb);
      ui.openModal();
      ui.closeModal();
      expect(cb).toHaveBeenCalledWith("closed");
      ui.destroy();
    });
  });

  // -------------------------------------------------------------------------
  // getWallets
  // -------------------------------------------------------------------------

  describe("getWallets", () => {
    it("returns a non-empty array", async () => {
      const ui = createUI();
      const wallets = await ui.getWallets();
      expect(Array.isArray(wallets)).toBe(true);
      expect(wallets.length).toBeGreaterThan(0);
      ui.destroy();
    });

    it("includes default wallets (TOS Wallet, TOS Keeper, TOS Hub)", async () => {
      const ui = createUI();
      const wallets = await ui.getWallets();
      const names = wallets.map((w) => w.name);
      expect(names).toContain("TOS Wallet");
      expect(names).toContain("TOS Keeper");
      expect(names).toContain("TOS Hub");
      ui.destroy();
    });

    it("includes custom wallets when provided", async () => {
      const ui = createUI({
        wallets: [
          {
            name: "Custom Wallet",
            appName: "customwallet",
            imageUrl: "https://custom.example/icon.png",
            platforms: ["web"],
          },
        ],
      });
      const wallets = await ui.getWallets();
      const names = wallets.map((w) => w.name);
      expect(names).toContain("Custom Wallet");
      ui.destroy();
    });
  });

  // -------------------------------------------------------------------------
  // Modal open / close
  // -------------------------------------------------------------------------

  describe("modal open/close", () => {
    it("openModal sets modalState to opened", () => {
      const ui = createUI();
      ui.openModal();
      expect(ui.modalState).toBe("opened");
      ui.closeModal();
      ui.destroy();
    });

    it("closeModal sets modalState to closed", () => {
      const ui = createUI();
      ui.openModal();
      ui.closeModal();
      expect(ui.modalState).toBe("closed");
      ui.destroy();
    });

    it("openModal is idempotent (does not re-open if already open)", () => {
      const ui = createUI();
      const cb = vi.fn();
      ui.onModalStateChange(cb);
      ui.openModal();
      ui.openModal(); // second call should be ignored
      // Only one "opened" notification
      expect(cb).toHaveBeenCalledTimes(1);
      ui.closeModal();
      ui.destroy();
    });
  });

  // -------------------------------------------------------------------------
  // destroy
  // -------------------------------------------------------------------------

  describe("destroy", () => {
    it("does not throw", () => {
      const ui = createUI();
      expect(() => ui.destroy()).not.toThrow();
    });

    it("calling destroy twice does not throw", () => {
      const ui = createUI();
      ui.destroy();
      expect(() => ui.destroy()).not.toThrow();
    });

    it("methods throw after destroy", async () => {
      const ui = createUI();
      ui.destroy();

      expect(() => ui.openModal()).toThrow(/destroyed/i);
      expect(() => ui.onStatusChange(() => {})).not.toThrow(); // callbacks don't call ensureNotDestroyed
      await expect(ui.getWallets()).rejects.toThrow(/destroyed/i);
    });

    it("connect throws after destroy", () => {
      const ui = createUI();
      ui.destroy();
      expect(() =>
        ui.connect({
          name: "Test",
          appName: "test",
          imageUrl: "",
          platforms: [],
        }),
      ).toThrow(/destroyed/i);
    });

    it("disconnect throws after destroy", async () => {
      const ui = createUI();
      ui.destroy();
      await expect(ui.disconnect()).rejects.toThrow(/destroyed/i);
    });

    it("sendTransaction throws after destroy", async () => {
      const ui = createUI();
      ui.destroy();
      await expect(
        ui.sendTransaction({
          validUntil: 0,
          messages: [],
        }),
      ).rejects.toThrow(/destroyed/i);
    });
  });

  // -------------------------------------------------------------------------
  // sendTransaction without connection
  // -------------------------------------------------------------------------

  describe("sendTransaction", () => {
    it("throws when no wallet is connected", async () => {
      const ui = createUI();
      await expect(
        ui.sendTransaction({ validUntil: 0, messages: [] }),
      ).rejects.toThrow(/No wallet connected/);
      ui.destroy();
    });
  });

  // -------------------------------------------------------------------------
  // restoreConnection
  // -------------------------------------------------------------------------

  describe("restoreConnection", () => {
    it("does not throw when no session is stored", async () => {
      const ui = createUI();
      await expect(ui.restoreConnection()).resolves.toBeUndefined();
      ui.destroy();
    });
  });

  // -------------------------------------------------------------------------
  // Mount button
  // -------------------------------------------------------------------------

  describe("button mount", () => {
    it("mounts a button when buttonRootId is provided and element exists", () => {
      const root = document.createElement("div");
      root.id = "tos-btn-root";
      document.body.appendChild(root);

      const ui = createUI({ buttonRootId: "tos-btn-root" });
      // The button host is appended inside the root
      const host = root.querySelector("[data-tos-connect-button]");
      expect(host).not.toBeNull();

      ui.destroy();
      root.remove();
    });

    it("does not throw when buttonRootId element is missing", () => {
      expect(() => createUI({ buttonRootId: "nonexistent-id" })).not.toThrow();
    });
  });
});
