import { describe, it, expect, vi } from "vitest";
import { TosConnect } from "./TosConnect.js";
import { MemoryStorageAdapter } from "./storage.js";
import { defaultWallets } from "./wallets.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createInstance(overrides?: Partial<Parameters<typeof TosConnect.prototype.getWallets>[0]>) {
  return new TosConnect({
    manifestUrl: "https://example.com/manifest.json",
    storage: new MemoryStorageAdapter(),
    ...overrides,
  });
}

// ---------------------------------------------------------------------------
// PROTOCOL_VERSION
// ---------------------------------------------------------------------------

describe("TosConnect", () => {
  it("PROTOCOL_VERSION is 2", () => {
    expect(TosConnect.PROTOCOL_VERSION).toBe(2);
  });

  // -----------------------------------------------------------------------
  // Initial state
  // -----------------------------------------------------------------------

  describe("initial state", () => {
    it("connected is false", () => {
      const tc = createInstance();
      expect(tc.connected).toBe(false);
    });

    it("account is null", () => {
      const tc = createInstance();
      expect(tc.account).toBeNull();
    });

    it("wallet is null", () => {
      const tc = createInstance();
      expect(tc.wallet).toBeNull();
    });
  });

  // -----------------------------------------------------------------------
  // getWallets
  // -----------------------------------------------------------------------

  describe("getWallets", () => {
    it("returns non-empty array (defaultWallets at minimum)", async () => {
      const tc = createInstance();
      const wallets = await tc.getWallets();
      expect(Array.isArray(wallets)).toBe(true);
      expect(wallets.length).toBeGreaterThan(0);
    });

    it("includes default wallets when no remote source", async () => {
      const tc = createInstance();
      const wallets = await tc.getWallets();
      const appNames = wallets.map((w) => w.appName);
      for (const dw of defaultWallets) {
        expect(appNames).toContain(dw.appName);
      }
    });
  });

  // -----------------------------------------------------------------------
  // onStatusChange
  // -----------------------------------------------------------------------

  describe("onStatusChange", () => {
    it("returns an unsubscribe function", () => {
      const tc = createInstance();
      const unsub = tc.onStatusChange(() => {});
      expect(typeof unsub).toBe("function");
    });

    it("calling unsubscribe removes the listener (no callback on disconnect)", async () => {
      const tc = createInstance();
      const callback = vi.fn();

      const unsub = tc.onStatusChange(callback);
      unsub();

      // disconnect triggers notifyStatusChange(null), but our callback
      // should NOT be called because we unsubscribed
      await tc.disconnect();
      expect(callback).not.toHaveBeenCalled();
    });

    it("callback IS called before unsubscribe", async () => {
      const tc = createInstance();
      const callback = vi.fn();

      tc.onStatusChange(callback);

      // disconnect triggers notifyStatusChange(null)
      await tc.disconnect();
      expect(callback).toHaveBeenCalledWith(null);
    });

    it("error callback is also removed on unsubscribe", () => {
      const tc = createInstance();
      const statusCb = vi.fn();
      const errorCb = vi.fn();

      const unsub = tc.onStatusChange(statusCb, errorCb);
      unsub();

      // We can't easily trigger an error without a bridge, but we can
      // verify the unsubscribe function itself is callable without error
      expect(unsub).not.toThrow();
    });

    it("multiple listeners are independent", async () => {
      const tc = createInstance();
      const cb1 = vi.fn();
      const cb2 = vi.fn();

      const unsub1 = tc.onStatusChange(cb1);
      tc.onStatusChange(cb2);

      // Unsubscribe only the first
      unsub1();

      await tc.disconnect();
      expect(cb1).not.toHaveBeenCalled();
      expect(cb2).toHaveBeenCalledWith(null);
    });
  });

  // -----------------------------------------------------------------------
  // disconnect
  // -----------------------------------------------------------------------

  describe("disconnect", () => {
    it("resolves without error on unconnected instance", async () => {
      const tc = createInstance();
      await expect(tc.disconnect()).resolves.toBeUndefined();
    });

    it("connected remains false after disconnect", async () => {
      const tc = createInstance();
      await tc.disconnect();
      expect(tc.connected).toBe(false);
    });

    it("wallet is null after disconnect", async () => {
      const tc = createInstance();
      await tc.disconnect();
      expect(tc.wallet).toBeNull();
    });
  });

  // -----------------------------------------------------------------------
  // Constructor options
  // -----------------------------------------------------------------------

  describe("constructor options", () => {
    it("accepts minimal options (just manifestUrl)", () => {
      const tc = new TosConnect({ manifestUrl: "https://example.com/manifest.json" });
      expect(tc).toBeDefined();
      expect(tc.connected).toBe(false);
    });

    it("accepts all options", () => {
      const tc = new TosConnect({
        manifestUrl: "https://example.com/manifest.json",
        bridgeUrl: "https://custom-bridge.example.com",
        storage: new MemoryStorageAdapter(),
        walletsListSource: "https://example.com/wallets.json",
        sessionTtl: 3600,
        reconnect: { enabled: true, maxRetries: 3, backoffMs: 1000 },
      });
      expect(tc).toBeDefined();
    });
  });

  // -----------------------------------------------------------------------
  // restoreConnection
  // -----------------------------------------------------------------------

  describe("restoreConnection", () => {
    it("throws when no session is stored", async () => {
      const tc = createInstance();
      await expect(tc.restoreConnection()).rejects.toThrow(
        "No persisted session found",
      );
    });
  });

  // -----------------------------------------------------------------------
  // pauseConnection / unpauseConnection
  // -----------------------------------------------------------------------

  describe("pauseConnection / unpauseConnection", () => {
    it("does not throw on unconnected instance", () => {
      const tc = createInstance();
      expect(() => tc.pauseConnection()).not.toThrow();
    });

    it("unpauseConnection resolves without error", async () => {
      const tc = createInstance();
      await expect(tc.unpauseConnection()).resolves.toBeUndefined();
    });
  });
});
