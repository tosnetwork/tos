import { describe, it, expect, vi, afterEach } from "vitest";
import { defaultWallets, fetchWalletList } from "./wallets.js";
import type { WalletInfo } from "./types.js";

// ---------------------------------------------------------------------------
// defaultWallets
// ---------------------------------------------------------------------------

describe("defaultWallets", () => {
  it("is a non-empty array", () => {
    expect(Array.isArray(defaultWallets)).toBe(true);
    expect(defaultWallets.length).toBeGreaterThan(0);
  });

  it("each wallet has required fields", () => {
    for (const wallet of defaultWallets) {
      expect(typeof wallet.name).toBe("string");
      expect(wallet.name.length).toBeGreaterThan(0);

      expect(typeof wallet.appName).toBe("string");
      expect(wallet.appName.length).toBeGreaterThan(0);

      expect(typeof wallet.imageUrl).toBe("string");
      expect(wallet.imageUrl.length).toBeGreaterThan(0);

      expect(Array.isArray(wallet.platforms)).toBe(true);
      expect(wallet.platforms.length).toBeGreaterThan(0);
    }
  });

  it("contains TOS Wallet", () => {
    const tos = defaultWallets.find((w) => w.appName === "toswallet");
    expect(tos).toBeDefined();
    expect(tos!.name).toBe("TOS Wallet");
  });
});

// ---------------------------------------------------------------------------
// fetchWalletList
// ---------------------------------------------------------------------------

describe("fetchWalletList", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("without URL returns a copy of defaultWallets", async () => {
    const wallets = await fetchWalletList();
    expect(wallets).toEqual(defaultWallets);
    // Should be a copy, not the same reference
    expect(wallets).not.toBe(defaultWallets);
  });

  it("with fetch mock returns merged list", async () => {
    const remoteWallet: WalletInfo = {
      name: "Remote Wallet",
      appName: "remotewallet",
      imageUrl: "https://example.com/icon.png",
      platforms: ["web"],
    };

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => [remoteWallet],
    });

    const wallets = await fetchWalletList("https://example.com/wallets.json");

    expect(wallets.length).toBeGreaterThanOrEqual(2);
    expect(wallets.some((w) => w.appName === "remotewallet")).toBe(true);
    expect(wallets.some((w) => w.appName === "toswallet")).toBe(true);
  });

  it("deduplicates by appName (remote takes precedence)", async () => {
    const updatedTosWallet: WalletInfo = {
      name: "TOS Wallet Updated",
      appName: "toswallet",
      imageUrl: "https://wallet.tos.network/icon-v2.png",
      platforms: ["ios", "android", "chrome", "web", "firefox"],
    };

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => [updatedTosWallet],
    });

    const wallets = await fetchWalletList("https://example.com/wallets.json");

    // toswallet should appear only once
    const tosEntries = wallets.filter((w) => w.appName === "toswallet");
    expect(tosEntries).toHaveLength(1);

    // The remote version should take precedence
    expect(tosEntries[0]!.name).toBe("TOS Wallet Updated");
  });

  it("returns defaultWallets on fetch failure", async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error("Network error"));

    const wallets = await fetchWalletList("https://example.com/wallets.json");
    expect(wallets).toEqual(defaultWallets);
  });

  it("returns defaultWallets on non-ok response", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      statusText: "Internal Server Error",
    });

    const wallets = await fetchWalletList("https://example.com/wallets.json");
    expect(wallets).toEqual(defaultWallets);
  });

  it("returns defaultWallets when remote returns non-array", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ wallets: [] }),
    });

    const wallets = await fetchWalletList("https://example.com/wallets.json");
    expect(wallets).toEqual(defaultWallets);
  });

  it("passes signal to fetch", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => [],
    });
    globalThis.fetch = mockFetch;

    const controller = new AbortController();
    await fetchWalletList("https://example.com/wallets.json", controller.signal);

    expect(mockFetch).toHaveBeenCalledWith(
      "https://example.com/wallets.json",
      expect.objectContaining({ signal: controller.signal }),
    );
  });
});
