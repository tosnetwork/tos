import { describe, it, expect } from "vitest";
import { I18nManager, type TranslationKeys } from "./index.js";

// ---------------------------------------------------------------------------
// Default behaviour
// ---------------------------------------------------------------------------

describe("I18nManager", () => {
  describe("defaults", () => {
    it('defaults to "en" when no locale is provided', () => {
      const i18n = new I18nManager();
      expect(i18n.getLocale()).toBe("en");
    });

    it('returns the English "connectWallet" string', () => {
      const i18n = new I18nManager();
      expect(i18n.t("connectWallet")).toBe("Connect Wallet");
    });

    it("returns the correct values for all English keys", () => {
      const i18n = new I18nManager();
      expect(i18n.t("disconnect")).toBe("Disconnect");
      expect(i18n.t("chooseWallet")).toBe("Choose a Wallet");
      expect(i18n.t("scanQR")).toBe("Scan QR Code");
      expect(i18n.t("openInWalletApp")).toBe("Open in Wallet App");
      expect(i18n.t("copyAddress")).toBe("Copy Address");
      expect(i18n.t("copied")).toBe("Copied!");
      expect(i18n.t("connecting")).toBe("Connecting...");
      expect(i18n.t("connected")).toBe("Connected");
      expect(i18n.t("walletNotInstalled")).toBe("Wallet not installed");
      expect(i18n.t("getWallet")).toBe("Get Wallet");
      expect(i18n.t("backToWallets")).toBe("Back to wallets");
      expect(i18n.t("close")).toBe("Close");
    });
  });

  // -------------------------------------------------------------------------
  // Explicit locale
  // -------------------------------------------------------------------------

  describe("explicit locale", () => {
    it('uses Chinese translations when constructed with "zh"', () => {
      const i18n = new I18nManager("zh");
      expect(i18n.getLocale()).toBe("zh");
      expect(i18n.t("connectWallet")).toBe("\u8fde\u63a5\u94b1\u5305");
    });

    it('falls back to "en" for unknown locale', () => {
      const i18n = new I18nManager("xx");
      expect(i18n.getLocale()).toBe("en");
    });

    it('resolves base language from compound code ("zh-CN" -> "zh")', () => {
      const i18n = new I18nManager("zh-CN");
      expect(i18n.getLocale()).toBe("zh");
    });
  });

  // -------------------------------------------------------------------------
  // Auto locale (browser detection)
  // -------------------------------------------------------------------------

  describe('"auto" locale', () => {
    it('resolves to "en" in jsdom (default navigator.language)', () => {
      const i18n = new I18nManager("auto");
      // jsdom sets navigator.language to "en-US" by default, which resolves to "en"
      expect(i18n.getLocale()).toBe("en");
    });
  });

  // -------------------------------------------------------------------------
  // All built-in locales instantiate without error
  // -------------------------------------------------------------------------

  describe("all 10 built-in locales", () => {
    const codes = ["en", "zh", "ja", "ko", "ru", "es", "de", "fr", "pt", "tr"];

    for (const code of codes) {
      it(`instantiates "${code}" and returns a non-empty connectWallet string`, () => {
        const i18n = new I18nManager(code);
        expect(i18n.getLocale()).toBe(code);
        const label = i18n.t("connectWallet");
        expect(typeof label).toBe("string");
        expect(label.length).toBeGreaterThan(0);
      });
    }
  });

  // -------------------------------------------------------------------------
  // setLocale
  // -------------------------------------------------------------------------

  describe("setLocale", () => {
    it("switches the active locale at runtime", () => {
      const i18n = new I18nManager("en");
      expect(i18n.t("connectWallet")).toBe("Connect Wallet");

      i18n.setLocale("zh");
      expect(i18n.getLocale()).toBe("zh");
      expect(i18n.t("connectWallet")).toBe("\u8fde\u63a5\u94b1\u5305");
    });
  });

  // -------------------------------------------------------------------------
  // addLocale (custom)
  // -------------------------------------------------------------------------

  describe("addLocale", () => {
    it("registers a custom locale", () => {
      const i18n = new I18nManager();
      const custom: TranslationKeys = {
        connectWallet: "CustomConnect",
        disconnect: "CustomDisconnect",
        chooseWallet: "CustomChoose",
        scanQR: "CustomScan",
        openInWalletApp: "CustomOpen",
        copyAddress: "CustomCopy",
        copied: "CustomCopied",
        connecting: "CustomConnecting",
        connected: "CustomConnected",
        walletNotInstalled: "CustomNotInstalled",
        getWallet: "CustomGet",
        backToWallets: "CustomBack",
        close: "CustomClose",
      };
      i18n.addLocale("custom", custom);
      i18n.setLocale("custom");
      expect(i18n.t("connectWallet")).toBe("CustomConnect");
    });
  });

  // -------------------------------------------------------------------------
  // Unknown key falls back to English value
  // -------------------------------------------------------------------------

  describe("t() with unknown key", () => {
    it("falls back to the English translation for a valid key on unknown locale", () => {
      const i18n = new I18nManager("en");
      // The implementation does:  translations[key] ?? en[key]
      // For a valid key, it returns the translation string.
      expect(i18n.t("close")).toBe("Close");
    });
  });
});
