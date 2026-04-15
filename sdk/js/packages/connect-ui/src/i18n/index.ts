/**
 * Internationalization manager for @tos/connect-ui.
 *
 * Ships with 10 built-in locales. The active locale can be switched at
 * runtime, and custom translations can be registered via `addLocale()`.
 */

import { en } from "./locales/en.js";
import { zh } from "./locales/zh.js";
import { ja } from "./locales/ja.js";
import { ko } from "./locales/ko.js";
import { ru } from "./locales/ru.js";
import { es } from "./locales/es.js";
import { de } from "./locales/de.js";
import { fr } from "./locales/fr.js";
import { pt } from "./locales/pt.js";
import { tr } from "./locales/tr.js";

// ---------------------------------------------------------------------------
// Translation key interface
// ---------------------------------------------------------------------------

export interface TranslationKeys {
  connectWallet: string;
  disconnect: string;
  chooseWallet: string;
  scanQR: string;
  openInWalletApp: string;
  copyAddress: string;
  copied: string;
  connecting: string;
  connected: string;
  walletNotInstalled: string;
  getWallet: string;
  backToWallets: string;
  close: string;
}

export type LocaleCode = string;

// ---------------------------------------------------------------------------
// Built-in locale registry
// ---------------------------------------------------------------------------

const builtInLocales: Record<string, TranslationKeys> = {
  en,
  zh,
  ja,
  ko,
  ru,
  es,
  de,
  fr,
  pt,
  tr,
};

// ---------------------------------------------------------------------------
// I18nManager
// ---------------------------------------------------------------------------

export class I18nManager {
  private locales: Record<string, TranslationKeys>;
  private currentLocale: string;

  constructor(locale?: string) {
    this.locales = { ...builtInLocales };
    this.currentLocale = this.resolveLocale(locale);
  }

  /**
   * Resolve a locale string to the best available match.
   * Falls back to `en` if nothing matches.
   */
  private resolveLocale(locale?: string): string {
    if (!locale || locale === "auto") {
      return this.detectBrowserLocale();
    }
    // Exact match
    if (this.locales[locale]) {
      return locale;
    }
    // Try base language (e.g. "zh-CN" -> "zh")
    const base = locale.split("-")[0];
    if (base && this.locales[base]) {
      return base;
    }
    return "en";
  }

  /**
   * Detect locale from browser `navigator.languages` or `navigator.language`.
   */
  private detectBrowserLocale(): string {
    if (typeof navigator === "undefined") {
      return "en";
    }
    const candidates = navigator.languages ?? [navigator.language];
    for (const lang of candidates) {
      const code = lang.toLowerCase();
      if (this.locales[code]) return code;
      const base = code.split("-")[0];
      if (base && this.locales[base]) return base;
    }
    return "en";
  }

  /** Get a translated string by key. */
  t(key: keyof TranslationKeys): string {
    const translations = this.locales[this.currentLocale] ?? this.locales["en"]!;
    return translations[key] ?? en[key];
  }

  /** Change the active locale. */
  setLocale(locale: string): void {
    this.currentLocale = this.resolveLocale(locale);
  }

  /** Get the current locale code. */
  getLocale(): string {
    return this.currentLocale;
  }

  /** Register a custom locale or override an existing one. */
  addLocale(code: string, translations: TranslationKeys): void {
    this.locales[code] = translations;
  }
}
