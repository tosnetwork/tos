/**
 * Theme management for @tos/connect-ui.
 *
 * Applies CSS custom properties and manages the `data-tos-theme` attribute
 * on the connect-ui shadow host. Supports light, dark, and auto (follows
 * system `prefers-color-scheme`).
 */

import { isBrowser, prefersDarkMode } from "../utils.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ThemeMode = "light" | "dark" | "auto";

export interface ThemeColors {
  accent: string;
  bg: string;
  text: string;
  border: string;
  modalBg: string;
  buttonBg: string;
  buttonText: string;
  radius: string;
  secondaryBg: string;
  secondaryText: string;
  hoverBg: string;
  overlay: string;
  shadow: string;
  success: string;
  error: string;
}

// ---------------------------------------------------------------------------
// Default palettes
// ---------------------------------------------------------------------------

const LIGHT_COLORS: ThemeColors = {
  accent: "#0088CC",
  bg: "#ffffff",
  text: "#1a1a2e",
  border: "#e5e7eb",
  modalBg: "#ffffff",
  buttonBg: "#0088CC",
  buttonText: "#ffffff",
  radius: "12px",
  secondaryBg: "#f5f5f7",
  secondaryText: "#6b7280",
  hoverBg: "#f0f0f2",
  overlay: "rgba(0, 0, 0, 0.5)",
  shadow: "0 8px 32px rgba(0, 0, 0, 0.12)",
  success: "#10b981",
  error: "#ef4444",
};

const DARK_COLORS: ThemeColors = {
  accent: "#0098e1",
  bg: "#1a1a2e",
  text: "#f0f0f0",
  border: "#2d2d44",
  modalBg: "#1a1a2e",
  buttonBg: "#0098e1",
  buttonText: "#ffffff",
  radius: "12px",
  secondaryBg: "#232340",
  secondaryText: "#9ca3af",
  hoverBg: "#2d2d44",
  overlay: "rgba(0, 0, 0, 0.7)",
  shadow: "0 8px 32px rgba(0, 0, 0, 0.4)",
  success: "#34d399",
  error: "#f87171",
};

// ---------------------------------------------------------------------------
// ThemeManager
// ---------------------------------------------------------------------------

export class ThemeManager {
  private mode: ThemeMode;
  private mediaQuery: MediaQueryList | null = null;
  private mediaHandler: ((e: MediaQueryListEvent) => void) | null = null;
  private target: HTMLElement | null = null;

  constructor(mode: ThemeMode = "auto") {
    this.mode = mode;
  }

  /** Attach the theme to a shadow host or element. */
  attach(target: HTMLElement): void {
    this.target = target;
    this.applyTheme();

    if (this.mode === "auto" && isBrowser()) {
      this.mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
      this.mediaHandler = () => this.applyTheme();
      this.mediaQuery.addEventListener("change", this.mediaHandler);
    }
  }

  /** Detach event listeners. */
  detach(): void {
    if (this.mediaQuery && this.mediaHandler) {
      this.mediaQuery.removeEventListener("change", this.mediaHandler);
      this.mediaQuery = null;
      this.mediaHandler = null;
    }
    this.target = null;
  }

  /** Change the theme mode at runtime. */
  setMode(mode: ThemeMode): void {
    // Clean up old auto listener
    if (this.mediaQuery && this.mediaHandler) {
      this.mediaQuery.removeEventListener("change", this.mediaHandler);
      this.mediaQuery = null;
      this.mediaHandler = null;
    }

    this.mode = mode;

    if (mode === "auto" && isBrowser()) {
      this.mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
      this.mediaHandler = () => this.applyTheme();
      this.mediaQuery.addEventListener("change", this.mediaHandler);
    }

    this.applyTheme();
  }

  /** Get the currently resolved theme ("light" or "dark"). */
  getResolvedTheme(): "light" | "dark" {
    if (this.mode === "auto") {
      return prefersDarkMode() ? "dark" : "light";
    }
    return this.mode;
  }

  /** Apply CSS custom properties on the target element. */
  private applyTheme(): void {
    if (!this.target) return;

    const resolved = this.getResolvedTheme();
    const colors = resolved === "dark" ? DARK_COLORS : LIGHT_COLORS;

    this.target.setAttribute("data-tos-theme", resolved);

    const style = this.target.style;
    style.setProperty("--tos-connect-accent", colors.accent);
    style.setProperty("--tos-connect-bg", colors.bg);
    style.setProperty("--tos-connect-text", colors.text);
    style.setProperty("--tos-connect-border", colors.border);
    style.setProperty("--tos-connect-modal-bg", colors.modalBg);
    style.setProperty("--tos-connect-button-bg", colors.buttonBg);
    style.setProperty("--tos-connect-button-text", colors.buttonText);
    style.setProperty("--tos-connect-radius", colors.radius);
    style.setProperty("--tos-connect-secondary-bg", colors.secondaryBg);
    style.setProperty("--tos-connect-secondary-text", colors.secondaryText);
    style.setProperty("--tos-connect-hover-bg", colors.hoverBg);
    style.setProperty("--tos-connect-overlay", colors.overlay);
    style.setProperty("--tos-connect-shadow", colors.shadow);
    style.setProperty("--tos-connect-success", colors.success);
    style.setProperty("--tos-connect-error", colors.error);
  }
}
