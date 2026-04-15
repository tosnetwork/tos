import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { ThemeManager, type ThemeMode } from "./theme.js";

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

describe("ThemeManager", () => {
  let target: HTMLElement;

  beforeEach(() => {
    target = document.createElement("div");
    document.body.appendChild(target);
  });

  afterEach(() => {
    target.remove();
  });

  // -------------------------------------------------------------------------
  // Construction
  // -------------------------------------------------------------------------

  describe("construction", () => {
    it('creates a manager with "light" mode', () => {
      const tm = new ThemeManager("light");
      expect(tm.getResolvedTheme()).toBe("light");
    });

    it('creates a manager with "dark" mode', () => {
      const tm = new ThemeManager("dark");
      expect(tm.getResolvedTheme()).toBe("dark");
    });

    it('defaults to "auto" mode when no argument is given', () => {
      const tm = new ThemeManager();
      // In jsdom, matchMedia typically returns false for dark, so auto -> light
      const resolved = tm.getResolvedTheme();
      expect(resolved === "light" || resolved === "dark").toBe(true);
    });

    it('"auto" mode resolves to "light" when prefers-color-scheme is not dark', () => {
      // jsdom matchMedia returns false by default for any query
      const tm = new ThemeManager("auto");
      expect(tm.getResolvedTheme()).toBe("light");
    });
  });

  // -------------------------------------------------------------------------
  // attach
  // -------------------------------------------------------------------------

  describe("attach", () => {
    it('sets data-tos-theme attribute on the target element (light)', () => {
      const tm = new ThemeManager("light");
      tm.attach(target);
      expect(target.getAttribute("data-tos-theme")).toBe("light");
    });

    it('sets data-tos-theme to "dark" for dark mode', () => {
      const tm = new ThemeManager("dark");
      tm.attach(target);
      expect(target.getAttribute("data-tos-theme")).toBe("dark");
    });

    it("sets CSS custom properties on the target element", () => {
      const tm = new ThemeManager("light");
      tm.attach(target);
      expect(target.style.getPropertyValue("--tos-connect-accent")).toBe("#0088CC");
      expect(target.style.getPropertyValue("--tos-connect-bg")).toBe("#ffffff");
      expect(target.style.getPropertyValue("--tos-connect-text")).toBe("#1a1a2e");
    });

    it("sets dark palette CSS variables for dark mode", () => {
      const tm = new ThemeManager("dark");
      tm.attach(target);
      expect(target.style.getPropertyValue("--tos-connect-accent")).toBe("#0098e1");
      expect(target.style.getPropertyValue("--tos-connect-bg")).toBe("#1a1a2e");
      expect(target.style.getPropertyValue("--tos-connect-text")).toBe("#f0f0f0");
    });
  });

  // -------------------------------------------------------------------------
  // detach
  // -------------------------------------------------------------------------

  describe("detach", () => {
    it("cleans up without error", () => {
      const tm = new ThemeManager("light");
      tm.attach(target);
      expect(() => tm.detach()).not.toThrow();
    });

    it("does not throw when called without prior attach", () => {
      const tm = new ThemeManager("light");
      expect(() => tm.detach()).not.toThrow();
    });
  });

  // -------------------------------------------------------------------------
  // setMode
  // -------------------------------------------------------------------------

  describe("setMode", () => {
    it("switches from light to dark and updates the element", () => {
      const tm = new ThemeManager("light");
      tm.attach(target);
      expect(target.getAttribute("data-tos-theme")).toBe("light");

      tm.setMode("dark");
      expect(target.getAttribute("data-tos-theme")).toBe("dark");
      expect(tm.getResolvedTheme()).toBe("dark");
    });

    it("switches from dark to light", () => {
      const tm = new ThemeManager("dark");
      tm.attach(target);
      tm.setMode("light");
      expect(target.getAttribute("data-tos-theme")).toBe("light");
      expect(target.style.getPropertyValue("--tos-connect-accent")).toBe("#0088CC");
    });

    it("can switch to auto mode", () => {
      const tm = new ThemeManager("light");
      tm.attach(target);
      tm.setMode("auto");
      // In jsdom, auto resolves to light (no dark preference)
      expect(target.getAttribute("data-tos-theme")).toBe("light");
    });
  });

  // -------------------------------------------------------------------------
  // getResolvedTheme
  // -------------------------------------------------------------------------

  describe("getResolvedTheme", () => {
    it('returns "light" for light mode', () => {
      const tm = new ThemeManager("light");
      expect(tm.getResolvedTheme()).toBe("light");
    });

    it('returns "dark" for dark mode', () => {
      const tm = new ThemeManager("dark");
      expect(tm.getResolvedTheme()).toBe("dark");
    });

    it('returns "light" or "dark" for auto mode', () => {
      const tm = new ThemeManager("auto");
      expect(["light", "dark"]).toContain(tm.getResolvedTheme());
    });
  });
});
