/**
 * DOM helpers and address formatting utilities for @tos/connect-ui.
 */

// ---------------------------------------------------------------------------
// SSR guard
// ---------------------------------------------------------------------------

/** Returns `true` when running in a browser with DOM access. */
export function isBrowser(): boolean {
  return typeof document !== "undefined" && typeof window !== "undefined";
}

// ---------------------------------------------------------------------------
// DOM helpers
// ---------------------------------------------------------------------------

/** Create an element with optional class names and attributes. */
export function createElement<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  classNames?: string | string[],
  attributes?: Record<string, string>,
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  if (classNames) {
    const names = Array.isArray(classNames) ? classNames : [classNames];
    el.classList.add(...names);
  }
  if (attributes) {
    for (const [key, value] of Object.entries(attributes)) {
      el.setAttribute(key, value);
    }
  }
  return el;
}

/** Append one or more children to a parent element. */
export function appendChildren(parent: Element, ...children: (Element | string)[]): void {
  for (const child of children) {
    if (typeof child === "string") {
      parent.appendChild(document.createTextNode(child));
    } else {
      parent.appendChild(child);
    }
  }
}

/** Remove all children from an element. */
export function clearElement(el: Element): void {
  while (el.firstChild) {
    el.removeChild(el.firstChild);
  }
}

// ---------------------------------------------------------------------------
// Address formatting
// ---------------------------------------------------------------------------

/**
 * Shorten an address for display: first 4 + last 3 characters.
 * e.g. "EQBvW8Z5n..." -> "EQBv...Z5n"
 */
export function shortenAddress(address: string, prefixLen = 4, suffixLen = 3): string {
  if (address.length <= prefixLen + suffixLen + 3) {
    return address;
  }
  return `${address.slice(0, prefixLen)}...${address.slice(-suffixLen)}`;
}

/**
 * Format a nanotomis balance to a human-readable string.
 * e.g. 1234567890000n -> "1,234.57"
 */
export function formatBalance(nanotomis: string | bigint, decimals = 2): string {
  const value = typeof nanotomis === "string" ? BigInt(nanotomis) : nanotomis;
  const NANO = 1_000_000_000n;
  const absValue = value < 0n ? -value : value;
  const whole = value / NANO;
  const frac = absValue % NANO;

  const wholeStr = whole.toLocaleString("en-US");

  if (decimals === 0) {
    return wholeStr;
  }

  const fracStr = frac.toString().padStart(9, "0").slice(0, decimals);
  return `${wholeStr}.${fracStr}`;
}

// ---------------------------------------------------------------------------
// Clipboard
// ---------------------------------------------------------------------------

/**
 * Copy text to the clipboard. Falls back to `execCommand` for older browsers.
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard) {
      await navigator.clipboard.writeText(text);
      return true;
    }
    // Fallback for HTTP or older browsers
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.style.position = "fixed";
    textarea.style.left = "-9999px";
    textarea.style.top = "-9999px";
    document.body.appendChild(textarea);
    textarea.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(textarea);
    return ok;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

/** Simple unique ID generator for DOM elements. */
let idCounter = 0;
export function uniqueId(prefix = "tos"): string {
  return `${prefix}-${++idCounter}-${Math.random().toString(36).slice(2, 7)}`;
}

/** Detect if the user prefers dark mode. */
export function prefersDarkMode(): boolean {
  if (!isBrowser()) return false;
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

/** Wait for a given number of milliseconds. */
export function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
