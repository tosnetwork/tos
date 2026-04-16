import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  isBrowser,
  createElement,
  appendChildren,
  clearElement,
  shortenAddress,
  formatBalance,
  copyToClipboard,
  uniqueId,
  prefersDarkMode,
  delay,
} from "./utils.js";

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
// isBrowser
// ---------------------------------------------------------------------------

describe("isBrowser", () => {
  it("returns true in jsdom", () => {
    expect(isBrowser()).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// prefersDarkMode
// ---------------------------------------------------------------------------

describe("prefersDarkMode", () => {
  it("returns a boolean in jsdom", () => {
    expect(typeof prefersDarkMode()).toBe("boolean");
  });
});

// ---------------------------------------------------------------------------
// createElement
// ---------------------------------------------------------------------------

describe("createElement", () => {
  it("creates an element of the given tag", () => {
    const el = createElement("div");
    expect(el.tagName).toBe("DIV");
  });

  it("applies a single class name", () => {
    const el = createElement("div", "my-class");
    expect(el.classList.contains("my-class")).toBe(true);
  });

  it("applies an array of class names", () => {
    const el = createElement("span", ["cls-a", "cls-b"]);
    expect(el.classList.contains("cls-a")).toBe(true);
    expect(el.classList.contains("cls-b")).toBe(true);
  });

  it("sets attributes when provided", () => {
    const el = createElement("input", undefined, { type: "text", placeholder: "hi" });
    expect(el.getAttribute("type")).toBe("text");
    expect(el.getAttribute("placeholder")).toBe("hi");
  });

  it("applies both class names and attributes together", () => {
    const el = createElement("button", "btn", { disabled: "" });
    expect(el.classList.contains("btn")).toBe(true);
    expect(el.hasAttribute("disabled")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// appendChildren
// ---------------------------------------------------------------------------

describe("appendChildren", () => {
  it("appends Element children", () => {
    const parent = document.createElement("div");
    const child1 = document.createElement("span");
    const child2 = document.createElement("p");
    appendChildren(parent, child1, child2);
    expect(parent.childNodes.length).toBe(2);
    expect(parent.childNodes[0]).toBe(child1);
    expect(parent.childNodes[1]).toBe(child2);
  });

  it("appends string children as text nodes", () => {
    const parent = document.createElement("div");
    appendChildren(parent, "hello");
    expect(parent.childNodes.length).toBe(1);
    expect(parent.childNodes[0]!.textContent).toBe("hello");
    expect(parent.childNodes[0]!.nodeType).toBe(Node.TEXT_NODE);
  });

  it("appends a mix of elements and strings", () => {
    const parent = document.createElement("div");
    const child = document.createElement("span");
    appendChildren(parent, child, "text");
    expect(parent.childNodes.length).toBe(2);
    expect(parent.childNodes[0]).toBe(child);
    expect(parent.childNodes[1]!.textContent).toBe("text");
  });
});

// ---------------------------------------------------------------------------
// clearElement
// ---------------------------------------------------------------------------

describe("clearElement", () => {
  it("removes all children from an element", () => {
    const el = document.createElement("div");
    el.appendChild(document.createElement("span"));
    el.appendChild(document.createElement("p"));
    el.appendChild(document.createTextNode("text"));
    expect(el.childNodes.length).toBe(3);

    clearElement(el);
    expect(el.childNodes.length).toBe(0);
  });

  it("is a no-op on an already-empty element", () => {
    const el = document.createElement("div");
    clearElement(el);
    expect(el.childNodes.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// shortenAddress
// ---------------------------------------------------------------------------

describe("shortenAddress", () => {
  it('shortens "EQBvW8Z5nAbcdef" to first 4 + last 3', () => {
    // "EQBvW8Z5nAbcdef" has 16 chars, > 4+3+3=10, so it gets shortened
    expect(shortenAddress("EQBvW8Z5nAbcdef")).toBe("EQBv...def");
  });

  it("returns the input unchanged when too short to shorten", () => {
    // "short" has 5 chars, <= 4+3+3=10
    expect(shortenAddress("short")).toBe("short");
  });

  it("returns the input unchanged when length equals threshold", () => {
    // Threshold = prefixLen + suffixLen + 3 = 10
    // A string of exactly 10 chars should be returned unchanged (<=)
    expect(shortenAddress("0123456789")).toBe("0123456789");
  });

  it("shortens an 11-char string", () => {
    expect(shortenAddress("01234567890")).toBe("0123...890");
  });

  it("supports custom prefix and suffix lengths", () => {
    expect(shortenAddress("EQBvW8Z5nAbcdef", 6, 4)).toBe("EQBvW8...cdef");
  });
});

// ---------------------------------------------------------------------------
// formatBalance
// ---------------------------------------------------------------------------

describe("formatBalance", () => {
  it('formats "1500000000" to "1.50"', () => {
    expect(formatBalance("1500000000")).toBe("1.50");
  });

  it('formats "0" to "0.00"', () => {
    expect(formatBalance("0")).toBe("0.00");
  });

  it('formats "999000000000" to "999.00"', () => {
    expect(formatBalance("999000000000")).toBe("999.00");
  });

  it("works with bigint input", () => {
    expect(formatBalance(1500000000n)).toBe("1.50");
  });

  it("formats fractional amounts correctly", () => {
    // 1,234,567,890,000 nanotons = 1234.567890000
    expect(formatBalance("1234567890000")).toBe("1,234.56");
  });

  it("supports 0 decimals", () => {
    expect(formatBalance("1500000000", 0)).toBe("1");
  });

  it("supports custom decimal places", () => {
    // 1.5 TOS = 1500000000, fraction = 500000000 -> padded "500000000" -> take 4 -> "5000"
    expect(formatBalance("1500000000", 4)).toBe("1.5000");
  });
});

// ---------------------------------------------------------------------------
// uniqueId
// ---------------------------------------------------------------------------

describe("uniqueId", () => {
  it("returns a string starting with the default prefix", () => {
    const id = uniqueId();
    expect(id.startsWith("tos-")).toBe(true);
  });

  it("returns a string starting with a custom prefix", () => {
    const id = uniqueId("custom");
    expect(id.startsWith("custom-")).toBe(true);
  });

  it("returns unique values on successive calls", () => {
    const a = uniqueId();
    const b = uniqueId();
    expect(a).not.toBe(b);
  });
});

// ---------------------------------------------------------------------------
// delay
// ---------------------------------------------------------------------------

describe("delay", () => {
  it("resolves after the specified time", async () => {
    vi.useFakeTimers();
    const p = delay(100);
    vi.advanceTimersByTime(100);
    await p;
    vi.useRealTimers();
  });
});

// ---------------------------------------------------------------------------
// copyToClipboard
// ---------------------------------------------------------------------------

describe("copyToClipboard", () => {
  it("returns true when clipboard API succeeds", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });

    const result = await copyToClipboard("hello");
    expect(result).toBe(true);
    expect(writeText).toHaveBeenCalledWith("hello");
  });

  it("returns false on error", async () => {
    Object.assign(navigator, {
      clipboard: { writeText: vi.fn().mockRejectedValue(new Error("fail")) },
    });

    const result = await copyToClipboard("hello");
    expect(result).toBe(false);
  });
});
