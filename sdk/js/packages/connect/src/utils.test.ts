import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  toBase64Url,
  fromBase64Url,
  buildUniversalLink,
  generateRequestId,
  randomBytes,
  isBrowser,
  withTimeout,
} from "./utils.js";

// ---------------------------------------------------------------------------
// toBase64Url / fromBase64Url
// ---------------------------------------------------------------------------

describe("toBase64Url / fromBase64Url", () => {
  it("round-trips arbitrary bytes", () => {
    const original = new Uint8Array([0, 1, 2, 255, 128, 64, 32, 16]);
    const encoded = toBase64Url(original);
    const decoded = fromBase64Url(encoded);
    expect(decoded).toEqual(original);
  });

  it("round-trips empty array", () => {
    const original = new Uint8Array(0);
    const encoded = toBase64Url(original);
    const decoded = fromBase64Url(encoded);
    expect(decoded).toEqual(original);
  });

  it("round-trips random 32-byte key", () => {
    const original = randomBytes(32);
    const encoded = toBase64Url(original);
    const decoded = fromBase64Url(encoded);
    expect(decoded).toEqual(original);
  });

  it("produces no +, /, or = characters", () => {
    // Use bytes that in standard base64 would produce +, /, and = padding
    const data = new Uint8Array([251, 255, 254, 63, 62, 61]);
    const encoded = toBase64Url(data);
    expect(encoded).not.toContain("+");
    expect(encoded).not.toContain("/");
    expect(encoded).not.toContain("=");
  });

  it("fromBase64Url handles input with padding", () => {
    // Manually create a padded base64url string
    const original = new Uint8Array([1, 2, 3]);
    const encoded = toBase64Url(original);
    // Add padding manually
    const paddedLength = Math.ceil(encoded.length / 4) * 4;
    const padded = encoded.padEnd(paddedLength, "=");
    const decoded = fromBase64Url(padded);
    expect(decoded).toEqual(original);
  });
});

// ---------------------------------------------------------------------------
// buildUniversalLink
// ---------------------------------------------------------------------------

describe("buildUniversalLink", () => {
  it("produces a valid URL with correct params", () => {
    const link = buildUniversalLink(
      "https://wallet.tos.network/connect",
      "aabbccdd",
      '{"manifestUrl":"https://example.com"}',
      "https://bridge.tos.network/bridge",
      2,
    );

    // Should be a valid URL
    expect(() => new URL(link.split("&bridge=")[0]!)).not.toThrow();

    // Should contain required parameters
    expect(link).toContain("v=2");
    expect(link).toContain("id=aabbccdd");
    expect(link).toContain("r=");
    expect(link).toContain("bridge=");
    expect(link).toContain("ret=back");
  });

  it("includes the bridge URL encoded", () => {
    const link = buildUniversalLink(
      "https://wallet.tos.network/connect",
      "1234",
      "{}",
      "https://bridge.tos.network/bridge",
      2,
    );

    expect(link).toContain(
      "bridge=" + encodeURIComponent("https://bridge.tos.network/bridge"),
    );
  });

  it("starts with the universal link base", () => {
    const link = buildUniversalLink(
      "https://wallet.tos.network/connect",
      "abcd",
      "{}",
      "https://bridge.tos.network/bridge",
      2,
    );

    expect(link.startsWith("https://wallet.tos.network/connect")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// generateRequestId
// ---------------------------------------------------------------------------

describe("generateRequestId", () => {
  it("returns a 32-character hex string", () => {
    const id = generateRequestId();
    expect(id).toHaveLength(32);
    expect(/^[0-9a-f]{32}$/.test(id)).toBe(true);
  });

  it("generates unique IDs", () => {
    const ids = new Set(Array.from({ length: 100 }, () => generateRequestId()));
    expect(ids.size).toBe(100);
  });
});

// ---------------------------------------------------------------------------
// randomBytes
// ---------------------------------------------------------------------------

describe("randomBytes", () => {
  it("returns Uint8Array of requested length", () => {
    for (const n of [0, 1, 16, 32, 64]) {
      const bytes = randomBytes(n);
      expect(bytes).toBeInstanceOf(Uint8Array);
      expect(bytes.length).toBe(n);
    }
  });

  it("produces different values on successive calls", () => {
    const a = randomBytes(32);
    const b = randomBytes(32);
    // Extremely unlikely to be equal
    expect(a).not.toEqual(b);
  });
});

// ---------------------------------------------------------------------------
// isBrowser
// ---------------------------------------------------------------------------

describe("isBrowser", () => {
  it("returns false in Node environment", () => {
    expect(isBrowser()).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// withTimeout
// ---------------------------------------------------------------------------

describe("withTimeout", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("resolves when promise resolves before timeout", async () => {
    const promise = Promise.resolve("ok");
    const result = await withTimeout(promise, 5000, "timed out");
    expect(result).toBe("ok");
  });

  it("rejects when timeout fires first", async () => {
    const neverResolves = new Promise<string>(() => {
      // intentionally never resolves
    });

    const resultPromise = withTimeout(neverResolves, 1000, "custom timeout message");

    vi.advanceTimersByTime(1000);

    await expect(resultPromise).rejects.toThrow("custom timeout message");
  });

  it("rejects when the original promise rejects before timeout", async () => {
    const failing = Promise.reject(new Error("original error"));

    const resultPromise = withTimeout(failing, 5000, "timed out");
    await expect(resultPromise).rejects.toThrow("original error");
  });

  it("rejects when AbortSignal is already aborted", async () => {
    const controller = new AbortController();
    controller.abort();

    const promise = Promise.resolve("ok");
    const resultPromise = withTimeout(promise, 5000, "timed out", controller.signal);

    await expect(resultPromise).rejects.toThrow("The operation was aborted.");
  });

  it("rejects when AbortSignal is aborted during wait", async () => {
    const controller = new AbortController();
    const neverResolves = new Promise<string>(() => {
      // intentionally never resolves
    });

    const resultPromise = withTimeout(neverResolves, 5000, "timed out", controller.signal);

    // Abort before timeout
    controller.abort();

    await expect(resultPromise).rejects.toThrow("The operation was aborted.");
  });

  it("abort error has name AbortError", async () => {
    const controller = new AbortController();
    controller.abort();

    const promise = Promise.resolve("ok");
    try {
      await withTimeout(promise, 5000, "timed out", controller.signal);
      expect.fail("should have thrown");
    } catch (err: unknown) {
      expect((err as DOMException).name).toBe("AbortError");
    }
  });

  it("clears timer when promise resolves before timeout", async () => {
    let resolved = false;
    const promise = new Promise<string>((resolve) => {
      // Resolve immediately via microtask
      queueMicrotask(() => {
        resolve("fast");
        resolved = true;
      });
    });

    const resultPromise = withTimeout(promise, 10000, "timed out");

    // Flush microtasks
    await vi.advanceTimersByTimeAsync(0);

    const result = await resultPromise;
    expect(result).toBe("fast");
    expect(resolved).toBe(true);

    // Advancing past the timeout should NOT cause an unhandled rejection
    vi.advanceTimersByTime(20000);
  });
});
