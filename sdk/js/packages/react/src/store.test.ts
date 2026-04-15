import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  serializeKey,
  setLoading,
  setData,
  setError,
  invalidate,
  subscribe,
  getSnapshot,
} from "./store.js";

/**
 * The store module uses a global singleton Map for caching.
 * Each test uses unique keys to avoid cross-test contamination.
 */

describe("serializeKey", () => {
  it("joins parts with colons", () => {
    expect(serializeKey(["balance", "0:abc"])).toBe("balance:0:abc");
  });

  it("produces a stable string for the same inputs", () => {
    const a = serializeKey(["contractRead", "addr", "method"]);
    const b = serializeKey(["contractRead", "addr", "method"]);
    expect(a).toBe(b);
  });

  it("handles a single-element array", () => {
    expect(serializeKey(["solo"])).toBe("solo");
  });

  it("handles an empty array", () => {
    expect(serializeKey([])).toBe("");
  });
});

describe("getSnapshot", () => {
  it("returns a fresh entry with isLoading=true for unknown keys", () => {
    const entry = getSnapshot("test:fresh:" + Math.random());
    expect(entry.data).toBeUndefined();
    expect(entry.error).toBeNull();
    expect(entry.isLoading).toBe(true);
    expect(entry.generation).toBe(0);
  });
});

describe("setLoading", () => {
  it("marks an entry as loading and bumps generation", () => {
    const key = "test:setLoading:" + Math.random();
    // First access creates the entry with isLoading=true, generation=0
    const before = getSnapshot(key);
    expect(before.isLoading).toBe(true);

    // Set data to flip isLoading off, then set loading again
    setData(key, "value");
    const afterData = getSnapshot(key);
    expect(afterData.isLoading).toBe(false);

    setLoading(key);
    const afterLoading = getSnapshot(key);
    expect(afterLoading.isLoading).toBe(true);
    expect(afterLoading.generation).toBeGreaterThan(afterData.generation);
  });

  it("does not emit when already loading (skips redundant)", () => {
    const key = "test:setLoading:redundant:" + Math.random();
    const listener = vi.fn();
    const unsub = subscribe(listener);

    // Fresh entry is already loading, so setLoading should be a no-op
    getSnapshot(key); // ensure entry exists
    listener.mockClear();

    setLoading(key);
    expect(listener).not.toHaveBeenCalled();

    unsub();
  });
});

describe("setData", () => {
  it("stores data, clears loading, and bumps generation", () => {
    const key = "test:setData:" + Math.random();
    setData(key, { result: 42 });
    const entry = getSnapshot(key);
    expect(entry.data).toEqual({ result: 42 });
    expect(entry.isLoading).toBe(false);
    expect(entry.error).toBeNull();
    expect(entry.generation).toBeGreaterThan(0);
  });

  it("notifies subscribers", () => {
    const key = "test:setData:notify:" + Math.random();
    const listener = vi.fn();
    const unsub = subscribe(listener);
    listener.mockClear();

    setData(key, "hello");
    expect(listener).toHaveBeenCalledTimes(1);

    unsub();
  });
});

describe("setError", () => {
  it("stores error, clears loading, and bumps generation", () => {
    const key = "test:setError:" + Math.random();
    const err = new Error("boom");
    setError(key, err);
    const entry = getSnapshot(key);
    expect(entry.error).toBe(err);
    expect(entry.isLoading).toBe(false);
    expect(entry.generation).toBeGreaterThan(0);
  });

  it("preserves existing data when error is set", () => {
    const key = "test:setError:preserveData:" + Math.random();
    setData(key, "preserved");
    setError(key, new Error("err"));
    const entry = getSnapshot(key);
    expect(entry.data).toBe("preserved");
    expect(entry.error).toBeInstanceOf(Error);
  });
});

describe("invalidate", () => {
  it("removes the cache entry so getSnapshot returns a fresh one", () => {
    const key = "test:invalidate:" + Math.random();
    setData(key, "cached");
    expect(getSnapshot(key).data).toBe("cached");

    invalidate(key);
    const fresh = getSnapshot(key);
    expect(fresh.data).toBeUndefined();
    expect(fresh.isLoading).toBe(true);
    expect(fresh.generation).toBe(0);
  });

  it("notifies subscribers when there is an entry to remove", () => {
    const key = "test:invalidate:notify:" + Math.random();
    setData(key, "val");

    const listener = vi.fn();
    const unsub = subscribe(listener);
    listener.mockClear();

    invalidate(key);
    expect(listener).toHaveBeenCalledTimes(1);

    unsub();
  });

  it("does not notify subscribers when key does not exist", () => {
    const key = "test:invalidate:noop:" + Math.random();
    const listener = vi.fn();
    const unsub = subscribe(listener);
    listener.mockClear();

    invalidate(key);
    expect(listener).not.toHaveBeenCalled();

    unsub();
  });
});

describe("subscribe / getSnapshot", () => {
  it("returns an unsubscribe function that prevents further notifications", () => {
    const listener = vi.fn();
    const unsub = subscribe(listener);
    listener.mockClear();

    const key = "test:unsub:" + Math.random();
    setData(key, 1);
    expect(listener).toHaveBeenCalledTimes(1);

    unsub();
    listener.mockClear();

    setData(key, 2);
    expect(listener).not.toHaveBeenCalled();
  });

  it("supports multiple subscribers", () => {
    const listener1 = vi.fn();
    const listener2 = vi.fn();
    const unsub1 = subscribe(listener1);
    const unsub2 = subscribe(listener2);
    listener1.mockClear();
    listener2.mockClear();

    const key = "test:multi:" + Math.random();
    setData(key, "x");
    expect(listener1).toHaveBeenCalledTimes(1);
    expect(listener2).toHaveBeenCalledTimes(1);

    unsub1();
    unsub2();
  });

  it("getSnapshot returns the same reference until a state change", () => {
    const key = "test:ref:" + Math.random();
    setData(key, "stable");
    const snap1 = getSnapshot(key);
    const snap2 = getSnapshot(key);
    expect(snap1).toBe(snap2);

    // After update, should be a different object
    setData(key, "changed");
    const snap3 = getSnapshot(key);
    expect(snap3).not.toBe(snap1);
  });
});
