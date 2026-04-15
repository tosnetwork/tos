import { describe, it, expect } from "vitest";
import {
  MemoryStorageAdapter,
  LocalStorageAdapter,
  createDefaultStorage,
} from "./storage.js";

// ---------------------------------------------------------------------------
// MemoryStorageAdapter
// ---------------------------------------------------------------------------

describe("MemoryStorageAdapter", () => {
  it("getItem returns null for a missing key", async () => {
    const store = new MemoryStorageAdapter();
    const result = await store.getItem("nonexistent");
    expect(result).toBeNull();
  });

  it("setItem / getItem round-trip", async () => {
    const store = new MemoryStorageAdapter();
    await store.setItem("key1", "value1");
    const result = await store.getItem("key1");
    expect(result).toBe("value1");
  });

  it("setItem overwrites existing value", async () => {
    const store = new MemoryStorageAdapter();
    await store.setItem("key", "first");
    await store.setItem("key", "second");
    const result = await store.getItem("key");
    expect(result).toBe("second");
  });

  it("removeItem removes the key", async () => {
    const store = new MemoryStorageAdapter();
    await store.setItem("key", "value");
    await store.removeItem("key");
    const result = await store.getItem("key");
    expect(result).toBeNull();
  });

  it("removeItem on missing key does not throw", async () => {
    const store = new MemoryStorageAdapter();
    await expect(store.removeItem("missing")).resolves.toBeUndefined();
  });

  it("stores multiple independent keys", async () => {
    const store = new MemoryStorageAdapter();
    await store.setItem("a", "1");
    await store.setItem("b", "2");
    await store.setItem("c", "3");

    expect(await store.getItem("a")).toBe("1");
    expect(await store.getItem("b")).toBe("2");
    expect(await store.getItem("c")).toBe("3");
  });

  it("handles empty string values", async () => {
    const store = new MemoryStorageAdapter();
    await store.setItem("empty", "");
    const result = await store.getItem("empty");
    expect(result).toBe("");
  });
});

// ---------------------------------------------------------------------------
// LocalStorageAdapter (structural tests — no real localStorage in node)
// ---------------------------------------------------------------------------

describe("LocalStorageAdapter", () => {
  it("can be constructed with a custom prefix", () => {
    // This just verifies instantiation does not throw
    const adapter = new LocalStorageAdapter("custom:");
    expect(adapter).toBeDefined();
  });

  it("getItem returns null when localStorage is unavailable", async () => {
    // In Node there is no global localStorage, so the try/catch fallback fires
    const adapter = new LocalStorageAdapter();
    const result = await adapter.getItem("anything");
    expect(result).toBeNull();
  });

  it("setItem does not throw when localStorage is unavailable", async () => {
    const adapter = new LocalStorageAdapter();
    await expect(adapter.setItem("key", "val")).resolves.toBeUndefined();
  });

  it("removeItem does not throw when localStorage is unavailable", async () => {
    const adapter = new LocalStorageAdapter();
    await expect(adapter.removeItem("key")).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// createDefaultStorage
// ---------------------------------------------------------------------------

describe("createDefaultStorage", () => {
  it("returns MemoryStorageAdapter in Node (non-browser) environment", () => {
    const storage = createDefaultStorage();
    expect(storage).toBeInstanceOf(MemoryStorageAdapter);
  });

  it("returned storage is functional (set/get/remove)", async () => {
    const storage = createDefaultStorage();
    await storage.setItem("test", "123");
    expect(await storage.getItem("test")).toBe("123");
    await storage.removeItem("test");
    expect(await storage.getItem("test")).toBeNull();
  });
});
