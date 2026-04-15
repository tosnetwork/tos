import { describe, it, expect } from "vitest";
import { createTosConfig } from "./config.js";

describe("createTosConfig", () => {
  it("returns a config with a TosClient using mainnet by default", () => {
    const config = createTosConfig();
    expect(config).toBeDefined();
    expect(config.client).toBeDefined();
    // The default endpoint should be the mainnet endpoint
    expect((config.client as any).endpoint).toBe("https://rpc.tos.network");
  });

  it('uses testnet endpoint when network is "testnet"', () => {
    const config = createTosConfig({ network: "testnet" });
    expect((config.client as any).endpoint).toBe(
      "https://testnet-rpc.tos.network",
    );
  });

  it("uses a custom endpoint when provided", () => {
    const config = createTosConfig({ endpoint: "http://custom:8080" });
    expect((config.client as any).endpoint).toBe("http://custom:8080");
  });

  it("prefers endpoint over network when both are provided", () => {
    const config = createTosConfig({
      endpoint: "http://my-node:9000",
      network: "testnet",
    });
    expect((config.client as any).endpoint).toBe("http://my-node:9000");
  });

  it("passes apiKey and timeout to the client", () => {
    const config = createTosConfig({
      apiKey: "test-key-123",
      timeout: 5000,
    });
    expect((config.client as any).apiKey).toBe("test-key-123");
    expect((config.client as any).timeoutMs).toBe(5000);
  });

  it("strips trailing slashes from custom endpoint", () => {
    const config = createTosConfig({ endpoint: "http://localhost:8080///" });
    expect((config.client as any).endpoint).toBe("http://localhost:8080");
  });
});
