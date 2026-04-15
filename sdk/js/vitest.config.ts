import { defineConfig } from "vitest/config";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

// Load .env.test for test-only environment variables (TEST_MNEMONIC, etc.)
function loadEnvTest(): Record<string, string> {
  try {
    const content = readFileSync(resolve(__dirname, ".env.test"), "utf-8");
    const env: Record<string, string> = {};
    for (const line of content.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eqIdx = trimmed.indexOf("=");
      if (eqIdx === -1) continue;
      const key = trimmed.slice(0, eqIdx).trim();
      let val = trimmed.slice(eqIdx + 1).trim();
      // Strip surrounding quotes
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      env[key] = val;
    }
    return env;
  } catch {
    return {};
  }
}

export default defineConfig({
  resolve: {
    alias: {
      "@tos/core": resolve(__dirname, "packages/core/src/index.ts"),
      "@tos/crypto": resolve(__dirname, "packages/crypto/src/index.ts"),
      "@tos/client": resolve(__dirname, "packages/client/src/index.ts"),
      "@tos/wallets": resolve(__dirname, "packages/wallets/src/index.ts"),
      "@tos/contracts": resolve(__dirname, "packages/contracts/src/index.ts"),
      "@tos/sdk": resolve(__dirname, "packages/sdk/src/index.ts"),
    },
  },
  test: {
    globals: true,
    environment: "node",
    include: ["packages/*/src/**/*.test.ts"],
    env: loadEnvTest(),
  },
});
