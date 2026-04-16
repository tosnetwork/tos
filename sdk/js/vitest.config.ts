import { defineConfig } from "vitest/config";
import { readFileSync } from "node:fs";
import { relative, resolve } from "node:path";

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

const repoRoot = __dirname;
const cwdFromRepoRoot = relative(repoRoot, process.cwd());
const isPackageCwd =
  cwdFromRepoRoot !== "" &&
  !cwdFromRepoRoot.startsWith("..") &&
  cwdFromRepoRoot.startsWith("packages/");
const include = isPackageCwd
  ? [`./${cwdFromRepoRoot}/src/**/*.test.{ts,tsx}`]
  : ["./packages/*/src/**/*.test.{ts,tsx}"];
const runLiveTests = process.env.RUN_LIVE_TESTS === "1";
const exclude = runLiveTests ? undefined : ["./packages/*/src/**/live-*.test.{ts,tsx}"];

export default defineConfig({
  root: repoRoot,
  resolve: {
    alias: {
      "@tos/core": resolve(repoRoot, "packages/core/src/index.ts"),
      "@tos/crypto": resolve(repoRoot, "packages/crypto/src/index.ts"),
      "@tos/client": resolve(repoRoot, "packages/client/src/index.ts"),
      "@tos/wallets": resolve(repoRoot, "packages/wallets/src/index.ts"),
      "@tos/contracts": resolve(repoRoot, "packages/contracts/src/index.ts"),
      "@tos/sdk": resolve(repoRoot, "packages/sdk/src/index.ts"),
      "@tos/connect": resolve(repoRoot, "packages/connect/src/index.ts"),
      "@tos/connect-ui": resolve(repoRoot, "packages/connect-ui/src/index.ts"),
      "@tos/react": resolve(repoRoot, "packages/react/src/index.ts"),
      "@tos/connect-react": resolve(repoRoot, "packages/connect-react/src/index.ts"),
      // Pin react to the hoisted v18 to avoid dual-version conflicts with
      // @testing-library/react@16 (which pulls react 19 as a dependency).
      "react": resolve(repoRoot, "node_modules/react"),
      "react-dom": resolve(repoRoot, "node_modules/react-dom"),
    },
  },
  test: {
    globals: true,
    environment: "node",
    include,
    exclude,
    env: loadEnvTest(),
    environmentMatchGlobs: [
      ["packages/react/**", "jsdom"],
      ["packages/connect-react/**", "jsdom"],
      ["packages/connect-ui/**", "jsdom"],
    ],
  },
});
