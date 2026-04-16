/**
 * @tos/react — Configuration factory.
 *
 * Creates a {@link TosConfig} that holds a pre-configured {@link TosClient}.
 * Pass the result to {@link TosProvider}.
 *
 * @packageDocumentation
 */

import { TosClient, Networks } from "@tos/client";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Options accepted by {@link createTosConfig}. */
export interface CreateTosConfigOptions {
  /** Full JSON-RPC endpoint URL.  Takes precedence over `network`. */
  endpoint?: string;
  /** Well-known network name.  Ignored when `endpoint` is set. Defaults to `"mainnet"`. */
  network?: "mainnet" | "testnet";
  /** API key sent as the `X-API-Key` header. */
  apiKey?: string;
  /** Per-request timeout in milliseconds (default 30 000). */
  timeout?: number;
}

/** Immutable config object provided to {@link TosProvider}. */
export interface TosConfig {
  readonly client: TosClient;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a TOS configuration object.
 *
 * @example
 * ```tsx
 * const config = createTosConfig({ network: "mainnet", apiKey: "..." });
 * // ... then in JSX:
 * <TosProvider config={config}>
 *   <App />
 * </TosProvider>
 * ```
 */
export function createTosConfig(options: CreateTosConfigOptions = {}): TosConfig {
  const endpoint =
    (options.endpoint ??
    Networks[options.network ?? "mainnet"].endpoint).replace(/\/+$/, "");

  const client = new TosClient({
    endpoint,
    apiKey: options.apiKey,
    timeout: options.timeout,
  });

  return { client };
}
