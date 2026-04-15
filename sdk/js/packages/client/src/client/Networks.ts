/**
 * @tos/client — Network presets.
 *
 * Each entry provides the default JSON-RPC endpoint for a well-known TOS
 * network.  Pass the whole object as part of the TosClient constructor
 * options, or spread it:
 *
 * ```ts
 * const client = new TosClient({ ...Networks.mainnet, apiKey: "..." });
 * ```
 */

export interface NetworkConfig {
  readonly endpoint: string;
}

/**
 * Pre-configured network endpoints for well-known TOS networks.
 *
 * @example
 * ```typescript
 * import { TosClient, Networks } from "@tos/client";
 *
 * const client = new TosClient({ ...Networks.mainnet, apiKey: "..." });
 * // or
 * const testClient = new TosClient(Networks.testnet);
 * const localClient = new TosClient(Networks.local);
 * ```
 */
export const Networks = {
  mainnet: { endpoint: "https://rpc.tos.network" },
  testnet: { endpoint: "https://testnet-rpc.tos.network" },
  local:   { endpoint: "http://127.0.0.1:8011" },
} as const satisfies Record<string, NetworkConfig>;
