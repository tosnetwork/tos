/**
 * @tos/react — useClient hook.
 *
 * Returns the raw {@link TosClient} from context. Throws if called outside
 * a {@link TosProvider}.
 */

import { useContext } from "react";
import type { TosClient } from "@tos/client";
import { TosClientContext } from "../context.js";

/**
 * Access the {@link TosClient} instance provided by {@link TosProvider}.
 *
 * @returns The configured TosClient.
 * @throws If used outside a TosProvider.
 *
 * @example
 * ```tsx
 * function Status() {
 *   const client = useClient();
 *   // client.rawCall(...)
 * }
 * ```
 */
export function useClient(): TosClient {
  const client = useContext(TosClientContext);
  if (!client) {
    throw new Error(
      "useClient must be used within a <TosProvider>. " +
        "Wrap your component tree with <TosProvider config={...}>.",
    );
  }
  return client;
}
