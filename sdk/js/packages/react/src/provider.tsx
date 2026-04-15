/**
 * @tos/react — TosProvider component.
 *
 * Wraps the application (or a subtree) and provides the {@link TosClient}
 * via React context so that all hooks can access the RPC client.
 *
 * @packageDocumentation
 */

import type { ReactNode } from "react";
import { TosClientContext } from "./context.js";
import type { TosConfig } from "./config.js";

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface TosProviderProps {
  /** Configuration created by {@link createTosConfig}. */
  config: TosConfig;
  children: ReactNode;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/**
 * Provide TOS blockchain access to all descendant hooks.
 *
 * @example
 * ```tsx
 * import { createTosConfig, TosProvider } from "@tos/react";
 *
 * const config = createTosConfig({ network: "mainnet" });
 *
 * function App() {
 *   return (
 *     <TosProvider config={config}>
 *       <MyDApp />
 *     </TosProvider>
 *   );
 * }
 * ```
 */
export function TosProvider({ config, children }: TosProviderProps): JSX.Element {
  return (
    <TosClientContext.Provider value={config.client}>
      {children}
    </TosClientContext.Provider>
  );
}
