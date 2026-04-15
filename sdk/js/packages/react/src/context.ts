/**
 * @tos/react — React contexts.
 *
 * Centralises all Context objects so that both the provider and the hooks
 * can import from a single location without circular dependencies.
 *
 * @internal Not part of the public API (contexts are consumed via hooks).
 */

import { createContext } from "react";
import type { TosClient } from "@tos/client";
import type { Sender } from "./types.js";

// ---------------------------------------------------------------------------
// TosClientContext
// ---------------------------------------------------------------------------

/**
 * Provides the {@link TosClient} instance to the component tree.
 * Set by {@link TosProvider}, consumed by {@link useClient} and all query hooks.
 */
export const TosClientContext = createContext<TosClient | null>(null);

// ---------------------------------------------------------------------------
// SenderContext
// ---------------------------------------------------------------------------

/**
 * Provides an optional {@link Sender} to the component tree.
 *
 * This context is designed to be populated by `@tos/connect-react` (or any
 * other wallet integration package) so that mutation hooks like
 * `useSendTransaction` can route through a connected wallet without tight
 * coupling.
 *
 * When no sender is available the context value is `null`.
 */
export const SenderContext = createContext<Sender | null>(null);
