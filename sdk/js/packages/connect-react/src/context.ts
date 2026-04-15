/**
 * @tos/connect-react — Internal React contexts.
 *
 * Centralises all Context objects so that the provider and hooks
 * import from a single location without circular dependencies.
 *
 * @internal Not part of the public API.
 */

import { createContext } from "react";
import type { ConnectContextValue, ModalContextValue, ResolvedTheme, TranslationKeys } from "./types.js";

// ---------------------------------------------------------------------------
// Connect context — wallet connection state and actions
// ---------------------------------------------------------------------------

export const ConnectContext = createContext<ConnectContextValue | null>(null);

// ---------------------------------------------------------------------------
// Modal context — modal open/close state
// ---------------------------------------------------------------------------

export const ModalContext = createContext<ModalContextValue | null>(null);

// ---------------------------------------------------------------------------
// Theme context — resolved theme values
// ---------------------------------------------------------------------------

export const ThemeContext = createContext<ResolvedTheme>({
  mode: "light",
  accentColor: "#0098EA",
  borderRadius: "16px",
  fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
});

// ---------------------------------------------------------------------------
// Translation context
// ---------------------------------------------------------------------------

const DEFAULT_TRANSLATIONS: TranslationKeys = {
  connectButton: "Connect Wallet",
  disconnect: "Disconnect",
  copyAddress: "Copy Address",
  connecting: "Connecting...",
  connected: "Connected",
  walletModalTitle: "Choose a Wallet",
  signRequestTitle: "Signature Request",
  transactionSent: "Transaction Sent",
  error: "Error",
};

export const TranslationContext = createContext<TranslationKeys>(DEFAULT_TRANSLATIONS);

export { DEFAULT_TRANSLATIONS };
