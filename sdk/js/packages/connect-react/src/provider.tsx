/**
 * @tos/connect-react — TosConnectProvider.
 *
 * The main provider that composes:
 *  1. TosProvider (from @tos/react) for RPC client access
 *  2. TosConnect protocol instance for wallet connections
 *  3. SenderContext bridge so useSendTransaction routes through the wallet
 *  4. Modal state management
 *  5. Theme / translation contexts
 *
 * @packageDocumentation
 */

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { createTosConfig, TosProvider } from "@tos/react";
import { SenderContext } from "@tos/react";
import type { ConnectedWallet, WalletInfo, ConnectRequest } from "@tos/connect";
import type { Sender } from "@tos/react";

import { ConnectContext, ModalContext, ThemeContext, TranslationContext, DEFAULT_TRANSLATIONS } from "./context.js";
import type {
  TosConnectProviderProps,
  TosConnectConfig,
  ThemeProp,
  ResolvedTheme,
  ConnectContextValue,
  ModalContextValue,
  TosConnectInstance,
  TranslationKeys,
} from "./types.js";

// ---------------------------------------------------------------------------
// SSR guard
// ---------------------------------------------------------------------------

function isBrowser(): boolean {
  return typeof window !== "undefined" && typeof document !== "undefined";
}

// ---------------------------------------------------------------------------
// Theme resolution
// ---------------------------------------------------------------------------

function resolveTheme(theme: ThemeProp | undefined): ResolvedTheme {
  const defaults: ResolvedTheme = {
    mode: "light",
    accentColor: "#0098EA",
    borderRadius: "16px",
    fontFamily:
      '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
  };

  if (!theme) return defaults;

  if (typeof theme === "string") {
    const mode =
      theme === "auto"
        ? isBrowser() && window.matchMedia("(prefers-color-scheme: dark)").matches
          ? "dark"
          : "light"
        : theme;
    return { ...defaults, mode };
  }

  const mode =
    theme.mode === "auto"
      ? isBrowser() && window.matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light"
      : theme.mode;

  return {
    mode,
    accentColor: theme.accentColor ?? defaults.accentColor,
    borderRadius: theme.borderRadius ?? defaults.borderRadius,
    fontFamily: theme.fontFamily ?? defaults.fontFamily,
  };
}

// ---------------------------------------------------------------------------
// CSS variable injection
// ---------------------------------------------------------------------------

function applyThemeVariables(theme: ResolvedTheme): void {
  if (!isBrowser()) return;

  const root = document.documentElement;
  const isDark = theme.mode === "dark";

  root.style.setProperty("--tos-connect-accent", theme.accentColor);
  root.style.setProperty("--tos-connect-radius", theme.borderRadius);

  root.style.setProperty(
    "--tos-connect-bg",
    isDark ? "#1A1A2E" : "#FFFFFF",
  );
  root.style.setProperty(
    "--tos-connect-text",
    isDark ? "#F0F0F0" : "#1A1A2E",
  );
  root.style.setProperty(
    "--tos-connect-border",
    isDark ? "rgba(255, 255, 255, 0.12)" : "rgba(0, 0, 0, 0.08)",
  );
  root.style.setProperty("--tos-connect-button-bg", theme.accentColor);
  root.style.setProperty("--tos-connect-button-text", "#FFFFFF");
  root.style.setProperty(
    "--tos-connect-font",
    theme.fontFamily,
  );
}

// ---------------------------------------------------------------------------
// Lazy TosConnect loader
// ---------------------------------------------------------------------------

/**
 * Dynamically imports and instantiates TosConnect.
 *
 * We defer the import so that:
 *  - SSR never attempts to load it
 *  - The class is only created client-side
 */
async function createConnector(
  config: TosConnectConfig,
): Promise<TosConnectInstance> {
  // Dynamic import — @tos/connect exposes the class as a named export.
  const { TosConnect } = await import("@tos/connect");
  const connector = new TosConnect({
    manifestUrl: config.manifestUrl,
    bridgeUrl: config.bridgeUrl,
  });
  return connector as unknown as TosConnectInstance;
}

// ---------------------------------------------------------------------------
// Connect sender — bridges TosConnect.sendTransaction to the Sender interface
// ---------------------------------------------------------------------------

function createConnectSender(connector: TosConnectInstance): Sender {
  return {
    async send(args) {
      const { to, value, body, bounce } = args;

      // Build TransactionMessage compatible with @tos/connect
      const message: {
        address: string;
        amount: string;
        payload?: string;
        bounce?: boolean;
      } = {
        address: to,
        amount: value.toString(),
      };

      // If body is a Cell, serialize to base64 BOC
      if (body && typeof body === "object" && "toBoc" in body && typeof (body as any).toBoc === "function") {
        const cell = body as { toBoc(): Uint8Array };
        const boc = cell.toBoc();
        // Convert Uint8Array to base64
        let binary = "";
        for (let i = 0; i < boc.length; i++) {
          binary += String.fromCharCode(boc[i]!);
        }
        message.payload = btoa(binary);
      }

      if (bounce !== undefined) {
        message.bounce = bounce;
      }

      const validUntil = Math.floor(Date.now() / 1000) + 300; // 5 minutes

      const result = await connector.sendTransaction({
        validUntil,
        messages: [message],
      });

      return { hash: result.boc };
    },
  };
}

// ---------------------------------------------------------------------------
// TosConnectProvider
// ---------------------------------------------------------------------------

export function TosConnectProvider({
  config,
  theme,
  locale: _locale,
  translations,
  children,
}: TosConnectProviderProps): ReactNode {
  // ---- TosConfig (for TosProvider) ----
  const tosConfig = useMemo(
    () =>
      createTosConfig({
        endpoint: config.endpoint,
        network: config.network ?? "mainnet",
        apiKey: config.apiKey,
      }),
    [config.endpoint, config.network, config.apiKey],
  );

  // ---- Resolved theme ----
  const [resolvedTheme, setResolvedTheme] = useState<ResolvedTheme>(() => resolveTheme(theme));

  useEffect(() => {
    setResolvedTheme(resolveTheme(theme));
  }, [theme]);

  useEffect(() => {
    applyThemeVariables(resolvedTheme);
    return () => {
      if (!isBrowser()) return;
      const root = document.documentElement;
      root.style.removeProperty("--tos-connect-accent");
      root.style.removeProperty("--tos-connect-radius");
      root.style.removeProperty("--tos-connect-bg");
      root.style.removeProperty("--tos-connect-text");
      root.style.removeProperty("--tos-connect-border");
      root.style.removeProperty("--tos-connect-button-bg");
      root.style.removeProperty("--tos-connect-button-text");
      root.style.removeProperty("--tos-connect-font");
    };
  }, [resolvedTheme]);

  // ---- System theme listener (for "auto" mode) ----
  useEffect(() => {
    if (!isBrowser()) return;

    const rawMode = typeof theme === "string" ? theme : theme?.mode;
    if (rawMode !== "auto") return;

    const mql = window.matchMedia("(prefers-color-scheme: dark)");
    const handler = () => {
      const updated = resolveTheme(theme);
      applyThemeVariables(updated);
      setResolvedTheme(updated);
    };
    mql.addEventListener("change", handler);
    return () => mql.removeEventListener("change", handler);
  }, [theme]);

  // ---- Translations ----
  const mergedTranslations = useMemo<TranslationKeys>(
    () => ({ ...DEFAULT_TRANSLATIONS, ...translations }),
    [translations],
  );

  // ---- TosConnect instance (client-side only) ----
  const [connector, setConnector] = useState<TosConnectInstance | null>(null);
  const [wallet, setWallet] = useState<ConnectedWallet | null>(null);
  const [connecting, setConnecting] = useState(false);
  const connectorRef = useRef<TosConnectInstance | null>(null);

  // Stable reference to config for the async init
  const configRef = useRef(config);
  configRef.current = config;

  useEffect(() => {
    if (!isBrowser()) return;

    let cancelled = false;
    let unsubscribe: (() => void) | undefined;

    setConnector(null);
    setWallet(null);
    setConnecting(false);
    connectorRef.current = null;

    createConnector(configRef.current)
      .then((instance) => {
        if (cancelled) return;

        connectorRef.current = instance;
        setConnector(instance);

        // Subscribe to status changes
        unsubscribe = instance.onStatusChange(
          (w) => {
            if (!cancelled) {
              setWallet(w);
              setConnecting(false);
            }
          },
          () => {
            if (!cancelled) {
              setWallet(null);
              setConnecting(false);
            }
          },
        );

        // Auto-restore previous session
        instance.restoreConnection().catch(() => {
          // Restoration failed silently — user will need to reconnect.
        });
      })
      .catch((err) => {
        if (!cancelled) {
          console.warn("[TOS Connect] Failed to initialize connector:", err);
        }
      });

    return () => {
      cancelled = true;
      unsubscribe?.();
    };
  }, [config.manifestUrl, config.bridgeUrl]);

  // ---- Connection actions ----
  const connect = useCallback(
    (walletInfo?: WalletInfo, request?: ConnectRequest) => {
      const c = connectorRef.current;
      if (!c) return;
      if (!walletInfo) {
        // No specific wallet — open the modal for wallet selection
        return;
      }

      setConnecting(true);
      // TosConnect.connect() is synchronous — returns a universal link or null.
      // The actual wallet state arrives asynchronously via onStatusChange.
      try {
        const items = request?.items;
        c.connect(walletInfo, items ? { items } : undefined);
      } catch {
        setConnecting(false);
      }
    },
    [],
  );

  const disconnect = useCallback(async () => {
    const c = connectorRef.current;
    if (!c) return;
    try {
      await c.disconnect();
    } finally {
      setWallet(null);
    }
  }, []);

  // ---- Sender (for SenderContext) ----
  const sender = useMemo<Sender | null>(() => {
    if (!connector || !wallet) return null;
    return createConnectSender(connector);
  }, [connector, wallet]);

  // ---- Connect context value ----
  const connectValue = useMemo<ConnectContextValue>(
    () => ({
      connector,
      wallet,
      connecting,
      disconnect,
      connect,
    }),
    [connector, wallet, connecting, disconnect, connect],
  );

  // ---- Modal state ----
  const [connectModalOpen, setConnectModalOpen] = useState(false);
  const [accountModalOpen, setAccountModalOpen] = useState(false);

  const modalValue = useMemo<ModalContextValue>(
    () => ({
      openConnectModal: () => setConnectModalOpen(true),
      closeConnectModal: () => setConnectModalOpen(false),
      openAccountModal: () => setAccountModalOpen(true),
      closeAccountModal: () => setAccountModalOpen(false),
      connectModalOpen,
      accountModalOpen,
    }),
    [connectModalOpen, accountModalOpen],
  );

  // ---- Render ----
  return (
    <ThemeContext.Provider value={resolvedTheme}>
      <TranslationContext.Provider value={mergedTranslations}>
        <TosProvider config={tosConfig}>
          <SenderContext.Provider value={sender}>
            <ConnectContext.Provider value={connectValue}>
              <ModalContext.Provider value={modalValue}>
                {children}
              </ModalContext.Provider>
            </ConnectContext.Provider>
          </SenderContext.Provider>
        </TosProvider>
      </TranslationContext.Provider>
    </ThemeContext.Provider>
  );
}
