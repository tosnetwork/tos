/**
 * @tos/connect-react — Package-specific types.
 *
 * @packageDocumentation
 */

import type { ReactNode } from "react";
import type { Address } from "@tos/core";
import type {
  WalletInfo,
  ConnectedWallet,
  WalletFeature,
  ConnectRequest,
  SignDataRequest,
  SignDataResponse,
} from "@tos/connect";
import type { TosError } from "@tos/client";

// ---------------------------------------------------------------------------
// Theme configuration
// ---------------------------------------------------------------------------

/** Fine-grained theme options for TosConnectProvider. */
export interface ThemeConfig {
  /** Color mode: light, dark, or auto (follows system preference). */
  mode: "light" | "dark" | "auto";
  /** Primary accent color (CSS color value). */
  accentColor?: string;
  /** Border radius applied to buttons and modals (CSS value). */
  borderRadius?: string;
  /** Font family (CSS font-family value). */
  fontFamily?: string;
}

/** Theme prop accepted by TosConnectProvider. */
export type ThemeProp = "light" | "dark" | "auto" | ThemeConfig;

// ---------------------------------------------------------------------------
// Translation keys (extensible)
// ---------------------------------------------------------------------------

/** Keys used by built-in UI text. Override via the `translations` prop. */
export interface TranslationKeys {
  connectButton: string;
  disconnect: string;
  copyAddress: string;
  connecting: string;
  connected: string;
  walletModalTitle: string;
  signRequestTitle: string;
  transactionSent: string;
  error: string;
}

// ---------------------------------------------------------------------------
// Provider configuration
// ---------------------------------------------------------------------------

/** Configuration object for TosConnectProvider. */
export interface TosConnectConfig {
  /** URL to the DApp manifest JSON (required). */
  manifestUrl: string;
  /** Network to connect to. Defaults to "mainnet". */
  network?: "mainnet" | "testnet";
  /** Custom RPC endpoint. When set, overrides the `network` default. */
  endpoint?: string;
  /** Bridge server URL for the connect protocol. */
  bridgeUrl?: string;
  /** Pre-defined list of wallets to display. */
  wallets?: WalletInfo[];
  /** API key passed to the RPC endpoint. */
  apiKey?: string;
}

/** Props for TosConnectProvider. */
export interface TosConnectProviderProps {
  /** Connect configuration (manifest URL, network, etc.). */
  config: TosConnectConfig;
  /** UI theme: "light", "dark", "auto", or a full ThemeConfig. */
  theme?: ThemeProp;
  /** Locale code for UI text (e.g. "en", "zh"). */
  locale?: string;
  /** Override built-in UI strings. */
  translations?: Partial<TranslationKeys>;
  /** React children. */
  children: ReactNode;
}

// ---------------------------------------------------------------------------
// ConnectButton types
// ---------------------------------------------------------------------------

/** Props for the default ConnectButton component. */
export interface ConnectButtonProps {
  /** Show the wallet balance next to the address. Default: true. */
  showBalance?: boolean;
  /** How to display the connected account. Default: "full". */
  accountStatus?: "full" | "avatar" | "address";
  /** Label shown when disconnected. Default: "Connect Wallet". */
  label?: string;
}

/** Render props passed to ConnectButton.Custom children. */
export interface ConnectButtonRenderProps {
  /** Whether a wallet is currently connected. */
  connected: boolean;
  /** The connected wallet's address, or null. */
  address: Address | null;
  /** The connected wallet's balance in nanotomis, or null. */
  balance: bigint | null;
  /** Display name of the connected wallet, or null. */
  walletName: string | null;
  /** URL to the connected wallet's icon, or null. */
  walletIcon: string | null;
  /** Open the connect/wallet-selection modal. */
  openConnectModal: () => void;
  /** Open the connected-account modal (shows address, balance, disconnect). */
  openAccountModal: () => void;
  /** Disconnect the current wallet. */
  disconnect: () => Promise<void>;
}

/** Props for ConnectButton.Custom. */
export interface ConnectButtonCustomProps {
  children: (props: ConnectButtonRenderProps) => ReactNode;
}

// ---------------------------------------------------------------------------
// Hook return types
// ---------------------------------------------------------------------------

/** Return type of useWallet(). */
export interface UseWalletResult {
  /** Whether a wallet is connected. */
  connected: boolean;
  /** The connected address, or null. */
  address: Address | null;
  /** The wallet's Ed25519 public key, or null. */
  publicKey: Uint8Array | null;
  /** Chain identifier (e.g. "-239" for mainnet), or null. */
  chain: string | null;
  /** Full connected wallet object, or null. */
  wallet: ConnectedWallet | null;
  /** Disconnect the wallet. */
  disconnect: () => Promise<void>;
}

/** Return type of useConnect(). */
export interface UseConnectResult {
  /** Initiate a connection (optionally to a specific wallet). */
  connect: (wallet?: WalletInfo, request?: ConnectRequest) => void;
  /** Disconnect the wallet. */
  disconnect: () => Promise<void>;
  /** Whether a wallet is connected. */
  connected: boolean;
  /** Whether a connection attempt is in progress. */
  connecting: boolean;
}

/** Return type of useConnectModal(). */
export interface UseConnectModalResult {
  /** Open the connect modal. */
  open: () => void;
  /** Close the connect modal. */
  close: () => void;
  /** Whether the modal is currently open. */
  isOpen: boolean;
}

/** Return type of useSignData(). */
export interface UseSignDataResult {
  /** Fire-and-forget sign data request. */
  signData: (request: SignDataRequest) => void;
  /** Sign data and return the response. */
  signDataAsync: (request: SignDataRequest) => Promise<SignDataResponse>;
  /** The last successful sign data response. */
  data: SignDataResponse | undefined;
  /** Whether a sign data request is in progress. */
  isPending: boolean;
  /** The last error, or null. */
  error: TosError | null;
}

/** Return type of useWalletInfo(). */
export interface UseWalletInfoResult {
  /** Display name of the wallet, or null when disconnected. */
  name: string | null;
  /** Icon URL of the wallet, or null when disconnected. */
  icon: string | null;
  /** Platform string of the wallet, or null when disconnected. */
  platform: string | null;
  /** Feature list of the wallet, or null when disconnected. */
  features: WalletFeature[] | null;
}

// ---------------------------------------------------------------------------
// Internal context value types
// ---------------------------------------------------------------------------

/** Shape of the connect context provided by TosConnectProvider. */
export interface ConnectContextValue {
  /** The TosConnect protocol instance (null on server / before init). */
  connector: TosConnectInstance | null;
  /** The connected wallet state, or null. */
  wallet: ConnectedWallet | null;
  /** Whether the wallet is currently connecting. */
  connecting: boolean;
  /** Disconnect the wallet. */
  disconnect: () => Promise<void>;
  /** Connect to a wallet. */
  connect: (wallet?: WalletInfo, request?: ConnectRequest) => void;
}

/** Shape of the modal context provided by TosConnectProvider. */
export interface ModalContextValue {
  /** Open the connect/wallet-selection modal. */
  openConnectModal: () => void;
  /** Close the modal. */
  closeConnectModal: () => void;
  /** Open the account modal (shows connected account info). */
  openAccountModal: () => void;
  /** Close the account modal. */
  closeAccountModal: () => void;
  /** Whether the connect modal is open. */
  connectModalOpen: boolean;
  /** Whether the account modal is open. */
  accountModalOpen: boolean;
}

/** Resolved theme values applied to the UI. */
export interface ResolvedTheme {
  mode: "light" | "dark";
  accentColor: string;
  borderRadius: string;
  fontFamily: string;
}

// ---------------------------------------------------------------------------
// Minimal TosConnect instance interface
// ---------------------------------------------------------------------------

/**
 * Subset of the TosConnect class API consumed by this package.
 *
 * Coded as an interface so that the package compiles even if
 * @tos/connect changes minor details. At runtime the actual
 * TosConnect instance is used.
 */
export interface TosConnectInstance {
  /** Initiate a connection. Returns a universal link (or null for injected). */
  connect(wallet: WalletInfo, request?: { items?: ConnectRequest["items"] }): string | null;
  disconnect(): Promise<void>;
  restoreConnection(): Promise<void>;
  sendTransaction(
    request: unknown,
    opts?: { signal?: AbortSignal; onRequestSent?: () => void },
  ): Promise<{ boc: string }>;
  signData(request: SignDataRequest, opts?: { signal?: AbortSignal }): Promise<SignDataResponse>;
  getWallets(): Promise<WalletInfo[]>;
  onStatusChange(
    callback: (wallet: ConnectedWallet | null) => void,
    errorsHandler?: (err: unknown) => void,
  ): () => void;
  readonly connected: boolean;
  readonly wallet: ConnectedWallet | null;
}
