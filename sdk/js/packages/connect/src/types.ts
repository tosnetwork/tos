/**
 * @tos/connect protocol types.
 *
 * Covers the full wallet-DApp communication protocol:
 * manifests, wallet discovery, connect flow, transactions,
 * data signing, device info, and event types.
 */

// ---------------------------------------------------------------------------
// DApp Manifest
// ---------------------------------------------------------------------------

/** Manifest served by the DApp so wallets can identify the requester. */
export interface DAppManifest {
  /** URL of the manifest (used as unique DApp identifier). */
  url: string;
  /** Human-readable DApp name. */
  name: string;
  /** URL to the DApp icon (PNG, min 180x180). */
  iconUrl: string;
  /** Optional: URL the wallet navigates to after connect/action (deep link). */
  termsOfUseUrl?: string;
  /** Optional: Privacy policy URL. */
  privacyPolicyUrl?: string;
}

// ---------------------------------------------------------------------------
// Wallet Discovery
// ---------------------------------------------------------------------------

/** Platform identifiers for wallet availability. */
export type WalletPlatform =
  | "ios"
  | "android"
  | "chrome"
  | "firefox"
  | "safari"
  | "edge"
  | "web"
  | "linux"
  | "macos"
  | "windows";

/** Describes a single wallet that the DApp can connect to. */
export interface WalletInfo {
  /** Display name. */
  name: string;
  /** Machine-readable app name (lowercase, no spaces). */
  appName: string;
  /** URL to the wallet icon. */
  imageUrl: string;
  /** Platforms on which this wallet is available. */
  platforms: WalletPlatform[];
  /** Universal link prefix for the HTTP-bridge flow (optional). */
  universalLink?: string;
  /** Bridge URL for this wallet (optional – falls back to default). */
  bridgeUrl?: string;
  /** Key of the injected JS bridge on `window.tos.providers`. */
  jsBridgeKey?: string;
  /** Whether this wallet is also injected into the page. */
  injected?: boolean;
  /** Download links per platform. */
  downloadUrls?: Partial<Record<WalletPlatform, string>>;
  /** Additional opaque metadata from wallet-list sources. */
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Connect Flow
// ---------------------------------------------------------------------------

/** Items a DApp can request during the connect handshake. */
export type ConnectItemName = "tos_addr" | "tos_proof";

/** A single item in a connect request. */
export interface ConnectItem {
  name: ConnectItemName;
  /** Required for the proof item; arbitrary payload the wallet must sign. */
  payload?: string;
}

/** The request body sent to the wallet during connect. */
export interface ConnectRequest {
  /** URL of the DApp's manifest.json. */
  manifestUrl: string;
  items: ConnectItem[];
}

// ---------------------------------------------------------------------------
// Connected State
// ---------------------------------------------------------------------------

/** TOS address chain identifier. */
export type TosChain = "-239" | "-3";

/** Represents the account the wallet connected with. */
export interface ConnectedAccount {
  /** Raw address string (e.g. "0:abc..."). */
  address: string;
  /** Chain / workchain identifier. */
  chain: TosChain;
  /** Hex-encoded Ed25519 public key. */
  publicKey?: string;
  /** Base64-encoded wallet state init (BOC). */
  walletStateInit?: string;
}

/** Device information reported by the wallet. */
export interface DeviceInfo {
  platform: WalletPlatform | "browser" | "desktop" | "mobile";
  appName: string;
  appVersion: string;
  maxProtocolVersion: number;
  features: WalletFeature[];
}

/** Feature flags advertised by the wallet. */
export type WalletFeature =
  | SendTransactionFeature
  | SignDataFeature
  | { name: string; [key: string]: unknown };

export interface SendTransactionFeature {
  name: "SendTransaction";
  /** Maximum number of messages in a single transaction. */
  maxMessages: number;
}

export interface SignDataFeature {
  name: "SignData";
}

// ---------------------------------------------------------------------------
// Connect-Item Replies
// ---------------------------------------------------------------------------

/** A reply to a single ConnectItem. */
export type ConnectItemReply = TosAddressItemReply | TosProofItemReply;

export interface TosAddressItemReply {
  name: "tos_addr";
  address: string;
  network: TosChain;
  publicKey: string;
  walletStateInit: string;
}

export interface TosProofItemReply {
  name: "tos_proof";
  proof: {
    timestamp: number;
    domain: {
      lengthBytes: number;
      value: string;
    };
    payload: string;
    signature: string;
  };
}

/** The wallet object stored after a successful connect. */
export interface ConnectedWallet {
  device: DeviceInfo;
  account: ConnectedAccount;
  connectItems?: ConnectItemReply[];
}

// ---------------------------------------------------------------------------
// Send Transaction
// ---------------------------------------------------------------------------

/** A single outgoing message inside a transaction request. */
export interface TransactionMessage {
  /** Destination address (raw or friendly). */
  address: string;
  /** Amount in nanotomis (decimal string). */
  amount: string;
  /** Optional: state init for deploying a contract (base64 BOC). */
  stateInit?: string;
  /** Optional: message payload (base64 BOC). */
  payload?: string;
  /** Optional: extra currencies map (currency_id -> amount string). */
  extraCurrency?: Record<number, string>;
}

/** Request to send a transaction. */
export interface SendTransactionRequest {
  /** Valid-until UNIX timestamp. */
  validUntil: number;
  /** Network (defaults to mainnet). */
  network?: TosChain;
  /** Source address (optional). */
  from?: string;
  /** One or more outgoing messages. */
  messages: TransactionMessage[];
}

/** Response from a successful sendTransaction. */
export interface SendTransactionResponse {
  /** Signed BOC (base64). */
  boc: string;
}

// ---------------------------------------------------------------------------
// Sign Data
// ---------------------------------------------------------------------------

/** Request to sign arbitrary data. */
export interface SignDataRequest {
  /** Type of data to sign. */
  type: "text" | "binary" | "cell";
  /** Text content, hex bytes, or base64 BOC depending on `type`. */
  data: string;
  /** Signing domain for replay protection. */
  domain?: string;
}

/** Response from a successful signData. */
export interface SignDataResponse {
  /** Base64-encoded Ed25519 signature. */
  signature: string;
  /** Signer address. */
  address: string;
  /** UNIX timestamp of signing. */
  timestamp: number;
  /** Domain used for signing, if provided. */
  domain?: string;
  /** Original data that was signed. */
  payload: string;
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

/** Async key-value storage used to persist session state. */
export interface ConnectStorage {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
}

// ---------------------------------------------------------------------------
// Injected Provider
// ---------------------------------------------------------------------------

/** The interface exposed by injected wallet extensions. */
export interface InjectedTosProvider {
  connect(protocolVersion: number, message: ConnectRequest): Promise<ConnectEventPayload>;
  disconnect(): Promise<void>;
  sendTransaction(request: SendTransactionRpcRequest): Promise<SendTransactionResponse>;
  signData?(request: SignDataRpcRequest): Promise<SignDataResponse>;
  restoreConnection(): Promise<ConnectEventPayload>;
  listen(callback: (event: WalletEvent) => void): () => void;
}

// ---------------------------------------------------------------------------
// RPC message types (bridge protocol)
// ---------------------------------------------------------------------------

/** Internal RPC request for sendTransaction over the bridge. */
export interface SendTransactionRpcRequest {
  method: "sendTransaction";
  params: [string]; // JSON-stringified SendTransactionRequest
  id: string;
}

/** Internal RPC request for signData over the bridge. */
export interface SignDataRpcRequest {
  method: "signData";
  params: [string]; // JSON-stringified SignDataRequest
  id: string;
}

export type RpcRequest = SendTransactionRpcRequest | SignDataRpcRequest;

export interface RpcResponse {
  id: string;
  result?: string;
  error?: { code: number; message: string; data?: unknown };
}

// ---------------------------------------------------------------------------
// Wallet Events (SSE / injected)
// ---------------------------------------------------------------------------

export type WalletEventName =
  | "connect"
  | "connect_error"
  | "disconnect";

export interface ConnectEventPayload {
  items: ConnectItemReply[];
  device: DeviceInfo;
}

export interface ConnectErrorPayload {
  code: number;
  message: string;
}

export interface WalletEvent {
  event: WalletEventName;
  id?: number;
  payload: ConnectEventPayload | ConnectErrorPayload | Record<string, never>;
}

// ---------------------------------------------------------------------------
// Bridge SSE message envelope
// ---------------------------------------------------------------------------

export interface BridgeIncomingMessage {
  from: string;
  message: string; // base64-encoded encrypted blob
}

// ---------------------------------------------------------------------------
// Session persistence
// ---------------------------------------------------------------------------

export interface PersistedSession {
  /** Our Curve25519 secret key (hex). */
  secretKey: string;
  /** Our Curve25519 public key / clientId (hex). */
  clientId: string;
  /** Wallet's Curve25519 public key (hex). */
  walletPublicKey: string;
  /** Bridge URL used for this session. */
  bridgeUrl: string;
  /** Connected wallet data. */
  wallet: ConnectedWallet;
  /** UNIX-ms timestamp when session was created. */
  createdAt: number;
  /** TTL in seconds. */
  ttl: number;
}
