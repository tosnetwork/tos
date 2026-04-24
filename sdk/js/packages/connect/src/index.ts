/**
 * @tos/connect — Wallet-DApp communication protocol for TOS Blockchain.
 *
 * Framework-agnostic. Supports HTTP bridge and injected wallet providers.
 */

// ---- Main class ----
export { TosConnect } from "./TosConnect.js";
export type { TosConnectOptions } from "./TosConnect.js";

// ---- Protocol types ----
export type {
  DAppManifest,
  WalletInfo,
  WalletPlatform,
  ConnectRequest,
  ConnectItem,
  ConnectItemName,
  ConnectedAccount,
  ConnectedWallet,
  DeviceInfo,
  WalletFeature,
  SendTransactionFeature,
  SignDataFeature,
  SendTransactionRequest,
  TransactionMessage,
  SendTransactionResponse,
  SignDataRequest,
  SignDataResponse,
  TosChain,
  ConnectItemReply,
  TosAddressItemReply,
  TosProofItemReply,
  ConnectStorage,
  InjectedTosProvider,
  SendTransactionRpcRequest,
  SignDataRpcRequest,
  RpcRequest,
  RpcResponse,
  WalletEventName,
  WalletEvent,
  ConnectEventPayload,
  ConnectErrorPayload,
  BridgeIncomingMessage,
  PersistedSession,
} from "./types.js";

// ---- Errors ----
export {
  TosConnectError,
  ConnectErrorCodes,
  userRejectedError,
  walletNotFoundError,
  bridgeUnreachableError,
  sessionExpiredError,
  sessionRestoreFailedError,
  txRejectedError,
  txTimeoutError,
  txInvalidError,
  protocolVersionMismatchError,
  manifestFetchFailedError,
} from "./errors.js";
export type { ConnectErrorCode } from "./errors.js";

// ---- Session ----
export {
  generateSessionKeypair,
  encryptMessage,
  decryptMessage,
  saveSession,
  loadSession,
  clearSession,
} from "./session.js";
export type { SessionKeypair } from "./session.js";

// ---- Bridge ----
export { BridgeClient } from "./bridge.js";
export type { BridgeClientOptions, BridgeMessage } from "./bridge.js";

// ---- Injected wallet ----
export {
  InjectedBridge,
  getInjectedProviders,
  isWalletInjected,
  findInjectedProvider,
} from "./injected.js";

// ---- Storage ----
export {
  LocalStorageAdapter,
  MemoryStorageAdapter,
  createDefaultStorage,
} from "./storage.js";

// ---- Wallets ----
export { defaultWallets, fetchWalletList } from "./wallets.js";

// ---- Utilities ----
export {
  buildUniversalLink,
  isBrowser,
  toBase64Url,
  fromBase64Url,
  generateRequestId,
  withTimeout,
} from "./utils.js";
