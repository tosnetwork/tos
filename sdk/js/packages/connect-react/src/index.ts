/**
 * @tos/connect-react — All-in-one React integration for TOS Blockchain.
 *
 * Combines @tos/connect (protocol), @tos/connect-ui (modals), and
 * @tos/react (hooks) into a single developer-friendly entry point.
 *
 * @example
 * ```tsx
 * import {
 *   TosConnectProvider,
 *   ConnectButton,
 *   useWallet,
 *   useBalance,
 *   useSendTransaction,
 * } from "@tos/connect-react";
 * import "@tos/connect-react/styles.css";
 *
 * function App() {
 *   return (
 *     <TosConnectProvider
 *       config={{ manifestUrl: "https://myapp.com/manifest.json" }}
 *     >
 *       <ConnectButton />
 *       <MyDApp />
 *     </TosConnectProvider>
 *   );
 * }
 * ```
 *
 * @packageDocumentation
 */

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export { TosConnectProvider } from "./provider.js";

// ---------------------------------------------------------------------------
// Components
// ---------------------------------------------------------------------------

export { ConnectButton } from "./components/ConnectButton.js";

// ---------------------------------------------------------------------------
// Connection hooks (this package)
// ---------------------------------------------------------------------------

export { useWallet } from "./hooks/useWallet.js";
export { useConnect } from "./hooks/useConnect.js";
export { useConnectModal } from "./hooks/useConnectModal.js";
export { useSignData } from "./hooks/useSignData.js";
export { useOnDisconnect } from "./hooks/useOnDisconnect.js";
export { useWalletInfo } from "./hooks/useWalletInfo.js";

// ---------------------------------------------------------------------------
// Types (this package)
// ---------------------------------------------------------------------------

export type {
  TosConnectConfig,
  TosConnectProviderProps,
  ThemeConfig,
  ThemeProp,
  TranslationKeys,
  ConnectButtonProps,
  ConnectButtonCustomProps,
  ConnectButtonRenderProps,
  UseWalletResult,
  UseConnectResult,
  UseConnectModalResult,
  UseSignDataResult,
  UseWalletInfoResult,
} from "./types.js";

// ---------------------------------------------------------------------------
// Re-exports from @tos/react — config & provider
// ---------------------------------------------------------------------------

export { createTosConfig, TosProvider, SenderContext } from "@tos/react";
export type { CreateTosConfigOptions, TosConfig, TosProviderProps } from "@tos/react";

// Re-export shared types
export type {
  QueryResult,
  QueryOptions,
  MutationResult,
  InfiniteQueryResult,
  Sender,
} from "@tos/react";

// ---------------------------------------------------------------------------
// Re-exports from @tos/react — all hooks
// ---------------------------------------------------------------------------

// Client
export { useClient } from "@tos/react";

// Account
export { useBalance } from "@tos/react";
export type { UseBalanceOptions } from "@tos/react";

export { useAccountInfo } from "@tos/react";
export type { UseAccountInfoOptions } from "@tos/react";

export { useAccountCapability } from "@tos/react";
export type { UseAccountCapabilityOptions } from "@tos/react";

// Transactions
export { useSendTransaction } from "@tos/react";
export type { SendTransactionArgs, UseSendTransactionResult } from "@tos/react";

export { useWaitForTransaction } from "@tos/react";
export type { UseWaitForTransactionOptions } from "@tos/react";

export { useTransactions } from "@tos/react";
export type { UseTransactionsOptions } from "@tos/react";

export { useEstimateFee } from "@tos/react";
export type { UseEstimateFeeArgs, UseEstimateFeeOptions } from "@tos/react";

// Contracts
export { useContractRead } from "@tos/react";
export type { UseContractReadArgs, UseContractReadOptions } from "@tos/react";

export { useContractWrite } from "@tos/react";
export type { ContractWriteArgs, UseContractWriteResult } from "@tos/react";

// Tokens
export { useJettonBalance } from "@tos/react";
export type { UseJettonBalanceArgs, UseJettonBalanceOptions } from "@tos/react";

export { useTokenData } from "@tos/react";
export type { UseTokenDataOptions } from "@tos/react";

export { useNftData } from "@tos/react";
export type { NftItemInfo, UseNftDataOptions } from "@tos/react";

// Chain / Blocks
export { useMasterchainInfo } from "@tos/react";
export type { UseMasterchainInfoOptions } from "@tos/react";

export { useBlockSeqno } from "@tos/react";
export type { UseBlockSeqnoOptions } from "@tos/react";

export { useConfigParam } from "@tos/react";
export type { UseConfigParamOptions, ConfigParamResult } from "@tos/react";

export { useShards } from "@tos/react";
export type { UseShardsOptions } from "@tos/react";

export { useBlockTransactions } from "@tos/react";
export type { UseBlockTransactionsOptions } from "@tos/react";

// ---------------------------------------------------------------------------
// Re-exports from @tos/connect — protocol types and errors
// ---------------------------------------------------------------------------

export type {
  WalletInfo,
  ConnectedWallet,
  ConnectedAccount,
  DeviceInfo,
  WalletFeature,
  ConnectRequest,
  ConnectItem,
  SendTransactionRequest,
  TransactionMessage,
  SendTransactionResponse,
  SignDataRequest,
  SignDataResponse,
  ConnectItemReply,
  TonAddressItemReply,
  TonProofItemReply,
  ConnectStorage,
  DAppManifest,
  InjectedTosProvider,
  WalletEvent,
} from "@tos/connect";

export { TosConnectError, ConnectErrorCodes } from "@tos/connect";

// ---------------------------------------------------------------------------
// Re-exports from @tos/core — commonly used primitives
// ---------------------------------------------------------------------------

export { Address, toNano, fromNano, comment } from "@tos/core";
export type { Cell, TupleReader, TupleItem } from "@tos/core";

// ---------------------------------------------------------------------------
// Re-exports from @tos/client — error types and client
// ---------------------------------------------------------------------------

export { TosError, TosClient, Networks } from "@tos/client";
