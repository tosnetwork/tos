/**
 * @tos/react — React hooks for reading and writing TOS blockchain data.
 *
 * Inspired by wagmi for Ethereum.  Provides a provider/hook architecture
 * backed by `useSyncExternalStore` with no external state libraries.
 *
 * @example
 * ```tsx
 * import { createTosConfig, TosProvider, useBalance } from "@tos/react";
 *
 * const config = createTosConfig({ network: "mainnet" });
 *
 * function App() {
 *   return (
 *     <TosProvider config={config}>
 *       <Wallet />
 *     </TosProvider>
 *   );
 * }
 *
 * function Wallet() {
 *   const { data, isLoading } = useBalance("0:abc...");
 *   return <div>{isLoading ? "Loading..." : data?.toString()}</div>;
 * }
 * ```
 *
 * @packageDocumentation
 */

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export { createTosConfig } from "./config.js";
export type { CreateTosConfigOptions, TosConfig } from "./config.js";

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

export { TosProvider } from "./provider.js";
export type { TosProviderProps } from "./provider.js";

// ---------------------------------------------------------------------------
// Contexts (for @tos/connect-react and custom integrations)
// ---------------------------------------------------------------------------

export { SenderContext } from "./context.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type {
  QueryResult,
  QueryOptions,
  MutationResult,
  InfiniteQueryResult,
  Sender,
} from "./types.js";

// ---------------------------------------------------------------------------
// Hooks — Client
// ---------------------------------------------------------------------------

export { useClient } from "./hooks/useClient.js";

// ---------------------------------------------------------------------------
// Hooks — Account
// ---------------------------------------------------------------------------

export { useBalance } from "./hooks/useBalance.js";
export type { UseBalanceOptions } from "./hooks/useBalance.js";

export { useAccountInfo } from "./hooks/useAccountInfo.js";
export type { UseAccountInfoOptions } from "./hooks/useAccountInfo.js";

export { useAccountCapability } from "./hooks/useAccountCapability.js";
export type { UseAccountCapabilityOptions } from "./hooks/useAccountCapability.js";

// ---------------------------------------------------------------------------
// Hooks — Transactions
// ---------------------------------------------------------------------------

export { useSendTransaction } from "./hooks/useSendTransaction.js";
export type {
  SendTransactionArgs,
  UseSendTransactionResult,
} from "./hooks/useSendTransaction.js";

export { useWaitForTransaction } from "./hooks/useWaitForTransaction.js";
export type { UseWaitForTransactionOptions } from "./hooks/useWaitForTransaction.js";

export { useTransactions } from "./hooks/useTransactions.js";
export type { UseTransactionsOptions } from "./hooks/useTransactions.js";

export { useEstimateFee } from "./hooks/useEstimateFee.js";
export type {
  UseEstimateFeeArgs,
  UseEstimateFeeOptions,
} from "./hooks/useEstimateFee.js";

// ---------------------------------------------------------------------------
// Hooks — Contracts
// ---------------------------------------------------------------------------

export { useContractRead } from "./hooks/useContractRead.js";
export type {
  UseContractReadArgs,
  UseContractReadOptions,
} from "./hooks/useContractRead.js";

export { useContractWrite } from "./hooks/useContractWrite.js";
export type {
  ContractWriteArgs,
  UseContractWriteResult,
} from "./hooks/useContractWrite.js";

// ---------------------------------------------------------------------------
// Hooks — Tokens
// ---------------------------------------------------------------------------

export { useJettonBalance } from "./hooks/useJettonBalance.js";
export type {
  UseJettonBalanceArgs,
  UseJettonBalanceOptions,
} from "./hooks/useJettonBalance.js";

export { useTokenData } from "./hooks/useTokenData.js";
export type { UseTokenDataOptions } from "./hooks/useTokenData.js";

export { useNftData } from "./hooks/useNftData.js";
export type { NftItemInfo, UseNftDataOptions } from "./hooks/useNftData.js";

// ---------------------------------------------------------------------------
// Hooks — Chain / Blocks
// ---------------------------------------------------------------------------

export { useMasterchainInfo } from "./hooks/useMasterchainInfo.js";
export type { UseMasterchainInfoOptions } from "./hooks/useMasterchainInfo.js";

export { useBlockSeqno } from "./hooks/useBlockSeqno.js";
export type { UseBlockSeqnoOptions } from "./hooks/useBlockSeqno.js";

export { useConfigParam } from "./hooks/useConfigParam.js";
export type {
  UseConfigParamOptions,
  ConfigParamResult,
} from "./hooks/useConfigParam.js";

export { useShards } from "./hooks/useShards.js";
export type { UseShardsOptions } from "./hooks/useShards.js";

export { useBlockTransactions } from "./hooks/useBlockTransactions.js";
export type { UseBlockTransactionsOptions } from "./hooks/useBlockTransactions.js";
