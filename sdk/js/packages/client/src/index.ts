/**
 * @tos/client — JSON-RPC client and Provider for TOS Blockchain.
 *
 * @packageDocumentation
 */

// Types — wire-format response types matching C++ server output
export type {
  BlockIdExt,
  ExtraCurrency,
  TransactionId,
  AccountInfo,
  ExtendedAccountInfo,
  WalletInfo,
  FeeEstimate,
  MasterchainInfo,
  ConsensusBlock,
  RunResult,
  LocateResult,
  ReadyzResult,
  OutMsgQueueSize,
  OutMsgQueueSizeShard,
  ShortTransaction,
  Transaction,
  MessageSummary,
  ComputePhaseSummary,
  ActionPhaseSummary,
  NftItemData,
  NftCollectionData,
  TokenMasterData,
  TokenWalletData,
  TokenData,
  ConfigAll,
  LibraryEntry,
  BlockHeader,
  BlockSignatures,
  ShardInfo,
  ShardBlockProof,
  AccountCapability,
  DelegationGrant,
  SessionCapability,
  AgentCapability,
  AuthorizationRoles,
  TransactionIntentRequest,
  TransactionIntent,
  SigningPayloadRequest,
  SigningPayload,
  SubmitSignedRequest,
  SubmissionResult,
  BlockTransactions,
  BlockTransactionsExt,
  TransactionList,
  SendBocResult,
  SendBocHashResult,
  SendQueryResult,
} from "./types.js";

// Errors
export {
  TosError,
  TosRpcError,
  TosContractError,
  TosNotDeployedError,
  TosNotDeliveredError,
  INACTIVE_ACCOUNT_EXIT_CODE,
  ErrorCodes,
  ErrorReasons,
} from "./errors.js";
export type { ErrorCode, ErrorReason, RpcErrorData } from "./errors.js";

// Provider interfaces
export type {
  TosProvider,
  AccountActions,
  BlockActions,
  TransactionActions,
  ContractActions,
  SendActions,
  IntentActions,
  ConfigActions,
  AddressLike,
  CellLike,
  TupleItemLike,
  BlockQueryOpts,
} from "./provider/TosProvider.js";

export type {
  ContractProvider,
  ContractState,
  ContractGetResult,
  SendConfirmation,
  ExternalSendResult,
  SendMode,
  StateInit,
  StackReader,
  SenderArguments as ContractSenderArguments,
} from "./provider/ContractProvider.js";

export { StackReaderImpl } from "./utils/StackReader.js";

export type {
  Signer,
  SenderArguments,
} from "./provider/Signer.js";

// open() and OpenedContract
export { open, setCoreParser, externalStateInit } from "./provider/open.js";
export type {
  OpenedContract,
  ContractLike,
  StateInitLike,
  ExternalStateInitFields,
} from "./provider/open.js";

// Client
export { TosClient } from "./client/TosClient.js";
export type { TosClientOptions } from "./client/TosClient.js";

// Networks
export { Networks } from "./client/Networks.js";
export type { NetworkConfig } from "./client/Networks.js";

// Utilities
export {
  waitForTransaction,
  waitForTransfer,
  waitForReceipt,
  requireDelivered,
  MAX_TRANSACTIONS_PER_POLL,
} from "./utils/wait.js";
export type { WaitOpts, PendingTransfer, Receipt } from "./utils/wait.js";
