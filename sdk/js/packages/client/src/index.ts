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
  ShortTransaction,
  Transaction,
  NftItemData,
  NftCollectionData,
  JettonMasterData,
  JettonWalletData,
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
  ErrorCodes,
} from "./errors.js";
export type { ErrorCode } from "./errors.js";

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
export { open, setCoreParser } from "./provider/open.js";
export type { OpenedContract, ContractLike } from "./provider/open.js";

// Client
export { TosClient } from "./client/TosClient.js";
export type { TosClientOptions } from "./client/TosClient.js";

// Networks
export { Networks } from "./client/Networks.js";
export type { NetworkConfig } from "./client/Networks.js";

// Utilities
export { waitForTransaction, waitForSeqnoChange } from "./utils/wait.js";
export type { WaitOpts } from "./utils/wait.js";
