/**
 * @tos/sdk — Official TypeScript SDK for TOS Blockchain
 *
 * Umbrella package that re-exports all sub-packages for convenience.
 * For optimal bundle size in production, import from specific packages instead:
 *   import { TosClient, open } from "@tos/client";
 *   import { WalletV4R2 } from "@tos/wallets";
 *   import { toNano, Address } from "@tos/core";
 */

// Layer 1: Core types (canonical source for Address, Cell, SendMode, StateInit, etc.)
export * from "@tos/core";

// Layer 1: Crypto primitives (canonical source for sha256, sign, mnemonic, etc.)
// Exclude sha256 which conflicts with the internal sha256 in @tos/core
export {
  type KeyPair,
  mnemonicGenerate,
  mnemonicValidate,
  mnemonicToPrivateKey,
  mnemonicToHDSeed,
  keyPairFromSeed,
  keyPairFromSecretKey,
  sign,
  signVerify,
  sha512,
  deriveEd25519Path,
} from "@tos/crypto";

// Layer 2: Client (exclude types that conflict with @tos/core)
export {
  // Classes
  TosClient,
  TosError,
  TosRpcError,
  TosContractError,
  ErrorCodes,
  StackReaderImpl,
  // Functions
  open,
  waitForTransaction,
  waitForSeqnoChange,
  // Constants
  Networks,
} from "@tos/client";

export type {
  // Provider interfaces
  TosProvider,
  AccountActions,
  BlockActions,
  TransactionActions,
  ContractActions,
  SendActions,
  IntentActions,
  ConfigActions,
  ContractProvider,
  ContractState,
  ContractGetResult,
  SendConfirmation,
  StackReader,
  Signer,
  SenderArguments,
  OpenedContract,
  TosClientOptions,
  NetworkConfig,
  WaitOpts,
  AddressLike,
  CellLike,
  TupleItemLike,
  BlockQueryOpts,
  // Response types
  BlockIdExt,
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
  TokenData,
  ConfigAll,
  LibraryEntry,
  BlockHeader,
  BlockSignatures,
  ShardInfo,
  ShardBlockProof,
  // Permission types
  AccountCapability,
  DelegationGrant,
  SessionCapability,
  AgentCapability,
  // Intent types
  TransactionIntentRequest,
  TransactionIntent,
  AuthorizationRoles,
  SigningPayloadRequest,
  SigningPayload,
  SubmitSignedRequest,
  SubmissionResult,
} from "@tos/client";

// Layer 3: Wallets
export * from "@tos/wallets";

// Layer 4: Contracts (exclude NftCollectionData/NftItemData if they conflict with client types)
export {
  JettonMinter,
  JettonWallet,
  NftCollection,
  NftItem,
} from "@tos/contracts";

export type {
  JettonData,
  JettonContent,
  NftCollectionData,
  NftItemData,
} from "@tos/contracts";
