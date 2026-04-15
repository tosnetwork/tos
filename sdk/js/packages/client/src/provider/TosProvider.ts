/**
 * @tos/client — TosProvider interface.
 *
 * This is the main abstraction layer between callers and the JSON-RPC
 * transport.  Each domain (accounts, blocks, transactions, ...) has its own
 * sub-interface so downstream consumers can depend on only the surface they
 * need.
 *
 * Types referenced from `@tos/core` are kept abstract (Address, Cell,
 * TupleItem) so that the provider interface itself does not pull in heavy
 * runtime code.
 */

import type {
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
  BlockIdExt,
  BlockHeader,
  BlockSignatures,
  ShardInfo,
  ShardBlockProof,
  ConfigAll,
  LibraryEntry,
  TokenData,
  AccountCapability,
  DelegationGrant,
  SessionCapability,
  AgentCapability,
  TransactionIntentRequest,
  TransactionIntent,
  SigningPayloadRequest,
  SigningPayload,
  SubmitSignedRequest,
  SubmissionResult,
  BlockTransactions,
  BlockTransactionsExt,
  Transaction,
  SendBocResult,
  SendBocHashResult,
  SendQueryResult,
} from "../types.js";

// ---------------------------------------------------------------------------
// Lightweight stand-ins for @tos/core types used in method signatures.
// The actual TosClient will accept real Address / Cell instances and convert
// them before sending over the wire.
// ---------------------------------------------------------------------------

/** Anything that can be serialized to a raw address string. */
export interface AddressLike {
  toRawString(): string;
}

/** Anything that can be serialized to a BOC (Bag of Cells). */
export interface CellLike {
  toBoc(): Uint8Array | { toString(encoding: "base64"): string };
}

/** A TVM stack item (mirroring @tos/core TupleItem). */
export type TupleItemLike =
  | { type: "int"; value: bigint }
  | { type: "cell"; cell: CellLike }
  | { type: "slice"; cell: CellLike }
  | { type: "builder"; cell: CellLike }
  | { type: "null" };

// ---------------------------------------------------------------------------
// Options shared across many queries
// ---------------------------------------------------------------------------

/** Optional historic-block query hint. */
export interface BlockQueryOpts {
  /** Query at this masterchain seqno instead of latest. */
  seqno?: number;
}

// ---------------------------------------------------------------------------
// Account actions
// ---------------------------------------------------------------------------

export interface AccountActions {
  getAddressInformation(address: AddressLike | string, opts?: BlockQueryOpts): Promise<AccountInfo>;
  getExtendedAddressInformation(address: AddressLike | string, opts?: BlockQueryOpts): Promise<ExtendedAccountInfo>;
  getWalletInformation(address: AddressLike | string, opts?: BlockQueryOpts): Promise<WalletInfo>;
  getBalance(address: AddressLike | string, opts?: BlockQueryOpts): Promise<string>;
  getState(address: AddressLike | string, opts?: BlockQueryOpts): Promise<string>;
  getAccountCapability(address: AddressLike | string, opts?: BlockQueryOpts): Promise<AccountCapability>;
  getAccountDelegations(address: AddressLike | string, opts?: BlockQueryOpts): Promise<DelegationGrant[]>;
  getAccountSessions(address: AddressLike | string, opts?: BlockQueryOpts): Promise<SessionCapability[]>;
  getAccountAgents(address: AddressLike | string, opts?: BlockQueryOpts): Promise<AgentCapability[]>;
}

// ---------------------------------------------------------------------------
// Block actions
// ---------------------------------------------------------------------------

export interface BlockActions {
  getMasterchainInfo(): Promise<MasterchainInfo>;
  getConsensusBlock(): Promise<ConsensusBlock>;
  lookupBlock(workchain: number, shard: string, seqno: number, opts?: { lt?: string; utime?: number }): Promise<BlockIdExt>;
  getBlockHeader(workchain: number, shard: string, seqno: number): Promise<BlockHeader>;
  getShards(seqno: number): Promise<ShardInfo>;
  getMasterchainBlockSignatures(seqno: number): Promise<BlockSignatures>;
  getShardBlockProof(workchain: number, shard: string, seqno: number): Promise<ShardBlockProof>;
}

// ---------------------------------------------------------------------------
// Transaction actions
// ---------------------------------------------------------------------------

export interface TransactionActions {
  getTransactions(
    address: AddressLike | string,
    limit: number,
    opts?: { lt?: string; hash?: string; to_lt?: string; archival?: boolean },
  ): Promise<Transaction[]>;
  getBlockTransactions(
    workchain: number,
    shard: string,
    seqno: number,
    opts?: { count?: number; after_lt?: string; after_hash?: string },
  ): Promise<BlockTransactions>;
  getBlockTransactionsExt(
    workchain: number,
    shard: string,
    seqno: number,
    opts?: { count?: number; after_lt?: string; after_hash?: string },
  ): Promise<BlockTransactionsExt>;
  tryLocateTx(source: AddressLike | string, destination: AddressLike | string, created_lt: string): Promise<LocateResult>;
  tryLocateResultTx(source: AddressLike | string, destination: AddressLike | string, created_lt: string): Promise<LocateResult>;
  tryLocateSourceTx(source: AddressLike | string, destination: AddressLike | string, created_lt: string): Promise<LocateResult>;
}

// ---------------------------------------------------------------------------
// Contract actions
// ---------------------------------------------------------------------------

export interface ContractActions {
  runGetMethod(
    address: AddressLike | string,
    method: string | number,
    stack?: TupleItemLike[],
    opts?: BlockQueryOpts,
  ): Promise<RunResult>;
}

// ---------------------------------------------------------------------------
// Send actions
// ---------------------------------------------------------------------------

export interface SendActions {
  sendBoc(boc: CellLike | Uint8Array | string): Promise<SendBocResult>;
  sendBocReturnHash(boc: CellLike | Uint8Array | string): Promise<SendBocHashResult>;
  sendQuery(body: {
    address: AddressLike | string;
    body: CellLike | string;
    init_code?: CellLike | string;
    init_data?: CellLike | string;
  }): Promise<SendQueryResult>;
  estimateFee(
    address: AddressLike | string,
    body: CellLike | string,
    init_code?: CellLike | string,
    init_data?: CellLike | string,
    ignore_chksig?: boolean,
  ): Promise<FeeEstimate>;
}

// ---------------------------------------------------------------------------
// Intent actions
// ---------------------------------------------------------------------------

export interface IntentActions {
  buildTransactionIntent(request: TransactionIntentRequest): Promise<TransactionIntent>;
  getSigningPayload(request: SigningPayloadRequest): Promise<SigningPayload>;
  submitSignedTransaction(request: SubmitSignedRequest): Promise<SubmissionResult>;
}

// ---------------------------------------------------------------------------
// Config / utility actions
// ---------------------------------------------------------------------------

export interface ConfigActions {
  getConfigParam(param: number, opts?: BlockQueryOpts): Promise<{ config: { bytes: string } }>;
  getConfigAll(opts?: BlockQueryOpts): Promise<ConfigAll>;
  getLibraries(libraryList: string[]): Promise<LibraryEntry[]>;
  getTokenData(address: AddressLike | string): Promise<TokenData>;
  getOutMsgQueueSize(): Promise<OutMsgQueueSize>;
  isReady(): Promise<ReadyzResult>;
}

// ---------------------------------------------------------------------------
// Unified provider
// ---------------------------------------------------------------------------

export interface TosProvider
  extends AccountActions,
    BlockActions,
    TransactionActions,
    SendActions,
    ContractActions,
    ConfigActions,
    IntentActions {
  /**
   * Low-level escape hatch: call any JSON-RPC method directly.
   * Returns the parsed `result` field from the JSON-RPC response.
   */
  rawCall<T = unknown>(method: string, params?: Record<string, unknown>): Promise<T>;
}
