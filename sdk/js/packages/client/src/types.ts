/**
 * @tos/client — Wire-format response types.
 *
 * All field names use snake_case to match the C++ JSON-RPC server output.
 * Numeric values that may exceed Number.MAX_SAFE_INTEGER are represented
 * as strings (e.g. logical time, balances).
 */

// ---------------------------------------------------------------------------
// Core building blocks
// ---------------------------------------------------------------------------

/** Block identifier with hashes. */
export interface BlockIdExt {
  "@type": "tos.blockIdExt";
  workchain: number;
  shard: string;
  seqno: number;
  root_hash: string;
  file_hash: string;
}

/** Extra currency entry (id + amount string). */
export interface ExtraCurrency {
  id: number;
  amount: string;
}

/** Transaction identifier (lt + hash). */
export interface TransactionId {
  "@type": "internal.transactionId";
  lt: string;
  hash: string;
}

// ---------------------------------------------------------------------------
// Account types
// ---------------------------------------------------------------------------

/** Response from getAddressInformation (raw.fullAccountState). */
export interface AccountInfo {
  "@type": "raw.fullAccountState";
  balance: string;
  code: string;
  data: string;
  last_transaction_id: TransactionId;
  block_id: BlockIdExt;
  sync_utime: number;
  extra_currencies: ExtraCurrency[];
  state: string;
  frozen_hash: string;
}

/** Response from getExtendedAddressInformation (fullAccountState). */
export interface ExtendedAccountInfo {
  "@type": "fullAccountState";
  address: { "@type": "accountAddress"; account_address: string };
  balance: number;
  extra_currencies: ExtraCurrency[];
  last_transaction_id: TransactionId;
  block_id: BlockIdExt;
  sync_utime: number;
  account_state: {
    "@type": "raw.accountState";
    code: string;
    data: string;
    frozen_hash: string;
  };
  revision: number;
}

/** Response from getWalletInformation (ext.accounts.walletInformation). */
export interface WalletInfo {
  "@type": "ext.accounts.walletInformation";
  wallet: boolean;
  balance: string;
  account_state: string;
  last_transaction_id: TransactionId;
  wallet_type: string | null;
  seqno: number | null;
  wallet_id: number | null;
}

// ---------------------------------------------------------------------------
// Fee estimate
// ---------------------------------------------------------------------------

export interface FeeEstimate {
  "@type": "query.fees";
  source_fees: {
    "@type": "fees";
    in_fwd_fee: number;
    storage_fee: number;
    gas_fee: number;
    fwd_fee: number;
  };
  destination_fees: Array<{
    "@type": "fees";
    in_fwd_fee: number;
    storage_fee: number;
    gas_fee: number;
    fwd_fee: number;
  }>;
}

// ---------------------------------------------------------------------------
// Masterchain / consensus
// ---------------------------------------------------------------------------

/** Response from getMasterchainInfo. */
export interface MasterchainInfo {
  "@type": "blocks.masterchainInfo";
  last: BlockIdExt;
  state_root_hash: string;
  init: {
    "@type": "tos.blockIdExt";
    workchain: number;
    shard: string;
    seqno: number;
    root_hash: string;
    file_hash: string;
  };
}

/** Response from getConsensusBlock. */
export interface ConsensusBlock {
  "@type": "consensus.block";
  consensus_block: number;
  timestamp: number;
}

// ---------------------------------------------------------------------------
// Smart-contract run result
// ---------------------------------------------------------------------------

/** Response from runGetMethod. */
export interface RunResult {
  "@type": "smc.runResult";
  gas_used: number;
  exit_code: number;
  stack: unknown[];
}

// ---------------------------------------------------------------------------
// Transaction locate
// ---------------------------------------------------------------------------

/** Response from tryLocateTx / tryLocateResultTx / tryLocateSourceTx. */
export interface LocateResult {
  "@type": "blocks.locate";
  block_id: BlockIdExt;
  transaction_id: TransactionId;
}

// ---------------------------------------------------------------------------
// Readyz
// ---------------------------------------------------------------------------

export interface ReadyzResult {
  ready: boolean;
  lag_seconds: number;
}

// ---------------------------------------------------------------------------
// Queue size
// ---------------------------------------------------------------------------

/** A single shard's outbound message queue size. */
export interface OutMsgQueueSizeShard {
  "@type": "blocks.outMsgQueueSize";
  id: BlockIdExt;
  size: number;
}

/** Response from getOutMsgQueueSize (blocks.outMsgQueueSizes). */
export interface OutMsgQueueSize {
  "@type": "blocks.outMsgQueueSizes";
  shards: OutMsgQueueSizeShard[];
  ext_msg_queue_size_limit: number;
}

// ---------------------------------------------------------------------------
// Short / full transactions
// ---------------------------------------------------------------------------

export interface ShortTransaction {
  "@type": "blocks.shortTxId";
  account?: string;
  lt?: string;
  hash?: string;
}

/**
 * A message as `getTransactions` summarizes it. `hash` is the base64
 * representation hash of the message cell: for an external message it equals
 * the hash `sendQuery` / `sendBocReturnHash` returned when it was sent.
 */
export interface MessageSummary {
  hash?: string;
  kind: "external" | "internal" | "unknown";
  source?: string;
  destination?: string;
  value?: string;
  bounced?: boolean;
  created_lt?: string;
  created_at?: number;
}

/** The compute phase of an ordinary or tick-tock transaction. */
export type ComputePhaseSummary =
  | {
      skipped: false;
      success: boolean;
      exit_code: number;
      vm_steps: number;
      account_activated: boolean;
    }
  | { skipped: true; skip_reason: number };

/** The action phase of an ordinary or tick-tock transaction. */
export interface ActionPhaseSummary {
  success: boolean;
  valid: boolean;
  no_funds: boolean;
  result_code: number;
  total_actions: number;
  skipped_actions: number;
  messages_created: number;
}

/** Full serialized transaction (from getTransactions / getBlockTransactionsExt). */
export interface Transaction {
  "@type": "raw.transaction";
  block_id?: BlockIdExt;
  data: string;               // base64-encoded BOC
  utime?: number;
  transaction_id: TransactionId;
  fee: string;
  account?: string;
  in_msg_hash?: string;
  /** The inbound message; null for a transaction without one. */
  in_msg: MessageSummary | null;
  out_msgs: MessageSummary[];
  transaction_type?: string;
  aborted?: boolean | null;
  destroyed?: boolean | null;
  compute?: ComputePhaseSummary | null;
  action?: ActionPhaseSummary | null;
}

// ---------------------------------------------------------------------------
// Token data (discriminated union)
// ---------------------------------------------------------------------------

type TokenMetadata<Prefix extends string> = Partial<Record<
  `${Prefix}_${"name" | "symbol" | "decimals" | "image" | "description" | "metadata_uri"}`,
  string
>>;

export interface NftItemData extends TokenMetadata<"nft"> {
  "@type": "ext.tokens.nftItemData";
  init: boolean;
  index: string;
  collection_address: string;
  owner_address: string;
  individual_content: string;
}

export interface NftCollectionData extends TokenMetadata<"collection"> {
  "@type": "ext.tokens.nftCollectionData";
  next_item_index: string;
  collection_content: string;
  owner_address: string;
}

export interface TokenMasterData extends TokenMetadata<"token"> {
  "@type": "ext.tokens.tokenMasterData";
  total_supply: string;
  mintable: boolean;
  admin_address: string;
  token_content: string;
  token_wallet_code: string;
}

export type TokenData =
  | NftItemData
  | NftCollectionData
  | TokenMasterData;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface ConfigAll {
  "@type": "configInfo";
  config: {
    "@type": "tvm.cell";
    bytes: string;
  };
}

export interface LibraryEntry {
  hash: string;
  data: string;
}

// ---------------------------------------------------------------------------
// Block header / signatures / shards
// ---------------------------------------------------------------------------

export interface BlockHeader {
  "@type": "blocks.header";
  id: BlockIdExt;
  global_id: number;
  version: number;
  flags: number;
  after_merge: boolean;
  after_split: boolean;
  before_split: boolean;
  want_merge: boolean;
  want_split: boolean;
  validator_list_hash_short: number;
  catchain_seqno: number;
  min_ref_mc_seqno: number;
  is_key_block: boolean;
  prev_key_block_seqno: number;
  start_lt: string;
  end_lt: string;
  gen_utime: number;
  prev_blocks: BlockIdExt[];
}

export interface BlockSignatureEntry {
  node_id_short: string;
  signature: string;
}

/** Validator signatures for a masterchain block signed under ordinary consensus. */
export interface BlockSignaturesOrdinary {
  "@type": "blocks.blockSignatures";
  id: BlockIdExt;
  signatures: BlockSignatureEntry[];
}

/**
 * Validator signatures for a masterchain block signed under simplex consensus.
 * Simplex signatures are made over a message derived from `session_id`, `slot`
 * and `candidate` (a finalize vote), not the block's root/file hash, so those
 * fields are required to reconstruct the signed message and verify a signature.
 */
export interface BlockSignaturesSimplex {
  "@type": "blocks.blockSignatures.simplex";
  id: BlockIdExt;
  signatures: BlockSignatureEntry[];
  /** base64-encoded 32-byte consensus session id */
  session_id: string;
  slot: number;
  /** base64-encoded serialized candidate consensus data */
  candidate: string;
}

export type BlockSignatures = BlockSignaturesOrdinary | BlockSignaturesSimplex;

export interface ShardInfo {
  "@type": "blocks.shards";
  shards: BlockIdExt[];
}

export interface ShardBlockProof {
  "@type": "blocks.shardBlockProof";
  from: BlockIdExt;
  mc_id: BlockIdExt;
  links: Array<{
    id: BlockIdExt;
    proof: string;
  }>;
  mc_proof: Array<{
    id: BlockIdExt;
    proof: string;
  }>;
}

// ---------------------------------------------------------------------------
// Permission types
// ---------------------------------------------------------------------------

/** Response from getAccountCapability. */
export interface AccountCapability {
  "@type": "account.capability";
  address: string;
  account_model: string;
  authorization_version: string;
  balance: string;
  account_state: string;
  wallet_type: string | null;
  seqno: number | null;
  supports_delegation: boolean;
  supports_sessions: boolean;
  supports_agents: boolean;
  revision: number;
  delegation_count: number;
  session_count: number;
  agent_count: number;
}

/** A single delegation grant. */
export interface DelegationGrant {
  "@type": "account.delegation";
  id: string;
  principal: string;
  start_at: number;
  available_balance: string;
  full_balance: string;
  status: string;
}

/** A session capability record. */
export interface SessionCapability {
  "@type": "account.session";
  session_id: number;
  principal: string;
  scope: number;
  created_at: number;
  expires_at: number;
  revoked: boolean;
  status: string;
}

/** An agent capability record. */
export interface AgentCapability {
  "@type": "account.agent";
  threshold_n: number;
  threshold_k: number;
  principals: string[];
  status: string;
}

// ---------------------------------------------------------------------------
// Intent types (buildTransactionIntent / getSigningPayload / submitSignedTransaction)
// ---------------------------------------------------------------------------

/** Authorization roles returned in a transaction intent. */
export interface AuthorizationRoles {
  signer: string;
  submitter: string;
}

/** Request body for buildTransactionIntent. */
export interface TransactionIntentRequest {
  address: string;
  body: string;             // base64 BOC
}

/** Response from buildTransactionIntent. */
export interface TransactionIntent {
  "@type": "transaction.intent";
  from: string;
  account_model: string;
  authorization_version: string;
  action: unknown;
  authorization_roles: AuthorizationRoles;
}

/** Request body for getSigningPayload. */
export interface SigningPayloadRequest {
  address: string;
  body: string;             // base64 BOC
}

/** Response from getSigningPayload. */
export interface SigningPayload {
  "@type": "transaction.signingPayload";
  payload_version: number;
  payload_encoding: string;
  payload: string;          // encoded bytes to sign
  chain_id: number;
}

/** Request body for submitSignedTransaction. */
export interface SubmitSignedRequest {
  intent_id: string;
  signature: string;        // base64
  public_key: string;       // hex or base64
}

/** Response from submitSignedTransaction. */
export interface SubmissionResult {
  "@type": "intent.submissionResult";
  intent_id: string;
  boc_hash: string;
  status: string;
}

// ---------------------------------------------------------------------------
// Block-transactions response wrapper
// ---------------------------------------------------------------------------

export interface BlockTransactions {
  "@type": "blocks.transactions";
  id: BlockIdExt;
  req_count: number;
  incomplete: boolean;
  transactions: ShortTransaction[];
}

export interface BlockTransactionsExt {
  "@type": "blocks.transactionsExt";
  id: BlockIdExt;
  req_count: number;
  incomplete: boolean;
  transactions: Transaction[];
}

// ---------------------------------------------------------------------------
// getTransactions response wrapper
// ---------------------------------------------------------------------------

export interface TransactionList {
  "@type": "raw.transactions";
  transactions: Transaction[];
  previous_transaction_id?: TransactionId;
}

// ---------------------------------------------------------------------------
// sendBoc / sendBocReturnHash / sendQuery responses
// ---------------------------------------------------------------------------

export interface SendBocResult {
  "@type"?: string;
  status: number;
}

export interface SendBocHashResult {
  "@type"?: string;
  hash: string;
}

export interface SendQueryResult {
  "@type"?: string;
  hash: string;
}
