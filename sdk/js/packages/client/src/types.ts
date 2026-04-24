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

/** Full serialized transaction (from getTransactions / getBlockTransactionsExt). */
export interface Transaction {
  "@type": "raw.transaction";
  data: string;               // base64-encoded BOC
  transaction_id: TransactionId;
  fee: string;
  storage_fee: string;
  other_fee: string;
  in_msg?: unknown;
  out_msgs?: unknown[];
}

// ---------------------------------------------------------------------------
// Token data (discriminated union)
// ---------------------------------------------------------------------------

export interface NftItemData {
  "@type": "nft.itemData";
  init: boolean;
  index: string;
  collection_address: string;
  owner_address: string;
  content: string;
}

export interface NftCollectionData {
  "@type": "nft.collectionData";
  next_item_index: string;
  collection_content: string;
  owner_address: string;
}

export interface JettonMasterData {
  "@type": "jetton.masterData";
  total_supply: string;
  mintable: boolean;
  admin_address: string;
  content: string;
  jetton_wallet_code: string;
}

export interface JettonWalletData {
  "@type": "jetton.walletData";
  balance: string;
  owner: string;
  jetton_master_address: string;
  jetton_wallet_code: string;
}

export type TokenData =
  | NftItemData
  | NftCollectionData
  | JettonMasterData
  | JettonWalletData;

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

export interface BlockSignatures {
  "@type": "blocks.blockSignatures";
  id: BlockIdExt;
  signatures: Array<{
    node_id_short: string;
    signature: string;
  }>;
}

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
