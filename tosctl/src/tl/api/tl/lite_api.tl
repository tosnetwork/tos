int ? = Int;
long ? = Long;
double ? = Double;
string ? = String;
object ? = Object;
function ? = Function;
bytes data:string = Bytes;
true = True;
boolTrue = Bool;
boolFalse = Bool;


vector {t:Type} # [ t ] = Vector t;

int128 4*[ int ] = Int128;
int256 8*[ int ] = Int256;

tosNode.blockId workchain:int shard:long seqno:int = tosNode.BlockId;
tosNode.blockIdExt workchain:int shard:long seqno:int root_hash:int256 file_hash:int256 = tosNode.BlockIdExt;
tosNode.zeroStateIdExt workchain:int root_hash:int256 file_hash:int256 = tosNode.ZeroStateIdExt;

adnl.message.query query_id:int256 query:bytes = adnl.Message;
adnl.message.answer query_id:int256 answer:bytes = adnl.Message;

liteServer.error code:int message:string = liteServer.Error; 

liteServer.accountId workchain:int id:int256 = liteServer.AccountId;
liteServer.libraryEntry hash:int256 data:bytes = liteServer.LibraryEntry;

liteServer.masterchainInfo last:tosNode.blockIdExt state_root_hash:int256 init:tosNode.zeroStateIdExt = liteServer.MasterchainInfo;
liteServer.masterchainInfoExt mode:# version:int capabilities:long last:tosNode.blockIdExt last_utime:int now:int state_root_hash:int256 init:tosNode.zeroStateIdExt = liteServer.MasterchainInfoExt;
liteServer.currentTime now:int = liteServer.CurrentTime;
liteServer.version mode:# version:int capabilities:long now:int = liteServer.Version;
liteServer.blockData id:tosNode.blockIdExt data:bytes = liteServer.BlockData;
liteServer.blockState id:tosNode.blockIdExt root_hash:int256 file_hash:int256 data:bytes = liteServer.BlockState;
liteServer.blockHeader id:tosNode.blockIdExt mode:# header_proof:bytes = liteServer.BlockHeader;
liteServer.sendMsgStatus status:int = liteServer.SendMsgStatus;
liteServer.accountState id:tosNode.blockIdExt shardblk:tosNode.blockIdExt shard_proof:bytes proof:bytes state:bytes = liteServer.AccountState;
liteServer.runMethodResult mode:# id:tosNode.blockIdExt shardblk:tosNode.blockIdExt shard_proof:mode.0?bytes proof:mode.0?bytes state_proof:mode.1?bytes init_c7:mode.3?bytes lib_extras:mode.4?bytes exit_code:int result:mode.2?bytes = liteServer.RunMethodResult;
liteServer.shardInfo id:tosNode.blockIdExt shardblk:tosNode.blockIdExt shard_proof:bytes shard_descr:bytes = liteServer.ShardInfo;
liteServer.allShardsInfo id:tosNode.blockIdExt proof:bytes data:bytes = liteServer.AllShardsInfo;
liteServer.transactionInfo id:tosNode.blockIdExt proof:bytes transaction:bytes = liteServer.TransactionInfo;
liteServer.transactionList ids:(vector tosNode.blockIdExt) transactions:bytes = liteServer.TransactionList;
liteServer.transactionMetadata mode:# depth:int initiator:liteServer.accountId initiator_lt:long = liteServer.TransactionMetadata;
liteServer.transactionId#b12f65af mode:# account:mode.0?int256 lt:mode.1?long hash:mode.2?int256 metadata:mode.8?liteServer.transactionMetadata = liteServer.TransactionId;
liteServer.transactionId3 account:int256 lt:long = liteServer.TransactionId3;
liteServer.blockTransactions id:tosNode.blockIdExt req_count:# incomplete:Bool ids:(vector liteServer.transactionId) proof:bytes = liteServer.BlockTransactions;
liteServer.blockTransactionsExt id:tosNode.blockIdExt req_count:# incomplete:Bool transactions:bytes proof:bytes = liteServer.BlockTransactionsExt;
liteServer.signature node_id_short:int256 signature:bytes = liteServer.Signature;
liteServer.signatureSet.ordinary#f644a6e6 validator_set_hash:int catchain_seqno:int signatures:(vector liteServer.signature) = liteServer.SignatureSet;
liteServer.signatureSet.simplex cc_seqno:int validator_set_hash:int signatures:(vector liteServer.signature)
 session_id:int256 slot:int candidate:bytes = liteServer.SignatureSet;
liteServer.blockLinkBack to_key_block:Bool from:tosNode.blockIdExt to:tosNode.blockIdExt dest_proof:bytes proof:bytes state_proof:bytes = liteServer.BlockLink;
liteServer.blockLinkForward to_key_block:Bool from:tosNode.blockIdExt to:tosNode.blockIdExt dest_proof:bytes config_proof:bytes signatures:liteServer.SignatureSet = liteServer.BlockLink;
liteServer.partialBlockProof complete:Bool from:tosNode.blockIdExt to:tosNode.blockIdExt steps:(vector liteServer.BlockLink) = liteServer.PartialBlockProof;
liteServer.configInfo mode:# id:tosNode.blockIdExt state_proof:bytes config_proof:bytes = liteServer.ConfigInfo;
liteServer.validatorStats mode:# id:tosNode.blockIdExt count:int complete:Bool state_proof:bytes data_proof:bytes = liteServer.ValidatorStats;
liteServer.libraryResult result:(vector liteServer.libraryEntry) = liteServer.LibraryResult;
liteServer.libraryResultWithProof id:tosNode.blockIdExt mode:# result:(vector liteServer.libraryEntry) state_proof:bytes data_proof:bytes = liteServer.LibraryResultWithProof;
liteServer.shardBlockLink id:tosNode.blockIdExt proof:bytes = liteServer.ShardBlockLink;
liteServer.shardBlockProof masterchain_id:tosNode.blockIdExt links:(vector liteServer.shardBlockLink) = liteServer.ShardBlockProof;
liteServer.lookupBlockResult id:tosNode.blockIdExt mode:# mc_block_id:tosNode.blockIdExt client_mc_state_proof:bytes mc_block_proof:bytes shard_links:(vector liteServer.shardBlockLink) header:bytes prev_header:bytes = liteServer.LookupBlockResult;
liteServer.outMsgQueueSize id:tosNode.blockIdExt size:int = liteServer.OutMsgQueueSize;
liteServer.outMsgQueueSizes shards:(vector liteServer.outMsgQueueSize) ext_msg_queue_size_limit:int = liteServer.OutMsgQueueSizes;
liteServer.blockOutMsgQueueSize mode:# id:tosNode.blockIdExt size:long proof:mode.0?bytes = liteServer.BlockOutMsgQueueSize;
liteServer.accountDispatchQueueInfo addr:int256 size:long min_lt:long max_lt:long = liteServer.AccountDispatchQueueInfo;
liteServer.dispatchQueueInfo mode:# id:tosNode.blockIdExt account_dispatch_queues:(vector liteServer.accountDispatchQueueInfo) complete:Bool proof:mode.0?bytes = liteServer.DispatchQueueInfo;
liteServer.dispatchQueueMessage addr:int256 lt:long hash:int256 metadata:liteServer.transactionMetadata = liteServer.DispatchQueueMessage;
liteServer.dispatchQueueMessages mode:# id:tosNode.blockIdExt messages:(vector liteServer.dispatchQueueMessage) complete:Bool
    proof:mode.0?bytes messages_boc:mode.2?bytes = liteServer.DispatchQueueMessages;

liteServer.debug.verbosity value:int = liteServer.debug.Verbosity;

liteServer.nonfinal.candidateId block_id:tosNode.blockIdExt creator:int256 collated_data_hash:int256 = liteServer.nonfinal.CandidateId;
liteServer.nonfinal.candidate id:liteServer.nonfinal.candidateId data:bytes collated_data:bytes = liteServer.nonfinal.Candidate;
liteServer.nonfinal.candidateInfo id:liteServer.nonfinal.candidateId available:Bool approved_weight:long signed_weight:long total_weight:long = liteServer.nonfinal.CandidateInfo;
liteServer.nonfinal.validatorGroupInfo next_block_id:tosNode.blockId cc_seqno:int prev:(vector tosNode.blockIdExt) candidates:(vector liteServer.nonfinal.candidateInfo) = liteServer.nonfinal.ValidatorGroupInfo;
liteServer.nonfinal.validatorGroups groups:(vector liteServer.nonfinal.validatorGroupInfo) = liteServer.nonfinal.ValidatorGroups;

---functions---

liteServer.getMasterchainInfo = liteServer.MasterchainInfo;
liteServer.getMasterchainInfoExt mode:# = liteServer.MasterchainInfoExt;
liteServer.getTime = liteServer.CurrentTime;
liteServer.getVersion = liteServer.Version;
liteServer.getBlock id:tosNode.blockIdExt = liteServer.BlockData;
liteServer.getState id:tosNode.blockIdExt = liteServer.BlockState;
liteServer.getBlockHeader id:tosNode.blockIdExt mode:# = liteServer.BlockHeader;
liteServer.sendMessage body:bytes = liteServer.SendMsgStatus;
liteServer.getAccountState id:tosNode.blockIdExt account:liteServer.accountId = liteServer.AccountState;
liteServer.getAccountStatePrunned id:tosNode.blockIdExt account:liteServer.accountId = liteServer.AccountState;
liteServer.runSmcMethod mode:# id:tosNode.blockIdExt account:liteServer.accountId method_id:long params:bytes = liteServer.RunMethodResult;
liteServer.getShardInfo id:tosNode.blockIdExt workchain:int shard:long exact:Bool = liteServer.ShardInfo;
liteServer.getAllShardsInfo id:tosNode.blockIdExt = liteServer.AllShardsInfo;
liteServer.getOneTransaction id:tosNode.blockIdExt account:liteServer.accountId lt:long = liteServer.TransactionInfo;
liteServer.getTransactions count:# account:liteServer.accountId lt:long hash:int256 = liteServer.TransactionList;
liteServer.lookupBlock mode:# id:tosNode.blockId lt:mode.1?long utime:mode.2?int = liteServer.BlockHeader;
liteServer.lookupBlockWithProof mode:# id:tosNode.blockId mc_block_id:tosNode.blockIdExt lt:mode.1?long utime:mode.2?int = liteServer.LookupBlockResult;
liteServer.listBlockTransactions id:tosNode.blockIdExt mode:# count:# after:mode.7?liteServer.transactionId3 reverse_order:mode.6?true want_proof:mode.5?true = liteServer.BlockTransactions;
liteServer.listBlockTransactionsExt id:tosNode.blockIdExt mode:# count:# after:mode.7?liteServer.transactionId3 reverse_order:mode.6?true want_proof:mode.5?true = liteServer.BlockTransactionsExt;
liteServer.getBlockProof mode:# known_block:tosNode.blockIdExt target_block:mode.0?tosNode.blockIdExt = liteServer.PartialBlockProof;
liteServer.getConfigAll mode:# id:tosNode.blockIdExt = liteServer.ConfigInfo;
liteServer.getConfigParams mode:# id:tosNode.blockIdExt param_list:(vector int) = liteServer.ConfigInfo;
liteServer.getValidatorStats#091a58bc mode:# id:tosNode.blockIdExt limit:int start_after:mode.0?int256 modified_after:mode.2?int = liteServer.ValidatorStats;
liteServer.getLibraries library_list:(vector int256) = liteServer.LibraryResult;
liteServer.getLibrariesWithProof id:tosNode.blockIdExt mode:# library_list:(vector int256) = liteServer.LibraryResultWithProof;
liteServer.getShardBlockProof id:tosNode.blockIdExt = liteServer.ShardBlockProof;
liteServer.getOutMsgQueueSizes mode:# wc:mode.0?int shard:mode.0?long = liteServer.OutMsgQueueSizes;
liteServer.getBlockOutMsgQueueSize mode:# id:tosNode.blockIdExt want_proof:mode.0?true = liteServer.BlockOutMsgQueueSize;
liteServer.getDispatchQueueInfo mode:# id:tosNode.blockIdExt after_addr:mode.1?int256 max_accounts:int want_proof:mode.0?true = liteServer.DispatchQueueInfo;
liteServer.getDispatchQueueMessages mode:# id:tosNode.blockIdExt addr:int256 after_lt:long max_messages:int
    want_proof:mode.0?true one_account:mode.1?true messages_boc:mode.2?true = liteServer.DispatchQueueMessages;

liteServer.nonfinal.getValidatorGroups mode:# wc:mode.0?int shard:mode.0?long = liteServer.nonfinal.ValidatorGroups;
liteServer.nonfinal.getCandidate id:liteServer.nonfinal.candidateId = liteServer.nonfinal.Candidate;

liteServer.queryPrefix = Object; 
liteServer.query data:bytes = Object;
liteServer.waitMasterchainSeqno seqno:int timeout_ms:int = Object; // query prefix
