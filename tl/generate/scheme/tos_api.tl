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

testObject value:int o:object f:function = TestObject;
testString value:string = TestObject;
testInt value:int = TestObject;
testVectorBytes value:(vector bytes) = TestObject;

tcp.pong random_id:long = tcp.Pong;

tcp.authentificate nonce:bytes = tcp.Message;
tcp.authentificationNonce nonce:bytes = tcp.Message;
tcp.authentificationComplete key:PublicKey signature:bytes = tcp.Message;

fec.raptorQ data_size:int symbol_size:int symbols_count:int = fec.Type;
fec.roundRobin data_size:int symbol_size:int symbols_count:int = fec.Type;
fec.online data_size:int symbol_size:int symbols_count:int = fec.Type;

---functions---

tcp.ping random_id:long = tcp.Pong;

getTestObject = TestObject;

---types---

pk.unenc data:bytes = PrivateKey;
pk.ed25519 key:int256 = PrivateKey;
pk.aes key:int256 = PrivateKey;
pk.overlay name:bytes = PrivateKey;

pub.unenc data:bytes = PublicKey;
pub.ed25519 key:int256 = PublicKey;
pub.aes key:int256 = PublicKey;
pub.overlay name:bytes = PublicKey;


---functions---

---types---

adnl.id.short id:int256 = adnl.id.Short;

adnl.proxyToFastHash ip:int port:int date:int data_hash:int256 shared_secret:int256 = adnl.ProxyTo;
adnl.proxyToFast ip:int port:int date:int signature:int256 = adnl.ProxyToSign;

adnl.proxy.none id:int256 = adnl.Proxy;
adnl.proxy.fast id:int256 shared_secret:bytes = adnl.Proxy;


adnl.address.udp ip:int port:int = adnl.Address;
adnl.address.udp6 ip:int128 port:int = adnl.Address;
//adnl.address.tcp ip:int port:int = adnl.Address;
//adnl.address.tcp6 ip:int128 port:int = adnl.Address;

adnl.address.tunnel to:int256 pubkey:PublicKey = adnl.Address;
adnl.address.reverse = adnl.Address;

adnl.address.quic ip:int port:int = adnl.Address;

adnl.addressList addrs:(vector adnl.Address) version:int reinit_date:int priority:int expire_at:int = adnl.AddressList;

adnl.node id:PublicKey addr_list:adnl.addressList = adnl.Node;
adnl.nodes nodes:(vector adnl.node) = adnl.Nodes;

---functions---

---types---

adnl.packetContents
  rand1:bytes
  flags:#
  from:flags.0?PublicKey
  from_short:flags.1?adnl.id.short
  message:flags.2?adnl.Message
  messages:flags.3?(vector adnl.Message)
  address:flags.4?adnl.addressList
  priority_address:flags.5?adnl.addressList
  seqno:flags.6?long
  confirm_seqno:flags.7?long
  recv_addr_list_version:flags.8?int
  recv_priority_addr_list_version:flags.9?int
  reinit_date:flags.10?int
  dst_reinit_date:flags.10?int
  signature:flags.11?bytes
  rand2:bytes
        = adnl.PacketContents;

adnl.tunnelPacketContents
  rand1:bytes
  flags:#
  from_ip:flags.0?int
  from_port:flags.0?int
  message:flags.1?bytes
  statistics:flags.2?bytes
  payment:flags.3?bytes
  rand2:bytes
        = adnl.TunnelPacketContents;


// flag 16 - packet is outbound
// flag 17 - control packet
adnl.proxyPacketHeader
  proxy_id:int256
  flags:#
  ip:flags.0?int
  port:flags.0?int
  adnl_start_time:flags.1?int
  seqno:flags.2?long
  date:flags.3?int
  signature:int256 = adnl.ProxyPacketHeader;

adnl.proxyControlPacketPing id:int256 = adnl.ProxyControlPacket;
adnl.proxyControlPacketPong id:int256 = adnl.ProxyControlPacket;
adnl.proxyControlPacketRegister ip:int port:int = adnl.ProxyControlPacket;


adnl.message.createChannel key:int256 date:int = adnl.Message;
adnl.message.confirmChannel key:int256 peer_key:int256 date:int = adnl.Message;

adnl.message.custom data:bytes = adnl.Message;

adnl.message.nop = adnl.Message;
adnl.message.reinit date:int = adnl.Message;

adnl.message.query query_id:int256 query:bytes = adnl.Message;
adnl.message.answer query_id:int256 answer:bytes = adnl.Message;

adnl.message.part hash:int256 total_size:int offset:int data:bytes = adnl.Message;

---functions---
---types---

adnl.db.node.key local_id:int256 peer_id:int256 = adnl.db.Key;
adnl.db.node.value date:int id:PublicKey addr_list:adnl.addressList priority_addr_list:adnl.addressList = adnl.db.node.Value;

adnl.stats.packets ts_start:double ts_end:double
    in_packets:long in_bytes:long in_packets_channel:long in_bytes_channel:long
    out_packets:long out_bytes:long out_packets_channel:long out_bytes_channel:long
    out_expired_messages:long out_expired_bytes:long = adnl.stats.Packets;
adnl.stats.peerPair local_id:int256 peer_id:int256 ip_str:string
    packets_recent:adnl.stats.packets packets_total:adnl.stats.packets
    last_out_packet_ts:double last_in_packet_ts:double
    connection_ready:Bool channel_status:int try_reinit_at:double
    out_queue_messages:long out_queue_bytes:long
    = adnl.stats.PeerPair;
adnl.stats.ipPackets ip_str:string packets:long = adnl.stats.IpPackets;
adnl.stats.localIdPackets ts_start:double ts_end:double
    decrypted_packets:(vector adnl.stats.ipPackets) dropped_packets:(vector adnl.stats.ipPackets) = adnl.stats.LocalIdPackets;
adnl.stats.localId short_id:int256
    current_decrypt:(vector adnl.stats.ipPackets)
    packets_recent:adnl.stats.localIdPackets
    peers:(vector adnl.stats.peerPair) = adnl.stats.LocalId;
adnl.stats timestamp:double local_ids:(vector adnl.stats.localId) = adnl.Stats;

---functions---


---types---

rldp2.messagePart transfer_id:int256 fec_type:fec.Type part:int total_size:long seqno:int data:bytes = rldp2.MessagePart;
rldp2.confirm transfer_id:int256 part:int max_seqno:int received_mask:int received_count:int = rldp2.MessagePart;
rldp2.complete transfer_id:int256 part:int = rldp2.MessagePart;

rldp.messagePart transfer_id:int256 fec_type:fec.Type part:int total_size:long seqno:int data:bytes = rldp.MessagePart;
rldp.confirm transfer_id:int256 part:int seqno:int = rldp.MessagePart;
rldp.complete transfer_id:int256 part:int = rldp.MessagePart;

rldp.message id:int256 data:bytes = rldp.Message;
rldp.query query_id:int256 max_answer_size:long timeout:int data:bytes = rldp.Message;
rldp.answer query_id:int256 data:bytes = rldp.Message;


---functions---
---types---
dht.node id:PublicKey addr_list:adnl.addressList version:int signature:bytes = dht.Node;
dht.nodes nodes:(vector dht.node) = dht.Nodes;

dht.key id:int256 name:bytes idx:int = dht.Key;

dht.updateRule.signature = dht.UpdateRule;
dht.updateRule.anybody = dht.UpdateRule;
dht.updateRule.overlayNodes = dht.UpdateRule;

dht.keyDescription key:dht.key id:PublicKey update_rule:dht.UpdateRule signature:bytes = dht.KeyDescription;

dht.value key:dht.keyDescription value:bytes ttl:int signature:bytes = dht.Value;

dht.pong random_id:long = dht.Pong;

dht.valueNotFound nodes:dht.nodes = dht.ValueResult;
dht.valueFound value:dht.Value = dht.ValueResult;

dht.clientNotFound nodes:dht.nodes = dht.ReversePingResult;
dht.reversePingOk = dht.ReversePingResult;

dht.stored = dht.Stored;
dht.message node:dht.node = dht.Message;
dht.requestReversePingCont target:adnl.Node signature:bytes client:int256 = dht.RequestReversePingCont;

dht.db.bucket nodes:dht.nodes = dht.db.Bucket;
dht.db.key.bucket id:int = dht.db.Key;

---functions---

dht.ping random_id:long = dht.Pong;
dht.store value:dht.value = dht.Stored;
dht.findNode key:int256 k:int = dht.Nodes;
dht.findValue key:int256 k:int = dht.ValueResult;
dht.getSignedAddressList = dht.Node;
dht.registerReverseConnection node:PublicKey ttl:int signature:bytes = dht.Stored;
dht.requestReversePing target:adnl.Node signature:bytes client:int256 k:int = dht.ReversePingResult;

dht.query node:dht.node = True;

---types---

overlay.node.toSign id:adnl.id.short overlay:int256 version:int = overlay.node.ToSign;
overlay.node.toSignEx id:adnl.id.short overlay:int256 flags:int version:int = overlay.node.ToSign;
overlay.node id:PublicKey overlay:int256 version:int signature:bytes = overlay.Node;
overlay.nodeV2 id:PublicKey overlay:int256 flags:int version:int signature:bytes certificate:overlay.MemberCertificate = overlay.NodeV2;
overlay.nodes nodes:(vector overlay.node) = overlay.Nodes;
overlay.nodesV2 nodes:(vector overlay.nodeV2) = overlay.NodesV2;

overlay.pong = overlay.Pong;

overlay.messageExtra flags:# certificate:flags.0?overlay.MemberCertificate = overlay.MessageExtra;
overlay.message overlay:int256 = overlay.Message;
overlay.messageWithExtra overlay:int256 extra:overlay.messageExtra = overlay.Message;
//overlay.randomPeers peers:(vector adnl.node) = overlay.RandomPeers;
overlay.broadcastList hashes:(vector int256) = overlay.BroadcastList;

overlay.fec.received hash:int256 = overlay.Broadcast;
overlay.fec.completed hash:int256 = overlay.Broadcast;

overlay.broadcast.id src:int256 data_hash:int256 flags:int = overlay.broadcast.Id;
overlay.broadcastFec.id src:int256 type:int256 data_hash:int256 size:int flags:int = overlay.broadcastFec.Id;
overlay.broadcastFec.partId broadcast_hash:int256 data_hash:int256 seqno:int = overlay.broadcastFec.PartId;

overlay.broadcast.toSign hash:int256 date:int = overlay.broadcast.ToSign;

overlay.memberCertificateId node:adnl.id.short flags:int slot:int expire_at:int = overlay.MemberCertificateId;
overlay.memberCertificate issued_by:PublicKey flags:int slot:int expire_at:int signature:bytes = overlay.MemberCertificate;
overlay.emptyMemberCertificate = overlay.MemberCertificate;
overlay.certificate issued_by:PublicKey expire_at:int max_size:int signature:bytes = overlay.Certificate;
overlay.certificateV2 issued_by:PublicKey expire_at:int max_size:int flags:int signature:bytes = overlay.Certificate;
overlay.emptyCertificate = overlay.Certificate;

overlay.certificateId overlay_id:int256 node:int256 expire_at:int max_size:int = overlay.CertificateId;
overlay.certificateIdV2 overlay_id:int256 node:int256 expire_at:int max_size:int flags:int = overlay.CertificateId;

overlay.unicast data:bytes = overlay.Broadcast;
overlay.broadcast src:PublicKey certificate:overlay.Certificate flags:int data:bytes date:int signature:bytes = overlay.Broadcast;
overlay.broadcastFec src:PublicKey certificate:overlay.Certificate data_hash:int256 data_size:int flags:int
          data:bytes seqno:int fec:fec.Type date:int signature:bytes = overlay.Broadcast;
overlay.broadcastFecShort src:PublicKey certificate:overlay.Certificate broadcast_hash:int256 part_data_hash:int256 seqno:int signature:bytes = overlay.Broadcast;
overlay.broadcastNotFound = overlay.Broadcast;

overlay.broadcastTwostepSimple flags:int date:int src:PublicKey src_adnl_id:int256 certificate:overlay.Certificate data:bytes extra:bytes signature:bytes = overlay.Broadcast;
overlay.broadcastTwostepFec flags:int date:int src:PublicKey src_adnl_id:int256 certificate:overlay.Certificate data_hash:int256 data_size:int seqno:int part:bytes extra:bytes signature:bytes = overlay.Broadcast;
overlay.broadcastTwostep.id flags:int date:int src:int256 src_adnl_id:int256 data_hash:int256 data_size:int part_size:int extra:bytes = overlay.broadcastTwostep.Id;
overlay.broadcastTwostepSimple.toSign id:int256 data:bytes = overlay.broadcastTwostepSimple.ToSign;
overlay.broadcastTwostepFec.toSign id:int256 seqno:int part:bytes = overlay.broadcastTwostepFec.ToSign;

---functions---

overlay.getRandomPeers peers:overlay.nodes = overlay.Nodes;
overlay.getRandomPeersV2 peers:overlay.nodesV2 = overlay.NodesV2;
overlay.ping = overlay.Pong;

overlay.query overlay:int256 = True;
overlay.queryWithExtra overlay:int256 extra:overlay.messageExtra = True;
overlay.getBroadcast hash:int256 = overlay.Broadcast;
overlay.getBroadcastList list:overlay.broadcastList = overlay.BroadcastList;

---types---

overlay.db.nodesV2 nodes:overlay.nodesV2 = overlay.db.Nodes;
overlay.db.nodes nodes:overlay.nodes = overlay.db.Nodes;
overlay.db.key.nodes local_id:int256 overlay:int256 = overlay.db.Key;

---functions---

---types---

catchain.block.id incarnation:int256 src:int256 height:int data_hash:int256 = catchain.block.Id;
catchain.block.dep src:int height:int data_hash:int256 signature:bytes = catchain.block.Dep;
catchain.block.data prev:catchain.block.dep deps:(vector catchain.block.dep) = catchain.block.Data;
catchain.block incarnation:int256 src:int height:int data:catchain.block.data signature:bytes = catchain.Block;
catchain.blocks blocks:(vector catchain.block) = catchain.Blocks;
catchain.blockUpdate block:catchain.block = catchain.Update;

catchain.block.data.badBlock block:catchain.block = catchain.block.inner.Data;
catchain.block.data.fork left:catchain.block.Dep right:catchain.block.Dep = catchain.block.inner.Data;
catchain.block.data.nop = catchain.block.inner.Data;
//catchain.block.data.vector msgs:(vector bytes) = catchain.block.inner.Data;
//catchain.block.data.custom = catchain.block.inner.Data;

catchain.firstblock unique_hash:int256 nodes:(vector int256) = catchain.FirstBlock;

catchain.difference sent_upto:(vector int) = catchain.Difference;
catchain.differenceFork left:catchain.block.dep right:catchain.block.dep = catchain.Difference;

catchain.blockNotFound = catchain.BlockResult;
catchain.blockResult block:catchain.block = catchain.BlockResult;

---functions---

catchain.getBlock block:int256 = catchain.BlockResult;
catchain.getDifference rt:(vector int) = catchain.Difference;
//catchain.getForkDifference src:int fork:catchain.fork = catchain.ForkDifference;

---types---

validatorSession.round.id session:int256 height:long prev_block:int256 seqno:int = validatorSession.round.Id;

validatorSession.candidate.id round:int256 block_hash:int256 = validatorSession.tempBlock.Id;

validatorSession.message.startSession = validatorSession.Message;
validatorSession.message.finishSession = validatorSession.Message;

validatorSession.message.submittedBlock round:int root_hash:int256 file_hash:int256
               collated_data_file_hash:int256 = validatorSession.round.Message;
validatorSession.message.approvedBlock round:int candidate:int256 signature:bytes = validatorSession.round.Message;
validatorSession.message.rejectedBlock round:int candidate:int256 reason:bytes = validatorSession.round.Message;
validatorSession.message.commit round:int candidate:int256 signature:bytes = validatorSession.round.Message;

validatorSession.message.vote round:int attempt:int candidate:int256 = validatorSession.round.Message;
validatorSession.message.voteFor round:int attempt:int candidate:int256 = validatorSession.round.Message;
validatorSession.message.precommit round:int attempt:int candidate:int256 = validatorSession.round.Message;
validatorSession.message.empty round:int attempt:int = validatorSession.round.Message;

validatorSession.pong hash:long = validatorSession.Pong;

validatorSession.candidateId src:int256 root_hash:int256 file_hash:int256 collated_data_file_hash:int256 = validatorSession.CandidateId;

validatorSession.blockUpdate ts:long actions:(vector validatorSession.round.Message) state:int = validatorSession.BlockUpdate;
validatorSession.candidate src:int256 round:int root_hash:int256 data:bytes collated_data:bytes = validatorSession.Candidate;
validatorSession.compressedCandidate flags:# src:int256 round:int root_hash:int256 decompressed_size:int data:bytes = validatorSession.Candidate;
validatorSession.compressedCandidateV2 flags:# src:int256 round:int root_hash:int256 data:bytes = validatorSession.Candidate;
validatorSession.optimisticCandidateBroadcast flags:# prev_candidate_id:int256 data:bytes = validatorSession.OptimisticCandidateBroadcast;

validatorSession.config catchain_idle_timeout:double catchain_max_deps:int round_candidates:int next_candidate_delay:double round_attempt_duration:int
        max_round_attempts:int max_block_size:int max_collated_data_size:int = validatorSession.Config;
validatorSession.configNew catchain_idle_timeout:double catchain_max_deps:int round_candidates:int next_candidate_delay:double round_attempt_duration:int
        max_round_attempts:int max_block_size:int max_collated_data_size:int new_catchain_ids:Bool = validatorSession.Config;
validatorSession.configVersioned catchain_idle_timeout:double catchain_max_deps:int round_candidates:int next_candidate_delay:double round_attempt_duration:int
        max_round_attempts:int max_block_size:int max_collated_data_size:int version:int = validatorSession.Config;

validatorSession.catchainOptions idle_timeout:double max_deps:int max_block_size:int block_hash_covers_data:Bool
        max_block_height_ceoff:int debug_disable_db:Bool = validatorSession.CatChainOptions;
validatorSession.configVersionedV2 catchain_opts:validatorSession.CatChainOptions round_candidates:int next_candidate_delay:double
        round_attempt_duration:int max_round_attempts:int max_block_size:int max_collated_data_size:int version:int = validatorSession.Config;

---functions---

validatorSession.ping hash:long = validatorSession.Pong;
validatorSession.downloadCandidate round:int id:validatorSession.candidateId = validatorSession.Candidate;

---types---

hashable.bool value:Bool = Hashable;
hashable.int32 value:int = Hashable;
hashable.int64 value:long = Hashable;
hashable.int256 value:int256 = Hashable;
hashable.bytes value:bytes = Hashable;
hashable.pair left:int right:int = Hashable;
hashable.vector value:(vector int) = Hashable;
hashable.validatorSessionOldRound seqno:int block:int signatures:int approve_signatures:int = Hashable;
hashable.validatorSessionRoundAttempt seqno:int votes:int precommitted:int vote_for_inited:int vote_for:int = Hashable;
hashable.validatorSessionRound locked_round:int locked_block:int seqno:int precommitted:Bool
          first_attempt:int approved_blocks:int signatures:int attempts:int = Hashable;
hashable.blockSignature signature:int = Hashable;
hashable.sentBlock src:int root_hash:int file_hash:int collated_data_file_hash:int = Hashable;
hashable.sentBlockEmpty = Hashable;
hashable.vote block:int node:int = Hashable;
hashable.blockCandidate block:int approved:int = Hashable;
hashable.blockVoteCandidate block:int approved:int = Hashable;
hashable.blockCandidateAttempt block:int votes:int = Hashable;

hashable.cntVector data:int = Hashable;
hashable.cntSortedVector data:int = Hashable;

hashable.validatorSession ts:int old_rounds:int cur_round:int = Hashable;

---functions---
---types---


tosNode.sessionId workchain:int shard:long cc_seqno:int opts_hash:int256 = tosNode.SessionId;


tosNode.blockSignature who:int256 signature:bytes = tosNode.BlockSignature;
tosNode.signatureSet.ordinary cc_seqno:int validator_set_hash:int signatures:(vector tosNode.blockSignature) = tosNode.SignatureSet;
tosNode.signatureSet.simplex final:Bool cc_seqno:int validator_set_hash:int signatures:(vector tosNode.blockSignature)
    session_id:int256 slot:int candidate:consensus.CandidateHashData = tosNode.SignatureSet;

tosNode.blockId workchain:int shard:long seqno:int = tosNode.BlockId;
tosNode.blockIdExt workchain:int shard:long seqno:int root_hash:int256 file_hash:int256 = tosNode.BlockIdExt;
tosNode.zeroStateIdExt workchain:int root_hash:int256 file_hash:int256 = tosNode.ZeroStateIdExt;
tosNode.shardId workchain:int shard:long = tosNode.ShardId;

tosNode.blockDescriptionEmpty = tosNode.BlockDescription;
tosNode.blockDescription id:tosNode.blockIdExt = tosNode.BlockDescription;
tosNode.blocksDescription ids:(vector tosNode.blockIdExt) incomplete:Bool = tosNode.BlocksDescription;
tosNode.preparedProofEmpty = tosNode.PreparedProof;
tosNode.preparedProof = tosNode.PreparedProof;
tosNode.preparedProofLink = tosNode.PreparedProof;
tosNode.preparedState = tosNode.PreparedState;
tosNode.notFoundState = tosNode.PreparedState;
tosNode.persistentStateIdV2 block:tosNode.blockIdExt masterchain_block:tosNode.blockIdExt effective_shard:long = tosNode.PersistentStateIdV2;
tosNode.persistentStateSize size:long = tosNode.PersistentStateSize;
tosNode.persistentStateSizeNotFound = tosNode.PersistentStateSize;
tosNode.prepared = tosNode.Prepared;
tosNode.notFound = tosNode.Prepared;
tosNode.data data:bytes = tosNode.Data;
//tosNode.preparedKeyBlockProofEmpty = tosNode.PreparedKeyBlockProof;
//tosNode.preparedKeyBlockProof block_id:tosNode.blockIdExt = tosNode.PreparedKeyBlockProof;

tosNode.ihrMessage data:bytes = tosNode.IhrMessage;
tosNode.externalMessage data:bytes = tosNode.ExternalMessage;

tosNode.newShardBlock block:tosNode.blockIdExt cc_seqno:int data:bytes = tosNode.NewShardBlock;

tosNode.blockBroadcastCompressed.data signatures:(vector tosNode.blockSignature) proof_data:bytes = tosNode.blockBroadcaseCompressed.Data;

tosNode.blockBroadcast id:tosNode.blockIdExt catchain_seqno:int validator_set_hash:int
              signatures:(vector tosNode.blockSignature)
              proof:bytes data:bytes = tosNode.Broadcast;
tosNode.blockBroadcastCompressed id:tosNode.blockIdExt catchain_seqno:int validator_set_hash:int
              flags:# compressed:bytes = tosNode.Broadcast;
tosNode.blockBroadcastCompressedV2 id:tosNode.blockIdExt signature_set:tosNode.SignatureSet flags:# proof:bytes data_compressed:bytes = tosNode.Broadcast;
tosNode.ihrMessageBroadcast message:tosNode.ihrMessage = tosNode.Broadcast;
tosNode.externalMessageBroadcast message:tosNode.externalMessage = tosNode.Broadcast;
tosNode.newShardBlockBroadcast block:tosNode.newShardBlock = tosNode.Broadcast;
// signature may be empty, at least for now
tosNode.newBlockCandidateBroadcast id:tosNode.blockIdExt catchain_seqno:int validator_set_hash:int
              collator_signature:tosNode.blockSignature data:bytes = tosNode.Broadcast;
tosNode.newBlockCandidateBroadcastCompressed id:tosNode.blockIdExt catchain_seqno:int validator_set_hash:int
              collator_signature:tosNode.blockSignature flags:# compressed:bytes = tosNode.Broadcast;
tosNode.newBlockCandidateBroadcastCompressedV2 id:tosNode.blockIdExt catchain_seqno:int validator_set_hash:int
              collator_signature:tosNode.blockSignature flags:# compressed:bytes = tosNode.Broadcast;

// optimistic broadcast of response to tosNode.getOutMsgQueueProof with dst_shard, block and limits arguments
tosNode.outMsgQueueProofBroadcast dst_shard:tosNode.shardId block:tosNode.blockIdExt
              limits:ImportedMsgQueueLimits proof:tosNode.OutMsgQueueProof = tosNode.Broadcast;

tosNode.shardPublicOverlayId workchain:int shard:long zero_state_file_hash:int256 = tosNode.ShardPublicOverlayId;

tosNode.privateBlockOverlayId zero_state_file_hash:int256 nodes:(vector int256) = tosNode.PrivateBlockOverlayId;
tosNode.customOverlayId zero_state_file_hash:int256 name:string nodes:(vector int256) = tosNode.CustomOverlayId;
tosNode.fastSyncOverlayId zero_state_file_hash:int256 shard:tosNode.shardId = tosNode.FastSyncOverlayId;

tosNode.keyBlocks blocks:(vector tosNode.blockIdExt) incomplete:Bool error:Bool = tosNode.KeyBlocks;

tos.blockId root_cell_hash:int256 file_hash:int256 = tos.BlockId;
tos.blockIdApprove root_cell_hash:int256 file_hash:int256 = tos.BlockId;

tosNode.dataFull id:tosNode.blockIdExt proof:bytes block:bytes is_link:Bool = tosNode.DataFull;
tosNode.dataFullCompressed id:tosNode.blockIdExt flags:# compressed:bytes is_link:Bool = tosNode.DataFull;
tosNode.dataFullCompressedV2 id:tosNode.blockIdExt flags:# proof:bytes block_compressed:bytes is_link:Bool = tosNode.DataFull;
tosNode.dataFullEmpty = tosNode.DataFull;

tosNode.capabilities#f5bf60c0 version_major:int version_minor:int flags:# = tosNode.Capabilities;

tosNode.success = tosNode.Success;

tosNode.archiveNotFound = tosNode.ArchiveInfo;
tosNode.archiveInfo id:long = tosNode.ArchiveInfo;

tosNode.importedMsgQueueLimits max_bytes:int max_msgs:int = ImportedMsgQueueLimits;
tosNode.outMsgQueueProof queue_proofs:bytes block_state_proofs:bytes msg_counts:(vector int) = tosNode.OutMsgQueueProof;
tosNode.outMsgQueueProofEmpty = tosNode.OutMsgQueueProof;

tosNode.forgetPeer = tosNode.ForgetPeer;
tosNode.newFastSyncMemberCertificate adnl_id:int256 certificate:overlay.MemberCertificate = tosNode.NewFastSyncMemberCertificate;


---functions---

tosNode.getNextBlockDescription prev_block:tosNode.blockIdExt = tosNode.BlockDescription;
tosNode.getNextBlocksDescription prev_block:tosNode.blockIdExt limit:int = tosNode.BlocksDescription;
tosNode.getPrevBlocksDescription next_block:tosNode.blockIdExt limit:int cutoff_seqno:int = tosNode.BlocksDescription;
tosNode.prepareBlockProof block:tosNode.blockIdExt allow_partial:Bool = tosNode.PreparedProof;
tosNode.prepareKeyBlockProof block:tosNode.blockIdExt allow_partial:Bool = tosNode.PreparedProof;
tosNode.prepareBlockProofs blocks:(vector tosNode.blockIdExt) allow_partial:Bool = tosNode.PreparedProof;
tosNode.prepareKeyBlockProofs blocks:(vector tosNode.blockIdExt) allow_partial:Bool = tosNode.PreparedProof;
tosNode.prepareBlock block:tosNode.blockIdExt = tosNode.Prepared;
tosNode.prepareBlocks blocks:(vector tosNode.blockIdExt) = tosNode.Prepared;
tosNode.prepareZeroState block:tosNode.blockIdExt = tosNode.PreparedState;
tosNode.getNextKeyBlockIds block:tosNode.blockIdExt max_size:int = tosNode.KeyBlocks;
tosNode.downloadNextBlockFull prev_block:tosNode.blockIdExt = tosNode.DataFull;
tosNode.downloadBlockFull block:tosNode.blockIdExt = tosNode.DataFull;
tosNode.downloadBlock block:tosNode.blockIdExt = tosNode.Data;
tosNode.downloadZeroState block:tosNode.blockIdExt = tosNode.Data;
tosNode.downloadBlockProof block:tosNode.blockIdExt = tosNode.Data;
tosNode.downloadKeyBlockProof block:tosNode.blockIdExt = tosNode.Data;
tosNode.downloadBlockProofLink block:tosNode.blockIdExt = tosNode.Data;
tosNode.downloadKeyBlockProofLink block:tosNode.blockIdExt = tosNode.Data;
tosNode.getArchiveInfo masterchain_seqno:int = tosNode.ArchiveInfo;
tosNode.getShardArchiveInfo masterchain_seqno:int shard_prefix:tosNode.shardId = tosNode.ArchiveInfo;
tosNode.getArchiveSlice archive_id:long offset:long max_size:int = tosNode.Data;
tosNode.getOutMsgQueueProof dst_shard:tosNode.shardId blocks:(vector tosNode.blockIdExt)
    limits:tosNode.importedMsgQueueLimits = tosNode.OutMsgQueueProof;

tosNode.preparePersistentState block:tosNode.blockIdExt masterchain_block:tosNode.blockIdExt = tosNode.PreparedState;
tosNode.downloadPersistentStateSliceV2 state:tosNode.persistentStateIdV2 offset:long max_size:long = tosNode.Data;
tosNode.getPersistentStateSizeV2 state:tosNode.persistentStateIdV2 = tosNode.PersistentStateSize;

tosNode.getCapabilities = tosNode.Capabilities;

tosNode.slave.sendExtMessage message:tosNode.externalMessage = tosNode.Success;

tosNode.query = Object;

---types---

// bit 0 - started
// bit 1 - ready to switch
// bit 2 - switched from
// bit 3 - archived
// bit 4 - disabled

db.root.dbDescription version:int first_masterchain_block_id:tosNode.blockIdExt flags:int = db.root.DbDescription;

db.root.key.cellDb version:int = db.root.Key;
db.root.key.blockDb version:int = db.root.Key;

db.root.config celldb_version:int blockdb_version:int = db.root.Config;
db.root.key.config = db.root.Key;

db.celldb.value block_id:tosNode.blockIdExt prev:int256 next:int256 root_hash:int256 = db.celldb.Value;
db.celldb.key.value hash:int256 = db.celldb.key.Value;

db.block.info#4ac6e727 id:tosNode.blockIdExt flags:# prev_left:flags.1?tosNode.blockIdExt
                                            prev_right:flags.2?tosNode.blockIdExt
                                            next_left:flags.3?tosNode.blockIdExt
                                            next_right:flags.4?tosNode.blockIdExt
                                            lt:flags.13?long
                                            ts:flags.14?int
                                            state:flags.17?int256
                                            masterchain_ref_seqno:flags.23?int = db.block.Info;
db.block.packedInfo id:tosNode.blockIdExt unixtime:int offset:long = db.block.Info;
db.block.archivedInfo id:tosNode.blockIdExt flags:# next:flags.0?tosNode.blockIdExt = db.block.Info;

db.blockdb.value next:tosNode.blockIdExt data:bytes = db.blockdb.Value;
db.blockdb.lru id:tosNode.blockIdExt prev:int256 next:int256 = db.blockdb.Lru;
db.blockdb.key.lru id:tosNode.blockIdExt = db.blockdb.Key;
db.blockdb.key.value id:tosNode.blockIdExt = db.blockdb.Key;

db.candidate source:PublicKey id:tosNode.blockIdExt data:bytes collated_data:bytes = db.Candidate;
db.candidate.id source:PublicKey id:tosNode.blockIdExt collated_data_file_hash:int256 = db.candidate.Id;

db.filedb.key.empty = db.filedb.Key;
db.filedb.key.blockFile block_id:tosNode.blockIdExt = db.filedb.Key;
db.filedb.key.zeroStateFile block_id:tosNode.blockIdExt = db.filedb.Key;
db.filedb.key.persistentStateFile block_id:tosNode.blockIdExt masterchain_block_id:tosNode.blockIdExt = db.filedb.Key;
db.filedb.key.splitAccountStateFile block_id:tosNode.blockIdExt masterchain_block_id:tosNode.blockIdExt effective_shard:long = db.filedb.Key;
db.filedb.key.splitPersistentStateFile block_id:tosNode.blockIdExt masterchain_block_id:tosNode.blockIdExt = db.filedb.Key;
db.filedb.key.proof block_id:tosNode.blockIdExt = db.filedb.Key;
db.filedb.key.proofLink block_id:tosNode.blockIdExt = db.filedb.Key;
db.filedb.key.signatures block_id:tosNode.blockIdExt = db.filedb.Key;
db.filedb.key.candidate id:db.candidate.id = db.filedb.Key;
db.filedb.key.candidateRef id:tosNode.blockIdExt = db.filedb.Key;
db.filedb.key.blockInfo block_id:tosNode.blockIdExt = db.filedb.Key;

db.filedb.value key:db.filedb.Key prev:int256 next:int256 file_hash:int256 = db.filedb.Value;

db.state.destroyedSessions sessions:(vector int256) = db.state.DestroyedSessions;
db.state.initBlockId block:tosNode.blockIdExt = db.state.InitBlockId;
db.state.gcBlockId block:tosNode.blockIdExt = db.state.GcBlockId;
db.state.shardClient block:tosNode.blockIdExt = db.state.ShardClient;
db.state.asyncSerializer block:tosNode.blockIdExt last:tosNode.blockIdExt last_ts:int = db.state.AsyncSerializer;
db.state.hardforks blocks:(vector tosNode.blockIdExt) = db.state.Hardforks;
db.state.dbVersion version:int = db.state.DbVersion;
db.state.persistentStateDescriptionShards shard_blocks:(vector tosNode.blockIdExt) = db.state.PersistentStateDescriptionShards;
db.state.persistentStateDescriptionShard block:tosNode.blockIdExt split_depth:int = db.state.PersistentStateDescriptionShard;
db.state.persistentStateDescriptionShardsV2 shard_blocks:(vector db.state.PersistentStateDescriptionShard) = db.state.PersistentStateDescriptionShards;
db.state.persistentStateDescriptionHeader masterchain_id:tosNode.blockIdExt start_time:int end_time:int = db.state.PersistentStateDescriptionHeader;
db.state.persistentStateDescriptionsList list:(vector db.state.persistentStateDescriptionHeader) = db.state.PersistentStateDescriptionsList;

db.state.key.destroyedSessions = db.state.Key;
db.state.key.initBlockId = db.state.Key;
db.state.key.gcBlockId = db.state.Key;
db.state.key.shardClient = db.state.Key;
db.state.key.asyncSerializer = db.state.Key;
db.state.key.hardforks = db.state.Key;
db.state.key.dbVersion = db.state.Key;
db.state.key.persistentStateDescriptionShards masterchain_seqno:int = db.state.Key;
db.state.key.persistentStateDescriptionsList = db.state.Key;

db.lt.el.key workchain:int shard:long idx:int = db.lt.Key;
db.lt.desc.key workchain:int shard:long = db.lt.Key;
db.lt.shard.key idx:int = db.lt.Key;
db.lt.status.key = db.lt.Key;
db.lt.el.value id:tosNode.blockIdExt lt:long ts:int = db.lt.el.Value;
db.lt.desc.value first_idx:int last_idx:int last_seqno:int last_lt:long last_ts:int = db.lt.desc.Value;
db.lt.shard.value workchain:int shard:long = db.lt.shard.Value;
db.lt.status.value total_shards:int = db.lt.status.Value;

db.files.index.key = db.files.Key;
db.files.package.key package_id:int key:Bool temp:Bool = db.files.Key;

db.files.index.value packages:(vector int) key_packages:(vector int) temp_packages:(vector int) = db.files.index.Value;
db.files.package.firstBlock workchain:int shard:long seqno:int unixtime:int lt:long = db.files.package.FirstBlock;
db.files.package.value package_id:int key:Bool temp:Bool firstblocks:(vector db.files.package.firstBlock) deleted:Bool
                   = db.files.package.Value;

db.event.blockApplied block_id:tosNode.blockIdExt = db.Event;
db.event.blockSigned block_id:tosNode.blockIdExt = db.Event;
db.event.blockCandidateReceived block_id:tosNode.blockIdExt = db.Event;

---functions---

---types---

validator.groupMember public_key_hash:int256 adnl:int256 weight:long = engine.validator.GroupMember;
validator.group workchain:int shard:long catchain_seqno:int config_hash:int256 members:(vector validator.groupMember) = validator.Group;
validator.groupEx workchain:int shard:long vertical_seqno:int catchain_seqno:int config_hash:int256 members:(vector validator.groupMember) = validator.Group;
validator.groupNew workchain:int shard:long vertical_seqno:int last_key_block_seqno:int catchain_seqno:int config_hash:int256 members:(vector validator.groupMember) = validator.Group;

validator.telemetry flags:# timestamp:double adnl_id:int256
    node_version:string os_version:string node_started_at:int
    ram_size:long cpu_cores:int node_threads:int = validator.Telemetry;

---functions---


---types---


id.config.local id:PrivateKey = id.config.Local;
dht.config.local id:adnl.id.short = dht.config.Local;
dht.config.random.local cnt:int = dht.config.Local;
liteserver.config.local id:PrivateKey port:int = liteserver.config.Local;
liteserver.config.random.local port:int = liteserver.config.Local;
validator.config.local id:adnl.id.short = validator.config.Local;
validator.config.random.local addr_list:adnl.addressList = validator.config.Local;
control.config.local priv:PrivateKey pub:int256 port:int = control.config.Local;
config.local local_ids:(vector id.config.local) dht:(vector dht.config.Local) validators:(vector validator.config.Local) liteservers:(vector liteserver.config.Local) control:(vector control.config.local) = config.Local;

dht.config.global static_nodes:dht.nodes k:int a:int = dht.config.Global;
dht.config.global_v2 static_nodes:dht.nodes k:int a:int network_id:int = dht.config.Global;
adnl.config.global static_nodes:adnl.nodes = adnl.config.Global;
catchain.config.global tag:int256 nodes:(vector PublicKey) = catchain.config.Global;
dummyworkchain0.config.global zero_state_hash:int256 = dummyworkchain0.config.Global;
validator.config.global zero_state:tosNode.blockIdExt init_block:tosNode.blockIdExt hardforks:(vector tosNode.blockIdExt) = validator.config.Global;
config.global adnl:adnl.config.global dht:dht.config.Global validator:validator.config.global = config.Global;

liteserver.descV2.sliceSimple shards:(vector tosNode.shardId) = liteserver.descV2.Slice;
liteserver.descV2.shardInfo shard_id:tosNode.shardId seqno:int utime:int lt:long = liteserver.descV2.ShardInfo;
liteserver.descV2.sliceTimed shards_from:(vector liteserver.descV2.shardInfo) shards_to:(vector liteserver.descV2.shardInfo) = liteserver.descV2.Slice;

liteserver.desc id:PublicKey ip:int port:int hostname:string = liteserver.Desc;
liteserver.descV2 id:PublicKey ip:int port:int hostname:string slices:(vector liteserver.descV2.Slice) = liteserver.DescV2;
liteclient.config.global liteservers:(vector liteserver.desc) liteservers_v2:(vector liteserver.descV2) validator:validator.config.global = liteclient.config.Global;

engine.adnl id:int256 category:int = engine.Adnl;
engine.addr ip:int port:int categories:(vector int) priority_categories:(vector int) = engine.Addr;
engine.addrProxy in_ip:int in_port:int out_ip:int out_port:int
          proxy_type:adnl.Proxy categories:(vector int) priority_categories:(vector int) = engine.Addr;
engine.quicAddr ip:int port:int categories:(vector int) priority_categories:(vector int) = engine.Addr;
engine.dht id:int256 = engine.Dht;
engine.validatorTempKey key:int256 expire_at:int = engine.ValidatorTempKey;
engine.validatorAdnlAddress id:int256 expire_at:int = engine.ValidatorAdnlAddress;
engine.validator id:int256 temp_keys:(vector engine.validatorTempKey) adnl_addrs:(vector engine.validatorAdnlAddress) election_date:int expire_at:int = engine.Validator;
engine.collator adnl_id:int256 shard:tosNode.shardId = engine.Collator;
engine.liteServer id:int256 port:int = engine.LiteServer;
engine.controlProcess id:int256 permissions:int = engine.ControlProcess;
engine.controlInterface id:int256 port:int allowed:(vector engine.controlProcess) = engine.ControlInterface;
engine.gc ids:(vector int256) = engine.Gc;

engine.dht.config dht:(vector engine.dht) gc:engine.gc = engine.dht.Config;
engine.validator.fullNodeMaster port:int adnl:int256 = engine.validator.FullNodeMaster;
engine.validator.fullNodeSlave ip:int port:int adnl:PublicKey = engine.validator.FullNodeSlave;
engine.validator.fullNodeConfig ext_messages_broadcast_disabled:Bool = engine.validator.FullNodeConfig;
engine.validator.fastSyncMemberCertificate adnl_id:int256 certificate:overlay.MemberCertificate = engine.validator.FastSyncMemberCertificate;
engine.validator.fastSyncOverlayClient adnl_id:int256 slot:int = engine.validator.FastSyncOverlayClient;
engine.validator.collatorNodeWhitelist enabled:Bool adnl_ids:(vector int256) = engine.validator.CollatorNodeWhitelist;
engine.validator.extraConfig state_serializer_enabled:Bool fast_sync_member_certificates:(vector engine.validator.fastSyncMemberCertificate)
    collator_node_whitelist:engine.validator.collatorNodeWhitelist
    fast_sync_overlay_clients:(vector engine.validator.fastSyncOverlayClient) = engine.validator.ExtraConfig;
engine.validator.config out_port:int addrs:(vector engine.Addr) adnl:(vector engine.adnl)
        dht:(vector engine.dht)
        validators:(vector engine.validator) collators:(vector engine.collator)
        fullnode:int256 fullnodeslaves:(vector engine.validator.fullNodeSlave)
        fullnodemasters:(vector engine.validator.fullNodeMaster)
        fullnodeconfig:engine.validator.fullNodeConfig
        extraconfig:engine.validator.extraConfig
        liteservers:(vector engine.liteServer) control:(vector engine.controlInterface)
        shards_to_monitor:(vector tosNode.shardId)
        gc:engine.gc = engine.validator.Config;

engine.validator.customOverlayNode adnl_id:int256 msg_sender:Bool msg_sender_priority:int block_sender:Bool = engine.validator.CustomOverlayNode;
engine.validator.customOverlay name:string nodes:(vector engine.validator.customOverlayNode) sender_shards:(vector tosNode.shardId)
    skip_public_msg_send:Bool use_quic:Bool = engine.validator.CustomOverlay;
engine.validator.customOverlaysConfig overlays:(vector engine.validator.customOverlay) = engine.validator.CustomOverlaysConfig;

engine.validator.collatorOptions
  deferring_enabled:Bool defer_messages_after:int defer_out_queue_size_limit:long
  dispatch_phase_2_max_total:int dispatch_phase_3_max_total:int
  dispatch_phase_2_max_per_initiator:int dispatch_phase_3_max_per_initiator:int
  whitelist:(vector string) prioritylist:(vector string)
  force_full_collated_data:Bool ignore_collated_data_limits:Bool = engine.validator.CollatorOptions;

engine.validator.collatorsList.collator adnl_id:int256 = engine.validator.collatorsList.Collator;
engine.validator.collatorsList.shard shard_id:tosNode.shardId collators:(vector engine.validator.collatorsList.collator)
    self_collate:Bool select_mode:string = engine.validator.collatorsList.Shard;
engine.validator.collatorsList shards:(vector engine.validator.collatorsList.shard) = engine.validator.CollatorsList;

engine.validator.shardBlockVerifierConfig.shard shard_id:(tosNode.shardId) trusted_nodes:(vector int256)
    required_confirms:int = engine.validator.shardBlockVerifierConfig.Shard;
engine.validator.shardBlockVerifierConfig shards:(vector engine.validator.shardBlockVerifierConfig.shard)
    = engine.validator.ShardBlockVerifierConfig;

---functions---
---types---

engine.adnlProxy.port in_port:int out_port:int dst_ip:int dst_port:int proxy_type:adnl.Proxy = engine.adnlProxy.Port;

engine.adnlProxy.config ports:(vector engine.adnlProxy.port) = engine.adnlProxy.Config;

---functions---

---types---

adnl.pong value:long = adnl.Pong;

---functions---

adnl.ping value:long = adnl.Pong;

---types---

engine.validator.keyHash key_hash:int256 = engine.validator.KeyHash;
engine.validator.signature signature:bytes = engine.validator.Signature;

engine.validator.oneStat key:string value:string = engine.validator.OneStat;
engine.validator.stats stats:(vector engine.validator.oneStat) = engine.validator.Stats;
engine.validator.textStats data:string = engine.validator.TextStats;

engine.validator.controlQueryError code:int message:string = engine.validator.ControlQueryError;

engine.validator.time time:int = engine.validator.Time;
engine.validator.success = engine.validator.Success;

engine.validator.jsonConfig data:string = engine.validator.JsonConfig;

engine.validator.electionBid election_date:int perm_key:int256 adnl_addr:int256 to_send_payload:bytes = engine.validator.ElectionBid;
engine.validator.proposalVote perm_key:int256 to_send:bytes = engine.validator.ProposalVote;

engine.validator.dhtServerStatus id:int256 status:int = engine.validator.DhtServerStatus;
engine.validator.dhtServersStatus servers:(vector engine.validator.dhtServerStatus) = engine.validator.DhtServersStatus;

engine.validator.overlayStatsTraffic t_out_bytes:long t_in_bytes:long t_out_pckts:int t_in_pckts:int = engine.validator.OverlayStatsTraffic;

engine.validator.overlayStatsNode adnl_id:int256 ip_addr:string is_neighbour:Bool is_alive:Bool node_flags:int
    bdcst_errors:int fec_bdcst_errors:int last_in_query:int last_out_query:int
    traffic:engine.validator.overlayStatsTraffic traffic_responses:engine.validator.overlayStatsTraffic
    last_ping_at:double last_ping_time:double = engine.validator.OverlayStatsNode;

engine.validator.overlayStatsBroadcasts source:int256 ts_start:double ts_end:double
    count:long total_size:long total_out_traffic:long = engine.validator.OverlayStatsBroadcasts;

engine.validator.overlayStats overlay_id:int256 overlay_id_full:PublicKey adnl_id:int256 scope:string
    nodes:(vector engine.validator.overlayStatsNode) stats:(vector engine.validator.oneStat)
    total_traffic:engine.validator.overlayStatsTraffic total_traffic_responses:engine.validator.overlayStatsTraffic
    broadcasts:(vector engine.validator.overlayStatsBroadcasts)
    extra:string = engine.validator.OverlayStats;
engine.validator.overlaysStats overlays:(vector engine.validator.overlayStats) = engine.validator.OverlaysStats;

engine.validator.shardOverlayStats.neighbour id:string verison_major:int version_minor:int flags:#
    roundtrip:double unreliability:double = engine.validator.shardOverlayStats.Neighbour;
engine.validator.shardOverlayStats shard:string active:Bool
    neighbours:(vector engine.validator.shardOverlayStats.neighbour) = engine.validator.ShardOverlayStats;
engine.validator.fastSyncOverlayStats shard:string validators_adnl:(vector int256) root_public_keys:(vector int256)
    member_certificate:overlay.MemberCertificate receive_broadcasts:Bool = engine.validator.FastSyncOverlayStats;

engine.validator.onePerfTimerStat time:int min:double avg:double max:double = engine.validator.OnePerfTimerStat;
engine.validator.perfTimerStatsByName name:string stats:(vector engine.validator.OnePerfTimerStat) = engine.validator.PerfTimerStatsByName;
engine.validator.perfTimerStats stats:(vector engine.validator.PerfTimerStatsByName) = engine.validator.PerfTimerStats;

engine.validator.shardOutQueueSize size:long = engine.validator.ShardOutQueueSize;

engine.validator.exportedPrivateKeys encrypted_data:bytes = engine.validator.ExportedPrivateKeys;

engine.validator.collationManagerStats.shard shard_id:tosNode.shardId self_collate:Bool select_mode:string active:Bool collators:(vector int256) = engine.validator.collationManagerStats.Shard;
engine.validator.collationManagerStats.collator adnl_id:int256 active:Bool alive:Bool ping_in:double last_ping_ago:double last_ping_status:string banned_for:double = engine.validator.collationManagerStats.Collator;
engine.validator.collationManagerStats.localId adnl_id:int256 shards:(vector engine.validator.collationManagerStats.shard)
    collators:(vector engine.validator.collationManagerStats.collator) = engine.validator.collationManagerStats.LocalId;
engine.validator.collationManagerStats local_ids:(vector engine.validator.collationManagerStats.localId) = engine.validator.CollationManagerStats;

---functions---

engine.validator.getTime = engine.validator.Time;
engine.validator.importPrivateKey key:PrivateKey = engine.validator.KeyHash;
engine.validator.exportPrivateKey key_hash:int256 = PrivateKey;
engine.validator.exportPublicKey key_hash:int256 = PublicKey;
engine.validator.generateKeyPair = engine.validator.KeyHash;
engine.validator.addAdnlId key_hash:int256 category:int = engine.validator.Success;
engine.validator.addDhtId key_hash:int256 = engine.validator.Success;
engine.validator.addValidatorPermanentKey key_hash:int256 election_date:int ttl:int = engine.validator.Success;
engine.validator.addValidatorTempKey permanent_key_hash:int256 key_hash:int256 ttl:int = engine.validator.Success;
engine.validator.addValidatorAdnlAddress permanent_key_hash:int256 key_hash:int256 ttl:int = engine.validator.Success;
engine.validator.changeFullNodeAdnlAddress adnl_id:int256 = engine.validator.Success;
engine.validator.addLiteserver key_hash:int256 port:int = engine.validator.Success;
engine.validator.addControlInterface key_hash:int256 port:int = engine.validator.Success;
engine.validator.addControlProcess key_hash:int256 port:int peer_key:int256 permissions:int = engine.validator.Success;

engine.validator.delAdnlId key_hash:int256 = engine.validator.Success;
engine.validator.delDhtId key_hash:int256 = engine.validator.Success;
engine.validator.delValidatorPermanentKey key_hash:int256 = engine.validator.Success;
engine.validator.delValidatorTempKey permanent_key_hash:int256 key_hash:int256 = engine.validator.Success;
engine.validator.delValidatorAdnlAddress permanent_key_hash:int256 key_hash:int256 = engine.validator.Success;

engine.validator.addListeningPort ip:int port:int categories:(vector int) priority_categories:(vector int) = engine.validator.Success;
engine.validator.addProxy in_ip:int in_port:int out_ip:int out_port:int proxy:adnl.Proxy categories:(vector int) priority_categories:(vector int) = engine.validator.Success;
engine.validator.delListeningPort ip:int port:int categories:(vector int) priority_categories:(vector int) = engine.validator.Success;
engine.validator.delProxy out_ip:int out_port:int categories:(vector int) priority_categories:(vector int) = engine.validator.Success;

engine.validator.addQuicAddr ip:int port:int categories:(vector int) priority_categories:(vector int) = engine.validator.Success;
engine.validator.delQuicAddr ip:int port:int categories:(vector int) priority_categories:(vector int) = engine.validator.Success;

engine.validator.sign key_hash:int256 data:bytes = engine.validator.Signature;
engine.validator.exportAllPrivateKeys encryption_key:PublicKey = engine.validator.ExportedPrivateKeys;

engine.validator.getStats = engine.validator.Stats;
engine.validator.getConfig = engine.validator.JsonConfig;

engine.validator.setVerbosity verbosity:int = engine.validator.Success;

engine.validator.createElectionBid election_date:int election_addr:string wallet:string = engine.validator.ElectionBid;
engine.validator.createProposalVote vote:bytes = engine.validator.ProposalVote;
engine.validator.createComplaintVote election_id:int vote:bytes = engine.validator.ProposalVote;

engine.validator.checkDhtServers id:int256 = engine.validator.DhtServersStatus;

engine.validator.getOverlaysStats = engine.validator.OverlaysStats;

engine.validator.controlQuery data:bytes = Object;

engine.validator.importCertificate overlay_id:int256 local_id:adnl.id.short signed_key:engine.validator.KeyHash cert:overlay.Certificate = engine.validator.Success;
engine.validator.signShardOverlayCertificate workchain:int shard:long signed_key:engine.validator.KeyHash expire_at:int max_size:int = overlay.Certificate;
engine.validator.importShardOverlayCertificate workchain:int shard:long signed_key:engine.validator.KeyHash cert:overlay.Certificate = engine.validator.Success;

engine.validator.getPerfTimerStats name:string = engine.validator.PerfTimerStats;
engine.validator.getShardOutQueueSize flags:# block_id:tosNode.blockId dest_wc:flags.0?int dest_shard:flags.0?long = engine.validator.ShardOutQueueSize;
engine.validator.setExtMessagesBroadcastDisabled disabled:Bool = engine.validator.Success;

engine.validator.addCustomOverlay overlay:engine.validator.customOverlay = engine.validator.Success;
engine.validator.delCustomOverlay name:string = engine.validator.Success;
engine.validator.showCustomOverlays = engine.validator.CustomOverlaysConfig;

engine.validator.setStateSerializerEnabled enabled:Bool = engine.validator.Success;

engine.validator.setCollatorOptionsJson json:string = engine.validator.Success;
engine.validator.getCollatorOptionsJson = engine.validator.JsonConfig;

engine.validator.getAdnlStats all:Bool = adnl.Stats;
engine.validator.getActorTextStats = engine.validator.TextStats;

engine.validator.addShard shard:tosNode.shardId = engine.validator.Success;
engine.validator.delShard shard:tosNode.shardId = engine.validator.Success;

engine.validator.addCollator adnl_id:int256 shard:tosNode.shardId = engine.validator.Success;
engine.validator.delCollator adnl_id:int256 shard:tosNode.shardId = engine.validator.Success;

engine.validator.collatorNodeSetWhitelistedValidator adnl_id:int256 add:Bool = engine.validator.Success;
engine.validator.collatorNodeSetWhitelistEnabled enabled:Bool = engine.validator.Success;
engine.validator.showCollatorNodeWhitelist = engine.validator.CollatorNodeWhitelist;

engine.validator.setCollatorsList list:engine.validator.collatorsList = engine.validator.Success;
engine.validator.clearCollatorsList = engine.validator.Success;
engine.validator.showCollatorsList = engine.validator.CollatorsList;
engine.validator.getCollationManagerStats = engine.validator.CollationManagerStats;

engine.validator.signOverlayMemberCertificate sign_by:int256 adnl_id:int256 slot:int expire_at:int = overlay.MemberCertificate;
engine.validator.importFastSyncMemberCertificate adnl_id:int256 certificate:overlay.MemberCertificate = engine.validator.Success;
engine.validator.addFastSyncClient adnl_id:int256 slot:int = engine.validator.Success;
engine.validator.delFastSyncClient adnl_id:int256 = engine.validator.Success;

engine.validator.setShardBlockVerifierConfig config:engine.validator.shardBlockVerifierConfig = engine.validator.Success;
engine.validator.showShardBlockVerifierConfig = engine.validator.ShardBlockVerifierConfig;

---types---

storage.pong = storage.Pong;
storage.ok = Ok;

storage.state will_upload:Bool want_download:Bool = storage.State;
storage.piece proof:bytes data:bytes = storage.Piece;
storage.torrentInfo data:bytes = storage.TorrentInfo;

storage.updateInit have_pieces:bytes have_pieces_offset:int state:storage.State = storage.Update;
storage.updateHavePieces piece_id:(vector int) = storage.Update;
storage.updateState state:storage.State = storage.Update;

---functions---

storage.ping session_id:long = storage.Pong;
storage.addUpdate session_id:long seqno:int update:storage.Update = Ok;

storage.getTorrentInfo = storage.TorrentInfo;
storage.getPiece piece_id:int = storage.Piece;

---types---

http.header name:string value:string = http.Header;
http.payloadPart data:bytes trailer:(vector http.header) last:Bool = http.PayloadPart;
http.response http_version:string status_code:int reason:string headers:(vector http.header) no_payload:Bool = http.Response;
http.proxy.capabilities capabilities:long = http.proxy.Capabilities;

---functions---

http.request id:int256 method:string url:string http_version:string headers:(vector http.header) = http.Response;
http.getNextPayloadPart id:int256 seqno:int max_chunk_size:int = http.PayloadPart;
http.proxy.getCapabilities capabilities:long = http.proxy.Capabilities;

---types---


http.server.dnsEntry domain:string addr:adnl.id.short = http.server.DnsEntry;
http.server.host domains:(vector string) ip:int port:int adnl_id:adnl.id.short = http.server.Host;

http.server.config dhs:(vector http.server.dnsEntry) local_hosts:(vector http.server.host) = http.server.Config;

---functions---

---types---

validatorStats.stats.producer flags:#
  validator_id:int256 block_status:int
  candidate_id:flags.0?int256 block_id:flags.0?tosNode.blockIdExt collated_data_hash:flags.0?int256
  is_accepted:flags.0?Bool is_ours:flags.0?Bool
  got_block_at:flags.0?double got_block_by:flags.0?int got_submit_at:flags.0?double gen_utime:flags.0?int comment:flags.0?string
  collation_time:flags.1?double collated_at:flags.1?double collation_cached:flags.1?Bool self_collated:flags.1?Bool collator_node_id:flags.2?int256
  validation_time:flags.3?double validated_at:flags.3?double validation_cached:flags.3?Bool
  approved_weight:flags.0?long approved_33pct_at:flags.0?double approved_66pct_at:flags.0?double approvers:flags.0?string
  signed_weight:flags.0?long signed_33pct_at:flags.0?double signed_66pct_at:flags.0?double signers:flags.0?string
  serialize_time:flags.4?double deserialize_time:flags.4?double serialized_size:flags.4?int = validatorStats.stats.Producer;

validatorStats.stats.round started_at:double producers:(vector validatorStats.stats.producer) = validatorStats.stats.Round;

validatorStats.stats flags:#
    session_id:int256 self:int256 block_id:tosNode.blockIdExt cc_seqno:int success:Bool timestamp:double
    creator:flags.0?int256
    total_validators:int total_weight:long
    signatures:flags.0?int signatures_weight:flags.0?long
    approve_signatures:flags.0?int approve_signatures_weight:flags.0?long
    first_round:int rounds:(vector validatorStats.stats.round) = validatorStats.Stats;

validatorStats.blockLimitsStatus
    bytes:int gas:int lt_delta:int collated_data_bytes:int
    cat_bytes:int cat_gas:int cat_lt_delta:int cat_collated_data_bytes:int
    load_fraction_queue_cleanup:double load_fraction_dispatch:double
    load_fraction_internals:double load_fraction_externals:double
    load_fraction_new_msgs:double
    limits_log:string = validatorStats.BlockLimitsStatus;
validatorStats.blockStats.extMsgsStats
    ext_msgs_total:int ext_msgs_filtered:int ext_msgs_accepted:int ext_msgs_rejected:int = validatorStats.ExtMsgsStats;
validatorStats.blockStats.neighborStats shard:tosNode.shardId is_trivial:Bool is_local:Bool msg_limit:int
    processed_msgs:int skipped_msgs:int limit_reached:Bool = validatorStats.blockStats.NeighborStats;
validatorStats.blockStats
    ext_msgs:validatorStats.blockStats.extMsgsStats transactions:int shard_configuration:(vector tosNode.blockIdExt)
    old_out_msg_queue_size:long new_out_msg_queue_size:long msg_queue_cleaned:int
    neighbors:(vector validatorStats.blockStats.neighborStats)
    mc_block_id:tosNode.blockIdExt = validatorStats.BlockStats;
validatorStats.storageStatCacheStats
    small_cnt:long small_cells:long hit_cnt:long hit_cells:long miss_cnt:long miss_cells:long = validatorStats.StorageStatCacheStats;

validatorStats.collatedBlock
    block_id:tosNode.blockIdExt collated_data_hash:int256 cc_seqno:int collated_at:double
    bytes:int collated_data_bytes:int attempt:int
    self:int256 is_validator:Bool
    total_time:double work_time:double cpu_work_time:double time_stats:string
    work_time_real_stats:string
    work_time_cpu_stats:string
    block_limits:validatorStats.blockLimitsStatus
    block_stats:validatorStats.blockStats
    storage_stat_cache:validatorStats.storageStatCacheStats = validatorSession.stats.CollatedBlock;

validatorStats.validatedBlock
    block_id:tosNode.blockIdExt collated_data_hash:int256 validated_at:double
    self:int256
    valid:Bool comment:string
    bytes:int collated_data_bytes:int
    total_time:double work_time:double actual_time:double cpu_work_time:double time_stats:string
    work_time_real_stats:string
    work_time_cpu_stats:string
    storage_stat_cache:validatorStats.storageStatCacheStats
    parallel_accounts_validation:Bool = validatorStats.ValidatedBlock;

validatorStats.newValidatorGroup.node id:int256 pubkey:PublicKey adnl_id:int256 weight:long = validatorStats.newValidatorGroup.Node;
validatorStats.newValidatorGroup session_id:int256 shard:tosNode.shardId cc_seqno:int
    last_key_block_seqno:int started_at:double prev:(vector tosNode.blockIdExt)
    self_idx:int self:int256 nodes:(vector validatorStats.newValidatorGroup.node) = validatorStats.NewValidatorGroup;

validatorStats.endValidatorGroup.node id:int256 catchain_blocks:int = validatorStats.endValidatorGroup.Node;
validatorStats.endValidatorGroup session_id:int256 timestamp:double self:int256
    nodes:(vector validatorStats.endValidatorGroup.node) = validatorStats.EndValidatorGroup;

validatorStats.collatorNodeResponse self:int256 validator_id:int256 timestamp:double
    block_id:tosNode.blockIdExt original_block_id:tosNode.blockIdExt collated_data_hash:int256
    = validatorStats.CollatorNodeResponse;

collatorNode.candidate source:PublicKey id:tosNode.blockIdExt data:bytes collated_data:bytes = collatorNode.Candidate;
collatorNode.compressedCandidate flags:# source:PublicKey id:tosNode.blockIdExt decompressed_size:int data:bytes = collatorNode.Candidate;
collatorNode.compressedCandidateV2 flags:# source:PublicKey id:tosNode.blockIdExt data:bytes = collatorNode.Candidate;
collatorNode.pong#5bbf0521 flags:# version:flags.0?int = collatorNode.Pong;
collatorNode.error code:int message:string = collatorNode.Error;

shardBlockVerifier.subscribed flags:# = shardBlockVerifier.Subscribed;
shardBlockVerifier.confirmBlocks blocks:(vector tosNode.blockIdExt) = shardBlockVerifier.ConfirmBlocks;

---functions---
collatorNode.generateBlock shard:tosNode.shardId cc_seqno:int prev_blocks:(vector tosNode.blockIdExt)
    creator:int256 round:int first_block_round:int priority:int = collatorNode.Candidate;
collatorNode.requestBlockCallback flags:# block_id:tosNode.BlockIdExt = collatorNode.Candidate;
collatorNode.ping flags:# = collatorNode.Pong;

shardBlockVerifier.subscribe shard:tosNode.shardId flags:# = shardBlockVerifier.Subscribed;

---types---

storage.db.key.torrentList = storage.db.key.TorrentList;
storage.db.key.torrent hash:int256 = storage.db.key.TorrentShort;
storage.db.key.torrentMeta hash:int256 = storage.db.key.TorrentMeta;
storage.db.key.priorities hash:int256 = storage.db.key.Priorities;
storage.db.key.piecesInDb hash:int256 = storage.db.key.PiecesInDb;
storage.db.key.pieceInDb hash:int256 idx:long = storage.db.key.PieceInDb;
storage.db.key.config = storage.db.key.Config;

storage.db.config flags:# download_speed_limit:double upload_speed_limit:double = storage.db.Config;
storage.db.torrentList torrents:(vector int256) = storage.db.TorrentList;
storage.db.torrent root_dir:string active_download:Bool active_upload:Bool = storage.db.TorrentShort;
storage.db.torrentV2 flags:# root_dir:string added_at:int active_download:Bool active_upload:Bool = storage.db.TorrentShort;
storage.db.priorities actions:(vector storage.PriorityAction) = storage.db.Priorities;
storage.db.piecesInDb pieces:(vector long) = storage.db.PiecesInDb;

storage.priorityAction.all priority:int = storage.PriorityAction;
storage.priorityAction.idx idx:long priority:int = storage.PriorityAction;
storage.priorityAction.name name:string priority:int = storage.PriorityAction;

storage.daemon.config server_key:PublicKey cli_key_hash:int256 provider_address:string adnl_id:PublicKey dht_id:PublicKey = storage.daemon.provider.Config;

storage.daemon.provider.params accept_new_contracts:Bool rate_per_mb_day:string max_span:int
    minimal_file_size:long maximal_file_size:long = storage.daemon.provider.Params;

storage.provider.db.key.state = storage.provider.db.key.State;
storage.provider.db.key.contractList = storage.provider.db.key.ContractList;
storage.provider.db.key.storageContract wc:int addr:int256 = storage.provider.db.key.StorageContract;
storage.provider.db.key.microchunkTree wc:int addr:int256 = storage.provider.db.key.MicrochunkTree;
storage.provider.db.key.providerConfig = storage.provider.db.key.ProviderConfig;

storage.provider.db.state last_processed_lt:long = storage.provider.db.State;
storage.provider.db.contractAddress wc:int addr:int256 = storage.db.ContractAddress;
storage.provider.db.contractList contracts:(vector storage.provider.db.contractAddress) = storage.db.ContractList;
storage.provider.db.storageContract torrent_hash:int256 microchunk_hash:int256 created_time:int state:int file_size:long
    rate:string max_span:int = storage.provider.db.StorageContract;
storage.provider.db.microchunkTree data:bytes = storage.provider.db.MicrochunkTree;

storage.daemon.queryError message:string = storage.daemon.QueryError;
storage.daemon.success = storage.daemon.Success;

storage.daemon.torrent
    hash:int256 flags:#
    // 0 - info ready
    // 1 - header ready
    // 2 - fatal error
    total_size:flags.0?long description:flags.0?string
    files_count:flags.1?long included_size:flags.1?long dir_name:flags.1?string
    downloaded_size:long
    added_at:int root_dir:string active_download:Bool active_upload:Bool completed:Bool
    download_speed:double upload_speed:double
    fatal_error:flags.2?string
    = storage.daemon.Torrent;

storage.daemon.fileInfo
    name:string size:long flags:#
    priority:int
    downloaded_size:long
    = storage.daemon.FileInfo;

storage.daemon.torrentFull torrent:storage.daemon.torrent files:(vector storage.daemon.fileInfo) = storage.daemon.TorrentFull;
storage.daemon.torrentList torrents:(vector storage.daemon.torrent) = storage.daemon.TorrentList;
storage.daemon.torrentMeta meta:bytes = storage.daemon.TorrentMeta;

storage.daemon.filePiecesInfo name:string range_l:long range_r:long = storage.daemon.FilePiecesInfo;
storage.daemon.torrentPiecesInfo
    flags:# // 0 - with file ranges
    total_pieces:long piece_size:int
    range_l:long range_r:long piece_ready_bitset:bytes
    files:flags.0?(vector storage.daemon.filePiecesInfo) // files[0] is header
    = storage.daemon.TorrentPiecesInfo;

storage.daemon.newContractParams rate:string max_span:int = storage.daemon.NewContractParams;
storage.daemon.newContractParamsAuto provider_address:string = storage.daemon.NewContractParams;
storage.daemon.newContractMessage body:bytes rate:string max_span:int = storage.daemon.NewContractMessage;

storage.daemon.peer adnl_id:int256 ip_str:string download_speed:double upload_speed:double ready_parts:long = storage.daemon.Peer;
storage.daemon.peerList peers:(vector storage.daemon.peer) download_speed:double upload_speed:double total_parts:long = storage.daemon.PeerList;

storage.daemon.prioritySet = storage.daemon.SetPriorityStatus;
storage.daemon.priorityPending = storage.daemon.SetPriorityStatus;

storage.daemon.keyHash key_hash:int256 = storage.daemon.KeyHash;

storage.daemon.speedLimits download:double upload:double = storage.daemon.SpeedLimits;

storage.daemon.providerConfig max_contracts:int max_total_size:long = storage.daemon.ProviderConfig;
storage.daemon.contractInfo address:string state:int torrent:int256 created_time:int file_size:long downloaded_size:long
    rate:string max_span:int client_balance:string contract_balance:string = storage.daemon.ContractInfo;
storage.daemon.providerInfo address:string balance:string config:storage.daemon.providerConfig
    contracts_count:int contracts_total_size:long
    contracts:(vector storage.daemon.contractInfo) = storage.daemon.ProviderInfo;
storage.daemon.providerAddress address:string = storage.daemon.ProviderAddress;

---functions---
storage.daemon.setVerbosity verbosity:int = storage.daemon.Success;
storage.daemon.createTorrent path:string description:string allow_upload:Bool copy_inside:Bool flags:# = storage.daemon.TorrentFull;
storage.daemon.addByHash hash:int256 root_dir:string start_download:Bool allow_upload:Bool priorities:(vector storage.PriorityAction) flags:# = storage.daemon.TorrentFull;
storage.daemon.addByMeta meta:bytes root_dir:string start_download:Bool allow_upload:Bool priorities:(vector storage.PriorityAction) flags:# = storage.daemon.TorrentFull;
storage.daemon.setActiveDownload hash:int256 active:Bool = storage.daemon.Success;
storage.daemon.setActiveUpload hash:int256 active:Bool = storage.daemon.Success;

storage.daemon.getTorrents flags:# = storage.daemon.TorrentList;
storage.daemon.getTorrentFull hash:int256 flags:# = storage.daemon.TorrentFull;
storage.daemon.getTorrentMeta hash:int256 flags:# = storage.daemon.TorrentMeta;
storage.daemon.getNewContractMessage hash:int256 query_id:long params:storage.daemon.NewContractParams = storage.daemon.NewContractMessage;
storage.daemon.getTorrentPeers hash:int256 flags:# = storage.daemon.PeerList;
storage.daemon.getTorrentPiecesInfo hash:int256
    flags:# // 0 - with file ranges
    offset:long max_pieces:long
    = storage.daemon.TorrentPiecesInfo;

storage.daemon.setFilePriorityAll hash:int256 priority:int = storage.daemon.SetPriorityStatus;
storage.daemon.setFilePriorityByIdx hash:int256 idx:long priority:int = storage.daemon.SetPriorityStatus;
storage.daemon.setFilePriorityByName hash:int256 name:string priority:int = storage.daemon.SetPriorityStatus;

storage.daemon.removeTorrent hash:int256 remove_files:Bool = storage.daemon.Success;
storage.daemon.loadFrom hash:int256 meta:bytes path:string flags:# = storage.daemon.Torrent;

storage.daemon.getSpeedLimits flags:# = storage.daemon.SpeedLimits;
storage.daemon.setSpeedLimits flags:# download:flags.0?double upload:flags.1?double = storage.daemon.Success;


storage.daemon.importPrivateKey key:PrivateKey = storage.daemon.KeyHash;
storage.daemon.initProvider account_address:string = storage.daemon.Success;
storage.daemon.deployProvider = storage.daemon.ProviderAddress;
storage.daemon.getProviderParams address:string = storage.daemon.provider.Params;
storage.daemon.setProviderParams params:storage.daemon.provider.params = storage.daemon.Success;
storage.daemon.getProviderInfo with_balances:Bool with_contracts:Bool = storage.daemon.ProviderInfo;
storage.daemon.setProviderConfig config:storage.daemon.providerConfig = storage.daemon.Success;
storage.daemon.withdraw contract:string = storage.daemon.Success;
storage.daemon.sendCoins address:string amount:string message:string = storage.daemon.Success;
storage.daemon.closeStorageContract address:string = storage.daemon.Success;
storage.daemon.removeStorageProvider = storage.daemon.Success;

---types---
proxyLiteserver.config port:int id:PublicKey = proxyLiteserver.Config;
---functions---

---types---
quic.message data:bytes = quic.Request;
quic.query data:bytes = quic.Request;
quic.answer data:bytes = quic.Response;

engineConsoleClient.config address:string server_public_key:PublicKey client_private_key:PrivateKey = engineConsoleClient.Config;

consensus.overlayId session_id:int256 nodes:(vector int256) = consensus.OverlayId;
consensus.dataToSign session_id:int256 data:bytes = consensus.DataToSign;

consensus.candidateId slot:int hash:int256 = consensus.CandidateId;
consensus.candidateParent id:consensus.CandidateId = consensus.CandidateParent;
consensus.candidateWithoutParents = consensus.CandidateParent;

consensus.candidateHashDataOrdinary block:tosNode.blockIdExt collated_file_hash:int256 parent:consensus.CandidateParent = consensus.CandidateHashData;
consensus.candidateHashDataEmpty block:tosNode.blockIdExt parent:consensus.candidateId = consensus.CandidateHashData;

consensus.block slot:int parent:consensus.CandidateParent candidate:bytes signature:bytes = consensus.CandidateData;
consensus.empty slot:int parent:consensus.CandidateId block:tosNode.blockIdExt signature:bytes = consensus.CandidateData;

consensus.broadcastExtra slot:int = consensus.BroadcastExtra;

consensus.requestError = consensus.RequestError;

consensus.simplex.notarizeVote id:consensus.CandidateId = consensus.simplex.UnsignedVote;
consensus.simplex.finalizeVote id:consensus.CandidateId = consensus.simplex.UnsignedVote;
consensus.simplex.skipVote slot:int = consensus.simplex.UnsignedVote;
consensus.simplex.vote vote:consensus.simplex.UnsignedVote signature:bytes = consensus.simplex.Vote;

consensus.simplex.voteSignature who:int signature:bytes = consensus.simplex.VoteSignature;
consensus.simplex.voteSignatureSet votes:(vector consensus.simplex.VoteSignature) = consensus.simplex.VoteSignatureSet;
consensus.simplex.certificate vote:consensus.simplex.UnsignedVote signatures:consensus.simplex.VoteSignatureSet = consensus.simplex.Certificate;

consensus.simplex.candidateAndCert candidate:bytes notar:bytes = consensus.simplex.CandidateAndCert;

consensus.simplex.db.key.vote vote_hash:int256 = consensus.simplex.db.key.Vote;
consensus.simplex.db.ourVote vote:consensus.simplex.UnsignedVote seqno:long = consensus.simplex.db.Vote;
consensus.simplex.db.cert cert:consensus.simplex.Certificate = consensus.simplex.db.Vote;

consensus.simplex.db.key.poolState = consensus.simplex.db.key.PoolState;
consensus.simplex.db.poolState first_nonannounced_window:int = consensus.simplex.db.PoolState;

consensus.simplex.db.key.finalizedBlock candidateId:consensus.candidateId = consensus.simplex.db.key.FinalizedBlock;
consensus.simplex.db.finalizedBlock block_id:tosNode.blockIdExt parent:consensus.CandidateParent is_final:Bool = consensus.simplex.db.FinalizedBlock;

consensus.simplex.db.key.candidate candidateId:consensus.candidateId = consensus.simplex.db.key.Candidate;

consensus.simplex.db.key.candidateResolver.candidateInfo candidateId:consensus.candidateId = consensus.simplex.db.key.candidateResolver.CandidateInfo;
consensus.simplex.db.candidateResolver.candidateInfo leader_id:int candidate_hash_data:consensus.CandidateHashData signature:bytes = consensus.simplex.db.candidateResolver.CandidateInfo;
consensus.simplex.db.key.candidateResolver.notarCert candidateId:consensus.candidateId = consensus.simplex.db.key.candidateResolver.NotarCert;
consensus.simplex.db.candidateResolver.notarCert notar:consensus.simplex.voteSignatureSet = consensus.simplex.db.candidateResolver.NotarCert;

consensus.stats.block id:tosNode.blockIdExt = consensus.stats.CandidateBlock;
consensus.stats.empty = consensus.stats.CandidateBlock;

consensus.stats.id workchain:int shard:long cc_seqno:int idx:int total_validators:int weight:long total_weight:long slots_per_leader_window:int = consensus.stats.Event;
consensus.stats.collateStarted target_slot:int = consensus.stats.Event;
consensus.stats.collateFinished target_slot:int id:consensus.candidateId = consensus.stats.Event;
consensus.stats.collatedEmpty id:consensus.candidateId = consensus.stats.Event;
consensus.stats.candidateReceived id:consensus.candidateId parent:consensus.CandidateParent block:consensus.stats.CandidateBlock is_collator:Bool = consensus.stats.Event;
consensus.stats.validationStarted id:consensus.candidateId = consensus.stats.Event;
consensus.stats.validationFinished id:consensus.candidateId = consensus.stats.Event;
consensus.stats.blockAccepted id:consensus.candidateId = consensus.stats.Event;
consensus.stats.timestampedEvent ts:double event:consensus.stats.Event = consensus.stats.TimestampedEvent;
consensus.stats.events id:int256 events:(vector consensus.stats.timestampedEvent) = consensus.stats.Events;

consensus.simplex.stats.voted vote:consensus.simplex.UnsignedVote = consensus.stats.Event;
consensus.simplex.stats.certObserved vote:consensus.simplex.UnsignedVote = consensus.stats.Event;

consensus.simplex.noncriticalParams
    flags:#
    target_rate_ms:flags.0?int
    first_block_timeout_ms:flags.1?int
    first_block_timeout_multiplier:flags.2?double
    first_block_timeout_cap_ms:flags.3?int
    candidate_resolve_timeout_ms:flags.4?int
    candidate_resolve_timeout_multiplier:flags.5?double
    candidate_resolve_timeout_cap_ms:flags.6?int
    candidate_resolve_cooldown_ms:flags.7?int
    standstill_timeout_ms:flags.8?int
    standstill_max_egress_bytes_per_s:flags.9?int
    max_leader_window_desync:flags.10?int
    bad_signature_ban_duration_ms:flags.11?int
    candidate_resolve_rate_limit:flags.12?int
    min_block_interval_ms:flags.13?int
    no_empty_blocks_on_error_timeout_ms:flags.14?int
    = consensus.NoncriticalParams;

consensus.noncriticalParamsOverride
    workchain:int
    shard:long
    from_seqno:int
    to_seqno:int
    override:consensus.NoncriticalParams
    = consensus.NoncriticalParamsOverride;

consensus.noncriticalParamsOverrideList
    overrides:(vector consensus.noncriticalParamsOverride)
    = consensus.NoncriticalParamsOverrideList;

---functions---
consensus.simplex.requestCandidate id:consensus.CandidateId want_candidate:Bool want_notar:Bool = consensus.simplex.CandidateAndCert;

engine.validator.setConsensusNoncriticalParamsOverrides overrides:consensus.noncriticalParamsOverrideList = engine.validator.Success;
engine.validator.getConsensusNoncriticalParamsOverrides = consensus.NoncriticalParamsOverrideList;
