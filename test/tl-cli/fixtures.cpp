// Deterministic public wire values for cross-language codec tests.
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

#include "auto/tl/lite_api.h"
#include "auto/tl/tos_api.h"
#include "auto/tl/toslib_api.h"
#include "td/utils/UInt.h"
#include "td/utils/misc.h"
#include "td/utils/tl_storers.h"
#include "tl-utils/tl-utils.hpp"
namespace {
td::Bits256 bits(unsigned char seed) {
  td::Bits256 value;
  value.as_slice().fill(char(seed));
  return value;
}
auto make_lite_api_liteserver_getconfigall(std::size_t length)
    -> tos::lite_api::object_ptr<tos::lite_api::liteServer_getConfigAll>;
auto make_lite_api_liteserver_getconfigparams(std::size_t length)
    -> tos::lite_api::object_ptr<tos::lite_api::liteServer_getConfigParams>;
auto make_lite_api_liteserver_sendmessage(std::size_t length)
    -> tos::lite_api::object_ptr<tos::lite_api::liteServer_sendMessage>;
auto make_tos_api_adnl_stats_ippackets(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::adnl_stats_ipPackets>;
auto make_tos_api_adnl_stats_localid(std::size_t length) -> tos::tos_api::object_ptr<tos::tos_api::adnl_stats_localId>;
auto make_tos_api_adnl_stats_localidpackets(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::adnl_stats_localIdPackets>;
auto make_tos_api_adnl_stats_packets(std::size_t length) -> tos::tos_api::object_ptr<tos::tos_api::adnl_stats_packets>;
auto make_tos_api_adnl_stats_peerpair(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::adnl_stats_peerPair>;
auto make_tos_api_engine_adnl(std::size_t length) -> tos::tos_api::object_ptr<tos::tos_api::engine_adnl>;
auto make_tos_api_engine_collator(std::size_t length) -> tos::tos_api::object_ptr<tos::tos_api::engine_collator>;
auto make_tos_api_engine_controlinterface(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_controlInterface>;
auto make_tos_api_engine_controlprocess(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_controlProcess>;
auto make_tos_api_engine_dht(std::size_t length) -> tos::tos_api::object_ptr<tos::tos_api::engine_dht>;
auto make_tos_api_engine_gc(std::size_t length) -> tos::tos_api::object_ptr<tos::tos_api::engine_gc>;
auto make_tos_api_engine_liteserver(std::size_t length) -> tos::tos_api::object_ptr<tos::tos_api::engine_liteServer>;
auto make_tos_api_engine_quicaddr(std::size_t length) -> tos::tos_api::object_ptr<tos::tos_api::engine_quicAddr>;
auto make_tos_api_engine_validator(std::size_t length) -> tos::tos_api::object_ptr<tos::tos_api::engine_validator>;
auto make_tos_api_engine_validator_addadnlid(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_addAdnlId>;
auto make_tos_api_engine_validator_addcollator(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_addCollator>;
auto make_tos_api_engine_validator_addcustomoverlay(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_addCustomOverlay>;
auto make_tos_api_engine_validator_addliteserver(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_addLiteserver>;
auto make_tos_api_engine_validator_addquicaddr(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_addQuicAddr>;
auto make_tos_api_engine_validator_addvalidatoradnladdress(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_addValidatorAdnlAddress>;
auto make_tos_api_engine_validator_addvalidatorpermanentkey(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_addValidatorPermanentKey>;
auto make_tos_api_engine_validator_addvalidatortempkey(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_addValidatorTempKey>;
auto make_tos_api_engine_validator_clearcollatorslist(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_clearCollatorsList>;
auto make_tos_api_engine_validator_collatornodesetwhitelistenabled(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_collatorNodeSetWhitelistEnabled>;
auto make_tos_api_engine_validator_collatornodesetwhitelistedvalidator(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_collatorNodeSetWhitelistedValidator>;
auto make_tos_api_engine_validator_collatornodewhitelist(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_collatorNodeWhitelist>;
auto make_tos_api_engine_validator_collatoroptions(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_collatorOptions>;
auto make_tos_api_engine_validator_collatorslist(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_collatorsList>;
auto make_tos_api_engine_validator_collatorslist_collator(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_collatorsList_collator>;
auto make_tos_api_engine_validator_collatorslist_shard(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_collatorsList_shard>;
auto make_tos_api_engine_validator_config(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_config>;
auto make_tos_api_engine_validator_configproposaldetail(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_configProposalDetail>;
auto make_tos_api_engine_validator_configproposalmeta(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_configProposalMeta>;
auto make_tos_api_engine_validator_configproposals(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_configProposals>;
auto make_tos_api_engine_validator_controlqueryerror(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_controlQueryError>;
auto make_tos_api_engine_validator_createpqstakeauthorization(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_createPqStakeAuthorization>;
auto make_tos_api_engine_validator_customoverlay(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_customOverlay>;
auto make_tos_api_engine_validator_customoverlaynode(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_customOverlayNode>;
auto make_tos_api_engine_validator_customoverlaysconfig(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_customOverlaysConfig>;
auto make_tos_api_engine_validator_delcollator(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_delCollator>;
auto make_tos_api_engine_validator_delcustomoverlay(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_delCustomOverlay>;
auto make_tos_api_engine_validator_electionparticipant(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_electionParticipant>;
auto make_tos_api_engine_validator_electorstate(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_electorState>;
auto make_tos_api_engine_validator_exportpublickey(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_exportPublicKey>;
auto make_tos_api_engine_validator_extmessagepoolconfig(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_extMessagePoolConfig>;
auto make_tos_api_engine_validator_extraconfig(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_extraConfig>;
auto make_tos_api_engine_validator_fastsyncmembercertificate(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_fastSyncMemberCertificate>;
auto make_tos_api_engine_validator_fastsyncoverlayclient(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_fastSyncOverlayClient>;
auto make_tos_api_engine_validator_frozenstake(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_frozenStake>;
auto make_tos_api_engine_validator_fullnodeconfig(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_fullNodeConfig>;
auto make_tos_api_engine_validator_fullnodemaster(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_fullNodeMaster>;
auto make_tos_api_engine_validator_fullnodeslave(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_fullNodeSlave>;
auto make_tos_api_engine_validator_generatekeypair(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_generateKeyPair>;
auto make_tos_api_engine_validator_getcollatoroptionsjson(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_getCollatorOptionsJson>;
auto make_tos_api_engine_validator_getconfig(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_getConfig>;
auto make_tos_api_engine_validator_getconfigproposal(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_getConfigProposal>;
auto make_tos_api_engine_validator_getconfigproposals(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_getConfigProposals>;
auto make_tos_api_engine_validator_getelectorstate(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_getElectorState>;
auto make_tos_api_engine_validator_getstats(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_getStats>;
auto make_tos_api_engine_validator_gettime(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_getTime>;
auto make_tos_api_engine_validator_jsonconfig(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_jsonConfig>;
auto make_tos_api_engine_validator_keyhash(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_keyHash>;
auto make_tos_api_engine_validator_onestat(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_oneStat>;
auto make_tos_api_engine_validator_overlaystats(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_overlayStats>;
auto make_tos_api_engine_validator_overlaystatsbroadcasts(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_overlayStatsBroadcasts>;
auto make_tos_api_engine_validator_overlaystatsnode(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_overlayStatsNode>;
auto make_tos_api_engine_validator_overlaystatstraffic(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_overlayStatsTraffic>;
auto make_tos_api_engine_validator_pastelection(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_pastElection>;
auto make_tos_api_engine_validator_pqconsensus(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_pqConsensus>;
auto make_tos_api_engine_validator_pqconsensuskey(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_pqConsensusKey>;
auto make_tos_api_engine_validator_returnedstake(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_returnedStake>;
auto make_tos_api_engine_validator_setcollatoroptionsjson(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_setCollatorOptionsJson>;
auto make_tos_api_engine_validator_shardblockverifierconfig_shard(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_shardBlockVerifierConfig_shard>;
auto make_tos_api_engine_validator_showcollatornodewhitelist(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_showCollatorNodeWhitelist>;
auto make_tos_api_engine_validator_showcollatorslist(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_showCollatorsList>;
auto make_tos_api_engine_validator_showcustomoverlays(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_showCustomOverlays>;
auto make_tos_api_engine_validator_sign(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_sign>;
auto make_tos_api_engine_validator_signature(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_signature>;
auto make_tos_api_engine_validator_stats(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_stats>;
auto make_tos_api_engine_validator_success(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_success>;
auto make_tos_api_engine_validator_time(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_time>;
auto make_tos_api_engine_validatoradnladdress(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validatorAdnlAddress>;
auto make_tos_api_engine_validatortempkey(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validatorTempKey>;
auto make_tos_api_liteserver_desc(std::size_t length) -> tos::tos_api::object_ptr<tos::tos_api::liteserver_desc>;
auto make_tos_api_liteserver_descv2(std::size_t length) -> tos::tos_api::object_ptr<tos::tos_api::liteserver_descV2>;
auto make_tos_api_liteserver_descv2_slicesimple(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::liteserver_descV2_sliceSimple>;
auto make_tos_api_overlay_membercertificate(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::overlay_memberCertificate>;
auto make_tos_api_pub_ed25519(std::size_t length) -> tos::tos_api::object_ptr<tos::tos_api::pub_ed25519>;
auto make_tos_api_tosnode_blockidext(std::size_t length) -> tos::tos_api::object_ptr<tos::tos_api::tosNode_blockIdExt>;
auto make_tos_api_tosnode_shardid(std::size_t length) -> tos::tos_api::object_ptr<tos::tos_api::tosNode_shardId>;
auto make_toslib_api_raw_extmessageinfo(std::size_t length)
    -> tos::toslib_api::object_ptr<tos::toslib_api::raw_extMessageInfo>;
auto make_lite_api_liteserver_getconfigall(std::size_t length)
    -> tos::lite_api::object_ptr<tos::lite_api::liteServer_getConfigAll> {
  auto out = tos::lite_api::make_object<tos::lite_api::liteServer_getConfigAll>();
  out->mode_ = 0;
  out->id_ = tos::lite_api::make_object<tos::lite_api::tosNode_blockIdExt>(0, std::numeric_limits<std::int64_t>::min(),
                                                                           0, bits(0), bits(0));
  return out;
}
auto make_lite_api_liteserver_getconfigparams(std::size_t length)
    -> tos::lite_api::object_ptr<tos::lite_api::liteServer_getConfigParams> {
  auto out = tos::lite_api::make_object<tos::lite_api::liteServer_getConfigParams>();
  out->mode_ = 0;
  out->id_ = tos::lite_api::make_object<tos::lite_api::tosNode_blockIdExt>(0, std::numeric_limits<std::int64_t>::min(),
                                                                           0, bits(0), bits(0));
  out->param_list_.push_back(5);
  return out;
}
auto make_lite_api_liteserver_sendmessage(std::size_t length)
    -> tos::lite_api::object_ptr<tos::lite_api::liteServer_sendMessage> {
  auto out = tos::lite_api::make_object<tos::lite_api::liteServer_sendMessage>();
  out->body_ = td::BufferSlice(std::string(length, char(18)));
  return out;
}
auto make_tos_api_adnl_stats_ippackets(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::adnl_stats_ipPackets> {
  auto out = tos::tos_api::make_object<tos::tos_api::adnl_stats_ipPackets>();
  out->ip_str_ = std::string("wire-fixture");
  out->packets_ = std::int64_t{6};
  return out;
}
auto make_tos_api_adnl_stats_localid(std::size_t length) -> tos::tos_api::object_ptr<tos::tos_api::adnl_stats_localId> {
  auto out = tos::tos_api::make_object<tos::tos_api::adnl_stats_localId>();
  out->short_id_ = bits(35);
  out->current_decrypt_.push_back(make_tos_api_adnl_stats_ippackets(length));
  out->packets_recent_ = make_tos_api_adnl_stats_localidpackets(length);
  out->peers_.push_back(make_tos_api_adnl_stats_peerpair(length));
  return out;
}
auto make_tos_api_adnl_stats_localidpackets(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::adnl_stats_localIdPackets> {
  auto out = tos::tos_api::make_object<tos::tos_api::adnl_stats_localIdPackets>();
  out->ts_start_ = 4.6875;
  out->ts_end_ = 4.0;
  out->decrypted_packets_.push_back(make_tos_api_adnl_stats_ippackets(length));
  out->dropped_packets_.push_back(make_tos_api_adnl_stats_ippackets(length));
  return out;
}
auto make_tos_api_adnl_stats_packets(std::size_t length) -> tos::tos_api::object_ptr<tos::tos_api::adnl_stats_packets> {
  auto out = tos::tos_api::make_object<tos::tos_api::adnl_stats_packets>();
  out->ts_start_ = 4.6875;
  out->ts_end_ = 4.0;
  out->in_packets_ = std::int64_t{1};
  out->in_bytes_ = std::int64_t{1};
  out->in_packets_channel_ = std::int64_t{6};
  out->in_bytes_channel_ = std::int64_t{6};
  out->out_packets_ = std::int64_t{4};
  out->out_bytes_ = std::int64_t{4};
  out->out_packets_channel_ = std::int64_t{2};
  out->out_bytes_channel_ = std::int64_t{2};
  out->out_expired_messages_ = std::int64_t{2};
  out->out_expired_bytes_ = std::int64_t{5};
  return out;
}
auto make_tos_api_adnl_stats_peerpair(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::adnl_stats_peerPair> {
  auto out = tos::tos_api::make_object<tos::tos_api::adnl_stats_peerPair>();
  out->local_id_ = bits(57);
  out->peer_id_ = bits(21);
  out->ip_str_ = std::string("wire-fixture");
  out->packets_recent_ = make_tos_api_adnl_stats_packets(length);
  out->packets_total_ = make_tos_api_adnl_stats_packets(length);
  out->last_out_packet_ts_ = 3.5625;
  out->last_in_packet_ts_ = 2.875;
  out->connection_ready_ = true;
  out->channel_status_ = 3;
  out->try_reinit_at_ = 4.0625;
  out->out_queue_messages_ = std::int64_t{1};
  out->out_queue_bytes_ = std::int64_t{4};
  return out;
}
auto make_tos_api_engine_adnl(std::size_t length) -> tos::tos_api::object_ptr<tos::tos_api::engine_adnl> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_adnl>();
  out->id_ = bits(29);
  out->category_ = 2;
  return out;
}
auto make_tos_api_engine_collator(std::size_t length) -> tos::tos_api::object_ptr<tos::tos_api::engine_collator> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_collator>();
  out->adnl_id_ = bits(8);
  out->shard_ = make_tos_api_tosnode_shardid(length);
  return out;
}
auto make_tos_api_engine_controlinterface(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_controlInterface> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_controlInterface>();
  out->id_ = bits(29);
  out->port_ = 6;
  out->allowed_.push_back(make_tos_api_engine_controlprocess(length));
  return out;
}
auto make_tos_api_engine_controlprocess(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_controlProcess> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_controlProcess>();
  out->id_ = bits(29);
  out->permissions_ = 2;
  return out;
}
auto make_tos_api_engine_dht(std::size_t length) -> tos::tos_api::object_ptr<tos::tos_api::engine_dht> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_dht>();
  out->id_ = bits(29);
  return out;
}
auto make_tos_api_engine_gc(std::size_t length) -> tos::tos_api::object_ptr<tos::tos_api::engine_gc> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_gc>();
  out->ids_.push_back(bits(26));
  return out;
}
auto make_tos_api_engine_liteserver(std::size_t length) -> tos::tos_api::object_ptr<tos::tos_api::engine_liteServer> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_liteServer>();
  out->id_ = bits(29);
  out->port_ = 6;
  return out;
}
auto make_tos_api_engine_quicaddr(std::size_t length) -> tos::tos_api::object_ptr<tos::tos_api::engine_quicAddr> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_quicAddr>();
  out->ip_ = 1;
  out->port_ = 6;
  out->categories_.push_back(6);
  out->priority_categories_.push_back(5);
  return out;
}
auto make_tos_api_engine_validator(std::size_t length) -> tos::tos_api::object_ptr<tos::tos_api::engine_validator> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator>();
  out->id_ = bits(29);
  out->temp_keys_.push_back(make_tos_api_engine_validatortempkey(length));
  out->adnl_addrs_.push_back(make_tos_api_engine_validatoradnladdress(length));
  out->election_date_ = 3;
  out->expire_at_ = 3;
  return out;
}
auto make_tos_api_engine_validator_addadnlid(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_addAdnlId> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_addAdnlId>();
  out->key_hash_ = bits(19);
  out->category_ = 2;
  return out;
}
auto make_tos_api_engine_validator_addcollator(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_addCollator> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_addCollator>();
  out->adnl_id_ = bits(8);
  out->shard_ = make_tos_api_tosnode_shardid(length);
  return out;
}
auto make_tos_api_engine_validator_addcustomoverlay(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_addCustomOverlay> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_addCustomOverlay>();
  out->overlay_ = make_tos_api_engine_validator_customoverlay(length);
  return out;
}
auto make_tos_api_engine_validator_addliteserver(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_addLiteserver> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_addLiteserver>();
  out->key_hash_ = bits(19);
  out->port_ = 6;
  return out;
}
auto make_tos_api_engine_validator_addquicaddr(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_addQuicAddr> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_addQuicAddr>();
  out->ip_ = 1;
  out->port_ = 6;
  out->categories_.push_back(6);
  out->priority_categories_.push_back(5);
  return out;
}
auto make_tos_api_engine_validator_addvalidatoradnladdress(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_addValidatorAdnlAddress> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_addValidatorAdnlAddress>();
  out->permanent_key_hash_ = bits(22);
  out->key_hash_ = bits(19);
  out->ttl_ = 5;
  return out;
}
auto make_tos_api_engine_validator_addvalidatorpermanentkey(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_addValidatorPermanentKey> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_addValidatorPermanentKey>();
  out->key_hash_ = bits(19);
  out->election_date_ = 3;
  out->ttl_ = 5;
  return out;
}
auto make_tos_api_engine_validator_addvalidatortempkey(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_addValidatorTempKey> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_addValidatorTempKey>();
  out->permanent_key_hash_ = bits(22);
  out->key_hash_ = bits(19);
  out->ttl_ = 5;
  return out;
}
auto make_tos_api_engine_validator_clearcollatorslist(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_clearCollatorsList> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_clearCollatorsList>();

  return out;
}
auto make_tos_api_engine_validator_collatornodesetwhitelistenabled(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_collatorNodeSetWhitelistEnabled> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_collatorNodeSetWhitelistEnabled>();
  out->enabled_ = false;
  return out;
}
auto make_tos_api_engine_validator_collatornodesetwhitelistedvalidator(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_collatorNodeSetWhitelistedValidator> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_collatorNodeSetWhitelistedValidator>();
  out->adnl_id_ = bits(8);
  out->add_ = true;
  return out;
}
auto make_tos_api_engine_validator_collatornodewhitelist(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_collatorNodeWhitelist> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_collatorNodeWhitelist>();
  out->enabled_ = false;
  out->adnl_ids_.push_back(bits(5));
  return out;
}
auto make_tos_api_engine_validator_collatoroptions(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_collatorOptions> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_collatorOptions>();
  out->deferring_enabled_ = false;
  out->defer_messages_after_ = 2;
  out->defer_out_queue_size_limit_ = std::int64_t{6};
  out->dispatch_phase_2_max_total_ = 1;
  out->dispatch_phase_3_max_total_ = 2;
  out->dispatch_phase_2_max_per_initiator_ = 7;
  out->dispatch_phase_3_max_per_initiator_ = 1;
  out->whitelist_.push_back(std::string("wire-fixture"));
  out->prioritylist_.push_back(std::string("wire-fixture"));
  out->force_full_collated_data_ = false;
  out->ignore_collated_data_limits_ = false;
  return out;
}
auto make_tos_api_engine_validator_collatorslist(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_collatorsList> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_collatorsList>();
  out->shards_.push_back(make_tos_api_engine_validator_collatorslist_shard(length));
  return out;
}
auto make_tos_api_engine_validator_collatorslist_collator(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_collatorsList_collator> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_collatorsList_collator>();
  out->adnl_id_ = bits(8);
  return out;
}
auto make_tos_api_engine_validator_collatorslist_shard(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_collatorsList_shard> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_collatorsList_shard>();
  out->shard_id_ = make_tos_api_tosnode_shardid(length);
  out->collators_.push_back(make_tos_api_engine_validator_collatorslist_collator(length));
  out->self_collate_ = true;
  out->select_mode_ = std::string("wire-fixture");
  return out;
}
auto make_tos_api_engine_validator_config(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_config> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_config>();
  out->out_port_ = 4;
  out->addrs_.push_back(make_tos_api_engine_quicaddr(length));
  out->adnl_.push_back(make_tos_api_engine_adnl(length));
  out->dht_.push_back(make_tos_api_engine_dht(length));
  out->validators_.push_back(make_tos_api_engine_validator(length));
  out->collators_.push_back(make_tos_api_engine_collator(length));
  out->fullnode_ = bits(32);
  out->fullnodeslaves_.push_back(make_tos_api_engine_validator_fullnodeslave(length));
  out->fullnodemasters_.push_back(make_tos_api_engine_validator_fullnodemaster(length));
  out->fullnodeconfig_ = make_tos_api_engine_validator_fullnodeconfig(length);
  out->extraconfig_ = make_tos_api_engine_validator_extraconfig(length);
  out->liteservers_.push_back(make_tos_api_engine_liteserver(length));
  out->control_.push_back(make_tos_api_engine_controlinterface(length));
  out->shards_to_monitor_.push_back(make_tos_api_tosnode_shardid(length));
  out->gc_ = make_tos_api_engine_gc(length);
  return out;
}
auto make_tos_api_engine_validator_configproposaldetail(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_configProposalDetail> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_configProposalDetail>();
  out->flags_ = 0;
  out->block_ = make_tos_api_tosnode_blockidext(length);
  return out;
}
auto make_tos_api_engine_validator_configproposalmeta(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_configProposalMeta> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_configProposalMeta>();
  out->flags_ = 0;
  out->hash_ = bits(8);
  out->expires_ = 6;
  out->critical_ = false;
  out->param_id_ = 4;
  out->has_value_ = true;
  out->vset_id_ = bits(43);
  out->voters_.push_back(4);
  out->weight_remaining_ = std::int64_t{4};
  out->rounds_remaining_ = 2;
  out->wins_ = 2;
  out->losses_ = 1;
  return out;
}
auto make_tos_api_engine_validator_configproposals(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_configProposals> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_configProposals>();
  out->block_ = make_tos_api_tosnode_blockidext(length);
  out->proposals_.push_back(make_tos_api_engine_validator_configproposalmeta(length));
  return out;
}
auto make_tos_api_engine_validator_controlqueryerror(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_controlQueryError> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_controlQueryError>();
  out->code_ = 6;
  out->message_ = std::string("wire-fixture");
  return out;
}
auto make_tos_api_engine_validator_createpqstakeauthorization(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_createPqStakeAuthorization> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_createPqStakeAuthorization>();
  out->election_date_ = 3;
  out->max_factor_ = 4;
  out->adnl_addr_ = bits(37);
  out->src_addr_ = bits(7);
  return out;
}
auto make_tos_api_engine_validator_customoverlay(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_customOverlay> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_customOverlay>();
  out->name_ = std::string("wire-fixture");
  out->nodes_.push_back(make_tos_api_engine_validator_customoverlaynode(length));
  out->sender_shards_.push_back(make_tos_api_tosnode_shardid(length));
  out->skip_public_msg_send_ = false;
  out->use_quic_ = true;
  return out;
}
auto make_tos_api_engine_validator_customoverlaynode(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_customOverlayNode> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_customOverlayNode>();
  out->adnl_id_ = bits(8);
  out->msg_sender_ = false;
  out->msg_sender_priority_ = 6;
  out->block_sender_ = true;
  return out;
}
auto make_tos_api_engine_validator_customoverlaysconfig(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_customOverlaysConfig> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_customOverlaysConfig>();
  out->overlays_.push_back(make_tos_api_engine_validator_customoverlay(length));
  return out;
}
auto make_tos_api_engine_validator_delcollator(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_delCollator> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_delCollator>();
  out->adnl_id_ = bits(8);
  out->shard_ = make_tos_api_tosnode_shardid(length);
  return out;
}
auto make_tos_api_engine_validator_delcustomoverlay(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_delCustomOverlay> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_delCustomOverlay>();
  out->name_ = std::string("wire-fixture");
  return out;
}
auto make_tos_api_engine_validator_electionparticipant(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_electionParticipant> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_electionParticipant>();
  out->id_ = bits(29);
  out->stake_ = td::BufferSlice(std::string(length, char(6)));
  out->max_factor_ = 4;
  out->adnl_ = bits(3);
  out->algorithm_ = 2;
  out->key_id_ = bits(40);
  return out;
}
auto make_tos_api_engine_validator_electorstate(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_electorState> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_electorState>();
  out->block_ = make_tos_api_tosnode_blockidext(length);
  out->elect_at_ = 1;
  out->elect_close_ = 7;
  out->min_stake_ = td::BufferSlice(std::string(length, char(12)));
  out->total_stake_ = td::BufferSlice(std::string(length, char(59)));
  out->failed_ = false;
  out->finished_ = true;
  out->participants_.push_back(make_tos_api_engine_validator_electionparticipant(length));
  out->past_elections_.push_back(make_tos_api_engine_validator_pastelection(length));
  out->returned_.push_back(make_tos_api_engine_validator_returnedstake(length));
  return out;
}
auto make_tos_api_engine_validator_exportpublickey(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_exportPublicKey> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_exportPublicKey>();
  out->key_hash_ = bits(19);
  return out;
}
auto make_tos_api_engine_validator_extmessagepoolconfig(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_extMessagePoolConfig> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_extMessagePoolConfig>();
  out->max_mempool_messages_ = 6;
  out->num_regular_checkers_ = 7;
  out->num_priority_checkers_ = 4;
  out->max_admission_waiters_ = 4;
  out->max_ext_msg_per_addr_ = 2;
  out->max_ext_msg_per_addr_time_window_ = 2.9375;
  out->local_ls_message_priority_ = 4;
  return out;
}
auto make_tos_api_engine_validator_extraconfig(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_extraConfig> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_extraConfig>();
  out->state_serializer_enabled_ = true;
  out->fast_sync_member_certificates_.push_back(make_tos_api_engine_validator_fastsyncmembercertificate(length));
  out->collator_node_whitelist_ = make_tos_api_engine_validator_collatornodewhitelist(length);
  out->fast_sync_overlay_clients_.push_back(make_tos_api_engine_validator_fastsyncoverlayclient(length));
  out->ext_message_pool_config_ = make_tos_api_engine_validator_extmessagepoolconfig(length);
  out->pq_consensus_ = make_tos_api_engine_validator_pqconsensus(length);
  return out;
}
auto make_tos_api_engine_validator_fastsyncmembercertificate(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_fastSyncMemberCertificate> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_fastSyncMemberCertificate>();
  out->adnl_id_ = bits(8);
  out->certificate_ = make_tos_api_overlay_membercertificate(length);
  return out;
}
auto make_tos_api_engine_validator_fastsyncoverlayclient(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_fastSyncOverlayClient> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_fastSyncOverlayClient>();
  out->adnl_id_ = bits(8);
  out->slot_ = 3;
  return out;
}
auto make_tos_api_engine_validator_frozenstake(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_frozenStake> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_frozenStake>();
  out->id_ = bits(29);
  out->owner_ = bits(25);
  out->weight_ = std::int64_t{5};
  out->stake_ = td::BufferSlice(std::string(length, char(6)));
  out->banned_ = true;
  return out;
}
auto make_tos_api_engine_validator_fullnodeconfig(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_fullNodeConfig> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_fullNodeConfig>();
  out->ext_messages_broadcast_disabled_ = true;
  return out;
}
auto make_tos_api_engine_validator_fullnodemaster(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_fullNodeMaster> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_fullNodeMaster>();
  out->port_ = 6;
  out->adnl_ = bits(3);
  return out;
}
auto make_tos_api_engine_validator_fullnodeslave(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_fullNodeSlave> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_fullNodeSlave>();
  out->ip_ = 1;
  out->port_ = 6;
  out->adnl_ = make_tos_api_pub_ed25519(length);
  return out;
}
auto make_tos_api_engine_validator_generatekeypair(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_generateKeyPair> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_generateKeyPair>();

  return out;
}
auto make_tos_api_engine_validator_getcollatoroptionsjson(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_getCollatorOptionsJson> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_getCollatorOptionsJson>();

  return out;
}
auto make_tos_api_engine_validator_getconfig(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_getConfig> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_getConfig>();

  return out;
}
auto make_tos_api_engine_validator_getconfigproposal(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_getConfigProposal> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_getConfigProposal>();
  out->flags_ = 0;
  out->hash_ = bits(8);
  return out;
}
auto make_tos_api_engine_validator_getconfigproposals(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_getConfigProposals> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_getConfigProposals>();
  out->flags_ = 0;
  return out;
}
auto make_tos_api_engine_validator_getelectorstate(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_getElectorState> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_getElectorState>();
  out->flags_ = 0;
  out->wallets_.push_back(bits(57));
  return out;
}
auto make_tos_api_engine_validator_getstats(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_getStats> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_getStats>();

  return out;
}
auto make_tos_api_engine_validator_gettime(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_getTime> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_getTime>();

  return out;
}
auto make_tos_api_engine_validator_jsonconfig(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_jsonConfig> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_jsonConfig>();
  out->data_ = std::string("wire-fixture");
  return out;
}
auto make_tos_api_engine_validator_keyhash(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_keyHash> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_keyHash>();
  out->key_hash_ = bits(19);
  return out;
}
auto make_tos_api_engine_validator_onestat(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_oneStat> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_oneStat>();
  out->key_ = std::string("wire-fixture");
  out->value_ = std::string("wire-fixture");
  return out;
}
auto make_tos_api_engine_validator_overlaystats(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_overlayStats> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_overlayStats>();
  out->overlay_id_ = bits(9);
  out->overlay_id_full_ = make_tos_api_pub_ed25519(length);
  out->adnl_id_ = bits(8);
  out->scope_ = std::string("wire-fixture");
  out->nodes_.push_back(make_tos_api_engine_validator_overlaystatsnode(length));
  out->stats_.push_back(make_tos_api_engine_validator_onestat(length));
  out->total_traffic_ = make_tos_api_engine_validator_overlaystatstraffic(length);
  out->total_traffic_responses_ = make_tos_api_engine_validator_overlaystatstraffic(length);
  out->broadcasts_.push_back(make_tos_api_engine_validator_overlaystatsbroadcasts(length));
  out->extra_ = std::string("wire-fixture");
  return out;
}
auto make_tos_api_engine_validator_overlaystatsbroadcasts(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_overlayStatsBroadcasts> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_overlayStatsBroadcasts>();
  out->source_ = bits(9);
  out->ts_start_ = 4.6875;
  out->ts_end_ = 4.0;
  out->count_ = std::int64_t{1};
  out->total_size_ = std::int64_t{2};
  out->total_out_traffic_ = std::int64_t{5};
  return out;
}
auto make_tos_api_engine_validator_overlaystatsnode(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_overlayStatsNode> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_overlayStatsNode>();
  out->adnl_id_ = bits(8);
  out->ip_addr_ = std::string("wire-fixture");
  out->is_neighbour_ = false;
  out->is_alive_ = true;
  out->node_flags_ = 7;
  out->bdcst_errors_ = 5;
  out->fec_bdcst_errors_ = 3;
  out->last_in_query_ = 1;
  out->last_out_query_ = 4;
  out->traffic_ = make_tos_api_engine_validator_overlaystatstraffic(length);
  out->traffic_responses_ = make_tos_api_engine_validator_overlaystatstraffic(length);
  out->last_ping_at_ = 2.9375;
  out->last_ping_time_ = 1.8125;
  return out;
}
auto make_tos_api_engine_validator_overlaystatstraffic(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_overlayStatsTraffic> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_overlayStatsTraffic>();
  out->t_out_bytes_ = std::int64_t{5};
  out->t_in_bytes_ = std::int64_t{2};
  out->t_out_pckts_ = 3;
  out->t_in_pckts_ = 7;
  return out;
}
auto make_tos_api_engine_validator_pastelection(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_pastElection> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_pastElection>();
  out->election_id_ = 4;
  out->unfreeze_at_ = 1;
  out->stake_held_ = 2;
  out->vset_hash_ = bits(22);
  out->total_stake_ = td::BufferSlice(std::string(length, char(59)));
  out->bonuses_ = td::BufferSlice(std::string(length, char(1)));
  out->frozen_.push_back(make_tos_api_engine_validator_frozenstake(length));
  return out;
}
auto make_tos_api_engine_validator_pqconsensus(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_pqConsensus> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_pqConsensus>();
  out->validator_id_ = bits(28);
  out->consensus_key_file_ = std::string("wire-fixture");
  out->keys_.push_back(make_tos_api_engine_validator_pqconsensuskey(length));
  return out;
}
auto make_tos_api_engine_validator_pqconsensuskey(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_pqConsensusKey> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_pqConsensusKey>();
  out->consensus_key_file_ = std::string("wire-fixture");
  out->valid_from_ = 3;
  out->expire_at_ = 3;
  return out;
}
auto make_tos_api_engine_validator_returnedstake(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_returnedStake> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_returnedStake>();
  out->wallet_ = bits(1);
  out->amount_ = td::BufferSlice(std::string(length, char(12)));
  return out;
}
auto make_tos_api_engine_validator_setcollatoroptionsjson(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_setCollatorOptionsJson> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_setCollatorOptionsJson>();
  out->json_ = std::string("wire-fixture");
  return out;
}
auto make_tos_api_engine_validator_shardblockverifierconfig_shard(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_shardBlockVerifierConfig_shard> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_shardBlockVerifierConfig_shard>();
  out->shard_id_ = make_tos_api_tosnode_shardid(length);
  out->trusted_nodes_.push_back(bits(55));
  out->required_confirms_ = 6;
  return out;
}
auto make_tos_api_engine_validator_showcollatornodewhitelist(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_showCollatorNodeWhitelist> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_showCollatorNodeWhitelist>();

  return out;
}
auto make_tos_api_engine_validator_showcollatorslist(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_showCollatorsList> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_showCollatorsList>();

  return out;
}
auto make_tos_api_engine_validator_showcustomoverlays(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_showCustomOverlays> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_showCustomOverlays>();

  return out;
}
auto make_tos_api_engine_validator_sign(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_sign> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_sign>();
  out->key_hash_ = bits(19);
  out->data_ = td::BufferSlice(std::string(length, char(57)));
  return out;
}
auto make_tos_api_engine_validator_signature(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_signature> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_signature>();
  out->signature_ = td::BufferSlice(std::string(length, char(35)));
  return out;
}
auto make_tos_api_engine_validator_stats(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_stats> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_stats>();
  out->stats_.push_back(make_tos_api_engine_validator_onestat(length));
  return out;
}
auto make_tos_api_engine_validator_success(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_success> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_success>();

  return out;
}
auto make_tos_api_engine_validator_time(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validator_time> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validator_time>();
  out->time_ = 5;
  return out;
}
auto make_tos_api_engine_validatoradnladdress(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validatorAdnlAddress> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validatorAdnlAddress>();
  out->id_ = bits(29);
  out->expire_at_ = 3;
  return out;
}
auto make_tos_api_engine_validatortempkey(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::engine_validatorTempKey> {
  auto out = tos::tos_api::make_object<tos::tos_api::engine_validatorTempKey>();
  out->key_ = bits(35);
  out->expire_at_ = 3;
  return out;
}
auto make_tos_api_liteserver_desc(std::size_t length) -> tos::tos_api::object_ptr<tos::tos_api::liteserver_desc> {
  auto out = tos::tos_api::make_object<tos::tos_api::liteserver_desc>();
  out->id_ = make_tos_api_pub_ed25519(length);
  out->ip_ = 1;
  out->port_ = 6;
  out->hostname_ = std::string("wire-fixture");
  return out;
}
auto make_tos_api_liteserver_descv2(std::size_t length) -> tos::tos_api::object_ptr<tos::tos_api::liteserver_descV2> {
  auto out = tos::tos_api::make_object<tos::tos_api::liteserver_descV2>();
  out->id_ = make_tos_api_pub_ed25519(length);
  out->ip_ = 1;
  out->port_ = 6;
  out->hostname_ = std::string("wire-fixture");
  out->slices_.push_back(make_tos_api_liteserver_descv2_slicesimple(length));
  return out;
}
auto make_tos_api_liteserver_descv2_slicesimple(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::liteserver_descV2_sliceSimple> {
  auto out = tos::tos_api::make_object<tos::tos_api::liteserver_descV2_sliceSimple>();
  out->shards_.push_back(make_tos_api_tosnode_shardid(length));
  return out;
}
auto make_tos_api_overlay_membercertificate(std::size_t length)
    -> tos::tos_api::object_ptr<tos::tos_api::overlay_memberCertificate> {
  auto out = tos::tos_api::make_object<tos::tos_api::overlay_memberCertificate>();
  out->issued_by_ = make_tos_api_pub_ed25519(length);
  out->flags_ = 1;
  out->slot_ = 3;
  out->expire_at_ = 3;
  out->signature_ = td::BufferSlice(std::string(length, char(35)));
  return out;
}
auto make_tos_api_pub_ed25519(std::size_t length) -> tos::tos_api::object_ptr<tos::tos_api::pub_ed25519> {
  auto out = tos::tos_api::make_object<tos::tos_api::pub_ed25519>();
  out->key_ = bits(35);
  return out;
}
auto make_tos_api_tosnode_blockidext(std::size_t length) -> tos::tos_api::object_ptr<tos::tos_api::tosNode_blockIdExt> {
  auto out = tos::tos_api::make_object<tos::tos_api::tosNode_blockIdExt>();
  out->workchain_ = -1;
  out->shard_ = std::numeric_limits<std::int64_t>::min();
  out->seqno_ = 7;
  out->root_hash_ = bits(31);
  out->file_hash_ = bits(37);
  return out;
}
auto make_tos_api_tosnode_shardid(std::size_t length) -> tos::tos_api::object_ptr<tos::tos_api::tosNode_shardId> {
  auto out = tos::tos_api::make_object<tos::tos_api::tosNode_shardId>();
  out->workchain_ = -1;
  out->shard_ = std::numeric_limits<std::int64_t>::min();
  return out;
}
auto make_toslib_api_raw_extmessageinfo(std::size_t length)
    -> tos::toslib_api::object_ptr<tos::toslib_api::raw_extMessageInfo> {
  auto out = tos::toslib_api::make_object<tos::toslib_api::raw_extMessageInfo>();
  out->hash_ = std::string(length, char(8));
  out->hash_norm_ = std::string(length, char(16));
  return out;
}
template <class T>
td::BufferSlice encode(const T &object) {
  constexpr bool function =
      std::is_base_of_v<tos::tos_api::Function, T> || std::is_base_of_v<tos::lite_api::Function, T>;
  td::TlStorerCalcLength length;
  if constexpr (!function)
    length.store_int(T::ID);
  object.store(length);
  td::BufferSlice bytes(length.get_length());
  td::TlStorerUnsafe writer(bytes.as_slice().ubegin());
  if constexpr (!function)
    writer.store_int(T::ID);
  object.store(writer);
  return bytes;
}
// This public API exposes JSON records; use the native primitive TL codecs for its two byte fields.
template <>
td::BufferSlice encode(const tos::toslib_api::raw_extMessageInfo &object) {
  td::TlStorerCalcLength length;
  length.store_int(object.ID);
  length.store_string(object.hash_);
  length.store_string(object.hash_norm_);
  td::BufferSlice bytes(length.get_length());
  td::TlStorerUnsafe writer(bytes.as_slice().ubegin());
  writer.store_int(object.ID);
  writer.store_string(object.hash_);
  writer.store_string(object.hash_norm_);
  return bytes;
}
struct Case {
  std::string name;
  std::string wire;
  std::function<bool(td::Slice)> verify;
};
std::vector<Case> cases() {
  std::vector<Case> result;
  auto add = [&](const std::string &name, auto object) {
    using T = std::remove_reference_t<decltype(*object)>;
    auto wire = encode(*object).as_slice().str();
    auto verify = [expected = wire](td::Slice bytes) {
      if constexpr (std::is_same_v<T, tos::toslib_api::raw_extMessageInfo>) {
        td::TlParser parser(bytes);
        const auto id = parser.fetch_int();
        const auto hash = parser.fetch_string<std::string>();
        const auto normalized = parser.fetch_string<std::string>();
        parser.fetch_end();
        return id == T::ID && parser.get_status().is_ok() &&
               encode(tos::toslib_api::raw_extMessageInfo(hash, normalized)).as_slice() == td::Slice(expected);
      } else {
        auto parsed = tos::fetch_tl_object<T>(td::BufferSlice(bytes), true);
        return parsed.is_ok() && encode(*parsed.ok()).as_slice() == td::Slice(expected);
      }
    };
    if (!verify(wire))
      throw std::runtime_error("native fixture does not round trip: " + name);
    result.push_back(Case{name, std::move(wire), std::move(verify)});
  };
  add("engine.validator.getElectorState", make_tos_api_engine_validator_getelectorstate(16));
  add("engine.validator.getConfigProposals", make_tos_api_engine_validator_getconfigproposals(16));
  add("engine.validator.getConfigProposal", make_tos_api_engine_validator_getconfigproposal(16));
  add("liteServer.getConfigAll", make_lite_api_liteserver_getconfigall(16));
  add("engine.validator.getConfig", make_tos_api_engine_validator_getconfig(16));
  add("liteServer.getConfigParams", make_lite_api_liteserver_getconfigparams(16));
  add("engine.validator.sign", make_tos_api_engine_validator_sign(16));
  add("engine.validator.createPqStakeAuthorization", make_tos_api_engine_validator_createpqstakeauthorization(16));
  add("engine.validator.generateKeyPair", make_tos_api_engine_validator_generatekeypair(16));
  add("engine.validator.exportPublicKey", make_tos_api_engine_validator_exportpublickey(16));
  add("engine.validator.addValidatorPermanentKey", make_tos_api_engine_validator_addvalidatorpermanentkey(16));
  add("engine.validator.addValidatorTempKey", make_tos_api_engine_validator_addvalidatortempkey(16));
  add("engine.validator.addAdnlId", make_tos_api_engine_validator_addadnlid(16));
  add("engine.validator.addValidatorAdnlAddress", make_tos_api_engine_validator_addvalidatoradnladdress(16));
  add("liteServer.sendMessage", make_lite_api_liteserver_sendmessage(16));
  add("engine.validator.getTime", make_tos_api_engine_validator_gettime(16));
  add("engine.validator.showCollatorsList", make_tos_api_engine_validator_showcollatorslist(16));
  add("engine.validator.showCollatorNodeWhitelist", make_tos_api_engine_validator_showcollatornodewhitelist(16));
  add("engine.validator.getCollatorOptionsJson", make_tos_api_engine_validator_getcollatoroptionsjson(16));
  add("engine.validator.setCollatorOptionsJson", make_tos_api_engine_validator_setcollatoroptionsjson(16));
  add("engine.validator.addCollator", make_tos_api_engine_validator_addcollator(16));
  add("engine.validator.delCollator", make_tos_api_engine_validator_delcollator(16));
  add("engine.validator.clearCollatorsList", make_tos_api_engine_validator_clearcollatorslist(16));
  add("engine.validator.collatorNodeSetWhitelistedValidator",
      make_tos_api_engine_validator_collatornodesetwhitelistedvalidator(16));
  add("engine.validator.collatorNodeSetWhitelistEnabled",
      make_tos_api_engine_validator_collatornodesetwhitelistenabled(16));
  add("engine.validator.getStats", make_tos_api_engine_validator_getstats(16));
  add("engine.validator.addQuicAddr", make_tos_api_engine_validator_addquicaddr(16));
  add("engine.validator.addLiteserver", make_tos_api_engine_validator_addliteserver(16));
  add("engine.validator.addCustomOverlay", make_tos_api_engine_validator_addcustomoverlay(16));
  add("engine.validator.delCustomOverlay", make_tos_api_engine_validator_delcustomoverlay(16));
  add("engine.validator.showCustomOverlays", make_tos_api_engine_validator_showcustomoverlays(16));
  add("adnl.stats.localId", make_tos_api_adnl_stats_localid(16));
  add("engine.validator.collatorOptions", make_tos_api_engine_validator_collatoroptions(16));
  add("engine.validator.config", make_tos_api_engine_validator_config(16));
  add("engine.validator.extraConfig", make_tos_api_engine_validator_extraconfig(16));
  add("engine.validator.overlayStats", make_tos_api_engine_validator_overlaystats(16));
  add("engine.validator.overlayStatsNode", make_tos_api_engine_validator_overlaystatsnode(16));
  add("liteserver.desc", make_tos_api_liteserver_desc(16));
  add("liteserver.descV2", make_tos_api_liteserver_descv2(16));
  add("raw.extMessageInfo", make_toslib_api_raw_extmessageinfo(16));
  add("engine.validator.shardBlockVerifierConfig.shard",
      make_tos_api_engine_validator_shardblockverifierconfig_shard(16));
  add("engine.validator.controlQueryError", make_tos_api_engine_validator_controlqueryerror(16));
  add("engine.validator.time", make_tos_api_engine_validator_time(16));
  add("engine.validator.signature", make_tos_api_engine_validator_signature(16));
  add("engine.validator.keyHash", make_tos_api_engine_validator_keyhash(16));
  add("engine.validator.jsonConfig", make_tos_api_engine_validator_jsonconfig(16));
  add("engine.validator.success", make_tos_api_engine_validator_success(16));
  add("engine.validator.stats", make_tos_api_engine_validator_stats(16));
  add("engine.validator.collatorsList", make_tos_api_engine_validator_collatorslist(16));
  add("engine.validator.collatorNodeWhitelist", make_tos_api_engine_validator_collatornodewhitelist(16));
  add("engine.validator.customOverlaysConfig", make_tos_api_engine_validator_customoverlaysconfig(16));
  add("engine.validator.electorState", make_tos_api_engine_validator_electorstate(16));
  add("engine.validator.configProposals", make_tos_api_engine_validator_configproposals(16));
  add("engine.validator.configProposalDetail", make_tos_api_engine_validator_configproposaldetail(16));
  {
    auto query = make_tos_api_engine_validator_getelectorstate(16);
    query->flags_ = 1;
    query->block_ = make_tos_api_tosnode_blockidext(16);
    add("engine.validator.getElectorState/with-block", std::move(query));
  }
  {
    auto query = make_tos_api_engine_validator_getconfigproposals(16);
    query->flags_ = 1;
    query->block_ = make_tos_api_tosnode_blockidext(16);
    add("engine.validator.getConfigProposals/with-block", std::move(query));
  }
  {
    auto query = make_tos_api_engine_validator_getconfigproposal(16);
    query->flags_ = 1;
    query->block_ = make_tos_api_tosnode_blockidext(16);
    add("engine.validator.getConfigProposal/with-block", std::move(query));
  }
  add("control/engine.validator.getElectorState",
      tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
          encode(*make_tos_api_engine_validator_getelectorstate(16))));
  add("control/engine.validator.getConfigProposals",
      tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
          encode(*make_tos_api_engine_validator_getconfigproposals(16))));
  add("control/engine.validator.getConfigProposal",
      tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
          encode(*make_tos_api_engine_validator_getconfigproposal(16))));
  add("control/liteServer.getConfigAll", tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
                                             encode(*make_lite_api_liteserver_getconfigall(16))));
  add("control/engine.validator.getConfig", tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
                                                encode(*make_tos_api_engine_validator_getconfig(16))));
  add("control/liteServer.getConfigParams", tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
                                                encode(*make_lite_api_liteserver_getconfigparams(16))));
  add("control/engine.validator.sign", tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
                                           encode(*make_tos_api_engine_validator_sign(16))));
  add("control/engine.validator.createPqStakeAuthorization",
      tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
          encode(*make_tos_api_engine_validator_createpqstakeauthorization(16))));
  add("control/engine.validator.generateKeyPair",
      tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
          encode(*make_tos_api_engine_validator_generatekeypair(16))));
  add("control/engine.validator.exportPublicKey",
      tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
          encode(*make_tos_api_engine_validator_exportpublickey(16))));
  add("control/engine.validator.addValidatorPermanentKey",
      tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
          encode(*make_tos_api_engine_validator_addvalidatorpermanentkey(16))));
  add("control/engine.validator.addValidatorTempKey",
      tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
          encode(*make_tos_api_engine_validator_addvalidatortempkey(16))));
  add("control/engine.validator.addAdnlId", tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
                                                encode(*make_tos_api_engine_validator_addadnlid(16))));
  add("control/engine.validator.addValidatorAdnlAddress",
      tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
          encode(*make_tos_api_engine_validator_addvalidatoradnladdress(16))));
  add("control/liteServer.sendMessage", tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
                                            encode(*make_lite_api_liteserver_sendmessage(16))));
  add("control/engine.validator.getTime", tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
                                              encode(*make_tos_api_engine_validator_gettime(16))));
  add("control/engine.validator.showCollatorsList",
      tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
          encode(*make_tos_api_engine_validator_showcollatorslist(16))));
  add("control/engine.validator.showCollatorNodeWhitelist",
      tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
          encode(*make_tos_api_engine_validator_showcollatornodewhitelist(16))));
  add("control/engine.validator.getCollatorOptionsJson",
      tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
          encode(*make_tos_api_engine_validator_getcollatoroptionsjson(16))));
  add("control/engine.validator.setCollatorOptionsJson",
      tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
          encode(*make_tos_api_engine_validator_setcollatoroptionsjson(16))));
  add("control/engine.validator.addCollator", tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
                                                  encode(*make_tos_api_engine_validator_addcollator(16))));
  add("control/engine.validator.delCollator", tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
                                                  encode(*make_tos_api_engine_validator_delcollator(16))));
  add("control/engine.validator.clearCollatorsList",
      tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
          encode(*make_tos_api_engine_validator_clearcollatorslist(16))));
  add("control/engine.validator.collatorNodeSetWhitelistedValidator",
      tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
          encode(*make_tos_api_engine_validator_collatornodesetwhitelistedvalidator(16))));
  add("control/engine.validator.collatorNodeSetWhitelistEnabled",
      tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
          encode(*make_tos_api_engine_validator_collatornodesetwhitelistenabled(16))));
  add("control/engine.validator.getStats", tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
                                               encode(*make_tos_api_engine_validator_getstats(16))));
  add("control/engine.validator.addQuicAddr", tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
                                                  encode(*make_tos_api_engine_validator_addquicaddr(16))));
  add("control/engine.validator.addLiteserver", tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
                                                    encode(*make_tos_api_engine_validator_addliteserver(16))));
  add("control/engine.validator.addCustomOverlay",
      tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
          encode(*make_tos_api_engine_validator_addcustomoverlay(16))));
  add("control/engine.validator.delCustomOverlay",
      tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
          encode(*make_tos_api_engine_validator_delcustomoverlay(16))));
  add("control/engine.validator.showCustomOverlays",
      tos::tos_api::make_object<tos::tos_api::engine_validator_controlQuery>(
          encode(*make_tos_api_engine_validator_showcustomoverlays(16))));
  add("engine.validator.sign/bytes-0", make_tos_api_engine_validator_sign(0));
  add("engine.validator.sign/bytes-1", make_tos_api_engine_validator_sign(1));
  add("engine.validator.sign/bytes-253", make_tos_api_engine_validator_sign(253));
  add("engine.validator.sign/bytes-254", make_tos_api_engine_validator_sign(254));
  add("engine.validator.sign/bytes-255", make_tos_api_engine_validator_sign(255));
  add("liteServer.sendMessage/bytes-0", make_lite_api_liteserver_sendmessage(0));
  add("liteServer.sendMessage/bytes-1", make_lite_api_liteserver_sendmessage(1));
  add("liteServer.sendMessage/bytes-253", make_lite_api_liteserver_sendmessage(253));
  add("liteServer.sendMessage/bytes-254", make_lite_api_liteserver_sendmessage(254));
  add("liteServer.sendMessage/bytes-255", make_lite_api_liteserver_sendmessage(255));
  return result;
}
}  // namespace
int main(int argc, char **argv) {
  try {
    const auto expected = cases();
    if (argc == 1) {
      for (const auto &item : expected)
        std::cout << item.name << '\t' << td::hex_encode(item.wire) << '\n';
      return 0;
    }
    if (argc != 3 || std::string(argv[1]) != "--verify")
      return 2;
    std::ifstream input(argv[2], std::ios::binary);
    if (!input)
      return 2;
    // Read at most the limit plus one byte, including when the file grows concurrently.
    std::string contents(1024 * 1024 + 1, '\0');
    input.read(contents.data(), static_cast<std::streamsize>(contents.size()));
    if (input.bad() || input.gcount() > 1024 * 1024)
      return 2;
    contents.resize(static_cast<std::size_t>(input.gcount()));
    std::istringstream records(contents);
    std::map<std::string, const Case *> names;
    for (const auto &item : expected)
      names.emplace(item.name, &item);
    std::string line;
    std::size_t count = 0;
    while (std::getline(records, line)) {
      const auto split = line.find('\t');
      if (split == std::string::npos || line.size() > 32768)
        return 1;
      const auto found = names.find(line.substr(0, split));
      if (found == names.end())
        return 1;
      auto bytes = td::hex_decode(line.substr(split + 1));
      if (bytes.is_error() || !found->second->verify(bytes.ok()))
        return 1;
      names.erase(found);
      ++count;
    }
    if (!names.empty() || count != expected.size())
      return 1;
    std::cout << "CPP_CLI_WIRE_OK " << count << '\n';
    return 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
