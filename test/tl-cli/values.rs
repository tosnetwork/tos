#![allow(unused_variables)]
// Explicit typed values are the field oracle for the native-produced fixtures.
use tl_api::IntoBoxed;
pub(crate) fn make_lite_api_liteserver_getconfigall(
    length: usize,
) -> tl_api::tos::rpc::lite_server::GetConfigAll {
    tl_api::tos::rpc::lite_server::GetConfigAll { mode: 0, id: chain_block::BlockIdExt::default() }
}
pub(crate) fn make_lite_api_liteserver_getconfigparams(
    length: usize,
) -> tl_api::tos::rpc::lite_server::GetConfigParams {
    tl_api::tos::rpc::lite_server::GetConfigParams {
        mode: 0,
        id: chain_block::BlockIdExt::default(),
        param_list: vec![5],
    }
}
pub(crate) fn make_lite_api_liteserver_sendmessage(
    length: usize,
) -> tl_api::tos::rpc::lite_server::SendMessage {
    tl_api::tos::rpc::lite_server::SendMessage { body: vec![18; length] }
}
pub(crate) fn make_tos_api_adnl_stats_ippackets(
    length: usize,
) -> tl_api::tos::adnl::stats::ippackets::IpPackets {
    tl_api::tos::adnl::stats::ippackets::IpPackets {
        ip_str: "wire-fixture".to_string(),
        packets: 6,
    }
}
pub(crate) fn make_tos_api_adnl_stats_localid(
    length: usize,
) -> tl_api::tos::adnl::stats::localid::LocalId {
    tl_api::tos::adnl::stats::localid::LocalId {
        short_id: chain_block::UInt256::with_array([35; 32]),
        current_decrypt: vec![make_tos_api_adnl_stats_ippackets(length)],
        packets_recent: make_tos_api_adnl_stats_localidpackets(length),
        peers: vec![make_tos_api_adnl_stats_peerpair(length)],
    }
}
pub(crate) fn make_tos_api_adnl_stats_localidpackets(
    length: usize,
) -> tl_api::tos::adnl::stats::localidpackets::LocalIdPackets {
    tl_api::tos::adnl::stats::localidpackets::LocalIdPackets {
        ts_start: 4.6875.into(),
        ts_end: 4.0.into(),
        decrypted_packets: vec![make_tos_api_adnl_stats_ippackets(length)],
        dropped_packets: vec![make_tos_api_adnl_stats_ippackets(length)],
    }
}
pub(crate) fn make_tos_api_adnl_stats_packets(
    length: usize,
) -> tl_api::tos::adnl::stats::packets::Packets {
    tl_api::tos::adnl::stats::packets::Packets {
        ts_start: 4.6875.into(),
        ts_end: 4.0.into(),
        in_packets: 1,
        in_bytes: 1,
        in_packets_channel: 6,
        in_bytes_channel: 6,
        out_packets: 4,
        out_bytes: 4,
        out_packets_channel: 2,
        out_bytes_channel: 2,
        out_expired_messages: 2,
        out_expired_bytes: 5,
    }
}
pub(crate) fn make_tos_api_adnl_stats_peerpair(
    length: usize,
) -> tl_api::tos::adnl::stats::peerpair::PeerPair {
    tl_api::tos::adnl::stats::peerpair::PeerPair {
        local_id: chain_block::UInt256::with_array([57; 32]),
        peer_id: chain_block::UInt256::with_array([21; 32]),
        ip_str: "wire-fixture".to_string(),
        packets_recent: make_tos_api_adnl_stats_packets(length),
        packets_total: make_tos_api_adnl_stats_packets(length),
        last_out_packet_ts: 3.5625.into(),
        last_in_packet_ts: 2.875.into(),
        connection_ready: tl_api::tos::Bool::BoolTrue,
        channel_status: 3,
        try_reinit_at: 4.0625.into(),
        out_queue_messages: 1,
        out_queue_bytes: 4,
    }
}
pub(crate) fn make_tos_api_engine_adnl(length: usize) -> tl_api::tos::engine::adnl::Adnl {
    tl_api::tos::engine::adnl::Adnl { id: chain_block::UInt256::with_array([29; 32]), category: 2 }
}
pub(crate) fn make_tos_api_engine_collator(
    length: usize,
) -> tl_api::tos::engine::collator::Collator {
    tl_api::tos::engine::collator::Collator {
        adnl_id: chain_block::UInt256::with_array([8; 32]),
        shard: make_tos_api_tosnode_shardid(length),
    }
}
pub(crate) fn make_tos_api_engine_controlinterface(
    length: usize,
) -> tl_api::tos::engine::controlinterface::ControlInterface {
    tl_api::tos::engine::controlinterface::ControlInterface {
        id: chain_block::UInt256::with_array([29; 32]),
        port: 6,
        allowed: vec![make_tos_api_engine_controlprocess(length)],
    }
}
pub(crate) fn make_tos_api_engine_controlprocess(
    length: usize,
) -> tl_api::tos::engine::controlprocess::ControlProcess {
    tl_api::tos::engine::controlprocess::ControlProcess {
        id: chain_block::UInt256::with_array([29; 32]),
        permissions: 2,
    }
}
pub(crate) fn make_tos_api_engine_dht(length: usize) -> tl_api::tos::engine::dht::Dht {
    tl_api::tos::engine::dht::Dht { id: chain_block::UInt256::with_array([29; 32]) }
}
pub(crate) fn make_tos_api_engine_gc(length: usize) -> tl_api::tos::engine::gc::Gc {
    tl_api::tos::engine::gc::Gc { ids: vec![chain_block::UInt256::with_array([26; 32])] }
}
pub(crate) fn make_tos_api_engine_liteserver(
    length: usize,
) -> tl_api::tos::engine::liteserver::LiteServer {
    tl_api::tos::engine::liteserver::LiteServer {
        id: chain_block::UInt256::with_array([29; 32]),
        port: 6,
    }
}
pub(crate) fn make_tos_api_engine_quicaddr(length: usize) -> tl_api::tos::engine::addr::QuicAddr {
    tl_api::tos::engine::addr::QuicAddr {
        ip: 1,
        port: 6,
        categories: vec![6],
        priority_categories: vec![5],
    }
}
pub(crate) fn make_tos_api_engine_validator(
    length: usize,
) -> tl_api::tos::engine::validator::Validator {
    tl_api::tos::engine::validator::Validator {
        id: chain_block::UInt256::with_array([29; 32]),
        temp_keys: vec![make_tos_api_engine_validatortempkey(length)],
        adnl_addrs: vec![make_tos_api_engine_validatoradnladdress(length)],
        election_date: 3,
        expire_at: 3,
    }
}
pub(crate) fn make_tos_api_engine_validator_addadnlid(
    length: usize,
) -> tl_api::tos::rpc::engine::validator::AddAdnlId {
    tl_api::tos::rpc::engine::validator::AddAdnlId {
        key_hash: chain_block::UInt256::with_array([19; 32]),
        category: 2,
    }
}
pub(crate) fn make_tos_api_engine_validator_addcollator(
    length: usize,
) -> tl_api::tos::rpc::engine::validator::AddCollator {
    tl_api::tos::rpc::engine::validator::AddCollator {
        adnl_id: chain_block::UInt256::with_array([8; 32]),
        shard: make_tos_api_tosnode_shardid(length),
    }
}
pub(crate) fn make_tos_api_engine_validator_addcustomoverlay(
    length: usize,
) -> tl_api::tos::rpc::engine::validator::AddCustomOverlay {
    tl_api::tos::rpc::engine::validator::AddCustomOverlay {
        overlay: make_tos_api_engine_validator_customoverlay(length),
    }
}
pub(crate) fn make_tos_api_engine_validator_addliteserver(
    length: usize,
) -> tl_api::tos::rpc::engine::validator::AddLiteserver {
    tl_api::tos::rpc::engine::validator::AddLiteserver {
        key_hash: chain_block::UInt256::with_array([19; 32]),
        port: 6,
    }
}
pub(crate) fn make_tos_api_engine_validator_addquicaddr(
    length: usize,
) -> tl_api::tos::rpc::engine::validator::AddQuicAddr {
    tl_api::tos::rpc::engine::validator::AddQuicAddr {
        ip: 1,
        port: 6,
        categories: vec![6],
        priority_categories: vec![5],
    }
}
pub(crate) fn make_tos_api_engine_validator_addvalidatoradnladdress(
    length: usize,
) -> tl_api::tos::rpc::engine::validator::AddValidatorAdnlAddress {
    tl_api::tos::rpc::engine::validator::AddValidatorAdnlAddress {
        permanent_key_hash: chain_block::UInt256::with_array([22; 32]),
        key_hash: chain_block::UInt256::with_array([19; 32]),
        ttl: 5,
    }
}
pub(crate) fn make_tos_api_engine_validator_addvalidatorpermanentkey(
    length: usize,
) -> tl_api::tos::rpc::engine::validator::AddValidatorPermanentKey {
    tl_api::tos::rpc::engine::validator::AddValidatorPermanentKey {
        key_hash: chain_block::UInt256::with_array([19; 32]),
        election_date: 3,
        ttl: 5,
    }
}
pub(crate) fn make_tos_api_engine_validator_addvalidatortempkey(
    length: usize,
) -> tl_api::tos::rpc::engine::validator::AddValidatorTempKey {
    tl_api::tos::rpc::engine::validator::AddValidatorTempKey {
        permanent_key_hash: chain_block::UInt256::with_array([22; 32]),
        key_hash: chain_block::UInt256::with_array([19; 32]),
        ttl: 5,
    }
}
pub(crate) fn make_tos_api_engine_validator_clearcollatorslist(
    length: usize,
) -> tl_api::tos::rpc::engine::validator::ClearCollatorsList {
    tl_api::tos::rpc::engine::validator::ClearCollatorsList
}
pub(crate) fn make_tos_api_engine_validator_collatornodesetwhitelistenabled(
    length: usize,
) -> tl_api::tos::rpc::engine::validator::CollatorNodeSetWhitelistEnabled {
    tl_api::tos::rpc::engine::validator::CollatorNodeSetWhitelistEnabled {
        enabled: tl_api::tos::Bool::BoolFalse,
    }
}
pub(crate) fn make_tos_api_engine_validator_collatornodesetwhitelistedvalidator(
    length: usize,
) -> tl_api::tos::rpc::engine::validator::CollatorNodeSetWhitelistedValidator {
    tl_api::tos::rpc::engine::validator::CollatorNodeSetWhitelistedValidator {
        adnl_id: chain_block::UInt256::with_array([8; 32]),
        add: tl_api::tos::Bool::BoolTrue,
    }
}
pub(crate) fn make_tos_api_engine_validator_collatornodewhitelist(
    length: usize,
) -> tl_api::tos::engine::validator::collatornodewhitelist::CollatorNodeWhitelist {
    tl_api::tos::engine::validator::collatornodewhitelist::CollatorNodeWhitelist {
        enabled: tl_api::tos::Bool::BoolFalse,
        adnl_ids: vec![chain_block::UInt256::with_array([5; 32])],
    }
}
pub(crate) fn make_tos_api_engine_validator_collatoroptions(
    length: usize,
) -> tl_api::tos::engine::validator::collatoroptions::CollatorOptions {
    tl_api::tos::engine::validator::collatoroptions::CollatorOptions {
        deferring_enabled: tl_api::tos::Bool::BoolFalse,
        defer_messages_after: 2,
        defer_out_queue_size_limit: 6,
        dispatch_phase_2_max_total: 1,
        dispatch_phase_3_max_total: 2,
        dispatch_phase_2_max_per_initiator: 7,
        dispatch_phase_3_max_per_initiator: 1,
        whitelist: vec!["wire-fixture".to_string()],
        prioritylist: vec!["wire-fixture".to_string()],
        force_full_collated_data: tl_api::tos::Bool::BoolFalse,
        ignore_collated_data_limits: tl_api::tos::Bool::BoolFalse,
    }
}
pub(crate) fn make_tos_api_engine_validator_collatorslist(
    length: usize,
) -> tl_api::tos::engine::validator::collatorslist::CollatorsList {
    tl_api::tos::engine::validator::collatorslist::CollatorsList {
        shards: vec![make_tos_api_engine_validator_collatorslist_shard(length)],
    }
}
pub(crate) fn make_tos_api_engine_validator_collatorslist_collator(
    length: usize,
) -> tl_api::tos::engine::validator::collators_list::collator::Collator {
    tl_api::tos::engine::validator::collators_list::collator::Collator {
        adnl_id: chain_block::UInt256::with_array([8; 32]),
    }
}
pub(crate) fn make_tos_api_engine_validator_collatorslist_shard(
    length: usize,
) -> tl_api::tos::engine::validator::collators_list::shard::Shard {
    tl_api::tos::engine::validator::collators_list::shard::Shard {
        shard_id: make_tos_api_tosnode_shardid(length),
        collators: vec![make_tos_api_engine_validator_collatorslist_collator(length)],
        self_collate: tl_api::tos::Bool::BoolTrue,
        select_mode: "wire-fixture".to_string(),
    }
}
pub(crate) fn make_tos_api_engine_validator_config(
    length: usize,
) -> tl_api::tos::engine::validator::config::Config {
    tl_api::tos::engine::validator::config::Config {
        out_port: 4,
        addrs: vec![make_tos_api_engine_quicaddr(length).into_boxed()],
        adnl: vec![make_tos_api_engine_adnl(length)],
        dht: vec![make_tos_api_engine_dht(length)],
        validators: vec![make_tos_api_engine_validator(length)],
        collators: vec![make_tos_api_engine_collator(length)],
        fullnode: chain_block::UInt256::with_array([32; 32]),
        fullnodeslaves: vec![make_tos_api_engine_validator_fullnodeslave(length)],
        fullnodemasters: vec![make_tos_api_engine_validator_fullnodemaster(length)],
        fullnodeconfig: make_tos_api_engine_validator_fullnodeconfig(length),
        extraconfig: make_tos_api_engine_validator_extraconfig(length),
        liteservers: vec![make_tos_api_engine_liteserver(length)],
        control: vec![make_tos_api_engine_controlinterface(length)],
        shards_to_monitor: vec![make_tos_api_tosnode_shardid(length)],
        gc: make_tos_api_engine_gc(length),
    }
}
pub(crate) fn make_tos_api_engine_validator_configproposaldetail(
    length: usize,
) -> tl_api::tos::engine::validator::configproposaldetail::ConfigProposalDetail {
    tl_api::tos::engine::validator::configproposaldetail::ConfigProposalDetail {
        block: make_tos_api_tosnode_blockidext(length),
        meta: None,
        value: None,
    }
}
pub(crate) fn make_tos_api_engine_validator_configproposalmeta(
    length: usize,
) -> tl_api::tos::engine::validator::configproposalmeta::ConfigProposalMeta {
    tl_api::tos::engine::validator::configproposalmeta::ConfigProposalMeta {
        hash: chain_block::UInt256::with_array([8; 32]),
        expires: 6,
        critical: tl_api::tos::Bool::BoolFalse,
        param_id: 4,
        param_hash: None,
        has_value: tl_api::tos::Bool::BoolTrue,
        vset_id: chain_block::UInt256::with_array([43; 32]),
        voters: vec![4],
        weight_remaining: 4,
        rounds_remaining: 2,
        wins: 2,
        losses: 1,
    }
}
pub(crate) fn make_tos_api_engine_validator_configproposals(
    length: usize,
) -> tl_api::tos::engine::validator::configproposals::ConfigProposals {
    tl_api::tos::engine::validator::configproposals::ConfigProposals {
        block: make_tos_api_tosnode_blockidext(length),
        proposals: vec![make_tos_api_engine_validator_configproposalmeta(length)],
    }
}
pub(crate) fn make_tos_api_engine_validator_controlqueryerror(
    length: usize,
) -> tl_api::tos::engine::validator::controlqueryerror::ControlQueryError {
    tl_api::tos::engine::validator::controlqueryerror::ControlQueryError {
        code: 6,
        message: "wire-fixture".to_string(),
    }
}
pub(crate) fn make_tos_api_engine_validator_createpqstakeauthorization(
    length: usize,
) -> tl_api::tos::rpc::engine::validator::CreatePqStakeAuthorization {
    tl_api::tos::rpc::engine::validator::CreatePqStakeAuthorization {
        election_date: 3,
        max_factor: 4,
        adnl_addr: chain_block::UInt256::with_array([37; 32]),
        stake_owner: chain_block::UInt256::with_array([7; 32]),
    }
}
pub(crate) fn make_tos_api_engine_validator_customoverlay(
    length: usize,
) -> tl_api::tos::engine::validator::customoverlay::CustomOverlay {
    tl_api::tos::engine::validator::customoverlay::CustomOverlay {
        name: "wire-fixture".to_string(),
        nodes: vec![make_tos_api_engine_validator_customoverlaynode(length)],
        sender_shards: vec![make_tos_api_tosnode_shardid(length)],
        skip_public_msg_send: tl_api::tos::Bool::BoolFalse,
        use_quic: tl_api::tos::Bool::BoolTrue,
    }
}
pub(crate) fn make_tos_api_engine_validator_customoverlaynode(
    length: usize,
) -> tl_api::tos::engine::validator::customoverlaynode::CustomOverlayNode {
    tl_api::tos::engine::validator::customoverlaynode::CustomOverlayNode {
        adnl_id: chain_block::UInt256::with_array([8; 32]),
        msg_sender: tl_api::tos::Bool::BoolFalse,
        msg_sender_priority: 6,
        block_sender: tl_api::tos::Bool::BoolTrue,
    }
}
pub(crate) fn make_tos_api_engine_validator_customoverlaysconfig(
    length: usize,
) -> tl_api::tos::engine::validator::customoverlaysconfig::CustomOverlaysConfig {
    tl_api::tos::engine::validator::customoverlaysconfig::CustomOverlaysConfig {
        overlays: vec![make_tos_api_engine_validator_customoverlay(length)],
    }
}
pub(crate) fn make_tos_api_engine_validator_delcollator(
    length: usize,
) -> tl_api::tos::rpc::engine::validator::DelCollator {
    tl_api::tos::rpc::engine::validator::DelCollator {
        adnl_id: chain_block::UInt256::with_array([8; 32]),
        shard: make_tos_api_tosnode_shardid(length),
    }
}
pub(crate) fn make_tos_api_engine_validator_delcustomoverlay(
    length: usize,
) -> tl_api::tos::rpc::engine::validator::DelCustomOverlay {
    tl_api::tos::rpc::engine::validator::DelCustomOverlay { name: "wire-fixture".to_string() }
}
pub(crate) fn make_tos_api_engine_validator_electionparticipant(
    length: usize,
) -> tl_api::tos::engine::validator::electionparticipant::ElectionParticipant {
    tl_api::tos::engine::validator::electionparticipant::ElectionParticipant {
        id: chain_block::UInt256::with_array([29; 32]),
        stake: vec![6; length],
        max_factor: 4,
        adnl: chain_block::UInt256::with_array([3; 32]),
        algorithm: 2,
        key_id: chain_block::UInt256::with_array([40; 32]),
    }
}
pub(crate) fn make_tos_api_engine_validator_electorstate(
    length: usize,
) -> tl_api::tos::engine::validator::electorstate::ElectorState {
    tl_api::tos::engine::validator::electorstate::ElectorState {
        block: make_tos_api_tosnode_blockidext(length),
        elect_at: 1,
        elect_close: 7,
        min_stake: vec![12; length],
        total_stake: vec![59; length],
        failed: tl_api::tos::Bool::BoolFalse,
        finished: tl_api::tos::Bool::BoolTrue,
        participants: vec![make_tos_api_engine_validator_electionparticipant(length)],
        past_elections: vec![make_tos_api_engine_validator_pastelection(length)],
        returned: vec![make_tos_api_engine_validator_returnedstake(length)],
    }
}
pub(crate) fn make_tos_api_engine_validator_exportpublickey(
    length: usize,
) -> tl_api::tos::rpc::engine::validator::ExportPublicKey {
    tl_api::tos::rpc::engine::validator::ExportPublicKey {
        key_hash: chain_block::UInt256::with_array([19; 32]),
    }
}
pub(crate) fn make_tos_api_engine_validator_extmessagepoolconfig(
    length: usize,
) -> tl_api::tos::engine::validator::extmessagepoolconfig::ExtMessagePoolConfig {
    tl_api::tos::engine::validator::extmessagepoolconfig::ExtMessagePoolConfig {
        max_mempool_messages: 6,
        num_regular_checkers: 7,
        num_priority_checkers: 4,
        max_admission_waiters: 4,
        max_ext_msg_per_addr: 2,
        max_ext_msg_per_addr_time_window: 2.9375.into(),
        local_ls_message_priority: 4,
    }
}
pub(crate) fn make_tos_api_engine_validator_extraconfig(
    length: usize,
) -> tl_api::tos::engine::validator::extraconfig::ExtraConfig {
    tl_api::tos::engine::validator::extraconfig::ExtraConfig {
        state_serializer_enabled: tl_api::tos::Bool::BoolTrue,
        fast_sync_member_certificates: vec![
            make_tos_api_engine_validator_fastsyncmembercertificate(length),
        ],
        collator_node_whitelist: make_tos_api_engine_validator_collatornodewhitelist(length),
        fast_sync_overlay_clients: vec![make_tos_api_engine_validator_fastsyncoverlayclient(
            length,
        )],
        ext_message_pool_config: make_tos_api_engine_validator_extmessagepoolconfig(length),
        pq_consensus: make_tos_api_engine_validator_pqconsensus(length),
    }
}
pub(crate) fn make_tos_api_engine_validator_fastsyncmembercertificate(
    length: usize,
) -> tl_api::tos::engine::validator::fastsyncmembercertificate::FastSyncMemberCertificate {
    tl_api::tos::engine::validator::fastsyncmembercertificate::FastSyncMemberCertificate {
        adnl_id: chain_block::UInt256::with_array([8; 32]),
        certificate: make_tos_api_overlay_membercertificate(length).into_boxed(),
    }
}
pub(crate) fn make_tos_api_engine_validator_fastsyncoverlayclient(
    length: usize,
) -> tl_api::tos::engine::validator::fastsyncoverlayclient::FastSyncOverlayClient {
    tl_api::tos::engine::validator::fastsyncoverlayclient::FastSyncOverlayClient {
        adnl_id: chain_block::UInt256::with_array([8; 32]),
        slot: 3,
    }
}
pub(crate) fn make_tos_api_engine_validator_frozenstake(
    length: usize,
) -> tl_api::tos::engine::validator::frozenstake::FrozenStake {
    tl_api::tos::engine::validator::frozenstake::FrozenStake {
        id: chain_block::UInt256::with_array([29; 32]),
        owner: chain_block::UInt256::with_array([25; 32]),
        weight: 5,
        stake: vec![6; length],
        banned: tl_api::tos::Bool::BoolTrue,
    }
}
pub(crate) fn make_tos_api_engine_validator_fullnodeconfig(
    length: usize,
) -> tl_api::tos::engine::validator::fullnodeconfig::FullNodeConfig {
    tl_api::tos::engine::validator::fullnodeconfig::FullNodeConfig {
        ext_messages_broadcast_disabled: tl_api::tos::Bool::BoolTrue,
    }
}
pub(crate) fn make_tos_api_engine_validator_fullnodemaster(
    length: usize,
) -> tl_api::tos::engine::validator::fullnodemaster::FullNodeMaster {
    tl_api::tos::engine::validator::fullnodemaster::FullNodeMaster {
        port: 6,
        adnl: chain_block::UInt256::with_array([3; 32]),
    }
}
pub(crate) fn make_tos_api_engine_validator_fullnodeslave(
    length: usize,
) -> tl_api::tos::engine::validator::fullnodeslave::FullNodeSlave {
    tl_api::tos::engine::validator::fullnodeslave::FullNodeSlave {
        ip: 1,
        port: 6,
        adnl: make_tos_api_pub_ed25519(length).into_boxed(),
    }
}
pub(crate) fn make_tos_api_engine_validator_generatekeypair(
    length: usize,
) -> tl_api::tos::rpc::engine::validator::GenerateKeyPair {
    tl_api::tos::rpc::engine::validator::GenerateKeyPair
}
pub(crate) fn make_tos_api_engine_validator_getcollatoroptionsjson(
    length: usize,
) -> tl_api::tos::rpc::engine::validator::GetCollatorOptionsJson {
    tl_api::tos::rpc::engine::validator::GetCollatorOptionsJson
}
pub(crate) fn make_tos_api_engine_validator_getconfig(
    length: usize,
) -> tl_api::tos::rpc::engine::validator::GetConfig {
    tl_api::tos::rpc::engine::validator::GetConfig
}
pub(crate) fn make_tos_api_engine_validator_getconfigproposal(
    length: usize,
) -> tl_api::tos::rpc::engine::validator::GetConfigProposal {
    tl_api::tos::rpc::engine::validator::GetConfigProposal {
        block: None,
        hash: chain_block::UInt256::with_array([8; 32]),
    }
}
pub(crate) fn make_tos_api_engine_validator_getconfigproposals(
    length: usize,
) -> tl_api::tos::rpc::engine::validator::GetConfigProposals {
    tl_api::tos::rpc::engine::validator::GetConfigProposals { block: None }
}
pub(crate) fn make_tos_api_engine_validator_getelectorstate(
    length: usize,
) -> tl_api::tos::rpc::engine::validator::GetElectorState {
    tl_api::tos::rpc::engine::validator::GetElectorState {
        block: None,
        wallets: vec![chain_block::UInt256::with_array([57; 32])],
    }
}
pub(crate) fn make_tos_api_engine_validator_getstats(
    length: usize,
) -> tl_api::tos::rpc::engine::validator::GetStats {
    tl_api::tos::rpc::engine::validator::GetStats
}
pub(crate) fn make_tos_api_engine_validator_gettime(
    length: usize,
) -> tl_api::tos::rpc::engine::validator::GetTime {
    tl_api::tos::rpc::engine::validator::GetTime
}
pub(crate) fn make_tos_api_engine_validator_jsonconfig(
    length: usize,
) -> tl_api::tos::engine::validator::jsonconfig::JsonConfig {
    tl_api::tos::engine::validator::jsonconfig::JsonConfig { data: "wire-fixture".to_string() }
}
pub(crate) fn make_tos_api_engine_validator_keyhash(
    length: usize,
) -> tl_api::tos::engine::validator::keyhash::KeyHash {
    tl_api::tos::engine::validator::keyhash::KeyHash {
        key_hash: chain_block::UInt256::with_array([19; 32]),
    }
}
pub(crate) fn make_tos_api_engine_validator_onestat(
    length: usize,
) -> tl_api::tos::engine::validator::onestat::OneStat {
    tl_api::tos::engine::validator::onestat::OneStat {
        key: "wire-fixture".to_string(),
        value: "wire-fixture".to_string(),
    }
}
pub(crate) fn make_tos_api_engine_validator_overlaystats(
    length: usize,
) -> tl_api::tos::engine::validator::overlaystats::OverlayStats {
    tl_api::tos::engine::validator::overlaystats::OverlayStats {
        overlay_id: chain_block::UInt256::with_array([9; 32]),
        overlay_id_full: make_tos_api_pub_ed25519(length).into_boxed(),
        adnl_id: chain_block::UInt256::with_array([8; 32]),
        scope: "wire-fixture".to_string(),
        nodes: vec![make_tos_api_engine_validator_overlaystatsnode(length)],
        stats: vec![make_tos_api_engine_validator_onestat(length)],
        total_traffic: make_tos_api_engine_validator_overlaystatstraffic(length),
        total_traffic_responses: make_tos_api_engine_validator_overlaystatstraffic(length),
        broadcasts: vec![make_tos_api_engine_validator_overlaystatsbroadcasts(length)],
        extra: "wire-fixture".to_string(),
    }
}
pub(crate) fn make_tos_api_engine_validator_overlaystatsbroadcasts(
    length: usize,
) -> tl_api::tos::engine::validator::overlaystatsbroadcasts::OverlayStatsBroadcasts {
    tl_api::tos::engine::validator::overlaystatsbroadcasts::OverlayStatsBroadcasts {
        source: chain_block::UInt256::with_array([9; 32]),
        ts_start: 4.6875.into(),
        ts_end: 4.0.into(),
        count: 1,
        total_size: 2,
        total_out_traffic: 5,
    }
}
pub(crate) fn make_tos_api_engine_validator_overlaystatsnode(
    length: usize,
) -> tl_api::tos::engine::validator::overlaystatsnode::OverlayStatsNode {
    tl_api::tos::engine::validator::overlaystatsnode::OverlayStatsNode {
        adnl_id: chain_block::UInt256::with_array([8; 32]),
        ip_addr: "wire-fixture".to_string(),
        is_neighbour: tl_api::tos::Bool::BoolFalse,
        is_alive: tl_api::tos::Bool::BoolTrue,
        node_flags: 7,
        bdcst_errors: 5,
        fec_bdcst_errors: 3,
        last_in_query: 1,
        last_out_query: 4,
        traffic: make_tos_api_engine_validator_overlaystatstraffic(length),
        traffic_responses: make_tos_api_engine_validator_overlaystatstraffic(length),
        last_ping_at: 2.9375.into(),
        last_ping_time: 1.8125.into(),
    }
}
pub(crate) fn make_tos_api_engine_validator_overlaystatstraffic(
    length: usize,
) -> tl_api::tos::engine::validator::overlaystatstraffic::OverlayStatsTraffic {
    tl_api::tos::engine::validator::overlaystatstraffic::OverlayStatsTraffic {
        t_out_bytes: 5,
        t_in_bytes: 2,
        t_out_pckts: 3,
        t_in_pckts: 7,
    }
}
pub(crate) fn make_tos_api_engine_validator_pastelection(
    length: usize,
) -> tl_api::tos::engine::validator::pastelection::PastElection {
    tl_api::tos::engine::validator::pastelection::PastElection {
        election_id: 4,
        unfreeze_at: 1,
        stake_held: 2,
        vset_hash: chain_block::UInt256::with_array([22; 32]),
        total_stake: vec![59; length],
        bonuses: vec![1; length],
        frozen: vec![make_tos_api_engine_validator_frozenstake(length)],
    }
}
pub(crate) fn make_tos_api_engine_validator_pqconsensus(
    length: usize,
) -> tl_api::tos::engine::validator::pqconsensus::PqConsensus {
    tl_api::tos::engine::validator::pqconsensus::PqConsensus {
        validator_id: chain_block::UInt256::with_array([28; 32]),
        consensus_key_file: "wire-fixture".to_string(),
        keys: vec![make_tos_api_engine_validator_pqconsensuskey(length)],
    }
}
pub(crate) fn make_tos_api_engine_validator_pqconsensuskey(
    length: usize,
) -> tl_api::tos::engine::validator::pqconsensuskey::PqConsensusKey {
    tl_api::tos::engine::validator::pqconsensuskey::PqConsensusKey {
        consensus_key_file: "wire-fixture".to_string(),
        valid_from: 3,
        expire_at: 3,
    }
}
pub(crate) fn make_tos_api_engine_validator_returnedstake(
    length: usize,
) -> tl_api::tos::engine::validator::returnedstake::ReturnedStake {
    tl_api::tos::engine::validator::returnedstake::ReturnedStake {
        wallet: chain_block::UInt256::with_array([1; 32]),
        amount: vec![12; length],
    }
}
pub(crate) fn make_tos_api_engine_validator_setcollatoroptionsjson(
    length: usize,
) -> tl_api::tos::rpc::engine::validator::SetCollatorOptionsJson {
    tl_api::tos::rpc::engine::validator::SetCollatorOptionsJson { json: "wire-fixture".to_string() }
}
pub(crate) fn make_tos_api_engine_validator_shardblockverifierconfig_shard(
    length: usize,
) -> tl_api::tos::engine::validator::shard_block_verifier_config::shard::Shard {
    tl_api::tos::engine::validator::shard_block_verifier_config::shard::Shard {
        shard_id: make_tos_api_tosnode_shardid(length),
        trusted_nodes: vec![chain_block::UInt256::with_array([55; 32])],
        required_confirms: 6,
    }
}
pub(crate) fn make_tos_api_engine_validator_showcollatornodewhitelist(
    length: usize,
) -> tl_api::tos::rpc::engine::validator::ShowCollatorNodeWhitelist {
    tl_api::tos::rpc::engine::validator::ShowCollatorNodeWhitelist
}
pub(crate) fn make_tos_api_engine_validator_showcollatorslist(
    length: usize,
) -> tl_api::tos::rpc::engine::validator::ShowCollatorsList {
    tl_api::tos::rpc::engine::validator::ShowCollatorsList
}
pub(crate) fn make_tos_api_engine_validator_showcustomoverlays(
    length: usize,
) -> tl_api::tos::rpc::engine::validator::ShowCustomOverlays {
    tl_api::tos::rpc::engine::validator::ShowCustomOverlays
}
pub(crate) fn make_tos_api_engine_validator_sign(
    length: usize,
) -> tl_api::tos::rpc::engine::validator::Sign {
    tl_api::tos::rpc::engine::validator::Sign {
        key_hash: chain_block::UInt256::with_array([19; 32]),
        data: vec![57; length],
    }
}
pub(crate) fn make_tos_api_engine_validator_signature(
    length: usize,
) -> tl_api::tos::engine::validator::signature::Signature {
    tl_api::tos::engine::validator::signature::Signature { signature: vec![35; length] }
}
pub(crate) fn make_tos_api_engine_validator_stats(
    length: usize,
) -> tl_api::tos::engine::validator::stats::Stats {
    tl_api::tos::engine::validator::stats::Stats {
        stats: vec![make_tos_api_engine_validator_onestat(length)],
    }
}
pub(crate) fn make_tos_api_engine_validator_success(
    length: usize,
) -> tl_api::tos::engine::validator::Success {
    tl_api::tos::engine::validator::Success::Engine_Validator_Success
}
pub(crate) fn make_tos_api_engine_validator_time(
    length: usize,
) -> tl_api::tos::engine::validator::time::Time {
    tl_api::tos::engine::validator::time::Time { time: 5 }
}
pub(crate) fn make_tos_api_engine_validatoradnladdress(
    length: usize,
) -> tl_api::tos::engine::validatoradnladdress::ValidatorAdnlAddress {
    tl_api::tos::engine::validatoradnladdress::ValidatorAdnlAddress {
        id: chain_block::UInt256::with_array([29; 32]),
        expire_at: 3,
    }
}
pub(crate) fn make_tos_api_engine_validatortempkey(
    length: usize,
) -> tl_api::tos::engine::validatortempkey::ValidatorTempKey {
    tl_api::tos::engine::validatortempkey::ValidatorTempKey {
        key: chain_block::UInt256::with_array([35; 32]),
        expire_at: 3,
    }
}
pub(crate) fn make_tos_api_liteserver_desc(length: usize) -> tl_api::tos::liteserver::desc::Desc {
    tl_api::tos::liteserver::desc::Desc {
        id: make_tos_api_pub_ed25519(length).into_boxed(),
        ip: 1,
        port: 6,
        hostname: "wire-fixture".to_string(),
    }
}
pub(crate) fn make_tos_api_liteserver_descv2(
    length: usize,
) -> tl_api::tos::liteserver::descv2::DescV2 {
    tl_api::tos::liteserver::descv2::DescV2 {
        id: make_tos_api_pub_ed25519(length).into_boxed(),
        ip: 1,
        port: 6,
        hostname: "wire-fixture".to_string(),
        slices: vec![make_tos_api_liteserver_descv2_slicesimple(length).into_boxed()],
    }
}
pub(crate) fn make_tos_api_liteserver_descv2_slicesimple(
    length: usize,
) -> tl_api::tos::liteserver::desc_v2::slice::SliceSimple {
    tl_api::tos::liteserver::desc_v2::slice::SliceSimple {
        shards: vec![make_tos_api_tosnode_shardid(length)],
    }
}
pub(crate) fn make_tos_api_overlay_membercertificate(
    length: usize,
) -> tl_api::tos::overlay::membercertificate::MemberCertificate {
    tl_api::tos::overlay::membercertificate::MemberCertificate {
        issued_by: make_tos_api_pub_ed25519(length).into_boxed(),
        flags: 1,
        slot: 3,
        expire_at: 3,
        signature: vec![35; length],
    }
}
pub(crate) fn make_tos_api_pub_ed25519(length: usize) -> tl_api::tos::pub_::publickey::Ed25519 {
    tl_api::tos::pub_::publickey::Ed25519 { key: chain_block::UInt256::with_array([35; 32]) }
}
pub(crate) fn make_tos_api_tosnode_blockidext(length: usize) -> chain_block::BlockIdExt {
    chain_block::BlockIdExt::with_params(
        chain_block::ShardIdent::masterchain(),
        7,
        chain_block::UInt256::with_array([31; 32]),
        chain_block::UInt256::with_array([37; 32]),
    )
}
pub(crate) fn make_tos_api_tosnode_shardid(
    length: usize,
) -> tl_api::tos::tos_node::shardid::ShardId {
    tl_api::tos::tos_node::shardid::ShardId { workchain: -1, shard: -9223372036854775808 }
}
pub(crate) fn make_toslib_api_raw_extmessageinfo(
    length: usize,
) -> tl_api::tos::raw::extmessageinfo::ExtMessageInfo {
    tl_api::tos::raw::extmessageinfo::ExtMessageInfo {
        hash: vec![8; length],
        hash_norm: vec![16; length],
    }
}
