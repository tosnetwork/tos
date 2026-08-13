/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::client_api::{
    Account, AddAdnlAddressRq, AddCollatorRq, AddLiteserverRq, AddValidatorAdnlAddrRq,
    AddValidatorPermKeyRq, AddValidatorTempKeyRq, BlockchainConfigInfo, ClientAPI, CollatorEntry,
    CollatorNodeWhitelist, CollatorNodeWhitelistRq, CollatorsList, CollatorsListShard,
    CustomOverlayConfig, CustomOverlayNode, CustomOverlaysConfig, EngineValidatorConfig, NodeStats,
    ShardAccountState, ShardDescriptor, Shutdown, SignRq,
};
use adnl::client::{AdnlClient, AdnlClientConfig, AdnlClientConfigJson};
use anyhow::Context;
use chain_block::{BlockIdExt, Deserializable, ShardAccount, UInt256, UnixTime, write_boc};
use std::time::Instant;
use tl_api::{
    AnyBoxedSerialize, TLObject, serialize_boxed,
    tos::{
        self, engine::validator::ControlQueryError, raw::ShardAccountState as ShardAccountState_TL,
        rpc::engine::validator::ControlQuery,
    },
};

pub trait ToFromTL {
    type Rq;
    type Rs;

    fn serialize(rq: &Self::Rq) -> anyhow::Result<TLObject>;
    fn deserialize(answer: TLObject) -> anyhow::Result<Self::Rs>;
}

fn downcast<T: tl_api::AnyBoxedSerialize>(data: TLObject) -> anyhow::Result<T> {
    match data.downcast::<T>() {
        Ok(result) => Ok(result),
        Err(obj) => anyhow::bail!("Wrong downcast {:?} to {}", obj, std::any::type_name::<T>()),
    }
}

struct GetAccountRqRs {}

impl ToFromTL for GetAccountRqRs {
    type Rq = String;
    type Rs = Account;

    fn serialize(address: &Self::Rq) -> anyhow::Result<TLObject> {
        Ok(tos::rpc::raw::GetShardAccountState {
            account_address: tl_api::tos::accountaddress::AccountAddress {
                account_address: address.to_owned(),
            },
        }
        .into_tl_object())
    }

    fn deserialize(rs: TLObject) -> anyhow::Result<Self::Rs> {
        Ok(match downcast::<ShardAccountState_TL>(rs)? {
            ShardAccountState_TL::Raw_ShardAccountNone => Account::Nonexist,
            ShardAccountState_TL::Raw_ShardAccountState(account_state) => {
                let shard_account =
                    ShardAccount::construct_from_bytes(&account_state.shard_account)?;
                let account = shard_account.read_account()?;
                let sas = ShardAccountState {
                    status: account.status(),
                    balance: account.balance().map_or(0, |val| val.coins.as_u128()),
                    last_paid: account.last_paid(),
                    last_trans: shard_account.last_trans_lt(),
                    data: write_boc(&shard_account.account_cell())?,
                };

                Account::ShardAccountState(sas)
            }
        })
    }
}

struct GetBlockchainConfigRqRs {}

impl ToFromTL for GetBlockchainConfigRqRs {
    type Rq = ();
    type Rs = BlockchainConfigInfo;

    fn serialize(_: &Self::Rq) -> anyhow::Result<TLObject> {
        Ok(tos::rpc::lite_server::GetConfigAll::default().into_tl_object())
    }

    fn deserialize(rs: TLObject) -> anyhow::Result<Self::Rs> {
        let config_info = downcast::<tl_api::tos::lite_server::ConfigInfo>(rs)?;

        Ok(BlockchainConfigInfo {
            state_proof: config_info.state_proof().clone(),
            config_proof: config_info.config_proof().clone(),
        })
    }
}

struct GetValidatorConfigRqRs {}

impl ToFromTL for GetValidatorConfigRqRs {
    type Rq = ();
    type Rs = EngineValidatorConfig;

    fn serialize(_: &Self::Rq) -> anyhow::Result<TLObject> {
        Ok(tos::rpc::engine::validator::GetConfig.into_tl_object())
    }

    fn deserialize(rs: TLObject) -> anyhow::Result<Self::Rs> {
        let config = downcast::<tl_api::tos::engine::validator::JsonConfig>(rs)?;
        let engine_validator_config = serde_json::from_str::<EngineValidatorConfig>(config.data())?;
        Ok(engine_validator_config)
    }
}

struct GetConfigParamRqRs {}

impl ToFromTL for GetConfigParamRqRs {
    type Rq = u32;
    type Rs = Vec<u8>;

    fn serialize(id: &Self::Rq) -> anyhow::Result<TLObject> {
        let param_id =
            i32::try_from(*id).map_err(|_| anyhow::anyhow!("id value does not fit into i32"))?;
        let param_list = vec![param_id];
        Ok(tos::rpc::lite_server::GetConfigParams {
            mode: 0,
            id: BlockIdExt::default(),
            param_list,
        }
        .into_tl_object())
    }

    fn deserialize(rs: TLObject) -> anyhow::Result<Self::Rs> {
        let config_info = downcast::<tl_api::tos::lite_server::ConfigInfo>(rs)?;
        Ok(config_info.only().config_proof)
    }
}

struct SignRqRs {}

impl ToFromTL for SignRqRs {
    type Rq = SignRq;
    type Rs = Vec<u8>;

    fn serialize(rq: &Self::Rq) -> anyhow::Result<TLObject> {
        let key_hash = UInt256::from_raw(rq.key_hash.clone(), 256);
        let ret = tos::rpc::engine::validator::Sign { key_hash, data: rq.data.clone() };
        Ok(ret.into_tl_object())
    }

    fn deserialize(rs: TLObject) -> anyhow::Result<Self::Rs> {
        let answer = downcast::<tl_api::tos::engine::validator::Signature>(rs)?;
        let signature = answer.signature().clone();

        Ok(signature)
    }
}

struct GenerateKeyPairRqRs {}

impl ToFromTL for GenerateKeyPairRqRs {
    type Rq = ();
    type Rs = Vec<u8>;

    fn serialize(_: &Self::Rq) -> anyhow::Result<TLObject> {
        Ok(tos::rpc::engine::validator::GenerateKeyPair.into_tl_object())
    }

    fn deserialize(rs: TLObject) -> anyhow::Result<Self::Rs> {
        let key_hash_resp = downcast::<tl_api::tos::engine::validator::KeyHash>(rs)?;
        let key_hash = key_hash_resp.key_hash().as_slice().to_vec();

        Ok(key_hash)
    }
}

struct ExportKeyPubRqRs {}

impl ToFromTL for ExportKeyPubRqRs {
    type Rq = Vec<u8>;
    type Rs = Vec<u8>;

    fn serialize(rq: &Self::Rq) -> anyhow::Result<TLObject> {
        let key_hash = UInt256::from_raw(rq.to_owned(), 256);

        let ret = tos::rpc::engine::validator::ExportPublicKey { key_hash };
        Ok(ret.into_tl_object())
    }

    fn deserialize(rs: TLObject) -> anyhow::Result<Self::Rs> {
        let answer = downcast::<tl_api::tos::PublicKey>(rs)?;
        let pub_key = match answer.key() {
            Some(key) => key.clone().into_vec(),
            None => anyhow::bail!("Public key not found in answer!"),
        };

        Ok(pub_key)
    }
}

struct AddValidatorPermKeyRqRs {}

impl ToFromTL for AddValidatorPermKeyRqRs {
    type Rq = AddValidatorPermKeyRq;
    type Rs = ();

    fn serialize(rq: &Self::Rq) -> anyhow::Result<TLObject> {
        let key_hash = UInt256::from_raw(rq.key_hash.clone(), 256);
        let election_date = rq.election_date;
        let ttl = rq.expire_at - election_date;

        let ret =
            tos::rpc::engine::validator::AddValidatorPermanentKey { key_hash, election_date, ttl };
        Ok(ret.into_tl_object())
    }

    fn deserialize(_: TLObject) -> anyhow::Result<Self::Rs> {
        Ok(())
    }
}

struct AddValidatorTempKeyRqRs {}

impl ToFromTL for AddValidatorTempKeyRqRs {
    type Rq = AddValidatorTempKeyRq;
    type Rs = ();

    fn serialize(rq: &Self::Rq) -> anyhow::Result<TLObject> {
        let perm_key_hash = UInt256::from_raw(rq.perm_key_hash.clone(), 256);
        let key_hash = UInt256::from_raw(rq.key_hash.clone(), 256);
        let expire_at = rq.expire_at;
        let ttl = expire_at - UnixTime::now() as i32;

        let ret = tos::rpc::engine::validator::AddValidatorTempKey {
            permanent_key_hash: perm_key_hash,
            key_hash,
            ttl,
        };

        Ok(ret.into_tl_object())
    }

    fn deserialize(_: TLObject) -> anyhow::Result<Self::Rs> {
        Ok(())
    }
}

struct AddAdnlAddressRqRs {}

impl ToFromTL for AddAdnlAddressRqRs {
    type Rq = AddAdnlAddressRq;
    type Rs = ();

    fn serialize(rq: &Self::Rq) -> anyhow::Result<TLObject> {
        let key_hash = UInt256::from_raw(rq.key_hash.clone(), 256);
        let category = rq.category;

        if !(0..=15).contains(&category) {
            anyhow::bail!("category must be not negative and less than 16")
        }
        let ret = tos::rpc::engine::validator::AddAdnlId { key_hash, category };

        Ok(ret.into_tl_object())
    }

    fn deserialize(_: TLObject) -> anyhow::Result<Self::Rs> {
        Ok(())
    }
}

struct AddValidatorAdnlAddrRqRs {}

impl ToFromTL for AddValidatorAdnlAddrRqRs {
    type Rq = AddValidatorAdnlAddrRq;
    type Rs = ();

    fn serialize(rq: &Self::Rq) -> anyhow::Result<TLObject> {
        let perm_key_hash = UInt256::from_raw(rq.perm_key_hash.clone(), 256);
        let key_hash = UInt256::from_raw(rq.key_hash.clone(), 256);
        let expire_at = rq.expire_at;
        let ttl = expire_at - UnixTime::now() as i32;

        let ret = tos::rpc::engine::validator::AddValidatorAdnlAddress {
            permanent_key_hash: perm_key_hash,
            key_hash,
            ttl,
        };

        Ok(ret.into_tl_object())
    }

    fn deserialize(_: TLObject) -> anyhow::Result<Self::Rs> {
        Ok(())
    }
}

struct SendBocRqRs {}

impl ToFromTL for SendBocRqRs {
    type Rq = Vec<u8>;
    type Rs = ();

    fn serialize(boc: &Self::Rq) -> anyhow::Result<TLObject> {
        let ret = tos::rpc::lite_server::SendMessage { body: boc.to_owned() };
        Ok(ret.into_tl_object())
    }

    fn deserialize(_: TLObject) -> anyhow::Result<Self::Rs> {
        Ok(())
    }
}

struct GetTimeRqRs {}

impl ToFromTL for GetTimeRqRs {
    type Rq = ();
    type Rs = i32;

    fn serialize(_: &Self::Rq) -> anyhow::Result<TLObject> {
        Ok(tos::rpc::engine::validator::GetTime {}.into_tl_object())
    }

    fn deserialize(answer: TLObject) -> anyhow::Result<Self::Rs> {
        let time = downcast::<tos::engine::validator::Time>(answer)?;
        Ok(*time.time())
    }
}

// --- Collator management RqRs adapters ---

fn bool_to_tl(val: bool) -> tos::Bool {
    if val { tos::Bool::BoolTrue } else { tos::Bool::BoolFalse }
}

fn tl_to_bool(val: &tos::Bool) -> bool {
    matches!(val, tos::Bool::BoolTrue)
}

struct ShowCollatorsListRqRs {}

impl ToFromTL for ShowCollatorsListRqRs {
    type Rq = ();
    type Rs = CollatorsList;

    fn serialize(_: &Self::Rq) -> anyhow::Result<TLObject> {
        Ok(tos::rpc::engine::validator::ShowCollatorsList.into_tl_object())
    }

    fn deserialize(rs: TLObject) -> anyhow::Result<Self::Rs> {
        let list = downcast::<tl_api::tos::engine::validator::CollatorsList>(rs)?;
        let inner = list.only();
        let mut shards = Vec::new();
        for shard_entry in inner.shards {
            let mut collators = Vec::new();
            for c in shard_entry.collators {
                collators.push(CollatorEntry {
                    adnl_id: c.adnl_id.as_slice().to_vec(),
                    workchain: shard_entry.shard_id.workchain,
                    shard: shard_entry.shard_id.shard,
                });
            }
            shards.push(CollatorsListShard {
                workchain: shard_entry.shard_id.workchain,
                shard: shard_entry.shard_id.shard,
                collators,
                self_collate: tl_to_bool(&shard_entry.self_collate),
                select_mode: shard_entry.select_mode.clone(),
            });
        }
        Ok(CollatorsList { shards })
    }
}

struct ShowCollatorNodeWhitelistRqRs {}

impl ToFromTL for ShowCollatorNodeWhitelistRqRs {
    type Rq = ();
    type Rs = CollatorNodeWhitelist;

    fn serialize(_: &Self::Rq) -> anyhow::Result<TLObject> {
        Ok(tos::rpc::engine::validator::ShowCollatorNodeWhitelist.into_tl_object())
    }

    fn deserialize(rs: TLObject) -> anyhow::Result<Self::Rs> {
        let wl = downcast::<tl_api::tos::engine::validator::CollatorNodeWhitelist>(rs)?;
        let inner = wl.only();
        let adnl_ids = inner.adnl_ids.iter().map(|id| hex::encode(id.as_slice())).collect();
        Ok(CollatorNodeWhitelist { enabled: tl_to_bool(&inner.enabled), adnl_ids })
    }
}

struct GetCollatorOptionsJsonRqRs {}

impl ToFromTL for GetCollatorOptionsJsonRqRs {
    type Rq = ();
    type Rs = String;

    fn serialize(_: &Self::Rq) -> anyhow::Result<TLObject> {
        Ok(tos::rpc::engine::validator::GetCollatorOptionsJson.into_tl_object())
    }

    fn deserialize(rs: TLObject) -> anyhow::Result<Self::Rs> {
        let config = downcast::<tl_api::tos::engine::validator::JsonConfig>(rs)?;
        Ok(config.data().clone())
    }
}

struct SetCollatorOptionsJsonRqRs {}

impl ToFromTL for SetCollatorOptionsJsonRqRs {
    type Rq = String;
    type Rs = ();

    fn serialize(json: &Self::Rq) -> anyhow::Result<TLObject> {
        Ok(tos::rpc::engine::validator::SetCollatorOptionsJson { json: json.clone() }
            .into_tl_object())
    }

    fn deserialize(_: TLObject) -> anyhow::Result<Self::Rs> {
        Ok(())
    }
}

struct AddCollatorRqRs {}

impl ToFromTL for AddCollatorRqRs {
    type Rq = AddCollatorRq;
    type Rs = ();

    fn serialize(rq: &Self::Rq) -> anyhow::Result<TLObject> {
        let adnl_id = UInt256::from_raw(rq.adnl_id.clone(), 256);
        Ok(tos::rpc::engine::validator::AddCollator {
            adnl_id,
            shard: tos::tos_node::shardid::ShardId { workchain: rq.workchain, shard: rq.shard },
        }
        .into_tl_object())
    }

    fn deserialize(_: TLObject) -> anyhow::Result<Self::Rs> {
        Ok(())
    }
}

struct DelCollatorRqRs {}

impl ToFromTL for DelCollatorRqRs {
    type Rq = AddCollatorRq;
    type Rs = ();

    fn serialize(rq: &Self::Rq) -> anyhow::Result<TLObject> {
        let adnl_id = UInt256::from_raw(rq.adnl_id.clone(), 256);
        Ok(tos::rpc::engine::validator::DelCollator {
            adnl_id,
            shard: tos::tos_node::shardid::ShardId { workchain: rq.workchain, shard: rq.shard },
        }
        .into_tl_object())
    }

    fn deserialize(_: TLObject) -> anyhow::Result<Self::Rs> {
        Ok(())
    }
}

struct ClearCollatorsListRqRs {}

impl ToFromTL for ClearCollatorsListRqRs {
    type Rq = ();
    type Rs = ();

    fn serialize(_: &Self::Rq) -> anyhow::Result<TLObject> {
        Ok(tos::rpc::engine::validator::ClearCollatorsList.into_tl_object())
    }

    fn deserialize(_: TLObject) -> anyhow::Result<Self::Rs> {
        Ok(())
    }
}

struct CollatorNodeSetWhitelistedValidatorRqRs {}

impl ToFromTL for CollatorNodeSetWhitelistedValidatorRqRs {
    type Rq = CollatorNodeWhitelistRq;
    type Rs = ();

    fn serialize(rq: &Self::Rq) -> anyhow::Result<TLObject> {
        let adnl_id = UInt256::from_raw(rq.adnl_id.clone(), 256);
        Ok(tos::rpc::engine::validator::CollatorNodeSetWhitelistedValidator {
            adnl_id,
            add: bool_to_tl(rq.add),
        }
        .into_tl_object())
    }

    fn deserialize(_: TLObject) -> anyhow::Result<Self::Rs> {
        Ok(())
    }
}

struct CollatorNodeSetWhitelistEnabledRqRs {}

impl ToFromTL for CollatorNodeSetWhitelistEnabledRqRs {
    type Rq = bool;
    type Rs = ();

    fn serialize(enabled: &Self::Rq) -> anyhow::Result<TLObject> {
        Ok(tos::rpc::engine::validator::CollatorNodeSetWhitelistEnabled {
            enabled: bool_to_tl(*enabled),
        }
        .into_tl_object())
    }

    fn deserialize(_: TLObject) -> anyhow::Result<Self::Rs> {
        Ok(())
    }
}

struct GetStatsRqRs {}

impl ToFromTL for GetStatsRqRs {
    type Rq = ();
    type Rs = NodeStats;

    fn serialize(_: &Self::Rq) -> anyhow::Result<TLObject> {
        Ok(tos::rpc::engine::validator::GetStats {}.into_tl_object())
    }

    fn deserialize(rs: TLObject) -> anyhow::Result<Self::Rs> {
        let stats = downcast::<tl_api::tos::engine::validator::Stats>(rs)?;
        let inner = stats.only();
        let pairs = inner.stats.into_iter().map(|s| (s.key.clone(), s.value.clone())).collect();
        Ok(NodeStats { stats: pairs })
    }
}

struct AddQuicAddrRqRs {}

impl ToFromTL for AddQuicAddrRqRs {
    type Rq = (i32, i32, Vec<i32>, Vec<i32>);
    type Rs = ();

    fn serialize(rq: &Self::Rq) -> anyhow::Result<TLObject> {
        let (ip, port, categories, priority_categories) = rq;
        Ok(tos::rpc::engine::validator::AddQuicAddr {
            ip: *ip,
            port: *port,
            categories: categories.clone(),
            priority_categories: priority_categories.clone(),
        }
        .into_tl_object())
    }

    fn deserialize(_: TLObject) -> anyhow::Result<Self::Rs> {
        Ok(())
    }
}

struct AddLiteserverRqRs {}

impl ToFromTL for AddLiteserverRqRs {
    type Rq = AddLiteserverRq;
    type Rs = ();

    fn serialize(rq: &Self::Rq) -> anyhow::Result<TLObject> {
        let key_hash = UInt256::from_raw(rq.key_hash.clone(), 256);
        Ok(tos::rpc::engine::validator::AddLiteserver { key_hash, port: rq.port }.into_tl_object())
    }

    fn deserialize(_: TLObject) -> anyhow::Result<Self::Rs> {
        Ok(())
    }
}

// --- Custom overlay management RqRs adapters ---

/// Convert a `CustomOverlayConfig` (serde-friendly) into the TL `CustomOverlay` struct.
fn custom_overlay_config_to_tl(
    config: &CustomOverlayConfig,
) -> anyhow::Result<tl_api::tos::engine::validator::customoverlay::CustomOverlay> {
    let mut nodes = Vec::new();
    for node in &config.nodes {
        let adnl_bytes = hex::decode(node.adnl_id.trim_start_matches("0x"))
            .map_err(|e| anyhow::anyhow!("Invalid hex ADNL ID '{}': {}", node.adnl_id, e))?;
        if adnl_bytes.len() != 32 {
            anyhow::bail!(
                "ADNL ID must be 32 bytes (64 hex chars), got {} for '{}'",
                adnl_bytes.len(),
                node.adnl_id
            );
        }
        let adnl_id = UInt256::from_raw(adnl_bytes, 256);
        nodes.push(tl_api::tos::engine::validator::customoverlaynode::CustomOverlayNode {
            adnl_id,
            msg_sender: bool_to_tl(node.msg_sender),
            msg_sender_priority: node.msg_sender_priority,
            block_sender: bool_to_tl(node.block_sender),
        });
    }
    let sender_shards = config
        .sender_shards
        .iter()
        .map(|s| tos::tos_node::shardid::ShardId { workchain: s.workchain, shard: s.shard })
        .collect();
    Ok(tl_api::tos::engine::validator::customoverlay::CustomOverlay {
        name: config.name.clone(),
        nodes,
        sender_shards,
        skip_public_msg_send: bool_to_tl(config.skip_public_msg_send),
        use_quic: bool_to_tl(config.use_quic),
    })
}

/// Convert a TL `CustomOverlay` struct back to the serde-friendly `CustomOverlayConfig`.
fn tl_to_custom_overlay_config(
    tl: &tl_api::tos::engine::validator::customoverlay::CustomOverlay,
) -> CustomOverlayConfig {
    let nodes = tl
        .nodes
        .iter()
        .map(|n| CustomOverlayNode {
            adnl_id: hex::encode(n.adnl_id.as_slice()),
            msg_sender: tl_to_bool(&n.msg_sender),
            msg_sender_priority: n.msg_sender_priority,
            block_sender: tl_to_bool(&n.block_sender),
        })
        .collect();
    let sender_shards = tl
        .sender_shards
        .iter()
        .map(|s| ShardDescriptor { workchain: s.workchain, shard: s.shard })
        .collect();
    CustomOverlayConfig {
        name: tl.name.clone(),
        nodes,
        sender_shards,
        skip_public_msg_send: tl_to_bool(&tl.skip_public_msg_send),
        use_quic: tl_to_bool(&tl.use_quic),
    }
}

struct AddCustomOverlayRqRs {}

impl ToFromTL for AddCustomOverlayRqRs {
    type Rq = CustomOverlayConfig;
    type Rs = ();

    fn serialize(config: &Self::Rq) -> anyhow::Result<TLObject> {
        let overlay = custom_overlay_config_to_tl(config)?;
        Ok(tos::rpc::engine::validator::AddCustomOverlay { overlay }.into_tl_object())
    }

    fn deserialize(_: TLObject) -> anyhow::Result<Self::Rs> {
        Ok(())
    }
}

struct DelCustomOverlayRqRs {}

impl ToFromTL for DelCustomOverlayRqRs {
    type Rq = String;
    type Rs = ();

    fn serialize(name: &Self::Rq) -> anyhow::Result<TLObject> {
        Ok(tos::rpc::engine::validator::DelCustomOverlay { name: name.clone() }.into_tl_object())
    }

    fn deserialize(_: TLObject) -> anyhow::Result<Self::Rs> {
        Ok(())
    }
}

struct ShowCustomOverlaysRqRs {}

impl ToFromTL for ShowCustomOverlaysRqRs {
    type Rq = ();
    type Rs = CustomOverlaysConfig;

    fn serialize(_: &Self::Rq) -> anyhow::Result<TLObject> {
        Ok(tos::rpc::engine::validator::ShowCustomOverlays.into_tl_object())
    }

    fn deserialize(rs: TLObject) -> anyhow::Result<Self::Rs> {
        let config = downcast::<tl_api::tos::engine::validator::CustomOverlaysConfig>(rs)?;
        let inner = config.only();
        let overlays = inner.overlays.iter().map(tl_to_custom_overlay_config).collect();
        Ok(CustomOverlaysConfig { overlays })
    }
}

// TOS compatibility: The ADNL control client connects to the TOS validator engine
// control port All engine.validator.* TL methods
// are supported by the TOS node. No changes required for TOS deployment.
pub struct ControlClientAdnl {
    config: AdnlClientConfig,
    adnl: Option<AdnlClient>,
    max_rq_attempts: u32,
}

impl ControlClientAdnl {
    /// Create a new disconnected control client.
    ///
    /// Connection will be established when the first request is made.
    pub fn new(config: AdnlClientConfig, max_rq_attempts: u32) -> Self {
        Self { config, adnl: None, max_rq_attempts }
    }

    /// Create a new disconnected control client from a JSON configuration.
    ///
    /// Connection will be established when the first request is made.
    pub fn new_from_json(config_json: &AdnlClientConfigJson) -> anyhow::Result<Self> {
        let (_, config) = AdnlClientConfig::from_json_config(config_json)?;
        Ok(Self::new(config, 4))
    }

    /// Establish connection to the Control Server via ADNL.
    ///
    /// If connection is already established, do nothing.
    /// It is not necessary to call this method before making requests,
    /// but it can be used to force connection establishment.
    pub async fn connect(&mut self) -> anyhow::Result<()> {
        if self.adnl.is_none() {
            self.adnl = Some(
                AdnlClient::connect(&self.config)
                    .await
                    .context("failed to connect to Control Server")?,
            );
        }
        Ok(())
    }

    /// Shutdown the Control Client.
    ///
    /// If connection is not established, do nothing.
    /// Call this method to ensure the connection is closed.
    pub async fn shutdown(&mut self) -> anyhow::Result<()> {
        if let Some(adnl) = self.adnl.take() {
            adnl.shutdown().await?;
        }
        Ok(())
    }

    /// Health-check the control server by sending `engine.validator.getTime`.
    ///
    /// Returns the round-trip time in seconds. The query is wrapped in
    /// `engine.validator.controlQuery` so it is accepted by the TOS control
    /// interface (which rejects raw `tcp.ping`).
    pub async fn ping(&mut self) -> anyhow::Result<u64> {
        let now = Instant::now();
        let _server_time = self.do_rq::<GetTimeRqRs>(&()).await?;
        Ok(now.elapsed().as_secs())
    }

    pub async fn reconnect(&mut self) -> anyhow::Result<()> {
        if let Some(adnl) = self.adnl.take() {
            if let Err(e) = adnl.shutdown().await {
                tracing::error!(target: "control-client", "failed to shut down ADNL client: {}", e)
            }
        }

        self.adnl = Some(AdnlClient::connect(&self.config).await?);
        Ok(())
    }

    async fn do_rq<T>(&mut self, rq: &T::Rq) -> anyhow::Result<T::Rs>
    where
        T: ToFromTL,
    {
        let tl_object_rq = T::serialize(rq)?;
        let tl_object_rq_boxed =
            ControlQuery { data: serialize_boxed(&tl_object_rq)? }.into_tl_object().into();

        // Establish connection if not established yet
        self.connect().await?;

        let mut attempt = 1;

        loop {
            let adnl = self.adnl.as_mut().context("control client not connected")?;
            let res = adnl.query(&tl_object_rq_boxed).await;

            match res {
                Ok(tl_object) => match tl_object.downcast::<ControlQueryError>() {
                    Err(tl_object_rs) => match T::deserialize(tl_object_rs) {
                        Err(err) => {
                            anyhow::bail!("Wrong response to {:?}: {:?}", tl_object_rq, err)
                        }
                        Ok(result) => return Ok(result),
                    },
                    Ok(error) => anyhow::bail!("Error response to {:?}: {:?}", tl_object_rq, error),
                },
                Err(err) => {
                    tracing::debug!(target: "control-client", "control query error: {}", err);
                    if attempt >= self.max_rq_attempts {
                        tracing::error!(target: "control-client", "max reconnecting attempts reached");
                        anyhow::bail!("control query error: {}", err)
                    }

                    tracing::debug!( target: "control-client",
                        "reconnect and repeat request: attempt {}/{}",
                        attempt,
                        self.max_rq_attempts,
                    );

                    self.reconnect().await?;
                    attempt += 1;
                    continue;
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl ClientAPI for ControlClientAdnl {
    async fn get_account_state(&mut self, address: &str) -> anyhow::Result<Account> {
        self.do_rq::<GetAccountRqRs>(&address.to_string()).await
    }

    async fn get_blockchain_config(&mut self) -> anyhow::Result<BlockchainConfigInfo> {
        self.do_rq::<GetBlockchainConfigRqRs>(&()).await
    }

    async fn get_validator_config(&mut self) -> anyhow::Result<EngineValidatorConfig> {
        self.do_rq::<GetValidatorConfigRqRs>(&()).await
    }

    async fn get_config_param(&mut self, id: u32) -> anyhow::Result<Vec<u8>> {
        self.do_rq::<GetConfigParamRqRs>(&id).await
    }

    async fn sign(&mut self, rq: &SignRq) -> anyhow::Result<Vec<u8>> {
        self.do_rq::<SignRqRs>(rq).await
    }

    async fn generate_key_pair(&mut self) -> anyhow::Result<Vec<u8>> {
        self.do_rq::<GenerateKeyPairRqRs>(&()).await
    }

    async fn export_key_pub(&mut self, key_hash: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.do_rq::<ExportKeyPubRqRs>(&key_hash.to_vec()).await
    }

    async fn add_validator_perm_key(&mut self, rq: &AddValidatorPermKeyRq) -> anyhow::Result<()> {
        self.do_rq::<AddValidatorPermKeyRqRs>(rq).await
    }

    async fn add_validator_temp_key(&mut self, rq: &AddValidatorTempKeyRq) -> anyhow::Result<()> {
        self.do_rq::<AddValidatorTempKeyRqRs>(rq).await
    }

    async fn add_adnl_address(&mut self, rq: &AddAdnlAddressRq) -> anyhow::Result<()> {
        self.do_rq::<AddAdnlAddressRqRs>(rq).await
    }

    async fn add_validator_adnl_addr(&mut self, rq: &AddValidatorAdnlAddrRq) -> anyhow::Result<()> {
        self.do_rq::<AddValidatorAdnlAddrRqRs>(rq).await
    }

    async fn send_boc(&mut self, boc: &[u8]) -> anyhow::Result<()> {
        self.do_rq::<SendBocRqRs>(&boc.to_vec()).await
    }

    // --- Collator management ---

    async fn show_collators_list(&mut self) -> anyhow::Result<CollatorsList> {
        self.do_rq::<ShowCollatorsListRqRs>(&()).await
    }

    async fn show_collator_node_whitelist(&mut self) -> anyhow::Result<CollatorNodeWhitelist> {
        self.do_rq::<ShowCollatorNodeWhitelistRqRs>(&()).await
    }

    async fn get_collator_options_json(&mut self) -> anyhow::Result<String> {
        self.do_rq::<GetCollatorOptionsJsonRqRs>(&()).await
    }

    async fn set_collator_options_json(&mut self, json: &str) -> anyhow::Result<()> {
        self.do_rq::<SetCollatorOptionsJsonRqRs>(&json.to_string()).await
    }

    async fn add_collator(&mut self, rq: &AddCollatorRq) -> anyhow::Result<()> {
        self.do_rq::<AddCollatorRqRs>(rq).await
    }

    async fn del_collator(&mut self, rq: &AddCollatorRq) -> anyhow::Result<()> {
        self.do_rq::<DelCollatorRqRs>(rq).await
    }

    async fn clear_collators_list(&mut self) -> anyhow::Result<()> {
        self.do_rq::<ClearCollatorsListRqRs>(&()).await
    }

    async fn collator_node_set_whitelisted_validator(
        &mut self,
        rq: &CollatorNodeWhitelistRq,
    ) -> anyhow::Result<()> {
        self.do_rq::<CollatorNodeSetWhitelistedValidatorRqRs>(rq).await
    }

    async fn collator_node_set_whitelist_enabled(&mut self, enabled: bool) -> anyhow::Result<()> {
        self.do_rq::<CollatorNodeSetWhitelistEnabledRqRs>(&enabled).await
    }

    async fn get_stats(&mut self) -> anyhow::Result<NodeStats> {
        self.do_rq::<GetStatsRqRs>(&()).await
    }

    async fn add_liteserver(&mut self, rq: &AddLiteserverRq) -> anyhow::Result<()> {
        self.do_rq::<AddLiteserverRqRs>(rq).await
    }

    async fn add_quic_addr(
        &mut self,
        ip: i32,
        port: i32,
        categories: Vec<i32>,
        priority_categories: Vec<i32>,
    ) -> anyhow::Result<()> {
        self.do_rq::<AddQuicAddrRqRs>(&(ip, port, categories, priority_categories)).await
    }

    // --- Custom overlay management ---

    async fn add_custom_overlay(&mut self, config: &CustomOverlayConfig) -> anyhow::Result<()> {
        self.do_rq::<AddCustomOverlayRqRs>(config).await
    }

    async fn del_custom_overlay(&mut self, name: &str) -> anyhow::Result<()> {
        self.do_rq::<DelCustomOverlayRqRs>(&name.to_string()).await
    }

    async fn show_custom_overlays(&mut self) -> anyhow::Result<CustomOverlaysConfig> {
        self.do_rq::<ShowCustomOverlaysRqRs>(&()).await
    }
}

#[async_trait::async_trait]
impl Shutdown for ControlClientAdnl {
    async fn shutdown(&mut self) -> anyhow::Result<()> {
        ControlClientAdnl::shutdown(self).await
    }
}
