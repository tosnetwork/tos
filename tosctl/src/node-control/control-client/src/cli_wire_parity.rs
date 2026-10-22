//! Compare the real request adapters with native-produced bytes.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
#[path = "../../../../../test/tl-cli/values.rs"]
mod values;
use values::*;

fn verify<T: ToFromTL>(name: &str, request: &T::Rq, fixtures: &BTreeMap<String, Vec<u8>>) {
    let query =
        T::serialize(request).unwrap_or_else(|error| panic!("CLI_REQUEST_SETUP {name}: {error}"));
    let bytes = serialize_boxed(&query).expect("production request encoding");
    assert_eq!(
        &bytes,
        fixtures.get(name).expect("native request fixture"),
        "CLI_REQUEST_BYTES {name}"
    );
    let outer = ControlQuery { data: bytes }.into_tl_object();
    assert_eq!(
        serialize_boxed(&outer).expect("production envelope"),
        fixtures[&format!("control/{name}")],
        "CLI_ENVELOPE_BYTES {name}"
    );
}

#[test]
fn production_request_serializers_match_cpp_and_have_complete_coverage() {
    let fixtures: BTreeMap<String, Vec<u8>> =
        include_str!("../../../../../test/tl-cli/fixtures.tsv")
            .lines()
            .map(|line| {
                let (name, wire) = line.split_once('\t').expect("fixture columns");
                (name.to_string(), hex::decode(wire).expect("native fixture"))
            })
            .collect();
    let mut checked = BTreeSet::new();
    macro_rules! case {
        ($adapter:ty, $name:literal, $q:ident = $factory:expr, $request:expr) => {{
            let $q = $factory;
            verify::<$adapter>($name, &$request, &fixtures);
            checked.insert(stringify!($adapter).to_string());
        }};
    }
    macro_rules! unit {
        ($adapter:ty, $name:literal) => {{
            verify::<$adapter>($name, &(), &fixtures);
            checked.insert(stringify!($adapter).to_string());
        }};
    }
    macro_rules! timed {
        ($adapter:ty, $name:literal, $q:ident = $factory:expr, $now:ident, $request:expr) => {{
            let $q = $factory;
            let mut stable = false;
            for _ in 0..3 {
                let $now = UnixTime::now() as i32;
                let request = $request;
                let encoded = <$adapter>::serialize(&request).expect("time-based request");
                if UnixTime::now() as i32 == $now {
                    assert_eq!(
                        serialize_boxed(&encoded).expect("encoded request"),
                        fixtures[$name],
                        "CLI_REQUEST_BYTES {}",
                        $name
                    );
                    stable = true;
                    break;
                }
            }
            assert!(stable, "CLI_REQUEST_CLOCK_BOUNDARY {}", $name);
            checked.insert(stringify!($adapter).to_string());
        }};
    }
    case!(
        GetElectorStateRqRs,
        "engine.validator.getElectorState",
        q = make_tos_api_engine_validator_getelectorstate(16),
        ElectorStateRequest {
            block: q.block,
            wallets: q.wallets.iter().map(|v| *v.as_slice()).collect()
        }
    );
    case!(
        GetConfigProposalsRqRs,
        "engine.validator.getConfigProposals",
        q = make_tos_api_engine_validator_getconfigproposals(16),
        ConfigProposalsRequest { block: q.block }
    );
    case!(
        GetConfigProposalRqRs,
        "engine.validator.getConfigProposal",
        q = make_tos_api_engine_validator_getconfigproposal(16),
        ConfigProposalRequest { block: q.block, hash: *q.hash.as_slice() }
    );
    unit!(GetBlockchainConfigRqRs, "liteServer.getConfigAll");
    unit!(GetValidatorConfigRqRs, "engine.validator.getConfig");
    case!(
        GetConfigParamRqRs,
        "liteServer.getConfigParams",
        q = make_lite_api_liteserver_getconfigparams(16),
        u32::try_from(q.param_list[0]).expect("parameter id")
    );
    case!(
        SignRqRs,
        "engine.validator.sign",
        q = make_tos_api_engine_validator_sign(16),
        SignRq { key_hash: q.key_hash.as_slice().to_vec(), data: q.data }
    );
    case!(
        CreatePqStakeAuthorizationRqRs,
        "engine.validator.createPqStakeAuthorization",
        q = make_tos_api_engine_validator_createpqstakeauthorization(16),
        CreatePqStakeAuthorizationRq {
            election_date: q.election_date as u32,
            max_factor: q.max_factor as u32,
            adnl_addr: q.adnl_addr.as_slice().to_vec(),
            stake_owner: q.stake_owner.as_slice().to_vec()
        }
    );
    unit!(GenerateKeyPairRqRs, "engine.validator.generateKeyPair");
    case!(
        ExportKeyPubRqRs,
        "engine.validator.exportPublicKey",
        q = make_tos_api_engine_validator_exportpublickey(16),
        q.key_hash.as_slice().to_vec()
    );
    case!(
        AddValidatorPermKeyRqRs,
        "engine.validator.addValidatorPermanentKey",
        q = make_tos_api_engine_validator_addvalidatorpermanentkey(16),
        AddValidatorPermKeyRq {
            key_hash: q.key_hash.as_slice().to_vec(),
            election_date: q.election_date,
            expire_at: q.election_date.checked_add(q.ttl).expect("expiry")
        }
    );
    timed!(
        AddValidatorTempKeyRqRs,
        "engine.validator.addValidatorTempKey",
        q = make_tos_api_engine_validator_addvalidatortempkey(16),
        now,
        AddValidatorTempKeyRq {
            perm_key_hash: q.permanent_key_hash.as_slice().to_vec(),
            key_hash: q.key_hash.as_slice().to_vec(),
            expire_at: now.checked_add(q.ttl).expect("expiry")
        }
    );
    case!(
        AddAdnlAddressRqRs,
        "engine.validator.addAdnlId",
        q = make_tos_api_engine_validator_addadnlid(16),
        AddAdnlAddressRq { key_hash: q.key_hash.as_slice().to_vec(), category: q.category }
    );
    timed!(
        AddValidatorAdnlAddrRqRs,
        "engine.validator.addValidatorAdnlAddress",
        q = make_tos_api_engine_validator_addvalidatoradnladdress(16),
        now,
        AddValidatorAdnlAddrRq {
            perm_key_hash: q.permanent_key_hash.as_slice().to_vec(),
            key_hash: q.key_hash.as_slice().to_vec(),
            expire_at: now.checked_add(q.ttl).expect("expiry")
        }
    );
    case!(
        SendBocRqRs,
        "liteServer.sendMessage",
        q = make_lite_api_liteserver_sendmessage(16),
        q.body
    );
    unit!(GetTimeRqRs, "engine.validator.getTime");
    unit!(ShowCollatorsListRqRs, "engine.validator.showCollatorsList");
    unit!(ShowCollatorNodeWhitelistRqRs, "engine.validator.showCollatorNodeWhitelist");
    unit!(GetCollatorOptionsJsonRqRs, "engine.validator.getCollatorOptionsJson");
    case!(
        SetCollatorOptionsJsonRqRs,
        "engine.validator.setCollatorOptionsJson",
        q = make_tos_api_engine_validator_setcollatoroptionsjson(16),
        q.json
    );
    case!(
        AddCollatorRqRs,
        "engine.validator.addCollator",
        q = make_tos_api_engine_validator_addcollator(16),
        AddCollatorRq {
            adnl_id: q.adnl_id.as_slice().to_vec(),
            workchain: q.shard.workchain,
            shard: q.shard.shard
        }
    );
    case!(
        DelCollatorRqRs,
        "engine.validator.delCollator",
        q = make_tos_api_engine_validator_delcollator(16),
        AddCollatorRq {
            adnl_id: q.adnl_id.as_slice().to_vec(),
            workchain: q.shard.workchain,
            shard: q.shard.shard
        }
    );
    unit!(ClearCollatorsListRqRs, "engine.validator.clearCollatorsList");
    case!(
        CollatorNodeSetWhitelistedValidatorRqRs,
        "engine.validator.collatorNodeSetWhitelistedValidator",
        q = make_tos_api_engine_validator_collatornodesetwhitelistedvalidator(16),
        CollatorNodeWhitelistRq { adnl_id: q.adnl_id.as_slice().to_vec(), add: tl_to_bool(&q.add) }
    );
    case!(
        CollatorNodeSetWhitelistEnabledRqRs,
        "engine.validator.collatorNodeSetWhitelistEnabled",
        q = make_tos_api_engine_validator_collatornodesetwhitelistenabled(16),
        tl_to_bool(&q.enabled)
    );
    unit!(GetStatsRqRs, "engine.validator.getStats");
    case!(
        AddQuicAddrRqRs,
        "engine.validator.addQuicAddr",
        q = make_tos_api_engine_validator_addquicaddr(16),
        (q.ip, q.port, q.categories, q.priority_categories)
    );
    case!(
        AddLiteserverRqRs,
        "engine.validator.addLiteserver",
        q = make_tos_api_engine_validator_addliteserver(16),
        AddLiteserverRq { key_hash: q.key_hash.as_slice().to_vec(), port: q.port }
    );
    case!(
        AddCustomOverlayRqRs,
        "engine.validator.addCustomOverlay",
        q = make_tos_api_engine_validator_addcustomoverlay(16),
        tl_to_custom_overlay_config(&q.overlay)
    );
    case!(
        DelCustomOverlayRqRs,
        "engine.validator.delCustomOverlay",
        q = make_tos_api_engine_validator_delcustomoverlay(16),
        q.name
    );
    unit!(ShowCustomOverlaysRqRs, "engine.validator.showCustomOverlays");
    let mut declared = BTreeSet::new();
    for source in [include_str!("client_adnl.rs"), include_str!("operator_requests.rs")] {
        for line in source.lines() {
            if let Some(name) = line.strip_prefix("impl ToFromTL for ") {
                declared.insert(name.trim_end_matches(" {").to_string());
            }
        }
    }
    assert_eq!(checked, declared, "CLI_REQUEST_COVERAGE");
}
