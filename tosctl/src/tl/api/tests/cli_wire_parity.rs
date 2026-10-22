#[path = "../../../../../test/tl-cli/values.rs"]
mod values;
use tl_api::IntoBoxed;
use values::*;

fn check<T>(
    name: &str,
    expected: T,
    fixtures: &std::collections::BTreeMap<String, Vec<u8>>,
    output: &mut String,
) where
    T: tl_api::BoxedSerialize + tl_api::BoxedDeserialize + PartialEq + std::fmt::Debug,
{
    let wire = fixtures.get(name).unwrap_or_else(|| panic!("CLI_WIRE_MISSING {name}"));
    let mut remaining = wire.as_slice();
    let actual: T = tl_api::Deserializer::new(&mut remaining)
        .read_boxed()
        .unwrap_or_else(|error| panic!("CLI_WIRE_PARSE {name}: {error}"));
    assert!(remaining.is_empty(), "CLI_WIRE_TRAILING {name}");
    assert_eq!(actual, expected, "CLI_WIRE_FIELDS {name}");
    let encoded = tl_api::serialize_boxed(&expected).expect("encode expected typed fields");
    assert_eq!(&encoded, wire, "CLI_WIRE_BYTES {name}");
    output.push_str(&format!("{name}\t{}\n", hex::encode(encoded)));
}
#[test]
fn native_cli_wire_fields_and_reverse_encoding() {
    let text = include_str!("../../../../../test/tl-cli/fixtures.tsv");
    let mut fixtures = std::collections::BTreeMap::new();
    for line in text.lines() {
        let (name, bytes) = line.split_once('\t').expect("fixture columns");
        assert!(
            fixtures.insert(name.to_string(), hex::decode(bytes).expect("native bytes")).is_none(),
            "CLI_WIRE_DUPLICATE"
        );
    }
    let mut output = String::new();
    check(
        "engine.validator.getElectorState",
        make_tos_api_engine_validator_getelectorstate(16),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.getConfigProposals",
        make_tos_api_engine_validator_getconfigproposals(16),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.getConfigProposal",
        make_tos_api_engine_validator_getconfigproposal(16),
        &fixtures,
        &mut output,
    );
    check(
        "liteServer.getConfigAll",
        make_lite_api_liteserver_getconfigall(16),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.getConfig",
        make_tos_api_engine_validator_getconfig(16),
        &fixtures,
        &mut output,
    );
    check(
        "liteServer.getConfigParams",
        make_lite_api_liteserver_getconfigparams(16),
        &fixtures,
        &mut output,
    );
    check("engine.validator.sign", make_tos_api_engine_validator_sign(16), &fixtures, &mut output);
    check(
        "engine.validator.createPqStakeAuthorization",
        make_tos_api_engine_validator_createpqstakeauthorization(16),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.generateKeyPair",
        make_tos_api_engine_validator_generatekeypair(16),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.exportPublicKey",
        make_tos_api_engine_validator_exportpublickey(16),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.addValidatorPermanentKey",
        make_tos_api_engine_validator_addvalidatorpermanentkey(16),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.addValidatorTempKey",
        make_tos_api_engine_validator_addvalidatortempkey(16),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.addAdnlId",
        make_tos_api_engine_validator_addadnlid(16),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.addValidatorAdnlAddress",
        make_tos_api_engine_validator_addvalidatoradnladdress(16),
        &fixtures,
        &mut output,
    );
    check(
        "liteServer.sendMessage",
        make_lite_api_liteserver_sendmessage(16),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.getTime",
        make_tos_api_engine_validator_gettime(16),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.showCollatorsList",
        make_tos_api_engine_validator_showcollatorslist(16),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.showCollatorNodeWhitelist",
        make_tos_api_engine_validator_showcollatornodewhitelist(16),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.getCollatorOptionsJson",
        make_tos_api_engine_validator_getcollatoroptionsjson(16),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.setCollatorOptionsJson",
        make_tos_api_engine_validator_setcollatoroptionsjson(16),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.addCollator",
        make_tos_api_engine_validator_addcollator(16),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.delCollator",
        make_tos_api_engine_validator_delcollator(16),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.clearCollatorsList",
        make_tos_api_engine_validator_clearcollatorslist(16),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.collatorNodeSetWhitelistedValidator",
        make_tos_api_engine_validator_collatornodesetwhitelistedvalidator(16),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.collatorNodeSetWhitelistEnabled",
        make_tos_api_engine_validator_collatornodesetwhitelistenabled(16),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.getStats",
        make_tos_api_engine_validator_getstats(16),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.addQuicAddr",
        make_tos_api_engine_validator_addquicaddr(16),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.addLiteserver",
        make_tos_api_engine_validator_addliteserver(16),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.addCustomOverlay",
        make_tos_api_engine_validator_addcustomoverlay(16),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.delCustomOverlay",
        make_tos_api_engine_validator_delcustomoverlay(16),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.showCustomOverlays",
        make_tos_api_engine_validator_showcustomoverlays(16),
        &fixtures,
        &mut output,
    );
    check(
        "adnl.stats.localId",
        make_tos_api_adnl_stats_localid(16).into_boxed(),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.collatorOptions",
        make_tos_api_engine_validator_collatoroptions(16).into_boxed(),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.config",
        make_tos_api_engine_validator_config(16).into_boxed(),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.extraConfig",
        make_tos_api_engine_validator_extraconfig(16).into_boxed(),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.overlayStats",
        make_tos_api_engine_validator_overlaystats(16).into_boxed(),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.overlayStatsNode",
        make_tos_api_engine_validator_overlaystatsnode(16).into_boxed(),
        &fixtures,
        &mut output,
    );
    check("liteserver.desc", make_tos_api_liteserver_desc(16).into_boxed(), &fixtures, &mut output);
    check(
        "liteserver.descV2",
        make_tos_api_liteserver_descv2(16).into_boxed(),
        &fixtures,
        &mut output,
    );
    check(
        "raw.extMessageInfo",
        make_toslib_api_raw_extmessageinfo(16).into_boxed(),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.shardBlockVerifierConfig.shard",
        make_tos_api_engine_validator_shardblockverifierconfig_shard(16).into_boxed(),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.controlQueryError",
        make_tos_api_engine_validator_controlqueryerror(16).into_boxed(),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.time",
        make_tos_api_engine_validator_time(16).into_boxed(),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.signature",
        make_tos_api_engine_validator_signature(16).into_boxed(),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.keyHash",
        make_tos_api_engine_validator_keyhash(16).into_boxed(),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.jsonConfig",
        make_tos_api_engine_validator_jsonconfig(16).into_boxed(),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.success",
        make_tos_api_engine_validator_success(16),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.stats",
        make_tos_api_engine_validator_stats(16).into_boxed(),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.collatorsList",
        make_tos_api_engine_validator_collatorslist(16).into_boxed(),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.collatorNodeWhitelist",
        make_tos_api_engine_validator_collatornodewhitelist(16).into_boxed(),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.customOverlaysConfig",
        make_tos_api_engine_validator_customoverlaysconfig(16).into_boxed(),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.electorState",
        make_tos_api_engine_validator_electorstate(16).into_boxed(),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.configProposals",
        make_tos_api_engine_validator_configproposals(16).into_boxed(),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.configProposalDetail",
        make_tos_api_engine_validator_configproposaldetail(16).into_boxed(),
        &fixtures,
        &mut output,
    );
    {
        let mut query = make_tos_api_engine_validator_getelectorstate(16);
        query.block = Some(make_tos_api_tosnode_blockidext(16));
        check("engine.validator.getElectorState/with-block", query, &fixtures, &mut output);
    }
    {
        let mut query = make_tos_api_engine_validator_getconfigproposals(16);
        query.block = Some(make_tos_api_tosnode_blockidext(16));
        check("engine.validator.getConfigProposals/with-block", query, &fixtures, &mut output);
    }
    {
        let mut query = make_tos_api_engine_validator_getconfigproposal(16);
        query.block = Some(make_tos_api_tosnode_blockidext(16));
        check("engine.validator.getConfigProposal/with-block", query, &fixtures, &mut output);
    }
    check(
        "control/engine.validator.getElectorState",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(&make_tos_api_engine_validator_getelectorstate(16))
                .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/engine.validator.getConfigProposals",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(&make_tos_api_engine_validator_getconfigproposals(16))
                .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/engine.validator.getConfigProposal",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(&make_tos_api_engine_validator_getconfigproposal(16))
                .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/liteServer.getConfigAll",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(&make_lite_api_liteserver_getconfigall(16))
                .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/engine.validator.getConfig",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(&make_tos_api_engine_validator_getconfig(16))
                .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/liteServer.getConfigParams",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(&make_lite_api_liteserver_getconfigparams(16))
                .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/engine.validator.sign",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(&make_tos_api_engine_validator_sign(16))
                .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/engine.validator.createPqStakeAuthorization",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(
                &make_tos_api_engine_validator_createpqstakeauthorization(16),
            )
            .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/engine.validator.generateKeyPair",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(&make_tos_api_engine_validator_generatekeypair(16))
                .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/engine.validator.exportPublicKey",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(&make_tos_api_engine_validator_exportpublickey(16))
                .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/engine.validator.addValidatorPermanentKey",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(&make_tos_api_engine_validator_addvalidatorpermanentkey(
                16,
            ))
            .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/engine.validator.addValidatorTempKey",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(&make_tos_api_engine_validator_addvalidatortempkey(16))
                .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/engine.validator.addAdnlId",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(&make_tos_api_engine_validator_addadnlid(16))
                .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/engine.validator.addValidatorAdnlAddress",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(&make_tos_api_engine_validator_addvalidatoradnladdress(
                16,
            ))
            .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/liteServer.sendMessage",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(&make_lite_api_liteserver_sendmessage(16))
                .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/engine.validator.getTime",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(&make_tos_api_engine_validator_gettime(16))
                .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/engine.validator.showCollatorsList",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(&make_tos_api_engine_validator_showcollatorslist(16))
                .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/engine.validator.showCollatorNodeWhitelist",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(
                &make_tos_api_engine_validator_showcollatornodewhitelist(16),
            )
            .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/engine.validator.getCollatorOptionsJson",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(&make_tos_api_engine_validator_getcollatoroptionsjson(
                16,
            ))
            .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/engine.validator.setCollatorOptionsJson",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(&make_tos_api_engine_validator_setcollatoroptionsjson(
                16,
            ))
            .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/engine.validator.addCollator",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(&make_tos_api_engine_validator_addcollator(16))
                .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/engine.validator.delCollator",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(&make_tos_api_engine_validator_delcollator(16))
                .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/engine.validator.clearCollatorsList",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(&make_tos_api_engine_validator_clearcollatorslist(16))
                .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/engine.validator.collatorNodeSetWhitelistedValidator",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(
                &make_tos_api_engine_validator_collatornodesetwhitelistedvalidator(16),
            )
            .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/engine.validator.collatorNodeSetWhitelistEnabled",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(
                &make_tos_api_engine_validator_collatornodesetwhitelistenabled(16),
            )
            .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/engine.validator.getStats",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(&make_tos_api_engine_validator_getstats(16))
                .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/engine.validator.addQuicAddr",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(&make_tos_api_engine_validator_addquicaddr(16))
                .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/engine.validator.addLiteserver",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(&make_tos_api_engine_validator_addliteserver(16))
                .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/engine.validator.addCustomOverlay",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(&make_tos_api_engine_validator_addcustomoverlay(16))
                .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/engine.validator.delCustomOverlay",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(&make_tos_api_engine_validator_delcustomoverlay(16))
                .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "control/engine.validator.showCustomOverlays",
        tl_api::tos::rpc::engine::validator::ControlQuery {
            data: tl_api::serialize_boxed(&make_tos_api_engine_validator_showcustomoverlays(16))
                .expect("inner query"),
        },
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.sign/bytes-0",
        make_tos_api_engine_validator_sign(0),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.sign/bytes-1",
        make_tos_api_engine_validator_sign(1),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.sign/bytes-253",
        make_tos_api_engine_validator_sign(253),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.sign/bytes-254",
        make_tos_api_engine_validator_sign(254),
        &fixtures,
        &mut output,
    );
    check(
        "engine.validator.sign/bytes-255",
        make_tos_api_engine_validator_sign(255),
        &fixtures,
        &mut output,
    );
    check(
        "liteServer.sendMessage/bytes-0",
        make_lite_api_liteserver_sendmessage(0),
        &fixtures,
        &mut output,
    );
    check(
        "liteServer.sendMessage/bytes-1",
        make_lite_api_liteserver_sendmessage(1),
        &fixtures,
        &mut output,
    );
    check(
        "liteServer.sendMessage/bytes-253",
        make_lite_api_liteserver_sendmessage(253),
        &fixtures,
        &mut output,
    );
    check(
        "liteServer.sendMessage/bytes-254",
        make_lite_api_liteserver_sendmessage(254),
        &fixtures,
        &mut output,
    );
    check(
        "liteServer.sendMessage/bytes-255",
        make_lite_api_liteserver_sendmessage(255),
        &fixtures,
        &mut output,
    );
    assert_eq!(fixtures.len(), 98, "CLI_WIRE_CASE_COUNT");
    if let Ok(path) = std::env::var("TL_CLI_REVERSE_OUTPUT") {
        std::fs::write(path, output).expect("reverse bytes");
    }
}

#[test]
fn retired_stream_constructor_is_not_registered() {
    use tl_api::BoxedDeserialize;
    let retired = 0x46efae62u32;
    assert!(
        !tl_api::TLObject::possible_constructors().contains(&retired),
        "RETIRED_STREAM_REGISTERED"
    );
    let bytes = retired.to_le_bytes();
    let error = tl_api::deserialize_boxed(&bytes).expect_err("retired constructor must refuse");
    let invalid =
        error.downcast_ref::<tl_api::InvalidConstructor>().expect("RETIRED_STREAM_WRONG_REFUSAL");
    assert_eq!(invalid.received, retired, "RETIRED_STREAM_REFUSAL_TAG");
}
