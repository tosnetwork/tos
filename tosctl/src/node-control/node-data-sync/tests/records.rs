use anyhow::Result;
use node_data_sync::{
    model::FullId,
    records::{ChainRecords, Key, LocalRecords, Record, reconcile_forks},
};
use std::collections::BTreeSet;
use tl_api::{IntoBoxed, tos::db::state};
fn block(n: i32) -> chain_block::BlockIdExt {
    chain_block::BlockIdExt::with_params(
        chain_block::ShardIdent::masterchain(),
        n as u32,
        chain_block::UInt256::from([0x12; 32]),
        chain_block::UInt256::from([0x34; 32]),
    )
}
fn chain(forks: Vec<chain_block::BlockIdExt>) -> Result<ChainRecords> {
    let values = vec![
        (
            Key::Version,
            tl_api::serialize_boxed(&state::dbversion::DbVersion { version: 2 }.into_boxed())?,
        ),
        (
            Key::Init,
            tl_api::serialize_boxed(
                &state::initblockid::InitBlockId { block: block(1) }.into_boxed(),
            )?,
        ),
        (
            Key::Gc,
            tl_api::serialize_boxed(&state::gcblockid::GcBlockId { block: block(2) }.into_boxed())?,
        ),
        (
            Key::ShardClient,
            tl_api::serialize_boxed(
                &state::shardclient::ShardClient { block: block(10) }.into_boxed(),
            )?,
        ),
        (
            Key::Hardforks,
            tl_api::serialize_boxed(&state::hardforks::Hardforks { blocks: forks }.into_boxed())?,
        ),
    ];
    Ok(ChainRecords {
        records: values
            .into_iter()
            .map(|(key, value)| Record { key, value: Some(value) })
            .collect(),
    })
}
#[test]
fn typed_stream_rejects_local_keys_unknown_keys_duplicates_and_trailing_bytes() -> Result<()> {
    let records = chain(vec![])?;
    let bytes = records.bytes()?;
    assert_eq!(ChainRecords::parse(&bytes)?, records);
    let mut bad = records.clone();
    bad.records.push(Record { key: Key::DestroyedSessions, value: None });
    assert!(bad.bytes().is_err());
    let mut bad = records.clone();
    bad.records.push(bad.records[0].clone());
    assert!(bad.bytes().is_err());
    let mut bad = records.clone();
    bad.records[0].value.as_mut().unwrap().push(0);
    assert!(bad.bytes().is_err());
    let mut bad = bytes;
    bad.push(0);
    assert!(ChainRecords::parse(&bad).is_err());
    let mut bad = records.clone();
    bad.records.push(Record { key: Key::PersistentShards(1), value: Some(vec![]) });
    assert!(bad.bytes().is_err());
    Ok(())
}
#[test]
fn fork_reconciliation_uses_held_policy_imported_history_old_prefix_and_ancestry() -> Result<()> {
    let fork = FullId::from_native(&block(5));
    let donor = chain(vec![block(5)])?;
    let ancestry = BTreeSet::from([fork.clone()]);
    reconcile_forks(std::slice::from_ref(&fork), &donor, &[], &ancestry)?;
    reconcile_forks(std::slice::from_ref(&fork), &donor, std::slice::from_ref(&fork), &ancestry)?;
    assert!(reconcile_forks(&[], &donor, &[], &ancestry).is_err());
    assert!(
        reconcile_forks(
            std::slice::from_ref(&fork),
            &donor,
            &[FullId::from_native(&block(4))],
            &ancestry
        )
        .is_err()
    );
    assert!(reconcile_forks(std::slice::from_ref(&fork), &donor, &[], &BTreeSet::new()).is_err());
    let future = FullId::from_native(&block(11));
    assert!(
        reconcile_forks(
            std::slice::from_ref(&future),
            &chain(vec![block(11)])?,
            &[],
            &BTreeSet::from([future.clone()])
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn preservation_distinguishes_absence_empty_and_arbitrary_existing_bytes() -> Result<()> {
    let local = LocalRecords {
        records: vec![
            Record { key: Key::DestroyedSessions, value: Some(vec![]) },
            Record { key: Key::PendingObserverCleanup, value: None },
            Record { key: Key::PendingValidatorCleanup([0xab; 32]), value: Some(vec![0, 1, 2]) },
        ],
    };
    local.validate()?;
    assert_ne!(local.records[0].value, local.records[1].value);
    let mut bad = local;
    bad.records.push(Record { key: Key::Version, value: None });
    assert!(bad.validate().is_err());
    Ok(())
}

#[test]
fn publication_checks_metadata_and_pruning_respects_capture_and_restore_leases() -> Result<()> {
    use chain_block::{Block, BlockInfo, Serializable, ShardIdent, ShardStateUnsplit};
    use node_data_sync::{
        cas::Objects,
        catalog::Catalog,
        model::{Manifest, NativeValidation, Network, SignedManifest, sha256},
        safe_io::Root,
    };
    let temp = tempfile::tempdir()?;
    let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let trusted = key.verifying_key().to_bytes();
    let catalog = Catalog::create(&temp.path().join("store"), trusted)?;
    let objects = Objects::open(&temp.path().join("store"))?;
    let mut zero = ShardStateUnsplit::with_ident(ShardIdent::masterchain());
    zero.set_global_id(3);
    let zero_boc = zero.write_to_bytes()?;
    let zero_id = FullId {
        workchain: -1,
        shard: i64::MIN,
        seqno: 0,
        root_hash: hex::encode(zero.serialize()?.repr_hash().as_slice()),
        file_hash: sha256(&zero_boc),
    };
    let mut info = BlockInfo::default();
    info.set_shard(ShardIdent::masterchain());
    info.set_seq_no(10)?;
    info.set_gen_utime(900);
    let block =
        Block::with_params(3, info, Default::default(), Default::default(), Default::default())?;
    let tip_boc = block.write_to_bytes()?;
    let tip = FullId {
        workchain: -1,
        shard: i64::MIN,
        seqno: 10,
        root_hash: hex::encode(block.serialize()?.repr_hash().as_slice()),
        file_hash: sha256(&tip_boc),
    };
    let mut records = chain(vec![])?;
    let shard = records.records.iter_mut().find(|r| r.key == Key::ShardClient).unwrap();
    shard.value = Some(tl_api::serialize_boxed(
        &state::shardclient::ShardClient { block: tip.native()? }.into_boxed(),
    )?);
    let source = Root::create(&temp.path().join("source"))?;
    source.write_new("zero", &zero_boc)?;
    source.write_new("tip", &tip_boc)?;
    source.write_new("records", &records.bytes()?)?;
    let writer = objects.writer()?;
    assert!(catalog.prune().is_err(), "pruner bypassed active capture");
    let mut files = vec![
        writer.put("metadata/zero-state.boc", source.read("zero", 1 << 20)?, 1 << 20)?,
        writer.put("metadata/tip-block.boc", source.read("tip", 1 << 20)?, 1 << 20)?,
        writer.put("state-records.cbor", source.read("records", 1 << 20)?, 1 << 20)?,
    ];
    files.sort_by(|a, b| a.path.cmp(&b.path));
    drop(writer);
    let mut manifest = Manifest {
        format: 1,
        network: Network { global_id: 3, zero: zero_id.clone(), init: zero_id },
        frontier: tip.clone(),
        frontier_utime: 900,
        created_utc: 1000,
        source_build: "12".repeat(32),
        database_version: 2,
        retained_from: records.gc()?,
        permanent_cells: false,
        coverage: vec!["-1:8000000000000000".to_owned()],
        approved_forks: vec![],
        capture: node_data_sync::model::CaptureReceipt {
            method: "cold_copy".to_owned(),
            started_utc: 0,
            finished_utc: 1,
            copied_bytes: 1,
            elapsed_millis: 1,
        },
        validation: NativeValidation {
            engine_sha256: "12".repeat(32),
            policy_sha256: "34".repeat(32),
            frontier: tip,
            passes: 2,
            permanent_cells: false,
            recovery_resolved: true,
            monitored_states_readable: true,
            elapsed_millis: 1,
            recovery_context_sha256: "56".repeat(32),
            started_utc: 1,
            finished_utc: 2,
        },
        files,
    };
    let mut ids = Vec::new();
    for n in 0..4 {
        manifest.created_utc = 1000 + n;
        ids.push(catalog.publish(&SignedManifest::sign(manifest.clone(), &key)?, &objects)?);
    }
    let operation = "ab".repeat(32);
    catalog.lease(&operation, &ids[0])?;
    assert_eq!(catalog.prune()?, vec![ids[1].clone()]);
    assert_eq!(catalog.list()?.len(), 3);
    catalog.release(&operation)?;
    assert_eq!(catalog.prune()?, vec![ids[0].clone()]);
    assert_eq!(catalog.list()?.len(), 2);
    // An incomplete receiver generation is leased before its first transfer, but cannot publish.
    let mut pending = manifest.clone();
    pending.created_utc = 2000;
    pending.files[0].sha256 = "78".repeat(32);
    pending.files[0].compressed_sha256 = "79".repeat(32);
    let pending = SignedManifest::sign(pending, &key)?;
    let receiver = "cd".repeat(32);
    let writer = objects.writer()?;
    let pending_id = catalog.begin_download(&pending, &writer, &receiver)?;
    drop(writer);
    let cache_root = Root::open(objects.root_path())?;
    let object = &pending.manifest.files[0];
    let partial = format!("incoming/{}-{}.part", object.compressed_sha256, object.compressed_size);
    cache_root.write_new(&partial, b"interrupted transfer")?;
    assert!(catalog.publish(&pending, &objects).is_err(), "incomplete generation was published");
    assert!(catalog.prune()?.is_empty(), "in-progress receiver generation was pruned");
    assert!(cache_root.path.join(&partial).exists(), "in-progress partial object was pruned");
    catalog.release(&receiver)?;
    assert_eq!(
        catalog.prune()?,
        vec![pending_id],
        "an incomplete generation displaced a completed retained generation"
    );
    assert!(!cache_root.path.join(&partial).exists(), "orphaned partial transfer was retained");
    assert_eq!(catalog.list()?.len(), 2);
    let mut bad = manifest;
    bad.network.global_id = 2;
    assert!(
        node_data_sync::metadata::validate(&bad, &zero_boc, &tip_boc).is_err(),
        "public metadata accepted the wrong global id"
    );
    assert!(
        catalog.publish(&SignedManifest::sign(bad, &key)?, &objects).is_err(),
        "publication accepted metadata from a different network"
    );
    Ok(())
}

#[test]
fn retirement_checkpoints_are_decoded_and_require_exact_imported_ancestry() -> Result<()> {
    let session = [0x45; 32];
    let anchor = FullId::from_native(&block(7));
    let mut bytes = vec![1];
    bytes.extend(session);
    bytes.extend((-1_i32).to_le_bytes());
    bytes.extend(i64::MIN.to_le_bytes());
    bytes.extend(7_u32.to_le_bytes());
    bytes.extend([0x12; 32]);
    bytes.extend([0x34; 32]);
    bytes.extend(
        format!("consensus.-1.9223372036854775808.9.{}", hex::encode_upper(session)).as_bytes(),
    );
    let local = LocalRecords {
        records: vec![Record {
            key: Key::PendingValidatorCleanup(session),
            value: Some(bytes.clone()),
        }],
    };
    let anchors = local.safety_anchors()?;
    assert_eq!(anchors, BTreeSet::from([anchor.clone()]));
    let donor = chain(vec![])?;
    assert!(
        node_data_sync::records::reconcile_anchors(&donor, &anchors, &BTreeSet::new()).is_err(),
        "missing full-id ancestry was accepted"
    );
    node_data_sync::records::reconcile_anchors(&donor, &anchors, &anchors)?;
    let mut wrong = anchor;
    wrong.root_hash = "56".repeat(32);
    assert!(
        node_data_sync::records::reconcile_anchors(&donor, &anchors, &BTreeSet::from([wrong]))
            .is_err()
    );
    bytes[0] = 2;
    let future = LocalRecords {
        records: vec![Record { key: Key::PendingValidatorCleanup(session), value: Some(bytes) }],
    };
    assert!(future.safety_anchors().is_err(), "future local safety schema was accepted");
    Ok(())
}
