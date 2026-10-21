#[path = "support/references.rs"]
mod reference_fixture;
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
    #[derive(serde::Serialize, serde::Deserialize)]
    struct WriteFault {
        directory: std::path::PathBuf,
        signed: node_data_sync::model::SignedManifest,
        trusted: [u8; 32],
    }
    if let Some(request) = std::env::var_os("NODE_SYNC_CATALOG_WRITE_FAULT") {
        let request: WriteFault = serde_json::from_slice(&std::fs::read(request)?)?;
        let catalog = node_data_sync::catalog::Catalog::open(&request.directory, request.trusted)?;
        let objects = node_data_sync::cas::Objects::open(&request.directory)?;
        let writer = objects.writer()?;
        let limit = libc::rlimit { rlim_cur: 128, rlim_max: 128 };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &limit) }, 0);
        unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_DFL) };
        catalog.begin_download(&request.signed, &writer, &"ef".repeat(32))?;
        panic!("the file-size fault did not interrupt metadata writing");
    }
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
        format: 2,
        corroboration: reference_fixture::historical_receipt(
            &Network { global_id: 3, zero: zero_id.clone(), init: zero_id.clone() },
            &tip,
            &"12".repeat(32),
            1000,
        ),
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
    manifest.corroboration.binding_sha256 = sha256(&serde_json::to_vec(&manifest.validation)?);
    let references = reference_fixture::References::new(
        &manifest.network,
        &manifest.frontier,
        reference_fixture::Mode::Agree,
    )?;
    // Exercise the actual pre-sign assembly gate with native-format component artifacts.
    // The separate engine fixture proves their provenance; this test proves ordering/refusal.
    #[cfg(feature = "native")]
    {
        use base64::Engine;
        let parent = Root::create(&temp.path().join("assembly"))?;
        let image = Root::create(&parent.path.join("image"))?;
        for name in ["celldb", "files", "archive", "static"] {
            std::fs::create_dir(image.path.join(name))?;
        }
        image.write_new(
            &format!("static/{}", manifest.network.zero.file_hash.to_uppercase()),
            &zero_boc,
        )?;
        let checked = Root::create(&parent.path.join("checked"))?;
        checked.write_new("state-records.cbor", &records.bytes()?)?;
        checked.write_new("zero-state.boc", &zero_boc)?;
        checked.write_new("tip-block.boc", &tip_boc)?;
        parent.write_new("capture.json", &serde_json::to_vec(&manifest.capture)?)?;
        let encode = |s: &str| -> Result<String> {
            Ok(base64::engine::general_purpose::STANDARD.encode(hex::decode(s)?))
        };
        let policy = serde_json::to_vec(
            &serde_json::json!({"validator":{"zero_state":{"workchain":-1,"shard":i64::MIN,"seqno":0,"root_hash":encode(&manifest.network.zero.root_hash)?,"file_hash":encode(&manifest.network.zero.file_hash)?}}}),
        )?;
        let mut validation = manifest.validation.clone();
        validation.policy_sha256 = sha256(&policy);
        checked.write_new(
            "validation.json",
            &serde_json::to_vec(&node_data_sync::engine::ValidationResult {
                validation,
                coverage: manifest.coverage.clone(),
                ancestors: vec![manifest.network.zero.clone()],
            })?,
        )?;
        for (index, mode) in [
            reference_fixture::Mode::Agree,
            reference_fixture::Mode::Behind,
            reference_fixture::Mode::DifferentRoot,
            reference_fixture::Mode::Unavailable,
        ]
        .into_iter()
        .enumerate()
        {
            let store = parent.path.join(format!("store-{index}"));
            let catalog = Catalog::create(&store, key.verifying_key().to_bytes())?;
            let objects = Objects::open(&store)?;
            let refs =
                reference_fixture::References::new(&manifest.network, &manifest.frontier, mode)?;
            let result = node_data_sync::generation::assemble(
                &image,
                &checked,
                node_data_sync::generation::GenerationPolicy {
                    global_config: &policy,
                    global_id: 3,
                    references: &refs.policy,
                },
                &objects,
                &key,
                &catalog,
            );
            if index == 0 {
                assert!(result.is_ok(), "positive assembly precondition: {result:?}");
                assert_eq!(catalog.list()?.len(), 1);
            } else {
                let error = result.expect_err("generation signed without corroboration");
                assert!(format!("{error:#}").contains("reference-2"), "wrong refusal: {error:#}");
                assert!(
                    catalog.list()?.is_empty(),
                    "uncorroborated generation was signed/prepared"
                );
                assert!(!store.join("latest.json").exists());
            }
        }
    }
    let mut ids = Vec::new();
    for n in 0..4 {
        manifest.created_utc = 1000 + n;
        ids.push(catalog.publish(
            &SignedManifest::sign(manifest.clone(), &key)?,
            &objects,
            &references.policy,
        )?);
    }
    let before = catalog
        .latest()?
        .expect("positive publication precondition")
        .verify(&key.verifying_key().to_bytes())?;
    let disagree = reference_fixture::References::new(
        &manifest.network,
        &manifest.frontier,
        reference_fixture::Mode::DifferentFile,
    )?;
    let mut refused = manifest.clone();
    refused.created_utc += 1;
    assert!(
        catalog.publish(&SignedManifest::sign(refused, &key)?, &objects, &disagree.policy).is_err(),
        "publication ignored a disagreeing named reference"
    );
    assert_eq!(
        catalog.latest()?.expect("latest disappeared").verify(&key.verifying_key().to_bytes())?,
        before,
        "failed corroboration changed publication"
    );
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
    assert!(
        catalog.publish(&pending, &objects, &references.policy).is_err(),
        "incomplete generation was published"
    );
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
    let mut interrupted = manifest.clone();
    interrupted.created_utc = 3000;
    let interrupted = SignedManifest::sign(interrupted, &key)?;
    let interrupted_id = interrupted.verify(&key.verifying_key().to_bytes())?;
    let fault_path = temp.path().join("write-fault.json");
    std::fs::write(
        &fault_path,
        serde_json::to_vec(&WriteFault {
            directory: objects.root_path().to_owned(),
            signed: interrupted,
            trusted: key.verifying_key().to_bytes(),
        })?,
    )?;
    let child = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "publication_checks_metadata_and_pruning_respects_capture_and_restore_leases",
        ])
        .env("NODE_SYNC_CATALOG_WRITE_FAULT", fault_path)
        .status()?;
    assert!(!child.success(), "metadata interruption control did not fire");
    let partial_public = cache_root
        .path
        .join(format!("generations/{interrupted_id}.json"))
        .symlink_metadata()
        .is_ok_and(|m| m.len() == 128);
    let partial_private = std::fs::read_dir(cache_root.path.join("incoming"))?
        .any(|entry| entry.is_ok_and(|entry| entry.metadata().is_ok_and(|m| m.len() == 128)));
    assert!(
        partial_public || partial_private,
        "the interruption did not reach a partial metadata write"
    );
    let listed = catalog.list();
    assert!(
        listed.is_ok(),
        "an interrupted metadata write exposed a partial generation: {listed:?}"
    );
    assert_eq!(listed?.len(), 2);
    catalog.prune()?;
    assert_eq!(
        std::fs::read_dir(cache_root.path.join("incoming"))?.count(),
        0,
        "unreachable temporary metadata was retained"
    );
    let mut bad = manifest;
    bad.network.global_id = 2;
    bad.corroboration.network = bad.network.clone();
    assert!(
        node_data_sync::metadata::validate(&bad, &zero_boc, &tip_boc).is_err(),
        "public metadata accepted the wrong global id"
    );
    assert!(
        catalog.publish(&SignedManifest::sign(bad, &key)?, &objects, &references.policy).is_err(),
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
