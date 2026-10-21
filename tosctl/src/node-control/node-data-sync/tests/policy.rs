#[path = "support/references.rs"]
mod reference_fixture;
use anyhow::Result;
use node_data_sync::{
    cas::Objects,
    journal::{Journal, Phase, Recovery, TreeIdentity},
    model::{FullId, sha256},
    paths,
    safe_io::Root,
    status::Observation,
};
use std::{
    fs,
    os::unix::fs::{MetadataExt, symlink},
};

fn id(n: u32) -> FullId {
    FullId {
        workchain: -1,
        shard: i64::MIN,
        seqno: n,
        root_hash: "12".repeat(32),
        file_hash: "34".repeat(32),
    }
}

#[test]
fn closed_payload_rejects_every_local_and_recovery_class() {
    for path in [
        "state/CURRENT",
        "chain/state/CURRENT",
        "chain/config.json",
        "chain/keyring/key",
        "chain/consensus/000001.sst",
        "chain/catchains/000001.sst",
        "chain/tmp/persistent-state",
        "chain/import/state",
        "chain/archive/tmp/file",
        "chain/adnl/key",
        "chain/celldb/LOCK",
        "chain/celldb/LOG",
        "chain/celldb/unknown",
        "../chain/celldb/CURRENT",
        "chain//celldb/CURRENT",
        "/chain/celldb/CURRENT",
        "chain/static/../../config.json",
    ] {
        assert!(paths::public_path(path).is_err(), "accepted {path}");
    }
    for path in [
        "chain/celldb/000001.sst",
        "chain/celldb/000002.log",
        "chain/celldb/MANIFEST-1",
        "chain/files/packages/temp.archive.3.pack",
        "chain/files/packages/temp.archive.3.index/CURRENT",
        "chain/archive/packages/arch0000/archive.3.-1_8000000000000000.pack",
        "state-records.cbor",
    ] {
        paths::public_path(path).unwrap_or_else(|e| panic!("refused {path}: {e}"));
    }
}

#[test]
fn descriptor_io_refuses_links_special_files_and_overwrites() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let root = Root::create(&tmp.path().join("private"))?;
    let outside = tmp.path().join("outside");
    fs::write(&outside, b"secret")?;
    symlink(&outside, root.path.join("link"))?;
    assert!(root.bytes("link", 100).is_err());
    symlink(tmp.path(), root.path.join("parent"))?;
    assert!(root.write_new("parent/escaped", b"bad").is_err());
    assert!(!tmp.path().join("escaped").exists());
    root.write_new("one", b"one")?;
    assert!(root.write_new("one", b"two").is_err());
    assert!(root.bytes("one", 2).is_err());
    assert_eq!(root.bytes("one", 3)?, b"one");
    root.replace("one", b"new")?;
    assert_eq!(root.bytes("one", 3)?, b"new");
    Ok(())
}

#[test]
fn objects_verify_both_hashes_and_reuse_only_matching_immutable_bytes() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let objects = Objects::create(&tmp.path().join("objects"))?;
    let source = tmp.path().join("source");
    fs::write(&source, b"owned table bytes")?;
    let object = objects.writer()?.put("chain/celldb/000001.sst", fs::File::open(&source)?, 100)?;
    objects.check(&object)?;
    let reuse = Root::create(&tmp.path().join("reuse"))?;
    reuse.write_new(&object.path, b"wrong table bytes")?;
    let first = Root::create(&tmp.path().join("first"))?;
    assert!(!objects.materialize(&object, &first, Some(&reuse))?);
    assert_eq!(first.bytes(&object.path, 100)?, b"owned table bytes");
    let second = Root::create(&tmp.path().join("second"))?;
    assert!(objects.materialize(&object, &second, Some(&first))?);
    assert_ne!(
        fs::metadata(first.path.join(&object.path))?.ino(),
        fs::metadata(second.path.join(&object.path))?.ino()
    );
    let compressed = tmp.path().join("objects").join(Objects::object_name(&object)?);
    let mut bad = object.clone();
    bad.sha256 = sha256(b"wrong");
    fs::copy(&compressed, tmp.path().join("objects").join(Objects::object_name(&bad)?))?;
    assert!(objects.check(&bad).is_err());
    let mut bad = object.clone();
    bad.size -= 1;
    fs::copy(&compressed, tmp.path().join("objects").join(Objects::object_name(&bad)?))?;
    assert!(objects.check(&bad).is_err());
    fs::write(&compressed, b"corrupt")?;
    assert!(objects.check(&object).is_err());
    let failed = Root::create(&tmp.path().join("failed"))?;
    assert!(objects.materialize(&object, &failed, None).is_err());
    assert!(!failed.path.join(&object.path).exists());
    Ok(())
}

#[test]
fn mutable_files_never_reuse_even_with_the_same_hash() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let objects = Objects::create(&tmp.path().join("objects"))?;
    let source = tmp.path().join("source");
    fs::write(&source, b"mutable")?;
    let object = objects.writer()?.put("chain/celldb/CURRENT", fs::File::open(&source)?, 100)?;
    let reuse = Root::create(&tmp.path().join("reuse"))?;
    reuse.write_new(&object.path, b"mutable")?;
    let out = Root::create(&tmp.path().join("out"))?;
    assert!(!objects.materialize(&object, &out, Some(&reuse))?);
    Ok(())
}

#[test]
fn durable_boundary_survives_exchange_without_a_start_marker() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let installed = tmp.path().join("installed");
    let staged = tmp.path().join("staged");
    let old = Root::create(&installed)?;
    let new = Root::create(&staged)?;
    old.write_new("vote", b"old signing state")?;
    new.write_new("vote", b"current signing state")?;
    let operation = Root::create(&tmp.path().join("operation"))?;
    let mut journal = Journal {
        version: 2,
        corroboration_sha256: None,
        operation: "ab".repeat(16),
        generation: "12".repeat(32),
        old: TreeIdentity::read(&installed)?,
        new: TreeIdentity::read(&staged)?,
        installed: installed.to_string_lossy().into_owned(),
        staged: staged.to_string_lossy().into_owned(),
        preservation_sha256: "34".repeat(32),
        target_anchor: id(1),
        phase: Phase::Staged,
    };
    journal.write(&operation)?;
    assert!(journal.exchange(&operation).is_err());
    reference_fixture::authorize(&mut journal, &operation)?;
    journal.forward_only(&operation)?;
    journal.exchange(&operation)?;
    // Simulate a boot-started signer completing work before the restore process resumes.
    Root::open(&installed)?.replace("vote", b"new signed state")?;
    // A crash between exchange and its journal write leaves only FORWARD_ONLY durable.
    journal.phase = Phase::ForwardOnly;
    journal.write(&operation)?;
    let mut recovered = Journal::read(&operation)?;
    assert_eq!(recovered.recovery()?, Recovery::NewContinueOnly);
    assert!(recovered.exchange(&operation).is_err());
    assert!(recovered.forward_only(&operation).is_err());
    assert_eq!(Root::open(&installed)?.bytes("vote", 100)?, b"new signed state");
    assert_eq!(Root::open(&staged)?.bytes("vote", 100)?, b"old signing state");
    Ok(())
}

#[test]
fn interrupted_old_root_always_requires_refresh_and_ambiguity_refuses() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let installed = tmp.path().join("installed");
    let staged = tmp.path().join("staged");
    Root::create(&installed)?;
    Root::create(&staged)?;
    let operation = Root::create(&tmp.path().join("operation"))?;
    let mut j = Journal {
        version: 2,
        corroboration_sha256: None,
        operation: "ab".repeat(16),
        generation: "12".repeat(32),
        old: TreeIdentity::read(&installed)?,
        new: TreeIdentity::read(&staged)?,
        installed: installed.to_string_lossy().into_owned(),
        staged: staged.to_string_lossy().into_owned(),
        preservation_sha256: "34".repeat(32),
        target_anchor: id(1),
        phase: Phase::Staged,
    };
    j.write(&operation)?;
    reference_fixture::authorize(&mut j, &operation)?;
    j.forward_only(&operation)?;
    Root::open(&installed)?.write_new("vote", b"signed during restart")?;
    assert_eq!(Journal::read(&operation)?.recovery()?, Recovery::OldRefreshRequired);
    fs::rename(&staged, tmp.path().join("unknown"))?;
    Root::create(&staged)?;
    assert!(j.recovery().is_err());
    Ok(())
}

#[test]
fn status_requires_fresh_coherent_full_ids_and_two_consistent_references() -> Result<()> {
    let obs = Observation {
        sampled_utc: 1000,
        tip: id(10),
        tip_utime: 990,
        coherent_tip: Some(id(10)),
        coherent_tip_utime: Some(990),
        shard_client_seqno: 10,
        initial_sync_complete: true,
    };
    let refs = vec![("a".to_owned(), id(11), id(10)), ("b".to_owned(), id(12), id(10))];
    assert_eq!(obs.clone().status(&refs, 300)?.exit_code, 0);
    assert_eq!(obs.clone().status(&refs, 299)?.exit_code, 2);
    assert_eq!(obs.clone().status(&refs[..1], 300)?.exit_code, 4);
    let mut bad = refs.clone();
    bad[0].2.root_hash = "ab".repeat(32);
    assert_eq!(obs.clone().status(&bad, 300)?.exit_code, 3);
    let mut bad = refs.clone();
    bad[0].1 = id(9);
    assert!(obs.clone().status(&bad, 300).is_err());
    let mut bad = refs.clone();
    bad[0].1 = id(10);
    bad[0].1.file_hash = "ab".repeat(32);
    assert!(obs.clone().status(&bad, 300).is_err());
    let mut bad = refs.clone();
    bad[0].0 = "b".to_owned();
    assert!(obs.clone().status(&bad, 300).is_err());
    let mut stale = obs.clone();
    stale.tip_utime = 900;
    stale.coherent_tip_utime = Some(900);
    assert_eq!(stale.status(&refs, 300)?.exit_code, 2);
    let mut initial = obs;
    initial.initial_sync_complete = false;
    assert_eq!(initial.status(&refs, 300)?.exit_code, 2);
    Ok(())
}

#[test]
fn private_capture_preserves_config_absence_and_referenced_seeds() -> Result<()> {
    use node_data_sync::{identity::Identity, paths::LOCAL_CONFIGS};
    let tmp = tempfile::tempdir()?;
    let db = Root::create(&tmp.path().join("db"))?;
    let work = Root::create(&tmp.path().join("work"))?;
    fs::create_dir(db.path.join("keyring"))?;
    fs::create_dir(work.path.join("keys"))?;
    db.write_new("keyring/one", b"own key")?;
    work.write_new("keys/two", b"own second key")?;
    work.write_new("primary.seed", &[1; 32])?;
    work.write_new("next.seed", &[2; 32])?;
    db.write_new("config.json", br#"{"extraconfig":{"pq_consensus":{"consensus_key_file":"primary.seed","keys":[{"consensus_key_file":"next.seed"}]}}}"#)?;
    for (i, name) in LOCAL_CONFIGS.iter().enumerate() {
        if i != 2 {
            db.write_new(name, format!("own-{i}").as_bytes())?;
        }
    }
    let operator = tmp.path().join("operator.json");
    fs::write(&operator, b"operator")?;
    let service = tmp.path().join("service.conf");
    fs::write(&service, b"service")?;
    let backup = Root::create(&tmp.path().join("backup"))?;
    db.write_new("global.json", b"held anchor")?;
    let inventory = Identity::capture(
        &db.path,
        &work.path,
        &work.path,
        &operator,
        &db.path.join("global.json"),
        &[service],
        &backup,
    )?;

    assert_eq!(inventory.files.iter().filter(|f| f.size.is_none()).count(), 1);
    assert!(inventory.files.iter().any(|f| f.source == work.path.join("primary.seed")));
    assert!(inventory.files.iter().any(|f| f.source == work.path.join("next.seed")));
    let target = Root::create(&tmp.path().join("target"))?;
    inventory.overlay(&db.path, &target, &backup)?;
    assert_eq!(target.bytes("global.json", 100)?, b"held anchor");
    assert_eq!(target.bytes("config.json", 1000)?, db.bytes("config.json", 1000)?);
    for (i, name) in LOCAL_CONFIGS.iter().enumerate() {
        if i == 2 {
            assert!(!target.path.join(name).exists());
        } else {
            assert_eq!(
                target.bytes(name, 100).ok().as_deref(),
                Some(format!("own-{i}").as_bytes()),
                "own config content was not preserved: {name}"
            );
        }
    }
    work.replace("next.seed", b"changed")?;
    let other = Root::create(&tmp.path().join("other"))?;
    assert!(inventory.overlay(&db.path, &other, &backup).is_err());
    Ok(())
}

fn manifest() -> node_data_sync::model::Manifest {
    use node_data_sync::model::{Manifest, NativeValidation, Network, Object};
    let mut manifest = Manifest {
        format: 2,
        corroboration: reference_fixture::historical_receipt(
            &reference_fixture::network(&id(10)),
            &id(10),
            &"12".repeat(32),
            1000,
        ),
        network: Network { global_id: 3, zero: id(0), init: id(0) },
        frontier: id(10),
        frontier_utime: 900,
        created_utc: 1000,
        source_build: "12".repeat(32),
        database_version: 2,
        retained_from: id(0),
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
            frontier: id(10),
            passes: 2,
            permanent_cells: false,
            recovery_resolved: true,
            monitored_states_readable: true,
            elapsed_millis: 100,
            recovery_context_sha256: "56".repeat(32),
            started_utc: 1,
            finished_utc: 2,
        },
        files: ["metadata/tip-block.boc", "metadata/zero-state.boc", "state-records.cbor"]
            .into_iter()
            .map(|path| Object {
                kind: node_data_sync::model::ObjectKind::RegularFile,
                path: path.to_owned(),
                size: 1,
                sha256: "12".repeat(32),
                compressed_size: 10,
                compressed_sha256: "34".repeat(32),
                codec: "zstd".to_owned(),
            })
            .collect(),
    };
    manifest.corroboration.binding_sha256 =
        node_data_sync::model::sha256(&serde_json::to_vec(&manifest.validation).unwrap());
    manifest
}

#[test]
fn signatures_bind_the_network_receipt_and_closed_file_inventory() -> Result<()> {
    use ed25519_dalek::SigningKey;
    use node_data_sync::model::SignedManifest;
    let key = SigningKey::from_bytes(&[42; 32]);
    let signed = SignedManifest::sign(manifest(), &key)?;
    let bytes = signed.bytes()?;
    let trusted = key.verifying_key().to_bytes();
    SignedManifest::parse(&bytes, &trusted)?;
    assert!(
        SignedManifest::parse(
            &bytes,
            &SigningKey::from_bytes(&[43; 32]).verifying_key().to_bytes()
        )
        .is_err()
    );
    let mut changed = signed.clone();
    changed.manifest.network.global_id = 2;
    assert!(changed.verify(&trusted).is_err());
    let mut changed = signed.clone();
    changed.manifest.validation.passes = 1;
    assert!(SignedManifest::sign(changed.manifest, &key).is_err());
    let mut changed = signed.clone();
    changed.manifest.files[0].path = "chain/keyring/key".to_owned();
    assert!(SignedManifest::sign(changed.manifest, &key).is_err());
    let mut changed = signed.clone();
    changed.manifest.files.push(changed.manifest.files[0].clone());
    assert!(SignedManifest::sign(changed.manifest, &key).is_err());
    let mut changed = signed.clone();
    changed.manifest.files[0].size = u64::MAX;
    assert!(SignedManifest::sign(changed.manifest, &key).is_err());
    let mut trailing = bytes;
    trailing.push(b' ');
    assert!(SignedManifest::parse(&trailing, &trusted).is_err());
    Ok(())
}

#[test]
fn stability_resets_on_missing_or_unqualified_samples() -> Result<()> {
    use node_data_sync::status::Stability;
    let obs = Observation {
        sampled_utc: 1000,
        tip: id(10),
        tip_utime: 990,
        coherent_tip: Some(id(10)),
        coherent_tip_utime: Some(990),
        shard_client_seqno: 10,
        initial_sync_complete: true,
    };
    let refs = vec![("a".to_owned(), id(10), id(10)), ("b".to_owned(), id(10), id(10))];
    let status = obs.status(&refs, 0)?;
    let mut stability = Stability::default();
    let start = std::time::Instant::now();
    for n in 0..=30 {
        assert_eq!(
            stability.observe(&status, start + std::time::Duration::from_secs(n * 10))?,
            n * 10
        );
    }
    stability.missing();
    assert_eq!(stability.observe(&status, start + std::time::Duration::from_secs(310))?, 0);
    assert_eq!(stability.observe(&status, start + std::time::Duration::from_secs(350))?, 0);
    Ok(())
}

#[test]
fn memory_only_forward_boundary_does_not_authorize_exchange() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let installed = tmp.path().join("installed");
    let staged = tmp.path().join("staged");
    Root::create(&installed)?;
    Root::create(&staged)?;
    let operation = Root::create(&tmp.path().join("operation"))?;
    let mut j = Journal {
        version: 2,
        corroboration_sha256: None,
        operation: "ab".repeat(16),
        generation: "12".repeat(32),
        old: TreeIdentity::read(&installed)?,
        new: TreeIdentity::read(&staged)?,
        installed: installed.to_string_lossy().into_owned(),
        staged: staged.to_string_lossy().into_owned(),
        preservation_sha256: "34".repeat(32),
        target_anchor: id(1),
        phase: Phase::Staged,
    };
    j.write(&operation)?;
    j.phase = Phase::ForwardOnly;
    assert!(j.exchange(&operation).is_err());
    assert_eq!(TreeIdentity::read(&installed)?, j.old);
    Ok(())
}

#[test]
fn sparse_input_is_refused_but_identical_dense_zero_bytes_are_readable() -> Result<()> {
    use std::io::Write;
    let temp = tempfile::tempdir()?;
    let root = Root::create(&temp.path().join("private"))?;
    let sparse = root.create_file("sparse")?;
    sparse.set_len(1 << 20)?;
    sparse.sync_all()?;
    assert!(root.read("sparse", 1 << 20).is_err(), "sparse expansion was admitted");
    let mut dense = root.create_file("dense")?;
    dense.write_all(&vec![0; 1 << 20])?;
    dense.sync_all()?;
    assert_eq!(root.bytes("dense", 1 << 20)?.len(), 1 << 20);
    Ok(())
}

#[test]
fn status_freshness_includes_reference_query_latency_and_fractional_gaps() -> Result<()> {
    let observation = Observation {
        sampled_utc: 1000,
        tip: id(10),
        tip_utime: 990,
        coherent_tip: Some(id(10)),
        coherent_tip_utime: Some(990),
        shard_client_seqno: 10,
        initial_sync_complete: true,
    };
    let references = vec![("a".to_owned(), id(10), id(10)), ("b".to_owned(), id(10), id(10))];
    assert_eq!(observation.clone().status_at(&references, 300, 1000)?.exit_code, 0);
    let delayed = observation.clone().status_at(&references, 300, 1040)?;
    assert_eq!(delayed.block_age_seconds, 50, "query latency was omitted from head age");
    assert_eq!(delayed.exit_code, 2);
    assert!(observation.clone().status_at(&references, 300, 999).is_err());
    let qualified = observation.status_at(&references, 0, 1000)?;
    let mut stability = node_data_sync::status::Stability::default();
    let start = std::time::Instant::now();
    stability.observe(&qualified, start)?;
    assert_eq!(
        stability.observe(&qualified, start + std::time::Duration::from_millis(30_001))?,
        0,
        "a gap longer than thirty seconds retained qualification"
    );
    Ok(())
}

#[test]
fn disk_admission_reserves_space_and_refuses_overflow() -> Result<()> {
    use node_data_sync::budget::{self, DiskPolicy, Space};
    let policy = DiskPolicy { max_owned_bytes: 1000, shutdown_free_bytes: Some(100) };
    let space = |free| Space { capacity: 2000, free };
    budget::admit(&policy, &[999], 1, space(101))?;
    assert!(budget::admit(&policy, &[1000], 1, space(101)).is_err());
    assert!(budget::admit(&policy, &[0], 1, space(100)).is_err());
    assert!(budget::admit(&policy, &[u64::MAX, 1], 0, space(2000)).is_err());
    assert!(budget::admit(&policy, &[1], u64::MAX, space(2000)).is_err());
    assert!(budget::admit(&policy, &[0], 2, space(1)).is_err());
    assert!(budget::reservation(u64::MAX, 0, 0).is_err());
    assert!(budget::reservation(1, u64::MAX, 0).is_err());
    assert!(budget::reservation(1, 0, u64::MAX).is_err());
    Ok(())
}

#[test]
fn admitted_full_reservation_reaches_exact_threshold_without_stopping() -> Result<()> {
    use node_data_sync::budget::{self, DiskPolicy, Space};
    let policy = DiskPolicy { max_owned_bytes: 1000, shutdown_free_bytes: Some(100) };
    budget::admit(&policy, &[10], 400, Space { capacity: 2000, free: 500 })?;
    budget::check_sample(&policy, 410, Space { capacity: 2000, free: 100 })?;
    let error = budget::check_sample(&policy, 411, Space { capacity: 2000, free: 99 })
        .expect_err("one extra byte must stop work");
    assert!(error.to_string().contains("shutdown threshold"));
    assert!(budget::admit(&policy, &[10], 401, Space { capacity: 2000, free: 500 }).is_err());
    Ok(())
}

#[test]
fn disk_policy_validation_and_probe_fail_closed() -> Result<()> {
    use node_data_sync::budget::{self, DiskPolicy, Space};
    let space = Space { capacity: 2000, free: 1500 };
    assert!(
        DiskPolicy::default()
            .threshold(space)
            .expect_err("required ceiling")
            .to_string()
            .contains("disk_policy.max_owned_bytes")
    );
    for (max_owned_bytes, threshold) in
        [(1000, 0), (1000, 2000), (1000, 2001), (2000, 100), (0, 100)]
    {
        assert!(
            DiskPolicy { max_owned_bytes, shutdown_free_bytes: Some(threshold) }
                .threshold(space)
                .is_err()
        );
    }
    let policy = DiskPolicy { max_owned_bytes: 1000, shutdown_free_bytes: Some(100) };
    assert!(policy.threshold(Space { capacity: 0, free: 0 }).is_err());
    assert!(policy.threshold(Space { capacity: 2000, free: 2001 }).is_err());
    assert!(
        budget::check_probe(&policy, 0, || anyhow::bail!("injected disk probe failure"))
            .expect_err("probe errors refuse")
            .to_string()
            .contains("injected disk probe failure")
    );
    let default = DiskPolicy { max_owned_bytes: 1, shutdown_free_bytes: None };
    assert_eq!(default.threshold(Space { capacity: 160 << 30, free: 100 << 30 })?, 16 << 30);
    assert_eq!(default.threshold(Space { capacity: 1000 << 30, free: 500 << 30 })?, 50 << 30);
    Ok(())
}

#[test]
fn recovery_rechecks_persisted_policy_before_writes() -> Result<()> {
    use node_data_sync::budget::{self, DiskPolicy, Space};
    let policy = DiskPolicy { max_owned_bytes: 1000, shutdown_free_bytes: Some(100) };
    let persisted = serde_json::to_vec(&policy)?;
    budget::admit(&policy, &[10], 400, Space { capacity: 2000, free: 500 })?;
    let restored: DiskPolicy = serde_json::from_slice(&persisted)?;
    let mut writes = 0;
    let mut resume = |space| -> Result<()> {
        budget::admit(&restored, &[10], 400, space)?;
        writes += 1;
        Ok(())
    };
    assert!(resume(Space { capacity: 2000, free: 499 }).is_err());
    assert!(resume(Space { capacity: 100, free: 99 }).is_err());
    assert_eq!(writes, 0);
    budget::admit(&restored, &[10], 400, Space { capacity: 2000, free: 500 })?;
    let source = include_str!("../src/operations.rs");
    let recovery = source.split("pub fn recover(").nth(1).expect("recovery function");
    assert!(
        recovery.find("Monitor::start").expect("admission")
            < recovery.find("operation_lock(").expect("first potential write")
    );
    Ok(())
}

#[test]
fn publisher_secret_cannot_enter_capture_or_public_trees() -> Result<()> {
    use node_data_sync::publisher::PublisherSecret;
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir()?;
    let root = Root::create(&temp.path().join("private"))?;
    for name in ["db", "db/static", "catalog", "operations"] {
        fs::create_dir(root.path.join(name))?;
    }
    let operation = root.path.join("operations/new");
    for relative in [
        format!("db/static/{}", "ab".repeat(32)),
        "db/key".to_owned(),
        "catalog/key".to_owned(),
        "operations/new/key".to_owned(),
    ] {
        if relative.starts_with("operations/new/") {
            fs::create_dir(&operation)?;
        }
        root.write_new(&relative, &[42; 32])?;
        let key = PublisherSecret::load(&root.path.join(&relative))?;
        let error = key
            .validate(&root.path.join("db"), &root.path.join("catalog"), &operation)
            .expect_err("secret overlap was accepted");
        assert!(error.to_string().contains("publisher secret overlaps"), "wrong refusal: {error}");
        fs::remove_file(root.path.join(&relative))?;
        if operation.exists() {
            fs::remove_dir(&operation)?;
        }
    }
    root.write_new("publisher", &[42; 32])?;
    let key = PublisherSecret::load(&root.path.join("publisher"))?;
    key.validate(&root.path.join("db"), &root.path.join("catalog"), &operation)?;
    symlink(root.path.join("publisher"), root.path.join("link"))?;
    assert!(PublisherSecret::load(&root.path.join("link")).is_err());
    fs::hard_link(root.path.join("publisher"), root.path.join("hard"))?;
    assert!(key.validate(&root.path.join("db"), &root.path.join("catalog"), &operation).is_err());
    fs::remove_file(root.path.join("hard"))?;
    fs::set_permissions(root.path.join("publisher"), fs::Permissions::from_mode(0o644))?;
    assert!(PublisherSecret::load(&root.path.join("publisher")).is_err());
    fs::set_permissions(root.path.join("publisher"), fs::Permissions::from_mode(0o600))?;
    fs::rename(root.path.join("publisher"), root.path.join("old"))?;
    root.write_new("publisher", &[43; 32])?;
    assert!(
        key.validate(&root.path.join("db"), &root.path.join("catalog"), &operation).is_err(),
        "post-stop key replacement was accepted"
    );
    assert!(!root.path.join("catalog/objects").exists(), "refusal wrote public objects");
    Ok(())
}

#[test]
fn exchange_requires_fresh_revision_bound_reference_evidence() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let installed = Root::create(&temp.path().join("installed"))?;
    let staged = Root::create(&temp.path().join("staged"))?;
    let operation = Root::create(&temp.path().join("operation"))?;
    let mut journal = Journal {
        version: 2,
        operation: "ab".repeat(16),
        generation: "12".repeat(32),
        old: TreeIdentity::read(&installed.path)?,
        new: TreeIdentity::read(&staged.path)?,
        installed: installed.path.to_str().unwrap().to_owned(),
        staged: staged.path.to_str().unwrap().to_owned(),
        preservation_sha256: "34".repeat(32),
        corroboration_sha256: None,
        target_anchor: id(1),
        phase: Phase::Staged,
    };
    journal.write(&operation)?;
    assert!(journal.forward_only(&operation).is_err(), "missing references authorized exposure");
    reference_fixture::authorize(&mut journal, &operation)?;
    journal.forward_only(&operation)?;
    let original = operation.bytes("corroboration.json", 1 << 20)?;
    let mut receipt: node_data_sync::references::ReferenceReceipt =
        serde_json::from_slice(&original)?;
    receipt.finished_utc -= 31;
    receipt.started_utc = receipt.finished_utc;
    for answer in &mut receipt.answers {
        answer.observed_utc = receipt.finished_utc;
    }
    let bytes = serde_json::to_vec(&receipt)?;
    operation.replace("corroboration.json", &bytes)?;
    journal.corroboration_sha256 = Some(node_data_sync::model::sha256(&bytes));
    journal.write(&operation)?;
    assert!(journal.exchange(&operation).is_err(), "expired references authorized exchange");
    assert_eq!(TreeIdentity::read(&installed.path)?, journal.old, "refusal exposed a new tree");
    operation.replace("corroboration.json", &original)?;
    journal.corroboration_sha256 = Some(node_data_sync::model::sha256(&original));
    journal.preservation_sha256 = "56".repeat(32);
    journal.write(&operation)?;
    assert!(journal.exchange(&operation).is_err(), "another preservation revision reused approval");
    assert_eq!(TreeIdentity::read(&installed.path)?, journal.old);
    Ok(())
}

#[test]
fn file_only_payload_recreates_empty_chain_roots_without_accepting_links() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let payload = Root::create(&temp.path().join("payload"))?;
    let replacement = Root::create(&temp.path().join("replacement"))?;
    // archive/tmp is filtered from public_files: no archive object creates its parent.
    payload.write_new("chain/files/packages/temp.archive.1.pack", b"package")?;
    let result = node_data_sync::capture::install_chain_roots(&payload, &replacement);
    assert!(result.is_ok(), "empty required chain roots were not materialized: {result:?}");
    result?;
    for name in paths::CHAIN_ROOTS {
        assert!(replacement.path.join(name).is_dir(), "missing native root {name}");
    }
    assert_eq!(replacement.bytes("files/packages/temp.archive.1.pack", 100)?, b"package");
    for kind in ["file", "link"] {
        let payload = Root::create(&temp.path().join(format!("payload-{kind}")))?;
        let replacement = Root::create(&temp.path().join(format!("replacement-{kind}")))?;
        payload.ensure_directory("chain")?;
        if kind == "file" {
            payload.write_new("chain/celldb", b"not a directory")?;
        } else {
            symlink(temp.path(), payload.path.join("chain/celldb"))?;
        }
        assert!(node_data_sync::capture::install_chain_roots(&payload, &replacement).is_err());
        assert!(std::fs::read_dir(&replacement.path)?.next().is_none());
    }
    Ok(())
}
