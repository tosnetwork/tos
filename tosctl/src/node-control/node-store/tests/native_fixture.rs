#![cfg(feature = "native")]
use anyhow::{Context, Result, ensure};
use node_store::{OfflineStore, StateKey};
use std::{
    env, fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn wal_and_local_records_roundtrip_through_native_statedb() -> Result<()> {
    let fixture = PathBuf::from(env::var("NODE_STORE_FIXTURE").context(
        "NODE_STORE_FIXTURE must name the native fixture binary; skipping this test is not a pass",
    )?);
    ensure!(fixture.is_file(), "native fixture binary is missing");
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = env::temp_dir().join(format!("node-store-proof-{}-{nonce}", std::process::id()));
    fs::create_dir(&root)?;
    let source = root.join("source");
    let rebuilt = root.join("rebuilt");
    let status = Command::new(&fixture).arg("create-wal").arg(&source).status()?;
    ensure!(status.success(), "native fixture creation failed");
    let files = fs::read_dir(&source)?.collect::<std::io::Result<Vec<_>>>()?;
    ensure!(
        files.iter().any(|file| file.path().extension().is_some_and(|ext| ext == "log")
            && file.metadata().is_ok_and(|m| m.len() > 0)),
        "fixture has no WAL"
    );
    ensure!(
        !files.iter().any(|file| file.path().extension().is_some_and(|ext| ext == "sst")),
        "fixture unexpectedly flushed to SST; WAL recovery was not exercised"
    );
    let source_store = OfflineStore::open_existing(&source)?;
    ensure!(
        OfflineStore::open_existing(&source).is_err(),
        "a second opener bypassed the native database lock"
    );
    let keys = vec![
        StateKey::Version,
        StateKey::Init,
        StateKey::Gc,
        StateKey::ShardClient,
        StateKey::DestroyedSessions,
        StateKey::Hardforks,
        StateKey::PendingObserverCleanup,
        StateKey::PendingValidatorCleanup([0; 32]),
        StateKey::PendingValidatorCleanup([0xab; 32]),
    ];
    let records = keys
        .into_iter()
        .map(|key| {
            let value = source_store.get(&key)?;
            Ok((key, value))
        })
        .collect::<Result<Vec<_>>>()?;
    for (key, value) in &records[..6] {
        ensure!(
            value.is_some(),
            "native record {key:?} missing; key encoding or WAL recovery is wrong"
        );
    }
    ensure!(records[0].0.bytes()?.len() == 4, "database-version key must be raw TL");
    ensure!(records[1].0.bytes()?.len() == 32, "init key must be hashed TL");
    ensure!(records[6].1 == Some(Vec::new()), "present-empty local record was lost");
    ensure!(records[7].1.is_none(), "absent local record became present");
    ensure!(
        records[8].1.as_ref().is_some_and(|v| !v.is_empty()),
        "native validator cleanup record missing"
    );
    let mut target = OfflineStore::create_staging(&rebuilt)?;
    ensure!(
        OfflineStore::create_staging(&rebuilt).is_err(),
        "existing staging database was accepted"
    );
    // Prove an absent record deletes a pre-existing value, rather than becoming empty.
    target.write(&[(StateKey::PendingValidatorCleanup([0; 32]), Some(b"stale".to_vec()))])?;
    target.write(&records)?;
    for (key, value) in &records {
        ensure!(&target.get(key)? == value, "record {key:?} was not byte-preserved");
    }
    drop(target);
    drop(source_store);
    let status = Command::new(&fixture).arg("verify").arg(&rebuilt).status()?;
    ensure!(status.success(), "production StateDb could not reopen reconstructed records");
    ensure!(
        OfflineStore::open_existing(&root.join("missing")).is_err(),
        "opening a missing source created a database"
    );
    ensure!(!root.join("missing").exists(), "missing-source open left a database behind");
    let invalid = root.join("invalid-version");
    let mut store = OfflineStore::create_staging(&invalid)?;
    store.write(&[(StateKey::Version, Some(vec![0; 8]))])?;
    drop(store);
    ensure!(
        OfflineStore::open_existing(&invalid).is_err(),
        "unsupported database version was accepted"
    );
    fs::remove_dir_all(root)?;
    Ok(())
}
