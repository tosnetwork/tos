//! Compatibility proof only: reconstruct a small engine-created fixture, not a restore command.
use anyhow::{Context, Result, ensure};
use node_store::{OfflineStore, StateKey};
use std::{env, path::Path};

fn main() -> Result<()> {
    let args: Vec<_> = env::args_os().collect();
    ensure!(args.len() == 3, "usage: reconstruct_fixture SOURCE_STATE NEW_STATE");
    let source = OfflineStore::open_existing(Path::new(&args[1]))?;
    let keys = [
        StateKey::Version,
        StateKey::Init,
        StateKey::Gc,
        StateKey::ShardClient,
        StateKey::DestroyedSessions,
        StateKey::Hardforks,
        StateKey::AsyncSerializer,
        StateKey::PersistentDescriptions,
        StateKey::PendingObserverCleanup,
        StateKey::PendingValidatorCleanup([0; 32]),
        StateKey::PendingValidatorCleanup([0xab; 32]),
    ];
    let known = keys.iter().map(StateKey::bytes).collect::<Result<Vec<_>>>()?;
    let inventory = source.inventory_keys()?;
    ensure!(
        inventory.iter().all(|key| known.contains(key)),
        "fixture contains a record outside this proof's closed key inventory"
    );
    let records = keys
        .into_iter()
        .map(|key| {
            let value = source.get(&key)?;
            Ok((key, value))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut target = OfflineStore::create_staging(Path::new(&args[2]))?;
    target.write(&records)?;
    for (key, value) in &records {
        ensure!(&target.get(key)? == value, "fixture reconstruction changed record {key:?}");
    }
    ensure!(target.inventory_keys()? == inventory, "fixture reconstruction changed key inventory");
    drop(target);
    OfflineStore::open_existing(Path::new(&args[2])).context("reopen reconstructed fixture")?;
    println!("NODE_STORE_FIXTURE_RECONSTRUCTED records={}", inventory.len());
    Ok(())
}
